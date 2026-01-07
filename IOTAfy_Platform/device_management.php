<?php
// device_management.php

require 'config.inc'; // Include the configuration file

// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Check if session is already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Redirect to login if user is not authenticated
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$db = getDbConnection();
$message = "";

// Pagination settings
$defaultItemsPerPage = 10;
$itemsPerPageOptions = [5, 10, 20, 50];
$itemsPerPage = isset($_GET['items_per_page']) && in_array((int)$_GET['items_per_page'], $itemsPerPageOptions) ? (int)$_GET['items_per_page'] : $defaultItemsPerPage;
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$offset = ($page - 1) * $itemsPerPage;

// Generate a CSRF token
function generateToken() {
    if (empty($_SESSION['token'])) {
        $_SESSION['token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['token'];
}

// Validate CSRF token
function validateToken($token) {
    return isset($_SESSION['token']) && hash_equals($_SESSION['token'], $token);
}

// Fetch device details by ID
function getDeviceById($db, $device_id) {
    $stmt = $db->prepare("SELECT mac, user_id, ip, external_ip FROM devices WHERE id = :id");
    $stmt->bindParam(':id', $device_id, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

// Fetch devices for the user with pagination
function fetchDevices($db, $offset, $itemsPerPage) {
    if ($_SESSION['role'] === 'admin') {
        $stmt = $db->prepare("SELECT * FROM devices ORDER BY name LIMIT :limit OFFSET :offset");
    } else {
        $stmt = $db->prepare("SELECT d.* FROM devices d
                              LEFT JOIN device_groups dg ON d.id = dg.device_id
                              LEFT JOIN user_groups ug ON dg.group_id = ug.group_id
                              WHERE d.user_id = :user_id OR ug.user_id = :user_id
                              GROUP BY d.id ORDER BY d.name LIMIT :limit OFFSET :offset");
        $stmt->bindParam(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    }
    $stmt->bindParam(':limit', $itemsPerPage, PDO::PARAM_INT);
    $stmt->bindParam(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// Get total count of devices for pagination
function getTotalDeviceCount($db) {
    if ($_SESSION['role'] === 'admin') {
        $stmt = $db->prepare("SELECT COUNT(*) FROM devices");
    } else {
        $stmt = $db->prepare("SELECT COUNT(DISTINCT d.id) FROM devices d
                              LEFT JOIN device_groups dg ON d.id = dg.device_id
                              LEFT JOIN user_groups ug ON dg.group_id = ug.group_id
                              WHERE d.user_id = :user_id OR ug.user_id = :user_id");
        $stmt->bindParam(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    }
    $stmt->execute();
    return $stmt->fetchColumn();
}

// Render Pagination
function renderPagination($totalPages, $currentPage, $itemsPerPage) {
    if ($totalPages <= 1) return '';

    $html = '<nav aria-label="Page navigation example"><ul class="pagination justify-content-center">';

    // Previous button
    if ($currentPage > 1) {
        $html .= '<li class="page-item"><a class="page-link" href="?page=' . ($currentPage - 1) . '&items_per_page=' . $itemsPerPage . '">Previous</a></li>';
    } else {
        $html .= '<li class="page-item disabled"><a class="page-link">Previous</a></li>';
    }

    // Page numbers
    for ($i = 1; $i <= $totalPages; $i++) {
        if ($i == $currentPage) {
            $html .= '<li class="page-item active"><a class="page-link" href="?page=' . $i . '&items_per_page=' . $itemsPerPage . '">' . $i . '</a></li>';
        } else {
            $html .= '<li class="page-item"><a class="page-link" href="?page=' . $i . '&items_per_page=' . $itemsPerPage . '">' . $i . '</a></li>';
        }
    }

    // Next button
    if ($currentPage < $totalPages) {
        $html .= '<li class="page-item"><a class="page-link" href="?page=' . ($currentPage + 1) . '&items_per_page=' . $itemsPerPage . '">Next</a></li>';
    } else {
        $html .= '<li class="page-item disabled"><a class="page-link">Next</a></li>';
    }

    $html .= '</ul></nav>';
    return $html;
}

// Handle device deletion
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['delete_device']) && validateToken($_POST['csrf_token'])) {
    $device_id = filter_input(INPUT_POST, 'device_id', FILTER_VALIDATE_INT);
    $delete_archives = isset($_POST['delete_archives']);

    try {
        $device = getDeviceById($db, $device_id);
        if ($device) {
            if ($_SESSION['role'] !== 'admin' && $device['user_id'] != $_SESSION['user_id']) {
                $message = "Unauthorized action.";
                logMessage("Unauthorized device deletion attempt by user {$_SESSION['user_id']} for device (MAC: {$device['mac']}, ID: {$device_id})");
            } else {
                $mac = $device['mac'];
                $stmt = $db->prepare("DELETE FROM devices WHERE id = :id");
                $stmt->bindParam(':id', $device_id, PDO::PARAM_INT);
                if ($stmt->execute()) {
                    deleteFiles($mac, $delete_archives);
                    $message = "Device and associated files deleted successfully.";
                    logMessage("Device deletion completed successfully. Device: MAC={$mac}, ID={$device_id}, User={$_SESSION['user_id']}, Delete Archives={$delete_archives}");
                } else {
                    $message = "Failed to delete device.";
                    logMessage("Failed to delete device. Device: MAC={$mac}, ID={$device_id}, User={$_SESSION['user_id']}, Error: Database operation failed");
                }
            }
        } else {
            $message = "Device not found.";
            logMessage("Device deletion failed - Device not found. ID={$device_id}, User={$_SESSION['user_id']}");
        }
    } catch (PDOException $e) {
        $message = "Database error: " . $e->getMessage();
        logMessage("Database error during device deletion. Device ID={$device_id}, User={$_SESSION['user_id']}, Error: " . $e->getMessage());
    }
}

// Delete device-related files
function deleteFiles($mac, $delete_archives) {
    $baseDir = BASE_DIR;
    $files = [
        $baseDir . "$mac.version",
        $baseDir . "$mac.bin"
    ];

    foreach ($files as $file) {
        if (file_exists($file)) {
            unlink($file);
        }
    }

    if ($delete_archives) {
        $archiveFiles = glob($baseDir . "{$mac}_*.bin");
        foreach ($archiveFiles as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }
    }
}

// Handle file upload
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['upload_bin']) && validateToken($_POST['csrf_token'])) {
    $device_id = filter_input(INPUT_POST, 'device_id', FILTER_VALIDATE_INT);

    try {
        $device = getDeviceById($db, $device_id);
        if ($device) {
            $mac = $device['mac'];
            logMessage("Firmware upload attempt for device (MAC: {$mac}) by user {$_SESSION['user_id']}");
            
            if (uploadBinFile($mac)) {
                $message = "File uploaded successfully.";
                logMessage("Firmware upload successful. Device: MAC={$mac}, User={$_SESSION['user_id']}, File Size=" . $_FILES['bin_file']['size']);
            } else {
                $message = "Failed to upload file.";
                logMessage("Firmware upload failed. Device: MAC={$mac}, User={$_SESSION['user_id']}, Error: File upload operation failed");
            }
        } else {
            $message = "Device not found.";
            logMessage("Firmware upload failed - Device not found. ID={$device_id}, User={$_SESSION['user_id']}");
        }
    } catch (PDOException $e) {
        $message = "Database error: " . $e->getMessage();
        logMessage("Database error during firmware upload. Device ID={$device_id}, User={$_SESSION['user_id']}, Error: " . $e->getMessage());
    }
}

// Upload binary file
function uploadBinFile($mac) {
    $targetDir = TARGET_DIR;
    $targetFile = $targetDir . $mac . ".bin";

    if (isset($_FILES['bin_file']) && $_FILES['bin_file']['error'] == 0) {
        if (move_uploaded_file($_FILES['bin_file']['tmp_name'], $targetFile)) {
            archiveFile($mac, $targetFile);
            return true;
        }
    }
    return false;
}

// Archive uploaded file
function archiveFile($mac, $targetFile) {
    $targetDir = TARGET_DIR;
    $datetime = date('Ymd_His');
    $archiveFile = $targetDir . $mac . "_" . $datetime . ".bin";
    copy($targetFile, $archiveFile);

    $files = glob($targetDir . $mac . "_*.bin");
    usort($files, function ($a, $b) {
        return filemtime($b) - filemtime($a);
    });

    if (count($files) > 10) {
        for ($i = 10; $i < count($files); $i++) {
            unlink($files[$i]);
        }
    }
}

// Handle firmware version update
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update_version']) && validateToken($_POST['csrf_token'])) {
    $device_id = filter_input(INPUT_POST, 'device_id', FILTER_VALIDATE_INT);
    $new_version = filter_input(INPUT_POST, 'firmware_version', FILTER_SANITIZE_FULL_SPECIAL_CHARS);

    try {
        $device = getDeviceById($db, $device_id);
        if ($device) {
            $mac = $device['mac'];
            $versionFilePath = BASE_DIR . "{$mac}.version";
            
            logMessage("Firmware version update attempt for device (MAC: {$mac}) by user {$_SESSION['user_id']}. New Version: {$new_version}");

            if (file_put_contents($versionFilePath, $new_version) !== false) {
                $stmt = $db->prepare("UPDATE devices SET firmware_version = :firmware_version WHERE id = :id");
                $stmt->bindParam(':firmware_version', $new_version, PDO::PARAM_STR);
                $stmt->bindParam(':id', $device_id, PDO::PARAM_INT);
                if ($stmt->execute()) {
                    $message = "Firmware version updated successfully.";
                    logMessage("Firmware version update successful. Device: MAC={$mac}, User={$_SESSION['user_id']}, New Version={$new_version}");
                } else {
                    $message = "Failed to update firmware version in the database.";
                    logMessage("Firmware version update failed - Database error. Device: MAC={$mac}, User={$_SESSION['user_id']}, New Version={$new_version}");
                }
            } else {
                $message = "Failed to update firmware version file.";
                logMessage("Firmware version update failed - File write error. Device: MAC={$mac}, User={$_SESSION['user_id']}, New Version={$new_version}");
            }
        } else {
            $message = "Device not found.";
            logMessage("Firmware version update failed - Device not found. ID={$device_id}, User={$_SESSION['user_id']}, New Version={$new_version}");
        }
    } catch (PDOException $e) {
        $message = "Database error: " . $e->getMessage();
        logMessage("Database error during firmware version update. Device ID={$device_id}, User={$_SESSION['user_id']}, Error: " . $e->getMessage());
    }
}

// Handle file loading from archive
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['load_bin']) && validateToken($_POST['csrf_token'])) {
    $device_id = filter_input(INPUT_POST, 'device_id', FILTER_VALIDATE_INT);
    $archive_file = filter_input(INPUT_POST, 'archive_file', FILTER_SANITIZE_FULL_SPECIAL_CHARS);

    try {
        $device = getDeviceById($db, $device_id);
        if ($device) {
            $mac = $device['mac'];
            $targetDir = TARGET_DIR;
            $targetFile = $targetDir . $mac . ".bin";
            $archiveFile = $targetDir . $archive_file;

            logMessage("Archive firmware load attempt for device (MAC: {$mac}) by user {$_SESSION['user_id']}. Archive File: {$archive_file}");

            if (file_exists($archiveFile) && copy($archiveFile, $targetFile)) {
                $message = "Firmware loaded successfully from archive.";
                logMessage("Archive firmware load successful. Device: MAC={$mac}, User={$_SESSION['user_id']}, Archive File={$archive_file}, Size=" . filesize($archiveFile));
            } else {
                $message = "Failed to load firmware from archive.";
                logMessage("Archive firmware load failed. Device: MAC={$mac}, User={$_SESSION['user_id']}, Archive File={$archive_file}, Error: File operation failed");
            }
        } else {
            $message = "Device not found.";
            logMessage("Archive firmware load failed - Device not found. ID={$device_id}, User={$_SESSION['user_id']}, Archive File={$archive_file}");
        }
    } catch (PDOException $e) {
        $message = "Database error: " . $e->getMessage();
        logMessage("Database error during archive firmware load. Device ID={$device_id}, User={$_SESSION['user_id']}, Error: " . $e->getMessage());
    }
}

// Handle device restart
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['restart_device']) && validateToken($_POST['csrf_token'])) {
    $device_id = filter_input(INPUT_POST, 'device_id', FILTER_VALIDATE_INT);
    $ip_type = filter_input(INPUT_POST, 'ip_type', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $port = filter_input(INPUT_POST, 'port', FILTER_VALIDATE_INT);
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_FULL_SPECIAL_CHARS);

    try {
        $device = getDeviceById($db, $device_id);
        if ($device) {
            $ip = ($ip_type === 'internal') ? $device['ip'] : $device['external_ip'];
            $url = "http://{$ip}:{$port}/restart";
            
            // Log the restart attempt
            logMessage("Restart attempt for device (MAC: {$device['mac']}) by user {$_SESSION['user_id']}. IP: {$ip}, Port: {$port}, IP Type: {$ip_type}");
            
            // Initialize cURL session
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
            curl_setopt($ch, CURLOPT_USERPWD, $username . ":" . $password);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_VERBOSE, true);
            
            // Create a temporary file to store verbose output
            $verbose = fopen('php://temp', 'w+');
            curl_setopt($ch, CURLOPT_STDERR, $verbose);
            
            // Execute cURL request
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = curl_error($ch);
            
            // Get verbose information
            rewind($verbose);
            $verboseLog = stream_get_contents($verbose);
            fclose($verbose);
            
            curl_close($ch);
            
            if ($httpCode >= 200 && $httpCode < 300) {
                $message = "Device restart command executed successfully.";
                logMessage("Device (MAC: {$device['mac']}) restart command executed successfully by user {$_SESSION['user_id']}. HTTP Code: {$httpCode}, Response: {$response}");
            } else {
                $message = "Failed to execute restart command. HTTP Code: " . $httpCode . ", Error: " . $error;
                logMessage("Failed to execute restart command for device (MAC: {$device['mac']}) by user {$_SESSION['user_id']}. HTTP Code: {$httpCode}, Error: {$error}, Verbose Log: {$verboseLog}");
            }
        } else {
            $message = "Device not found.";
            logMessage("Device (ID: $device_id) not found for restart by user {$_SESSION['user_id']}.");
        }
    } catch (PDOException $e) {
        $message = "Database error: " . $e->getMessage();
        logMessage("Database error during device restart: " . $e->getMessage());
    }
}

// Fetch devices for display with pagination
try {
    $totalDevices = getTotalDeviceCount($db);
    $devices = fetchDevices($db, $offset, $itemsPerPage);
    $totalPages = ceil($totalDevices / $itemsPerPage);
    logMessage("Device list loaded. User={$_SESSION['user_id']}, Page={$page}, Items Per Page={$itemsPerPage}, Total Devices={$totalDevices}");
} catch (PDOException $e) {
    $message = "Error fetching devices: " . $e->getMessage();
    logMessage("Error fetching devices list. User={$_SESSION['user_id']}, Error: " . $e->getMessage());
    die($message);
}

$token = generateToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Management</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" rel="stylesheet">
    <style>
        #search-input {
            width: 300px;
            margin: 0 auto 20px auto;
        }
        #items-per-page {
            width: 100px;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="dashboard.php">IOTAfy</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav mr-auto">
                <li class="nav-item">
                    <a class="nav-link" href="dashboard.php">
                        <i class="fas fa-tachometer-alt"></i> Dashboard
                    </a>
                </li>
                <?php if (in_array($_SESSION['role'], ['admin', 'superuser'])): ?>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="usersDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        <i class="fas fa-users"></i> Users
                    </a>
                    <div class="dropdown-menu" aria-labelledby="usersDropdown">
                        <a class="dropdown-item" href="user_management.php">
                            <i class="fas fa-user-cog"></i> Manage Users
                        </a>
                        <a class="dropdown-item" href="group_management.php">
                            <i class="fas fa-users-cog"></i> Manage Groups
                        </a>
                    </div>
                </li>
                <?php endif; ?>
                
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle active" href="#" id="devicesDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        <i class="fas fa-microchip"></i> Devices
                    </a>
                    <div class="dropdown-menu" aria-labelledby="devicesDropdown">
                        <a class="dropdown-item active" href="device_management.php">
                            <i class="fas fa-cogs"></i> Manage Devices
                        </a>
                        <a class="dropdown-item" href="monitor_status.php">
                            <i class="fas fa-chart-line"></i> Monitor Status
                        </a>
                        <?php if ($_SESSION['role'] === 'admin'): ?>
                        <a class="dropdown-item" href="devices_per_user.php">
                            <i class="fas fa-user-shield"></i> Devices per User
                        </a>
                        <?php endif; ?>
                    </div>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="settingsDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        <i class="fas fa-cog"></i> Settings
                    </a>
                    <div class="dropdown-menu" aria-labelledby="settingsDropdown">
                        <a class="dropdown-item" href="profile.php">
                            <i class="fas fa-user"></i> Profile
                        </a>
                        <a class="dropdown-item" href="change_password.php">
                            <i class="fas fa-key"></i> Change Password
                        </a>
                    </div>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="logout.php">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="#" data-toggle="modal" data-target="#aboutModal">
                        <i class="fas fa-info-circle"></i> About
                    </a>
                </li>
            </ul>
            <span class="navbar-text">
                Logged in as: <?php echo htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8'); ?>
            </span>
        </div>
    </nav>

    <div class="container mt-5">
        <h1 class="text-center">Device Management</h1>
        <?php if (!empty($message)): ?>
            <div class="alert alert-info text-center"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        <input type="text" id="search-input" class="form-control" placeholder="Search Devices...">
        <div class="text-right mb-3">
            <a href="add_device.php" class="btn btn-primary"><i class="fas fa-plus"></i> Add Device</a>
        </div>
        <div class="d-flex justify-content-between mb-3">
            <div>
                <form method="GET" action="">
                    <label for="items-per-page">Items per page:</label>
                    <select id="items-per-page" name="items_per_page" onchange="this.form.submit()">
                        <?php foreach ($itemsPerPageOptions as $option): ?>
                            <option value="<?php echo $option; ?>" <?php if ($option == $itemsPerPage) echo 'selected'; ?>><?php echo $option; ?></option>
                        <?php endforeach; ?>
                    </select>
                    <noscript><input type="submit" value="Submit"></noscript>
                </form>
            </div>
        </div>
        <?php if (empty($devices)): ?>
            <p class="text-center">No devices found.</p>
        <?php else: ?>
            <table class="table table-bordered" id="devices-table">
                <thead class="thead-dark">
                    <tr>
                        <th>Device Name</th>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Device ID</th>
                        <th>Firmware Version</th>
                        <th>External IP Address</th>
                        <th>Groups</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($devices as $device): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($device['name']); ?></td>
                            <td><?php echo htmlspecialchars($device['ip']); ?></td>
                            <td><?php echo htmlspecialchars($device['mac']); ?></td>
                            <td><?php echo htmlspecialchars($device['device_id']); ?></td>
                            <td><?php echo htmlspecialchars($device['firmware_version']); ?></td>
                            <td><?php echo htmlspecialchars($device['external_ip']); ?></td>
                            <td>
                                <?php
                                $stmt = $db->prepare("SELECT g.name FROM groups g JOIN device_groups dg ON g.id = dg.group_id WHERE dg.device_id = :device_id");
                                $stmt->bindParam(':device_id', $device['id'], PDO::PARAM_INT);
                                $stmt->execute();
                                $groups = $stmt->fetchAll(PDO::FETCH_COLUMN);
                                echo htmlspecialchars(implode(', ', $groups));
                                ?>
                            </td>
                            <td>
                                <div class="btn-group" role="group" aria-label="Device Actions">
                                    <a href="edit_device.php?id=<?php echo $device['id']; ?>" class="btn btn-secondary btn-sm"><i class="fas fa-edit"></i> Edit</a>
                                    <?php if ($_SESSION['role'] === 'admin'): ?>
                                        <a href="assign_device_groups.php?id=<?php echo $device['id']; ?>" class="btn btn-primary btn-sm"><i class="fas fa-users"></i> Assign Groups</a>
                                    <?php endif; ?>
                                    <button type="button" class="btn btn-info btn-sm" data-toggle="modal" data-target="#uploadModal<?php echo $device['id']; ?>"><i class="fas fa-upload"></i> Upload .bin</button>
                                    <button type="button" class="btn btn-warning btn-sm" data-toggle="modal" data-target="#updateModal<?php echo $device['id']; ?>"><i class="fas fa-sync"></i> Update Version</button>
                                    <button type="button" class="btn btn-success btn-sm" data-toggle="modal" data-target="#loadModal<?php echo $device['id']; ?>"><i class="fas fa-file-alt"></i> Load Archive</button>
                                    <button type="button" class="btn btn-danger btn-sm" data-toggle="modal" data-target="#restartModal<?php echo $device['id']; ?>"><i class="fas fa-sync"></i> Restart</button>
                                    <form method="POST" action="" class="d-inline" onsubmit="return confirm('Are you sure you want to delete this device?');">
                                        <input type="hidden" name="csrf_token" value="<?php echo $token; ?>">
                                        <input type="hidden" name="device_id" value="<?php echo $device['id']; ?>">
                                        <div class="custom-control custom-checkbox d-inline">
                                            <input type="checkbox" class="custom-control-input" id="deleteArchives<?php echo $device['id']; ?>" name="delete_archives">
                                            <label class="custom-control-label" for="deleteArchives<?php echo $device['id']; ?>" data-toggle="tooltip" data-placement="top" title="Delete all archived firmware files for this device">Delete Archives</label>
                                        </div>
                                        <button type="submit" name="delete_device" class="btn btn-danger btn-sm"><i class="fas fa-trash"></i> Delete</button>
                                    </form>
                                </div>

                                <!-- Upload Modal -->
                                <div class="modal fade" id="uploadModal<?php echo $device['id']; ?>" tabindex="-1" role="dialog" aria-labelledby="uploadModalLabel<?php echo $device['id']; ?>" aria-hidden="true">
                                    <div class="modal-dialog" role="document">
                                        <div class="modal-content">
                                            <div class="modal-header">
                                                <h5 class="modal-title" id="uploadModalLabel<?php echo $device['id']; ?>">Upload .bin for <?php echo htmlspecialchars($device['name']); ?></h5>
                                                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                                    <span aria-hidden="true">&times;</span>
                                                </button>
                                            </div>
                                            <div class="modal-body">
                                                <form method="POST" action="" enctype="multipart/form-data">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $token; ?>">
                                                    <input type="hidden" name="device_id" value="<?php echo $device['id']; ?>">
                                                    <input type="file" name="bin_file" class="form-control-file" required>
                                                    <button type="submit" name="upload_bin" class="btn btn-info mt-3"><i class="fas fa-upload"></i> Upload .bin</button>
                                                </form>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <!-- Update Modal -->
                                <div class="modal fade" id="updateModal<?php echo $device['id']; ?>" tabindex="-1" role="dialog" aria-labelledby="updateModalLabel<?php echo $device['id']; ?>" aria-hidden="true">
                                    <div class="modal-dialog" role="document">
                                        <div class="modal-content">
                                            <div class="modal-header">
                                                <h5 class="modal-title" id="updateModalLabel<?php echo $device['id']; ?>">Update Firmware Version for <?php echo htmlspecialchars($device['name']); ?></h5>
                                                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                                    <span aria-hidden="true">&times;</span>
                                                </button>
                                            </div>
                                            <div class="modal-body">
                                                <form method="POST" action="">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $token; ?>">
                                                    <input type="hidden" name="device_id" value="<?php echo $device['id']; ?>">
                                                    <input type="text" name="firmware_version" class="form-control" placeholder="New Version" required>
                                                    <button type="submit" name="update_version" class="btn btn-warning mt-3"><i class="fas fa-sync"></i> Update Version</button>
                                                </form>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <!-- Load Archive Modal -->
                                <div class="modal fade" id="loadModal<?php echo $device['id']; ?>" tabindex="-1" role="dialog" aria-labelledby="loadModalLabel<?php echo $device['id']; ?>" aria-hidden="true">
                                    <div class="modal-dialog" role="document">
                                        <div class="modal-content">
                                            <div class="modal-header">
                                                <h5 class="modal-title" id="loadModalLabel<?php echo $device['id']; ?>">Load Firmware from Archive for <?php echo htmlspecialchars($device['name']); ?></h5>
                                                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                                    <span aria-hidden="true">&times;</span>
                                                </button>
                                            </div>
                                            <div class="modal-body">
                                                <form method="POST" action="">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $token; ?>">
                                                    <input type="hidden" name="device_id" value="<?php echo $device['id']; ?>">
                                                    <select name="archive_file" class="form-control" required>
                                                        <option value="" disabled selected>Select Archive</option>
                                                        <?php
                                                        $archiveFiles = glob(BASE_DIR . "{$device['mac']}_*.bin");
                                                        foreach ($archiveFiles as $file) {
                                                            $filename = basename($file);
                                                            echo "<option value=\"$filename\">$filename</option>";
                                                        }
                                                        ?>
                                                    </select>
                                                    <button type="submit" name="load_bin" class="btn btn-success mt-3"><i class="fas fa-file-alt"></i> Load Archive</button>
                                                </form>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <!-- Restart Modal -->
                                <div class="modal fade" id="restartModal<?php echo $device['id']; ?>" tabindex="-1" role="dialog" aria-labelledby="restartModalLabel<?php echo $device['id']; ?>" aria-hidden="true">
                                    <div class="modal-dialog" role="document">
                                        <div class="modal-content">
                                            <div class="modal-header">
                                                <h5 class="modal-title" id="restartModalLabel<?php echo $device['id']; ?>">Restart Device: <?php echo htmlspecialchars($device['name']); ?></h5>
                                                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                                    <span aria-hidden="true">&times;</span>
                                                </button>
                                            </div>
                                            <div class="modal-body">
                                                <form method="POST" action="">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $token; ?>">
                                                    <input type="hidden" name="device_id" value="<?php echo $device['id']; ?>">
                                                    <div class="form-group">
                                                        <label>IP Address Type:</label>
                                                        <select name="ip_type" class="form-control" required>
                                                            <option value="internal">Internal IP (<?php echo htmlspecialchars($device['ip']); ?>)</option>
                                                            <option value="external">External IP (<?php echo htmlspecialchars($device['external_ip']); ?>)</option>
                                                        </select>
                                                    </div>
                                                    <div class="form-group">
                                                        <label>Port:</label>
                                                        <input type="number" name="port" class="form-control" value="80" required>
                                                    </div>
                                                    <div class="form-group">
                                                        <label>Username:</label>
                                                        <input type="text" name="username" class="form-control" required>
                                                    </div>
                                                    <div class="form-group">
                                                        <label>Password:</label>
                                                        <input type="password" name="password" class="form-control" required>
                                                    </div>
                                                    <button type="submit" name="restart_device" class="btn btn-danger"><i class="fas fa-sync"></i> Restart Device</button>
                                                </form>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <!-- Pagination Controls -->
            <?php echo renderPagination($totalPages, $page, $itemsPerPage); ?>
        <?php endif; ?>
        <div class="text-center mt-4">
            <a href="index.php" class="btn btn-secondary"><i class="fas fa-home"></i> Back to Main Menu</a>
        </div>
    </div>

    <!-- About Modal -->
   <div class="modal fade" id="aboutModal" tabindex="-1" role="dialog" aria-labelledby="aboutModalLabel" aria-hidden="true">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="aboutModalLabel">About</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <center>IOTAfy<br>Devices Management Platform<br>created by<br>Ioannis Panagou</center>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    <script>
        $(document).ready(function() {
            $("#search-input").on("keyup", function() {
                var value = $(this).val().toLowerCase();
                $("#devices-table tbody tr").filter(function() {
                    $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
                });
            });
        });
    </script>
</body>
</html>


