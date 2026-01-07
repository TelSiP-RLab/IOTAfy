<?php
// show_devices.php

require 'config.inc'; // Include the configuration file

if (!isset($_SESSION['user_id']) || !checkPermission('view_devices')) {
    header('Location: login.php');
    exit;
}

$db = getDbConnection();
$message = "";

// Define the directory where files will be created
$firmware_dir = BASE_DIR;

// Handle device deletion
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['delete_device'])) {
    $device_id = $_POST['device_id'];
    $stmt = $db->prepare("DELETE FROM device_info WHERE id = :id");
    $stmt->bindParam(':id', $device_id);
    $stmt->execute();
    $message = "Device deleted successfully.";
}

// Handle firmware file generation
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['generate_firmware_file'])) {
    $mac_address = $_POST['mac_address'];
    $firmware_version = $_POST['firmware_version'];
    $file_path = rtrim($firmware_dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $mac_address . '.version';

    // Check if the directory exists, if not, create it
    if (!is_dir($firmware_dir)) {
        mkdir($firmware_dir, 0777, true);
    }

    // Check if the file exists, if not, create it and write the firmware version
    if (!file_exists($file_path)) {
        file_put_contents($file_path, $firmware_version);
        if (file_exists($file_path)) {
            $message = "Firmware file created successfully.";
        } else {
            $message = "Failed to create firmware file.";
        }
    } else {
        $message = "Firmware file already exists.";
    }
}

// Fetch all devices
$devices_stmt = $db->query("SELECT * FROM device_info ORDER BY name");
$devices = $devices_stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Show Devices</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .status-online {
            color: green;
            font-weight: bold;
        }
        .status-offline {
            color: red;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">Devices</h1>
        <?php if (!empty($message)): ?>
            <div class="alert alert-info text-center"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        <?php if (empty($devices)): ?>
            <p class="text-center">No devices found.</p>
        <?php else: ?>
            <table class="table table-bordered">
                <thead class="thead-dark">
                    <tr>
                        <th>Name</th>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Device ID</th>
                        <th>Firmware Version</th>
                        <th>Status</th>
                        <?php if (checkPermission('edit_device') || checkPermission('delete_device') || checkPermission('generate_firmware_file')): ?>
                            <th>Actions</th>
                        <?php endif; ?>
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
                            <td class="<?php echo $device['status'] == 'up' ? 'status-online' : 'status-offline'; ?>">
                                <?php echo htmlspecialchars($device['status']); ?>
                            </td>
                            <?php if (checkPermission('edit_device') || checkPermission('delete_device') || checkPermission('generate_firmware_file')): ?>
                                <td class="actions">
                                    <?php if (checkPermission('edit_device')): ?>
                                        <a href="edit_device.php?id=<?php echo $device['id']; ?>" class="btn btn-secondary btn-sm">Edit</a>
                                    <?php endif; ?>
                                    <?php if (checkPermission('delete_device')): ?>
                                        <form method="POST" action="" class="d-inline" onsubmit="return confirm('Are you sure you want to delete this device?');">
                                            <input type="hidden" name="device_id" value="<?php echo $device['id']; ?>">
                                            <button type="submit" name="delete_device" class="btn btn-danger btn-sm">Delete</button>
                                        </form>
                                    <?php endif; ?>
                                    <?php if (checkPermission('generate_firmware_file')): ?>
                                        <form method="POST" action="" class="d-inline">
                                            <input type="hidden" name="mac_address" value="<?php echo $device['mac']; ?>">
                                            <input type="hidden" name="firmware_version" value="<?php echo $device['firmware_version']; ?>">
                                            <button type="submit" name="generate_firmware_file" class="btn btn-info btn-sm">Generate Firmware File</button>
                                        </form>
                                    <?php endif; ?>
                                </td>
                            <?php endif; ?>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
        <div class="text-center mt-4">
            <a href="index.php" class="btn btn-primary">Back to Main Menu</a>
        </div>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>

