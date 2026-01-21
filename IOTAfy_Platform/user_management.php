<?php
// user_management.php

require 'config.inc'; // Include the configuration file

// Ensure the user is logged in and is an admin
//session_start();
if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    logMessage("Unauthorized access attempt to user management page.");
    header('Location: login.php');
    exit;
}

$db = getDbConnection();
$message = "";
$error = "";

// Handle user deletion
if (isset($_POST['delete_user']) && isset($_POST['user_id'])) {
    $user_id = $_POST['user_id'];

    try {
        // Start transaction
        $db->beginTransaction();

        // Delete user's group assignments
        $stmt = $db->prepare("DELETE FROM user_groups WHERE user_id = :user_id");
        $stmt->execute(['user_id' => $user_id]);

        // Delete user
        $stmt = $db->prepare("DELETE FROM users WHERE id = :user_id");
        $stmt->execute(['user_id' => $user_id]);

        // Commit transaction
        $db->commit();

            $message = "User deleted successfully.";
        logMessage("User ID: $user_id deleted by user {$_SESSION['user_id']}");
    } catch (PDOException $e) {
        // Rollback transaction on error
        $db->rollBack();
        $error = "Error deleting user: " . $e->getMessage();
        logMessage("Error deleting user: " . $e->getMessage() . " by user {$_SESSION['user_id']}");
    }
}

// Handle user status change (activate/deactivate)
if (isset($_POST['toggle_status']) && isset($_POST['user_id'])) {
    $user_id = $_POST['user_id'];
    $new_status = $_POST['new_status'];
    
    try {
        $stmt = $db->prepare("UPDATE users SET is_active = :status WHERE id = :user_id");
        $stmt->execute([
            'user_id' => $user_id,
            'status' => $new_status
        ]);

        $message = $new_status ? "User activated successfully." : "User deactivated successfully.";
        logMessage("User ID: $user_id " . ($new_status ? "activated" : "deactivated") . " by user {$_SESSION['user_id']}");
    } catch (PDOException $e) {
        $error = "Error updating user status: " . $e->getMessage();
        logMessage("Error updating user status: " . $e->getMessage() . " by user {$_SESSION['user_id']}");
    }
}

// Handle authkey regeneration
if (isset($_POST['regenerate_authkey']) && isset($_POST['user_id'])) {
    $user_id = $_POST['user_id'];
    
    try {
        $new_authkey = bin2hex(random_bytes(16));
        $stmt = $db->prepare("UPDATE users SET authkey = :authkey WHERE id = :user_id");
        $stmt->execute([
            'user_id' => $user_id,
            'authkey' => $new_authkey
        ]);

            $message = "Authkey regenerated successfully.";
        logMessage("Authkey regenerated for user ID: $user_id by user {$_SESSION['user_id']}");
    } catch (PDOException $e) {
        $error = "Error regenerating authkey: " . $e->getMessage();
        logMessage("Error regenerating authkey: " . $e->getMessage() . " by user {$_SESSION['user_id']}");
    }
}

// Handle device assignment
if (isset($_POST['assign_device']) && isset($_POST['user_id']) && isset($_POST['device_id'])) {
    $user_id = $_POST['user_id'];
    $device_id = $_POST['device_id'];
    
    try {
        // Check if device is already assigned
        $stmt = $db->prepare("SELECT COUNT(*) FROM devices WHERE id = :device_id AND user_id IS NOT NULL");
        $stmt->execute(['device_id' => $device_id]);
        if ($stmt->fetchColumn() > 0) {
            $error = "Device is already assigned to another user.";
        } else {
            $stmt = $db->prepare("UPDATE devices SET user_id = :user_id WHERE id = :device_id");
            $stmt->execute([
                'user_id' => $user_id,
                'device_id' => $device_id
            ]);

            $message = "Device assigned successfully.";
            logMessage("Device ID: $device_id assigned to user ID: $user_id by user {$_SESSION['user_id']}");
        }
    } catch (PDOException $e) {
        $error = "Error assigning device: " . $e->getMessage();
        logMessage("Error assigning device: " . $e->getMessage() . " by user {$_SESSION['user_id']}");
    }
}

// Handle device unassignment
if (isset($_POST['unassign_device']) && isset($_POST['device_id'])) {
        $device_id = $_POST['device_id'];
    
    try {
        $stmt = $db->prepare("UPDATE devices SET user_id = NULL WHERE id = :device_id");
        $stmt->execute(['device_id' => $device_id]);

            $message = "Device unassigned successfully.";
        logMessage("Device ID: $device_id unassigned by user {$_SESSION['user_id']}");
    } catch (PDOException $e) {
        $error = "Error unassigning device: " . $e->getMessage();
        logMessage("Error unassigning device: " . $e->getMessage() . " by user {$_SESSION['user_id']}");
    }
}

// Handle account locking/unlocking
if (isset($_POST['toggle_lock']) && isset($_POST['user_id'])) {
    $user_id = $_POST['user_id'];
    $new_lock_status = $_POST['new_lock_status'];
    
    try {
        if ($new_lock_status) {
            // Lock account by admin
            $stmt = $db->prepare("
                UPDATE users 
                SET locked_until = datetime('now', '+' || :duration || ' minutes'),
                    failed_login_attempts = :max_attempts,
                    admin_locked = 1
                WHERE id = :user_id
            ");
            $stmt->execute([
                'user_id' => $user_id,
                'duration' => 1440, // 24 hours
                'max_attempts' => 999 // Effectively lock the account
            ]);
            $message = "Account locked successfully.";
        } else {
            // Unlock account by admin
            $stmt = $db->prepare("
                UPDATE users 
                SET locked_until = NULL,
                    failed_login_attempts = 0,
                    admin_locked = 0
                WHERE id = :user_id
            ");
            $stmt->execute(['user_id' => $user_id]);
            $message = "Account unlocked successfully.";
        }
        logMessage("User ID: $user_id " . ($new_lock_status ? "locked" : "unlocked") . " by user {$_SESSION['user_id']}");
    } catch (PDOException $e) {
        $error = "Error updating account lock status: " . $e->getMessage();
        logMessage("Error updating account lock status: " . $e->getMessage() . " by user {$_SESSION['user_id']}");
    }
}

// Fetch all users with their group information
try {
    $stmt = $db->query("
        SELECT u.*, 
               GROUP_CONCAT(g.name) as group_names,
               CASE 
                   WHEN u.locked_until IS NOT NULL AND datetime(u.locked_until) > datetime('now') 
                   THEN 1 
                   ELSE 0 
               END as is_locked,
               CASE 
                   WHEN u.locked_until IS NOT NULL AND datetime(u.locked_until) > datetime('now')
                   THEN round((julianday(u.locked_until) - julianday('now')) * 24 * 60)
                   ELSE 0
               END as remaining_lockout_minutes,
               (SELECT MAX(timestamp) 
                FROM login_attempts 
                WHERE username = u.username AND success = 1) as last_login
        FROM users u
        LEFT JOIN user_groups ug ON u.id = ug.user_id
        LEFT JOIN groups g ON ug.group_id = g.id
        GROUP BY u.id
        ORDER BY u.username
    ");
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Error fetching users: " . $e->getMessage();
    logMessage("Error fetching users: " . $e->getMessage() . " by user {$_SESSION['user_id']}");
}

// Fetch all devices
try {
    $stmt = $db->query("
        SELECT d.*, u.username as assigned_to
        FROM devices d
        LEFT JOIN users u ON d.user_id = u.id
        WHERE d.user_id IS NULL
        ORDER BY d.name
    ");
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Error fetching devices: " . $e->getMessage();
    logMessage("Error fetching devices: " . $e->getMessage() . " by user {$_SESSION['user_id']}");
}

// Handle search input
$search = isset($_GET['search']) ? $_GET['search'] : '';

// Handle items per page input
$items_per_page = isset($_GET['items_per_page']) ? (int)$_GET['items_per_page'] : 10;
$current_page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$offset = ($current_page - 1) * $items_per_page;

// Fetch total users count for pagination calculation
$total_users_stmt = $db->prepare("SELECT COUNT(*) FROM users WHERE username LIKE :search OR email LIKE :search OR full_name LIKE :search");
$search_param = '%' . $search . '%';
$total_users_stmt->bindParam(':search', $search_param);
$total_users_stmt->execute();
$total_users = $total_users_stmt->fetchColumn();
$total_pages = ceil($total_users / $items_per_page);

function renderPaginationControls($current_page, $total_pages, $search, $items_per_page) {
    if ($total_pages <= 1) {
        return '';
    }

    $pagination_html = '<nav aria-label="Page navigation"><ul class="pagination justify-content-center">';

    if ($current_page > 1) {
        $pagination_html .= '<li class="page-item"><a class="page-link" href="?search=' . urlencode($search) . '&items_per_page=' . $items_per_page . '&page=' . ($current_page - 1) . '">Previous</a></li>';
    }

    for ($page = 1; $page <= $total_pages; $page++) {
        $active_class = $page == $current_page ? 'active' : '';
        $pagination_html .= '<li class="page-item ' . $active_class . '"><a class="page-link" href="?search=' . urlencode($search) . '&items_per_page=' . $items_per_page . '&page=' . $page . '">' . $page . '</a></li>';
    }

    if ($current_page < $total_pages) {
        $pagination_html .= '<li class="page-item"><a class="page-link" href="?search=' . urlencode($search) . '&items_per_page=' . $items_per_page . '&page=' . ($current_page + 1) . '">Next</a></li>';
    }

    $pagination_html .= '</ul></nav>';

    return $pagination_html;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" rel="stylesheet">
    <style>
        .card {
            margin: 10px 0;
            transition: transform 0.2s;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .card:hover {
            transform: translateY(-5px);
        }
        .user-card {
            border-left: 4px solid #007bff;
            margin-bottom: 15px;
        }
        .user-card.admin {
            border-left-color: #28a745;
        }
        .user-card.locked {
            border-left-color: #dc3545;
        }
        .status-badge {
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.9rem;
        }
        .status-active {
            background-color: #28a745;
            color: white;
        }
        .status-locked {
            background-color: #dc3545;
            color: white;
        }
        .status-secondary {
            background-color: #fd7e14; /* orange */
            color: white;
        }
        .filter-section {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .table th {
            background-color: #f8f9fa;
        }
        .action-buttons .btn {
            margin: 0 2px;
        }
        .modal-header {
            background-color: #f8f9fa;
        }
        .user-info {
            font-size: 0.9rem;
            color: #6c757d;
        }
        .last-login {
            font-size: 0.8rem;
            color: #6c757d;
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
                    <a class="nav-link dropdown-toggle active" href="#" id="usersDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        <i class="fas fa-users"></i> Users
                    </a>
                    <div class="dropdown-menu" aria-labelledby="usersDropdown">
                        <a class="dropdown-item active" href="user_management.php">
                            <i class="fas fa-user-cog"></i> Manage Users
                        </a>
                        <a class="dropdown-item" href="group_management.php">
                            <i class="fas fa-users-cog"></i> Manage Groups
                        </a>
                    </div>
                </li>
                <?php endif; ?>
                
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="devicesDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        <i class="fas fa-microchip"></i> Devices
                    </a>
                    <div class="dropdown-menu" aria-labelledby="devicesDropdown">
                        <a class="dropdown-item" href="device_management.php">
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
        <h1 class="text-center mb-4">User Management</h1>
        
        <?php if (!empty($message)): ?>
            <div class="alert alert-info text-center"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>

        <?php if (!empty($error)): ?>
            <div class="alert alert-danger text-center"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <!-- Filter Section -->
        <div class="filter-section">
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label for="searchInput"><i class="fas fa-search"></i> Search Users:</label>
                        <input type="text" class="form-control" id="searchInput" placeholder="Search by username, email, or full name...">
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label for="roleFilter"><i class="fas fa-user-tag"></i> Role Filter:</label>
                        <select class="form-control" id="roleFilter">
                            <option value="all">All Roles</option>
                            <option value="admin">Admin</option>
                            <option value="user">User</option>
                        </select>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label for="statusFilter"><i class="fas fa-toggle-on"></i> Status Filter:</label>
                        <select class="form-control" id="statusFilter">
                            <option value="all">All Status</option>
                            <option value="active">Active</option>
                            <option value="locked">Locked</option>
                        </select>
        </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label for="twofaFilter"><i class="fas fa-shield-alt"></i> 2FA Filter:</label>
                        <select class="form-control" id="twofaFilter">
                            <option value="all">All</option>
                            <option value="enabled">2FA Enabled</option>
                            <option value="disabled">2FA Disabled</option>
                        </select>
                    </div>
                </div>
            </div>
        </div>

        <!-- Add User Button -->
        <div class="text-right mb-3">
            <a href="add_user.php" class="btn btn-primary">
                <i class="fas fa-user-plus"></i> Add New User
            </a>
            </div>

        <?php if (empty($users)): ?>
            <div class="alert alert-info text-center">No users found.</div>
        <?php else: ?>
            <div class="row">
                <?php foreach ($users as $user): ?>
                    <div class="col-md-6">
                        <div class="card user-card <?php echo $user['role'] === 'admin' ? 'admin' : ''; ?> <?php echo $user['is_locked'] ? 'locked' : ''; ?>" data-twofa="<?php echo !empty($user['twofa_enabled']) ? 'enabled' : 'disabled'; ?>">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <h5 class="card-title">
                                            <?php echo htmlspecialchars($user['username']); ?>
                                            <?php if ($user['role'] === 'admin'): ?>
                                                <i class="fas fa-shield-alt text-success"></i>
                                            <?php endif; ?>
                                        </h5>
                                        <p class="card-text">
                                            <i class="fas fa-user"></i> <?php echo htmlspecialchars($user['full_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?><br>
                                            <i class="fas fa-envelope"></i> <?php echo htmlspecialchars($user['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?>
                                        </p>
                                        <div class="user-info">
                                            <span class="status-badge <?php echo $user['is_locked'] ? 'status-locked' : ($user['is_active'] ? 'status-active' : 'status-secondary'); ?>">
                                                <?php echo $user['is_locked'] ? 'Locked' : ($user['is_active'] ? 'Active' : 'Inactive'); ?>
                                            </span>
                                            <span class="ml-2">
                                                <?php if (!empty($user['twofa_enabled'])): ?>
                                                    <i class="fas fa-shield-alt text-success" title="2FA Enabled"></i> 2FA Enabled
                                                <?php else: ?>
                                                    <i class="fas fa-shield-alt text-muted" title="2FA Disabled"></i> 2FA Disabled
                                                <?php endif; ?>
                                            </span>
                                            <span class="ml-2">
                                                <i class="fas fa-clock"></i> Last Login: 
                                    <?php
                                                if (isset($user['last_login']) && $user['last_login']) {
                                                    $last_login = new DateTime($user['last_login']);
                                                    echo $last_login->format('d/m/Y H:i:s');
                                                } else {
                                                    echo 'Never';
                                                }
                                                ?>
                                            </span>
                                        </div>
                                        <div class="mt-2">
                                            <small class="text-muted">
                                                <i class="fas fa-key"></i> Authkey: <?php echo htmlspecialchars($user['authkey'] ?? '', ENT_QUOTES, 'UTF-8'); ?>
                                            </small>
                                        </div>
                                        <div class="mt-2">
                                            <small class="text-muted">
                                                <i class="fas fa-microchip"></i> Devices:
                                                <?php
                                                $user_devices = getUserDevices($user['id']);
                                                if (empty($user_devices)) {
                                                    echo " No devices assigned";
                                                } else {
                                                    foreach ($user_devices as $device) {
                                                        echo "<br>" . htmlspecialchars($device['name'] ?? '', ENT_QUOTES, 'UTF-8');
                                                    }
                                                }
                                                ?>
                                            </small>
                                        </div>
                                        <?php if (!empty($user_devices)): ?>
                                            <!-- Hidden select per user to τροφοδοτεί το Unassign modal χωρίς AJAX -->
                                            <select id="user-devices-<?php echo $user['id']; ?>" class="d-none">
                                                <?php foreach ($user_devices as $device): ?>
                                                    <option value="<?php echo $device['id']; ?>">
                                                        <?php echo htmlspecialchars($device['name'] ?? 'Unnamed', ENT_QUOTES, 'UTF-8'); ?>
                                                        (<?php echo htmlspecialchars($device['mac'] ?? 'n/a', ENT_QUOTES, 'UTF-8'); ?>)
                                                    </option>
                                                <?php endforeach; ?>
                                            </select>
                                        <?php endif; ?>
                                    </div>
                                    <div class="action-buttons">
                                        <a href="edit_user.php?id=<?php echo $user['id']; ?>" class="btn btn-sm btn-info" title="Edit User">
                                            <i class="fas fa-edit"></i>
                                        </a>
                                        <a href="assign_user_groups.php?id=<?php echo $user['id']; ?>" class="btn btn-sm btn-primary" title="Assign Groups">
                                            <i class="fas fa-users"></i>
                                        </a>
                                        <?php if (!empty($user_devices)): ?>
                                            <button type="button" class="btn btn-sm btn-danger" title="Unassign Device" data-toggle="modal" data-target="#unassignDeviceModal" data-user-id="<?php echo $user['id']; ?>">
                                                <i class="fas fa-minus-circle"></i>
                                            </button>
                                    <?php endif; ?>
                                        <button type="button" class="btn btn-sm btn-warning" title="Assign Device" data-toggle="modal" data-target="#assignDeviceModal" data-user-id="<?php echo $user['id']; ?>">
                                            <i class="fas fa-plus-circle"></i>
                                        </button>
                                        <form method="POST" action="" class="d-inline">
                                    <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                            <input type="hidden" name="new_status" value="<?php echo $user['is_active'] ? '0' : '1'; ?>">
                                            <button type="submit" name="toggle_status" class="btn btn-sm btn-<?php echo $user['is_active'] ? 'warning' : 'success'; ?>" title="Toggle Status">
                                                <i class="fas fa-<?php echo $user['is_active'] ? 'ban' : 'check'; ?>"></i>
                                            </button>
                                </form>
                                        <form method="POST" action="" class="d-inline">
                                    <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                            <input type="hidden" name="new_lock_status" value="<?php echo $user['is_locked'] ? '0' : '1'; ?>">
                                            <button type="submit" name="toggle_lock" class="btn btn-sm btn-<?php echo $user['is_locked'] ? 'success' : 'warning'; ?>" title="<?php echo $user['is_locked'] ? 'Unlock Account' : 'Lock Account'; ?>">
                                                <i class="fas fa-<?php echo $user['is_locked'] ? 'unlock' : 'lock'; ?>"></i>
                                            </button>
                                </form>
                                        <form method="POST" action="" class="d-inline">
                                            <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                            <button type="submit" name="regenerate_authkey" class="btn btn-sm btn-secondary" title="Regenerate Authkey">
                                                <i class="fas fa-key"></i>
                                            </button>
                                        </form>
                                        <form method="POST" action="" class="d-inline" onsubmit="return confirm('Are you sure you want to delete this user?');">
                                            <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                            <button type="submit" name="delete_user" class="btn btn-sm btn-danger" title="Delete User">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- Pagination -->
            <?php echo renderPaginationControls($current_page, $total_pages, $search, $items_per_page); ?>
        <?php endif; ?>

        <div class="text-center mt-4">
            <a href="index.php" class="btn btn-secondary">
                <i class="fas fa-home"></i> Back to Main Menu
            </a>
        </div>
    </div>

    <!-- Assign Device Modal -->
    <div class="modal fade" id="assignDeviceModal" tabindex="-1" role="dialog" aria-labelledby="assignDeviceModalLabel" aria-hidden="true">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <form method="POST" action="">
                    <div class="modal-header">
                        <h5 class="modal-title" id="assignDeviceModalLabel">Assign Device</h5>
                        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                            <span aria-hidden="true">&times;</span>
                        </button>
                    </div>
                    <div class="modal-body">
                        <input type="hidden" name="user_id" id="assign_user_id">
                        <div class="form-group">
                            <label for="device_id">Select Device:</label>
                            <select name="device_id" id="device_id" class="form-control">
                                <?php if (empty($devices)): ?>
                                    <option value="" disabled>No available devices</option>
                                <?php else: ?>
                                <?php foreach ($devices as $device): ?>
                                        <option value="<?php echo $device['id']; ?>">
                                            <?php echo htmlspecialchars($device['name'] ?? ''); ?> 
                                            (<?php echo htmlspecialchars($device['mac'] ?? ''); ?>)
                                        </option>
                                <?php endforeach; ?>
                                <?php endif; ?>
                            </select>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                        <button type="submit" name="assign_device" class="btn btn-primary">Assign Device</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Unassign Device Modal -->
    <div class="modal fade" id="unassignDeviceModal" tabindex="-1" role="dialog" aria-labelledby="unassignDeviceModalLabel" aria-hidden="true">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <form method="POST" action="">
                    <div class="modal-header">
                        <h5 class="modal-title" id="unassignDeviceModalLabel">Unassign Device</h5>
                        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                            <span aria-hidden="true">&times;</span>
                        </button>
                    </div>
                    <div class="modal-body">
                        <input type="hidden" name="user_id" id="unassign_user_id">
                        <div class="form-group">
                            <label for="unassign_device_id">Select Device:</label>
                            <select name="device_id" id="unassign_device_id" class="form-control">
                                <!-- Options will be populated dynamically via JavaScript -->
                            </select>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                        <button type="submit" name="unassign_device" class="btn btn-danger">Unassign Device</button>
                    </div>
                </form>
            </div>
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
                    <center>
                        <strong>IOTAfy</strong><br>
                        Devices Management Platform<br>
                        <br>
                        <strong>University of West Attica</strong><br>
                        <strong>TelSiP Research Lab</strong><br>
                        <br>
                        Created by: Ioannis Panagou<br>
                        <br>
                        &copy; <?php echo date('Y'); ?> IOTAfy Platform. All rights reserved.
                    </center>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    <script>
        // Filter functionality
        $('#searchInput, #roleFilter, #statusFilter, #twofaFilter').on('change keyup', function() {
            const search = $('#searchInput').val().toLowerCase();
            const role = $('#roleFilter').val();
            const status = $('#statusFilter').val();
            const twofa = $('#twofaFilter').val();
            
            $('.user-card').each(function() {
                const card = $(this);
                const username = card.find('.card-title').text().toLowerCase();
                const email = card.find('.fa-envelope').next().text().toLowerCase();
                const fullName = card.find('.fa-user').next().text().toLowerCase();
                const userRole = card.hasClass('admin') ? 'admin' : 'user';
                const userStatus = card.find('.status-badge').text().toLowerCase();
                const userTwofa = card.data('twofa');
                
                const searchMatch = !search || username.includes(search) || email.includes(search) || fullName.includes(search);
                const roleMatch = role === 'all' || userRole === role;
                const statusMatch = status === 'all' || userStatus.includes(status);
                const twofaMatch = twofa === 'all' || userTwofa === twofa;
                
                card.closest('.col-md-6').toggle(searchMatch && roleMatch && statusMatch && twofaMatch);
            });
        });

        // Modal functionality
        $('#assignDeviceModal').on('show.bs.modal', function (event) {
            var button = $(event.relatedTarget);
            var userId = button.data('user-id');
            var modal = $(this);
            modal.find('#assign_user_id').val(userId);
        });

        $('#unassignDeviceModal').on('show.bs.modal', function (event) {
            var button = $(event.relatedTarget);
            var userId = button.data('user-id');
            var modal = $(this);
            modal.find('#unassign_user_id').val(userId);

            var select = modal.find('#unassign_device_id');
            select.empty();

            // Παίρνουμε τις συσκευές από το κρυφό select του συγκεκριμένου user
            var source = $('#user-devices-' + userId);
            if (source.length && source.find('option').length) {
                source.find('option').each(function () {
                    select.append($(this).clone());
                });
            } else {
                select.append('<option value="" disabled selected>No devices assigned</option>');
            }
        });
    </script>

    <!-- Footer -->
    <footer class="footer mt-5 py-3 bg-light text-center">
        <div class="container">
            <p class="mb-1">
                <strong>University of West Attica</strong> | <strong>TelSiP Research Lab</strong>
            </p>
            <p class="mb-0 text-muted small">
                &copy; <?php echo date('Y'); ?> IOTAfy Platform. All rights reserved.
            </p>
        </div>
    </footer>
</body>
</html>


