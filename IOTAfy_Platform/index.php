<?php
session_start();

require 'config.inc'; // Include the configuration file

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$user_id = $_SESSION['user_id'];
$user_role = $_SESSION['role'];

// Fetch user's devices
$db = getDbConnection();
try {
    $stmt = $db->prepare("
        SELECT d.*, u.username, u.full_name, u.email,
               CASE 
                   WHEN d.status = 'online' THEN 'Online'
                   WHEN d.status = 'offline' THEN 'Offline'
                   ELSE 'Never'
               END as status
        FROM devices d
        LEFT JOIN users u ON d.user_id = u.id
        WHERE d.user_id = :user_id
        ORDER BY d.name
    ");
    $stmt->execute(['user_id' => $user_id]);
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Error fetching devices: " . $e->getMessage();
    logMessage("Error fetching devices: " . $e->getMessage() . " by user {$_SESSION['user_id']}");
}

// Fetch devices assigned to user's groups
try {
    $stmt = $db->prepare("
        SELECT DISTINCT d.*, u.username, u.full_name, u.email,
               CASE 
                   WHEN d.status = 'online' THEN 'Online'
                   WHEN d.status = 'offline' THEN 'Offline'
                   ELSE 'Never'
               END as status
        FROM devices d
        LEFT JOIN users u ON d.user_id = u.id
        INNER JOIN device_groups dg ON d.id = dg.device_id
        INNER JOIN user_groups ug ON dg.group_id = ug.group_id
        WHERE ug.user_id = :user_id AND d.user_id != :user_id
        ORDER BY d.name
    ");
    $stmt->execute(['user_id' => $user_id]);
    $group_devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Error fetching group devices: " . $e->getMessage();
    logMessage("Error fetching group devices: " . $e->getMessage() . " by user {$_SESSION['user_id']}");
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IOTAfy - Device Management</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" rel="stylesheet">
    <style>
        .status-badge {
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.9rem;
        }
        .status-online {
            background-color: #28a745;
            color: white;
        }
        .status-offline {
            background-color: #dc3545;
            color: white;
        }
        .status-never {
            background-color: #6c757d;
            color: white;
        }
        .table {
            background-color: white;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .table thead th {
            background-color: #343a40;
            color: white;
            border-bottom: none;
            font-weight: 500;
        }
        .table tbody tr:hover {
            background-color: #f8f9fa;
        }
        .table td {
            vertical-align: middle;
        }
        .btn-group {
            display: flex;
            gap: 5px;
        }
        .btn-group .btn {
            padding: 0.25rem 0.5rem;
        }
        .table-responsive {
            margin-bottom: 20px;
        }
        .section-title {
            color: #343a40;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #343a40;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="index.php">IOTAfy</a>
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
                <?php if (in_array($user_role, ['admin', 'superuser'])): ?>
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
        <h1 class="text-center mb-4">Welcome to IOTAfy Device Management</h1>
        
        <?php if (!empty($error)): ?>
            <div class="alert alert-danger text-center"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <!-- My Devices Section -->
        <h2 class="section-title">My Devices</h2>
        <?php if (empty($devices)): ?>
            <div class="alert alert-info text-center">No devices assigned to you.</div>
        <?php else: ?>
            <div class="table-responsive">
                <table class="table table-hover table-bordered">
                    <thead class="thead-dark">
                        <tr>
                            <th>Device Name</th>
                            <th>Status</th>
                            <th>MAC Address</th>
                            <th>IP Address</th>
                            <th>Last Seen</th>
                            <?php if ($_SESSION['role'] === 'admin'): ?>
                                <th>Actions</th>
                            <?php endif; ?>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($devices as $device): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($device['name']); ?></td>
                                <td>
                                    <span class="status-badge status-<?php echo strtolower($device['status']); ?>">
                                        <?php echo $device['status']; ?>
                                    </span>
                                </td>
                                <td><?php echo htmlspecialchars($device['mac']); ?></td>
                                <td><?php echo htmlspecialchars($device['ip']); ?></td>
                                <td>
                                    <?php 
                                    if ($device['last_ping']) {
                                        $last_seen = new DateTime($device['last_ping']);
                                        echo $last_seen->format('d/m/Y H:i:s');
                                    } else {
                                        echo 'Never';
                                    }
                                    ?>
                                </td>
                                <?php if ($_SESSION['role'] === 'admin'): ?>
                                    <td>
                                        <div class="btn-group">
                                            <a href="edit_device.php?id=<?php echo $device['id']; ?>" class="btn btn-sm btn-info" title="Edit Device">
                                                <i class="fas fa-edit"></i>
                                            </a>
                                            <a href="assign_device_groups.php?id=<?php echo $device['id']; ?>" class="btn btn-sm btn-primary" title="Assign Groups">
                                                <i class="fas fa-users"></i>
                                            </a>
                                        </div>
                                    </td>
                                <?php endif; ?>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <!-- Group Devices Section -->
        <h2 class="section-title">Group Devices</h2>
        <?php if (empty($group_devices)): ?>
            <div class="alert alert-info text-center">No devices assigned to your groups.</div>
        <?php else: ?>
            <div class="table-responsive">
                <table class="table table-hover table-bordered">
                    <thead class="thead-dark">
                        <tr>
                            <th>Device Name</th>
                            <th>Status</th>
                            <th>MAC Address</th>
                            <th>IP Address</th>
                            <th>Assigned To</th>
                            <th>Last Seen</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($group_devices as $device): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($device['name']); ?></td>
                                <td>
                                    <span class="status-badge status-<?php echo strtolower($device['status']); ?>">
                                        <?php echo $device['status']; ?>
                                    </span>
                                </td>
                                <td><?php echo htmlspecialchars($device['mac']); ?></td>
                                <td><?php echo htmlspecialchars($device['ip']); ?></td>
                                <td>
                                    <?php echo htmlspecialchars($device['full_name']); ?>
                                    <small class="text-muted">(<?php echo htmlspecialchars($device['username']); ?>)</small>
                                </td>
                                <td>
                                    <?php 
                                    if ($device['last_ping']) {
                                        $last_seen = new DateTime($device['last_ping']);
                                        echo $last_seen->format('d/m/Y H:i:s');
                                    } else {
                                        echo 'Never';
                                    }
                                    ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
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

    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>


