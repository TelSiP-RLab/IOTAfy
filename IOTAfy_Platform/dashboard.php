<?php
require 'config.inc'; // Include the configuration file

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Redirect to login if the user is not authenticated
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// Get database connection
$db = getDbConnection();

// Determine if the current user is an admin
$isAdmin = ($_SESSION['role'] === 'admin');

try {
    // Query to fetch dashboard data
    if ($isAdmin) {
        // Admin can see all devices and total users
        $query = "
            SELECT
                (SELECT COUNT(*) FROM devices) AS totalDevices,
                (SELECT COUNT(*) FROM users) AS totalUsers,
                (SELECT COUNT(*) FROM devices WHERE status = 'online') AS totalOnlineDevices,
                (SELECT COUNT(*) FROM devices WHERE status = 'offline') AS totalOfflineDevices,
                (SELECT COUNT(*) FROM devices WHERE firmware_version IS NOT NULL) AS devicesWithFirmware,
                (SELECT COUNT(*) FROM groups) AS totalGroups
        ";
    } else {
        // Regular user can see only their assigned devices
        $query = "
            SELECT
                (SELECT COUNT(DISTINCT d.id) 
                 FROM devices d
                 LEFT JOIN device_groups dg ON d.id = dg.device_id
                 LEFT JOIN groups g ON dg.group_id = g.id
                 LEFT JOIN user_groups ug ON g.id = ug.group_id
                 WHERE d.user_id = :user_id 
                 OR ug.user_id = :user_id) AS totalDevices,
                (SELECT COUNT(DISTINCT d.id) 
                 FROM devices d
                 LEFT JOIN device_groups dg ON d.id = dg.device_id
                 LEFT JOIN groups g ON dg.group_id = g.id
                 LEFT JOIN user_groups ug ON g.id = ug.group_id
                 WHERE (d.user_id = :user_id 
                 OR ug.user_id = :user_id)
                 AND d.status = 'online') AS totalOnlineDevices,
                (SELECT COUNT(DISTINCT d.id) 
                 FROM devices d
                 LEFT JOIN device_groups dg ON d.id = dg.device_id
                 LEFT JOIN groups g ON dg.group_id = g.id
                 LEFT JOIN user_groups ug ON g.id = ug.group_id
                 WHERE (d.user_id = :user_id 
                 OR ug.user_id = :user_id)
                 AND d.status = 'offline') AS totalOfflineDevices,
                (SELECT COUNT(DISTINCT d.id) 
                 FROM devices d
                 LEFT JOIN device_groups dg ON d.id = dg.device_id
                 LEFT JOIN groups g ON dg.group_id = g.id
                 LEFT JOIN user_groups ug ON g.id = ug.group_id
                 WHERE (d.user_id = :user_id 
                 OR ug.user_id = :user_id)
                 AND d.firmware_version IS NOT NULL) AS devicesWithFirmware,
                (SELECT COUNT(DISTINCT g.id) 
                 FROM groups g 
                 JOIN user_groups ug ON g.id = ug.group_id 
                 WHERE ug.user_id = :user_id) AS totalGroups
        ";
    }

    // Prepare and execute the query
    $stmt = $db->prepare($query);

    if (!$isAdmin) {
        $stmt->bindParam(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    }

    $stmt->execute();
    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    $totalDevices = $result['totalDevices'];
    $totalOnlineDevices = $result['totalOnlineDevices'];
    $totalOfflineDevices = $result['totalOfflineDevices'];
    $devicesWithFirmware = $result['devicesWithFirmware'];
    $totalGroups = $result['totalGroups'];

    // Get total users for admins only
    if ($isAdmin) {
        $totalUsers = $result['totalUsers'];
    }

    // Fetch detailed device data for the devices tab
    if ($isAdmin) {
        $stmtDevices = $db->prepare("SELECT * FROM devices ORDER BY name");
    } else {
        $stmtDevices = $db->prepare("
            SELECT DISTINCT d.* 
            FROM devices d
            LEFT JOIN device_groups dg ON d.id = dg.device_id
            LEFT JOIN groups g ON dg.group_id = g.id
            LEFT JOIN user_groups ug ON g.id = ug.group_id
            WHERE d.user_id = :user_id 
            OR ug.user_id = :user_id
            ORDER BY d.name
        ");
        $stmtDevices->bindParam(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    }

    $stmtDevices->execute();
    $devices = $stmtDevices->fetchAll(PDO::FETCH_ASSOC);

    // Get user's groups
    $stmt = $db->prepare("
        SELECT g.* 
        FROM groups g 
        JOIN user_groups ug ON g.id = ug.group_id 
        WHERE ug.user_id = :user_id
    ");
    $stmt->execute(['user_id' => $_SESSION['user_id']]);
    $user_groups = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Get devices assigned to user's groups
    $stmt = $db->prepare("
        SELECT DISTINCT 
            d.id,
            d.name,
            d.mac,
            d.ip as internal_ip,
            d.external_ip,
            d.status,
            g.name as group_name,
            CASE 
                WHEN d.user_id = :user_id THEN 'Direct'
                ELSE 'Group'
            END as assignment_type
        FROM devices d
        LEFT JOIN device_groups dg ON d.id = dg.device_id
        LEFT JOIN groups g ON dg.group_id = g.id
        LEFT JOIN user_groups ug ON g.id = ug.group_id
        WHERE d.user_id = :user_id 
        OR ug.user_id = :user_id
        ORDER BY d.name
    ");
    $stmt->execute(['user_id' => $_SESSION['user_id']]);
    $group_devices = $stmt->fetchAll(PDO::FETCH_ASSOC);

} catch (PDOException $e) {
    logMessage("Database query error: " . $e->getMessage());
    die(json_encode(['status' => 'error', 'message' => 'Failed to load dashboard data.']));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .card { 
            margin: 10px 0;
            transition: transform 0.2s;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .card:hover {
            transform: translateY(-5px);
        }
        .card-header { 
            font-size: 1.25rem;
            font-weight: bold;
        }
        .card-body { 
            font-size: 1.5rem;
            padding: 1.5rem;
        }
        .table { 
            margin-top: 20px;
            font-size: 0.95rem;
        }
        .table thead th {
            font-size: 1rem;
            font-weight: 600;
        }
        .table td {
            vertical-align: middle;
        }
        .tab-content { 
            margin-top: 20px;
        }
        .chart-container {
            position: relative;
            height: 300px;
            margin: 20px 0;
        }
        .status-badge {
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.85rem;
        }
        .status-online {
            background-color: #28a745;
            color: white;
        }
        .status-offline {
            background-color: #dc3545;
            color: white;
        }
        .refresh-button {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 1000;
        }
        .filter-section {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .group-devices-header {
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 1rem;
        }
        .group-devices-table th {
            font-size: 0.95rem;
            font-weight: 600;
        }
        .group-devices-table td {
            font-size: 0.9rem;
        }
        .badge {
            font-size: 0.85rem;
            padding: 0.5em 0.75em;
        }
        .btn-sm {
            font-size: 0.85rem;
            padding: 0.25rem 0.5rem;
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
                    <a class="nav-link active" href="dashboard.php">
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
        <h1 class="text-center mb-4">Dashboard</h1>
        
        <!-- Filter Section -->
        <div class="filter-section">
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label for="statusFilter">Status Filter:</label>
                        <select class="form-control" id="statusFilter">
                            <option value="all">All</option>
                            <option value="online">Online</option>
                            <option value="offline">Offline</option>
                        </select>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label for="searchInput">Search:</label>
                        <input type="text" class="form-control" id="searchInput" placeholder="Search devices...">
                    </div>
                </div>
            </div>
        </div>

        <!-- Statistics Cards -->
        <div class="row mt-4">
            <div class="col-md-3">
                <div class="card text-white bg-primary">
                    <div class="card-header">
                        <i class="fas fa-microchip"></i> Total Devices
                    </div>
                    <div class="card-body">
                        <p class="card-text"><?php echo htmlspecialchars($totalDevices); ?></p>
                    </div>
                </div>
            </div>
            <?php if ($isAdmin): ?>
            <div class="col-md-3">
                <div class="card text-white bg-success">
                    <div class="card-header">
                        <i class="fas fa-users"></i> Total Users
                    </div>
                    <div class="card-body">
                        <p class="card-text"><?php echo htmlspecialchars($totalUsers); ?></p>
                    </div>
                </div>
            </div>
            <?php endif; ?>
            <div class="col-md-3">
                <div class="card text-white bg-info">
                    <div class="card-header">
                        <i class="fas fa-plug"></i> Online Devices
                    </div>
                    <div class="card-body">
                        <p class="card-text"><?php echo htmlspecialchars($totalOnlineDevices); ?></p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-white bg-danger">
                    <div class="card-header">
                        <i class="fas fa-power-off"></i> Offline Devices
                    </div>
                    <div class="card-body">
                        <p class="card-text"><?php echo htmlspecialchars($totalOfflineDevices); ?></p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Additional Statistics -->
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-code-branch"></i> Devices with Firmware
                    </div>
                    <div class="card-body">
                        <p class="card-text"><?php echo htmlspecialchars($devicesWithFirmware); ?></p>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-users-cog"></i> Total Groups
                    </div>
                    <div class="card-body">
                        <p class="card-text"><?php echo htmlspecialchars($totalGroups); ?></p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts -->
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-chart-pie"></i> Device Status Distribution
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="statusChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-chart-bar"></i> Firmware Distribution
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="firmwareChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Devices Table -->
        <div class="card mt-4">
            <div class="card-header">
                <i class="fas fa-list"></i> Devices List
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-bordered" id="devicesTable">
                        <thead class="thead-dark">
                            <tr>
                                <th>Name</th>
                                <th>IP Address</th>
                                <th>MAC Address</th>
                                <th>Status</th>
                                <th>Last Ping</th>
                                <th>Firmware Version</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($devices as $device): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($device['name']); ?></td>
                                <td><?php echo htmlspecialchars($device['ip']); ?></td>
                                <td><?php echo htmlspecialchars($device['mac']); ?></td>
                                <td>
                                    <span class="status-badge <?php echo $device['status'] === 'online' ? 'status-online' : 'status-offline'; ?>">
                                        <?php echo ucfirst(htmlspecialchars($device['status'])); ?>
                                    </span>
                                </td>
                                <td><?php echo htmlspecialchars($device['last_ping']); ?></td>
                                <td><?php echo htmlspecialchars($device['firmware_version'] ?? 'N/A'); ?></td>
                            </tr>
                            <?php endforeach; ?>
                            <?php if (empty($devices)): ?>
                            <tr>
                                <td colspan="6" class="text-center">No devices found.</td>
                            </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Group Devices Section -->
        <div class="card mb-4">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-network-wired"></i> 
                    Group Devices
                </h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover group-devices-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>MAC</th>
                                <th>Internal IP</th>
                                <th>External IP</th>
                                <th>Group</th>
                                <th>Status</th>
                                <th>Assignment Type</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($group_devices as $device): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($device['name']); ?></td>
                                    <td><?php echo htmlspecialchars($device['mac']); ?></td>
                                    <td><?php echo htmlspecialchars($device['internal_ip']); ?></td>
                                    <td><?php echo htmlspecialchars($device['external_ip']); ?></td>
                                    <td>
                                        <span class="badge badge-info">
                                            <?php echo htmlspecialchars($device['group_name'] ?? 'Direct'); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <?php if ($device['status'] == 'online'): ?>
                                            <span class="badge badge-success">Online</span>
                                        <?php else: ?>
                                            <span class="badge badge-danger">Offline</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <span class="badge <?php echo $device['assignment_type'] == 'Direct' ? 'badge-primary' : 'badge-info'; ?>">
                                            <?php echo htmlspecialchars($device['assignment_type']); ?>
                                        </span>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            <?php if (empty($group_devices)): ?>
                                <tr>
                                    <td colspan="7" class="text-center">No devices found.</td>
                                </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

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

    <!-- Refresh Button -->
    <button class="btn btn-primary refresh-button" onclick="refreshDashboard()">
        <i class="fas fa-sync-alt"></i> Refresh
    </button>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    <script>
        // Status Chart
        const statusCtx = document.getElementById('statusChart').getContext('2d');
        new Chart(statusCtx, {
            type: 'pie',
            data: {
                labels: ['Online', 'Offline'],
                datasets: [{
                    data: [<?php echo $totalOnlineDevices; ?>, <?php echo $totalOfflineDevices; ?>],
                    backgroundColor: ['#28a745', '#dc3545']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });

        // Firmware Chart
        const firmwareCtx = document.getElementById('firmwareChart').getContext('2d');
        new Chart(firmwareCtx, {
            type: 'doughnut',
            data: {
                labels: ['With Firmware', 'Without Firmware'],
                datasets: [{
                    data: [<?php echo $devicesWithFirmware; ?>, <?php echo $totalDevices - $devicesWithFirmware; ?>],
                    backgroundColor: ['#17a2b8', '#6c757d']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });

        // Filter functionality
        $('#statusFilter, #searchInput').on('change keyup', function() {
            const status = $('#statusFilter').val();
            const search = $('#searchInput').val().toLowerCase();
            
            $('#devicesTable tbody tr').each(function() {
                const row = $(this);
                const deviceStatus = row.find('td:eq(3)').text().toLowerCase();
                const deviceText = row.text().toLowerCase();
                
                const statusMatch = status === 'all' || deviceStatus.includes(status);
                const searchMatch = !search || deviceText.includes(search);
                
                row.toggle(statusMatch && searchMatch);
            });
        });

        // Refresh dashboard
        function refreshDashboard() {
            location.reload();
        }

        // Auto-refresh every 5 minutes
        setInterval(refreshDashboard, 300000);
    </script>
</body>
</html>


