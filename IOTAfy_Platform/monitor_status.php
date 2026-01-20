<?php
// monitor_status.php

require 'config.inc'; // Include the configuration file

// Check if the session is already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Redirect if the user is not logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$user_id = $_SESSION['user_id'];
$user_role = $_SESSION['role'];

$db = getDbConnection();
$message = "";

// Handle search input
$search = isset($_GET['search']) ? $_GET['search'] : '';

// Handle pagination input
$page = isset($_GET['page']) && is_numeric($_GET['page']) ? (int)$_GET['page'] : 1;
$perPage = isset($_GET['perPage']) && is_numeric($_GET['perPage']) ? (int)$_GET['perPage'] : 10;
$offset = ($page - 1) * $perPage;

try {
    if ($_SESSION['role'] === 'admin') {
        // Admin can see all devices
        $stmt = $db->prepare("SELECT * 
                              FROM devices
                              WHERE name LIKE :search OR ip LIKE :search OR mac LIKE :search
                              ORDER BY name
                              LIMIT :perPage OFFSET :offset");
    } else {
        // Regular users can only see their own devices and those in their assigned groups
        $stmt = $db->prepare("SELECT d.* 
                              FROM devices d
                              LEFT JOIN device_groups dg ON d.id = dg.device_id
                              LEFT JOIN user_groups ug ON dg.group_id = ug.group_id
                              WHERE (d.user_id = :user_id OR ug.user_id = :user_id)
                              AND (d.name LIKE :search OR d.ip LIKE :search OR d.mac LIKE :search)
                              GROUP BY d.id ORDER BY d.name
                              LIMIT :perPage OFFSET :offset");
        $stmt->bindParam(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    }
    $search_param = '%' . $search . '%';
    $stmt->bindParam(':search', $search_param, PDO::PARAM_STR);
    $stmt->bindParam(':perPage', $perPage, PDO::PARAM_INT);
    $stmt->bindParam(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Get total count for pagination
    if ($_SESSION['role'] === 'admin') {
        $countStmt = $db->prepare("SELECT COUNT(*) FROM devices WHERE name LIKE :search OR ip LIKE :search OR mac LIKE :search");
    } else {
        $countStmt = $db->prepare("SELECT COUNT(DISTINCT d.id) FROM devices d
                                   LEFT JOIN device_groups dg ON d.id = dg.device_id
                                   LEFT JOIN user_groups ug ON dg.group_id = ug.group_id
                                   WHERE (d.user_id = :user_id OR ug.user_id = :user_id)
                                   AND (d.name LIKE :search OR d.ip LIKE :search OR d.mac LIKE :search)");
        $countStmt->bindParam(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    }
    $countStmt->bindParam(':search', $search_param, PDO::PARAM_STR);
    $countStmt->execute();
    $totalDevices = $countStmt->fetchColumn();
    $totalPages = ceil($totalDevices / $perPage);

} catch (PDOException $e) {
    $message = "Error fetching devices: " . $e->getMessage();
    logMessage("ERROR", $message);
    die($message);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IOTAfy - Monitor Device Status</title>
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
        .refresh-button {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 1000;
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
                        <a class="dropdown-item" href="device_management.php">
                            <i class="fas fa-cogs"></i> Manage Devices
                        </a>
                        <a class="dropdown-item active" href="monitor_status.php">
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
        <h1 class="text-center mb-4">Monitor Device Status</h1>
        
        <?php if (!empty($message)): ?>
            <div class="alert alert-danger text-center"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>

        <!-- Search Form -->
        <form method="GET" class="mb-4">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="input-group">
                        <input type="text" name="search" class="form-control" placeholder="Search by device name, IP, or MAC..." value="<?php echo htmlspecialchars($search); ?>">
                        <div class="input-group-append">
                            <button class="btn btn-primary" type="submit">
                                <i class="fas fa-search"></i> Search
                            </button>
                            <?php if (!empty($search)): ?>
                                <a href="monitor_status.php" class="btn btn-secondary">
                                    <i class="fas fa-times"></i> Clear
                                </a>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </form>

        <div class="d-flex justify-content-end my-3">
            <label for="perPage" class="mr-2">Items per page:</label>
            <select id="perPage" class="form-control" style="width: auto;">
                <option value="5" <?php if ($perPage == 5) echo 'selected'; ?>>5</option>
                <option value="10" <?php if ($perPage == 10) echo 'selected'; ?>>10</option>
                <option value="20" <?php if ($perPage == 20) echo 'selected'; ?>>20</option>
                <option value="50" <?php if ($perPage == 50) echo 'selected'; ?>>50</option>
            </select>
        </div>
        <?php if (empty($devices)): ?>
            <p class="text-center mt-4">No devices found.</p>
        <?php else: ?>
            <div class="table-responsive">
                <table class="table table-hover table-bordered">
                    <thead class="thead-dark">
                        <tr>
                            <th>Device Name</th>
                            <th>Status</th>
                            <th>MAC Address</th>
                            <th>IP Address</th>
                            <th>External IP Address</th>
                            <th>Last Seen</th>
                            <?php if ($_SESSION['role'] === 'admin'): ?>
                                <th>Actions</th>
                            <?php endif; ?>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($devices as $device): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($device['name'] ?? ''); ?></td>
                                <td>
                                    <span class="status-badge status-<?php echo strtolower($device['status'] ?? ''); ?>">
                                        <?php echo htmlspecialchars($device['status'] ?? ''); ?>
                                    </span>
                                </td>
                                <td><?php echo htmlspecialchars($device['mac'] ?? ''); ?></td>
                                <td><?php echo htmlspecialchars($device['ip'] ?? ''); ?></td>
                                <td><?php echo htmlspecialchars($device['external_ip'] ?? ''); ?></td>
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
            <nav>
                <ul class="pagination">
                    <li class="page-item <?php if ($page <= 1) echo 'disabled'; ?>">
                        <a class="page-link" href="?search=<?php echo htmlspecialchars($search); ?>&perPage=<?php echo $perPage; ?>&page=<?php echo $page - 1; ?>">Previous</a>
                    </li>
                    <?php for ($i = 1; $i <= $totalPages; $i++): ?>
                        <li class="page-item <?php if ($i == $page) echo 'active'; ?>">
                            <a class="page-link" href="?search=<?php echo htmlspecialchars($search); ?>&perPage=<?php echo $perPage; ?>&page=<?php echo $i; ?>"><?php echo $i; ?></a>
                        </li>
                    <?php endfor; ?>
                    <li class="page-item <?php if ($page >= $totalPages) echo 'disabled'; ?>">
                        <a class="page-link" href="?search=<?php echo htmlspecialchars($search); ?>&perPage=<?php echo $perPage; ?>&page=<?php echo $page + 1; ?>">Next</a>
                    </li>
                </ul>
            </nav>
        <?php endif; ?>
        <div class="text-center mt-4">
            <a href="index.php" class="btn btn-secondary">Back to Main Menu</a>
        </div>
    </div>

    <!-- Refresh Button -->
    <button class="btn btn-primary refresh-button" onclick="location.reload()">
        <i class="fas fa-sync-alt"></i> Refresh
    </button>

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
        let searchTimeout;

        // Function to perform the search
        function performSearch() {
            const searchInput = document.querySelector('input[name="search"]');
            const searchValue = searchInput.value.trim();
            const perPage = document.getElementById('perPage').value;
            
            // Update URL without reloading
            const urlParams = new URLSearchParams(window.location.search);
            if (searchValue) {
                urlParams.set('search', searchValue);
            } else {
                urlParams.delete('search');
            }
            urlParams.set('perPage', perPage);
            urlParams.set('page', '1');
            
            // Update browser URL without reloading
            window.history.pushState({}, '', 'monitor_status.php?' + urlParams.toString());
            
            // Show loading indicator
            document.querySelector('.table-responsive').innerHTML = '<div class="text-center"><i class="fas fa-spinner fa-spin fa-2x"></i></div>';
            
            // Perform AJAX request
            fetch('monitor_status.php?' + urlParams.toString())
                .then(response => response.text())
                .then(html => {
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(html, 'text/html');
                    const newTable = doc.querySelector('.table-responsive');
                    document.querySelector('.table-responsive').innerHTML = newTable.innerHTML;
                    
                    // Update pagination
                    const newPagination = doc.querySelector('.pagination');
                    if (newPagination) {
                        document.querySelector('.pagination').outerHTML = newPagination.outerHTML;
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    document.querySelector('.table-responsive').innerHTML = '<div class="alert alert-danger">Error performing search. Please try again.</div>';
                });
        }

        // Add event listener for search input
        document.querySelector('input[name="search"]').addEventListener('input', function() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(performSearch, 500); // Wait 500ms after user stops typing
        });

        // Auto-submit form when perPage changes
        document.getElementById('perPage').addEventListener('change', function() {
            performSearch();
        });

        // Handle form submission
        document.querySelector('form').addEventListener('submit', function(e) {
            e.preventDefault();
            performSearch();
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



