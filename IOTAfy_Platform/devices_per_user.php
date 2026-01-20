<?php
session_start();

require 'config.inc'; // Include the configuration file

// Έλεγχος αν ο χρήστης είναι admin
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit;
}

$user_id = $_SESSION['user_id'];
$user_role = $_SESSION['role'];

// Handle search input
$search = isset($_GET['search']) ? $_GET['search'] : '';

// Handle pagination input
$page = isset($_GET['page']) && is_numeric($_GET['page']) ? (int)$_GET['page'] : 1;
$perPage = isset($_GET['perPage']) && is_numeric($_GET['perPage']) ? (int)$_GET['perPage'] : 10;
$offset = ($page - 1) * $perPage;

$db = getDbConnection();
$message = "";

try {
    if ($_SESSION['role'] === 'admin') {
        // Admin can see all users and their devices
        $stmt = $db->prepare("
            SELECT DISTINCT u.id, u.username, u.full_name, u.email,
                   COUNT(DISTINCT d.id) as total_devices,
                   SUM(CASE WHEN d.status = 'online' THEN 1 ELSE 0 END) as online_devices,
                   SUM(CASE WHEN d.status = 'offline' THEN 1 ELSE 0 END) as offline_devices
            FROM users u
            LEFT JOIN devices d ON u.id = d.user_id
            WHERE u.username LIKE :search OR u.full_name LIKE :search OR u.email LIKE :search
            GROUP BY u.id
            ORDER BY u.username
            LIMIT :perPage OFFSET :offset
        ");
    } else {
        // Regular users can only see their own devices
        $stmt = $db->prepare("
            SELECT u.id, u.username, u.full_name, u.email,
                   COUNT(DISTINCT d.id) as total_devices,
                   SUM(CASE WHEN d.status = 'online' THEN 1 ELSE 0 END) as online_devices,
                   SUM(CASE WHEN d.status = 'offline' THEN 1 ELSE 0 END) as offline_devices
            FROM users u
            LEFT JOIN devices d ON u.id = d.user_id
            WHERE u.id = :user_id
            GROUP BY u.id
            ORDER BY u.username
            LIMIT :perPage OFFSET :offset
        ");
        $stmt->bindParam(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    }
    $search_param = '%' . $search . '%';
    $stmt->bindParam(':search', $search_param, PDO::PARAM_STR);
    $stmt->bindParam(':perPage', $perPage, PDO::PARAM_INT);
    $stmt->bindParam(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Get total count for pagination
    if ($_SESSION['role'] === 'admin') {
        $countStmt = $db->prepare("
            SELECT COUNT(DISTINCT u.id) 
            FROM users u 
            WHERE u.username LIKE :search OR u.full_name LIKE :search OR u.email LIKE :search
        ");
    } else {
        $countStmt = $db->prepare("
            SELECT COUNT(DISTINCT u.id) 
            FROM users u 
            WHERE u.id = :user_id
        ");
        $countStmt->bindParam(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    }
    $countStmt->bindParam(':search', $search_param, PDO::PARAM_STR);
    $countStmt->execute();
    $totalUsers = $countStmt->fetchColumn();
    $totalPages = ceil($totalUsers / $perPage);

} catch (PDOException $e) {
    $message = "Error fetching users: " . $e->getMessage();
    logMessage("ERROR", $message);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Devices per User</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" rel="stylesheet">
    <style>
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
        .stats-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: transform 0.2s ease-in-out;
            text-align: center;
        }
        .stats-card:hover {
            transform: translateY(-5px);
        }
        .stats-number {
            font-size: 28px;
            font-weight: bold;
            color: #343a40;
            margin-bottom: 5px;
        }
        .stats-label {
            color: #6c757d;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .badge {
            padding: 8px 12px;
            font-size: 0.9rem;
            font-weight: 500;
        }
        .badge-pill {
            padding: 8px 12px;
            border-radius: 20px;
        }
        .badge-primary {
            background-color: #007bff;
            color: white;
        }
        .badge-success {
            background-color: #28a745;
            color: white;
        }
        .badge-danger {
            background-color: #dc3545;
            color: white;
        }
        .input-group {
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .input-group .form-control {
            border: 1px solid #ced4da;
        }
        .input-group .btn {
            border: none;
        }
        .pagination .page-link {
            color: #343a40;
            border: none;
            padding: 8px 16px;
            margin: 0 2px;
            border-radius: 4px;
        }
        .pagination .page-item.active .page-link {
            background-color: #343a40;
            color: white;
        }
        .pagination .page-item:not(.active) .page-link:hover {
            background-color: #f8f9fa;
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
                        <a class="dropdown-item" href="monitor_status.php">
                            <i class="fas fa-chart-line"></i> Monitor Status
                        </a>
                        <?php if ($_SESSION['role'] === 'admin'): ?>
                        <a class="dropdown-item active" href="devices_per_user.php">
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
        <h1 class="text-center mb-4">Devices per User</h1>
        
        <?php if (!empty($message)): ?>
            <div class="alert alert-danger text-center"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>

        <!-- Search Form -->
        <form method="GET" class="mb-4">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="input-group">
                        <input type="text" name="search" class="form-control" placeholder="Search by username, name, or email..." value="<?php echo htmlspecialchars($search); ?>">
                        <div class="input-group-append">
                            <button class="btn btn-primary" type="submit">
                                <i class="fas fa-search"></i> Search
                            </button>
                            <?php if (!empty($search)): ?>
                                <a href="devices_per_user.php" class="btn btn-secondary">
                                    <i class="fas fa-times"></i> Clear
                                </a>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </form>

        <div class="d-flex justify-content-between align-items-center my-3">
            <div>
                <label for="perPage" class="mr-2">Items per page:</label>
                <select id="perPage" class="form-control" style="width: auto;">
                    <option value="5" <?php if ($perPage == 5) echo 'selected'; ?>>5</option>
                    <option value="10" <?php if ($perPage == 10) echo 'selected'; ?>>10</option>
                    <option value="20" <?php if ($perPage == 20) echo 'selected'; ?>>20</option>
                    <option value="50" <?php if ($perPage == 50) echo 'selected'; ?>>50</option>
                </select>
            </div>
            <button class="btn btn-primary" onclick="location.reload()">
                <i class="fas fa-sync-alt"></i> Refresh
            </button>
        </div>

        <div class="table-responsive">
            <table class="table table-bordered table-hover">
                <thead class="thead-dark">
                    <tr>
                        <th>Username</th>
                        <th>Full Name</th>
                        <th>Email</th>
                        <th>Device Name</th>
                        <th>Total Devices</th>
                        <th>Online Devices</th>
                        <th>Offline Devices</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (!empty($users)): ?>
                        <?php foreach ($users as $user): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($user['username'] ?? '', ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars($user['full_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars($user['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>
                                    <?php
                                    try {
                                        $deviceStmt = $db->prepare("
                                            SELECT name FROM devices 
                                            WHERE user_id = :user_id 
                                            ORDER BY name
                                        ");
                                        $deviceStmt->execute(['user_id' => $user['id']]);
                                        $devices = $deviceStmt->fetchAll(PDO::FETCH_COLUMN);
                                        echo implode('<br>', array_map('htmlspecialchars', $devices));
                                    } catch (PDOException $e) {
                                        echo "Error fetching devices";
                                    }
                                    ?>
                                </td>
                                <td>
                                    <span class="badge badge-primary"><?php echo $user['total_devices']; ?></span>
                                </td>
                                <td>
                                    <span class="badge badge-success badge-pill"><?php echo $user['online_devices']; ?></span>
                                </td>
                                <td>
                                    <span class="badge badge-danger badge-pill"><?php echo $user['offline_devices']; ?></span>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="7" class="text-center">No users found</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <nav>
            <ul class="pagination justify-content-center">
                <?php if ($page > 1): ?>
                    <li class="page-item">
                        <a class="page-link" href="?page=<?php echo $page - 1; ?>&search=<?php echo urlencode($search); ?>&perPage=<?php echo $perPage; ?>" aria-label="Previous">
                            <span aria-hidden="true">&laquo;</span>
                        </a>
                    </li>
                <?php endif; ?>
                <?php for ($i = 1; $i <= $totalPages; $i++): ?>
                    <li class="page-item <?php if ($i == $page) echo 'active'; ?>">
                        <a class="page-link" href="?page=<?php echo $i; ?>&search=<?php echo urlencode($search); ?>&perPage=<?php echo $perPage; ?>"><?php echo $i; ?></a>
                    </li>
                <?php endfor; ?>
                <?php if ($page < $totalPages): ?>
                    <li class="page-item">
                        <a class="page-link" href="?page=<?php echo $page + 1; ?>&search=<?php echo urlencode($search); ?>&perPage=<?php echo $perPage; ?>" aria-label="Next">
                            <span aria-hidden="true">&raquo;</span>
                        </a>
                    </li>
                <?php endif; ?>
            </ul>
        </nav>
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
            window.history.pushState({}, '', 'devices_per_user.php?' + urlParams.toString());
            
            // Show loading indicator
            document.querySelector('.table-responsive').innerHTML = '<div class="text-center"><i class="fas fa-spinner fa-spin fa-2x"></i></div>';
            
            // Perform AJAX request
            fetch('devices_per_user.php?' + urlParams.toString())
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
</body>
</html>


