<?php
// notification_history.php

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
$isAdmin = ($user_role === 'admin');

$db = getDbConnection();
$message = "";

// Handle search input
$search = isset($_GET['search']) ? $_GET['search'] : '';

// Handle filter inputs
$filterType = isset($_GET['type']) ? $_GET['type'] : '';
$filterStatus = isset($_GET['status']) ? $_GET['status'] : '';
$filterSuccess = isset($_GET['success']) ? $_GET['success'] : '';

// Handle pagination input
$page = isset($_GET['page']) && is_numeric($_GET['page']) ? (int)$_GET['page'] : 1;
$perPage = isset($_GET['perPage']) && is_numeric($_GET['perPage']) ? (int)$_GET['perPage'] : 25;
$offset = ($page - 1) * $perPage;

try {
    // Build query based on user role
    $whereConditions = [];
    $params = [];
    
    if (!$isAdmin) {
        // Regular users can only see their own notifications
        $whereConditions[] = "n.user_id = :user_id";
        $params[':user_id'] = $user_id;
    }
    
    // Add search condition
    if (!empty($search)) {
        $whereConditions[] = "(d.name LIKE :search OR u.username LIKE :search OR n.message LIKE :search)";
        $params[':search'] = '%' . $search . '%';
    }
    
    // Add filter conditions
    if (!empty($filterType)) {
        $whereConditions[] = "n.type = :type";
        $params[':type'] = $filterType;
    }
    
    if (!empty($filterStatus)) {
        $whereConditions[] = "n.status = :status";
        $params[':status'] = $filterStatus;
    }
    
    if ($filterSuccess !== '') {
        $whereConditions[] = "n.success = :success";
        $params[':success'] = (int)$filterSuccess;
    }
    
    $whereClause = !empty($whereConditions) ? 'WHERE ' . implode(' AND ', $whereConditions) : '';
    
    // Main query
    $query = "
        SELECT 
            n.id,
            n.user_id,
            n.device_id,
            n.type,
            n.status,
            n.message,
            n.sent_at,
            n.success,
            n.error_message,
            d.name AS device_name,
            u.username AS user_username
        FROM notifications n
        INNER JOIN devices d ON n.device_id = d.id
        INNER JOIN users u ON n.user_id = u.id
        {$whereClause}
        ORDER BY n.sent_at DESC
        LIMIT :perPage OFFSET :offset
    ";
    
    $stmt = $db->prepare($query);
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    $stmt->bindValue(':perPage', $perPage, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get total count for pagination
    $countQuery = "
        SELECT COUNT(*)
        FROM notifications n
        INNER JOIN devices d ON n.device_id = d.id
        INNER JOIN users u ON n.user_id = u.id
        {$whereClause}
    ";
    
    $countStmt = $db->prepare($countQuery);
    foreach ($params as $key => $value) {
        if ($key !== ':perPage' && $key !== ':offset') {
            $countStmt->bindValue($key, $value);
        }
    }
    $countStmt->execute();
    $totalNotifications = $countStmt->fetchColumn();
    $totalPages = ceil($totalNotifications / $perPage);
    
} catch (PDOException $e) {
    $message = "Error fetching notifications: " . $e->getMessage();
    logMessage("ERROR: " . $message);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IOTAfy - Notification History</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" rel="stylesheet">
    <style>
        .status-badge {
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.9rem;
            font-weight: bold;
        }
        .status-online {
            background-color: #28a745;
            color: white;
        }
        .status-offline {
            background-color: #dc3545;
            color: white;
        }
        .type-badge {
            padding: 3px 8px;
            border-radius: 10px;
            font-size: 0.85rem;
        }
        .type-email {
            background-color: #007bff;
            color: white;
        }
        .type-telegram {
            background-color: #17a2b8;
            color: white;
        }
        .type-both {
            background-color: #6f42c1;
            color: white;
        }
        .success-badge {
            padding: 3px 8px;
            border-radius: 10px;
            font-size: 0.85rem;
        }
        .success-yes {
            background-color: #28a745;
            color: white;
        }
        .success-no {
            background-color: #dc3545;
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
        .table-responsive {
            margin-bottom: 20px;
        }
        .section-title {
            color: #343a40;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #343a40;
        }
        .error-message {
            color: #dc3545;
            font-size: 0.85rem;
            font-style: italic;
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
                <li class="nav-item">
                    <a class="nav-link active" href="notification_history.php">
                        <i class="fas fa-bell"></i> Notification History
                    </a>
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
            </ul>
            <span class="navbar-text">
                Logged in as: <?php echo htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8'); ?>
            </span>
        </div>
    </nav>

    <div class="container mt-5">
        <h1 class="text-center mb-4">Notification History</h1>
        
        <?php if (!empty($message)): ?>
            <div class="alert alert-danger text-center"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>

        <!-- Filters Form -->
        <form method="GET" class="mb-4">
            <div class="card mb-4">
                <div class="card-header">
                    <h5 class="mb-0"><i class="fas fa-filter"></i> Filters</h5>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-3">
                            <label for="search">Search:</label>
                            <input type="text" name="search" id="search" class="form-control" placeholder="Device, user, message..." value="<?php echo htmlspecialchars($search); ?>">
                        </div>
                        <div class="col-md-2">
                            <label for="type">Type:</label>
                            <select name="type" id="type" class="form-control">
                                <option value="">All</option>
                                <option value="email" <?php echo $filterType === 'email' ? 'selected' : ''; ?>>Email</option>
                                <option value="telegram" <?php echo $filterType === 'telegram' ? 'selected' : ''; ?>>Telegram</option>
                                <option value="both" <?php echo $filterType === 'both' ? 'selected' : ''; ?>>Both</option>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <label for="status">Status:</label>
                            <select name="status" id="status" class="form-control">
                                <option value="">All</option>
                                <option value="online" <?php echo $filterStatus === 'online' ? 'selected' : ''; ?>>Online</option>
                                <option value="offline" <?php echo $filterStatus === 'offline' ? 'selected' : ''; ?>>Offline</option>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <label for="success">Success:</label>
                            <select name="success" id="success" class="form-control">
                                <option value="">All</option>
                                <option value="1" <?php echo $filterSuccess === '1' ? 'selected' : ''; ?>>Success</option>
                                <option value="0" <?php echo $filterSuccess === '0' ? 'selected' : ''; ?>>Failed</option>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <label>&nbsp;</label>
                            <div>
                                <button class="btn btn-primary btn-block" type="submit">
                                    <i class="fas fa-search"></i> Apply Filters
                                </button>
                                <?php if (!empty($search) || !empty($filterType) || !empty($filterStatus) || $filterSuccess !== ''): ?>
                                    <a href="notification_history.php" class="btn btn-secondary btn-block mt-2">
                                        <i class="fas fa-times"></i> Clear Filters
                                    </a>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </form>

        <div class="d-flex justify-content-between align-items-center my-3">
            <div>
                <strong>Total: <?php echo $totalNotifications; ?> notifications</strong>
            </div>
            <div>
                <label for="perPage" class="mr-2">Items per page:</label>
                <select id="perPage" class="form-control" style="width: auto; display: inline-block;">
                    <option value="10" <?php if ($perPage == 10) echo 'selected'; ?>>10</option>
                    <option value="25" <?php if ($perPage == 25) echo 'selected'; ?>>25</option>
                    <option value="50" <?php if ($perPage == 50) echo 'selected'; ?>>50</option>
                    <option value="100" <?php if ($perPage == 100) echo 'selected'; ?>>100</option>
                </select>
            </div>
        </div>

        <?php if (empty($notifications)): ?>
            <div class="alert alert-info text-center">
                <i class="fas fa-info-circle"></i> No notifications found.
            </div>
        <?php else: ?>
            <div class="table-responsive">
                <table class="table table-hover table-bordered">
                    <thead class="thead-dark">
                        <tr>
                            <th>Date/Time</th>
                            <?php if ($isAdmin): ?>
                                <th>User</th>
                            <?php endif; ?>
                            <th>Device</th>
                            <th>Type</th>
                            <th>Status</th>
                            <th>Message</th>
                            <th>Success</th>
                            <th>Error</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($notifications as $notif): ?>
                            <tr>
                                <td>
                                    <?php 
                                    $sentAt = new DateTime($notif['sent_at']);
                                    echo $sentAt->format('d/m/Y H:i:s');
                                    ?>
                                </td>
                                <?php if ($isAdmin): ?>
                                    <td><?php echo htmlspecialchars($notif['user_username'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
                                <?php endif; ?>
                                <td><?php echo htmlspecialchars($notif['device_name'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>
                                    <span class="type-badge type-<?php echo htmlspecialchars($notif['type'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <?php echo htmlspecialchars(strtoupper($notif['type']), ENT_QUOTES, 'UTF-8'); ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="status-badge status-<?php echo htmlspecialchars($notif['status'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <?php echo htmlspecialchars(strtoupper($notif['status']), ENT_QUOTES, 'UTF-8'); ?>
                                    </span>
                                </td>
                                <td><?php echo htmlspecialchars($notif['message'] ?? '', ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>
                                    <span class="success-badge success-<?php echo $notif['success'] ? 'yes' : 'no'; ?>">
                                        <?php echo $notif['success'] ? 'YES' : 'NO'; ?>
                                    </span>
                                </td>
                                <td>
                                    <?php if (!empty($notif['error_message'])): ?>
                                        <span class="error-message" title="<?php echo htmlspecialchars($notif['error_message'], ENT_QUOTES, 'UTF-8'); ?>">
                                            <i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars(substr($notif['error_message'], 0, 50), ENT_QUOTES, 'UTF-8'); ?><?php echo strlen($notif['error_message']) > 50 ? '...' : ''; ?>
                                        </span>
                                    <?php else: ?>
                                        <span class="text-muted">-</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            <?php if ($totalPages > 1): ?>
                <nav aria-label="Page navigation">
                    <ul class="pagination justify-content-center">
                        <?php if ($page > 1): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?php echo $page - 1; ?>&perPage=<?php echo $perPage; ?>&search=<?php echo urlencode($search); ?>&type=<?php echo urlencode($filterType); ?>&status=<?php echo urlencode($filterStatus); ?>&success=<?php echo urlencode($filterSuccess); ?>">
                                    <i class="fas fa-chevron-left"></i> Previous
                                </a>
                            </li>
                        <?php endif; ?>
                        
                        <?php for ($i = max(1, $page - 2); $i <= min($totalPages, $page + 2); $i++): ?>
                            <li class="page-item <?php echo $i === $page ? 'active' : ''; ?>">
                                <a class="page-link" href="?page=<?php echo $i; ?>&perPage=<?php echo $perPage; ?>&search=<?php echo urlencode($search); ?>&type=<?php echo urlencode($filterType); ?>&status=<?php echo urlencode($filterStatus); ?>&success=<?php echo urlencode($filterSuccess); ?>">
                                    <?php echo $i; ?>
                                </a>
                            </li>
                        <?php endfor; ?>
                        
                        <?php if ($page < $totalPages): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?php echo $page + 1; ?>&perPage=<?php echo $perPage; ?>&search=<?php echo urlencode($search); ?>&type=<?php echo urlencode($filterType); ?>&status=<?php echo urlencode($filterStatus); ?>&success=<?php echo urlencode($filterSuccess); ?>">
                                    Next <i class="fas fa-chevron-right"></i>
                                </a>
                            </li>
                        <?php endif; ?>
                    </ul>
                </nav>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Handle perPage change
        document.getElementById('perPage').addEventListener('change', function() {
            const url = new URL(window.location.href);
            url.searchParams.set('perPage', this.value);
            url.searchParams.set('page', '1'); // Reset to first page
            window.location.href = url.toString();
        });
    </script>
</body>
</html>
