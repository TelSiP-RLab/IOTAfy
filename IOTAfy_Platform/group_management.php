<?php
// group_management.php

require 'config.inc'; // Include the configuration file

// Ensure the user is logged in and has admin privileges
if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header('Location: login.php');
    exit;
}

// Generate a CSRF token if one doesn't exist
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$db = getDbConnection();
$message = "";

/**
 * Validates the CSRF token
 *
 * @param string $token The token to validate
 * @return bool True if valid, false otherwise
 */
function validateCsrfToken($token) {
    return hash_equals($_SESSION['csrf_token'], $token);
}

// Handle group deletion
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['delete_group'])) {
    if (!validateCsrfToken($_POST['csrf_token'])) {
        $message = 'Invalid CSRF token';
        logMessage("Invalid CSRF token during group deletion by user {$_SESSION['user_id']}.");
        die($message);
    }

    $group_id = $_POST['group_id'];
    try {
        $stmt = $db->prepare("DELETE FROM groups WHERE id = :id");
        $stmt->bindParam(':id', $group_id, PDO::PARAM_INT);
        if ($stmt->execute()) {
            $message = "Group deleted successfully.";
            logMessage("Group (ID: $group_id) deleted successfully by user {$_SESSION['user_id']}.");
        } else {
            $message = "Failed to delete group.";
            logMessage("Failed to delete group (ID: $group_id) by user {$_SESSION['user_id']}.");
        }
    } catch (PDOException $e) {
        $message = "Database error: " . $e->getMessage();
        logMessage("Database error during group deletion: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
    }
}

// Handle device assignment to group
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['assign_device'])) {
    if (!validateCsrfToken($_POST['csrf_token'])) {
        $message = 'Invalid CSRF token';
        logMessage("Invalid CSRF token during device assignment by user {$_SESSION['user_id']}.");
        die($message);
    }

    $device_id = $_POST['device_id'];
    $group_id = $_POST['group_id'];
    try {
        $stmt = $db->prepare("INSERT INTO device_groups (device_id, group_id) VALUES (:device_id, :group_id)");
        $stmt->bindParam(':device_id', $device_id, PDO::PARAM_INT);
        $stmt->bindParam(':group_id', $group_id, PDO::PARAM_INT);
        if ($stmt->execute()) {
            $message = "Device assigned to group successfully.";
            logMessage("Device (ID: $device_id) assigned to group (ID: $group_id) by user {$_SESSION['user_id']}.");
        } else {
            $message = "Failed to assign device to group.";
            logMessage("Failed to assign device (ID: $device_id) to group (ID: $group_id) by user {$_SESSION['user_id']}.");
        }
    } catch (PDOException $e) {
        $message = "Database error: " . $e->getMessage();
        logMessage("Database error during device assignment to group: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
    }
}

// Handle device unassignment from group
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['unassign_device'])) {
    if (!validateCsrfToken($_POST['csrf_token'])) {
        $message = 'Invalid CSRF token';
        logMessage("Invalid CSRF token during device unassignment by user {$_SESSION['user_id']}.");
        die($message);
    }

    $device_id = $_POST['device_id'];
    $group_id = $_POST['group_id'];
    try {
        $stmt = $db->prepare("DELETE FROM device_groups WHERE device_id = :device_id AND group_id = :group_id");
        $stmt->bindParam(':device_id', $device_id, PDO::PARAM_INT);
        $stmt->bindParam(':group_id', $group_id, PDO::PARAM_INT);
        if ($stmt->execute()) {
            $message = "Device unassigned from group successfully.";
            logMessage("Device (ID: $device_id) unassigned from group (ID: $group_id) by user {$_SESSION['user_id']}.");
        } else {
            $message = "Failed to unassign device from group.";
            logMessage("Failed to unassign device (ID: $device_id) from group (ID: $group_id) by user {$_SESSION['user_id']}.");
        }
    } catch (PDOException $e) {
        $message = "Database error: " . $e->getMessage();
        logMessage("Database error during device unassignment from group: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
    }
}

// Handle group creation
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'create') {
    $name = trim((string)($_POST['name'] ?? ''));
    $description = trim((string)($_POST['description'] ?? ''));
    
    if (empty($name)) {
        $message = "Group name is required.";
    } else {
        try {
            // Check if group name already exists
            $stmt = $db->prepare("SELECT COUNT(*) FROM groups WHERE name = :name");
            $stmt->execute(['name' => $name]);
            if ($stmt->fetchColumn() > 0) {
                $message = "A group with this name already exists.";
            } else {
                // Insert new group with created_by and create_date
                $stmt = $db->prepare("INSERT INTO groups (name, description, created_by, create_date) VALUES (:name, :description, :created_by, datetime('now'))");
                $stmt->execute([
                    'name' => $name,
                    'description' => $description,
                    'created_by' => $_SESSION['user_id']
                ]);
                
                $message = "Group created successfully.";
                logMessage("Group '$name' created by user {$_SESSION['user_id']}.");
            }
        } catch (PDOException $e) {
            $message = "Error creating group: " . $e->getMessage();
            logMessage("Error creating group: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
        }
    }
}

// Fetch all groups
try {
    $query = "SELECT g.*, 
              (SELECT COUNT(*) FROM user_groups WHERE group_id = g.id) as member_count,
              u.username as created_by_name
              FROM groups g 
              LEFT JOIN users u ON g.created_by = u.id 
              ORDER BY g.name";
    $groups = $db->query($query)->fetchAll(PDO::FETCH_ASSOC);
    logMessage("Groups fetched successfully by user {$_SESSION['user_id']}.");
} catch (PDOException $e) {
    $message = "Error fetching groups: " . $e->getMessage();
    logMessage("Error fetching groups: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
    $groups = [];
}

// Add pagination variables
$items_per_page = 10;
$current_page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$search = isset($_GET['search']) ? $_GET['search'] : '';
$total_items = count($groups);
$total_pages = ceil($total_items / $items_per_page);
$offset = ($current_page - 1) * $items_per_page;
$groups = array_slice($groups, $offset, $items_per_page);

// Filter groups based on search if search term is provided
if (!empty($search)) {
    $groups = array_filter($groups, function($group) use ($search) {
        return stripos($group['name'], $search) !== false || 
               stripos($group['created_by_name'], $search) !== false;
    });
}

/**
 * Renders pagination controls
 */
function renderPaginationControls($current_page, $total_pages, $search = '', $items_per_page = 10) {
    if ($total_pages <= 1) return '';
    
    $html = '<nav aria-label="Page navigation" class="mt-4"><ul class="pagination justify-content-center">';
    
    // Previous button
    if ($current_page > 1) {
        $html .= '<li class="page-item"><a class="page-link" href="?page=' . ($current_page - 1) . 
                 ($search ? '&search=' . urlencode($search) : '') . 
                 '&items_per_page=' . $items_per_page . '">Previous</a></li>';
    }
    
    // Page numbers
    for ($i = 1; $i <= $total_pages; $i++) {
        if ($i == $current_page) {
            $html .= '<li class="page-item active"><span class="page-link">' . $i . '</span></li>';
        } else {
            $html .= '<li class="page-item"><a class="page-link" href="?page=' . $i . 
                     ($search ? '&search=' . urlencode($search) : '') . 
                     '&items_per_page=' . $items_per_page . '">' . $i . '</a></li>';
        }
    }
    
    // Next button
    if ($current_page < $total_pages) {
        $html .= '<li class="page-item"><a class="page-link" href="?page=' . ($current_page + 1) . 
                 ($search ? '&search=' . urlencode($search) : '') . 
                 '&items_per_page=' . $items_per_page . '">Next</a></li>';
    }
    
    $html .= '</ul></nav>';
    return $html;
}

// Fetch all devices
try {
    $devices = $db->query("SELECT * FROM devices ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
    logMessage("Devices fetched successfully by user {$_SESSION['user_id']}.");
} catch (PDOException $e) {
    $message = "Error fetching devices: " . $e->getMessage();
    logMessage("Error fetching devices: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
    $devices = [];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Group Management</title>
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
        .group-card {
            border-left: 4px solid #007bff;
            margin-bottom: 15px;
        }
        .filter-section {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .action-buttons .btn {
            margin: 0 2px;
        }
        .modal-header {
            background-color: #f8f9fa;
        }
        .group-info {
            font-size: 0.9rem;
            color: #6c757d;
        }
        .member-count {
            background-color: #e9ecef;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8rem;
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
                        <a class="dropdown-item" href="user_management.php">
                            <i class="fas fa-user-cog"></i> Manage Users
                        </a>
                        <a class="dropdown-item active" href="group_management.php">
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
        <h1 class="text-center mb-4">Group Management</h1>
        
        <?php if (!empty($message)): ?>
            <div class="alert alert-info text-center"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>

        <!-- Filter Section -->
        <div class="filter-section">
            <div class="row">
                <div class="col-md-6">
                    <div class="form-group">
                        <label for="searchInput"><i class="fas fa-search"></i> Search Groups:</label>
                        <input type="text" class="form-control" id="searchInput" 
                               placeholder="Search by group name..." value="<?php echo htmlspecialchars($search); ?>">
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="form-group">
                        <label for="sortSelect"><i class="fas fa-sort"></i> Sort By:</label>
                        <select class="form-control" id="sortSelect">
                            <option value="name">Name (A-Z)</option>
                            <option value="members">Members (High-Low)</option>
                            <option value="created">Created Date (New-Old)</option>
                        </select>
                    </div>
                </div>
            </div>
        </div>

        <!-- Add Group Button -->
        <div class="text-right mb-3">
            <button type="button" class="btn btn-primary" data-toggle="modal" data-target="#addGroupModal">
                <i class="fas fa-plus-circle"></i> Add New Group
            </button>
        </div>

        <?php if (empty($groups)): ?>
            <div class="alert alert-info text-center">No groups found.</div>
        <?php else: ?>
            <div class="row">
                <?php foreach ($groups as $group): ?>
                    <div class="col-md-6">
                        <div class="card group-card">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <h5 class="card-title">
                                            <?php echo htmlspecialchars($group['name']); ?>
                                            <span class="member-count">
                                                <i class="fas fa-users"></i> <?php echo $group['member_count']; ?> members
                                            </span>
                                        </h5>
                                        <div class="group-info">
                                            <p class="mb-1">
                                                <i class="fas fa-calendar-alt"></i> Created: 
                                                <?php echo date('d/m/Y', strtotime($group['create_date'])); ?>
                                            </p>
                                            <p class="mb-1">
                                                <i class="fas fa-user"></i> Created by: 
                                                <?php echo htmlspecialchars($group['created_by_name']); ?>
                                            </p>
                                        </div>
                                    </div>
                                    <div class="action-buttons">
                                        <a href="edit_group.php?id=<?php echo $group['id']; ?>" class="btn btn-sm btn-info" title="Edit Group">
                                            <i class="fas fa-edit"></i>
                                        </a>
                                        <a href="assign_group_users.php?id=<?php echo $group['id']; ?>" class="btn btn-sm btn-primary" title="Assign Users">
                                            <i class="fas fa-users"></i>
                                        </a>
                                        <form method="POST" action="" class="d-inline" onsubmit="return confirm('Are you sure you want to delete this group?');">
                                            <input type="hidden" name="group_id" value="<?php echo $group['id']; ?>">
                                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                            <button type="submit" name="delete_group" class="btn btn-sm btn-danger" title="Delete Group">
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

    <!-- Add Group Modal -->
    <div class="modal fade" id="addGroupModal" tabindex="-1" role="dialog" aria-labelledby="addGroupModalLabel" aria-hidden="true">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <form method="POST" action="">
                    <div class="modal-header">
                        <h5 class="modal-title" id="addGroupModalLabel">Add New Group</h5>
                        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                            <span aria-hidden="true">&times;</span>
                        </button>
                    </div>
                    <div class="modal-body">
                        <input type="hidden" name="action" value="create">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label for="name">Group Name:</label>
                            <input type="text" class="form-control" id="name" name="name" required>
                        </div>
                        <div class="form-group">
                            <label for="description">Description:</label>
                            <textarea class="form-control" id="description" name="description" rows="3"></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                        <button type="submit" class="btn btn-primary">Create Group</button>
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
        $('#searchInput').on('keyup', function() {
            const search = $(this).val().toLowerCase();
            
            $('.group-card').each(function() {
                const card = $(this);
                const groupName = card.find('.card-title').text().toLowerCase();
                const createdBy = card.find('.fa-user').next().text().toLowerCase();
                
                const searchMatch = !search || groupName.includes(search) || createdBy.includes(search);
                card.closest('.col-md-6').toggle(searchMatch);
            });
        });

        // Sort functionality
        $('#sortSelect').on('change', function() {
            const sortBy = $(this).val();
            const container = $('.row');
            const cards = container.find('.col-md-6').get();
            
            cards.sort(function(a, b) {
                if (sortBy === 'name') {
                    return $(a).find('.card-title').text().localeCompare($(b).find('.card-title').text());
                } else if (sortBy === 'members') {
                    const aCount = parseInt($(a).find('.member-count').text());
                    const bCount = parseInt($(b).find('.member-count').text());
                    return bCount - aCount;
                } else if (sortBy === 'created') {
                    const aDate = new Date($(a).find('.fa-calendar-alt').next().text());
                    const bDate = new Date($(b).find('.fa-calendar-alt').next().text());
                    return bDate - aDate;
                }
                return 0;
            });
            
            $.each(cards, function(idx, card) {
                container.append(card);
            });
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


