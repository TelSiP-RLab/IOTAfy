<?php
// assign_group_users.php

require 'config.inc'; // Include the configuration file

/**
 * Validates the CSRF token
 * @param string $token The token to validate
 * @return bool True if token is valid, false otherwise
 */
function validateCsrfToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

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

// Get group ID from URL
$group_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

// Handle user assignment/unassignment
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'])) {
        $message = 'Invalid CSRF token';
        logMessage("Invalid CSRF token during user assignment by user {$_SESSION['user_id']}.");
        die($message);
    }

    if (isset($_POST['assign_user'])) {
        $user_id = $_POST['user_id'];
        try {
            // Check if user is already assigned
            $stmt = $db->prepare("SELECT COUNT(*) FROM user_groups WHERE user_id = :user_id AND group_id = :group_id");
            $stmt->execute(['user_id' => $user_id, 'group_id' => $group_id]);
            if ($stmt->fetchColumn() > 0) {
                $message = "User is already assigned to this group.";
            } else {
                $stmt = $db->prepare("INSERT INTO user_groups (user_id, group_id, assigned_date) VALUES (:user_id, :group_id, datetime('now'))");
                $stmt->execute(['user_id' => $user_id, 'group_id' => $group_id]);
                $message = "User assigned successfully.";
                logMessage("User (ID: $user_id) assigned to group (ID: $group_id) by user {$_SESSION['user_id']}.");
            }
        } catch (PDOException $e) {
            $message = "Error assigning user: " . $e->getMessage();
            logMessage("Error assigning user: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
        }
    } elseif (isset($_POST['unassign_user'])) {
        $user_id = $_POST['user_id'];
        try {
            $stmt = $db->prepare("DELETE FROM user_groups WHERE user_id = :user_id AND group_id = :group_id");
            $stmt->execute(['user_id' => $user_id, 'group_id' => $group_id]);
            $message = "User unassigned successfully.";
            logMessage("User (ID: $user_id) unassigned from group (ID: $group_id) by user {$_SESSION['user_id']}.");
        } catch (PDOException $e) {
            $message = "Error unassigning user: " . $e->getMessage();
            logMessage("Error unassigning user: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
        }
    }
}

// Get group details
try {
    $stmt = $db->prepare("SELECT * FROM groups WHERE id = :id");
    $stmt->execute(['id' => $group_id]);
    $group = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$group) {
        header('Location: group_management.php');
        exit;
    }
} catch (PDOException $e) {
    $message = "Error fetching group details: " . $e->getMessage();
    logMessage("Error fetching group details: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
    $group = null;
}

// Get assigned users
try {
    $stmt = $db->prepare("
        SELECT u.*, ug.assigned_date 
        FROM users u 
        JOIN user_groups ug ON u.id = ug.user_id 
        WHERE ug.group_id = :group_id 
        ORDER BY u.username
    ");
    $stmt->execute(['group_id' => $group_id]);
    $assigned_users = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $message = "Error fetching assigned users: " . $e->getMessage();
    logMessage("Error fetching assigned users: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
    $assigned_users = [];
}

// Get unassigned users
try {
    $stmt = $db->prepare("
        SELECT u.* 
        FROM users u 
        WHERE u.id NOT IN (
            SELECT user_id FROM user_groups WHERE group_id = :group_id
        )
        ORDER BY u.username
    ");
    $stmt->execute(['group_id' => $group_id]);
    $unassigned_users = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $message = "Error fetching unassigned users: " . $e->getMessage();
    logMessage("Error fetching unassigned users: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
    $unassigned_users = [];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Assign Users to Group</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" rel="stylesheet">
    <style>
        .user-card {
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 10px;
            margin-bottom: 10px;
            transition: all 0.3s ease;
        }
        .user-card:hover {
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }
        .assigned-users {
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 15px;
        }
        .unassigned-users {
            background-color: #fff;
            border-radius: 5px;
            padding: 15px;
        }
        .search-box {
            margin-bottom: 20px;
        }
        .user-info {
            font-size: 0.9rem;
            color: #6c757d;
        }
        .assigned-date {
            font-size: 0.8rem;
            color: #28a745;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1>Assign Users to Group: <?php echo htmlspecialchars($group['name']); ?></h1>
            <a href="group_management.php" class="btn btn-secondary">
                <i class="fas fa-arrow-left"></i> Back to Groups
            </a>
        </div>

        <?php if (!empty($message)): ?>
            <div class="alert alert-info"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>

        <div class="row">
            <!-- Assigned Users -->
            <div class="col-md-6">
                <div class="assigned-users">
                    <h3 class="mb-3">Assigned Users</h3>
                    <div class="search-box">
                        <input type="text" class="form-control" id="assignedSearch" placeholder="Search assigned users...">
                    </div>
                    <div id="assignedUsersList">
                        <?php foreach ($assigned_users as $user): ?>
                            <div class="user-card assigned-user">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h5 class="mb-1"><?php echo htmlspecialchars($user['username']); ?></h5>
                                        <div class="user-info">
                                            <i class="fas fa-envelope"></i> <?php echo htmlspecialchars($user['email'] ?? ''); ?>
                                        </div>
                                        <div class="assigned-date">
                                            <i class="fas fa-calendar-alt"></i> Assigned: <?php echo date('d/m/Y', strtotime($user['assigned_date'])); ?>
                                        </div>
                                    </div>
                                    <form method="POST" class="d-inline">
                                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                        <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                        <button type="submit" name="unassign_user" class="btn btn-sm btn-danger" title="Remove User">
                                            <i class="fas fa-user-minus"></i>
                                        </button>
                                    </form>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>

            <!-- Unassigned Users -->
            <div class="col-md-6">
                <div class="unassigned-users">
                    <h3 class="mb-3">Available Users</h3>
                    <div class="search-box">
                        <input type="text" class="form-control" id="unassignedSearch" placeholder="Search available users...">
                    </div>
                    <div id="unassignedUsersList">
                        <?php foreach ($unassigned_users as $user): ?>
                            <div class="user-card unassigned-user">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h5 class="mb-1"><?php echo htmlspecialchars($user['username']); ?></h5>
                                        <div class="user-info">
                                            <i class="fas fa-envelope"></i> <?php echo htmlspecialchars($user['email'] ?? ''); ?>
                                        </div>
                                    </div>
                                    <form method="POST" class="d-inline">
                                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                        <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                        <button type="submit" name="assign_user" class="btn btn-sm btn-success" title="Add User">
                                            <i class="fas fa-user-plus"></i>
                                        </button>
                                    </form>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    <script>
        // Search functionality for assigned users
        $('#assignedSearch').on('keyup', function() {
            const search = $(this).val().toLowerCase();
            $('.assigned-user').each(function() {
                const username = $(this).find('h5').text().toLowerCase();
                const email = $(this).find('.user-info').text().toLowerCase();
                $(this).toggle(username.includes(search) || email.includes(search));
            });
        });

        // Search functionality for unassigned users
        $('#unassignedSearch').on('keyup', function() {
            const search = $(this).val().toLowerCase();
            $('.unassigned-user').each(function() {
                const username = $(this).find('h5').text().toLowerCase();
                const email = $(this).find('.user-info').text().toLowerCase();
                $(this).toggle(username.includes(search) || email.includes(search));
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


