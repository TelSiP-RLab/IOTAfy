<?php
// assign_user_groups.php

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

// Get user ID from URL
$user_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

// Handle group assignment/unassignment
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'])) {
        $message = 'Invalid CSRF token';
        logMessage("Invalid CSRF token during group assignment by user {$_SESSION['user_id']}.");
        die($message);
    }

    if (isset($_POST['assign_group'])) {
        $group_id = $_POST['group_id'];
        try {
            // Check if user is already assigned to this group
            $stmt = $db->prepare("SELECT COUNT(*) FROM user_groups WHERE user_id = :user_id AND group_id = :group_id");
            $stmt->execute(['user_id' => $user_id, 'group_id' => $group_id]);
            if ($stmt->fetchColumn() > 0) {
                $message = "User is already assigned to this group.";
            } else {
                $stmt = $db->prepare("INSERT INTO user_groups (user_id, group_id, assigned_date) VALUES (:user_id, :group_id, datetime('now'))");
                $stmt->execute(['user_id' => $user_id, 'group_id' => $group_id]);
                $message = "User assigned to group successfully.";
                logMessage("User (ID: $user_id) assigned to group (ID: $group_id) by user {$_SESSION['user_id']}.");
            }
        } catch (PDOException $e) {
            $message = "Error assigning user to group: " . $e->getMessage();
            logMessage("Error assigning user to group: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
        }
    } elseif (isset($_POST['unassign_group'])) {
        $group_id = $_POST['group_id'];
        try {
            $stmt = $db->prepare("DELETE FROM user_groups WHERE user_id = :user_id AND group_id = :group_id");
            $stmt->execute(['user_id' => $user_id, 'group_id' => $group_id]);
            $message = "User unassigned from group successfully.";
            logMessage("User (ID: $user_id) unassigned from group (ID: $group_id) by user {$_SESSION['user_id']}.");
        } catch (PDOException $e) {
            $message = "Error unassigning user from group: " . $e->getMessage();
            logMessage("Error unassigning user from group: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
        }
    }
}

// Get user details
try {
    $stmt = $db->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->execute(['id' => $user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user) {
        header('Location: user_management.php');
        exit;
    }
} catch (PDOException $e) {
    $message = "Error fetching user details: " . $e->getMessage();
    logMessage("Error fetching user details: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
    $user = null;
}

// Get assigned groups
try {
    $stmt = $db->prepare("
        SELECT g.*, ug.assigned_date 
        FROM groups g 
        JOIN user_groups ug ON g.id = ug.group_id 
        WHERE ug.user_id = :user_id 
        ORDER BY g.name
    ");
    $stmt->execute(['user_id' => $user_id]);
    $assigned_groups = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $message = "Error fetching assigned groups: " . $e->getMessage();
    logMessage("Error fetching assigned groups: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
    $assigned_groups = [];
}

// Get unassigned groups
try {
    $stmt = $db->prepare("
        SELECT g.* 
        FROM groups g 
        WHERE g.id NOT IN (
            SELECT group_id FROM user_groups WHERE user_id = :user_id
        )
        ORDER BY g.name
    ");
    $stmt->execute(['user_id' => $user_id]);
    $unassigned_groups = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $message = "Error fetching unassigned groups: " . $e->getMessage();
    logMessage("Error fetching unassigned groups: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
    $unassigned_groups = [];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Assign Groups to User</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" rel="stylesheet">
    <style>
        .group-card {
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 10px;
            margin-bottom: 10px;
            transition: all 0.3s ease;
        }
        .group-card:hover {
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }
        .assigned-groups {
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 15px;
        }
        .unassigned-groups {
            background-color: #fff;
            border-radius: 5px;
            padding: 15px;
        }
        .search-box {
            margin-bottom: 20px;
        }
        .group-info {
            font-size: 0.9rem;
            color: #6c757d;
        }
        .assigned-date {
            font-size: 0.8rem;
            color: #28a745;
        }
        .user-info {
            background-color: #e9ecef;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1>Assign Groups to User</h1>
            <a href="user_management.php" class="btn btn-secondary">
                <i class="fas fa-arrow-left"></i> Back to Users
            </a>
        </div>

        <?php if (!empty($message)): ?>
            <div class="alert alert-info"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>

        <!-- User Information -->
        <div class="user-info">
            <h4>User Details</h4>
            <div class="row">
                <div class="col-md-4">
                    <p><strong>Username:</strong> <?php echo htmlspecialchars($user['username']); ?></p>
                </div>
                <div class="col-md-4">
                    <p><strong>Email:</strong> <?php echo htmlspecialchars($user['email']); ?></p>
                </div>
                <div class="col-md-4">
                    <p><strong>Role:</strong> <?php echo htmlspecialchars($user['role']); ?></p>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- Assigned Groups -->
            <div class="col-md-6">
                <div class="assigned-groups">
                    <h3 class="mb-3">Assigned Groups</h3>
                    <div class="search-box">
                        <input type="text" class="form-control" id="assignedSearch" placeholder="Search assigned groups...">
                    </div>
                    <div id="assignedGroupsList">
                        <?php foreach ($assigned_groups as $group): ?>
                            <div class="group-card assigned-group">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h5 class="mb-1"><?php echo htmlspecialchars($group['name']); ?></h5>
                                        <div class="group-info">
                                            <i class="fas fa-info-circle"></i> <?php echo htmlspecialchars($group['description']); ?>
                                        </div>
                                        <div class="assigned-date">
                                            <i class="fas fa-calendar-alt"></i> Assigned: <?php echo date('d/m/Y', strtotime($group['assigned_date'])); ?>
                                        </div>
                                    </div>
                                    <form method="POST" class="d-inline">
                                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                        <input type="hidden" name="group_id" value="<?php echo $group['id']; ?>">
                                        <button type="submit" name="unassign_group" class="btn btn-sm btn-danger" title="Remove Group">
                                            <i class="fas fa-minus-circle"></i>
                                        </button>
                                    </form>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>

            <!-- Unassigned Groups -->
            <div class="col-md-6">
                <div class="unassigned-groups">
                    <h3 class="mb-3">Available Groups</h3>
                    <div class="search-box">
                        <input type="text" class="form-control" id="unassignedSearch" placeholder="Search available groups...">
                    </div>
                    <div id="unassignedGroupsList">
                        <?php foreach ($unassigned_groups as $group): ?>
                            <div class="group-card unassigned-group">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h5 class="mb-1"><?php echo htmlspecialchars($group['name']); ?></h5>
                                        <div class="group-info">
                                            <i class="fas fa-info-circle"></i> <?php echo htmlspecialchars($group['description']); ?>
                                        </div>
                                    </div>
                                    <form method="POST" class="d-inline">
                                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                        <input type="hidden" name="group_id" value="<?php echo $group['id']; ?>">
                                        <button type="submit" name="assign_group" class="btn btn-sm btn-success" title="Add Group">
                                            <i class="fas fa-plus-circle"></i>
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
        // Search functionality for assigned groups
        $('#assignedSearch').on('keyup', function() {
            const search = $(this).val().toLowerCase();
            $('.assigned-group').each(function() {
                const name = $(this).find('h5').text().toLowerCase();
                const description = $(this).find('.group-info').text().toLowerCase();
                $(this).toggle(name.includes(search) || description.includes(search));
            });
        });

        // Search functionality for unassigned groups
        $('#unassignedSearch').on('keyup', function() {
            const search = $(this).val().toLowerCase();
            $('.unassigned-group').each(function() {
                const name = $(this).find('h5').text().toLowerCase();
                const description = $(this).find('.group-info').text().toLowerCase();
                $(this).toggle(name.includes(search) || description.includes(search));
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


