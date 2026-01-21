<?php
// edit_user.php

require 'config.inc'; // Include the configuration file

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    logMessage('Unauthorized access attempt to edit_user.php');
    header('Location: login.php');
    exit;
}

$db = getDbConnection();
$message = "";
$messageType = "info";

// Generate a CSRF token and store it in the session
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (isset($_GET['id'])) {
    $user_id = $_GET['id'];
    $stmt = $db->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->bindParam(':id', $user_id);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        logMessage("User not found: ID $user_id");
        header('Location: user_management.php');
        exit;
    }
} else {
    logMessage('User ID not provided for edit_user.php');
    header('Location: user_management.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = (string)($_POST['username'] ?? '');
    $email = (string)($_POST['email'] ?? '');
    $role = (string)($_POST['role'] ?? '');
    $full_name = (string)($_POST['full_name'] ?? '');
    $password = (string)($_POST['password'] ?? '');
    $confirm_password = (string)($_POST['confirm_password'] ?? '');
    $is_active = isset($_POST['is_active']) ? (int)$_POST['is_active'] : 1;
    $csrf_token = (string)($_POST['csrf_token'] ?? '');

    // Validate CSRF token
    if (!hash_equals($_SESSION['csrf_token'], $csrf_token)) {
        $message = "Invalid CSRF token.";
        $messageType = "danger";
    } else {
        // Server-side validation
        if (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
            $message = "Invalid username. It should be 3-20 characters long and contain only letters, numbers, and underscores.";
            $messageType = "danger";
            logMessage("Validation error: $message");
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $message = "Invalid email address.";
            $messageType = "danger";
            logMessage("Validation error: $message");
        } elseif (empty($full_name) || strlen($full_name) < 3 || strlen($full_name) > 50) {
            $message = "Invalid full name. It should be 3-50 characters long.";
            $messageType = "danger";
            logMessage("Validation error: $message");
        } elseif (!empty($password) && $password !== $confirm_password) {
            $message = "Passwords do not match.";
            $messageType = "danger";
            logMessage("Validation error: $message");
        } elseif (!empty($password) && strlen($password) < 6) {
            $message = "Password must be at least 6 characters long.";
            $messageType = "danger";
            logMessage("Validation error: $message");
        } else {
            // Check if the username already exists
            $stmt = $db->prepare("SELECT COUNT(*) FROM users WHERE username = :username AND id != :id");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':id', $user_id);
            $stmt->execute();
            $count = $stmt->fetchColumn();

            if ($count > 0) {
                $message = "Username already taken.";
                $messageType = "danger";
                logMessage("Database error: $message");
            } else {
                // Update user information
                $stmt = $db->prepare("UPDATE users SET username = :username, email = :email, role = :role, full_name = :full_name, is_active = :is_active WHERE id = :id");
                $stmt->bindParam(':username', $username);
                $stmt->bindParam(':email', $email);
                $stmt->bindParam(':role', $role);
                $stmt->bindParam(':full_name', $full_name);
                $stmt->bindParam(':is_active', $is_active);
                $stmt->bindParam(':id', $user_id);

                if ($stmt->execute()) {
                    // Update password if provided
                    if (!empty($password)) {
                        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                        $last_password_change = date('Y-m-d H:i:s');
                        $stmt = $db->prepare("UPDATE users SET password = :password, last_password_change = :last_password_change WHERE id = :id");
                        $stmt->bindParam(':password', $hashed_password);
                        $stmt->bindParam(':last_password_change', $last_password_change);
                        $stmt->bindParam(':id', $user_id);
                        $stmt->execute();
                    }

                    $message = "User updated successfully.";
                    $messageType = "success";
                    logMessage("User $username updated successfully.");
                } else {
                    $message = "Failed to update user.";
                    $messageType = "danger";
                    logMessage("Database error: $message");
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit User</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" rel="stylesheet">
    <style>
        .form-container {
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-top: 20px;
        }
        .form-group label {
            font-weight: 500;
            color: #343a40;
        }
        .form-control {
            border: 1px solid #ced4da;
            border-radius: 4px;
        }
        .form-control:focus {
            border-color: #80bdff;
            box-shadow: 0 0 0 0.2rem rgba(0,123,255,.25);
        }
        .btn-primary {
            background-color: #007bff;
            border: none;
            padding: 10px 20px;
        }
        .btn-secondary {
            background-color: #6c757d;
            border: none;
            padding: 10px 20px;
        }
        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .alert {
            border-radius: 4px;
            margin-bottom: 20px;
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
                Logged in as: <?php echo htmlspecialchars($_SESSION['username'] ?? '', ENT_QUOTES, 'UTF-8'); ?>
            </span>
        </div>
    </nav>

    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="form-container">
                    <h2 class="text-center mb-4">Edit User</h2>
                    
                    <?php if (!empty($message)): ?>
                        <div class="alert alert-<?php echo htmlspecialchars($messageType ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                            <?php echo htmlspecialchars($message ?? '', ENT_QUOTES, 'UTF-8'); ?>
                        </div>
                    <?php endif; ?>

                    <form method="POST" action="">
                        <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($user['id'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                        
                        <div class="form-group">
                            <label for="username">Username</label>
                            <input type="text" class="form-control" id="username" name="username" value="<?php echo htmlspecialchars($user['username'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>
                        </div>

                        <div class="form-group">
                            <label for="full_name">Full Name</label>
                            <input type="text" class="form-control" id="full_name" name="full_name" value="<?php echo htmlspecialchars($user['full_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>
                        </div>

                        <div class="form-group">
                            <label for="email">Email</label>
                            <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($user['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>
                        </div>

                        <div class="form-group">
                            <label for="role">Role</label>
                            <select class="form-control" id="role" name="role" required>
                                <option value="user" <?php echo $user['role'] === 'user' ? 'selected' : ''; ?>>User</option>
                                <option value="admin" <?php echo $user['role'] === 'admin' ? 'selected' : ''; ?>>Admin</option>
                                <option value="superuser" <?php echo $user['role'] === 'superuser' ? 'selected' : ''; ?>>Superuser</option>
                            </select>
                        </div>

                        <div class="form-group">
                            <label for="is_active">Status</label>
                            <select class="form-control" id="is_active" name="is_active" required>
                                <option value="1" <?php echo $user['is_active'] == 1 ? 'selected' : ''; ?>>Active</option>
                                <option value="0" <?php echo $user['is_active'] == 0 ? 'selected' : ''; ?>>Inactive</option>
                            </select>
                        </div>

                        <div class="form-group">
                            <label for="password">New Password (leave blank to keep current)</label>
                            <input type="password" class="form-control" id="password" name="password">
                        </div>

                        <div class="form-group">
                            <label for="confirm_password">Confirm New Password</label>
                            <input type="password" class="form-control" id="confirm_password" name="confirm_password">
                        </div>

                        <div class="text-center mt-4">
                            <button type="submit" class="btn btn-primary mr-2">
                                <i class="fas fa-save"></i> Save Changes
                            </button>
                            <a href="user_management.php" class="btn btn-secondary">
                                <i class="fas fa-times"></i> Cancel
                            </a>
                        </div>
                    </form>
                </div>
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


