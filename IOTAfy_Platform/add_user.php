<?php
// add_user.php

require 'config.inc'; // Include the configuration file

// Ensure the user is logged in and has admin privileges
if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header('Location: login.php');
    exit;
}

$db = getDbConnection();
$message = "";
$error = "";

// Get all groups for the dropdown
try {
    $stmt = $db->query("SELECT * FROM groups ORDER BY name");
    $groups = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    logMessage("Error fetching groups: " . $e->getMessage());
    $error = "Error loading groups.";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    $role = $_POST['role'];
    $selected_groups = isset($_POST['groups']) ? $_POST['groups'] : [];
    $is_active = isset($_POST['is_active']) ? 1 : 0;
    $max_failed_logins = isset($_POST['max_failed_logins']) ? (int)$_POST['max_failed_logins'] : 5;
    $lockout_duration = isset($_POST['lockout_duration']) ? (int)$_POST['lockout_duration'] : 30;

    // Validate input
    if (empty($username) || empty($email) || empty($password)) {
        $error = "All fields are required.";
    } elseif ($password !== $confirm_password) {
        $error = "Passwords do not match.";
    } elseif (strlen($password) < 8) {
        $error = "Password must be at least 8 characters long.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email format.";
    } else {
        try {
            // Check if username or email already exists
            $stmt = $db->prepare("SELECT COUNT(*) FROM users WHERE username = :username OR email = :email");
            $stmt->execute(['username' => $username, 'email' => $email]);
            if ($stmt->fetchColumn() > 0) {
                $error = "Username or email already exists.";
            } else {
                // Start transaction
                $db->beginTransaction();

                // Insert user
                $stmt = $db->prepare("
                    INSERT INTO users (
                        username, 
                        email, 
                        password, 
                        role, 
                        is_active,
                        max_failed_logins,
                        lockout_duration,
                        create_date
                    ) VALUES (
                        :username, 
                        :email, 
                        :password, 
                        :role,
                        :is_active,
                        :max_failed_logins,
                        :lockout_duration,
                        datetime('now')
                    )
                ");

                $stmt->execute([
                    'username' => $username,
                    'email' => $email,
                    'password' => password_hash($password, PASSWORD_DEFAULT),
                    'role' => $role,
                    'is_active' => $is_active,
                    'max_failed_logins' => $max_failed_logins,
                    'lockout_duration' => $lockout_duration
                ]);

                $user_id = $db->lastInsertId();

                // Assign groups
                if (!empty($selected_groups)) {
                    $stmt = $db->prepare("INSERT INTO user_groups (user_id, group_id) VALUES (:user_id, :group_id)");
                    foreach ($selected_groups as $group_id) {
                        $stmt->execute(['user_id' => $user_id, 'group_id' => $group_id]);
                    }
                }

                // Commit transaction
                $db->commit();

                $message = "User added successfully.";
                logMessage("New user '$username' added by user {$_SESSION['user_id']}.");

                // Redirect to user management page after 2 seconds
                header("refresh:2;url=user_management.php");
            }
        } catch (PDOException $e) {
            // Rollback transaction on error
            $db->rollBack();
            $error = "Error adding user: " . $e->getMessage();
            logMessage("Error adding user: " . $e->getMessage() . " by user {$_SESSION['user_id']}.");
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add New User</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" rel="stylesheet">
    <style>
        .card {
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            margin-top: 20px;
        }
        .card-header {
            background-color: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        .password-requirements {
            font-size: 0.85rem;
            color: #6c757d;
            margin-top: 0.25rem;
        }
        .group-select {
            max-height: 200px;
            overflow-y: auto;
        }
        .security-settings {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
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
                Logged in as: <?php echo htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8'); ?>
            </span>
        </div>
    </nav>

    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <h4 class="mb-0">
                            <i class="fas fa-user-plus"></i> Add New User
                        </h4>
                    </div>
                    <div class="card-body">
                        <?php if (!empty($error)): ?>
                            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                        <?php endif; ?>

                        <?php if (!empty($message)): ?>
                            <div class="alert alert-success"><?php echo htmlspecialchars($message); ?></div>
                        <?php endif; ?>

                        <form method="POST" action="">
                            <!-- Basic Information -->
                            <div class="form-group">
                                <label for="username">Username</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>

                            <div class="form-group">
                                <label for="email">Email</label>
                                <input type="email" class="form-control" id="email" name="email" required>
                            </div>

                            <div class="form-group">
                                <label for="password">Password</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                                <div class="password-requirements">
                                    Password must be at least 8 characters long.
                                </div>
                            </div>

                            <div class="form-group">
                                <label for="confirm_password">Confirm Password</label>
                                <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                            </div>

                            <div class="form-group">
                                <label for="role">Role</label>
                                <select class="form-control" id="role" name="role" required>
                                    <option value="user">User</option>
                                    <option value="admin">Admin</option>
                                </select>
                            </div>

                            <!-- Group Assignment -->
                            <div class="form-group">
                                <label>Assign to Groups</label>
                                <div class="group-select">
                                    <?php foreach ($groups as $group): ?>
                                        <div class="custom-control custom-checkbox">
                                            <input type="checkbox" class="custom-control-input" 
                                                   id="group_<?php echo $group['id']; ?>" 
                                                   name="groups[]" 
                                                   value="<?php echo $group['id']; ?>">
                                            <label class="custom-control-label" for="group_<?php echo $group['id']; ?>">
                                                <?php echo htmlspecialchars($group['name']); ?>
                                            </label>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>

                            <!-- Security Settings -->
                            <div class="security-settings">
                                <h5><i class="fas fa-shield-alt"></i> Security Settings</h5>
                                <div class="form-group">
                                    <div class="custom-control custom-switch">
                                        <input type="checkbox" class="custom-control-input" id="is_active" name="is_active" checked>
                                        <label class="custom-control-label" for="is_active">Active Account</label>
                                    </div>
                                </div>

                                <div class="form-group">
                                    <label for="max_failed_logins">Maximum Failed Login Attempts</label>
                                    <input type="number" class="form-control" id="max_failed_logins" name="max_failed_logins" 
                                           value="5" min="1" max="10">
                                    <small class="form-text text-muted">
                                        Number of failed login attempts before account is locked.
                                    </small>
                                </div>

                                <div class="form-group">
                                    <label for="lockout_duration">Lockout Duration (minutes)</label>
                                    <input type="number" class="form-control" id="lockout_duration" name="lockout_duration" 
                                           value="30" min="1" max="1440">
                                    <small class="form-text text-muted">
                                        How long the account remains locked after exceeding failed login attempts.
                                    </small>
                                </div>
                            </div>

                            <div class="form-group">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-save"></i> Add User
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
        // Password match validation
        document.getElementById('confirm_password').addEventListener('input', function() {
            const password = document.getElementById('password').value;
            const confirmPassword = this.value;
            if (password !== confirmPassword) {
                this.setCustomValidity('Passwords do not match');
            } else {
                this.setCustomValidity('');
            }
        });

        // Password length validation
        document.getElementById('password').addEventListener('input', function() {
            if (this.value.length < 8) {
                this.setCustomValidity('Password must be at least 8 characters long');
            } else {
                this.setCustomValidity('');
            }
        });
    </script>
</body>
</html>


