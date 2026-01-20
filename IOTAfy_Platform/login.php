<?php
// login.php

require 'config.inc'; // Include the configuration file

// Function to get the client IP address
function getClientIp() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        return $_SERVER['REMOTE_ADDR'];
    }
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Sanitize and validate inputs (avoid deprecated FILTER_SANITIZE_STRING)
    $username = trim((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    $ip_address = getClientIp(); // Get the client's IP address
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $additional_info = json_encode([
        'referer' => $_SERVER['HTTP_REFERER'] ?? '',
        'request_method' => $_SERVER['REQUEST_METHOD'],
        'request_uri' => $_SERVER['REQUEST_URI']
    ]);

    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "Invalid CSRF token.";
        logMessage("CSRF token validation failed for username: $username from IP: $ip_address");
    } else {
        try {
            $db = getDbConnection();

            // Get user with security settings
            $stmt = $db->prepare("
                SELECT u.*, 
                       CASE 
                           WHEN u.locked_until IS NOT NULL AND datetime(u.locked_until) > datetime('now') 
                           THEN 1 
                           ELSE 0 
                       END as is_locked,
                       CASE 
                           WHEN u.locked_until IS NOT NULL AND datetime(u.locked_until) > datetime('now')
                           THEN round((julianday(u.locked_until) - julianday('now')) * 24 * 60)
                           ELSE 0
                       END as remaining_lockout_minutes
                FROM users u 
                WHERE username = :username
            ");
            $stmt->execute(['username' => $username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                // Check if account is active
                if (!$user['is_active']) {
                    $error = "This account has been deactivated. Please contact the administrator.";
                    logMessage("Login attempt for inactive account: $username");
                }
                // Check if account is locked
                elseif ($user['is_locked']) {
                    if ($user['admin_locked']) {
                        $error = "This account has been locked by an administrator. Please contact the administrator.";
                    } else {
                        $error = "This account is locked. Please try again in {$user['remaining_lockout_minutes']} minutes.";
                    }
                    logMessage("Login attempt for locked account: $username");
                }
                // Verify password
                elseif (password_verify($password, $user['password'])) {
                    // Reset failed login attempts on successful login
                    // Only unlock if not admin-locked
                    if ($user['admin_locked']) {
                        // Don't unlock admin-locked accounts
                        $stmt = $db->prepare("
                            UPDATE users 
                            SET failed_login_attempts = 0,
                                last_failed_login = NULL
                            WHERE id = :user_id
                        ");
                    } else {
                        // Unlock automatic locks only
                        $stmt = $db->prepare("
                            UPDATE users 
                            SET failed_login_attempts = 0,
                                last_failed_login = NULL,
                                locked_until = NULL
                            WHERE id = :user_id
                        ");
                    }
                    $stmt->execute(['user_id' => $user['id']]);

                    // If 2FA is enabled, require second factor before full login
                    if (!empty($user['twofa_enabled'])) {
                        $_SESSION['pending_2fa_user_id'] = $user['id'];
                        // Log successful password step
                        $log_stmt = $db->prepare("INSERT INTO login_attempts (username, ip_address, success, user_agent, additional_info) VALUES (:username, :ip_address, 1, :user_agent, :additional_info)");
                        $log_stmt->execute([
                            'username' => $username,
                            'ip_address' => $ip_address,
                            'user_agent' => $user_agent,
                            'additional_info' => json_encode(['stage' => 'password_ok_pending_2fa'])
                        ]);
                        logMessage("User {$user['username']} passed password step; redirecting to 2FA.");
                        header('Location: verify_2fa.php');
                        exit;
                    } else {
                        // Regenerate session ID to prevent fixation
                        session_regenerate_id(true);

                        // Set session variables
                        $_SESSION['user_id'] = $user['id'];
                        $_SESSION['username'] = $user['username'];
                        $_SESSION['role'] = $user['role'];

                        // Log successful login attempt
                        $log_stmt = $db->prepare("INSERT INTO login_attempts (username, ip_address, success, user_agent, additional_info) VALUES (:username, :ip_address, 1, :user_agent, :additional_info)");
                        $log_stmt->execute([
                            'username' => $username,
                            'ip_address' => $ip_address,
                            'user_agent' => $user_agent,
                            'additional_info' => $additional_info
                        ]);

                        logMessage("User {$user['username']} logged in successfully.");

                        // Redirect to index page
                        header('Location: index.php');
                        exit;
                    }
                } else {
                    // Increment failed login attempts
                    $stmt = $db->prepare("
                        UPDATE users 
                        SET failed_login_attempts = failed_login_attempts + 1,
                            last_failed_login = datetime('now')
                        WHERE id = :user_id
                    ");
                    $stmt->execute(['user_id' => $user['id']]);

                    // Check if account should be locked (only for non-admin-locked accounts)
                    if (!$user['admin_locked'] && $user['failed_login_attempts'] + 1 >= $user['max_failed_logins']) {
                        $stmt = $db->prepare("
                            UPDATE users 
                            SET locked_until = datetime('now', '+' || :duration || ' minutes')
                            WHERE id = :user_id
                        ");
                        $stmt->execute([
                            'user_id' => $user['id'],
                            'duration' => $user['lockout_duration']
                        ]);
                        
                        $error = "Too many failed attempts. Account locked for {$user['lockout_duration']} minutes.";
                        logMessage("Account locked for user: $username after {$user['failed_login_attempts']} failed attempts");
                    } else {
                        $remaining_attempts = $user['max_failed_logins'] - ($user['failed_login_attempts'] + 1);
                        $error = "Invalid password. {$remaining_attempts} attempts remaining.";
                        logMessage("Failed login attempt for user: $username. {$remaining_attempts} attempts remaining.");
                    }

                    // Log failed login attempt
                    $log_stmt = $db->prepare("INSERT INTO login_attempts (username, ip_address, success, user_agent, additional_info) VALUES (:username, :ip_address, 0, :user_agent, :additional_info)");
                    $log_stmt->execute([
                        'username' => $username,
                        'ip_address' => $ip_address,
                        'user_agent' => $user_agent,
                        'additional_info' => $additional_info
                    ]);
                }
            } else {
                $error = "Invalid username or password.";
                logMessage("Failed login attempt for non-existent user: $username");

                // Log failed login attempt for non-existent user
                $log_stmt = $db->prepare("INSERT INTO login_attempts (username, ip_address, success, user_agent, additional_info) VALUES (:username, :ip_address, 0, :user_agent, :additional_info)");
                $log_stmt->execute([
                    'username' => $username,
                    'ip_address' => $ip_address,
                    'user_agent' => $user_agent,
                    'additional_info' => $additional_info
                ]);
            }
        } catch (PDOException $e) {
            $error = "Database error: " . $e->getMessage();
            logMessage("Database error during login: " . $e->getMessage());
        }
    }
}

// Generate a CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IOTAfy Login</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .login-container {
            max-width: 400px;
            margin: 100px auto;
            padding: 20px;
        }
        .card {
            border: none;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .card-header {
            background-color: #fff;
            border-bottom: none;
            text-align: center;
            padding: 20px;
        }
        .card-header i {
            font-size: 48px;
            color: #007bff;
            margin-bottom: 10px;
        }
        .form-control {
            border-radius: 5px;
            padding: 10px 15px;
        }
        .btn-primary {
            padding: 10px 20px;
            border-radius: 5px;
            width: 100%;
        }
        .alert {
            border-radius: 5px;
        }
        .logo {
            display: block;
            margin: 0 auto 10px;
            max-width: 230px;
            height: auto;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="card">
            <div class="card-header">
                <img src="images/logo.png" alt="IOTAfy Logo" class="logo">
                <i class="fas fa-user-circle"></i>
                <h4 class="mb-0">Login</h4>
            </div>
            <div class="card-body">
                <?php if (!empty($error)): ?>
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>

                <form method="POST" action="">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <div class="input-group">
                            <div class="input-group-prepend">
                                <span class="input-group-text"><i class="fas fa-user"></i></span>
                            </div>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="password">Password</label>
                        <div class="input-group">
                            <div class="input-group-prepend">
                                <span class="input-group-text"><i class="fas fa-lock"></i></span>
                            </div>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                    </div>

                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-sign-in-alt"></i> Login
                    </button>
                </form>
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


