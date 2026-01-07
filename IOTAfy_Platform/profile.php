<?php
// profile.php

require 'config.inc'; // Include the configuration file
require_once 'totp.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
    logMessage("Unauthorized access attempt to profile page.");
    header('Location: login.php');
    exit;
}

$db = getDbConnection();
$stmt = $db->prepare("SELECT * FROM users WHERE id = :id");
$stmt->bindParam(':id', $_SESSION['user_id']);
$stmt->execute();
$user = $stmt->fetch(PDO::FETCH_ASSOC);

$message = "";
$error = "";
$show2faSetup = false;
$otpauthUrl = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $full_name = trim($_POST['full_name']);
    $token = trim($_POST['token']);
    $chat_id = trim($_POST['chat_id']);
    $notification_preference = trim($_POST['notification_preference']);

    // 2FA actions
    if (isset($_POST['enable_2fa'])) {
        try {
            if (!empty($user['twofa_enabled'])) {
                $message = "2FA is already enabled.";
            } else {
                // Generate a new secret and store it temporarily for confirmation
                $secret = totp_generate_secret(20);
                $enc = encryptSensitive($secret);
                $stmt = $db->prepare("UPDATE users SET twofa_secret = :secret WHERE id = :id");
                $stmt->execute(['secret' => $enc, 'id' => $_SESSION['user_id']]);
                // Refresh
                $stmt = $db->prepare("SELECT * FROM users WHERE id = :user_id");
                $stmt->execute(['user_id' => $_SESSION['user_id']]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                // Build otpauth URL and show QR
                $issuer = 'IOTAfy';
                $account = $user['email'] ?: $user['username'];
                $plainSecret = '';
                try { $plainSecret = decryptSensitive($user['twofa_secret']); } catch (Throwable $e) { $plainSecret = ''; }
                $otpauthUrl = $plainSecret ? totp_build_otpauth_url($plainSecret, $account, $issuer) : '';
                $show2faSetup = true;
                $message = "Scan the QR code and enter a code to confirm.";
            }
        } catch (PDOException $e) {
            $error = "Error enabling 2FA: " . $e->getMessage();
        }
    } elseif (isset($_POST['confirm_enable_2fa'])) {
        $otp = trim((string)($_POST['otp'] ?? ''));
        $plainSecret = '';
        try { $plainSecret = decryptSensitive($user['twofa_secret']); } catch (Throwable $e) { $plainSecret = ''; }
        if (!empty($plainSecret) && totp_verify($plainSecret, $otp)) {
            $stmt = $db->prepare("UPDATE users SET twofa_enabled = 1 WHERE id = :id");
            $stmt->execute(['id' => $_SESSION['user_id']]);
            // Refresh
            $stmt = $db->prepare("SELECT * FROM users WHERE id = :user_id");
            $stmt->execute(['user_id' => $_SESSION['user_id']]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            $message = "2FA enabled successfully.";
        } else {
            $error = "Invalid code. Please try again.";
            if (!empty($user['twofa_secret'])) {
                $issuer = 'IOTAfy';
                $account = $user['email'] ?: $user['username'];
                $plainSecret = '';
                try { $plainSecret = decryptSensitive($user['twofa_secret']); } catch (Throwable $e) { $plainSecret = ''; }
                $otpauthUrl = $plainSecret ? totp_build_otpauth_url($plainSecret, $account, $issuer) : '';
                $show2faSetup = true;
            }
        }
    } elseif (isset($_POST['disable_2fa'])) {
        $otp = trim((string)($_POST['otp'] ?? ''));
        $plainSecret = '';
        try { $plainSecret = decryptSensitive($user['twofa_secret']); } catch (Throwable $e) { $plainSecret = ''; }
        if (!empty($user['twofa_enabled']) && !empty($plainSecret) && totp_verify($plainSecret, $otp)) {
            $stmt = $db->prepare("UPDATE users SET twofa_enabled = 0, twofa_secret = twofa_secret WHERE id = :id");
            $stmt->execute(['id' => $_SESSION['user_id']]);
            // keep secret or clear? We keep for easier re-enable; change to NULL to clear.
            $stmt = $db->prepare("SELECT * FROM users WHERE id = :user_id");
            $stmt->execute(['user_id' => $_SESSION['user_id']]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            $message = "2FA disabled.";
        } else {
            $error = "Invalid code. Unable to disable 2FA.";
        }
    }

    try {
        // Update user data
        $updates = [];
        $params = ['user_id' => $_SESSION['user_id']];

        if ($username !== $user['username']) {
            $updates[] = "username = :username";
            $params['username'] = $username;
        }

        if ($email !== $user['email']) {
            $updates[] = "email = :email";
            $params['email'] = $email;
        }

        if ($full_name !== $user['full_name']) {
            $updates[] = "full_name = :full_name";
            $params['full_name'] = $full_name;
        }

        if ($token !== $user['token']) {
            $updates[] = "token = :token";
            $params['token'] = $token;
        }

        if ($chat_id !== $user['chat_id']) {
            $updates[] = "chat_id = :chat_id";
            $params['chat_id'] = $chat_id;
        }

        if ($notification_preference !== $user['notification_preference']) {
            $updates[] = "notification_preference = :notification_preference";
            $params['notification_preference'] = $notification_preference;
        }

        if (!empty($updates)) {
            $sql = "UPDATE users SET " . implode(", ", $updates) . " WHERE id = :user_id";
            $stmt = $db->prepare($sql);
            $stmt->execute($params);

            $message = "Profile updated successfully.";
            logMessage("Profile updated by user {$_SESSION['user_id']}");
            
            // Refresh user data
            $stmt = $db->prepare("SELECT * FROM users WHERE id = :user_id");
            $stmt->execute(['user_id' => $_SESSION['user_id']]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
        }
    } catch (PDOException $e) {
        $error = "Error updating profile: " . $e->getMessage();
        logMessage("Error updating profile: " . $e->getMessage() . " by user {$_SESSION['user_id']}");
    }
}

// Handle regenerate authkey
if (isset($_POST['regenerate_authkey'])) {
    try {
        // Generate a 16-byte random string and convert to hex (32 characters)
        $new_auth_key = bin2hex(random_bytes(16));
        $stmt = $db->prepare("UPDATE users SET authkey = :authkey WHERE id = :id");
        $stmt->execute([
            'authkey' => $new_auth_key,
            'id' => $_SESSION['user_id']
        ]);
        
        $message = "Authentication key regenerated successfully.";
        logMessage("User authentication key regenerated: " . $_SESSION['username']);
        
        // Refresh user data
        $stmt = $db->prepare("SELECT * FROM users WHERE id = :user_id");
        $stmt->execute(['user_id' => $_SESSION['user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        $error = "Error regenerating authentication key: " . $e->getMessage();
        logMessage("Error regenerating authentication key: " . $e->getMessage() . " by user {$_SESSION['user_id']}");
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .profile-container {
            max-width: 800px;
            margin: 2rem auto;
            padding: 2rem;
            background: white;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .profile-header {
            text-align: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid #f0f0f0;
        }
        .profile-header i {
            font-size: 4rem;
            color: #343a40;
            margin-bottom: 1rem;
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        .form-control {
            border-radius: 5px;
            border: 1px solid #ced4da;
            padding: 0.75rem;
        }
        .form-control:focus {
            border-color: #80bdff;
            box-shadow: 0 0 0 0.2rem rgba(0,123,255,.25);
        }
        .btn-primary {
            padding: 0.75rem 1.5rem;
            font-weight: 500;
            border-radius: 5px;
            background-color: #007bff;
            border: none;
        }
        .btn-primary:hover {
            background-color: #0056b3;
        }
        .alert {
            border-radius: 5px;
            margin-bottom: 1.5rem;
        }
        .section-title {
            color: #343a40;
            margin-bottom: 1.5rem;
            font-weight: 500;
        }
        .password-section {
            background-color: #f8f9fa;
            padding: 1.5rem;
            border-radius: 5px;
            margin-top: 2rem;
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
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle active" href="#" id="settingsDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        <i class="fas fa-cog"></i> Settings
                    </a>
                    <div class="dropdown-menu" aria-labelledby="settingsDropdown">
                        <a class="dropdown-item active" href="profile.php">
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

    <div class="container">
        <div class="profile-container">
            <div class="profile-header">
                <i class="fas fa-user-circle"></i>
                <h2>Profile Settings</h2>
            </div>

            <?php if (!empty($message)): ?>
                <div class="alert alert-success alert-dismissible fade show" role="alert">
                    <?php echo htmlspecialchars($message); ?>
                    <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
            <?php endif; ?>

            <?php if (!empty($error)): ?>
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    <?php echo htmlspecialchars($error); ?>
                    <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
            <?php endif; ?>

            <form method="POST" action="">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" class="form-control" id="username" name="username" value="<?php echo htmlspecialchars($user['username']); ?>" required>
                </div>

                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($user['email']); ?>" required>
                </div>

                <div class="form-group">
                    <label for="full_name">Full Name</label>
                    <input type="text" class="form-control" id="full_name" name="full_name" value="<?php echo htmlspecialchars($user['full_name']); ?>" required>
                </div>

                <div class="form-group">
                    <label for="token">Telegram Bot Token</label>
                    <input type="text" class="form-control" id="token" name="token" value="<?php echo htmlspecialchars($user['token']); ?>">
                </div>

                <div class="form-group">
                    <label for="chat_id">Telegram Chat ID</label>
                    <input type="text" class="form-control" id="chat_id" name="chat_id" value="<?php echo htmlspecialchars($user['chat_id']); ?>">
                </div>

                <div class="form-group">
                    <label for="notification_preference">Notification Preference</label>
                    <select class="form-control" id="notification_preference" name="notification_preference">
                        <option value="email" <?php echo $user['notification_preference'] === 'email' ? 'selected' : ''; ?>>Email</option>
                        <option value="telegram" <?php echo $user['notification_preference'] === 'telegram' ? 'selected' : ''; ?>>Telegram</option>
                        <option value="both" <?php echo $user['notification_preference'] === 'both' ? 'selected' : ''; ?>>Both</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="authkey">Authkey</label>
                    <div class="input-group">
                        <input type="text" class="form-control" id="authkey" name="authkey" value="<?php echo htmlspecialchars($user['authkey']); ?>" readonly>
                        <div class="input-group-append">
                            <button type="submit" name="regenerate_authkey" class="btn btn-warning" onclick="return confirm('Please be advised that regenerating the authentication key will result in the loss of connection with your devices. Do you want to proceed?');">
                                <i class="fas fa-sync"></i> Regenerate
                            </button>
                        </div>
                    </div>
                </div>

                <hr>
                <h5 class="section-title"><i class="fas fa-shield-alt"></i> Two-Factor Authentication (2FA)</h5>
                <?php if ((int)$user['twofa_enabled'] === 1): ?>
                    <div class="alert alert-success"><i class="fas fa-check-circle"></i> 2FA is currently enabled.</div>
                    <div>
                        <div class="form-group">
                            <label for="otp_disable">Enter code to disable 2FA</label>
                            <input type="text" class="form-control" id="otp_disable" name="otp" pattern="\d{6}" maxlength="6">
                        </div>
                        <button type="submit" name="disable_2fa" class="btn btn-danger"><i class="fas fa-times"></i> Disable 2FA</button>
                    </div>
                <?php else: ?>
                    <?php if ($show2faSetup && !empty($otpauthUrl)): ?>
                        <div class="alert alert-info">Scan this QR with your authenticator app and enter a code to confirm.</div>
                        <div class="text-center mb-3">
                            <?php 
                                $qrUrlPrimary = 'https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=' . urlencode($otpauthUrl);
                                $qrUrlAlt = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . urlencode($otpauthUrl);
                            ?>
                            <div>
                                <img src="<?php echo htmlspecialchars($qrUrlPrimary); ?>" alt="QR Code (Google Charts)" onerror="this.style.display='none';document.getElementById('qr-alt').style.display='inline-block';">
                                <img id="qr-alt" src="<?php echo htmlspecialchars($qrUrlAlt); ?>" alt="QR Code (Alt)" style="display:none;">
                            </div>
                            <?php 
                                $secretPreview = '';
                                try { $secretPreview = decryptSensitive($user['twofa_secret']); } catch (Throwable $e) { $secretPreview = ''; }
                            ?>
                            <p class="mt-2"><code><?php echo htmlspecialchars($secretPreview); ?></code></p>
                            <p class="small">If image not visible, open this link in your Authenticator: <a href="<?php echo htmlspecialchars($otpauthUrl); ?>" target="_blank" rel="noopener noreferrer">otpauth link</a></p>
                        </div>
                        <div>
                            <div class="form-group">
                                <label for="otp_enable">Enter code to confirm enable</label>
                                <input type="text" class="form-control" id="otp_enable" name="otp" pattern="\d{6}" maxlength="6">
                            </div>
                            <button type="submit" name="confirm_enable_2fa" class="btn btn-success"><i class="fas fa-check"></i> Confirm Enable</button>
                        </div>
                    <?php else: ?>
                        <div>
                            <button type="submit" name="enable_2fa" class="btn btn-info"><i class="fas fa-shield-alt"></i> Enable 2FA</button>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>

                <div class="text-center">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i> Save Changes
                    </button>
                </div>
            </form>
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
    // Toggle required dynamically only for 2FA actions
    (function(){
        const form = document.querySelector('form[method="POST"]');
        if (!form) return;

        const otpEnable = document.getElementById('otp_enable');
        const otpDisable = document.getElementById('otp_disable');

        form.addEventListener('click', function(e){
            const target = e.target;
            // Before any submit, remove required from both OTP fields
            if (otpEnable) otpEnable.removeAttribute('required');
            if (otpDisable) otpDisable.removeAttribute('required');

            if (target && target.name === 'confirm_enable_2fa') {
                if (otpEnable) otpEnable.setAttribute('required', 'required');
            } else if (target && target.name === 'disable_2fa') {
                if (otpDisable) otpDisable.setAttribute('required', 'required');
            }
        }, true);
    })();
    </script>
</body>
</html>



