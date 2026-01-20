<?php
require 'config.inc';
require_once 'totp.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// If not coming from pending 2FA, redirect to login
if (empty($_SESSION['pending_2fa_user_id'])) {
    header('Location: login.php');
    exit;
}

$db = getDbConnection();
$stmt = $db->prepare("SELECT id, username, role, twofa_secret FROM users WHERE id = :id");
$stmt->execute(['id' => $_SESSION['pending_2fa_user_id']]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$user || empty($user['twofa_secret'])) {
    // Nothing to verify; clean up and redirect
    unset($_SESSION['pending_2fa_user_id']);
    header('Location: login.php');
    exit;
}

$error = '';

// Handle rate limiting basic: track attempts in session
$_SESSION['otp_attempts'] = $_SESSION['otp_attempts'] ?? 0;
$_SESSION['otp_lock_until'] = $_SESSION['otp_lock_until'] ?? null;

if (!empty($_SESSION['otp_lock_until']) && time() < (int)$_SESSION['otp_lock_until']) {
    $remaining = (int)$_SESSION['otp_lock_until'] - time();
    $error = "Too many attempts. Try again in " . ceil($remaining / 60) . " minutes.";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($error)) {
    $otp = trim((string)($_POST['otp'] ?? ''));
    $plainSecret = '';
    try { $plainSecret = decryptSensitive($user['twofa_secret']); } catch (Throwable $e) { $plainSecret = ''; }
    $valid = $plainSecret ? totp_verify($plainSecret, $otp, 30, 6, 1, 'sha1') : false;
    if ($valid) {
        // Success: create full session
        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        unset($_SESSION['pending_2fa_user_id'], $_SESSION['otp_attempts'], $_SESSION['otp_lock_until']);
        logMessage("2FA verification successful for user {$user['username']}");
        header('Location: index.php');
        exit;
    } else {
        $_SESSION['otp_attempts'] = (int)$_SESSION['otp_attempts'] + 1;
        logMessage("2FA verification failed for user {$user['username']} (attempt #{$_SESSION['otp_attempts']})");
        if ($_SESSION['otp_attempts'] >= 5) {
            $_SESSION['otp_lock_until'] = time() + (5 * 60); // 5 minutes lock
        }
        $error = 'Invalid code. Please try again.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify 2FA</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .container { max-width: 420px; margin-top: 100px; }
        .card { border: none; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .card-header { background-color: #fff; border-bottom: none; text-align: center; padding: 20px; }
        .card-header i { font-size: 48px; color: #17a2b8; margin-bottom: 10px; }
    </style>
<?php // CSRF token for this form
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
</head>
<body>
<div class="container">
    <div class="card">
        <div class="card-header">
            <i class="fas fa-shield-alt"></i>
            <h4 class="mb-0">Two-Factor Authentication</h4>
        </div>
        <div class="card-body">
            <?php if (!empty($error)): ?>
                <div class="alert alert-danger"><i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            <p class="text-muted">Enter the 6-digit code from your authenticator app.</p>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <div class="form-group">
                    <label for="otp">Authentication Code</label>
                    <input type="text" class="form-control" id="otp" name="otp" inputmode="numeric" pattern="\d{6}" maxlength="6" required>
                </div>
                <button type="submit" class="btn btn-info btn-block"><i class="fas fa-unlock"></i> Verify</button>
            </form>
        </div>
    </div>
    <p class="text-center mt-3"><a href="login.php">Back to login</a></p>
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
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


