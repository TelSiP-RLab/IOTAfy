<?php
// reset_admin.php

// STRICT CLI-ONLY: Block web access immediately, before loading any config
if (php_sapi_name() !== 'cli') {
    // Try to log if possible (but don't require config.inc)
    $log_file = __DIR__ . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR . 'server.log';
    if (is_dir(dirname($log_file))) {
        $timestamp = date("Y-m-d H:i:s");
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        file_put_contents($log_file, "[$timestamp] SECURITY: reset_admin.php blocked - non-CLI execution attempt from IP $ip (User-Agent: $user_agent)\n", FILE_APPEND);
    }
    
    // Send 403 response
    if (!headers_sent()) {
        header('Content-Type: text/plain');
        http_response_code(403);
    }
    die("Forbidden: This script can only be run from command line (CLI).\n");
}

// Additional safety check: ensure we're really in CLI mode
if (!defined('STDIN') || !is_resource(STDIN)) {
    die("Error: CLI environment not properly detected.\n");
}

require 'config.inc'; // Include the configuration file

// Default password hash for "admin"
// This is a bcrypt hash for the password: admin
$password_hash = password_hash('admin', PASSWORD_BCRYPT);

try {
    $db = getDbConnection();
    
    // Start transaction for atomicity
    $db->beginTransaction();
    
    // Set the values for the admin user
    $username = 'admin';
    $password = $password_hash;
    $role = 'admin';
    
    // Delete the existing admin user (if exists)
    $delete_stmt = $db->prepare("DELETE FROM users WHERE username = :username");
    $delete_stmt->bindValue(':username', $username);
    $delete_stmt->execute();
    $deleted_count = $delete_stmt->rowCount();
    
    // Insert the new admin user with 2FA disabled
    $insert_stmt = $db->prepare("INSERT INTO users (username, password, role, twofa_enabled, twofa_secret) VALUES (:username, :password, :role, :twofa_enabled, :twofa_secret)");
    $insert_stmt->bindValue(':username', $username);
    $insert_stmt->bindValue(':password', $password);
    $insert_stmt->bindValue(':role', $role);
    $insert_stmt->bindValue(':twofa_enabled', 0, PDO::PARAM_INT);
    $insert_stmt->bindValue(':twofa_secret', null, PDO::PARAM_NULL);
    
    if (!$insert_stmt->execute()) {
        throw new Exception("Failed to insert admin user.");
    }
    
    // Commit transaction
    $db->commit();
    
    $message = "Admin user reset successfully.";
    if ($deleted_count > 0) {
        $message .= " (Deleted $deleted_count existing admin user(s))";
    }
    $message .= " 2FA is disabled.";
    echo $message . "\n";
    logMessage("reset_admin.php: Admin user reset successfully with 2FA disabled");
    
} catch (PDOException $e) {
    // Rollback transaction on error
    if ($db->inTransaction()) {
        $db->rollBack();
    }
    $error_msg = "Database error: " . $e->getMessage();
    echo "Error: $error_msg\n";
    logMessage("reset_admin.php error: $error_msg");
    exit(1);
} catch (Exception $e) {
    // Rollback transaction on error
    if ($db->inTransaction()) {
        $db->rollBack();
    }
    $error_msg = $e->getMessage();
    echo "Error: $error_msg\n";
    logMessage("reset_admin.php error: $error_msg");
    exit(1);
}
?>

