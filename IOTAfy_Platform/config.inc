<?php
// config.inc

// Set secure session settings before session_start()
if (session_status() === PHP_SESSION_NONE) {
    $isHttps = (
        (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] && strtolower((string)$_SERVER['HTTPS']) !== 'off') ||
        (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower((string)$_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https')
    );
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', $isHttps ? '1' : '0');
    ini_set('session.cookie_samesite', 'Lax');
    ini_set('session.use_strict_mode', 1);
    session_start();  // Only start the session if it's not already started
}

// Resolve paths relative to project root for portability across servers
$ROOT_DIR = realpath(__DIR__);
define("DB_PATH", $ROOT_DIR . DIRECTORY_SEPARATOR . "data" . DIRECTORY_SEPARATOR . "device_info.db");
define("LOG_FILE", $ROOT_DIR . DIRECTORY_SEPARATOR . "logs" . DIRECTORY_SEPARATOR . "server.log");
define("MONITOR_LOG_FILE", $ROOT_DIR . DIRECTORY_SEPARATOR . "logs" . DIRECTORY_SEPARATOR . "monitor.log");
define("BASE_DIR", $ROOT_DIR . DIRECTORY_SEPARATOR . "firmware" . DIRECTORY_SEPARATOR);
define("TARGET_DIR", BASE_DIR); // Same as BASE_DIR

// Email configuration settings
// Use SMTP_FROM from environment if available, otherwise use default
define("EMAIL_FROM", getenv("SMTP_FROM") ?: "no-reply@yourdomain.com");
define("EMAIL_SUBJECT", "Device Status Changed");

// Offline detection threshold in minutes (used by monitor_devices.php)
define("OFFLINE_THRESHOLD_MINUTES", 15);
// Separate threshold for still-online notification (minutes)
define("STILL_ONLINE_MINUTES", 5);


/**
 * Establishes a connection to the SQLite database.
 *
 * @return PDO The database connection.
 * @throws PDOException If the connection fails.
 */
function getDbConnection() {
    try {
        $db = new PDO("sqlite:" . DB_PATH);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        // Ensure 2FA-related columns exist (lazy migration)
        ensureTwoFactorColumns($db);
        return $db;
    } catch (PDOException $e) {
        logMessage("Database connection error: " . $e->getMessage());
        die(json_encode(['status' => 'error', 'message' => 'Database connection error: ' . $e->getMessage()]));
    }
}

//session_start();

/**
 * Logs a message to the log file.
 *
 * @param string $message The message to log.
 */
function rotateLogIfNeeded($filePath, $maxBytes = 1048576, $maxFiles = 7) {
    // Ensure directory exists
    $dir = dirname($filePath);
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }
    // If file doesn't exist yet, nothing to do
    if (!file_exists($filePath)) {
        return;
    }
    $size = filesize($filePath);
    if ($size === false) {
        return;
    }
    // Determine if daily rotation is needed (file mtime is not today)
    $fileDate = date('Y-m-d', (int)filemtime($filePath));
    $today = date('Y-m-d');
    $needsDailyRotate = ($fileDate !== $today);
    $needsSizeRotate = ((int)$size >= (int)$maxBytes);
    if (!$needsDailyRotate && !$needsSizeRotate) {
        return; // no rotation needed
    }
    // Safe rotate: rename current file to a temp path, then gzip it to final rotated name
    $dateSuffix = date('Ymd_His');
    $tempPath = $filePath . ".rotate_" . $dateSuffix . ".tmp";
    if (!@rename($filePath, $tempPath)) {
        return; // cannot rotate; avoid blocking logging
    }
    // Compose final gzip path
    $gzPath = $filePath . "." . $dateSuffix . ".gz";
    $in = @fopen($tempPath, 'rb');
    $gz = @gzopen($gzPath, 'wb6');
    if ($in && $gz) {
        while (!feof($in)) {
            $chunk = fread($in, 1048576);
            if ($chunk === false) { break; }
            gzwrite($gz, $chunk);
        }
    }
    if ($gz) { @gzclose($gz); }
    if ($in) { @fclose($in); }
    @unlink($tempPath);
    // Prune old rotated files, keep newest $maxFiles
    $rotated = glob($filePath . '.*.gz') ?: [];
    usort($rotated, function ($a, $b) { return filemtime($b) <=> filemtime($a); });
    $toDelete = array_slice($rotated, (int)$maxFiles);
    foreach ($toDelete as $old) {
        @unlink($old);
    }
}

function logMessage($message) {
    $timestamp = date("Y-m-d H:i:s");
    $sanitized = redactSecrets((string)$message);
    rotateLogIfNeeded(LOG_FILE);
    file_put_contents(LOG_FILE, "[$timestamp] $sanitized\n", FILE_APPEND);
}

/**
 * Writes a message to the monitor log file.
 *
 * @param string $message
 */
function monitorLog($message) {
    $timestamp = date("Y-m-d H:i:s");
    $sanitized = redactSecrets((string)$message);
    rotateLogIfNeeded(MONITOR_LOG_FILE);
    file_put_contents(MONITOR_LOG_FILE, "[$timestamp] $sanitized\n", FILE_APPEND);
}

/**
 * Redacts secrets (tokens, passwords, auth keys) from log messages.
 * Masks the middle of the secret keeping at most first and last 4 chars.
 *
 * @param string $text
 * @return string
 */
function redactSecrets($text) {
    $mask = function ($secret) {
        $secret = (string)($secret ?? '');
        $len = strlen($secret);
        if ($len <= 8) {
            return str_repeat('*', max(3, $len));
        }
        $prefix = substr($secret, 0, 4);
        $suffix = substr($secret, -4);
        return $prefix . str_repeat('*', $len - 8) . $suffix;
    };

    // JSON style: "auth_key":"..."
    $text = preg_replace_callback('/("auth[_-]?key"\s*:\s*")(.*?)(")/i', function ($m) use ($mask) {
        return $m[1] . $mask($m[2]) . $m[3];
    }, $text);

    // key=value or key: value patterns
    $text = preg_replace_callback('/\b(auth[_-]?key|token|access[_-]?token|id[_-]?token|api[_-]?key|password)\s*[:=]\s*([^\s\"]+)/i', function ($m) use ($mask) {
        return $m[1] . '=' . $mask($m[2]);
    }, $text);

    // Authorization: Bearer <token>
    $text = preg_replace_callback('/(Authorization\s*:\s*Bearer\s+)([A-Za-z0-9._\-]+)(?!\S)/i', function ($m) use ($mask) {
        return $m[1] . $mask($m[2]);
    }, $text);

    // Bare "Authorization: <value>"
    $text = preg_replace_callback('/(Authorization\s*:\s*)([^\s]+)(?!\S)/i', function ($m) use ($mask) {
        return $m[1] . $mask($m[2]);
    }, $text);

    // JSON style password: "password":"..."
    $text = preg_replace_callback('/("password"\s*:\s*")(.*?)(")/i', function ($m) use ($mask) {
        return $m[1] . $mask($m[2]) . $m[3];
    }, $text);

    return $text;
}

/**
 * Encryption utilities for sensitive data (AES-256-GCM).
 * Requires APP KEY in environment var IOTAFY_APP_KEY (base64-encoded 32 bytes recommended).
 */
function getAppKey(): string {
    $key = getenv('IOTAFY_APP_KEY') ?: '';
    if ($key === '') {
        // fallback: derive from file path (not ideal, but prevents empty key in dev)
        $fallback = hash('sha256', __FILE__, true);
        return $fallback; // 32 bytes
    }
    // If base64 prefixed, decode
    if (strpos($key, 'base64:') === 0) {
        $decoded = base64_decode(substr($key, 7), true);
        if ($decoded !== false && strlen($decoded) >= 32) {
            return substr($decoded, 0, 32);
        }
    }
    // Raw string: stretch to 32 bytes
    return substr(hash('sha256', $key, true), 0, 32);
}

function encryptSensitive(string $plaintext): string {
    $key = getAppKey();
    $iv = random_bytes(12); // GCM nonce
    $tag = '';
    $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($cipher === false) {
        throw new RuntimeException('Encryption failed');
    }
    return base64_encode($iv . $tag . $cipher);
}

function decryptSensitive(string $ciphertextB64): string {
    $data = base64_decode($ciphertextB64, true);
    if ($data === false || strlen($data) < 12 + 16) {
        throw new RuntimeException('Invalid ciphertext');
    }
    $iv = substr($data, 0, 12);
    $tag = substr($data, 12, 16);
    $cipher = substr($data, 28);
    $key = getAppKey();
    $plain = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($plain === false) {
        throw new RuntimeException('Decryption failed');
    }
    return $plain;
}

/**
 * Ensures the database has the columns required for 2FA.
 * Adds columns if missing: twofa_enabled INTEGER DEFAULT 0, twofa_secret TEXT.
 * This is safe to run on every request (no-op if already present).
 *
 * @param PDO $db
 * @return void
 */
function ensureTwoFactorColumns(PDO $db) {
    try {
        $stmt = $db->query("PRAGMA table_info(users)");
        $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $existing = [];
        foreach ($columns as $col) {
            $existing[strtolower((string)$col['name'])] = true;
        }

        if (!isset($existing['twofa_enabled'])) {
            $db->exec("ALTER TABLE users ADD COLUMN twofa_enabled INTEGER DEFAULT 0");
        }
        if (!isset($existing['twofa_secret'])) {
            $db->exec("ALTER TABLE users ADD COLUMN twofa_secret TEXT");
        }
        // Optional future: recovery codes
        // if (!isset($existing['twofa_recovery_codes'])) {
        //     $db->exec("ALTER TABLE users ADD COLUMN twofa_recovery_codes TEXT");
        // }
    } catch (Throwable $e) {
        // Do not break application if migration fails; just log.
        logMessage("2FA migration check failed: " . $e->getMessage());
    }
}

/**
 * Checks if the current user has a specific permission.
 *
 * @param string $permission The name of the permission to check.
 * @return bool True if the user has the permission, false otherwise.
 */
function checkPermission($permission) {
    if ($_SESSION["role"] === "admin") {
        return true;
    }

    $db = getDbConnection();
    $stmt = $db->prepare("SELECT 1 FROM group_permissions
                          INNER JOIN user_groups ON group_permissions.group_id = user_groups.group_id
                          INNER JOIN permissions ON group_permissions.permission_id = permissions.id
                          WHERE user_groups.user_id = :user_id AND permissions.name = :permission");
    $stmt->bindParam(":user_id", $_SESSION["user_id"]);
    $stmt->bindParam(":permission", $permission);
    $stmt->execute();
    return $stmt->fetch() !== false;
}

/**
 * Generates a unique authkey for a user.
 *
 * @return string The generated authkey.
 */
function generateAuthkey() {
    return bin2hex(random_bytes(16));
}

/**
 * Assigns a new authkey to a user.
 *
 * @param int $user_id The ID of the user.
 * @return bool True if the authkey was updated successfully, false otherwise.
 */
function assignAuthkey($user_id) {
    $db = getDbConnection();
    $authkey = generateAuthkey();
    $stmt = $db->prepare("UPDATE users SET authkey = :authkey WHERE id = :id");
    $stmt->bindParam(":authkey", $authkey);
    $stmt->bindParam(":id", $user_id);
    return $stmt->execute();
}

/**
 * Verifies if a device belongs to a user by comparing authkeys.
 *
 * @param int $user_id The ID of the user.
 * @param int $device_id The ID of the device.
 * @return bool True if the device belongs to the user, false otherwise.
 */
function verifyDeviceOwnership($user_id, $device_id) {
    $db = getDbConnection();

    // Fetch the user's authkey
    $stmt = $db->prepare("SELECT authkey FROM users WHERE id = :user_id");
    $stmt->bindParam(":user_id", $user_id);
    $stmt->execute();
    $user_authkey = $stmt->fetchColumn();

    // Fetch the device's authkey
    $stmt = $db->prepare("SELECT authkey FROM devices WHERE id = :device_id");
    $stmt->bindParam(":device_id", $device_id);
    $stmt->execute();
    $device_authkey = $stmt->fetchColumn();

    // Compare authkeys
    return $user_authkey === $device_authkey;
}

/**
 * Assigns a device to a user.
 *
 * @param int $user_id The ID of the user.
 * @param int $device_id The ID of the device.
 * @return bool True if the device was assigned successfully, false otherwise.
 */
function assignDeviceToUser($user_id, $device_id) {
    $db = getDbConnection();
    $stmt = $db->prepare("UPDATE devices SET user_id = :user_id WHERE id = :device_id");
    $stmt->bindParam(":user_id", $user_id);
    $stmt->bindParam(":device_id", $device_id);
    return $stmt->execute();
}

/**
 * Unassigns a device from a user.
 *
 * @param int $device_id The ID of the device.
 * @return bool True if the device was unassigned successfully, false otherwise.
 */
function unassignDeviceFromUser($device_id) {
    $db = getDbConnection();
    $stmt = $db->prepare("UPDATE devices SET user_id = NULL WHERE id = :device_id");
    $stmt->bindParam(":device_id", $device_id);
    return $stmt->execute();
}

/**
 * Fetches the devices associated with a user.
 *
 * @param int $user_id The ID of the user.
 * @return array The devices associated with the user.
 */
function getUserDevices($user_id) {
    $db = getDbConnection();
    $stmt = $db->prepare("SELECT * FROM devices WHERE user_id = :user_id");
    $stmt->bindParam(":user_id", $user_id);
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}
