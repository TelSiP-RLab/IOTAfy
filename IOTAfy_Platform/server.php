<?php
// server.php

require 'config.inc'; // Include the configuration file

// Set the content type to application/json
header('Content-Type: application/json');

// Get the raw POST data (do not log raw body)
$rawPostData = file_get_contents('php://input');
// Decode the JSON data
$data = json_decode($rawPostData, true);
// Safe summary logging: length and top-level keys only
$bodyLength = is_string($rawPostData) ? strlen($rawPostData) : 0;
$topLevelKeys = is_array($data) ? implode(',', array_slice(array_keys($data), 0, 10)) : 'n/a';
logMessage("Received POST body (len={$bodyLength}, keys={$topLevelKeys})");

// Function to create a version file (with safe filename)
function createVersionFile($mac, $firmwareVersion) {
    // Keep only hex digits for filename, uppercase
    $safeMac = strtoupper(preg_replace('/[^A-F0-9]/i', '', (string)$mac));
    if ($safeMac === '' || strlen($safeMac) > 40) {
        // Do not attempt to write if invalid
        logMessage("Skipping version file creation due to invalid MAC for filename.");
        return;
    }
    $filePath = BASE_DIR . "{$safeMac}.version";
    if (!file_exists($filePath)) {
        file_put_contents($filePath, $firmwareVersion);
        logMessage("Created version file for MAC: {$safeMac} with firmware version: {$firmwareVersion}");
    }
}

// Validate and extract Authorization token
function extractAuthToken($headers) {
    // Normalize header keys to handle different casing
    $normalized = [];
    foreach ($headers as $k => $v) {
        $normalized[strtolower($k)] = $v;
    }
    if (!isset($normalized['authorization'])) {
        return [null, 'Missing Authorization header'];
    }
    $raw = trim((string)$normalized['authorization']);
    if ($raw === '') {
        return [null, 'Empty Authorization header'];
    }
    // Support "Bearer <token>" or raw token
    if (preg_match('/^Bearer\s+(.+)$/i', $raw, $m)) {
        $token = trim($m[1]);
    } else {
        $token = $raw;
    }
    // Validate allowed characters and length
    if (!preg_match('/^[A-Za-z0-9._\-]{16,512}$/', $token)) {
        return [null, 'Invalid token format'];
    }
    return [$token, null];
}

// Validate MAC address (accepts 6 octets with ':' or '-' or 12 hex without separators)
function isValidMac($mac) {
    if (!is_string($mac)) { return false; }
    $mac = trim($mac);
    if ($mac === '') { return false; }
    if (preg_match('/^([0-9A-Fa-f]{2}([:\-])){5}[0-9A-Fa-f]{2}$/', $mac)) { return true; }
    if (preg_match('/^[0-9A-Fa-f]{12}$/', $mac)) { return true; }
    return false;
}

// Check for the Authorization header and validate
$headers = getallheaders();
list($authKey, $authError) = extractAuthToken($headers);
// Prepare masked and fingerprint for token (never log raw token)
$maskedKey = (is_string($authKey) && strlen($authKey) > 8)
    ? (substr($authKey, 0, 4) . str_repeat('*', max(0, strlen($authKey) - 8)) . substr($authKey, -4))
    : '***';
$keyFingerprint = $authKey !== null ? substr(hash('sha256', (string)$authKey), 0, 12) : 'n/a';
if ($authError !== null) {
    logMessage("Unauthorized access attempt: {$authError}");
    http_response_code(401);
    echo json_encode(["status" => "error", "message" => "Unauthorized"]);
    exit;
}
logMessage("Authorization header validated (masked_key={$maskedKey}, fp={$keyFingerprint}).");

try {
    // Open SQLite database
    $db = new PDO('sqlite:' . DB_PATH);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    logMessage("Connected to SQLite database");

    // Verify the provided authkey
    $stmt = $db->prepare("SELECT id FROM users WHERE authkey = :authkey");
    $stmt->bindParam(':authkey', $authKey);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        logMessage("Unauthorized access attempt: Invalid Authorization key (fp={$keyFingerprint})");
        http_response_code(401);
        echo json_encode(["status" => "error", "message" => "Unauthorized"]);
        exit;
    }

    $userId = $user['id'];
    logMessage("Authorized user ID: " . $userId . " (fp={$keyFingerprint})");

    // Check if data is received properly
    if (
        isset($data['ip']) && isset($data['mac']) && isset($data['device_id']) &&
        isset($data['name']) && isset($data['firmware_version']) && isset($data['external_ip'])
    ) {
        // Validate MAC format
        if (!isValidMac($data['mac'])) {
            logMessage("Invalid MAC format received: " . (string)$data['mac']);
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "Invalid MAC address format."]);
            exit;
        }
        // Check for duplicity regardless of the user
        $stmt = $db->prepare("SELECT * FROM devices WHERE mac = :mac");
        $stmt->bindParam(':mac', $data['mac']);
        $stmt->execute();
        $existingDevice = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($existingDevice) {
            logMessage("Existing device found for MAC: " . $data['mac']);
            // Check for exact match
            if (
                $existingDevice['ip'] == $data['ip'] &&
                $existingDevice['device_id'] == $data['device_id'] &&
                $existingDevice['name'] == $data['name'] &&
                $existingDevice['firmware_version'] == $data['firmware_version'] &&
                $existingDevice['external_ip'] == $data['external_ip'] &&
                $existingDevice['user_id'] == $userId
            ) {
                logMessage("Device already exists with the same data for MAC: " . $data['mac'] . ", no update needed.");
                echo json_encode(["status" => "info", "message" => "Device already exists with the same data, no update needed."]);
            } else {
                // Update the existing record
                $stmt = $db->prepare(
                    "UPDATE devices SET 
                        ip = :ip, device_id = :device_id, name = :name, 
                        firmware_version = :firmware_version, external_ip = :external_ip, 
                        timestamp = CURRENT_TIMESTAMP, user_id = :user_id 
                    WHERE mac = :mac"
                );
                $stmt->bindParam(':ip', $data['ip']);
                $stmt->bindParam(':device_id', $data['device_id']);
                $stmt->bindParam(':name', $data['name']);
                $stmt->bindParam(':firmware_version', $data['firmware_version']);
                $stmt->bindParam(':external_ip', $data['external_ip']);
                $stmt->bindParam(':user_id', $userId);
                $stmt->bindParam(':mac', $data['mac']);
                $stmt->execute();
                logMessage("Device data updated for MAC: " . $data['mac']);
                echo json_encode(["status" => "success", "message" => "Device data updated."]);
            }
        } else {
            logMessage("No existing device found for MAC: " . $data['mac'] . ", inserting new record.");
            // Insert new record
            $stmt = $db->prepare(
                "INSERT INTO devices (ip, mac, device_id, name, firmware_version, external_ip, user_id) 
                VALUES (:ip, :mac, :device_id, :name, :firmware_version, :external_ip, :user_id)"
            );
            $stmt->bindParam(':ip', $data['ip']);
            $stmt->bindParam(':mac', $data['mac']);
            $stmt->bindParam(':device_id', $data['device_id']);
            $stmt->bindParam(':name', $data['name']);
            $stmt->bindParam(':firmware_version', $data['firmware_version']);
            $stmt->bindParam(':external_ip', $data['external_ip']);
            $stmt->bindParam(':user_id', $userId);
            $stmt->execute();

            // Create version file for the new device
            createVersionFile($data['mac'], $data['firmware_version']);
            logMessage("Device data inserted for MAC: " . $data['mac']);
            echo json_encode(["status" => "success", "message" => "Device data inserted."]);
        }
    } else {
        logMessage("Invalid data received: " . json_encode($data));
        // Respond with an error message if data is missing
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "Invalid data received."]);
    }
} catch (PDOException $e) {
    logMessage("Database error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Database error: " . $e->getMessage()]);
}
?>

