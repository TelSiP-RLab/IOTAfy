<?php
// ping.php

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

// Normalize and validate Authorization header (supports "Bearer <token>" or raw token)
$headers = getallheaders();
$normalized = [];
foreach ($headers as $k => $v) { $normalized[strtolower($k)] = $v; }
if (!isset($normalized['authorization'])) {
    logMessage("Unauthorized access attempt: Missing Authorization header");
    http_response_code(401);
    echo json_encode(["status" => "error", "message" => "Unauthorized"]);
    exit;
}
$rawAuth = trim((string)$normalized['authorization']);
if (preg_match('/^Bearer\s+(.+)$/i', $rawAuth, $m)) {
    $authKey = trim($m[1]);
} else {
    $authKey = $rawAuth;
}
if (!preg_match('/^[A-Za-z0-9._\-]{16,512}$/', $authKey)) {
    logMessage("Unauthorized access attempt: Invalid token format");
    http_response_code(401);
    echo json_encode(["status" => "error", "message" => "Unauthorized"]);
    exit;
}
// Prepare masked and fingerprint for token (never log raw token)
$maskedKey = (strlen($authKey) > 8)
    ? (substr($authKey, 0, 4) . str_repeat('*', max(0, strlen($authKey) - 8)) . substr($authKey, -4))
    : '***';
$keyFingerprint = substr(hash('sha256', (string)$authKey), 0, 12);
logMessage("Authorization header validated (masked_key={$maskedKey}, fp={$keyFingerprint})");

try {
    // Use shared database connection
    $db = getDbConnection();

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
    if (isset($data['device_id']) && isset($data['mac']) && isset($data['status'])) {
        // Update the device status and timestamps
        $stmt = $db->prepare("UPDATE devices SET status = :status, last_ping = CURRENT_TIMESTAMP, timestamp = CURRENT_TIMESTAMP WHERE mac = :mac AND device_id = :device_id AND user_id = :user_id");
        $stmt->bindParam(':status', $data['status']);
        $stmt->bindParam(':mac', $data['mac']);
        $stmt->bindParam(':device_id', $data['device_id']);
        $stmt->bindParam(':user_id', $userId);
        $stmt->execute();

        if ($stmt->rowCount() == 0) {
            logMessage("Device not found or does not belong to user: MAC {$data['mac']}, Device ID {$data['device_id']}");
            echo json_encode(["status" => "error", "message" => "Device not found or does not belong to user."]);
        } else {
            logMessage("Device status updated: MAC {$data['mac']}, Device ID {$data['device_id']}, Status {$data['status']}");
            echo json_encode(["status" => "success", "message" => "Device status updated."]);
        }
    } else {
        // Safe logging: do not log full data payload
        $receivedKeys = is_array($data) ? implode(',', array_keys($data)) : 'invalid';
        logMessage("Invalid data received (keys={$receivedKeys})");
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

