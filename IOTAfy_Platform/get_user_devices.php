<?php
require 'config.inc';

header('Content-Type: application/json');

// Require authenticated session
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized']);
    exit;
}

// Validate input (allow numeric strings, cast safely to int)
$requestedUserId = isset($_GET['user_id']) ? (int)$_GET['user_id'] : 0;
if ($requestedUserId <= 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid user_id']);
    exit;
}

// Authorization: allow only self or privileged roles (admin / superuser)
$role = $_SESSION['role'] ?? null;
$isPrivileged = in_array($role, ['admin', 'superuser'], true);
if (!$isPrivileged && (int)$_SESSION['user_id'] !== (int)$requestedUserId) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Forbidden']);
    exit;
}

// Fetch and return devices
$db = getDbConnection();
try {
    $stmt = $db->prepare("SELECT id, name, mac FROM devices WHERE user_id = :user_id ORDER BY name");
    $stmt->bindParam(':user_id', $requestedUserId, PDO::PARAM_INT);
    $stmt->execute();
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode($devices);
} catch (PDOException $e) {
    logMessage("Error fetching user devices via API: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Database error']);
}
?>
