<?php
require 'config.inc';

header('Content-Type: application/json');

// Require authenticated session
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized']);
    exit;
}

// Validate input
if (!isset($_GET['user_id'])) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Missing user_id']);
    exit;
}

$requestedUserId = filter_var($_GET['user_id'], FILTER_VALIDATE_INT);
if ($requestedUserId === false) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid user_id']);
    exit;
}

// Authorization: allow only self or admin
$isAdmin = isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
if (!$isAdmin && (int)$_SESSION['user_id'] !== (int)$requestedUserId) {
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
