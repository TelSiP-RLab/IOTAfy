<?php
// add_device.php

require 'config.inc'; // Include the configuration file

// Check if session is already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$message = "";

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $name = $_POST['name'];
    $ip = $_POST['ip'];
    $mac = $_POST['mac'];
    $device_id = $_POST['device_id'];
    $firmware_version = $_POST['firmware_version'];
    $external_ip = $_POST['external_ip'];

    $db = getDbConnection();
    $stmt = $db->prepare("INSERT INTO devices (name, ip, mac, device_id, firmware_version, external_ip, status, timestamp) VALUES (:name, :ip, :mac, :device_id, :firmware_version, :external_ip, 'offline', CURRENT_TIMESTAMP)");
    $stmt->bindParam(':name', $name);
    $stmt->bindParam(':ip', $ip);
    $stmt->bindParam(':mac', $mac);
    $stmt->bindParam(':device_id', $device_id);
    $stmt->bindParam(':firmware_version', $firmware_version);
    $stmt->bindParam(':external_ip', $external_ip);
    if ($stmt->execute()) {
        $message = "Device added successfully.";

        // Create the firmware version file if it doesn't already exist
        $filePath = BASE_DIR . $mac . '.version';
        if (!file_exists($filePath)) {
            file_put_contents($filePath, $firmware_version);
        }
    } else {
        $message = "Failed to add device.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add Device</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">Add Device</h1>
        <?php if (!empty($message)): ?>
            <div class="alert alert-info text-center"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        <form method="POST" action="" class="mx-auto" style="max-width: 600px;">
            <div class="form-group">
                <label for="name">Device Name</label>
                <input type="text" class="form-control" id="name" name="name" required>
            </div>
            <div class="form-group">
                <label for="ip">IP Address</label>
                <input type="text" class="form-control" id="ip" name="ip" required>
            </div>
            <div class="form-group">
                <label for="mac">MAC Address</label>
                <input type="text" class="form-control" id="mac" name="mac" required>
            </div>
            <div class="form-group">
                <label for="device_id">Device ID</label>
                <input type="text" class="form-control" id="device_id" name="device_id" required>
            </div>
            <div class="form-group">
                <label for="firmware_version">Firmware Version</label>
                <input type="text" class="form-control" id="firmware_version" name="firmware_version" required>
            </div>
            <div class="form-group">
                <label for="external_ip">External IP Address</label>
                <input type="text" class="form-control" id="external_ip" name="external_ip" required>
            </div>
            <button type="submit" class="btn btn-primary btn-block">Add Device</button>
        </form>
        <div class="text-center mt-4">
            <a href="device_management.php" class="btn btn-secondary">Back to Device Management</a>
        </div>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
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

