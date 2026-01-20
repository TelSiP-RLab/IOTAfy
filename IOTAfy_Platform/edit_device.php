<?php
// edit_device.php

require 'config.inc'; // Include the configuration file

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$db = getDbConnection();
$message = "";

if (isset($_GET['id'])) {
    $device_id = $_GET['id'];
    $stmt = $db->prepare("SELECT * FROM devices WHERE id = :id");
    $stmt->bindParam(':id', $device_id);
    $stmt->execute();
    $device = $stmt->fetch(PDO::FETCH_ASSOC);
} else {
    header('Location: device_management.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $name = $_POST['name'];
    $ip = $_POST['ip'];
    $mac = $_POST['mac'];
    $device_id = $_POST['device_id'];
    $firmware_version = $_POST['firmware_version'];

    $stmt = $db->prepare("UPDATE devices SET name = :name, ip = :ip, mac = :mac, device_id = :device_id, firmware_version = :firmware_version WHERE id = :id");
    $stmt->bindParam(':name', $name);
    $stmt->bindParam(':ip', $ip);
    $stmt->bindParam(':mac', $mac);
    $stmt->bindParam(':device_id', $device_id);
    $stmt->bindParam(':firmware_version', $firmware_version);
    $stmt->bindParam(':id', $device_id);
    if ($stmt->execute()) {
        $message = "Device updated successfully.";
    } else {
        $message = "Failed to update device.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Device</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">Edit Device</h1>
        <?php if (!empty($message)): ?>
            <div class="alert alert-info text-center"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        <form method="POST" action="" class="mx-auto" style="max-width: 600px;">
            <div class="form-group">
                <label for="name">Device Name</label>
                <input type="text" class="form-control" id="name" name="name" value="<?php echo htmlspecialchars($device['name'] ?? ''); ?>" required>
            </div>
            <div class="form-group">
                <label for="ip">IP Address</label>
                <input type="text" class="form-control" id="ip" name="ip" value="<?php echo htmlspecialchars($device['ip'] ?? ''); ?>" required>
            </div>
            <div class="form-group">
                <label for="mac">MAC Address</label>
                <input type="text" class="form-control" id="mac" name="mac" value="<?php echo htmlspecialchars($device['mac'] ?? ''); ?>" required>
            </div>
            <div class="form-group">
                <label for="device_id">Device ID</label>
                <input type="text" class="form-control" id="device_id" name="device_id" value="<?php echo htmlspecialchars($device['device_id'] ?? ''); ?>" required>
            </div>
            <div class="form-group">
                <label for="firmware_version">Firmware Version</label>
                <input type="text" class="form-control" id="firmware_version" name="firmware_version" value="<?php echo htmlspecialchars($device['firmware_version'] ?? ''); ?>" required>
            </div>
            <button type="submit" class="btn btn-primary btn-block">Update Device</button>
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

