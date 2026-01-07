<?php
// permission_management.php

require 'config.inc'; // Include the configuration file

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header('Location: login.php');
    exit;
}

$db = getDbConnection();
$message = "";

// Handle permission update
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update_permission'])) {
    $user_id = $_POST['user_id'];
    $permission = $_POST['permission'];
    $value = $_POST['value'] == '1' ? 1 : 0;

    $stmt = $db->prepare("UPDATE user_permissions SET value = :value WHERE user_id = :user_id AND permission = :permission");
    $stmt->bindParam(':value', $value);
    $stmt->bindParam(':user_id', $user_id);
    $stmt->bindParam(':permission', $permission);
    if ($stmt->execute()) {
        $message = "Permission updated successfully.";
    } else {
        $message = "Failed to update permission.";
    }
}

// Fetch all users and permissions
$users = $db->query("SELECT * FROM users ORDER BY username")->fetchAll(PDO::FETCH_ASSOC);
$permissions = ['view_devices', 'edit_device', 'delete_device', 'generate_firmware_file'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Permission Management</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">Permission Management</h1>
        <?php if (!empty($message)): ?>
            <div class="alert alert-info text-center"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        <form method="POST" action="" class="mx-auto" style="max-width: 800px;">
            <div class="form-group">
                <label for="user_id">User</label>
                <select id="user_id" name="user_id" class="form-control" required>
                    <?php foreach ($users as $user): ?>
                        <option value="<?php echo $user['id']; ?>"><?php echo htmlspecialchars($user['username']); ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group">
                <label for="permission">Permission</label>
                <select id="permission" name="permission" class="form-control" required>
                    <?php foreach ($permissions as $permission): ?>
                        <option value="<?php echo $permission; ?>"><?php echo $permission; ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group">
                <label for="value">Value</label>
                <select id="value" name="value" class="form-control" required>
                    <option value="1">Allow</option>
                    <option value="0">Deny</option>
                </select>
            </div>
            <button type="submit" name="update_permission" class="btn btn-primary btn-block">Update Permission</button>
        </form>
        <div class="text-center mt-4">
            <a href="index.php" class="btn btn-secondary">Back to Main Menu</a>
        </div>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>

