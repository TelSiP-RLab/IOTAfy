<?php
// edit_group.php

require 'config.inc'; // Include the configuration file

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header('Location: login.php');
    exit;
}

$db = getDbConnection();
$message = "";

if (isset($_GET['id'])) {
    $group_id = $_GET['id'];
    $stmt = $db->prepare("SELECT * FROM groups WHERE id = :id");
    $stmt->bindParam(':id', $group_id);
    $stmt->execute();
    $group = $stmt->fetch(PDO::FETCH_ASSOC);
} else {
    header('Location: group_management.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $name = $_POST['name'];
    $description = $_POST['description'];

    $stmt = $db->prepare("UPDATE groups SET name = :name, description = :description WHERE id = :id");
    $stmt->bindParam(':name', $name);
    $stmt->bindParam(':description', $description);
    $stmt->bindParam(':id', $group_id);
    if ($stmt->execute()) {
        $message = "Group updated successfully.";
    } else {
        $message = "Failed to update group.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Group</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">Edit Group</h1>
        <?php if (!empty($message)): ?>
            <div class="alert alert-info text-center"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        <form method="POST" action="" class="mx-auto" style="max-width: 600px;">
            <div class="form-group">
                <label for="name">Group Name</label>
                <input type="text" class="form-control" id="name" name="name" value="<?php echo htmlspecialchars($group['name']); ?>" required>
            </div>
            <div class="form-group">
                <label for="description">Description</label>
                <input type="text" class="form-control" id="description" name="description" value="<?php echo htmlspecialchars($group['description']); ?>" required>
            </div>
            <button type="submit" class="btn btn-primary btn-block">Update Group</button>
        </form>
        <div class="text-center mt-4">
            <a href="group_management.php" class="btn btn-secondary">Back to Group Management</a>
        </div>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>

