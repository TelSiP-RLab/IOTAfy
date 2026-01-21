<?php
// delete_group.php

require 'config.inc'; // Include the configuration file

// Check if the form was submitted
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['id'])) {
    $db = getDbConnection();

    // Prepare the DELETE statement
    $stmt = $db->prepare("DELETE FROM groups WHERE id = :id");
    $stmt->bindParam(':id', $_POST['id'], PDO::PARAM_INT);
    $stmt->execute();

    // Unassign devices from this group
    $unassign_stmt = $db->prepare("UPDATE device_info SET group_id = NULL WHERE group_id = :group_id");
    $unassign_stmt->bindParam(':group_id', $_POST['id'], PDO::PARAM_INT);
    $unassign_stmt->execute();

    // Redirect back to the view_groups.php with a success message
    header('Location: view_groups.php?status=deleted');
    exit;
} else {
    // Redirect back to the view_groups.php with an error message
    header('Location: view_groups.php?status=error');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Delete Group</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
        }
        .container {
            width: 80%;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            text-align: center;
        }
        .back-link {
            text-align: center;
            margin: 20px 0;
        }
        .back-link a {
            text-decoration: none;
            color: #007BFF;
            font-weight: bold;
        }
        .back-link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Delete Group</h1>
        <div class="back-link"><a href="view_groups.php">Back to View Groups</a></div>
        <p>Group deleted successfully.</p>
        <div class="back-link"><a href="view_groups.php">Back to View Groups</a></div>
    </div>

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

