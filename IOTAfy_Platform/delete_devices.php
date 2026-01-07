<?php
// delete_device.php

require 'config.inc'; // Include the configuration file

if (!isset($_SESSION['user_id']) || !checkPermission('delete_device')) {
    header('Location: login.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Process form submission
    $id = $_POST['id'];

    $db = getDbConnection();

    // Delete record
    $stmt = $db->prepare("DELETE FROM device_info WHERE id = :id");
    $stmt->bindParam(':id', $id);
    $stmt->execute();

    // Redirect to show_devices.php with a success message
    header('Location: show_devices.php?status=deleted');
    exit;
}

// Fetch device info
$id = $_GET['id'];
$db = getDbConnection();
$stmt = $db->prepare("SELECT * FROM device_info WHERE id = :id");
$stmt->bindParam(':id', $id);
$stmt->execute();
$device = $stmt->fetch(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Delete Device</title>
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
        form {
            display: flex;
            flex-direction: column;
        }
        label, input, button {
            margin: 10px 0;
        }
        input, button {
            padding: 10px;
            font-size: 1em;
        }
        button {
            background-color: #007BFF;
            color: white;
            border: none;
            cursor: pointer;
        }
        button:hover {
            background-color: #0056b3;
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
        <h1>Delete Device</h1>
        <div class="back-link"><a href="index.php">Back to Main Menu</a></div>
        <form method="POST" action="">
            <input type="hidden" name="id" value="<?php echo htmlspecialchars($device['id']); ?>">
            <p>Are you sure you want to delete the device <strong><?php echo htmlspecialchars($device['name']); ?></strong>?</p>
            <button type="submit">Delete Device</button>
        </form>
        <div class="back-link"><a href="index.php">Back to Main Menu</a></div>
    </div>
</body>
</html>

