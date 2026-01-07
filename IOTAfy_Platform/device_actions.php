<?php
// device_actions.php

require 'config.inc'; // Include the configuration file

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['device_ids'])) {
    $db = getDbConnection();
    $action = $_POST['action'];
    $device_ids = $_POST['device_ids'];

    if ($action == 'delete') {
        $stmt = $db->prepare("DELETE FROM device_info WHERE id = :id");
        foreach ($device_ids as $device_id) {
            $stmt->bindParam(':id', $device_id, PDO::PARAM_INT);
            $stmt->execute();
        }
        header('Location: search_devices.php?status=deleted');
        exit;
    } elseif ($action == 'edit' && count($device_ids) == 1) {
        $device_id = $device_ids[0];
        header("Location: edit_device.php?id=$device_id");
        exit;
    } elseif ($action == 'change_group' && isset($_POST['group_id'])) {
        $group_id = $_POST['group_id'];
        $stmt = $db->prepare("UPDATE device_info SET group_id = :group_id WHERE id = :id");
        foreach ($device_ids as $device_id) {
            $stmt->bindParam(':group_id', $group_id, PDO::PARAM_INT);
            $stmt->bindParam(':id', $device_id, PDO::PARAM_INT);
            $stmt->execute();
        }
        header('Location: search_devices.php?status=group_changed');
        exit;
    } else {
        header('Location: search_devices.php?status=error');
        exit;
    }
} else {
    header('Location: search_devices.php?status=error');
    exit;
}
?>

