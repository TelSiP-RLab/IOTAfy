<?php
require 'config.inc'; // Include the configuration file

// Καθολικό logging σφαλμάτων/εξαιρέσεων στο monitor.log, ώστε να μη χρειάζεται redirect από το cron.
set_error_handler(function ($severity, $message, $file, $line) {
    // Αγνόησε σιωπηρά errors που έχουν κατασταλεί με @
    if (!(error_reporting() & $severity)) {
        return false;
    }
    $typeMap = [
        E_ERROR             => 'E_ERROR',
        E_WARNING           => 'E_WARNING',
        E_PARSE             => 'E_PARSE',
        E_NOTICE            => 'E_NOTICE',
        E_CORE_ERROR        => 'E_CORE_ERROR',
        E_CORE_WARNING      => 'E_CORE_WARNING',
        E_COMPILE_ERROR     => 'E_COMPILE_ERROR',
        E_COMPILE_WARNING   => 'E_COMPILE_WARNING',
        E_USER_ERROR        => 'E_USER_ERROR',
        E_USER_WARNING      => 'E_USER_WARNING',
        E_USER_NOTICE       => 'E_USER_NOTICE',
        E_STRICT            => 'E_STRICT',
        E_RECOVERABLE_ERROR => 'E_RECOVERABLE_ERROR',
        E_DEPRECATED        => 'E_DEPRECATED',
        E_USER_DEPRECATED   => 'E_USER_DEPRECATED',
    ];
    $type = $typeMap[$severity] ?? (string)$severity;
    monitorLog("PHP {$type}: {$message} in {$file}:{$line}");
    // Επέτρεψε στο προεπιλεγμένο handler να τρέξει για fatal κ.λπ.
    return false;
});

set_exception_handler(function ($e) {
    monitorLog("Uncaught exception (" . get_class($e) . "): " . $e->getMessage() . " in " . $e->getFile() . ":" . $e->getLine());
    // Μπορεί να σταλεί και JSON σφάλματος αν τρέχει μέσω web
    if (php_sapi_name() !== 'cli') {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Internal server error']);
    }
});

/**
 * Sends a notification to the device owner via Email or Telegram, based on preferences.
 * Accepts a single device row that already includes user fields from JOIN.
 */
function sendNotification($deviceRow, $status) {
    $deviceName = $deviceRow['name'] ?? 'Unknown';
    $deviceId = $deviceRow['id'] ?? 'N/A';
    $userEmail = $deviceRow['email'] ?? '';
    $userToken = $deviceRow['token'] ?? '';
    $userChatId = $deviceRow['chat_id'] ?? '';
    $preference = $deviceRow['notification_preference'] ?? 'email';
    $userId = $deviceRow['user_id'] ?? 'N/A';

    $message = "Device '{$deviceName}' (ID: {$deviceId}) is now {$status}.";

    // Email
    if (in_array($preference, ['email', 'both'], true) && filter_var($userEmail, FILTER_VALIDATE_EMAIL)) {
        $headers = [];
        $headers[] = 'From: ' . EMAIL_FROM;
        $headers[] = 'MIME-Version: 1.0';
        $headers[] = 'Content-Type: text/plain; charset=UTF-8';
        $headersStr = implode("\r\n", $headers);
        @mail($userEmail, EMAIL_SUBJECT, $message, $headersStr);
        logMessage("Email notification queued to {$userEmail} for Device ID {$deviceId} status: {$status}.");
        monitorLog("Notification queued: type=email, user_id={$userId}, email={$userEmail}, device_id={$deviceId}, status={$status}");
    }

    // Telegram
    if (in_array($preference, ['telegram', 'both'], true) && !empty($userToken) && !empty($userChatId)) {
        $telegramMessage = $message; // let cURL handle encoding via POSTFIELDS
        $url = "https://api.telegram.org/bot{$userToken}/sendMessage";
        $curl = curl_init();
        $payload = [
            'chat_id' => $userChatId,
            'text' => $telegramMessage,
        ];
        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($payload),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/x-www-form-urlencoded',
            ],
        ]);
        $response = curl_exec($curl);
        $curlErrNo = curl_errno($curl);
        $curlErr = curl_error($curl);
        $httpCode = (int)curl_getinfo($curl, CURLINFO_HTTP_CODE);
        // curl_close() deprecated since PHP 8.5 - cURL handle closes automatically
        // curl_close($curl);

        if ($response === false) {
            logMessage("Telegram cURL error ({$curlErrNo}) for chat_id {$userChatId} (Device ID {$deviceId}): {$curlErr}");
            monitorLog("Notification failed: type=telegram, user_id={$userId}, chat_id={$userChatId}, device_id={$deviceId}, status={$status}, http={$httpCode}, curl_errno={$curlErrNo}");
        } else {
            $json = json_decode($response, true);
            $ok = is_array($json) && isset($json['ok']) ? (bool)$json['ok'] : false;
            if ($ok && $httpCode >= 200 && $httpCode < 300) {
                logMessage("Telegram notification sent to chat_id {$userChatId} for Device ID {$deviceId} status: {$status}. HTTP {$httpCode}");
                monitorLog("Notification sent: type=telegram, user_id={$userId}, chat_id={$userChatId}, device_id={$deviceId}, status={$status}, http={$httpCode}");
            } else {
                $errorCode = $json['error_code'] ?? null;
                $description = $json['description'] ?? 'Unknown error';
                $retryAfter = $json['parameters']['retry_after'] ?? null;
                $extra = "";
                if ($retryAfter !== null) {
                    $extra = ", retry_after={$retryAfter}";
                }
                logMessage("Telegram failed (HTTP {$httpCode}, api_error={$errorCode}): {$description}{$extra} for chat_id {$userChatId} (Device ID {$deviceId}). Raw: {$response}");
                monitorLog("Notification failed: type=telegram, user_id={$userId}, chat_id={$userChatId}, device_id={$deviceId}, status={$status}, http={$httpCode}, api_error={$errorCode}, description=" . str_replace(["\r","\n"], ' ', (string)$description) . $extra);
            }
        }
    }
}

/**
 * Updates the status and last_ping of devices based on their last ping timestamp.
 */
function updateDeviceStatus() {
    $start = microtime(true);
    $callerIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $minutesConfigured = defined('OFFLINE_THRESHOLD_MINUTES') ? (int)OFFLINE_THRESHOLD_MINUTES : 15;
    $stillOnlineMinutes = defined('STILL_ONLINE_MINUTES') ? (int)STILL_ONLINE_MINUTES : $minutesConfigured;
    monitorLog("Monitor run started from {$callerIp} with threshold {$minutesConfigured} min; still_online={$stillOnlineMinutes} min");
    $db = getDbConnection();
    try {
        // Define the offline threshold using config value
        $minutes = $minutesConfigured;
        if ($minutes < 1) { $minutes = 1; }
        if ($minutes > 1440) { $minutes = 1440; }
        $thresholdTime = date('Y-m-d H:i:s', strtotime('-' . $minutes . ' minutes'));

        // Fetch devices and their owners
        $stmtDevices = $db->prepare("
            SELECT d.*, u.id AS user_id, u.email, u.token, u.chat_id, u.notification_preference
            FROM devices d
            LEFT JOIN users u ON d.user_id = u.id
        ");
        $stmtDevices->execute();
        $devices = $stmtDevices->fetchAll(PDO::FETCH_ASSOC);
        $totalDevices = is_array($devices) ? count($devices) : 0;
        monitorLog("Fetched {$totalDevices} devices. Threshold time: {$thresholdTime}");

        $changes = 0;
        // Prepare marker files in logs dir for still-online notifications
        $logsDir = dirname(MONITOR_LOG_FILE);
        if (!is_dir($logsDir)) {
            @mkdir($logsDir, 0777, true);
        }
        $getMarkerPath = function($deviceId) use ($logsDir) {
            return $logsDir . DIRECTORY_SEPARATOR . "online_marker_{$deviceId}.flag";
        };
        $getNotifiedPath = function($deviceId) use ($logsDir) {
            return $logsDir . DIRECTORY_SEPARATOR . "online_notified_{$deviceId}.flag";
        };
        foreach ($devices as $device) {
            $previousStatus = $device['status'];
            $newStatus = (strtotime($device['timestamp']) >= strtotime($thresholdTime)) ? 'online' : 'offline';
            $currentStatus = $previousStatus;

            // Update status and last_ping only if it has changed
            if ($previousStatus !== $newStatus) {
                $stmtUpdate = $db->prepare("UPDATE devices SET status = :status, last_ping = CURRENT_TIMESTAMP WHERE id = :id");
                $stmtUpdate->bindParam(':status', $newStatus);
                $stmtUpdate->bindParam(':id', $device['id']);
                $stmtUpdate->execute();

                $changes++;
                $when = $device['timestamp'] ?? 'n/a';
                monitorLog("Device #{$device['id']} ({$device['name']}) changed {$previousStatus} -> {$newStatus}; last ping at {$when}");

                // Send notification to the user
                if (!empty($device['user_id'])) {
                    sendNotification($device, $newStatus);
                }

                // Manage marker lifecycle on transitions
                $markerPath = $getMarkerPath($device['id']);
                $notifiedPath = $getNotifiedPath($device['id']);
                if ($newStatus === 'online') {
                    @file_put_contents($markerPath, (string)time());
                    if (file_exists($notifiedPath)) { @unlink($notifiedPath); }
                } else {
                    if (file_exists($markerPath)) { @unlink($markerPath); }
                    if (file_exists($notifiedPath)) { @unlink($notifiedPath); }
                }

                $currentStatus = $newStatus;
            }

            // Still-online notification: if remained online for threshold minutes
            if ($currentStatus === 'online') {
                $markerPath = $getMarkerPath($device['id']);
                $notifiedPath = $getNotifiedPath($device['id']);
                // If device is online but no marker exists (e.g., monitor started while already online), create it based on last change time
                if (!file_exists($markerPath)) {
                    $baseTs = null;
                    if (!empty($device['last_ping'])) {
                        $baseTs = strtotime($device['last_ping']);
                    } elseif (!empty($device['timestamp'])) {
                        $baseTs = strtotime($device['timestamp']);
                    } else {
                        $baseTs = time();
                    }
                    if ($baseTs === false || $baseTs === 0) { $baseTs = time(); }
                    @file_put_contents($markerPath, (string)$baseTs);
                    monitorLog("Marker created for already-online device_id={$device['id']} at ts={$baseTs}");
                }
                if (file_exists($markerPath) && !file_exists($notifiedPath)) {
                    $createdAt = (int)@file_get_contents($markerPath);
                    $ageSec = time() - $createdAt;
                    if ($ageSec >= ($stillOnlineMinutes * 60)) {
                        // Additional guard: ensure no recent change contradicts
                        $lastChangeTs = isset($device['last_ping']) ? strtotime($device['last_ping']) : null;
                        if ($lastChangeTs === null || $lastChangeTs <= strtotime('-' . $stillOnlineMinutes . ' minutes')) {
                            monitorLog("Still-online notification: user_id={$device['user_id']}, device_id={$device['id']}, minutes={$stillOnlineMinutes}");
                            if (!empty($device['user_id'])) {
                                sendNotification($device, 'online');
                            }
                            @file_put_contents($notifiedPath, (string)time()); // mark notified; resend only after status change
                        }
                    }
                }
            }
        }

        $durationMs = (int)round((microtime(true) - $start) * 1000);
        monitorLog("Monitor run completed: changes={$changes}, devices_scanned={$totalDevices}, duration_ms={$durationMs}");

        echo json_encode(["status" => "success", "message" => "Device statuses and last_ping updated. Notifications sent.", "changes" => $changes, "devices" => $totalDevices, "duration_ms" => $durationMs]);
    } catch (PDOException $e) {
        monitorLog("Database error during device status update: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(["status" => "error", "message" => "An error occurred while updating device statuses."]);
    }
}

updateDeviceStatus();
?>
