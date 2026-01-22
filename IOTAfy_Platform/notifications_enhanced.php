<?php
/**
 * Enhanced Notification System
 * 
 * This file contains improved notification functions with:
 * - Rate limiting & cooldown
 * - Retry mechanism
 * - Enhanced message formatting
 * - Better error handling
 */

// config.inc is already included by monitor_devices.php, but include it here for standalone use
if (!defined('DB_PATH')) {
    require_once 'config.inc';
}

/**
 * Checks if notification should be sent based on cooldown period
 * 
 * @param int $deviceId Device ID
 * @param string $status Status ('online' or 'offline')
 * @param int $cooldownMinutes Cooldown period in minutes (default: 5)
 * @return bool True if notification should be sent
 */
function shouldSendNotification($deviceId, $status, $cooldownMinutes = null) {
    // Use config value if not provided
    if ($cooldownMinutes === null) {
        $cooldownMinutes = defined('NOTIFICATION_COOLDOWN_MINUTES') 
            ? (int)NOTIFICATION_COOLDOWN_MINUTES 
            : 5;
    }
    
    $logsDir = dirname(MONITOR_LOG_FILE);
    if (!is_dir($logsDir)) {
        @mkdir($logsDir, 0777, true);
    }
    
    $cooldownFile = $logsDir . DIRECTORY_SEPARATOR . "notification_cooldown_{$deviceId}_{$status}.flag";
    
    if (file_exists($cooldownFile)) {
        $lastSent = (int)@file_get_contents($cooldownFile);
        $elapsedMinutes = (time() - $lastSent) / 60;
        
        if ($elapsedMinutes < $cooldownMinutes) {
            monitorLog("Notification skipped (cooldown): device_id={$deviceId}, status={$status}, elapsed={$elapsedMinutes}min, required={$cooldownMinutes}min");
            return false;
        }
    }
    
    // Update cooldown timestamp
    @file_put_contents($cooldownFile, (string)time());
    return true;
}

/**
 * Builds an enhanced notification message with device details
 * 
 * @param array $deviceRow Device and user data
 * @param string $status Status ('online' or 'offline')
 * @return string Formatted message
 */
function buildNotificationMessage($deviceRow, $status) {
    $deviceName = $deviceRow['name'] ?? 'Unknown';
    $deviceId = $deviceRow['id'] ?? 'N/A';
    $ip = $deviceRow['ip'] ?? 'N/A';
    $mac = $deviceRow['mac'] ?? 'N/A';
    $firmware = $deviceRow['firmware_version'] ?? 'N/A';
    $timestamp = date('Y-m-d H:i:s');
    
    $statusEmoji = $status === 'online' ? '✅' : '❌';
    $statusText = strtoupper($status);
    
    $message = "🔔 Device Status Alert\n\n";
    $message .= "Device: {$deviceName}\n";
    $message .= "Status: {$statusText} {$statusEmoji}\n";
    $message .= "Time: {$timestamp}\n";
    $message .= "Device ID: {$deviceId}\n";
    $message .= "IP Address: {$ip}\n";
    $message .= "MAC Address: {$mac}\n";
    $message .= "Firmware: {$firmware}\n";
    
    if (!empty($deviceRow['timestamp'])) {
        $lastPing = date('Y-m-d H:i:s', strtotime($deviceRow['timestamp']));
        $minutesAgo = round((time() - strtotime($deviceRow['timestamp'])) / 60);
        $message .= "Last Ping: {$lastPing} ({$minutesAgo} minutes ago)\n";
    }
    
    return $message;
}

/**
 * Builds HTML email body
 * 
 * @param array $deviceRow Device and user data
 * @param string $status Status
 * @return string HTML email body
 */
function buildEmailHTML($deviceRow, $status) {
    $deviceName = htmlspecialchars($deviceRow['name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8');
    $deviceId = htmlspecialchars($deviceRow['id'] ?? 'N/A', ENT_QUOTES, 'UTF-8');
    $ip = htmlspecialchars($deviceRow['ip'] ?? 'N/A', ENT_QUOTES, 'UTF-8');
    $mac = htmlspecialchars($deviceRow['mac'] ?? 'N/A', ENT_QUOTES, 'UTF-8');
    $firmware = htmlspecialchars($deviceRow['firmware_version'] ?? 'N/A', ENT_QUOTES, 'UTF-8');
    $timestamp = date('Y-m-d H:i:s');
    
    $statusColor = $status === 'online' ? '#28a745' : '#dc3545';
    $statusText = strtoupper($status);
    
    $html = "
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset='UTF-8'>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #007bff; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
            .content { background-color: #f8f9fa; padding: 20px; border-radius: 0 0 5px 5px; }
            .status { display: inline-block; padding: 5px 15px; border-radius: 3px; color: white; font-weight: bold; }
            .status.online { background-color: #28a745; }
            .status.offline { background-color: #dc3545; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; }
            td { padding: 8px; border-bottom: 1px solid #ddd; }
            td:first-child { font-weight: bold; width: 40%; }
            .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h2>🔔 Device Status Alert</h2>
            </div>
            <div class='content'>
                <table>
                    <tr><td>Device Name:</td><td>{$deviceName}</td></tr>
                    <tr><td>Status:</td><td><span class='status {$status}'>{$statusText}</span></td></tr>
                    <tr><td>Time:</td><td>{$timestamp}</td></tr>
                    <tr><td>Device ID:</td><td>{$deviceId}</td></tr>
                    <tr><td>IP Address:</td><td>{$ip}</td></tr>
                    <tr><td>MAC Address:</td><td>{$mac}</td></tr>
                    <tr><td>Firmware Version:</td><td>{$firmware}</td></tr>
    ";
    
    if (!empty($deviceRow['timestamp'])) {
        $lastPing = date('Y-m-d H:i:s', strtotime($deviceRow['timestamp']));
        $minutesAgo = round((time() - strtotime($deviceRow['timestamp'])) / 60);
        $html .= "<tr><td>Last Ping:</td><td>{$lastPing} ({$minutesAgo} minutes ago)</td></tr>";
    }
    
    $html .= "
                </table>
            </div>
            <div class='footer'>
                <p>IOTAfy Platform - Device Monitoring System</p>
                <p>This is an automated notification. Please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
    ";
    
    return $html;
}

/**
 * Builds Telegram message with Markdown formatting
 * 
 * @param array $deviceRow Device and user data
 * @param string $status Status
 * @return string Telegram message with Markdown
 */
function buildTelegramMessage($deviceRow, $status) {
    $deviceName = $deviceRow['name'] ?? 'Unknown';
    $deviceId = $deviceRow['id'] ?? 'N/A';
    $ip = $deviceRow['ip'] ?? 'N/A';
    $mac = $deviceRow['mac'] ?? 'N/A';
    $firmware = $deviceRow['firmware_version'] ?? 'N/A';
    $timestamp = date('Y-m-d H:i:s');
    
    $statusEmoji = $status === 'online' ? '✅' : '❌';
    $statusText = strtoupper($status);
    
    $message = "🔔 *Device Status Alert*\n\n";
    $message .= "*Device:* {$deviceName}\n";
    $message .= "*Status:* {$statusText} {$statusEmoji}\n";
    $message .= "*Time:* {$timestamp}\n";
    $message .= "*Device ID:* `{$deviceId}`\n";
    $message .= "*IP:* `{$ip}`\n";
    $message .= "*MAC:* `{$mac}`\n";
    $message .= "*Firmware:* `{$firmware}`\n";
    
    if (!empty($deviceRow['timestamp'])) {
        $lastPing = date('Y-m-d H:i:s', strtotime($deviceRow['timestamp']));
        $minutesAgo = round((time() - strtotime($deviceRow['timestamp'])) / 60);
        $message .= "*Last Ping:* `{$lastPing}` ({$minutesAgo} min ago)\n";
    }
    
    return $message;
}

/**
 * Sends email with retry mechanism
 * 
 * @param string $email Recipient email
 * @param string $subject Email subject
 * @param string $body Email body (HTML or plain text)
 * @param int $maxRetries Maximum retry attempts
 * @return array Result array with 'success' and 'error' keys
 */
function sendEmailWithRetry($email, $subject, $body, $maxRetries = null) {
    // Use config value if not provided
    if ($maxRetries === null) {
        $maxRetries = defined('NOTIFICATION_MAX_RETRIES') 
            ? (int)NOTIFICATION_MAX_RETRIES 
            : 3;
    }
    $attempt = 0;
    $lastError = null;
    
    while ($attempt < $maxRetries) {
        $attempt++;
        
        // Determine if body is HTML
        $isHTML = (strpos($body, '<html') !== false || strpos($body, '<!DOCTYPE') !== false);
        
        $headers = [];
        $headers[] = 'From: ' . EMAIL_FROM;
        $headers[] = 'MIME-Version: 1.0';
        
        if ($isHTML) {
            $headers[] = 'Content-Type: text/html; charset=UTF-8';
        } else {
            $headers[] = 'Content-Type: text/plain; charset=UTF-8';
        }
        
        $headersStr = implode("\r\n", $headers);
        
        $result = @mail($email, $subject, $body, $headersStr);
        
        if ($result) {
            monitorLog("Email sent successfully: attempt={$attempt}, email={$email}");
            return ['success' => true, 'attempt' => $attempt];
        }
        
        $error = error_get_last();
        $lastError = $error ? $error['message'] : 'Unknown error';
        monitorLog("Email attempt {$attempt} failed: {$lastError}");
        
        // Exponential backoff: wait before retry (except on last attempt)
        if ($attempt < $maxRetries) {
            $waitSeconds = pow(2, $attempt); // 2s, 4s, 8s
            sleep($waitSeconds);
        }
    }
    
    monitorLog("Email permanently failed after {$maxRetries} attempts: {$lastError}");
    return ['success' => false, 'error' => $lastError, 'attempts' => $maxRetries];
}

/**
 * Sends Telegram message with retry mechanism
 * 
 * @param array $deviceRow Device and user data
 * @param string $message Telegram message
 * @param int $maxRetries Maximum retry attempts
 * @return array Result array with 'success' and 'error' keys
 */
function sendTelegramWithRetry($deviceRow, $message, $maxRetries = null) {
    // Use config value if not provided
    if ($maxRetries === null) {
        $maxRetries = defined('NOTIFICATION_MAX_RETRIES') 
            ? (int)NOTIFICATION_MAX_RETRIES 
            : 3;
    }
    $userToken = $deviceRow['token'] ?? '';
    $userChatId = $deviceRow['chat_id'] ?? '';
    $deviceId = $deviceRow['id'] ?? 'N/A';
    
    if (empty($userToken) || empty($userChatId)) {
        return ['success' => false, 'error' => 'Missing token or chat_id'];
    }
    
    $attempt = 0;
    $lastError = null;
    
    while ($attempt < $maxRetries) {
        $attempt++;
        
        $url = "https://api.telegram.org/bot{$userToken}/sendMessage";
        $curl = curl_init();
        
        $payload = [
            'chat_id' => $userChatId,
            'text' => $message,
            'parse_mode' => 'Markdown', // Enable Markdown formatting
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
        
        if ($response === false) {
            $lastError = "cURL error ({$curlErrNo}): {$curlErr}";
            monitorLog("Telegram attempt {$attempt} failed: {$lastError}");
        } else {
            $json = json_decode($response, true);
            $ok = is_array($json) && isset($json['ok']) ? (bool)$json['ok'] : false;
            
            if ($ok && $httpCode >= 200 && $httpCode < 300) {
                monitorLog("Telegram sent successfully: attempt={$attempt}, chat_id={$userChatId}, device_id={$deviceId}");
                return ['success' => true, 'attempt' => $attempt, 'http_code' => $httpCode];
            } else {
                $errorCode = $json['error_code'] ?? null;
                $description = $json['description'] ?? 'Unknown error';
                $lastError = "API error (HTTP {$httpCode}, code={$errorCode}): {$description}";
                monitorLog("Telegram attempt {$attempt} failed: {$lastError}");
            }
        }
        
        // Exponential backoff: wait before retry (except on last attempt)
        if ($attempt < $maxRetries) {
            $waitSeconds = pow(2, $attempt); // 2s, 4s, 8s
            sleep($waitSeconds);
        }
    }
    
    monitorLog("Telegram permanently failed after {$maxRetries} attempts: {$lastError}");
    return ['success' => false, 'error' => $lastError, 'attempts' => $maxRetries];
}

/**
 * Enhanced sendNotification function with all improvements
 * 
 * @param array $deviceRow Device and user data
 * @param string $status Status ('online' or 'offline')
 * @return array Results array
 */
function sendNotificationEnhanced($deviceRow, $status) {
    $deviceName = $deviceRow['name'] ?? 'Unknown';
    $deviceId = $deviceRow['id'] ?? 'N/A';
    $userEmail = $deviceRow['email'] ?? '';
    $userToken = $deviceRow['token'] ?? '';
    $userChatId = $deviceRow['chat_id'] ?? '';
    $preference = $deviceRow['notification_preference'] ?? 'email';
    $userId = $deviceRow['user_id'] ?? 'N/A';
    
    // Rate limiting check
    if (!shouldSendNotification($deviceId, $status)) {
        return [
            'success' => false,
            'reason' => 'cooldown',
            'skipped' => true
        ];
    }
    
    // Build messages
    $plainMessage = buildNotificationMessage($deviceRow, $status);
    $emailHTML = buildEmailHTML($deviceRow, $status);
    $telegramMessage = buildTelegramMessage($deviceRow, $status);
    
    $results = [
        'device_id' => $deviceId,
        'device_name' => $deviceName,
        'status' => $status,
        'user_id' => $userId,
        'email' => null,
        'telegram' => null,
    ];
    
    // Send Email
    if (in_array($preference, ['email', 'both'], true) && filter_var($userEmail, FILTER_VALIDATE_EMAIL)) {
        $emailResult = sendEmailWithRetry($userEmail, EMAIL_SUBJECT, $emailHTML);
        $results['email'] = $emailResult;
        
        if ($emailResult['success']) {
            logMessage("Email notification sent to {$userEmail} for Device ID {$deviceId} status: {$status}.");
            monitorLog("Notification sent: type=email, user_id={$userId}, email={$userEmail}, device_id={$deviceId}, status={$status}");
        } else {
            logMessage("Email notification FAILED to {$userEmail} for Device ID {$deviceId} after {$emailResult['attempts']} attempts: {$emailResult['error']}");
            monitorLog("Notification FAILED: type=email, user_id={$userId}, email={$userEmail}, device_id={$deviceId}, error={$emailResult['error']}");
        }
    }
    
    // Send Telegram
    if (in_array($preference, ['telegram', 'both'], true) && !empty($userToken) && !empty($userChatId)) {
        $telegramResult = sendTelegramWithRetry($deviceRow, $telegramMessage);
        $results['telegram'] = $telegramResult;
        
        if ($telegramResult['success']) {
            logMessage("Telegram notification sent to chat_id {$userChatId} for Device ID {$deviceId} status: {$status}.");
            monitorLog("Notification sent: type=telegram, user_id={$userId}, chat_id={$userChatId}, device_id={$deviceId}, status={$status}");
        } else {
            logMessage("Telegram notification FAILED for chat_id {$userChatId} (Device ID {$deviceId}) after {$telegramResult['attempts']} attempts: {$telegramResult['error']}");
            monitorLog("Notification FAILED: type=telegram, user_id={$userId}, chat_id={$userChatId}, device_id={$deviceId}, error={$telegramResult['error']}");
        }
    }
    
    // Determine overall success
    $results['success'] = (
        ($results['email'] === null || ($results['email'] && $results['email']['success'])) &&
        ($results['telegram'] === null || ($results['telegram'] && $results['telegram']['success']))
    );
    
    return $results;
}
