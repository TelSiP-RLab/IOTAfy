<?php
// auth.php

require_once 'config.inc';

/**
 * Handles authorization requests.
 */
function handleAuthRequest() {
    try {
        $db = getDbConnection();
    } catch (Exception $e) {
        logMessage("Database connection error: " . $e->getMessage());
        echo json_encode(['status' => 'error', 'message' => 'Failed to connect to the database.']);
        return;
    }

    // Get the input data
    $input = json_decode(file_get_contents('php://input'), true);

    if (isset($input['auth_key'])) {
        $auth_key = $input['auth_key'];
        // Prepare masked and hashed fingerprint (do not log raw key)
        $maskedKey = (is_string($auth_key) && strlen($auth_key) > 8)
            ? (substr($auth_key, 0, 4) . str_repeat('*', max(0, strlen($auth_key) - 8)) . substr($auth_key, -4))
            : '***';
        $keyFingerprint = substr(hash('sha256', (string)$auth_key), 0, 12);

        // Log without exposing the raw key
        logMessage("Received auth request (masked_key={$maskedKey}, fp={$keyFingerprint})");

        try {
            // Prepare and execute the SQL statement
            $stmt = $db->prepare('SELECT * FROM users WHERE authkey = :auth_key');
            $stmt->bindParam(':auth_key', $auth_key, PDO::PARAM_STR);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            // Check if the user is found
            if ($user) {
                // User is authorized
                logMessage("Authorization approved (fp={$keyFingerprint})");
                echo json_encode(['status' => 'approved']);
            } else {
                // User is not authorized
                logMessage("Authorization denied (fp={$keyFingerprint})");
                echo json_encode(['status' => 'denied', 'message' => 'Invalid auth_key provided.']);
            }
        } catch (PDOException $e) {
            // Log any errors during query execution
            logMessage("Query error: " . $e->getMessage());
            echo json_encode(['status' => 'error', 'message' => 'Query execution failed: ' . $e->getMessage()]);
        }
    } else {
        // Missing auth_key in the request
        logMessage("Authorization request failed: Missing auth_key");
        echo json_encode(['status' => 'error', 'message' => 'Missing auth_key in the request.']);
    }
}

// Handle the authorization request
handleAuthRequest();
?>

