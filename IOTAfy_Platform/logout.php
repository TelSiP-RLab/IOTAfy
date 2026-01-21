<?php
// logout.php

require 'config.inc'; // Include the configuration file
//session_start();

if (isset($_SESSION['username'])) {
    $username = $_SESSION['username'];

    // Unset all session variables
    session_unset();

    // Destroy the session
    session_destroy();

    // Log the logout
    logMessage("User $username logged out successfully.");
}

// Redirect to login page
header('Location: login.php');
exit;
?>

