<?php
// logout.php - Logout Script

// Start session
session_start();

// Destroy all session data
$_SESSION = array();

// Delete session cookie
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Destroy the session
session_destroy();

// Clear any existing output buffer
if (ob_get_length()) {
    ob_end_clean();
}

// Redirect to login page with logout message
header('Location: login.php?logout=success');
exit();
?>