
<?php

require_once __DIR__ . '/backend/auth_common.php';

// Start the user's session.
auth_start_session();

// Get the logged-in user's ID.
$userId = $_SESSION['user_id'] ?? null;

// Record the logout activity.
if (is_string($userId) && $userId !== '') {

    // Find the user's username or email.
    $statement = $pdo->prepare(
        'SELECT username, email
         FROM users
         WHERE id_number = :user_id
         LIMIT 1'
    );

    $statement->execute([
        'user_id' => $userId
    ]);

    $user = $statement->fetch(PDO::FETCH_ASSOC);

    $username = $user
        ? ($user['username'] ?: $user['email'])
        : 'UNKNOWN';

    // Save the logout event.
    auth_log_event(
        $pdo,
        'LOGOUT',
        $username,
        $userId,
        'User logged out successfully.'
    );
}

// Remove all session data.
$_SESSION = [];

// Remove the session cookie.
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();

    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params['path'],
        $params['domain'],
        $params['secure'],
        $params['httponly']
    );
}

// Destroy the session.
session_destroy();

// Return to the login page.
header('Location: login.php');
exit;
