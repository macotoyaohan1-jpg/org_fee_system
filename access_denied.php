<?php
require_once __DIR__ . '/backend/auth_common.php';
auth_start_session();

$message = $_SESSION['access_denied_message'] ?? 'You do not have permission to access this page.';
unset($_SESSION['access_denied_message']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied | Student Organization Fee System</title>
    <link rel="stylesheet" href="frontend/css/auth.css?v=20261112-2">
</head>
<body>
<main class="auth-container">
    <section class="form-panel">
        <div class="form-container">
            <h1>Access Denied</h1>
            <p class="error-message" role="alert"><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></p>
            <p><a href="login.php">Return to login</a></p>
        </div>
    </section>
</main>
</body>
</html>
