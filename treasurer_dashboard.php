<?php
require_once __DIR__ . '/backend/auth_guard.php';
$user = auth_require_treasurer($pdo, 'APPROVED');
$name = trim($user['first_name'] . ' ' . $user['family_name']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Treasurer Dashboard | Student Organization Fee System</title>
    <link rel="stylesheet" href="frontend/css/auth.css?v=20261112-2">
</head>
<body>
<main class="auth-container">
    <section class="form-panel">
        <div class="form-container">
            <h1>Treasurer Dashboard</h1>
            <p>Welcome, <?= htmlspecialchars($name, ENT_QUOTES, 'UTF-8') ?>.</p>
            <p>Treasurer features will be added in a later phase.</p>
        </div>
    </section>
</main>
</body>
</html>
