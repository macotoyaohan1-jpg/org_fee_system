<?php
require_once __DIR__ . '/backend/auth_guard.php';
$user = auth_require_treasurer($pdo, 'PENDING');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Awaiting Approval | Student Organization Fee System</title>
    <link rel="stylesheet" href="frontend/css/auth.css?v=20261112-2">
</head>
<body>
<main class="auth-container">
    <section class="form-panel">
        <div class="form-container">
            <h1>Awaiting Approval</h1>
            <p>Your Treasurer account is pending approval. Dashboard access will be available after approval.</p>
        </div>
    </section>
</main>
</body>
</html>
