<?php
require_once __DIR__ . '/backend/auth_guard.php';
$user = auth_require_treasurer($pdo, 'REJECTED');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Application Status | Student Organization Fee System</title>
    <link rel="stylesheet" href="frontend/css/auth.css?v=20261112-2">
</head>
<body>
<main class="auth-container">
    <section class="form-panel">
        <div class="form-container">
            <h1>Application Status</h1>
            <p>Your Treasurer application was not approved. Contact the organization administrator for more information.</p>
        </div>
    </section>
</main>
</body>
</html>
