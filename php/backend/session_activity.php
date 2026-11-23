<?php

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed.']);
    exit;
}

require_once __DIR__ . '/auth_common.php';
auth_start_session();

$userId = $_SESSION['user_id'] ?? null;
if (!is_string($userId) || $userId === '') {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Sign in again to continue.']);
    exit;
}

if (!auth_csrf_is_valid()) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'The request could not be verified.']);
    exit;
}

$userQuery = $pdo->prepare(
    'SELECT account_status FROM users WHERE id_number = :user_id LIMIT 1'
);
$userQuery->execute(['user_id' => $userId]);

if ($userQuery->fetchColumn() !== 'ACTIVE') {
    unset($_SESSION['user_id'], $_SESSION['user_role'], $_SESSION['approval_status']);
    session_regenerate_id(true);
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Sign in again to continue.']);
    exit;
}

$_SESSION['last_activity_at'] = time();
echo json_encode(['success' => true]);
