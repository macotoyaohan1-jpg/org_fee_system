<?php
session_start();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

function respond(int $status, array $result): void
{
    http_response_code($status);
    echo json_encode($result);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    respond(405, [
        'valid' => false,
        'message' => 'Use POST to verify the CAPTCHA.'
    ]);
}

$csrfToken = $_POST['csrf_token'] ?? null;
$sessionToken = $_SESSION['csrf_token'] ?? null;

if (
    !is_string($csrfToken) ||
    !is_string($sessionToken) ||
    !hash_equals($sessionToken, $csrfToken)
) {
    respond(403, [
        'valid' => false,
        'message' => 'Your form expired. Refresh the page and try again.'
    ]);
}

respond(501, [
    'valid' => false,
    'message' => 'CAPTCHA answer verification is not available yet.'
]);
