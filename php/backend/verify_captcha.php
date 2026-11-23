<?php

require_once __DIR__ . '/auth_common.php';
auth_start_session();

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

if (!auth_csrf_is_valid()) {
    respond(403, [
        'valid' => false,
        'message' => 'Your form expired. Refresh the page and try again.'
    ]);
}

$answer = $_POST['captcha_answer'] ?? null;
$expectedAnswer = $_SESSION['login_captcha'] ?? null;

if (!is_string($expectedAnswer) || $expectedAnswer === '') {
    respond(409, [
        'valid' => false,
        'message' => 'The CAPTCHA expired. Refresh the challenge and try again.'
    ]);
}

if (!is_string($answer) || !hash_equals($expectedAnswer, strtoupper(trim($answer)))) {
    unset($_SESSION['login_captcha'], $_SESSION['login_captcha_verified_at']);
    auth_log_event(
        $pdo,
        'CAPTCHA_FAILED',
        is_string($_POST['username'] ?? null) ? substr($_POST['username'], 0, 100) : null,
        null,
        'The login CAPTCHA did not match.'
    );
    respond(422, [
        'valid' => false,
        'message' => 'The CAPTCHA answer was incorrect. A new challenge has been loaded.'
    ]);
}

unset($_SESSION['login_captcha']);
$_SESSION['login_captcha_verified_at'] = time();

respond(200, ['valid' => true]);
