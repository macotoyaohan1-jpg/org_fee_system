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
    respond(422, [
        'valid' => false,
        'message' => 'The CAPTCHA answer was incorrect. A new challenge has been loaded.'
    ]);
}

unset($_SESSION['login_captcha']);
$_SESSION['login_captcha_verified_at'] = time();

respond(200, ['valid' => true]);
