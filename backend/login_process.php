<?php

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Use POST to sign in.');
}

require_once __DIR__ . '/auth_common.php';
require_once __DIR__ . '/otp_service.php';

auth_start_session();

function return_to_login(string $message, ?int $failures = null, int $lockoutSeconds = 0): void
{
    auth_flash_login($message, $failures, $lockoutSeconds);
    auth_redirect('../login.php');
}

if (!auth_csrf_is_valid()) {
    return_to_login('Your login form expired. Refresh the page and try again.');
}

$captchaVerifiedAt = $_SESSION['login_captcha_verified_at'] ?? null;
unset($_SESSION['login_captcha_verified_at']);

if (
    !is_int($captchaVerifiedAt) ||
    $captchaVerifiedAt > time() ||
    time() - $captchaVerifiedAt > 180
) {
    return_to_login('Your CAPTCHA verification expired. Refresh the challenge and try again.');
}

$identifierInput = $_POST['username'] ?? null;
$password = $_POST['password'] ?? null;
$identifier = is_string($identifierInput) ? trim($identifierInput) : '';
$normalizedIdentifier = function_exists('mb_strtolower')
    ? mb_strtolower($identifier, 'UTF-8')
    : strtolower($identifier);
$loggedIdentifier = substr($normalizedIdentifier, 0, 100);
$normalizedIdentifier = $loggedIdentifier;
$passwordValid = is_string($password) && $password !== '' && strlen($password) <= 1024;
$identifierValid = $identifier !== ''
    && strlen($identifier) <= 100
    && preg_match('/[\x00-\x1F\x7F]/', $identifier) !== 1;

if ($identifierValid && strpos($identifier, '@') !== false) {
    $identifierValid = filter_var($identifier, FILTER_VALIDATE_EMAIL) !== false;
} elseif ($identifierValid) {
    $identifierValid = strlen($identifier) <= 19;
}

$ipAddress = $_SERVER['REMOTE_ADDR'] ?? '';
if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
    http_response_code(400);
    exit('Unable to verify the client address.');
}

try {
    $ipLockSeconds = auth_ip_block_seconds($pdo, $ipAddress);
    if ($ipLockSeconds > 0) {
        auth_record_login_attempt($pdo, null, $loggedIdentifier, $ipAddress, false);
        $history = auth_failure_history($pdo, null, $loggedIdentifier);
        $state = auth_lockout_state($history);
        return_to_login(
            'This network is temporarily blocked. Try again when the countdown ends.',
            $state['failures'],
            $ipLockSeconds
        );
    }

    $user = $identifierValid ? auth_find_user($pdo, $identifier) : null;
    $userId = $user['id_number'] ?? null;
    $history = auth_failure_history($pdo, $userId, $loggedIdentifier);
    $state = auth_lockout_state($history);

    if ($state['seconds'] > 0) {
        return_to_login(
            'Too many failed sign-in attempts. Try again when the countdown ends.',
            $state['failures'],
            $state['seconds']
        );
    }

    $credentialsValid = $identifierValid
        && $passwordValid
        && $user !== null
        && password_verify($password, $user['password_hash']);

    if (!$credentialsValid) {
        auth_record_login_attempt($pdo, $userId, $loggedIdentifier, $ipAddress, false);
        $state = auth_lockout_state(
            auth_failure_history($pdo, $userId, $loggedIdentifier)
        );
        $message = $state['seconds'] > 0
            ? 'Too many failed sign-in attempts. Try again when the countdown ends.'
            : 'The username or password is incorrect.';

        return_to_login($message, $state['failures'], $state['seconds']);
    }

    auth_clear_pending_otp();
    unset($_SESSION['user_id'], $_SESSION['user_role'], $_SESSION['approval_status']);
    session_regenerate_id(true);

    try {
        $issuedOtp = auth_issue_login_otp($pdo, $userId, $user['email'], false);
    } catch (AuthOtpThrottleException $error) {
        return_to_login($error->getMessage(), $state['failures']);
    } catch (RuntimeException $error) {
        error_log('Unable to start login OTP challenge: ' . $error->getMessage());
        return_to_login(
            'Unable to send a verification code. Check the email configuration and try again.',
            $state['failures']
        );
    }

    $_SESSION['pending_login_user_id'] = $userId;
    $_SESSION['pending_login_otp_id'] = $issuedOtp['otp_id'];
    $_SESSION['pending_login_started_at'] = time();
    $_SESSION['pending_login_identifier'] = $loggedIdentifier;
    $_SESSION['otp_notice'] = 'A verification code was sent to your registered email address.';
    $_SESSION['otp_resends_remaining'] = $issuedOtp['resends_remaining'];

    auth_redirect('../otp_verification.php');
} catch (PDOException $error) {
    error_log('Login processing database operation failed: ' . $error->getMessage());
    return_to_login('Sign-in is temporarily unavailable. Please try again later.');
}
