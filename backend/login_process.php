<?php

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Use POST to sign in.');
}

require_once __DIR__ . '/auth_common.php';
require_once __DIR__ . '/otp_service.php';

auth_start_session();

function return_to_login(
    string $message,
    ?int $failures = null,
    int $lockoutSeconds = 0,
    ?string $identifier = null
): void
{
    auth_flash_login($message, $failures, $lockoutSeconds, $identifier);
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
    auth_log_event(
        $pdo,
        'CAPTCHA_FAILED',
        null,
        null,
        'The login CAPTCHA verification expired or was missing.'
    );
    return_to_login('Your CAPTCHA verification expired. Refresh the challenge and try again.');
}

$identifierInput = $_POST['username'] ?? null;
$password = $_POST['password'] ?? null;
$typedIdentifier = is_string($identifierInput) ? substr($identifierInput, 0, 100) : '';
$identifier = trim($typedIdentifier);
$normalizedIdentifier = function_exists('mb_strtolower')
    ? mb_strtolower($identifier, 'UTF-8')
    : strtolower($identifier);
$loggedIdentifier = $typedIdentifier;
$normalizedIdentifier = substr($normalizedIdentifier, 0, 100);
$passwordValid = is_string($password) && $password !== '' && strlen($password) <= 1024;
$identifierValid = $identifier !== ''
    && strlen($identifier) <= 100
    && preg_match('/[\x00-\x1F\x7F]/', $identifier) !== 1;

if ($identifierValid && strpos($identifier, '@') !== false) {
    $identifierValid = filter_var($identifier, FILTER_VALIDATE_EMAIL) !== false;
} elseif ($identifierValid) {
    $identifierValid = preg_match(
        '/\A[A-Za-z][A-Za-z0-9]{7,18}\z/',
        $identifier
    ) === 1;
}

$ipAddress = $_SERVER['REMOTE_ADDR'] ?? '';
if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
    http_response_code(400);
    exit('Unable to verify the client address.');
}

try {
    $ipLockSeconds = auth_ip_block_seconds($pdo, $ipAddress);
    if ($ipLockSeconds > 0) {
        auth_log_event(
            $pdo,
            'LOGIN_IP_BLOCKED',
            $loggedIdentifier,
            null,
            'Login attempted from a temporarily blocked IP address.'
        );
        $user = $identifierValid ? auth_find_user($pdo, $identifier) : null;
        $userId = $user['id_number'] ?? null;
        $history = auth_failure_history($pdo, $userId, $normalizedIdentifier);
        $state = auth_lockout_state($history);
        return_to_login(
            'This network is temporarily blocked. Try again when the countdown ends.',
            $state['failures'],
            $ipLockSeconds,
            $loggedIdentifier
        );
    }

    $user = $identifierValid ? auth_find_user($pdo, $identifier) : null;
    $userId = $user['id_number'] ?? null;
    $history = auth_failure_history($pdo, $userId, $normalizedIdentifier);
    $state = auth_lockout_state($history);

    if ($state['seconds'] > 0) {
        auth_log_event(
            $pdo,
            'LOGIN_BLOCKED',
            $loggedIdentifier,
            $userId,
            'Login attempted while the account was temporarily locked.'
        );
        return_to_login(
            'Too many failed sign-in attempts. Try again when the countdown ends.',
            $state['failures'],
            $state['seconds'],
            $loggedIdentifier
        );
    }

    $credentialsValid = $identifierValid
        && $passwordValid
        && $user !== null
        && password_verify($password, $user['password_hash']);

    if (!$credentialsValid) {
        auth_record_login_attempt($pdo, $userId, $loggedIdentifier, $ipAddress, false);
        auth_log_event(
            $pdo,
            'LOGIN_FAILED',
            $loggedIdentifier,
            $userId,
            'Incorrect username or password.'
        );
        $state = auth_lockout_state(
            auth_failure_history($pdo, $userId, $normalizedIdentifier)
        );

        if (in_array($state['failures'], [3, 6, 9], true)) {
            $tier = (int) ($state['failures'] / 3);
            auth_log_event(
                $pdo,
                'LOCKOUT_TIER_' . $tier,
                $loggedIdentifier,
                $userId,
                'The account reached lockout tier ' . $tier . '.'
            );

            if ($user !== null) {
                try {
                    auth_send_lockout_alert_email(
                        $user['email'],
                        $state['failures'],
                        $ipAddress,
                        (string) ($_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN'),
                        $tier
                    );
                    auth_log_event(
                        $pdo,
                        'ALERT_EMAIL_SENT',
                        $loggedIdentifier,
                        $userId,
                        'A lockout tier ' . $tier . ' alert was emailed.'
                    );
                } catch (RuntimeException $error) {
                    error_log('Unable to send lockout alert: ' . $error->getMessage());
                    auth_log_event(
                        $pdo,
                        'ALERT_EMAIL_FAILED',
                        $loggedIdentifier,
                        $userId,
                        'Lockout alert delivery failed.'
                    );
                }
            }
        }

        $ipBlockSeconds = 0;
        if (auth_ip_failure_count($pdo, $ipAddress) >= AUTH_IP_BLOCK_THRESHOLD) {
            auth_block_ip($pdo, $ipAddress);
            $ipBlockSeconds = auth_ip_block_seconds($pdo, $ipAddress);
            auth_log_event(
                $pdo,
                'IP_BLOCKED',
                $loggedIdentifier,
                $userId,
                'The IP address reached the 16-failure threshold across accounts.'
            );
        }

        $message = $state['seconds'] > 0
            ? 'Too many failed sign-in attempts. Try again when the countdown ends.'
            : 'Invalid username or password.';

        if ($ipBlockSeconds > 0) {
            $message = 'This network is temporarily blocked. Try again when the countdown ends.';
        }

        return_to_login(
            $message,
            $state['failures'],
            max($state['seconds'], $ipBlockSeconds),
            $loggedIdentifier
        );
    }

    // Prevent users with unverified email addresses from signing in.
    if (empty($user['email_verified_at'])) {
        return_to_login(
            'Invalid username or password.',
            $state['failures']
        );
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
            'Sign-in is temporarily unavailable. Please try again later.',
            $state['failures']
        );
    }

    $_SESSION['pending_login_user_id'] = $userId;
    $_SESSION['pending_login_otp_id'] = $issuedOtp['otp_id'];
    $_SESSION['pending_login_started_at'] = time();
    $_SESSION['pending_login_identifier'] = $loggedIdentifier;
    $_SESSION['otp_notice'] = 'A verification code was sent to your registered email address.';
    $_SESSION['otp_resends_remaining'] = $issuedOtp['resends_remaining'];

    auth_log_event(
        $pdo,
        'LOGIN_OTP_SENT',
        $loggedIdentifier,
        $userId,
        'Password verified. Email OTP verification is pending.'
    );
    auth_log_event(
        $pdo,
        'OTP_SENT',
        $loggedIdentifier,
        $userId,
        'Login verification OTP sent.'
    );

    auth_redirect('../otp_verification.php');
} catch (PDOException $error) {
    error_log('Login processing database operation failed: ' . $error->getMessage());
    return_to_login('Sign-in is temporarily unavailable. Please try again later.');
}
