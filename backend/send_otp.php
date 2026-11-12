<?php

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Use POST to request another verification code.');
}

require_once __DIR__ . '/otp_service.php';

auth_start_session();
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

if (!auth_csrf_is_valid()) {
    $_SESSION['otp_error'] = 'Your verification page expired. Sign in again.';
    auth_clear_pending_otp();
    auth_redirect('../login.php');
}

$userId = $_SESSION['pending_login_user_id'] ?? null;
$otpId = $_SESSION['pending_login_otp_id'] ?? null;

if (!is_string($userId) || !is_string($otpId)) {
    auth_clear_pending_otp();
    auth_redirect('../login.php');
}

try {
    $currentOtp = $pdo->prepare(
        'SELECT otp_id
         FROM user_otps
         WHERE otp_id = :otp_id
           AND user_id = :user_id
           AND purpose = :purpose
           AND used_at IS NULL
           AND expires_at > NOW()
           AND attempts < 3'
    );
    $currentOtp->execute([
        'otp_id' => $otpId,
        'user_id' => $userId,
        'purpose' => 'LOGIN'
    ]);

    if (!$currentOtp->fetchColumn()) {
        auth_clear_pending_otp();
        $_SESSION['login_error'] = 'Your verification code expired. Sign in again to request a new code.';
        auth_redirect('../login.php');
    }

    $userQuery = $pdo->prepare(
        'SELECT email FROM users WHERE id_number = :user_id LIMIT 1'
    );
    $userQuery->execute(['user_id' => $userId]);
    $email = $userQuery->fetchColumn();

    if (!is_string($email) || $email === '') {
        auth_clear_pending_otp();
        auth_redirect('../login.php');
    }

    $issuedOtp = auth_issue_login_otp($pdo, $userId, $email, true);
    $_SESSION['pending_login_otp_id'] = $issuedOtp['otp_id'];
    $_SESSION['otp_resends_remaining'] = $issuedOtp['resends_remaining'];
    $_SESSION['otp_notice'] = 'A new verification code was sent to your registered email address.';
    unset($_SESSION['otp_error'], $_SESSION['otp_resend_seconds']);
} catch (AuthOtpThrottleException $error) {
    $_SESSION['otp_error'] = $error->getMessage();
    $_SESSION['otp_resend_seconds'] = $error->retryAfter;
    $_SESSION['otp_resends_remaining'] = $error->resendsRemaining;
} catch (RuntimeException $error) {
    error_log('Unable to resend login OTP: ' . $error->getMessage());
    $_SESSION['otp_error'] = 'The verification code could not be sent. Please try again.';
} catch (PDOException $error) {
    error_log('Login OTP resend database operation failed: ' . $error->getMessage());
    $_SESSION['otp_error'] = 'The verification code could not be sent. Please try again.';
}

auth_redirect('../otp_verification.php');
