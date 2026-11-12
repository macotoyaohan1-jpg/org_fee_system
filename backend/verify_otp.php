<?php

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Use POST to verify the code.');
}

require_once __DIR__ . '/auth_common.php';

auth_start_session();
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

if (!auth_csrf_is_valid()) {
    $_SESSION['otp_error'] = 'Your verification page expired. Sign in again.';
    auth_clear_pending_otp();
    auth_redirect('../login.php');
}

$userId = $_SESSION['pending_login_user_id'] ?? null;
$otpId = $_SESSION['pending_login_otp_id'] ?? null;
$submittedCode = $_POST['otp_code'] ?? null;

if (!is_string($userId) || !is_string($otpId)) {
    auth_clear_pending_otp();
    auth_redirect('../login.php');
}

try {
    $pdo->beginTransaction();
    $statement = $pdo->prepare(
        'SELECT otp_hash, attempts, expires_at > NOW() AS is_valid_time
         FROM user_otps
         WHERE otp_id = :otp_id
           AND user_id = :user_id
           AND purpose = :purpose
           AND used_at IS NULL
         FOR UPDATE'
    );
    $statement->execute([
        'otp_id' => $otpId,
        'user_id' => $userId,
        'purpose' => 'LOGIN'
    ]);
    $challenge = $statement->fetch(PDO::FETCH_ASSOC);

    if (!$challenge || (int) $challenge['is_valid_time'] !== 1 || (int) $challenge['attempts'] >= 3) {
        if ($challenge) {
            $expire = $pdo->prepare(
                'UPDATE user_otps SET used_at = NOW() WHERE otp_id = :otp_id'
            );
            $expire->execute(['otp_id' => $otpId]);
        }
        $pdo->commit();
        auth_clear_pending_otp();
        $_SESSION['login_error'] = 'Your verification code expired. Sign in again to request a new code.';
        auth_redirect('../login.php');
    }

    $codeValid = is_string($submittedCode)
        && preg_match('/\A[0-9]{6}\z/', $submittedCode) === 1
        && password_verify($submittedCode, $challenge['otp_hash']);

    if (!$codeValid) {
        $newAttempts = (int) $challenge['attempts'] + 1;
        $update = $pdo->prepare(
            'UPDATE user_otps
             SET attempts = :attempts,
                 used_at = CASE WHEN :exhausted = 1 THEN NOW() ELSE used_at END
             WHERE otp_id = :otp_id'
        );
        $update->execute([
            'attempts' => $newAttempts,
            'exhausted' => $newAttempts >= 3 ? 1 : 0,
            'otp_id' => $otpId
        ]);
        $pdo->commit();

        if ($newAttempts >= 3) {
            auth_clear_pending_otp();
            $_SESSION['login_error'] = 'Too many incorrect verification codes. Sign in again to request a new code.';
            auth_redirect('../login.php');
        }

        $_SESSION['otp_error'] = 'The verification code is incorrect.';
        auth_redirect('../otp_verification.php');
    }

    $markUsed = $pdo->prepare(
        'UPDATE user_otps SET used_at = NOW() WHERE otp_id = :otp_id'
    );
    $markUsed->execute(['otp_id' => $otpId]);

    $userQuery = $pdo->prepare(
        'SELECT id_number, username, role, approval_status, account_status
         FROM users
         WHERE id_number = :user_id
         LIMIT 1'
    );
    $userQuery->execute(['user_id' => $userId]);
    $user = $userQuery->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $pdo->commit();
        auth_clear_pending_otp();
        $_SESSION['login_error'] = 'Your account could not be found. Sign in again.';
        auth_redirect('../login.php');
    }

    if (
        $user['account_status'] === 'ACTIVE' &&
        (
            $user['role'] === 'ADMIN' ||
            (
                $user['role'] === 'TREASURER' &&
                in_array($user['approval_status'], ['APPROVED', 'PENDING', 'REJECTED'], true)
            )
        )
    ) {
        $loggedIdentifier = (string) ($_SESSION['pending_login_identifier'] ?? $user['username']);
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '';
        if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
            $ipAddress = '0.0.0.0';
        }
        auth_record_login_attempt($pdo, $user['id_number'], $loggedIdentifier, $ipAddress, true);
    }

    $pdo->commit();
} catch (PDOException $error) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('OTP verification database operation failed: ' . $error->getMessage());
    $_SESSION['otp_error'] = 'Verification is temporarily unavailable. Please try again.';
    auth_redirect('../otp_verification.php');
}

auth_clear_pending_otp();
session_regenerate_id(true);

if ($user['account_status'] !== 'ACTIVE') {
    unset($_SESSION['user_id'], $_SESSION['user_role'], $_SESSION['approval_status']);
    $_SESSION['access_denied_message'] = 'This account is suspended. Contact an administrator for assistance.';
    auth_redirect('../access_denied.php');
}

if ($user['role'] === 'ADMIN') {
    unset($_SESSION['login_failed_attempts']);
    $_SESSION['user_id'] = $user['id_number'];
    $_SESSION['user_role'] = $user['role'];
    $_SESSION['approval_status'] = $user['approval_status'];
    auth_redirect('../admin_dashboard.php');
}

if (
    $user['role'] === 'TREASURER' &&
    in_array($user['approval_status'], ['APPROVED', 'PENDING', 'REJECTED'], true)
) {
    unset($_SESSION['login_failed_attempts']);
    $_SESSION['user_id'] = $user['id_number'];
    $_SESSION['user_role'] = $user['role'];
    $_SESSION['approval_status'] = $user['approval_status'];

    if ($user['approval_status'] === 'APPROVED') {
        auth_redirect('../treasurer_dashboard.php');
    }
    if ($user['approval_status'] === 'PENDING') {
        auth_redirect('../awaiting_approval.php');
    }
    if ($user['approval_status'] === 'REJECTED') {
        auth_redirect('../application_status.php');
    }
}

unset($_SESSION['user_id'], $_SESSION['user_role'], $_SESSION['approval_status']);
$_SESSION['access_denied_message'] = 'This account is not eligible to sign in.';
auth_redirect('../access_denied.php');
