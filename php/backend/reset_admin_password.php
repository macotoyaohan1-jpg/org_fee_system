<?php

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Use the password recovery form.');
}

require_once __DIR__ . '/otp_service.php';
auth_start_session();

function password_reset_finish_with_error(string $message): void
{
    $_SESSION['password_reset_error'] = $message;
    auth_redirect('../forgot_password.php');
}

if (!auth_csrf_is_valid()) {
    password_reset_finish_with_error('The form expired. Refresh the page and try again.');
}

$action = $_POST['action'] ?? '';
$userId = $_SESSION['pending_password_reset_user_id'] ?? null;
$otpId = $_SESSION['pending_password_reset_otp_id'] ?? null;
$username = $_SESSION['pending_password_reset_username'] ?? null;

if ($action === 'verify_otp') {
    $code = $_POST['reset_code'] ?? null;

    if (($_SESSION['password_reset_security_question_verified'] ?? false) !== true) {
        password_reset_finish_with_error(
            'Verify your registered security question before entering a recovery code.'
        );
    }

    if (($_SESSION['password_reset_otp_stage'] ?? false) !== true) {
        password_reset_finish_with_error('Start a new recovery request first.');
    }

    if (!is_string($code) || preg_match('/\A[0-9]{6}\z/', $code) !== 1) {
        password_reset_finish_with_error('Enter the six-digit code from your email.');
    }

    if (!is_string($userId) || $userId === '' || !is_string($otpId) || !ctype_digit($otpId)) {
        try {
            auth_log_event(
                $pdo,
                'OTP_FAILED',
                is_string($username) ? $username : null,
                null,
                'A password recovery code could not be verified.'
            );
        } catch (PDOException $error) {
            error_log('Unable to log password recovery code failure: ' . $error->getMessage());
        }
        password_reset_finish_with_error('The recovery code could not be verified. Start a new recovery request.');
    }

    try {
        $pdo->beginTransaction();

        $userQuery = $pdo->prepare(
            "SELECT email FROM users
             WHERE id_number = :user_id
               AND role IN ('ADMIN', 'TREASURER')
               AND account_status = 'ACTIVE'
               AND email_verified_at IS NOT NULL
             FOR UPDATE"
        );
        $userQuery->execute(['user_id' => $userId]);
        $email = $userQuery->fetchColumn();

        $otpQuery = $pdo->prepare(
            'SELECT otp_hash, attempts, expires_at > NOW() AS is_valid
             FROM user_otps
             WHERE otp_id = :otp_id
               AND user_id = :user_id
               AND purpose = :purpose
               AND used_at IS NULL
             FOR UPDATE'
        );
        $otpQuery->execute([
            'otp_id' => $otpId,
            'user_id' => $userId,
            'purpose' => 'PASSWORD_RESET'
        ]);
        $otp = $otpQuery->fetch(PDO::FETCH_ASSOC);

        if (
            !is_string($email)
            || !$otp
            || (int) $otp['is_valid'] !== 1
            || (int) $otp['attempts'] >= 3
        ) {
            if ($otp) {
                $expire = $pdo->prepare(
                    'UPDATE user_otps SET used_at = NOW() WHERE otp_id = :otp_id'
                );
                $expire->execute(['otp_id' => $otpId]);
            }
            auth_log_event(
                $pdo,
                'OTP_FAILED',
                is_string($username) ? $username : null,
                $userId,
                'A password recovery code was expired or unavailable.'
            );
            $pdo->commit();
            password_reset_finish_with_error('That recovery code expired. Request a new code.');
        }

        if (!password_verify($code, $otp['otp_hash'])) {
            $attempts = (int) $otp['attempts'] + 1;
            $updateOtp = $pdo->prepare(
                'UPDATE user_otps
                 SET attempts = :attempts,
                     used_at = CASE WHEN :exhausted = 1 THEN NOW() ELSE used_at END
                 WHERE otp_id = :otp_id'
            );
            $updateOtp->execute([
                'attempts' => $attempts,
                'exhausted' => $attempts >= 3 ? 1 : 0,
                'otp_id' => $otpId
            ]);
            auth_log_event(
                $pdo,
                'OTP_FAILED',
                is_string($username) ? $username : null,
                $userId,
                'An incorrect password recovery code was submitted.'
            );
            $pdo->commit();
            password_reset_finish_with_error(
                $attempts >= 3
                    ? 'Too many incorrect codes. Request a new recovery code.'
                    : 'That code is incorrect. Check your email and try again.'
            );
        }

        $markUsed = $pdo->prepare(
            'UPDATE user_otps SET used_at = NOW() WHERE otp_id = :otp_id'
        );
        $markUsed->execute(['otp_id' => $otpId]);
        auth_log_event(
            $pdo,
            'PASSWORD_RESET_OTP_VERIFIED',
            is_string($username) ? $username : null,
            $userId,
            'The password recovery email code was verified.'
        );
        $pdo->commit();

        session_regenerate_id(true);
        $_SESSION['password_reset_verified'] = true;
        $_SESSION['password_reset_verified_at'] = time();
        $_SESSION['password_reset_notice'] = 'Recovery code verified. Choose a new password.';
        unset($_SESSION['password_reset_error']);
        auth_redirect('../forgot_password.php');
    } catch (PDOException $error) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('Password recovery code verification failed: ' . $error->getMessage());
        password_reset_finish_with_error('Password recovery is temporarily unavailable. Please try again.');
    }
}

if ($action !== 'change_password') {
    password_reset_finish_with_error('The password recovery request is invalid. Please try again.');
}

$verifiedAt = $_SESSION['password_reset_verified_at'] ?? null;
if (
    ($_SESSION['password_reset_security_question_verified'] ?? false) !== true
    || ($_SESSION['password_reset_verified'] ?? false) !== true
    || !is_int($verifiedAt)
    || time() - $verifiedAt > AUTH_OTP_EXPIRY_MINUTES * 60
    || !is_string($userId)
    || $userId === ''
) {
    password_reset_finish_with_error('Verify a new recovery code before changing your password.');
}

$password = $_POST['new_password'] ?? null;
$confirmation = $_POST['confirm_password'] ?? null;
if (!is_string($password) || !is_string($confirmation) || $password !== $confirmation) {
    password_reset_finish_with_error('The new passwords do not match.');
}

if (strlen($password) < AUTH_PASSWORD_MIN_LENGTH || strlen($password) > 64) {
    password_reset_finish_with_error(
        'Password must be between ' . AUTH_PASSWORD_MIN_LENGTH . ' and 64 characters.'
    );
}

$strengthScore = 0;
$strengthScore += preg_match('/[a-z]/', $password) === 1
    && preg_match('/[A-Z]/', $password) === 1 ? 1 : 0;
$strengthScore += preg_match('/[0-9]/', $password) === 1 ? 1 : 0;
$strengthScore += preg_match('/[^A-Za-z0-9]/', $password) === 1 ? 1 : 0;
$strengthScore += strlen($password) >= 12 ? 1 : 0;

if ($strengthScore < 3) {
    password_reset_finish_with_error('Choose a password with at least three strength criteria.');
}

try {
    $pdo->beginTransaction();

    $userQuery = $pdo->prepare(
        "SELECT email FROM users
         WHERE id_number = :user_id
           AND role IN ('ADMIN', 'TREASURER')
           AND account_status = 'ACTIVE'
           AND email_verified_at IS NOT NULL
         FOR UPDATE"
    );
    $userQuery->execute(['user_id' => $userId]);
    $email = $userQuery->fetchColumn();

    if (!is_string($email) || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        throw new RuntimeException('The account is unavailable.');
    }

    $historyQuery = $pdo->prepare(
        'SELECT password_hash FROM password_history WHERE user_id = :user_id'
    );
    $historyQuery->execute(['user_id' => $userId]);
    foreach ($historyQuery->fetchAll(PDO::FETCH_COLUMN) as $oldHash) {
        if (password_verify($password, $oldHash)) {
            throw new RuntimeException('Choose a password you have not used before.');
        }
    }

    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    if (!is_string($passwordHash)) {
        throw new RuntimeException('Could not secure the new password.');
    }

    $updateUser = $pdo->prepare(
        'UPDATE users SET password_hash = :password_hash WHERE id_number = :user_id'
    );
    $updateUser->execute([
        'password_hash' => $passwordHash,
        'user_id' => $userId
    ]);

    $insertHistory = $pdo->prepare(
        'INSERT INTO password_history (user_id, password_hash)
         VALUES (:user_id, :password_hash)'
    );
    $insertHistory->execute([
        'user_id' => $userId,
        'password_hash' => $passwordHash
    ]);

    $invalidate = $pdo->prepare(
        'UPDATE user_otps SET used_at = NOW()
         WHERE user_id = :user_id AND purpose = :purpose AND used_at IS NULL'
    );
    $invalidate->execute([
        'user_id' => $userId,
        'purpose' => 'PASSWORD_RESET'
    ]);

    auth_log_event(
        $pdo,
        'PASSWORD_CHANGED',
        is_string($username) ? $username : null,
        $userId,
        'The account password was changed after security-answer and email-code verification.'
    );
    $pdo->commit();
} catch (PDOException $error) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('Account password reset failed: ' . $error->getMessage());
    password_reset_finish_with_error('Password reset could not be completed. Request a new recovery code and try again.');
} catch (RuntimeException $error) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    password_reset_finish_with_error($error->getMessage());
}

try {
    auth_send_password_changed_email(
        $email,
        (string) ($_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN'),
        (string) ($_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN')
    );
    $alertEmailSent = true;
} catch (RuntimeException $error) {
    error_log('Password change alert email failed: ' . $error->getMessage());
    $alertEmailSent = false;
    try {
        auth_log_event(
            $pdo,
            'ALERT_EMAIL_FAILED',
            is_string($username) ? $username : null,
            $userId,
            'Password change alert email delivery failed.'
        );
    } catch (PDOException $logError) {
        error_log('Unable to log failed password change alert: ' . $logError->getMessage());
    }
}

if ($alertEmailSent) {
    try {
        auth_log_event(
            $pdo,
            'ALERT_EMAIL_SENT',
            is_string($username) ? $username : null,
            $userId,
            'Password change alert email sent.'
        );
    } catch (PDOException $error) {
        error_log('Unable to log sent password change alert: ' . $error->getMessage());
    }
    $_SESSION['password_reset_success'] = 'Password updated. Sign in with your new password.';
} else {
    $_SESSION['password_reset_success'] =
        'Password updated, but the security alert email could not be sent.';
}

unset(
    $_SESSION['pending_password_reset_user_id'],
    $_SESSION['pending_password_reset_otp_id'],
    $_SESSION['pending_password_reset_email'],
    $_SESSION['pending_password_reset_username'],
    $_SESSION['pending_password_reset_question_ids'],
    $_SESSION['password_reset_otp_stage'],
    $_SESSION['password_reset_verified'],
    $_SESSION['password_reset_verified_at'],
    $_SESSION['password_reset_security_question_verified'],
    $_SESSION['password_reset_answer_attempts']
);
session_regenerate_id(true);
auth_redirect('../login.php?reset=1');
