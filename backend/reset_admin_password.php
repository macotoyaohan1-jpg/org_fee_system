
<?php

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Use the password recovery form.');
}

require_once __DIR__ . '/auth_common.php';
auth_start_session();

function password_reset_fail(string $message): void
{
    $_SESSION['password_reset_error'] = $message;
    auth_redirect('../forgot_password.php');
}

if (!auth_csrf_is_valid()) {
    password_reset_fail('The form expired. Refresh the page and request a new code.');
}

$userId = $_SESSION['pending_password_reset_user_id'] ?? null;
$otpId = $_SESSION['pending_password_reset_otp_id'] ?? null;
$code = $_POST['reset_code'] ?? null;
$password = $_POST['new_password'] ?? null;
$confirmation = $_POST['confirm_password'] ?? null;

if (!is_string($userId) || !is_string($otpId) || !ctype_digit($otpId)) {
    password_reset_fail('Request a new recovery code first.');
}

if (!is_string($code) || preg_match('/\A[0-9]{6}\z/', $code) !== 1) {
    password_reset_fail('Enter the six-digit code from your email.');
}

if (!is_string($password) || !is_string($confirmation) || $password !== $confirmation) {
    password_reset_fail('The new passwords do not match.');
}

if (strlen($password) < 8 || strlen($password) > 64) {
    password_reset_fail('Password must be between 8 and 64 characters.');
}

$score = 0;
$score += strlen($password) >= 8 ? 1 : 0;
$score += preg_match('/[a-z]/', $password) === 1 && preg_match('/[A-Z]/', $password) === 1 ? 1 : 0;
$score += preg_match('/[0-9]/', $password) === 1 ? 1 : 0;
$score += preg_match('/[^A-Za-z0-9]/', $password) === 1 ? 1 : 0;
$score += strlen($password) >= 12 ? 1 : 0;

if ($score < 3) {
    password_reset_fail('Choose a password with at least three strength criteria.');
}

try {
    $pdo->beginTransaction();

    // Accept either an active Admin or Treasurer account.
    $userQuery = $pdo->prepare(
        "SELECT id_number FROM users
         WHERE id_number = :user_id
           AND role IN ('ADMIN', 'TREASURER')
           AND account_status = 'ACTIVE'
         FOR UPDATE"
    );

    $userQuery->execute(['user_id' => $userId]);

    if (!$userQuery->fetchColumn()) {
        throw new RuntimeException('The account is unavailable.');
    }

    $otpQuery = $pdo->prepare(
        'SELECT otp_hash, attempts, expires_at > NOW() AS is_valid
         FROM user_otps
         WHERE otp_id = :otp_id AND user_id = :user_id
           AND purpose = :purpose AND used_at IS NULL
         FOR UPDATE'
    );

    $otpQuery->execute([
        'otp_id' => $otpId,
        'user_id' => $userId,
        'purpose' => 'PASSWORD_RESET'
    ]);

    $otp = $otpQuery->fetch(PDO::FETCH_ASSOC);

    if (!$otp || (int)$otp['is_valid'] !== 1 || (int)$otp['attempts'] >= 3) {
        if ($otp) {
            $expire = $pdo->prepare(
                'UPDATE user_otps SET used_at = NOW() WHERE otp_id = :otp_id'
            );
            $expire->execute(['otp_id' => $otpId]);
        }

        $pdo->commit();
        password_reset_fail('That recovery code expired. Request a new code.');
    }

    if (!password_verify($code, $otp['otp_hash'])) {
        $attempts = (int)$otp['attempts'] + 1;

        $updateOtp = $pdo->prepare(
            'UPDATE user_otps SET attempts = :attempts,
             used_at = CASE WHEN :exhausted = 1 THEN NOW() ELSE used_at END
             WHERE otp_id = :otp_id'
        );

        $updateOtp->execute([
            'attempts' => $attempts,
            'exhausted' => $attempts >= 3 ? 1 : 0,
            'otp_id' => $otpId
        ]);

        $pdo->commit();

        password_reset_fail($attempts >= 3
            ? 'Too many incorrect codes. Request a new recovery code.'
            : 'That code is incorrect. Check your email and try again.');
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
        'ACCOUNT_PASSWORD_RESET',
        null,
        $userId,
        'Account password reset completed using email verification.'
    );

    $pdo->commit();

    unset(
        $_SESSION['pending_password_reset_user_id'],
        $_SESSION['pending_password_reset_otp_id'],
        $_SESSION['pending_password_reset_email']
    );

    $_SESSION['password_reset_success'] = 'Password updated. Sign in with your new password.';
    auth_redirect('../login.php?reset=1');

} catch (Throwable $error) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log('Account password reset failed: ' . $error->getMessage());

    password_reset_fail($error instanceof RuntimeException
        ? $error->getMessage()
        : 'Password reset could not be completed. Request a new recovery code and try again.');
}
