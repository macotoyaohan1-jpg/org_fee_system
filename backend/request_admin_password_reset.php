
<?php

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Use the password recovery form.');
}

require_once __DIR__ . '/otp_service.php';
auth_start_session();

if (!auth_csrf_is_valid()) {
    $_SESSION['password_reset_error'] = 'The form expired. Refresh the page and try again.';
    auth_redirect('../forgot_password.php');
}

// Check whether this is a resend request.
$isResend = ($_POST['resend'] ?? '') === '1';

if ($isResend) {

    // Resending requires an existing recovery session.
    $pendingUserId = $_SESSION['pending_password_reset_user_id'] ?? '';
    $pendingOtpId = $_SESSION['pending_password_reset_otp_id'] ?? '';
    $pendingEmail = $_SESSION['pending_password_reset_email'] ?? '';

    if (
        !is_string($pendingUserId) ||
        trim($pendingUserId) === '' ||
        !is_string($pendingOtpId) ||
        !ctype_digit($pendingOtpId) ||
        !is_string($pendingEmail) ||
        !filter_var($pendingEmail, FILTER_VALIDATE_EMAIL)
    ) {
        $_SESSION['password_reset_error'] = 'Please start a new password recovery request.';
        auth_redirect('../forgot_password.php');
    }

    // Use the email saved in the session.
    $email = strtolower(trim($pendingEmail));

} else {

    // CAPTCHA is required for the initial recovery request.
    $captchaAnswer = $_POST['captcha_answer'] ?? '';
    $captchaExpected = $_SESSION['password_reset_captcha'] ?? '';

    unset($_SESSION['password_reset_captcha']);

    if (
        !is_string($captchaAnswer) ||
        !is_string($captchaExpected) ||
        $captchaExpected === '' ||
        !hash_equals($captchaExpected, strtoupper(trim($captchaAnswer)))
    ) {
        $_SESSION['password_reset_error'] = 'The CAPTCHA code did not match. Please try again.';
        auth_redirect('../forgot_password.php');
    }

    // Validate the email address.
    $emailInput = $_POST['email'] ?? '';
    $email = is_string($emailInput) ? strtolower(trim($emailInput)) : '';

    // Remember the email address for the next page load.
    if (
        filter_var($email, FILTER_VALIDATE_EMAIL) &&
        strlen($email) <= 100
    ) {
        $_SESSION['password_reset_email_input'] = $email;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 100) {
        $_SESSION['password_reset_error'] = 'Enter a valid registered email address.';
        auth_redirect('../forgot_password.php');
    }
}

$genericNotice = 'If this matches an active Admin or Treasurer account, a recovery code will be sent to that address.';

try {

    // Find an active, verified Admin or Treasurer account.
    $lookup = $pdo->prepare(
        "SELECT id_number, email, role FROM users
         WHERE email = :email
           AND role IN ('ADMIN', 'TREASURER')
           AND account_status = 'ACTIVE'
           AND email_verified_at IS NOT NULL
         LIMIT 1"
    );

    $lookup->execute(['email' => $email]);
    $account = $lookup->fetch(PDO::FETCH_ASSOC);

    if (!$account) {
        $_SESSION['password_reset_notice'] = $genericNotice;

        $_SESSION['pending_password_reset_user_id'] = '';
        $_SESSION['pending_password_reset_otp_id'] = '';
        $_SESSION['pending_password_reset_email'] = $email;

        auth_redirect('../forgot_password.php');
    }

    // For resend requests, confirm that the account matches the saved session.
    if (
        $isResend &&
        (string)$account['id_number'] !== (string)$pendingUserId
    ) {
        throw new RuntimeException('The recovery session is no longer valid. Start again.');
    }

    $pdo->beginTransaction();

    // Lock the account while creating its recovery code.
    $lock = $pdo->prepare(
        'SELECT id_number FROM users WHERE id_number = :user_id FOR UPDATE'
    );

    $lock->execute(['user_id' => $account['id_number']]);

    if (!$lock->fetchColumn()) {
        throw new RuntimeException('Account not found.');
    }

    // Check when the previous recovery code was requested.
    $latestQuery = $pdo->prepare(
        'SELECT TIMESTAMPDIFF(SECOND, created_at, NOW())
         FROM user_otps
         WHERE user_id = :user_id AND purpose = :purpose
         ORDER BY otp_id DESC LIMIT 1'
    );

    $latestQuery->execute([
        'user_id' => $account['id_number'],
        'purpose' => 'PASSWORD_RESET'
    ]);

    $latestAge = $latestQuery->fetchColumn();

    // Limit recovery code requests within 15 minutes.
    $countQuery = $pdo->prepare(
        'SELECT COUNT(*) FROM user_otps
         WHERE user_id = :user_id
           AND purpose = :purpose
           AND created_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)'
    );

    $countQuery->execute([
        'user_id' => $account['id_number'],
        'purpose' => 'PASSWORD_RESET'
    ]);

    $recentCount = (int)$countQuery->fetchColumn();

    if ($latestAge !== false && (int)$latestAge < 60) {
        throw new RuntimeException('Wait one minute before requesting another recovery code.');
    }

    if ($recentCount >= 4) {
        throw new RuntimeException('Too many recovery codes were requested. Try again in 15 minutes.');
    }

    // Generate a six-digit recovery code.
    $code = str_pad(
        (string) random_int(0, 999999),
        6,
        '0',
        STR_PAD_LEFT
    );

    $hash = password_hash($code, PASSWORD_DEFAULT);

    if (!is_string($hash)) {
        throw new RuntimeException('Could not create the recovery code.');
    }

    // Save the hashed recovery code.
    $insert = $pdo->prepare(
        'INSERT INTO user_otps
         (user_id, otp_hash, purpose, expires_at, attempts, resend_count)
         VALUES
         (:user_id, :otp_hash, :purpose, DATE_ADD(NOW(), INTERVAL 5 MINUTE), 0, :resend_count)'
    );

    $insert->execute([
        'user_id' => $account['id_number'],
        'otp_hash' => $hash,
        'purpose' => 'PASSWORD_RESET',
        'resend_count' => $recentCount
    ]);

    $otpId = (string)$pdo->lastInsertId();

    // Send the recovery code to the registered email.
    auth_send_password_reset_otp_email($account['email'], $code);

    // Invalidate previous unused recovery codes.
    $invalidate = $pdo->prepare(
        'UPDATE user_otps
         SET used_at = NOW()
         WHERE user_id = :user_id
           AND purpose = :purpose
           AND used_at IS NULL
           AND otp_id <> :otp_id'
    );

    $invalidate->execute([
        'user_id' => $account['id_number'],
        'purpose' => 'PASSWORD_RESET',
        'otp_id' => $otpId
    ]);

    $pdo->commit();

    // Store the pending recovery information in the session.
    $_SESSION['pending_password_reset_user_id'] = (string)$account['id_number'];
    $_SESSION['pending_password_reset_otp_id'] = $otpId;
    $_SESSION['pending_password_reset_email'] = $account['email'];

    // Keep the email available if the user starts another request later.
    $_SESSION['password_reset_email_input'] = $account['email'];

    $_SESSION['password_reset_notice'] = 'A recovery code was sent. It expires in five minutes.';

    unset($_SESSION['password_reset_error']);

} catch (Throwable $error) {

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log('Password reset code request failed: ' . $error->getMessage());

    $_SESSION['password_reset_error'] = $error instanceof RuntimeException
        ? $error->getMessage()
        : 'Could not send a recovery code. Check the mail configuration and try again.';
}

auth_redirect('../forgot_password.php');
