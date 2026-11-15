
<?php

// Allow POST requests only.
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Use the verification form to continue.');
}

require_once __DIR__ . '/auth_common.php';

auth_start_session();

// Check the registration verification session.
$userId = $_SESSION['pending_registration_user_id'] ?? null;
$otpId = $_SESSION['pending_registration_otp_id'] ?? null;

if (
    !is_string($userId) ||
    !is_string($otpId) ||
    !ctype_digit($otpId) ||
    (int) $otpId < 1
) {
    $_SESSION['registration_otp_error'] =
        'Your verification session has expired or no verification code has been issued. Request a new code.';

    auth_redirect('../registration_otp_verification.php');
}

// Validate CSRF token.
if (!auth_csrf_is_valid()) {
    $_SESSION['registration_otp_error'] =
        'Your form expired. Refresh the page and try again.';

    auth_redirect('../registration_otp_verification.php');
}

// Validate six-digit OTP input.
$submittedOtp = $_POST['otp'] ?? '';

if (
    !is_string($submittedOtp) ||
    preg_match('/^[0-9]{6}$/', $submittedOtp) !== 1
) {
    $_SESSION['registration_otp_error'] =
        'Enter a valid six-digit verification code.';

    auth_redirect('../registration_otp_verification.php');
}

try {
    $pdo->beginTransaction();

    // Find and lock the correct registration OTP.
    $otpStatement = $pdo->prepare(
        "SELECT otp_id, otp_hash, expires_at, attempts
         FROM user_otps
         WHERE otp_id = :otp_id
           AND user_id = :user_id
           AND purpose = 'REGISTRATION'
           AND used_at IS NULL
         LIMIT 1
         FOR UPDATE"
    );

    $otpStatement->execute([
        'otp_id' => $otpId,
        'user_id' => $userId
    ]);

    $otpRecord = $otpStatement->fetch(PDO::FETCH_ASSOC);

    // Check whether the OTP exists and is still usable.
    if (!$otpRecord) {
        $pdo->rollBack();

        $_SESSION['registration_otp_error'] =
            'This verification code is no longer valid. Request a new code.';

        auth_redirect('../registration_otp_verification.php');
    }

    $attempts = (int) $otpRecord['attempts'];

    // Allow only three incorrect attempts.
    if ($attempts >= 3) {
        $expireOtp = $pdo->prepare(
            'UPDATE user_otps
             SET used_at = NOW()
             WHERE otp_id = :otp_id
               AND user_id = :user_id'
        );

        $expireOtp->execute([
            'otp_id' => $otpId,
            'user_id' => $userId
        ]);

        $pdo->commit();

        $_SESSION['registration_otp_error'] =
            'You have used all three attempts. Request a new verification code.';

        auth_redirect('../registration_otp_verification.php');
    }

    // Check OTP expiration.
    $expiryTime = new DateTimeImmutable($otpRecord['expires_at']);

    if ($expiryTime <= new DateTimeImmutable()) {
        $expireOtp = $pdo->prepare(
            'UPDATE user_otps
             SET used_at = NOW()
             WHERE otp_id = :otp_id
               AND user_id = :user_id'
        );

        $expireOtp->execute([
            'otp_id' => $otpId,
            'user_id' => $userId
        ]);

        $pdo->commit();

        $_SESSION['registration_otp_error'] =
            'Your verification code has expired. Request a new verification code.';

        auth_redirect('../registration_otp_verification.php');
    }

    // Compare the submitted OTP with the stored password hash.
    if (!password_verify($submittedOtp, $otpRecord['otp_hash'])) {

        $newAttempts = $attempts + 1;

        // Update incorrect attempt count.
        $updateAttempts = $pdo->prepare(
            'UPDATE user_otps
             SET attempts = :attempts,
                 used_at = CASE
                     WHEN :attempts_check >= 3 THEN NOW()
                     ELSE used_at
                 END
             WHERE otp_id = :otp_id
               AND user_id = :user_id'
        );

        $updateAttempts->execute([
            'attempts' => $newAttempts,
            'attempts_check' => $newAttempts,
            'otp_id' => $otpId,
            'user_id' => $userId
        ]);

        // Record the failed verification attempt.
        try {
            $userStatement = $pdo->prepare(
                'SELECT username
                 FROM users
                 WHERE id_number = :user_id
                 LIMIT 1'
            );

            $userStatement->execute([
                'user_id' => $userId
            ]);

            $username = $userStatement->fetchColumn();

            auth_log_event(
                $pdo,
                'OTP_FAILED',
                is_string($username) ? $username : '',
                $userId,
                'Incorrect registration verification code. Attempt ' .
                    $newAttempts . ' of 3.'
            );

        } catch (Throwable $logError) {
            error_log(
                'Failed OTP activity logging error: ' .
                $logError->getMessage()
            );
        }

        $pdo->commit();

        if ($newAttempts >= 3) {
            $_SESSION['registration_otp_error'] =
                'You have used all three attempts. Request a new verification code.';
        } else {
            $_SESSION['registration_otp_error'] =
                'Incorrect verification code. ' .
                (3 - $newAttempts) . ' attempt(s) remaining.';
        }

        auth_redirect('../registration_otp_verification.php');
    }

    // Get the registered user's information.
    $userStatement = $pdo->prepare(
        'SELECT username, email_verified_at
         FROM users
         WHERE id_number = :user_id
         LIMIT 1
         FOR UPDATE'
    );

    $userStatement->execute([
        'user_id' => $userId
    ]);

    $user = $userStatement->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        throw new RuntimeException(
            'The registered account could not be found.'
        );
    }

    // Mark the email address as verified.
    if ($user['email_verified_at'] === null) {
        $verifyEmail = $pdo->prepare(
            'UPDATE users
             SET email_verified_at = NOW()
             WHERE id_number = :user_id
               AND email_verified_at IS NULL'
        );

        $verifyEmail->execute([
            'user_id' => $userId
        ]);
    }

    // Mark the OTP as used to prevent reuse.
    $useOtp = $pdo->prepare(
        'UPDATE user_otps
         SET used_at = NOW()
         WHERE otp_id = :otp_id
           AND user_id = :user_id
           AND purpose = \'REGISTRATION\'
           AND used_at IS NULL'
    );

    $useOtp->execute([
        'otp_id' => $otpId,
        'user_id' => $userId
    ]);

    // Record successful email verification.
    try {
        auth_log_event(
            $pdo,
            'OTP_VERIFIED',
            $user['username'],
            $userId,
            'Registration email successfully verified.'
        );

    } catch (Throwable $logError) {
        error_log(
            'Successful OTP activity logging failed: ' .
            $logError->getMessage()
        );
    }

    // Save all verification changes.
    $pdo->commit();

    // Clear registration verification session data.
    unset(
        $_SESSION['pending_registration_user_id'],
        $_SESSION['pending_registration_otp_id'],
        $_SESSION['pending_registration_email'],
        $_SESSION['registration_otp_resends_remaining'],
        $_SESSION['registration_otp_error'],
        $_SESSION['registration_otp_success']
    );

    // User must still sign in normally.
    auth_redirect('../login.php?verified=1');

} catch (Throwable $error) {

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log(
        'Registration OTP verification failed: ' .
        $error->getMessage()
    );

    $_SESSION['registration_otp_error'] =
        'Verification is temporarily unavailable. Please try again.';

    auth_redirect('../registration_otp_verification.php');
}
