<?php

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Use the verification page to request another code.');
}

require_once __DIR__ . '/auth_common.php';
require_once __DIR__ . '/otp_service.php';

auth_start_session();
// Preserve the modal state when redirecting back after a resend attempt.
$embeddedAuth = ($_GET['embed'] ?? '') === '1';
$verificationPage = '../registration_otp_verification.php' . ($embeddedAuth ? '?embed=1' : '');

// Check the pending registration session.
$userId = $_SESSION['pending_registration_user_id'] ?? null;
$email = $_SESSION['pending_registration_email'] ?? null;


if (
    !is_string($userId) ||
    !is_string($email)
) {
    $_SESSION['registration_otp_error'] =
        'Your registration verification session has expired.';

    auth_redirect('../login.php' . ($embeddedAuth ? '?embed=1' : ''));
}

// Validate CSRF token.
if (!auth_csrf_is_valid()) {
    $_SESSION['registration_otp_error'] =
        'Your form expired. Refresh the page and try again.';

    auth_redirect($verificationPage);
}

try {
    // Request another registration OTP.
    $result = auth_issue_registration_otp(
        $pdo,
        $userId,
        $email,
        true
    );

    // Update the pending OTP details.
    $_SESSION['pending_registration_otp_id'] =
        (string) $result['otp_id'];

    $_SESSION['registration_otp_resends_remaining'] =
        (int) $result['resends_remaining'];

    $_SESSION['registration_otp_success'] =
        'A new verification code has been sent to your email address.';

    // Record the resend activity.
    try {
        auth_log_event(
            $pdo,
            'OTP_SENT',
            $email,
            $userId,
            'Registration verification OTP resent.'
        );
    } catch (Throwable $logError) {
        error_log(
            'Registration OTP activity logging failed: ' .
            $logError->getMessage()
        );
    }

    auth_redirect($verificationPage);

} catch (Throwable $error) {

    error_log(
        'Registration OTP resend failed: ' . $error->getMessage()
    );

    // Do not expose internal errors to the user.
    $_SESSION['registration_otp_error'] =
        'Unable to send another verification code right now. Please wait 60 seconds if you recently requested one, then try again.';

    auth_redirect($verificationPage);
}
