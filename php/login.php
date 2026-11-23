<?php

require_once __DIR__ . '/backend/auth_common.php';
auth_start_session();

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// Create a CSRF token for the login form.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$csrf = $_SESSION['csrf_token'];

$loginError = $_SESSION['login_error'] ?? '';
$passwordResetSuccess = $_SESSION['password_reset_success'] ?? '';
$registrationPendingApprovalNotice =
    ($_SESSION['registration_pending_approval_notice'] ?? false) === true;

$lastLoginFailureAt = $_SESSION['login_forgot_last_attempt_at'] ?? null;
if (
    !is_int($lastLoginFailureAt) ||
    time() - $lastLoginFailureAt >= AUTH_IP_BLOCK_WINDOW_SECONDS
) {
    unset(
        $_SESSION['login_forgot_session_attempts'],
        $_SESSION['login_forgot_identifier'],
        $_SESSION['login_forgot_attempt_key'],
        $_SESSION['login_forgot_last_attempt_at'],
        $_SESSION['login_failed_attempts'],
        $_SESSION['login_lockout_seconds']
    );
}

$forgotPasswordAttempts = max(
    (int) ($_SESSION['login_forgot_session_attempts'] ?? 0),
    (int) ($_SESSION['login_failed_attempts'] ?? 0)
);
$failedIdentifier = $_SESSION['login_forgot_identifier'] ?? '';

if (!is_string($failedIdentifier)) {
    $failedIdentifier = '';
}

$showForgotPassword = $forgotPasswordAttempts >= AUTH_FORGOT_PASSWORD_FAILURES
    && is_string($failedIdentifier)
    && $failedIdentifier !== '';

$lockoutSeconds = max(0, (int) ($_SESSION['login_lockout_seconds'] ?? 0));

// Check whether the email was successfully verified.
$emailVerified = isset($_GET['verified']) && $_GET['verified'] === '1';

// Clear temporary flash messages after reading them.
unset(
    $_SESSION['login_error'],
    $_SESSION['login_lockout_seconds'],
    $_SESSION['password_reset_success'],
    $_SESSION['registration_pending_approval_notice']
);

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Login | Student Organization Fee System</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>

    <link
        href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap"
        rel="stylesheet"
    >

    <!-- Match the stylesheet version used by registration so both auth pages stay visually in sync. -->
    <link rel="stylesheet" href="css/auth.css?v=20261123-24">

    <script src="js/login.js?v=20261123-24" defer></script>
    <script src="js/auth-transition.js?v=20261121-4" defer></script>
</head>

<body>

<main class="auth-container">

    <!-- LEFT PANEL: CAMPUS BACKGROUND AND SYSTEM INFORMATION -->
    <section
        class="auth-visual"
        style="
            background-image:
                linear-gradient(rgba(8, 30, 17, 0.68), rgba(8, 30, 17, 0.82)),
                url('images/campus-background.jpg');
            background-size: cover;
            background-position: center;
        "
    >

        <div class="visual-content">

            <div class="visual-circle">

                <div class="visual-orbit orbit-one"></div>
                <div class="visual-orbit orbit-two"></div>

                <img
                    src="images/logo.jpg"
                    alt="Student Organization Fee System Logo"
                    class="visual-logo"
                >

            </div>

            <div class="visual-actions">
                <a
                    class="visual-decoration"
                    id="registrationLink"
                    <?= $lockoutSeconds > 0
                        ? 'aria-disabled="true" tabindex="-1"'
                        : 'href="register.php' . (($_GET['embed'] ?? '') === '1' ? '?embed=1' : '') . '"' ?>
                >Register</a>

                <a class="visual-home-button" href="index.php"<?= ($_GET['embed'] ?? '') === '1' ? ' target="_top"' : '' ?>>
                    Home
                </a>
            </div>

            <h2>Welcome!</h2>

            <p>
                Manage student organization membership fees and payments.
            </p>

        </div>

    </section>


    <!-- RIGHT PANEL: LOGIN FORM -->
    <section class="form-panel login-panel">

        <div class="form-container">

            <h1>Welcome Back</h1>

            <p class="form-intro">
                Sign in to manage your organization's membership
                fees and payment records.
            </p>


            <!-- EMAIL VERIFICATION MESSAGE -->
            <?php if ($emailVerified): ?>

                <div class="success-message">
                    <?php if ($registrationPendingApprovalNotice): ?>
                        Your email is verified. Your Treasurer application is waiting for administrator approval.
                    <?php else: ?>
                        Your email has been successfully verified.
                        You may now log in.
                    <?php endif; ?>
                </div>

            <?php endif; ?>


            <!-- PASSWORD RESET MESSAGE -->
            <?php if ($passwordResetSuccess !== ''): ?>

                <div class="success-message">
                    <?= htmlspecialchars(
                        $passwordResetSuccess,
                        ENT_QUOTES,
                        'UTF-8'
                    ) ?>
                </div>

            <?php endif; ?>


            <!-- LOGIN FORM -->
            <form
                action="backend/login_process.php<?= ($_GET['embed'] ?? '') === '1' ? '?embed=1' : '' ?>"
                method="POST"
                id="loginForm"
                novalidate
                autocomplete="off"
            >

                <!-- CSRF TOKEN -->
                <input
                    type="hidden"
                    name="csrf_token"
                    id="csrfToken"
                    value="<?= htmlspecialchars(
                        $csrf,
                        ENT_QUOTES,
                        'UTF-8'
                    ) ?>"
                >


                <!-- USERNAME -->
                <div class="login-input">

                    <svg
                        class="login-input-icon"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="1.8"
                        aria-hidden="true"
                    >
                        <circle cx="12" cy="8" r="4"></circle>
                        <path d="M4 21c0-4.2 3.6-7 8-7s8 2.8 8 7"></path>
                    </svg>

                    <input
                        type="text"
                        id="username"
                        name="username"
                        placeholder="Username or Email"
                        autocomplete="off"
                        maxlength="100"
                        value="<?= htmlspecialchars($failedIdentifier, ENT_QUOTES, 'UTF-8') ?>"
                        aria-label="Username or Email"
                        required
                    >

                </div>


                <!-- PASSWORD -->
                <div class="login-input password-wrapper">

                    <svg
                        class="login-input-icon"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="1.8"
                        aria-hidden="true"
                    >
                        <rect x="4" y="10" width="16" height="11" rx="2"></rect>
                        <path d="M8 10V7a4 4 0 0 1 8 0v3"></path>
                    </svg>

                    <input
                        type="password"
                        id="password"
                        name="password"
                        placeholder="Password"
                        autocomplete="off"
                        aria-label="Password"
                        required
                    >

                    <button
                        type="button"
                        id="togglePassword"
                        class="password-visibility-toggle"
                        aria-label="Show password"
                        aria-pressed="false"
                    >
                        <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                            <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z" />
                            <circle cx="12" cy="12" r="3" />
                            <path class="password-eye-slash" d="M3 21 21 3" />
                        </svg>
                    </button>

                </div>


                <!-- CAPTCHA -->
                <div class="captcha-field">

                    <p class="captcha-heading">
                        Security Check
                    </p>

                    <div class="captcha-challenge">

                        <img
                            src="captcha.image.php"
                            alt="CAPTCHA challenge"
                            id="loginCaptchaImage"
                        >

                        <button
                            type="button"
                            id="refreshCaptcha"
                            class="captcha-refresh"
                            aria-label="Refresh CAPTCHA"
                        >
                            Refresh
                        </button>

                    </div>

                    <input
                        type="text"
                        id="captcha_answer"
                        name="captcha_answer"
                        placeholder="Enter CAPTCHA answer"
                        maxlength="6"
                        autocomplete="off"
                        autocapitalize="characters"
                        aria-label="CAPTCHA answer"
                        required
                    >

                </div>


                <!-- LOGIN ERROR -->
                <div
                    class="error-message"
                    id="loginError"
                    role="alert"
                ><?= htmlspecialchars(
                    $loginError,
                    ENT_QUOTES,
                    'UTF-8'
                ) ?></div>


                <!-- ACCOUNT LOCKOUT COUNTDOWN -->
                <div
                    id="lockoutStatus"
                    <?= $lockoutSeconds > 0 ? '' : 'hidden' ?>
                >

                    Account temporarily locked.
                    Please wait

                    <span
                        id="lockoutCountdown"
                        data-seconds="<?= $lockoutSeconds ?>"
                    ><?= $lockoutSeconds ?></span>

                    seconds.

                </div>


                <!-- FORGOT PASSWORD: APPEARS AFTER 3 FAILED ATTEMPTS -->
                <?php if ($showForgotPassword): ?>

                    <p class="login-actions" id="forgotPasswordAction">

                        <a
                            href="forgot_password.php"
                            data-attempt-identifier="<?= htmlspecialchars($failedIdentifier, ENT_QUOTES, 'UTF-8') ?>"
                        >
                                Forgot your password? Start account recovery
                        </a>

                    </p>

                <?php endif; ?>


                <!-- LOGIN BUTTON -->
                <button
                    type="submit"
                    class="primary-button"
                    id="loginButton"
                    <?= $lockoutSeconds > 0 ? 'disabled' : '' ?>
                >
                    Login
                </button>


                <!-- SECURITY NOTICE -->
                <div class="security-notice">

                    <svg
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="1.8"
                        aria-hidden="true"
                    >
                        <path d="M12 2.5 3.5 6v5.3c0 5.15 3.52 9.74 8.5 11.2 4.98-1.46 8.5-6.05 8.5-11.2V6L12 2.5Z"></path>
                        <path d="m8.5 12 2.3 2.3 4.8-5"></path>
                    </svg>

                    <span>
                        <strong>Your Information Matters</strong>

                        Keep your account details private to protect
                        your organization's records.
                    </span>

                </div>

            </form>

        </div>

    </section>

</main>

<?php if ($registrationPendingApprovalNotice): ?>
    <div class="approval-notice-overlay">
        <section
            class="approval-notice-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="approvalNoticeTitle"
            aria-describedby="approvalNoticeMessage"
        >
            <p class="approval-notice-eyebrow">APPLICATION SUBMITTED</p>
            <h2 id="approvalNoticeTitle">Waiting for administrator approval</h2>
            <p id="approvalNoticeMessage">
                Your email is verified and your Treasurer application is pending.
                You can sign in after an administrator approves your account.
            </p>
            <a class="approval-notice-button" href="login.php">Continue to login</a>
        </section>
    </div>
<?php endif; ?>

</body>
</html>
