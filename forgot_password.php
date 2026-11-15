
<?php
require_once __DIR__ . '/backend/auth_common.php';
auth_start_session();

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Allow the user to start a new password recovery request.
if (
    ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' &&
    ($_POST['action'] ?? '') === 'new_recovery'
) {
    if (!auth_csrf_is_valid()) {
        $_SESSION['password_reset_error'] = 'The form expired. Please try again.';
        auth_redirect('forgot_password.php');
    }

    // Clear pending recovery information and the saved email.
    unset(
        $_SESSION['pending_password_reset_user_id'],
        $_SESSION['pending_password_reset_otp_id'],
        $_SESSION['pending_password_reset_email'],
        $_SESSION['password_reset_notice'],
        $_SESSION['password_reset_error'],
        $_SESSION['password_reset_captcha'],
        $_SESSION['password_reset_email_input']
    );

    auth_redirect('forgot_password.php');
}

$notice = $_SESSION['password_reset_notice'] ?? '';
$error = $_SESSION['password_reset_error'] ?? '';
$savedEmail = $_SESSION['password_reset_email_input'] ?? '';

unset(
    $_SESSION['password_reset_notice'],
    $_SESSION['password_reset_error']
);

$pendingUserId = $_SESSION['pending_password_reset_user_id'] ?? null;
$pendingOtpId = $_SESSION['pending_password_reset_otp_id'] ?? null;
$pendingEmail = $_SESSION['pending_password_reset_email'] ?? null;

$resetPending = is_string($pendingUserId)
    && trim($pendingUserId) !== ''
    && is_string($pendingOtpId)
    && ctype_digit($pendingOtpId)
    && is_string($pendingEmail)
    && filter_var($pendingEmail, FILTER_VALIDATE_EMAIL) !== false;

$maskedEmail = '';

if ($resetPending) {
    $parts = explode('@', $pendingEmail, 2);

    $maskedEmail = count($parts) === 2
        ? substr($parts[0], 0, 1)
            . str_repeat('*', max(2, strlen($parts[0]) - 1))
            . '@' . $parts[1]
        : 'your registered email address';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Password Recovery | Student Organization Fee System</title>

    <link rel="stylesheet" href="frontend/css/auth.css?v=20261115-1">

    <style>
        .reset-panel {
            width: min(520px, 100%);
            margin: auto;
        }

        .reset-panel .form-container {
            width: 100%;
            max-width: 430px;
        }

        .reset-panel .message {
            margin: 0 0 16px;
            padding: 12px 14px;
            border-radius: 10px;
            line-height: 1.5;
        }

        .reset-panel .message.error {
            background: #fff0ee;
            color: #a3342c;
        }

        .reset-panel .message.success {
            background: #edf6ed;
            color: #245c38;
        }

        .reset-panel .field {
            margin-top: 16px;
        }

        .reset-panel .primary-button {
            margin-top: 16px;
        }

        .reset-panel .secondary-button {
            width: 100%;
            min-height: 44px;
            margin-top: 12px;
            border: 1px solid #cfddce;
            border-radius: 9px;
            background: #edf6ed;
            color: #245c38;
            font: inherit;
            font-weight: 600;
            cursor: pointer;
        }

        .reset-panel .back-link {
            display: block;
            margin-top: 18px;
            color: #2a6940;
            text-align: center;
        }
    </style>
</head>

<body>

<main class="auth-container">

    <section class="form-panel reset-panel">

        <div class="form-container">

            <h1>
                <?= $resetPending
                    ? 'Set a new password'
                    : 'Account password recovery' ?>
            </h1>

            <p>
                <?= $resetPending
                    ? 'Enter the six-digit code sent to '
                        . htmlspecialchars($maskedEmail, ENT_QUOTES, 'UTF-8')
                        . ' and choose a new password.'
                    : 'Request a one-time code using the email address registered to your account.' ?>
            </p>

            <?php if ($error !== ''): ?>
                <p class="message error" role="alert">
                    <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
                </p>
            <?php endif; ?>

            <?php if ($notice !== ''): ?>
                <p class="message success" role="status">
                    <?= htmlspecialchars($notice, ENT_QUOTES, 'UTF-8') ?>
                </p>
            <?php endif; ?>


            <?php if ($resetPending): ?>

                <!-- Reset password form -->
                <form
                    action="backend/reset_admin_password.php"
                    method="post"
                    autocomplete="off"
                >

                    <input
                        type="hidden"
                        name="csrf_token"
                        value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>"
                    >

                    <div class="field">
                        <label for="reset_code">Email code</label>

                        <input
                            id="reset_code"
                            name="reset_code"
                            type="text"
                            inputmode="numeric"
                            pattern="[0-9]{6}"
                            maxlength="6"
                            autocomplete="one-time-code"
                            required
                        >
                    </div>

                    <div class="field">
                        <label for="new_password">New password</label>

                        <input
                            id="new_password"
                            name="new_password"
                            type="password"
                            minlength="8"
                            maxlength="64"
                            autocomplete="new-password"
                            required
                        >
                    </div>

                    <div class="field">
                        <label for="confirm_password">Confirm new password</label>

                        <input
                            id="confirm_password"
                            name="confirm_password"
                            type="password"
                            minlength="8"
                            maxlength="64"
                            autocomplete="new-password"
                            required
                        >
                    </div>

                    <button class="primary-button" type="submit">
                        Reset password
                    </button>

                </form>


                <!-- Resend code form -->
                <form
                    action="backend/request_admin_password_reset.php"
                    method="post"
                >

                    <input
                        type="hidden"
                        name="csrf_token"
                        value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>"
                    >

                    <input
                        type="hidden"
                        name="resend"
                        value="1"
                    >

                    <button class="secondary-button" type="submit">
                        Resend code
                    </button>

                </form>


                <!-- Start a new recovery request -->
                <form method="post" action="forgot_password.php">

                    <input
                        type="hidden"
                        name="csrf_token"
                        value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>"
                    >

                    <input
                        type="hidden"
                        name="action"
                        value="new_recovery"
                    >

                    <button class="secondary-button" type="submit">
                        Start a new recovery request
                    </button>

                </form>


            <?php else: ?>


                <!-- Initial password recovery request -->
                <form
                    action="backend/request_admin_password_reset.php"
                    method="post"
                >

                    <input
                        type="hidden"
                        name="csrf_token"
                        value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>"
                    >

                    <div class="field">
                        <label for="email">Registered email address</label>

                        <input
                            id="email"
                            name="email"
                            type="email"
                            maxlength="100"
                            autocomplete="email"
                            value="<?= htmlspecialchars(
                                is_string($savedEmail) ? $savedEmail : '',
                                ENT_QUOTES,
                                'UTF-8'
                            ) ?>"
                            required
                        >
                    </div>

                    <!-- CAPTCHA is required for the initial request -->
                    <div class="field">

                        <label for="captcha_answer">
                            Enter the CAPTCHA code
                        </label>

                        <img
                            id="passwordResetCaptchaImage"
                            src="password_reset_captcha.image.php"
                            alt="CAPTCHA verification code"
                            width="180"
                            height="60"
                        >

                        <button
                            type="button"
                            class="secondary-button"
                            onclick="refreshPasswordResetCaptcha()"
                        >
                            Refresh CAPTCHA
                        </button>

                        <input
                            id="captcha_answer"
                            name="captcha_answer"
                            type="text"
                            inputmode="text"
                            pattern="[A-Za-z2-9]{6}"
                            maxlength="6"
                            autocapitalize="characters"
                            autocomplete="off"
                            spellcheck="false"
                            required
                        >

                    </div>

                    <button class="primary-button" type="submit">
                        Send recovery code
                    </button>

                </form>

            <?php endif; ?>


            <a class="back-link" href="login.php">
                Back to Login
            </a>

        </div>

    </section>

</main>


<script>
function refreshPasswordResetCaptcha() {

    const captchaImage = document.getElementById('passwordResetCaptchaImage');
    const captchaAnswer = document.getElementById('captcha_answer');

    if (captchaImage) {

        if (captchaAnswer) {
            captchaAnswer.value = '';
        }

        captchaImage.src =
            'password_reset_captcha.image.php?t=' + Date.now();
    }
}
</script>

</body>
</html>
