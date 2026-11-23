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

    // Clear pending recovery information and the saved username.
    unset(
        $_SESSION['pending_password_reset_user_id'],
        $_SESSION['pending_password_reset_otp_id'],
        $_SESSION['pending_password_reset_email'],
        $_SESSION['pending_password_reset_username'],
        $_SESSION['pending_password_reset_question_ids'],
        $_SESSION['password_reset_answer_attempts'],
        $_SESSION['password_reset_otp_stage'],
        $_SESSION['password_reset_verified'],
        $_SESSION['password_reset_verified_at'],
        $_SESSION['password_reset_security_question_verified'],
        $_SESSION['password_reset_resend_seconds'],
        $_SESSION['password_reset_resends_remaining'],
        $_SESSION['password_reset_notice'],
        $_SESSION['password_reset_error'],
        $_SESSION['password_reset_captcha'],
        $_SESSION['password_reset_username_input']
    );

    auth_redirect('forgot_password.php');
}

if (
    ($_SESSION['password_reset_otp_stage'] ?? false) === true
    && ($_SESSION['password_reset_security_question_verified'] ?? false) !== true
) {
    unset(
        $_SESSION['pending_password_reset_user_id'],
        $_SESSION['pending_password_reset_otp_id'],
        $_SESSION['pending_password_reset_email'],
        $_SESSION['pending_password_reset_username'],
        $_SESSION['pending_password_reset_question_ids'],
        $_SESSION['password_reset_otp_stage'],
        $_SESSION['password_reset_verified'],
        $_SESSION['password_reset_verified_at'],
        $_SESSION['password_reset_resend_seconds'],
        $_SESSION['password_reset_resends_remaining'],
        $_SESSION['password_reset_notice'],
        $_SESSION['password_reset_security_question_verified'],
        $_SESSION['password_reset_username_input']
    );
    $_SESSION['password_reset_error'] =
        'This recovery session must be restarted. Enter the account username again.';
}

$notice = $_SESSION['password_reset_notice'] ?? '';
$error = $_SESSION['password_reset_error'] ?? '';
$savedUsername = $_SESSION['password_reset_username_input']
    ?? $_SESSION['login_forgot_identifier']
    ?? '';

if (
    !is_string($savedUsername)
    || preg_match('/\A[A-Za-z][A-Za-z0-9]{7,18}\z/', $savedUsername) !== 1
) {
    $savedUsername = '';
}

unset(
    $_SESSION['password_reset_notice'],
    $_SESSION['password_reset_error']
);

$pendingUserId = $_SESSION['pending_password_reset_user_id'] ?? null;
$pendingOtpId = $_SESSION['pending_password_reset_otp_id'] ?? null;
$pendingEmail = $_SESSION['pending_password_reset_email'] ?? null;
$pendingUsername = $_SESSION['pending_password_reset_username'] ?? null;
$otpStage = ($_SESSION['password_reset_otp_stage'] ?? false) === true
    && ($_SESSION['password_reset_security_question_verified'] ?? false) === true;
$resendSeconds = max(0, (int) ($_SESSION['password_reset_resend_seconds'] ?? 0));
$resendsRemaining = max(0, (int) ($_SESSION['password_reset_resends_remaining'] ?? 3));
$verifiedAt = $_SESSION['password_reset_verified_at'] ?? null;
$passwordResetVerified = ($_SESSION['password_reset_verified'] ?? false) === true
    && is_int($verifiedAt)
    && time() - $verifiedAt <= AUTH_OTP_EXPIRY_MINUTES * 60;

$resetPending = $otpStage
    && $passwordResetVerified
    && is_string($pendingUserId)
    && trim($pendingUserId) !== ''
    && is_string($pendingOtpId)
    && ctype_digit($pendingOtpId)
    && is_string($pendingEmail)
    && filter_var($pendingEmail, FILTER_VALIDATE_EMAIL) !== false;

$questionStage = !$otpStage
    && is_string($pendingUsername)
    && trim($pendingUsername) !== '';
$questionStage = $questionStage
    && is_string($pendingUserId)
    && trim($pendingUserId) !== '';

$seedQuestions = $pdo->query(
    'SELECT question_id, question_text
     FROM security_question_bank
     WHERE question_id IN (1, 4, 6)
     ORDER BY question_id'
)->fetchAll(PDO::FETCH_ASSOC);
$questionIds = $_SESSION['pending_password_reset_question_ids'] ?? [];
$questionIds = is_array($questionIds) ? array_map('intval', $questionIds) : [];
$seedQuestions = array_values(array_filter(
    $seedQuestions,
    static fn (array $question): bool => in_array(
        (int) $question['question_id'],
        $questionIds,
        true
    )
));

$maskedEmail = '';

if ($otpStage && is_string($pendingEmail) && filter_var($pendingEmail, FILTER_VALIDATE_EMAIL)) {
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

    <link rel="stylesheet" href="css/auth.css?v=20261115-1">
    <script src="js/password_visibility.js?v=20261116-1" defer></script>

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

        .reset-panel .captcha-refresh-row {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-top: 8px;
            margin-bottom: 10px;
        }

        .reset-panel .captcha-refresh-button {
            width: auto;
            min-height: 28px;
            margin: 0;
            padding: 4px 8px;
            font-size: 0.85rem;
            white-space: nowrap;
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
                    : ($otpStage
                        ? 'Verify recovery code'
                        : ($questionStage
                            ? 'Verify your security answer'
                            : 'Account password recovery')) ?>
            </h1>

            <p>
                <?= $resetPending
                    ? 'Choose a new password for your account.'
                    : ($otpStage
                        ? 'If the account details are valid, a recovery code was sent to '
                            . htmlspecialchars($maskedEmail, ENT_QUOTES, 'UTF-8')
                            . '.'
                        : ($questionStage
                            ? 'Choose one of your security questions and enter the same answer twice.'
                            : 'Enter your Admin or Treasurer username.')) ?>
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
                <form
                    action="backend/reset_admin_password.php"
                    method="post"
                    autocomplete="off"
                    id="passwordResetForm"
                >

                    <input
                        type="hidden"
                        name="csrf_token"
                        value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>"
                    >

                    <input type="hidden" name="action" value="change_password">

                    <div class="field">
                        <label for="new_password">New password</label>

                        <div class="password-wrapper">
                            <input
                                id="new_password"
                                name="new_password"
                                type="password"
                                minlength="<?= AUTH_PASSWORD_MIN_LENGTH ?>"
                                maxlength="64"
                                autocomplete="new-password"
                                required
                            >
                            <button
                                type="button"
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
                        <div class="password-strength">
                            <span id="resetStrengthText" aria-live="polite">
                                Password strength
                            </span>
                            <div class="strength-bar">
                                <div id="resetStrengthFill"></div>
                            </div>
                        </div>
                    </div>

                    <div class="field">
                        <label for="confirm_password">Confirm new password</label>

                        <div class="password-wrapper">
                            <input
                                id="confirm_password"
                                name="confirm_password"
                                type="password"
                                minlength="<?= AUTH_PASSWORD_MIN_LENGTH ?>"
                                maxlength="64"
                                autocomplete="new-password"
                                required
                            >
                            <button
                                type="button"
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
                    </div>

                    <button
                        class="primary-button"
                        type="submit"
                        id="resetPasswordButton"
                    >
                        Change password
                    </button>

                </form>

            <?php elseif ($otpStage): ?>
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
                    <input type="hidden" name="action" value="verify_otp">

                    <div class="field">
                        <label for="reset_code">Six-digit recovery code</label>
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

                    <button class="primary-button" type="submit">
                        Verify code
                    </button>
                </form>

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

                    <button
                        class="secondary-button"
                        type="submit"
                        id="passwordResetResendButton"
                        <?= $resendSeconds > 0 || $resendsRemaining === 0 ? 'disabled' : '' ?>
                    >
                        Resend code
                        <span id="passwordResetResendCountdown" aria-live="polite"></span>
                    </button>
                    <small id="passwordResetResendStatus" aria-live="polite">
                        <?= $resendsRemaining === 0
                            ? 'No resends are available. Start a new recovery after the 15-minute limit.'
                            : 'Resends remaining: ' . $resendsRemaining ?>
                    </small>

                </form>

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

            <?php elseif ($questionStage): ?>
                <form
                    action="backend/request_admin_password_reset.php"
                    method="post"
                    autocomplete="off"
                >
                    <input
                        type="hidden"
                        name="csrf_token"
                        value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>"
                    >
                    <input type="hidden" name="action" value="answer">

                    <div class="field">
                        <label for="security_question">Choose your security question</label>
                        <select id="security_question" name="question_id" required>
                            <option value="">Select a question</option>
                            <?php foreach ($seedQuestions as $question): ?>
                                <option value="<?= (int) $question['question_id'] ?>">
                                    <?= htmlspecialchars($question['question_text'], ENT_QUOTES, 'UTF-8') ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="field">
                        <label for="security_answer">Your answer</label>
                        <input
                            id="security_answer"
                            name="security_answer"
                            type="text"
                            minlength="2"
                            maxlength="50"
                            pattern="[A-Za-z]+( [A-Za-z]+)*"
                            autocomplete="off"
                            required
                        >
                    </div>

                    <div class="field">
                        <label for="confirm_security_answer">Re-enter answer</label>
                        <input
                            id="confirm_security_answer"
                            name="confirm_security_answer"
                            type="text"
                            minlength="2"
                            maxlength="50"
                            pattern="[A-Za-z]+( [A-Za-z]+)*"
                            autocomplete="off"
                            required
                        >
                    </div>

                    <button class="primary-button" type="submit">
                        Verify answer
                    </button>
                </form>

            <?php else: ?>
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
                        <label for="username">Username</label>

                        <input
                            id="username"
                            name="username"
                            type="text"
                            minlength="<?= AUTH_USERNAME_MIN_LENGTH ?>"
                            maxlength="<?= AUTH_USERNAME_MAX_LENGTH ?>"
                            pattern="[A-Za-z][A-Za-z0-9]{7,18}"
                            autocomplete="username"
                            value="<?= htmlspecialchars(
                                is_string($savedUsername) ? $savedUsername : '',
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

                        <div class="captcha-refresh-row">
                            <img
                                id="passwordResetCaptchaImage"
                                src="password_reset_captcha.image.php"
                                alt="CAPTCHA verification code"
                                width="180"
                                height="60"
                            >

                            <button
                                type="button"
                                class="secondary-button captcha-refresh-button"
                                aria-label="Refresh CAPTCHA"
                                onclick="refreshPasswordResetCaptcha()"
                            >
                                Refresh
                            </button>
                        </div>

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
                        Continue
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
const resetPassword = document.getElementById('new_password');
const resetStrengthText = document.getElementById('resetStrengthText');
const resetStrengthFill = document.getElementById('resetStrengthFill');
const resetPasswordButton = document.getElementById('resetPasswordButton');
const passwordResetForm = document.getElementById('passwordResetForm');

if (resetPassword && resetStrengthText && resetStrengthFill && resetPasswordButton) {
    resetPassword.addEventListener('input', function () {
        resetPassword.setCustomValidity('');
        let score = 0;
        score += resetPassword.value.length >= <?= AUTH_PASSWORD_MIN_LENGTH ?> ? 1 : 0;
        score += /[a-z]/.test(resetPassword.value) && /[A-Z]/.test(resetPassword.value) ? 1 : 0;
        score += /[0-9]/.test(resetPassword.value) ? 1 : 0;
        score += /[^A-Za-z0-9]/.test(resetPassword.value) ? 1 : 0;
        score += resetPassword.value.length >= 12 ? 1 : 0;

        if (resetPassword.value.length === 0) {
            resetStrengthText.textContent = 'Password strength';
            resetStrengthFill.style.width = '0%';
        } else if (score <= 2) {
            resetStrengthText.textContent = 'Weak';
            resetStrengthFill.style.width = '33%';
            resetStrengthFill.style.background = '#dc4c5c';
        } else if (score <= 3) {
            resetStrengthText.textContent = 'Medium';
            resetStrengthFill.style.width = '66%';
            resetStrengthFill.style.background = '#e6a23c';
        } else {
            resetStrengthText.textContent = 'Strong';
            resetStrengthFill.style.width = '100%';
            resetStrengthFill.style.background = '#35a66a';
        }

        resetPasswordButton.disabled = score <= 2;
    });
    resetPassword.dispatchEvent(new Event('input'));
}

if (passwordResetForm) {
    passwordResetForm.addEventListener('submit', function (event) {
        if (resetStrengthText && resetStrengthText.textContent === 'Weak') {
            event.preventDefault();
            resetPassword.setCustomValidity('Please create a Medium or Strong password.');
            resetPassword.reportValidity();
        }
    });
}

const passwordResetResendButton = document.getElementById('passwordResetResendButton');
const passwordResetResendCountdown = document.getElementById('passwordResetResendCountdown');
const passwordResetResendStatus = document.getElementById('passwordResetResendStatus');
if (
    passwordResetResendButton
    && passwordResetResendCountdown
    && passwordResetResendStatus
) {
    let remainingSeconds = <?= $resendSeconds ?>;
    const resendsRemaining = <?= $resendsRemaining ?>;
    let resendTimer = null;
    const updateResendCountdown = function () {
        passwordResetResendButton.disabled =
            remainingSeconds > 0 || resendsRemaining === 0;
        passwordResetResendCountdown.textContent = remainingSeconds > 0
            ? ' (' + remainingSeconds + 's)'
            : '';
        if (remainingSeconds <= 0) {
            window.clearInterval(resendTimer);
            resendTimer = null;
        }
    };

    updateResendCountdown();
    if (remainingSeconds > 0) {
        resendTimer = window.setInterval(function () {
            remainingSeconds--;
            updateResendCountdown();
        }, 1000);
    }
}

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
