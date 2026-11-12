<?php
require_once __DIR__ . '/backend/auth_common.php';

auth_start_session();
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

if (empty($_SESSION['pending_login_user_id']) || empty($_SESSION['pending_login_otp_id'])) {
    auth_redirect('login.php');
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$userId = (string) $_SESSION['pending_login_user_id'];
$otpId = (string) $_SESSION['pending_login_otp_id'];
$statement = $pdo->prepare(
    'SELECT u.email,
            o.expires_at,
            o.attempts,
            o.resend_count,
            GREATEST(0, TIMESTAMPDIFF(SECOND, NOW(), o.expires_at)) AS expires_in,
            GREATEST(0, 60 - TIMESTAMPDIFF(SECOND, o.created_at, NOW())) AS resend_in
     FROM user_otps AS o
     INNER JOIN users AS u ON u.id_number = o.user_id
     WHERE o.otp_id = :otp_id
       AND o.user_id = :user_id
       AND o.purpose = :purpose
       AND o.used_at IS NULL
     LIMIT 1'
);
$statement->execute([
    'otp_id' => $otpId,
    'user_id' => $userId,
    'purpose' => 'LOGIN'
]);
$challenge = $statement->fetch(PDO::FETCH_ASSOC);
$otpError = $_SESSION['otp_error'] ?? '';
$otpNotice = $_SESSION['otp_notice'] ?? '';
$resendSeconds = max(
    0,
    (int) ($challenge['resend_in'] ?? 0),
    (int) ($_SESSION['otp_resend_seconds'] ?? 0)
);
$resendsRemaining = max(
    0,
    (int) ($challenge ? 3 - (int) $challenge['resend_count'] : 0)
);
$expirySeconds = max(0, (int) ($challenge['expires_in'] ?? 0));
$attemptsRemaining = $challenge
    ? max(0, 3 - (int) $challenge['attempts'])
    : 0;
$expired = !$challenge || $expirySeconds <= 0 || $attemptsRemaining <= 0;

unset(
    $_SESSION['otp_error'],
    $_SESSION['otp_notice'],
    $_SESSION['otp_resend_seconds']
);

if ($expired) {
    auth_clear_pending_otp();
}

$maskedEmail = '';
if ($challenge && is_string($challenge['email'])) {
    $parts = explode('@', $challenge['email'], 2);
    $maskedEmail = count($parts) === 2
        ? substr($parts[0], 0, 1) . str_repeat('*', max(2, strlen($parts[0]) - 1)) . '@' . $parts[1]
        : 'your registered email address';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Sign-in | Student Organization Fee System</title>
    <link rel="stylesheet" href="frontend/css/auth.css?v=20261112-2">
    <script src="frontend/js/otp-verification.js" defer></script>
</head>
<body>
<main class="auth-container">
    <aside class="auth-visual" aria-label="Student Organization Fee System">
        <div class="visual-content">
            <h2>One more step</h2>
            <p>Verify your identity to finish signing in.</p>
            <img class="visual-logo" src="images/logo.jpg" alt="Student Organization Fee System logo">
        </div>
    </aside>
    <section class="form-panel">
        <div class="form-container">
            <h1>Verify your sign-in</h1>
            <?php if ($expired): ?>
                <p class="error-message">Your verification code expired or used all attempts. Sign in again to request a new code.</p>
                <p><a href="login.php">Return to login</a></p>
            <?php else: ?>
                <p>Enter the six-digit code sent to <?= htmlspecialchars($maskedEmail, ENT_QUOTES, 'UTF-8') ?>.</p>
                <?php if ($otpError !== ''): ?>
                    <p class="error-message" role="alert"><?= htmlspecialchars($otpError, ENT_QUOTES, 'UTF-8') ?></p>
                <?php endif; ?>
                <?php if ($otpNotice !== ''): ?>
                    <p class="success-message" role="status"><?= htmlspecialchars($otpNotice, ENT_QUOTES, 'UTF-8') ?></p>
                <?php endif; ?>
                <p>Code expires in <span id="otpExpiryCountdown" data-seconds="<?= $expirySeconds ?>"><?= $expirySeconds ?></span> seconds.</p>
                <p><?= $attemptsRemaining ?> verification attempts remaining.</p>
                <form action="backend/verify_otp.php" method="POST">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                    <div class="field">
                        <label for="otp_code">Six-digit code *</label>
                        <input type="text"
                               id="otp_code"
                               name="otp_code"
                               inputmode="numeric"
                               pattern="[0-9]{6}"
                               maxlength="6"
                               autocomplete="one-time-code"
                               required>
                    </div>
                    <button class="primary-button" type="submit">Verify code</button>
                </form>
                <form action="backend/send_otp.php" method="POST">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                    <button class="primary-button"
                            id="resendOtpButton"
                            type="submit"
                            <?= ($resendSeconds > 0 || $resendsRemaining <= 0) ? 'disabled' : '' ?>>
                        Resend code
                    </button>
                    <?php if ($resendsRemaining > 0): ?>
                        <p>
                            <?php if ($resendSeconds > 0): ?>
                                Resend available in <span id="otpResendCountdown" data-seconds="<?= $resendSeconds ?>"><?= $resendSeconds ?></span> seconds.
                            <?php else: ?>
                                <?= $resendsRemaining ?> resends remaining in the current 15-minute window.
                            <?php endif; ?>
                        </p>
                    <?php else: ?>
                        <p>No resends remain in the current 15-minute window.</p>
                    <?php endif; ?>
                </form>
            <?php endif; ?>
        </div>
    </section>
</main>
</body>
</html>
