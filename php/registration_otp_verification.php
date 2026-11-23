<?php

require_once __DIR__ . '/backend/auth_common.php';

auth_start_session();
// Remember whether verification is inside the homepage modal so form posts stay there.
$isEmbeddedAuth = ($_GET['embed'] ?? '') === '1';

// Check whether a registration is waiting for email verification.
$userId = $_SESSION['pending_registration_user_id'] ?? null;
$email = $_SESSION['pending_registration_email'] ?? null;

if (!is_string($userId) || !is_string($email)) {
    $embeddedAuth = ($_GET['embed'] ?? '') === '1';
    auth_redirect('login.php' . ($embeddedAuth ? '?embed=1' : ''));
}

// Create CSRF token.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$csrf = $_SESSION['csrf_token'];

// Get messages.
$error = $_SESSION['registration_otp_error'] ?? '';
$success = $_SESSION['registration_otp_success'] ?? '';

unset(
    $_SESSION['registration_otp_error'],
    $_SESSION['registration_otp_success']
);

// Mask email address for privacy.
$emailParts = explode('@', $email, 2);

if (count($emailParts) === 2) {
    $emailName = $emailParts[0];
    $emailDomain = $emailParts[1];

    $maskedEmail = substr($emailName, 0, 2)
        . str_repeat('*', max(1, strlen($emailName) - 2))
        . '@'
        . $emailDomain;
} else {
    $maskedEmail = 'your registered email address';
}

// Get remaining resend attempts.
$resendsRemaining = (int) (
    $_SESSION['registration_otp_resends_remaining'] ?? 3
);

// Prevent negative resend counts.
$resendsRemaining = max(0, $resendsRemaining);

// Check whether a valid OTP ID is available.
$otpId = $_SESSION['pending_registration_otp_id'] ?? null;

$hasOtp = is_string($otpId)
    && ctype_digit($otpId)
    && (int) $otpId > 0;

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Verify Email - Organization Fee System</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            background: #edf4ee;
            font-family: Arial, sans-serif;
        }

        .verification-card {
            width: 100%;
            max-width: 420px;
            padding: 35px;
            background: white;
            border-radius: 14px;
            border: 1px solid #dce8dd;
            box-shadow: 0 12px 34px rgba(28, 77, 46, 0.12);
        }

        h2 {
            margin-top: 0;
            text-align: center;
            color: #1c4d2e;
        }

        .description {
            text-align: center;
            color: #5f6f63;
            line-height: 1.6;
            font-size: 14px;
        }

        .email {
            font-weight: bold;
            color: #245c38;
        }

        label {
            display: block;
            margin-top: 22px;
            margin-bottom: 8px;
            font-weight: bold;
            color: #333;
        }

        input[type="text"] {
            width: 100%;
            padding: 13px;
            border: 1px solid #cbdaca;
            border-radius: 7px;
            font-size: 22px;
            text-align: center;
            letter-spacing: 8px;
        }

        input[type="text"]:focus {
            border-color: #4b8b5c;
            outline: 3px solid rgba(75, 139, 92, 0.14);
        }

        button {
            width: 100%;
            margin-top: 18px;
            padding: 13px;
            border: none;
            border-radius: 7px;
            background: linear-gradient(100deg, #174c2c, #3c8653);
            color: white;
            font-size: 15px;
            font-weight: bold;
            cursor: pointer;
        }

        button:hover {
            background: linear-gradient(100deg, #1d5b35, #4a9660);
        }

        .resend-button {
            background: #eaf3e9;
            color: #245c38;
        }

        .resend-button:hover {
            background: #dcebdd;
        }

        button:disabled {
            background: #d8dfd8;
            color: #657066;
            cursor: not-allowed;
        }

        button:disabled:hover {
            background: #d8dfd8;
        }

        .message {
            margin: 15px 0;
            padding: 11px;
            border-radius: 7px;
            font-size: 14px;
            line-height: 1.5;
        }

        .error {
            background: #fee2e2;
            color: #991b1b;
        }

        .success {
            background: #dcfce7;
            color: #166534;
        }

        .resend-info {
            margin-top: 18px;
            text-align: center;
            font-size: 13px;
            color: #5f6f63;
        }

        .back-link {
            display: block;
            margin-top: 20px;
            text-align: center;
            color: #2a6940;
            text-decoration: none;
            font-size: 14px;
        }
    </style>
</head>

<body>

<div class="verification-card">

    <h2>Verify Your Email</h2>

    <p class="description">
        <?= $hasOtp
            ? 'We sent a six-digit verification code to:'
            : 'Your account was created, but a verification code has not been sent yet. Request one below for:'
        ?>

        <br>

        <span class="email">
            <?= htmlspecialchars($maskedEmail, ENT_QUOTES, 'UTF-8') ?>
        </span>
    </p>

    <?php if ($error !== ''): ?>
        <div class="message error">
            <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
        </div>
    <?php endif; ?>

    <?php if ($success !== ''): ?>
        <div class="message success">
            <?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?>
        </div>
    <?php endif; ?>

    <?php if ($hasOtp): ?>

        <!-- Keep OTP verification in the same modal or standalone page where registration began. -->
        <form action="backend/verify_registration_otp.php<?= $isEmbeddedAuth ? '?embed=1' : '' ?>" method="POST">

            <input
                type="hidden"
                name="csrf_token"
                value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>"
            >

            <label for="otp">Enter Verification Code</label>

            <input
                type="text"
                id="otp"
                name="otp"
                maxlength="6"
                minlength="6"
                pattern="[0-9]{6}"
                inputmode="numeric"
                autocomplete="one-time-code"
                placeholder="000000"
                required
            >

            <button type="submit">
                Verify Email
            </button>

        </form>

    <?php endif; ?>

    <div class="resend-info">
        Resends remaining: <?= $resendsRemaining ?>
    </div>

    <!-- Preserve the same display mode when the user requests another code. -->
    <form action="backend/resend_registration_otp.php<?= $isEmbeddedAuth ? '?embed=1' : '' ?>" method="POST">

        <input
            type="hidden"
            name="csrf_token"
            value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>"
        >

        <button
            type="submit"
            class="resend-button"
            <?= $resendsRemaining <= 0 ? 'disabled' : '' ?>
        >
            <?= $resendsRemaining <= 0
                ? 'Resend Limit Reached'
                : 'Resend Verification Code'
            ?>
        </button>

    </form>

    <!-- Return to login in the same modal or full-page context. -->
    <a href="login.php<?= $isEmbeddedAuth ? '?embed=1' : '' ?>" class="back-link">
        Back to Login
    </a>

</div>

</body>
</html>
