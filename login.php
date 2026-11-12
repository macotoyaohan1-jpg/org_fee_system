
<?php
session_start();

// Create a CSRF token for the login form.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$csrf = $_SESSION['csrf_token'];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Login | Student Organization Fee System</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="frontend/css/auth.css?v=20261112-1">
    <script src="frontend/js/login.js" defer></script>
</head>

<body>

<main class="auth-container">

    <aside class="auth-visual" aria-label="Student Organization Fee System">
        <div class="visual-content">
            <h2>Welcome!</h2>
            <p>Manage student organization membership fees and payments.</p>
            <img class="visual-logo" src="images/logo.jpg" alt="Student Organization Fee System logo">
            <a class="visual-switch-button" href="register.php">Register</a>
        </div>
    </aside>

    <section class="form-panel login-panel">
        <div class="form-container">

            <h1>Login</h1>
            <p>Sign in to manage your organization's membership fees and payments.</p>

            <?php if (isset($_GET['registered'])): ?>
                <p class="success-message">
                    Registration submitted. Verify your email to continue.
                </p>
            <?php endif; ?>

            <p class="error-message" id="loginError"></p>

            <form action="backend/login_process.php"
                  method="POST"
                  id="loginForm">

                <input type="hidden"
                       name="csrf_token"
                       value="<?= htmlspecialchars($csrf) ?>">

                <div class="field">
                    <label for="username">Username *</label>
                    <div class="login-input">
                        <svg class="login-input-icon" viewBox="0 0 24 24" aria-hidden="true">
                            <path d="M3 6.75A2.75 2.75 0 0 1 5.75 4h12.5A2.75 2.75 0 0 1 21 6.75v10.5A2.75 2.75 0 0 1 18.25 20H5.75A2.75 2.75 0 0 1 3 17.25V6.75Zm2 .1v.36l7 4.9 7-4.9v-.36a.75.75 0 0 0-.75-.75H5.75A.75.75 0 0 0 5 6.85Zm14 2.8-6.43 4.5a1 1 0 0 1-1.14 0L5 9.65v7.6c0 .41.34.75.75.75h12.5a.75.75 0 0 0 .75-.75v-7.6Z"/>
                        </svg>
                        <input type="text"
                               id="username"
                               name="username"
                               placeholder="Official email or Admin username"
                               autocomplete="username"
                               required>
                    </div>
                </div>

                <div class="field">
                    <label for="password">Password *</label>

                    <div class="password-wrapper login-input">
                        <svg class="login-input-icon" viewBox="0 0 24 24" aria-hidden="true">
                            <path d="M7 10V7a5 5 0 0 1 10 0v3h1.25A2.75 2.75 0 0 1 21 12.75v7A2.25 2.25 0 0 1 18.75 22h-13A2.25 2.25 0 0 1 3.5 19.75v-7A2.75 2.75 0 0 1 6.25 10H7Zm2 0h6V7a3 3 0 0 0-6 0v3Zm3 4a1.5 1.5 0 0 0-.75 2.8v1.45a.75.75 0 0 0 1.5 0V16.8A1.5 1.5 0 0 0 12 14Z"/>
                        </svg>
                        <input type="password"
                               id="password"
                               name="password"
                               placeholder="Password"
                               autocomplete="current-password"
                               required>

                        <button type="button"
                                id="togglePassword">
                            Show
                        </button>
                    </div>
                </div>

                <h2 class="captcha-heading">CAPTCHA Verification</h2>

                <div class="field captcha-field">
                    <p id="captchaQuestion">
                        CAPTCHA will appear here.
                    </p>

                    <label for="captcha_answer">
                        Your Answer *
                    </label>

                    <input type="number"
                           id="captcha_answer"
                           name="captcha_answer"
                           placeholder="Enter your answer"
                           required>
                </div>

                <div id="lockoutStatus" hidden>
                    Account temporarily locked.
                    Please wait
                    <span id="lockoutCountdown">0</span>
                    seconds.
                </div>

                <p class="form-footer login-actions">
                    <a href="forgot_password.php">
                        Forgot Password?
                    </a>
                </p>

                <button type="submit"
                        class="primary-button"
                        id="loginButton">
                    Login
                </button>

                <div class="security-notice">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M12 2.5 3.5 6v5.3c0 5.15 3.52 9.74 8.5 11.2 4.98-1.46 8.5-6.05 8.5-11.2V6L12 2.5Zm0 3.1 5.5 2.26v3.44c0 3.74-2.32 7.13-5.5 8.5V5.6Z"/>
                    </svg>
                    <span>
                        <strong>Your Information Matters</strong>
                        Keep your account details private to protect your organization records.
                    </span>
                </div>

            </form>

        </div>

    </section>

</main>

</body>
</html>
