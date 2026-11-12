
<?php
session_start();

// Create a CSRF token for this form.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$csrf = $_SESSION['csrf_token'];

// Authentication questions from the handout.
$questions = [
    1 => "What was the name of your first pet?",
    2 => "Who was your best friend in elementary school?",
    3 => "Who was your favorite teacher in high school?",
    4 => "What is your mother's maiden first name?",
    5 => "What street did you live on in Grade 1?",
    6 => "What was the first song you learned by heart?",
    7 => "What was the name of your elementary school?",
    8 => "What was the first dish you learned to cook?"
];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Register | Student Organization Fee System</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="frontend/css/auth.css?v=20261112-1">
    <script src="frontend/js/register.js" defer></script>
</head>

<body>

<main class="auth-container register-auth-container">

    <aside class="auth-visual" aria-label="Student Organization Fee System">
        <div class="visual-content">
            <h2>Welcome!</h2>
            <p>Manage student organization membership fees and payments.</p>
            <img class="visual-logo" src="images/logo.jpg" alt="Student Organization Fee System logo">
            <a class="visual-switch-button" href="login.php">Login</a>
        </div>
    </aside>

    <section class="form-panel register-panel">
        <div class="form-container">

            <h1>Create Your Account</h1>
            <p>Complete the information below to register.</p>

            <form action="backend/register_process.php"
                  method="POST"
                  id="registerForm">

                <input type="hidden"
                       name="csrf_token"
                       value="<?= htmlspecialchars($csrf) ?>">

                <!-- Hidden field for bot protection -->
                <input type="text"
                       name="website"
                       class="honeypot"
                       tabindex="-1"
                       autocomplete="off">

                <h2>Personal Information</h2>

                <div class="field">
                    <label for="id_number">ID Number *</label>
                    <input type="text"
                           id="id_number"
                           name="id_number"
                           placeholder="xxxx-xxxx"
                           pattern="[0-9]{4}-[0-9]{4}"
                           required>
                    <small class="error-message" id="id_numberError"></small>
                </div>

                <div class="field">
                    <label for="first_name">First Name *</label>
                    <input type="text" id="first_name"
                           name="first_name" required>
                    <small class="error-message" id="first_nameError"></small>
                </div>

                <div class="field">
                    <label for="middle_name">
                        Middle Name <span class="optional">optional</span>
                    </label>
                    <input type="text" id="middle_name"
                           name="middle_name">
                    <small class="error-message" id="middle_nameError"></small>
                </div>

                <div class="field">
                    <label for="family_name">Family Name *</label>
                    <input type="text" id="family_name"
                           name="family_name" required>
                    <small class="error-message" id="family_nameError"></small>
                </div>

                <div class="field">
                    <label for="extension">Name Extension</label>
                    <select id="extension" name="extension">
                        <option value="">None</option>
                        <option value="Jr.">Jr.</option>
                        <option value="Sr.">Sr.</option>
                        <option value="Other">Other</option>
                    </select>
                </div>

                <div class="field" id="otherExtensionField" hidden>
                    <label for="other_extension">Other Extension</label>
                    <input type="text" id="other_extension"
                           name="other_extension"
                           placeholder="Example: II">
                </div>

                <div class="field">
                    <label for="birthdate">Birthdate *</label>
                    <input type="date" id="birthdate"
                           name="birthdate" required>
                </div>

                <div class="field">
                    <label for="age">Age *</label>
                    <input type="number" id="age"
                           name="age" readonly required>
                </div>

                <h2>Address Information</h2>

                <div class="field">
                    <label for="street">Purok / Street *</label>
                    <input type="text" id="street"
                           name="street" required>
                </div>

                <div class="field">
                    <label for="barangay">Barangay *</label>
                    <input type="text" id="barangay"
                           name="barangay" required>
                </div>

                <div class="field">
                    <label for="city">Municipality / City *</label>
                    <input type="text" id="city"
                           name="city" required>
                </div>

                <div class="field">
                    <label for="province">Province *</label>
                    <input type="text" id="province"
                           name="province" required>
                </div>

                <div class="field">
                    <label for="country">Country *</label>
                    <input type="text" id="country"
                           name="country" required>
                </div>

                <div class="field">
                    <label for="zip_code">ZIP Code *</label>
                    <input type="text" id="zip_code"
                           name="zip_code"
                           maxlength="4"
                           pattern="[0-9]{4}" required>
                </div>

                <h2>Account Information</h2>

                <div class="field">
                    <label for="email">Email Address *</label>
                    <input type="email" id="email"
                           name="email" maxlength="100" required>
                </div>

                <div class="field">
                    <label for="username">Username *</label>
                    <input type="text" id="username"
                           name="username" required>
                    <small id="usernameFeedback"></small>
                </div>

                <div class="field">
                    <label for="password">Password *</label>
                    <input type="password" id="password"
                           name="password" maxlength="64" required>

                    <div class="password-strength">
                        <span id="strengthText">Password strength</span>
                        <div class="strength-bar">
                            <div id="strengthFill"></div>
                        </div>
                    </div>
                </div>

                <div class="field">
                    <label for="confirm_password">
                        Re-enter Password *
                    </label>
                    <input type="password" id="confirm_password"
                           name="confirm_password"
                           maxlength="64" required>
                </div>

                <h2>Security Questions</h2>
                <p>Choose three questions and provide your answers.</p>

                <?php for ($i = 1; $i <= 3; $i++): ?>
                    <div class="field">
                        <label for="question<?= $i ?>">
                            Security Question <?= $i ?> *
                        </label>

                        <select id="question<?= $i ?>"
                                name="security_questions[]"
                                required>
                            <option value="">Select a question</option>

                            <?php foreach ($questions as $number => $question): ?>
                                <option value="<?= $number ?>">
                                    <?= htmlspecialchars($question) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>

                        <label for="answer<?= $i ?>">Answer *</label>
                        <input type="text"
                               id="answer<?= $i ?>"
                               name="security_answers[]"
                               minlength="2"
                               maxlength="50"
                               required>
                    </div>
                <?php endfor; ?>

                <div class="field privacy-field">
                    <input type="checkbox"
                           id="privacy_consent"
                           name="privacy_consent"
                           value="1" required>

                    <label for="privacy_consent">
                        I have read and agree to the Privacy Notice.
                    </label>
                </div>

                <button type="submit" class="primary-button">
                    Create Account
                </button>

            </form>

        </div>

    </section>

</main>

</body>
</html>
