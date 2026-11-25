<?php

require_once __DIR__ . '/backend/auth_common.php';
auth_start_session();
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// Create a CSRF token for this form.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$csrf = $_SESSION['csrf_token'];
$registrationError = $_SESSION['registration_error'] ?? '';
$registrationErrors = $_SESSION['registration_errors'] ?? [];
if (!is_array($registrationErrors)) {
    $registrationErrors = [];
}
$registrationOld = $_SESSION['registration_old'] ?? [];
unset($_SESSION['registration_error']);
unset($_SESSION['registration_errors']);
unset($_SESSION['registration_old']);
$oldValue = static function (string $key) use ($registrationOld): string {
    return htmlspecialchars(
        is_string($registrationOld[$key] ?? null) ? $registrationOld[$key] : '',
        ENT_QUOTES,
        'UTF-8'
    );
};
$oldQuestions = is_array($registrationOld['security_questions'] ?? null)
    ? array_map('strval', $registrationOld['security_questions'])
    : [];
$oldAnswers = is_array($registrationOld['security_answers'] ?? null)
    ? array_map('strval', $registrationOld['security_answers'])
    : [];

// Load security questions directly from the database.
$statement = $pdo->query("
    SELECT question_id, question_text
    FROM security_question_bank
    WHERE question_id IN (1, 4, 6)
    ORDER BY question_id
");

$questions = $statement->fetchAll(PDO::FETCH_ASSOC);

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Register | Student Organization Fee System</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>

    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap"
          rel="stylesheet">

    <!-- Bump this version when auth.css changes so browsers fetch the latest styles. -->
    <link rel="stylesheet" href="css/auth.css?v=20261123-23">

    <!-- Update the version when register.js changes so browsers load its latest validation message. -->
    <script src="js/register.js?v=20261124-2" defer></script>
    <script src="js/auth-transition.js?v=20261121-4" defer></script>
</head>

<body>

<main class="auth-container register-auth-container">

    <!-- LEFT SIDE -->
    <aside class="auth-visual" aria-label="Student Organization Fee System">

        <div class="visual-content">

            <h2>Welcome!</h2>

            <p>
                Apply for a treasurer account and connect it to your organization.
            </p>

            <div class="registration-flow-note">
                <span>1  Submit your application</span>
                <span>2  Verify your email at sign-in</span>
                <span>3  Wait for administrator approval</span>
            </div>

            <img class="visual-logo"
                 src="images/logo.jpg"
                 alt="Student Organization Fee System logo">

            <div class="visual-actions">
                <a class="visual-switch-button" href="login.php<?= ($_GET['embed'] ?? '') === '1' ? '?embed=1' : '' ?>">Login</a>
                <a class="visual-home-button" href="index.php"<?= ($_GET['embed'] ?? '') === '1' ? ' target="_top"' : '' ?>>Home</a>
            </div>

        </div>

    </aside>


    <!-- RIGHT SIDE -->
    <section class="form-panel register-panel">

        <div class="form-container">

            <h1>Create Your Account</h1>

            <p>Complete your treasurer application in a few short steps.</p>

            <?php if ($registrationError !== ''): ?>
                <p class="registration-error" id="registrationError" role="alert"><?= htmlspecialchars($registrationError, ENT_QUOTES, 'UTF-8') ?></p>
            <?php endif; ?>


            <form action="backend/register_process.php<?= ($_GET['embed'] ?? '') === '1' ? '?embed=1' : '' ?>"
                  method="POST"
                  id="registerForm"
                  novalidate
                  autocomplete="off"
                  data-registration-errors="<?= htmlspecialchars(
                      json_encode($registrationErrors, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP),
                      ENT_QUOTES,
                      'UTF-8'
                  ) ?>">

                <!-- CSRF Protection -->
                <input type="hidden"
                       name="csrf_token"
                       value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">


                <!-- Honeypot Bot Protection -->
                <input type="text"
                       name="website"
                       class="honeypot"
                       tabindex="-1"
                       autocomplete="off"
                       aria-hidden="true">


                <!-- ================================= -->
                <!-- PERSONAL INFORMATION -->
                <!-- ================================= -->

                <h2>Personal Information</h2>


                <div class="field">

                    <label for="id_number">ID Number <span class="required-marker">*</span></label>

                    <input type="text"
                           id="id_number"
                           name="id_number"
                           value="<?= $oldValue('id_number') ?>"
                           placeholder="xxxx-xxxx"
                           pattern="[0-9]{4}-[0-9]{4}"
                           maxlength="9"
                           required>

                    <small class="error-message" id="id_numberError"></small>

                </div>


                <div class="field">

                    <label for="first_name">First Name <span class="required-marker">*</span></label>

                    <input type="text"
                           id="first_name"
                           name="first_name"
                           value="<?= $oldValue('first_name') ?>"
                           minlength="2"
                           maxlength="28"
                           pattern="[A-Z][a-z]+( [A-Z][a-z]+)*"
                           placeholder="e.g., Juan"
                           required>

                    <small class="error-message" id="first_nameError"></small>

                </div>


                <div class="field">

                    <label for="middle_name">
                        Middle Name <span class="optional">optional</span>
                    </label>

                    <input type="text"
                           id="middle_name"
                           name="middle_name"
                           value="<?= $oldValue('middle_name') ?>"
                           minlength="2"
                           maxlength="28"
                           pattern="[A-Z][a-z]+( [A-Z][a-z]+)*">

                    <small class="error-message" id="middle_nameError"></small>

                </div>


                <div class="field">

                    <label for="family_name">Family Name <span class="required-marker">*</span></label>

                    <input type="text"
                           id="family_name"
                           name="family_name"
                           value="<?= $oldValue('family_name') ?>"
                           minlength="2"
                           maxlength="28"
                           pattern="[A-Z][a-z]+( [A-Z][a-z]+)*"
                           placeholder="e.g., Dela Cruz"
                           required>

                    <small class="error-message" id="family_nameError"></small>

                </div>


                <div class="field">

                    <label for="extension">Name Extension</label>

                    <select id="extension" name="extension">

                        <option value="">None</option>
                        <option value="Jr." <?= ($registrationOld['extension'] ?? '') === 'Jr.' ? 'selected' : '' ?>>Jr.</option>
                        <option value="Sr." <?= ($registrationOld['extension'] ?? '') === 'Sr.' ? 'selected' : '' ?>>Sr.</option>
                        <option value="Other" <?= ($registrationOld['extension'] ?? '') === 'Other' ? 'selected' : '' ?>>Other</option>

                    </select>

                </div>


                <div class="field" id="otherExtensionField" hidden>

                    <label for="other_extension">Other Extension</label>

                    <input type="text"
                           id="other_extension"
                           name="other_extension"
                           value="<?= $oldValue('other_extension') ?>"
                           placeholder="Example: II"
                           maxlength="10">

                </div>


                <div class="field">

                    <label for="birthdate">Birthdate <span class="required-marker">*</span></label>

                    <input type="date"
                           id="birthdate"
                           name="birthdate"
                           value="<?= $oldValue('birthdate') ?>"
                           max="<?= date('Y-m-d') ?>"
                           required>

                </div>


                <div class="field">

                    <label for="age">Age <span class="required-marker">*</span></label>

                    <input type="number"
                           id="age"
                           name="age"
                           readonly
                           required>

                </div>



                <!-- ================================= -->
                <!-- ADDRESS INFORMATION -->
                <!-- ================================= -->

                <h2>Address Information</h2>


                <div class="field">
                    <label for="country">Country <span class="required-marker">*</span></label>
                    <input type="text"
                           id="country"
                           name="country"
                           value="<?= $oldValue('country') !== '' ? $oldValue('country') : 'Philippines' ?>"
                           minlength="2"
                           maxlength="50"
                           pattern="[A-Z][A-Za-z]*( [A-Za-z]+)*"
                           autocomplete="off"
                           required>
                    <small class="error-message" id="countryError"></small>
                    <div class="address-suggestions" id="countrySuggestions" hidden></div>
                </div>

                <div class="field">
                    <label for="province">Province <span class="required-marker">*</span></label>
                    <input type="text"
                           id="province"
                           name="province"
                           value="<?= $oldValue('province') ?>"
                           minlength="2"
                           maxlength="50"
                           pattern="[A-Z][A-Za-z]*( [A-Za-z]+)*"
                           autocomplete="off"
                           required>
                    <small class="error-message" id="provinceError"></small>
                    <div class="address-suggestions" id="provinceSuggestions" hidden></div>
                </div>

                <div class="field">
                    <label for="city">Municipality / City <span class="required-marker">*</span></label>
                    <input type="text"
                           id="city"
                           name="city"
                           value="<?= $oldValue('city') ?>"
                           minlength="2"
                           maxlength="50"
                           pattern="[A-Z][A-Za-z]*( [A-Za-z]+)*"
                           autocomplete="off"
                           required>
                    <small class="error-message" id="cityError"></small>
                    <div class="address-suggestions" id="citySuggestions" hidden></div>
                </div>

                <div class="field">
                    <label for="barangay">Barangay <span class="required-marker">*</span></label>
                    <input type="text"
                           id="barangay"
                           name="barangay"
                           value="<?= $oldValue('barangay') ?>"
                           minlength="2"
                           maxlength="50"
                           pattern="[A-Z][A-Za-z]*( [A-Za-z]+)*"
                           autocomplete="off"
                           required>
                    <small class="error-message" id="barangayError"></small>
                    <div class="address-suggestions" id="barangaySuggestions" hidden></div>
                </div>

                <div class="field">
                    <label for="street">Purok / Street <span class="required-marker">*</span></label>
                    <input type="text"
                           id="street"
                           name="street"
                           value="<?= $oldValue('street') ?>"
                           minlength="3"
                           maxlength="50"
                           pattern="[A-Za-z0-9]+( [A-Za-z0-9]+)*"
                           autocomplete="off"
                           required>
                    <small class="error-message" id="streetError"></small>
                </div>


                <div class="field">

                    <label for="zip_code">ZIP Code <span class="required-marker">*</span></label>

                    <input type="text"
                           id="zip_code"
                           name="zip_code"
                           value="<?= $oldValue('zip_code') ?>"
                           maxlength="4"
                           pattern="[0-9]{4}"
                           required>

                    <small class="error-message" id="zip_codeError"></small>

                </div>



                <!-- ================================= -->
                <!-- ORGANIZATION INFORMATION -->
                <!-- ================================= -->

                <h2>Organization Information</h2>

                <p>Enter your organization's details below.</p>


                <div class="field">

                    <label for="organization_name">Organization Name <span class="required-marker">*</span></label>

                    <input type="text"
                           id="organization_name"
                           name="organization_name"
                           value="<?= $oldValue('organization_name') ?>"
                           maxlength="150"
                           required>

                    <small class="availability-feedback error-message"
                           id="organizationNameFeedback"
                           aria-live="polite"></small>

                </div>


                <div class="field">

                    <label for="organization_acronym">
                        Organization Acronym <span class="required-marker">*</span>
                    </label>

                    <input type="text"
                           id="organization_acronym"
                           name="organization_acronym"
                           value="<?= $oldValue('organization_acronym') ?>"
                           maxlength="30"
                           required>

                    <small class="error-message" id="organization_acronymError"></small>

                </div>


                <div class="field">

                    <label for="organization_type">Organization Type <span class="required-marker">*</span></label>

                    <select id="organization_type"
                            name="organization_type"
                            required>

                        <option value="">Select organization type</option>
                        <option value="Academic" <?= ($registrationOld['organization_type'] ?? '') === 'Academic' ? 'selected' : '' ?>>Academic</option>
                        <option value="Socio-Civic" <?= ($registrationOld['organization_type'] ?? '') === 'Socio-Civic' ? 'selected' : '' ?>>Socio-Civic</option>
                        <option value="Cultural" <?= ($registrationOld['organization_type'] ?? '') === 'Cultural' ? 'selected' : '' ?>>Cultural</option>
                        <option value="Sports" <?= ($registrationOld['organization_type'] ?? '') === 'Sports' ? 'selected' : '' ?>>Sports</option>
                        <option value="Religious" <?= ($registrationOld['organization_type'] ?? '') === 'Religious' ? 'selected' : '' ?>>Religious</option>
                        <option value="Other" <?= ($registrationOld['organization_type'] ?? '') === 'Other' ? 'selected' : '' ?>>Other</option>

                    </select>

                </div>


                <div class="field">

                    <label for="department_college">
                        Department / College <span class="required-marker">*</span>
                    </label>

                    <input type="text"
                           id="department_college"
                           name="department_college"
                           value="<?= $oldValue('department_college') ?>"
                           maxlength="150"
                           required>

                    <small class="error-message" id="department_collegeError"></small>

                </div>


                <div class="field">

                    <label for="organization_contact_number">
                        Organization Contact Number <span class="required-marker">*</span>
                    </label>

                    <input type="text"
                           id="organization_contact_number"
                           name="organization_contact_number"
                           value="<?= $oldValue('organization_contact_number') ?>"
                           placeholder="09xxxxxxxxx"
                           maxlength="11"
                           pattern="09[0-9]{9}"
                           inputmode="numeric"
                           required>

                    <small class="error-message" id="organization_contact_numberError"></small>

                </div>


                <!-- ================================= -->
                <!-- ACCOUNT INFORMATION -->
                <!-- ================================= -->

                <h2>Account Information</h2>


                <div class="field">

                    <label for="email">Email Address <span class="required-marker">*</span></label>

                    <input type="email"
                           id="email"
                           name="email"
                           value="<?= $oldValue('email') ?>"
                           maxlength="100"
                           placeholder="example@example.com"
                           required>

                    <!-- Displays email availability feedback directly below the email field. -->
                    <small class="availability-feedback error-message"
                           id="emailFeedback"
                           aria-live="polite"></small>

                </div>


                <div class="field">

                    <label for="username">Username <span class="required-marker">*</span></label>

                    <input type="text"
                           id="username"
                           name="username"
                           value="<?= $oldValue('username') ?>"
                           minlength="8"
                           maxlength="19"
                           pattern="[A-Za-z][A-Za-z0-9]{7,18}"
                           required>

                    <small class="availability-feedback error-message"
                           id="usernameFeedback"
                           aria-live="polite"></small>

                </div>


                <div class="field">

                    <label for="password">Password <span class="required-marker">*</span></label>

                    <div class="password-wrapper register-password-wrapper">
                        <input type="password"
                               id="password"
                               name="password"
                               minlength="8"
                               maxlength="64"
                               required>
                        <button type="button"
                                class="password-visibility-toggle"
                                aria-label="Show password"
                                aria-pressed="false">
                            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                                <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z" />
                                <circle cx="12" cy="12" r="3" />
                                <path class="password-eye-slash" d="M3 21 21 3" />
                            </svg>
                        </button>
                    </div>

                    <div class="password-strength">

                        <span id="strengthText">Password strength</span>

                        <div class="strength-bar">
                            <div id="strengthFill"></div>
                        </div>

                    </div>

                </div>


                <div class="field">

                    <label for="confirm_password">
                        Re-enter Password <span class="required-marker">*</span>
                    </label>

                    <div class="password-wrapper register-password-wrapper">
                        <input type="password"
                               id="confirm_password"
                               name="confirm_password"
                               minlength="8"
                               maxlength="64"
                               required>
                        <button type="button"
                                class="password-visibility-toggle"
                                aria-label="Show password"
                                aria-pressed="false">
                            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                                <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z" />
                                <circle cx="12" cy="12" r="3" />
                                <path class="password-eye-slash" d="M3 21 21 3" />
                            </svg>
                        </button>
                    </div>

                </div>



                <!-- ================================= -->
                <!-- SECURITY QUESTIONS -->
                <!-- ================================= -->

                <h2>Security Questions</h2>

                <p>Choose three questions and provide your answers.</p>


                <?php for ($i = 1; $i <= 3; $i++): ?>

                    <div class="field">

                        <label for="question<?= $i ?>">
                            Security Question <?= $i ?> <span class="required-marker">*</span>
                        </label>

                        <select id="question<?= $i ?>"
                                name="security_questions[]"
                                required>
                            <option value="">Select a question</option>

                            <?php foreach ($questions as $question): ?>
                                <option value="<?= (int) $question['question_id'] ?>" <?= ($oldQuestions[$i - 1] ?? '') === (string) $question['question_id'] ? 'selected' : '' ?>>
                                    <?= htmlspecialchars($question['question_text'], ENT_QUOTES, 'UTF-8') ?>
                                </option>
                            <?php endforeach; ?>
                        </select>

                        <label for="answer<?= $i ?>">Answer <span class="required-marker">*</span></label>

                        <input type="text"
                               id="answer<?= $i ?>"
                               name="security_answers[]"
                               value="<?= htmlspecialchars($oldAnswers[$i - 1] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                               minlength="2"
                               maxlength="50"
                               pattern="[A-Za-z]+( [A-Za-z]+)*"
                               required>

                    </div>

                <?php endfor; ?>



                <!-- Keep privacy consent with the security questions, as requested. -->
                <div class="field privacy-field">
                    <input type="checkbox"
                           id="privacy_consent"
                           name="privacy_consent"
                           value="1"
                           required>

                    <label for="privacy_consent">
                        I have read the
                        <!-- Open the notice in the same browsing context to preserve the form. -->
                        <a id="privacyNoticeLink" href="privacy_notice.php">Privacy Notice</a>
                        and agree to the collection and processing of my personal data in
                        accordance with the Data Privacy Act of 2012 (RA 10173).
                    </label>
                </div>

                <!-- ================================= -->
                <!-- REGISTRATION CAPTCHA -->
                <!-- ================================= -->

                <h2>Security Verification</h2>

                <div class="field">

                    <label for="captcha_answer">
                        Enter the CAPTCHA code <span class="required-marker">*</span>
                    </label>

                    <!-- Keep the CAPTCHA image and refresh control in one row with visible separation. -->
                    <div class="registration-captcha-controls">

                        <img src="registration_captcha.image.php"
                             alt="Registration CAPTCHA"
                             id="registrationCaptcha">

                        <button type="button" class="captcha-refresh-button" id="refreshRegistrationCaptcha">
                            Refresh code
                        </button>

                    </div>

                    <input type="text"
                           id="captcha_answer"
                           name="captcha_answer"
                           minlength="6"
                           maxlength="6"
                           pattern="[A-Za-z0-9]{6}"
                           inputmode="text"
                           autocomplete="off"
                           required>

                </div>



                <!-- ================================= -->
                <!-- SUBMIT BUTTON -->
                <!-- ================================= -->

                <button type="submit" class="auth-button">
                    Create Account
                </button>


            </form>

        </div>

    </section>

</main>

</body>
</html>
