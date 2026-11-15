
<?php

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Use the registration form to create an account.');
}

require_once __DIR__ . '/auth_common.php';
require_once __DIR__ . '/otp_service.php';

auth_start_session();

function registration_fail(string $message): void
{
    $_SESSION['registration_error'] = $message;

    $preserve = [
        'id_number', 'first_name', 'middle_name', 'family_name', 'extension',
        'other_extension', 'birthdate', 'street', 'barangay', 'city', 'province',
        'country', 'zip_code', 'organization_name', 'organization_acronym',
        'organization_type', 'department_college', 'email', 'username'
    ];

    $_SESSION['registration_old'] = [];

    foreach ($preserve as $key) {
        if (isset($_POST[$key]) && is_string($_POST[$key])) {
            $_SESSION['registration_old'][$key] = trim($_POST[$key]);
        }
    }

    if (isset($_POST['security_questions']) && is_array($_POST['security_questions'])) {
        $_SESSION['registration_old']['security_questions'] = array_values(
            array_filter(
                $_POST['security_questions'],
                static fn ($id) => is_scalar($id)
            )
        );
    }

    auth_redirect('../register.php');
}


// =========================================
// CSRF VALIDATION
// =========================================

if (!auth_csrf_is_valid()) {
    registration_fail('This form expired. Refresh the page and submit it again.');
}


// =========================================
// HONEYPOT VALIDATION
// =========================================

$honeypot = $_POST['website'] ?? '';

if (is_string($honeypot) && trim($honeypot) !== '') {
    registration_fail('Unable to submit the registration. Please try again.');
}


// =========================================
// CAPTCHA VALIDATION
// =========================================

$captchaAnswer = $_POST['captcha_answer'] ?? '';
$captchaExpected = $_SESSION['registration_captcha'] ?? '';

unset($_SESSION['registration_captcha']);

if (
    !is_string($captchaAnswer) ||
    !is_string($captchaExpected) ||
    $captchaExpected === '' ||
    !hash_equals($captchaExpected, strtoupper(trim($captchaAnswer)))
) {
    registration_fail('The CAPTCHA code did not match. Please try again.');
}


// =========================================
// GET FORM VALUES
// =========================================

$value = static function (string $key): string {
    return isset($_POST[$key]) && is_string($_POST[$key])
        ? trim($_POST[$key])
        : '';
};

$idNumber = $value('id_number');
$firstName = $value('first_name');
$middleName = $value('middle_name');
$familyName = $value('family_name');
$extension = $value('extension');
$otherExtension = $value('other_extension');
$birthdateInput = $value('birthdate');

$street = $value('street');
$barangay = $value('barangay');
$city = $value('city');
$province = $value('province');
$country = $value('country');
$zipCode = $value('zip_code');

$organizationName = $value('organization_name');
$organizationAcronym = $value('organization_acronym');
$organizationType = $value('organization_type');
$departmentCollege = $value('department_college');

$email = strtolower($value('email'));
$username = $value('username');

$password = $_POST['password'] ?? null;
$confirmPassword = $_POST['confirm_password'] ?? null;


// =========================================
// MAXIMUM FIELD LENGTHS
// =========================================

$maxLengths = [
    'ID number' => [$idNumber, 9],
    'First name' => [$firstName, 28],
    'Middle name' => [$middleName, 28],
    'Family name' => [$familyName, 28],
    'Name extension' => [$extension === 'Other' ? $otherExtension : $extension, 10],
    'Street' => [$street, 50],
    'Barangay' => [$barangay, 50],
    'City' => [$city, 50],
    'Province' => [$province, 50],
    'Country' => [$country, 50],
    'ZIP code' => [$zipCode, 4],
    'Organization name' => [$organizationName, 150],
    'Organization acronym' => [$organizationAcronym, 30],
    'Department / college' => [$departmentCollege, 150],
    'Email' => [$email, 100],
    'Username' => [$username, 19]
];

foreach ($maxLengths as $label => [$text, $limit]) {
    if (strlen($text) > $limit) {
        registration_fail($label . ' is too long.');
    }
}


// =========================================
// ID NUMBER VALIDATION
// =========================================

if (!preg_match('/^[0-9]{3}-[0-9]{5}$/', $idNumber)) {
    registration_fail('Enter your ID number in the format 123-45678.');
}


// =========================================
// PERSONAL AND ADDRESS VALIDATION
// =========================================

if (
    $firstName === '' ||
    $familyName === '' ||
    $street === '' ||
    $barangay === '' ||
    $city === '' ||
    $province === '' ||
    $country === ''
) {
    registration_fail('Complete all required personal and address fields.');
}


// =========================================
// EMAIL VALIDATION
// =========================================

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    registration_fail('Enter a valid email address.');
}


// =========================================
// USERNAME VALIDATION
// =========================================

if (
    $username === '' ||
    preg_match('/^[A-Za-z0-9._-]{3,19}$/', $username) !== 1
) {
    registration_fail('Username must be 3-19 characters using letters, numbers, dots, underscores, or hyphens.');
}


// =========================================
// ZIP CODE VALIDATION
// =========================================

if (!preg_match('/^[0-9]{4}$/', $zipCode)) {
    registration_fail('Enter a four-digit ZIP code.');
}


// =========================================
// NAME EXTENSION VALIDATION
// =========================================

if (!in_array($extension, ['', 'Jr.', 'Sr.', 'Other'], true)) {
    registration_fail('Choose a valid name extension.');
}

if ($extension === 'Other' && $otherExtension === '') {
    registration_fail('Enter the name extension you selected.');
}


// =========================================
// ORGANIZATION VALIDATION
// =========================================

if (!in_array(
    $organizationType,
    ['Academic', 'Socio-Civic', 'Cultural', 'Sports', 'Religious', 'Other'],
    true
)) {
    registration_fail('Choose a valid organization type.');
}

if (
    $organizationName === '' ||
    $organizationAcronym === '' ||
    $departmentCollege === ''
) {
    registration_fail('Complete all organization fields.');
}


// =========================================
// BIRTHDATE AND AGE VALIDATION
// =========================================

$birthdate = DateTimeImmutable::createFromFormat('!Y-m-d', $birthdateInput);
$dateErrors = DateTimeImmutable::getLastErrors();

if (
    !$birthdate ||
    ($dateErrors !== false && (
        $dateErrors['warning_count'] > 0 ||
        $dateErrors['error_count'] > 0
    )) ||
    $birthdate->format('Y-m-d') !== $birthdateInput ||
    $birthdate > new DateTimeImmutable('today') ||
    $birthdate->diff(new DateTimeImmutable('today'))->y < 18
) {
    registration_fail('Applicants must be at least 18 years old and enter a valid birthdate.');
}


// =========================================
// PASSWORD VALIDATION
// =========================================

if (
    !is_string($password) ||
    !is_string($confirmPassword) ||
    $password !== $confirmPassword
) {
    registration_fail('The passwords do not match.');
}

if (strlen($password) < 8 || strlen($password) > 64) {
    registration_fail('Password must be between 8 and 64 characters.');
}

$passwordScore = 0;
$passwordScore += strlen($password) >= 8 ? 1 : 0;
$passwordScore += (
    preg_match('/[a-z]/', $password) &&
    preg_match('/[A-Z]/', $password)
) ? 1 : 0;
$passwordScore += preg_match('/[0-9]/', $password) ? 1 : 0;
$passwordScore += preg_match('/[^A-Za-z0-9]/', $password) ? 1 : 0;
$passwordScore += strlen($password) >= 12 ? 1 : 0;

if ($passwordScore < 3) {
    registration_fail('Choose a medium or strong password with at least three character types.');
}


// =========================================
// PRIVACY CONSENT VALIDATION
// =========================================

if ($value('privacy_consent') !== '1') {
    registration_fail('Please agree to the Privacy Notice to continue.');
}


// =========================================
// SECURITY QUESTIONS AND ANSWERS
// =========================================

$questionIds = $_POST['security_questions'] ?? null;
$answers = $_POST['security_answers'] ?? null;

if (
    !is_array($questionIds) ||
    !is_array($answers) ||
    count($questionIds) !== 3 ||
    count($answers) !== 3
) {
    registration_fail('Choose three security questions and provide all three answers.');
}

$questionIds = array_map(
    static fn ($id) => is_scalar($id) ? trim((string) $id) : '',
    $questionIds
);

$answers = array_map(
    static fn ($answer) => is_string($answer) ? trim($answer) : '',
    $answers
);

if (
    count(array_unique($questionIds)) !== 3 ||
    in_array('', $questionIds, true)
) {
    registration_fail('Choose three different security questions.');
}


// Allow letters, single spaces, apostrophes, and hyphens.
$answerPattern = "/^[A-Za-z]+(?:[ '-][A-Za-z]+)*$/";

foreach ($answers as $answer) {
    if (
        strlen($answer) < 2 ||
        strlen($answer) > 50 ||
        preg_match($answerPattern, $answer) !== 1
    ) {
        registration_fail(
            'Security answers may contain letters, single spaces, apostrophes, and hyphens only.'
        );
    }
}


// =========================================
// DATABASE REGISTRATION
// =========================================

try {

    // Confirm that all selected questions exist.
    $questionCheck = $pdo->prepare(
        'SELECT COUNT(*) FROM security_question_bank
         WHERE question_id IN (?, ?, ?)'
    );

    $questionCheck->execute($questionIds);

    if ((int) $questionCheck->fetchColumn() !== 3) {
        registration_fail(
            'One of the selected security questions is unavailable. Refresh the form and try again.'
        );
    }


    // Check for duplicate ID number, email, or username.
    $duplicate = $pdo->prepare(
        'SELECT id_number FROM users
         WHERE id_number = :id_number
            OR email = :email
            OR username = :username
         LIMIT 1'
    );

    $duplicate->execute([
        'id_number' => $idNumber,
        'email' => $email,
        'username' => $username
    ]);

    if ($duplicate->fetchColumn()) {
        registration_fail(
            'That ID number, email, or username is already registered.'
        );
    }


    // Secure the password.
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    if (!is_string($passwordHash)) {
        throw new RuntimeException('Unable to secure the password.');
    }


    // Start database transaction.
    $pdo->beginTransaction();


    // Create organization.
    $organizationInsert = $pdo->prepare(
        'INSERT INTO organizations
            (organization_name, organization_acronym, organization_type, department_college)
         VALUES
            (:name, :acronym, :type, :department)'
    );

    $organizationInsert->execute([
        'name' => $organizationName,
        'acronym' => $organizationAcronym,
        'type' => $organizationType,
        'department' => $departmentCollege
    ]);

    $organizationId = (int) $pdo->lastInsertId();


    // Create treasurer account.
    $userInsert = $pdo->prepare(
        "INSERT INTO users (
            id_number, first_name, middle_name, family_name, name_extension, birthdate,
            purok_street, barangay, municipality_city, province, country, zip_code,
            email, username, password_hash, role, organization_id, email_verified_at,
            approval_status, account_status, privacy_consent, privacy_consent_at
        ) VALUES (
            :id_number, :first_name, :middle_name, :family_name, :name_extension, :birthdate,
            :street, :barangay, :city, :province, :country, :zip_code,
            :email, :username, :password_hash, 'TREASURER', :organization_id, NULL,
            'PENDING', 'ACTIVE', 1, NOW()
        )"
    );

    $userInsert->execute([
        'id_number' => $idNumber,
        'first_name' => $firstName,
        'middle_name' => $middleName !== '' ? $middleName : null,
        'family_name' => $familyName,
        'name_extension' => $extension === 'Other'
            ? $otherExtension
            : ($extension !== '' ? $extension : null),
        'birthdate' => $birthdate->format('Y-m-d'),
        'street' => $street,
        'barangay' => $barangay,
        'city' => $city,
        'province' => $province,
        'country' => $country,
        'zip_code' => $zipCode,
        'email' => $email,
        'username' => $username,
        'password_hash' => $passwordHash,
        'organization_id' => $organizationId
    ]);


    // Assign treasurer to organization.
    $assignment = $pdo->prepare(
        'INSERT INTO organization_treasurers
            (organization_id, treasurer_id)
         VALUES
            (:organization_id, :user_id)'
    );

    $assignment->execute([
        'organization_id' => $organizationId,
        'user_id' => $idNumber
    ]);


    // Save hashed security answers.
    $questionInsert = $pdo->prepare(
        'INSERT INTO user_security_questions
            (user_id, question_id, answer_hash)
         VALUES
            (:user_id, :question_id, :answer_hash)'
    );

    foreach ($questionIds as $index => $questionId) {

        $answerHash = password_hash(
            strtolower($answers[$index]),
            PASSWORD_DEFAULT
        );

        if (!is_string($answerHash)) {
            throw new RuntimeException('Unable to secure security answers.');
        }

        $questionInsert->execute([
            'user_id' => $idNumber,
            'question_id' => $questionId,
            'answer_hash' => $answerHash
        ]);
    }


    // Save initial password history.
    $historyInsert = $pdo->prepare(
        'INSERT INTO password_history (user_id, password_hash)
         VALUES (:user_id, :password_hash)'
    );

    $historyInsert->execute([
        'user_id' => $idNumber,
        'password_hash' => $passwordHash
    ]);


    // Record registration activity.
    auth_log_event(
        $pdo,
        'TREASURER_APPLICATION_SUBMITTED',
        $username,
        $idNumber,
        'Treasurer registration submitted and awaiting approval.'
    );


    // Commit account creation before sending email.
    $pdo->commit();


} catch (PDOException $error) {

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log(
        'Registration database operation failed: ' .
        $error->getMessage()
    );

    registration_fail(
        $error->getCode() === '23000'
            ? 'That ID number, email, username, or organization is already registered.'
            : 'Registration is temporarily unavailable. Please try again.'
    );


} catch (Throwable $error) {

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log('Registration failed: ' . $error->getMessage());

    registration_fail(
        'Registration is temporarily unavailable. Please try again.'
    );
}


// =========================================
// SEND REGISTRATION VERIFICATION OTP
// =========================================

try {

    $otpResult = auth_issue_registration_otp(
        $pdo,
        $idNumber,
        $email,
        false
    );


    // Save details needed by the verification and resend pages.
    $_SESSION['pending_registration_user_id'] = $idNumber;
    $_SESSION['pending_registration_otp_id'] = (string) $otpResult['otp_id'];
    $_SESSION['pending_registration_email'] = $email;

    $_SESSION['registration_otp_resends_remaining'] =
        (int) $otpResult['resends_remaining'];


    // Record successful OTP email delivery.
    try {

        auth_log_event(
            $pdo,
            'OTP_SENT',
            $email,
            $idNumber,
            'Initial registration verification OTP sent.'
        );

    } catch (Throwable $logError) {

        error_log(
            'Initial registration OTP activity logging failed: ' .
            $logError->getMessage()
        );
    }


    // Clear old registration form errors.
    unset(
        $_SESSION['registration_error'],
        $_SESSION['registration_old']
    );


    // Go to the email verification page.
    auth_redirect('../registration_otp_verification.php');


} catch (Throwable $error) {

    // The account already exists, so do not ask the user to register again.
    error_log(
        'Registration OTP sending failed: ' .
        $error->getMessage()
    );

    $_SESSION['pending_registration_user_id'] = $idNumber;
    $_SESSION['pending_registration_email'] = $email;

    $_SESSION['registration_otp_error'] =
        'Your account was created, but the verification email could not be sent. Please try requesting a verification code again.';

    auth_redirect('../registration_otp_verification.php');
}
