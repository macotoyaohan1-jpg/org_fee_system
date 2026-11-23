<?php

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Use the registration form to create an account.');
}

require_once __DIR__ . '/auth_common.php';
require_once __DIR__ . '/otp_service.php';
require_once __DIR__ . '/encryption.php';

auth_start_session();

if (($_POST['action'] ?? '') === 'check_organization_name') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');

    $organizationName = $_POST['organization_name'] ?? null;
    if (!auth_csrf_is_valid()) {
        http_response_code(403);
        echo json_encode([
            'available' => false,
            'message' => 'Refresh the registration form and try again.'
        ]);
        exit;
    }

    if (
        !is_string($organizationName) ||
        strlen(trim($organizationName)) < 2 ||
        strlen(trim($organizationName)) > 150 ||
        preg_match('/\A[A-Za-z0-9][A-Za-z0-9 .,&()\/\-]*\z/', trim($organizationName)) !== 1
    ) {
        echo json_encode([
            'available' => false,
            'message' => 'Organization Name must contain 2-150 valid characters.'
        ]);
        exit;
    }

    try {
        $organizationNameCheck = $pdo->prepare(
            'SELECT COUNT(*) FROM organizations
             WHERE LOWER(TRIM(organization_name)) LIKE
                   CONCAT(LOWER(TRIM(:organization_name)), \'%\')'
        );
        $organizationNameCheck->execute([
            'organization_name' => trim($organizationName)
        ]);
        $available = (int) $organizationNameCheck->fetchColumn() === 0;
    } catch (PDOException $error) {
        error_log('Organization name availability check failed: ' . $error->getMessage());
        http_response_code(503);
        echo json_encode([
            'available' => false,
            'message' => 'Organization Name availability could not be checked.'
        ]);
        exit;
    }

    echo json_encode([
        'available' => $available,
        'message' => $available
            ? 'This Organization Name is available.'
            : 'This Organization Name or a similar name is already registered.'
    ]);
    exit;
}

if (($_POST['action'] ?? '') === 'check_username') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');

    $username = $_POST['username'] ?? null;
    if (!auth_csrf_is_valid()) {
        http_response_code(403);
        echo json_encode([
            'available' => false,
            'message' => 'Refresh the registration form and try again.'
        ]);
        exit;
    }

    if (
        !is_string($username) ||
        preg_match('/\A[A-Za-z][A-Za-z0-9]{7,18}\z/', $username) !== 1
    ) {
        echo json_encode([
            'available' => false,
            'message' => 'Use 8-19 letters and numbers, starting with a letter.'
        ]);
        exit;
    }

    try {
        $usernameCheck = $pdo->prepare(
            'SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(:username)'
        );
        $usernameCheck->execute(['username' => $username]);
        $available = (int) $usernameCheck->fetchColumn() === 0;
    } catch (PDOException $error) {
        error_log('Username availability check failed: ' . $error->getMessage());
        http_response_code(503);
        echo json_encode([
            'available' => false,
            'message' => 'Username availability could not be checked. Try again.'
        ]);
        exit;
    }

    echo json_encode([
        'available' => $available,
        'message' => $available ? 'This username is available.' : 'This username is taken.'
    ]);
    exit;
}

// Check email uniqueness while the applicant is entering the registration form.
if (($_POST['action'] ?? '') === 'check_email') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');

    $emailToCheck = $_POST['email'] ?? null;
    if (!auth_csrf_is_valid()) {
        http_response_code(403);
        echo json_encode([
            'available' => false,
            'message' => 'Refresh the registration form and try again.'
        ]);
        exit;
    }

    if (
        !is_string($emailToCheck) ||
        strlen(trim($emailToCheck)) > 100 ||
        filter_var(trim($emailToCheck), FILTER_VALIDATE_EMAIL) === false
    ) {
        echo json_encode([
            'available' => false,
            'message' => 'Please enter a valid email address.'
        ]);
        exit;
    }

    $emailToCheck = strtolower(trim($emailToCheck));

    try {
        $emailCheck = $pdo->prepare(
            'SELECT COUNT(*) FROM users WHERE LOWER(email) = :email'
        );
        $emailCheck->execute(['email' => $emailToCheck]);
        $available = (int) $emailCheck->fetchColumn() === 0;
    } catch (PDOException $error) {
        error_log('Email availability check failed: ' . $error->getMessage());
        http_response_code(503);
        echo json_encode([
            'available' => false,
            'message' => 'Email availability could not be checked. Try again.'
        ]);
        exit;
    }

    echo json_encode([
        'available' => $available,
        'message' => $available ? 'This email is available.' : 'This email is already registered.'
    ]);
    exit;
}

function registration_fail(string $message, ?string $field = null): void
{
    unset($_SESSION['registration_error'], $_SESSION['registration_errors']);

    if ($field !== null) {
        $_SESSION['registration_errors'] = [$field => $message];
    } else {
        $_SESSION['registration_error'] = $message;
    }

    $preserve = [
        'id_number', 'first_name', 'middle_name', 'family_name', 'extension',
        'other_extension', 'birthdate', 'street', 'barangay', 'city', 'province',
        'country', 'zip_code', 'organization_name', 'organization_acronym',
        'organization_type', 'department_college', 'organization_contact_number',
        'email', 'username'
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

    if (isset($_POST['security_answers']) && is_array($_POST['security_answers'])) {
        $_SESSION['registration_old']['security_answers'] = array_values(
            array_filter(
                $_POST['security_answers'],
                static fn ($answer) => is_scalar($answer)
            )
        );
    }

    $wantsJson = (
        ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'XMLHttpRequest'
        || str_contains((string) ($_SERVER['HTTP_ACCEPT'] ?? ''), 'application/json')
    );

    if ($wantsJson) {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        http_response_code(422);
        echo json_encode([
            'success' => false,
            'message' => $message,
            'field' => $field
        ]);
        exit;
    }

    $embeddedAuth = ($_GET['embed'] ?? '') === '1';
    auth_redirect('../register.php' . ($embeddedAuth ? '?embed=1' : ''));
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
    auth_log_event(
        $pdo,
        'HONEYPOT_REJECTED',
        null,
        null,
        'The hidden registration field was filled.'
    );
    http_response_code(400);
    exit;
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
    auth_log_event(
        $pdo,
        'CAPTCHA_FAILED',
        null,
        null,
        'The registration CAPTCHA did not match.'
    );
    registration_fail('The CAPTCHA code did not match. Please try again.', 'captcha_answer');
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
$organizationContactNumber = $value('organization_contact_number');

$email = strtolower($value('email'));
$username = $value('username');

$password = $_POST['password'] ?? null;
$confirmPassword = $_POST['confirm_password'] ?? null;


// =========================================
// MAXIMUM FIELD LENGTHS
// =========================================

$maxLengths = [
    'id_number' => ['ID Number', $idNumber, 9],
    'first_name' => ['First Name', $firstName, AUTH_NAME_MAX_LENGTH],
    'middle_name' => ['Middle Name', $middleName, AUTH_NAME_MAX_LENGTH],
    'family_name' => ['Family Name', $familyName, AUTH_NAME_MAX_LENGTH],
    'other_extension' => [
        'Name Extension',
        $extension === 'Other' ? $otherExtension : $extension,
        10
    ],
    'street' => ['Purok / Street', $street, 50],
    'barangay' => ['Barangay', $barangay, 50],
    'city' => ['Municipality / City', $city, 50],
    'province' => ['Province', $province, 50],
    'country' => ['Country', $country, 50],
    'zip_code' => ['ZIP Code', $zipCode, 4],
    'organization_name' => ['Organization Name', $organizationName, 150],
    'organization_acronym' => ['Organization Acronym', $organizationAcronym, 30],
    'department_college' => ['Department / College', $departmentCollege, 150],
    'organization_contact_number' => [
        'Organization Contact Number',
        $organizationContactNumber,
        11
    ],
    'email' => ['Email', $email, 100],
    'username' => ['Username', $username, AUTH_USERNAME_MAX_LENGTH]
];

foreach ($maxLengths as $field => [$label, $text, $limit]) {
    if (strlen($text) > $limit) {
        registration_fail($label . ' is too long.', $field);
    }
}


// =========================================
// ID NUMBER VALIDATION
// =========================================

// Report an empty required ID field before checking its format, as the handout requires field-specific errors.
if ($idNumber === '') {
    registration_fail('Please enter your ID Number.', 'id_number');
}

if (!preg_match('/\A[0-9]{4}-[0-9]{4}\z/', $idNumber)) {
    registration_fail(
        'ID Number must follow the format xxxx-xxxx.',
        'id_number'
    );
}


// =========================================
// PERSONAL AND ADDRESS VALIDATION
// =========================================

$nameFields = [
    'first_name' => ['First Name', $firstName, true],
    'middle_name' => ['Middle Name', $middleName, false],
    'family_name' => ['Family Name', $familyName, true]
];

foreach ($nameFields as $field => [$label, $name, $required]) {
    if ($name === '' && $required) {
        registration_fail($label . ' is required.', $field);
    }

    if ($name === '') {
        continue;
    }

    if (strlen($name) < 2) {
        registration_fail($label . ' must be at least 2 characters.', $field);
    }
    if (preg_match('/[0-9]/', $name) === 1) {
        registration_fail('Numbers are not allowed in ' . $label . '.', $field);
    }
    if (strpos($name, '  ') !== false) {
        registration_fail('Double space is not allowed.', $field);
    }
    if (preg_match('/([A-Za-z])\1\1/i', $name) === 1) {
        registration_fail('Three consecutive identical letters are not allowed.', $field);
    }
    if (preg_match('/^[A-Z ]+$/', $name) === 1) {
        registration_fail('Do not use all capital letters.', $field);
    }
    if (!preg_match('/\A[A-Za-z]+(?: [A-Za-z]+)*\z/', $name)) {
        registration_fail('Special characters are not allowed in ' . $label . '.', $field);
    }
    if (!preg_match('/\A[A-Z][a-z]+(?: [A-Z][a-z]+)*\z/', $name)) {
        if ($field === 'first_name' && preg_match('/\A[a-z]/', $name) === 1) {
            registration_fail(
                'First letter of your name must be capital.',
                $field
            );
        }
        registration_fail(
            'First letter of each word must be capital; the rest must be lowercase.',
            $field
        );
    }
}

$addressFields = [
    'street' => ['Purok / Street', $street, 3, 50, false],
    'barangay' => ['Barangay', $barangay, 2, 50, true],
    'city' => ['Municipality / City', $city, 2, 50, true],
    'province' => ['Province', $province, 2, 50, true],
    'country' => ['Country', $country, 2, 50, true]
];

foreach ($addressFields as $field => [$label, $text, $minimum, $maximum, $titleCase]) {
    if ($text === '') {
        registration_fail($label . ' is required.', $field);
    }
    if (strlen($text) < $minimum || strlen($text) > $maximum) {
        registration_fail($label . ' must be between ' . $minimum . ' and ' . $maximum . ' characters.', $field);
    }
    if (strpos($text, '  ') !== false) {
        registration_fail('Double space is not allowed in ' . $label . '.', $field);
    }

    if (!$titleCase) {
        if (preg_match('/\A[A-Za-z0-9]+(?: [A-Za-z0-9]+)*\z/', $text) !== 1) {
            registration_fail(
                'Purok / Street must contain letters, numbers, and single spaces only.',
                $field
            );
        }
        if (preg_match('/\A[a-z]/', $text) === 1) {
            registration_fail(
                'First letter of Purok / Street must be capital.',
                $field
            );
        }
    } else {
        if (preg_match('/\A[A-Za-z]+(?: [A-Za-z]+)*\z/', $text) !== 1) {
            registration_fail(
                $label . ' must contain letters and single spaces only.',
                $field
            );
        }
        if (preg_match('/\A[A-Z][a-z]*(?: [A-Z][a-z]*)*\z/', $text) !== 1) {
            registration_fail(
                'First letter of each word in ' . $label . ' must be capital.',
                $field
            );
        }
    }
}


// =========================================
// EMAIL VALIDATION
// =========================================

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    registration_fail('Please enter a valid email address.', 'email');
}


// =========================================
// USERNAME VALIDATION
// =========================================

if (
    $username === '' ||
    preg_match('/\A[A-Za-z][A-Za-z0-9]{7,18}\z/', $username) !== 1
) {
    registration_fail(
        'Username must start with a letter and contain 8-19 letters and numbers only.',
        'username'
    );
}


// =========================================
// ZIP CODE VALIDATION
// =========================================

if (!preg_match('/^[0-9]{4}$/', $zipCode)) {
    registration_fail('ZIP Code must contain exactly 4 digits.', 'zip_code');
}


// =========================================
// NAME EXTENSION VALIDATION
// =========================================

if (!in_array($extension, ['', 'Jr.', 'Sr.', 'Other'], true)) {
    registration_fail('Choose a valid name extension.');
}

if ($extension === 'Other' && $otherExtension === '') {
    registration_fail('Enter the name extension you selected.', 'other_extension');
}

if (
    $extension === 'Other' &&
    !in_array($otherExtension, ['I', 'II', 'III', 'IV', 'IX', 'X'], true)
) {
    registration_fail(
        'Choose I, II, III, IV, IX, or X for the other name extension.',
        'other_extension'
    );
}


// =========================================
// ORGANIZATION VALIDATION
// =========================================

if (!in_array(
    $organizationType,
    ['Academic', 'Socio-Civic', 'Cultural', 'Sports', 'Religious', 'Other'],
    true
)) {
    registration_fail('Choose a valid organization type.', 'organization_type');
}

if ($organizationName === '') {
    registration_fail(
        'Organization Name is required.',
        'organization_name'
    );
}

if (strlen($organizationName) < 2 || strlen($organizationName) > 150) {
    registration_fail(
        'Organization Name must be between 2 and 150 characters.',
        'organization_name'
    );
}

if (!preg_match('/\A[A-Za-z0-9][A-Za-z0-9 .,&()\/\-]*\z/', $organizationName)) {
    registration_fail(
        'Organization Name contains invalid characters.',
        'organization_name'
    );
}

if ($organizationAcronym === '') {
    registration_fail(
        'Organization Acronym is required.',
        'organization_acronym'
    );
}

if (
    strlen($organizationAcronym) < 2 ||
    strlen($organizationAcronym) > 30 ||
    preg_match('/\A[A-Za-z0-9][A-Za-z0-9 .,&()\/\-]*\z/', $organizationAcronym) !== 1
) {
    registration_fail(
        'Organization Acronym must be 2-30 letters, numbers, spaces, or valid punctuation.',
        'organization_acronym'
    );
}

if ($departmentCollege === '') {
    registration_fail(
        'Department / College is required.',
        'department_college'
    );
}

if (
    strlen($departmentCollege) < 2 ||
    strlen($departmentCollege) > 150 ||
    preg_match('/\A[A-Za-z0-9][A-Za-z0-9 .,&()\/\-]*\z/', $departmentCollege) !== 1
) {
    registration_fail(
        'Department / College must be 2-150 letters, numbers, spaces, or valid punctuation.',
        'department_college'
    );
}

if ($organizationContactNumber === '') {
    registration_fail(
        'Organization Contact Number is required.',
        'organization_contact_number'
    );
}

if (
    preg_match('/\A09[0-9]{9}\z/', $organizationContactNumber) !== 1
) {
    registration_fail(
        'Organization Contact Number must be 11 digits and start with 09.',
        'organization_contact_number'
    );
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
    $message = $birthdate && $birthdate->diff(new DateTimeImmutable('today'))->y < 18
        ? 'You must be at least 18 years old to register.'
        : 'Enter a valid birthdate.';
    registration_fail($message, 'birthdate');
}


// =========================================
// PASSWORD VALIDATION
// =========================================

if (
    !is_string($password) ||
    !is_string($confirmPassword) ||
    $password !== $confirmPassword
) {
    registration_fail('Passwords do not match.', 'confirm_password');
}

if (
    strlen($password) < AUTH_PASSWORD_MIN_LENGTH ||
    strlen($password) > 64
) {
    registration_fail(
        'Password must be between ' . AUTH_PASSWORD_MIN_LENGTH . ' and 64 characters.',
        'password'
    );
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
    registration_fail('Choose a medium or strong password with at least three character types.', 'password');
}


// =========================================
// PRIVACY CONSENT VALIDATION
// =========================================

if ($value('privacy_consent') !== '1') {
    registration_fail(
        'You must agree to the Privacy Notice to register.',
        'privacy_consent'
    );
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
    registration_fail(
        'Choose the three security questions provided for your account and enter each answer.',
        'question1'
    );
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
    registration_fail('Choose three different security questions.', 'question1');
}

$sortedQuestionIds = $questionIds;
sort($sortedQuestionIds, SORT_NUMERIC);
if ($sortedQuestionIds !== ['1', '4', '6']) {
    registration_fail(
        'Choose the three security questions assigned to your account.',
        'question1'
    );
}

// Security answers accept letters and single spaces only.
$answerPattern = '/\A[A-Za-z]+(?: [A-Za-z]+)*\z/';

foreach ($answers as $answerIndex => $answer) {
    if (
        strlen($answer) < 2 ||
        strlen($answer) > 50 ||
        preg_match($answerPattern, $answer) !== 1
    ) {
        registration_fail(
            'Security answers must contain 2-50 letters and single spaces only.',
            'answer' . ($answerIndex + 1)
        );
    }
}


// =========================================
// DATABASE REGISTRATION
// =========================================

try {

    // Confirm that the seed-selected questions exist.
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

    $organizationDuplicate = $pdo->prepare(
        'SELECT organization_id
         FROM organizations
         WHERE LOWER(TRIM(organization_name)) LIKE
               CONCAT(LOWER(TRIM(:organization_name)), \'%\')
         LIMIT 1'
    );
    $organizationDuplicate->execute([
        'organization_name' => $organizationName
    ]);

    if ($organizationDuplicate->fetchColumn() !== false) {
        registration_fail(
            'This Organization Name or a similar name is already registered.',
            'organization_name'
        );
    }

    // Check for duplicate ID number, email, or username.
    $duplicate = $pdo->prepare(
        'SELECT id_number, email, username FROM users
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

    $existingAccount = $duplicate->fetch(PDO::FETCH_ASSOC);
    if ($existingAccount) {
        if ($existingAccount['id_number'] === $idNumber) {
            registration_fail('This ID Number is already registered.', 'id_number');
        }
        if (strcasecmp((string) $existingAccount['email'], $email) === 0) {
            registration_fail('This email is already registered.', 'email');
        }
        registration_fail('This username is already registered.', 'username');
    }


    // Secure the password.
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    if (!is_string($passwordHash)) {
        throw new RuntimeException('Unable to secure the password.');
    }


    // Start database transaction.
    $pdo->beginTransaction();

    $encryptedOrganizationContactNumber =
        encrypt_emergency_contact_number($organizationContactNumber);

    if (!is_string($encryptedOrganizationContactNumber)) {
        throw new RuntimeException('Unable to secure the organization contact number.');
    }

    // Create organization.
    $organizationInsert = $pdo->prepare(
        'INSERT INTO organizations
            (organization_name, organization_acronym, organization_type, department_college,
             organization_contact_number_encrypted)
         VALUES
            (:name, :acronym, :type, :department, :contact_number)'
    );

    $organizationInsert->execute([
        'name' => $organizationName,
        'acronym' => $organizationAcronym,
        'type' => $organizationType,
        'department' => $departmentCollege,
        'contact_number' => $encryptedOrganizationContactNumber
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
        'REGISTERED',
        $username,
        $idNumber,
        'A new Treasurer account was saved and is awaiting verification.'
    );
    auth_log_event(
        $pdo,
        'TREASURER_APPLICATION_SUBMITTED',
        $username,
        $idNumber,
        'Treasurer registration submitted and awaiting approval.'
    );
    auth_log_event(
        $pdo,
        'TREASURER_REGISTERED',
        $username,
        $idNumber,
        'Treasurer account registered successfully.'
    );


    // Keep the new account and its first OTP in one transaction. If the
    // verification email cannot be sent, the incomplete registration rolls back.
    $otpResult = auth_issue_registration_otp(
        $pdo,
        $idNumber,
        $email,
        false,
        false
    );

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


// Save details needed by the verification and resend pages.
$_SESSION['pending_registration_user_id'] = $idNumber;
$_SESSION['pending_registration_otp_id'] = (string) $otpResult['otp_id'];
$_SESSION['pending_registration_email'] = $email;
$_SESSION['registration_otp_resends_remaining'] =
    (int) $otpResult['resends_remaining'];

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

unset(
    $_SESSION['registration_error'],
    $_SESSION['registration_errors'],
    $_SESSION['registration_old']
);

$_SESSION['registration_otp_success'] =
    'Your account was created. Enter the verification code sent to your email to finish registration.';

$embeddedAuth = ($_GET['embed'] ?? '') === '1';
auth_redirect('../registration_otp_verification.php' . ($embeddedAuth ? '?embed=1' : ''));
