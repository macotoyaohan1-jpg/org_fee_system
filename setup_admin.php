<?php

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once __DIR__ . '/backend/db.php';

if (!isset($pdo) || !$pdo instanceof PDO) {
    fwrite(STDERR, "The database connection is unavailable.\n");
    exit(1);
}

function setup_prompt(string $label): string
{
    $value = readline($label . ': ');
    if ($value === false) {
        throw new RuntimeException('Unable to read the requested value.');
    }

    return trim($value);
}

function setup_read_secret(string $label): string
{
    if (PHP_OS_FAMILY !== 'Windows' || !function_exists('shell_exec')) {
        throw new RuntimeException('Secure password input requires Windows PowerShell in this environment.');
    }

    fwrite(STDOUT, $label . ' (input hidden): ');
    $powershell = '$secret = Read-Host -AsSecureString; '
        . '$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret); '
        . 'try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer); '
        . 'if ($plain.Length -eq 0) { [Console]::Out.WriteLine("EMPTY") } '
        . 'else { [Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($plain))) } '
        . '} finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }';
    $command = 'powershell.exe -NoProfile -Command ' . escapeshellarg($powershell);
    $output = shell_exec($command);

    if (!is_string($output) || trim($output) === '') {
        throw new RuntimeException('Secure password input failed.');
    }

    $lines = preg_split('/\R/', trim($output));
    $encoded = end($lines);

    if ($encoded === 'EMPTY') {
        return '';
    }

    $secret = base64_decode((string) $encoded, true);
    if (!is_string($secret)) {
        throw new RuntimeException('Secure password input could not be decoded.');
    }

    return $secret;
}

function setup_password_score(string $password): int
{
    $score = 0;
    $score += strlen($password) >= 8 ? 1 : 0;
    $score += preg_match('/[a-z]/', $password) === 1 && preg_match('/[A-Z]/', $password) === 1 ? 1 : 0;
    $score += preg_match('/[0-9]/', $password) === 1 ? 1 : 0;
    $score += preg_match('/[^A-Za-z0-9]/', $password) === 1 ? 1 : 0;
    $score += strlen($password) >= 12 ? 1 : 0;

    return $score;
}

function setup_length(string $value): int
{
    return function_exists('mb_strlen')
        ? mb_strlen($value, 'UTF-8')
        : strlen($value);
}

function setup_validate_birthdate(string $birthdate): void
{
    $date = DateTimeImmutable::createFromFormat('!Y-m-d', $birthdate);
    $errors = DateTimeImmutable::getLastErrors();
    $hasErrors = $errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0);

    if (
        !$date ||
        $hasErrors ||
        $date->format('Y-m-d') !== $birthdate ||
        $date > new DateTimeImmutable('today') ||
        $date->diff(new DateTimeImmutable('today'))->y < 18
    ) {
        throw new RuntimeException('Birthdate must be a valid date and the Admin must be at least 18 years old.');
    }
}

$lockAcquired = false;
$created = false;

try {
    $lock = $pdo->query("SELECT GET_LOCK('org_fee_setup_admin_bootstrap', 10)")->fetchColumn();
    if ((int) $lock !== 1) {
        throw new RuntimeException('Another Admin setup is in progress. Try again later.');
    }
    $lockAcquired = true;

    if ((int) $pdo->query("SELECT COUNT(*) FROM users WHERE role = 'ADMIN'")->fetchColumn() > 0) {
        throw new RuntimeException('An Admin account already exists. The setup script will not create another one.');
    }

    $questions = $pdo->query(
        'SELECT question_id, question_text
         FROM security_question_bank
         ORDER BY question_id'
    )->fetchAll(PDO::FETCH_KEY_PAIR);

    if (count($questions) < 3) {
        throw new RuntimeException('At least three seeded security questions are required.');
    }

    fwrite(STDOUT, "Create the first Admin account. Required profile fields are collected to match the users table.\n");
    $idNumber = setup_prompt('Admin ID Number (####-####)');
    $firstName = setup_prompt('First Name');
    $middleName = setup_prompt('Middle Name (leave blank if none)');
    $familyName = setup_prompt('Family Name');
    $birthdate = setup_prompt('Birthdate (YYYY-MM-DD)');
    $street = setup_prompt('Purok / Street');
    $barangay = setup_prompt('Barangay');
    $city = setup_prompt('Municipality / City');
    $province = setup_prompt('Province');
    $country = setup_prompt('Country');
    $zipCode = setup_prompt('ZIP Code (4 digits)');
    $email = strtolower(setup_prompt('Email Address'));
    $username = setup_prompt('Username');
    $password = setup_read_secret('Admin password');
    $confirmation = setup_read_secret('Confirm Admin password');

    if ($password === '' || !hash_equals($password, $confirmation)) {
        throw new RuntimeException('The password is empty or the two entries do not match.');
    }
    if (strlen($password) > 64 || setup_password_score($password) < 3) {
        throw new RuntimeException(
            'Password must be at most 64 characters and meet at least three of the registration strength criteria.'
        );
    }

    if (preg_match('/\A[0-9]{4}-[0-9]{4}\z/', $idNumber) !== 1) {
        throw new RuntimeException('Admin ID Number must contain four digits, a hyphen, and four digits.');
    }
    if ($firstName === '' || setup_length($firstName) > 28 || setup_length($middleName) > 28 || $familyName === '' || setup_length($familyName) > 28) {
        throw new RuntimeException('Name fields are required where indicated and must fit the existing database columns.');
    }
    setup_validate_birthdate($birthdate);

    $addressFields = [
        'Purok / Street' => [$street, 50],
        'Barangay' => [$barangay, 50],
        'Municipality / City' => [$city, 50],
        'Province' => [$province, 50],
        'Country' => [$country, 50]
    ];
    foreach ($addressFields as $label => $field) {
        if ($field[0] === '' || setup_length($field[0]) > $field[1]) {
            throw new RuntimeException($label . ' is required and must be 50 characters or fewer.');
        }
    }
    if (preg_match('/\A[0-9]{4}\z/', $zipCode) !== 1) {
        throw new RuntimeException('ZIP Code must contain exactly four digits.');
    }
    if ($email === '' || setup_length($email) > 100 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        throw new RuntimeException('Enter a valid email address of at most 100 characters.');
    }
    if ($username === '' || setup_length($username) > 19 || preg_match('/[\x00-\x1F\x7F]/', $username) === 1) {
        throw new RuntimeException('Username is required and must be at most 19 characters.');
    }

    $selectedQuestionIds = [];
    $answers = [];
    foreach (array_values($questions) as $index => $questionText) {
        fwrite(STDOUT, (string) ($index + 1) . '. ' . $questionText . PHP_EOL);
    }
    for ($index = 1; $index <= 3; $index++) {
        $questionId = setup_prompt('Choose a different security question number for answer ' . $index);
        if (!ctype_digit($questionId) || !array_key_exists((int) $questionId, $questions) || in_array((int) $questionId, $selectedQuestionIds, true)) {
            throw new RuntimeException('Choose three different question numbers from the displayed list.');
        }

        $answer = setup_read_secret('Security answer ' . $index);
        if (
            strlen($answer) < 2 ||
            strlen($answer) > 50 ||
            preg_match('/\A[A-Za-z]+(?: [A-Za-z]+)*\z/', trim($answer)) !== 1
        ) {
            throw new RuntimeException('Security answers must be 2-50 letters, with single spaces between words.');
        }

        $answerHash = password_hash(trim($answer), PASSWORD_DEFAULT);
        if ($answerHash === false) {
            throw new RuntimeException('A security answer could not be secured.');
        }

        $selectedQuestionIds[] = (int) $questionId;
        $answers[] = [
            'question_id' => (int) $questionId,
            'answer_hash' => $answerHash
        ];
    }

    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    if ($passwordHash === false) {
        throw new RuntimeException('The Admin password could not be secured.');
    }
    unset($password, $confirmation);

    $duplicate = $pdo->prepare(
        'SELECT id_number
         FROM users
         WHERE id_number = :id_number OR email = :email OR username = :username
         LIMIT 1'
    );
    $duplicate->execute([
        'id_number' => $idNumber,
        'email' => $email,
        'username' => $username
    ]);

    if ($duplicate->fetchColumn()) {
        throw new RuntimeException('The ID Number, email, or username is already in use.');
    }

    $pdo->beginTransaction();
    if ((int) $pdo->query("SELECT COUNT(*) FROM users WHERE role = 'ADMIN'")->fetchColumn() > 0) {
        throw new RuntimeException('An Admin account was created while setup was in progress.');
    }

    $insertUser = $pdo->prepare(
        "INSERT INTO users (
            id_number, first_name, middle_name, family_name, birthdate,
            purok_street, barangay, municipality_city, province, country, zip_code,
            email, username, password_hash, role, organization_id,
            email_verified_at, approval_status, account_status, privacy_consent
         ) VALUES (
            :id_number, :first_name, :middle_name, :family_name, :birthdate,
            :purok_street, :barangay, :municipality_city, :province, :country, :zip_code,
            :email, :username, :password_hash, 'ADMIN', NULL,
            NOW(), 'APPROVED', 'ACTIVE', 0
         )"
    );
    $insertUser->execute([
        'id_number' => $idNumber,
        'first_name' => $firstName,
        'middle_name' => $middleName === '' ? null : $middleName,
        'family_name' => $familyName,
        'birthdate' => $birthdate,
        'purok_street' => $street,
        'barangay' => $barangay,
        'municipality_city' => $city,
        'province' => $province,
        'country' => $country,
        'zip_code' => $zipCode,
        'email' => $email,
        'username' => $username,
        'password_hash' => $passwordHash
    ]);

    $insertQuestion = $pdo->prepare(
        'INSERT INTO user_security_questions (user_id, question_id, answer_hash)
         VALUES (:user_id, :question_id, :answer_hash)'
    );
    foreach ($answers as $answer) {
        $insertQuestion->execute([
            'user_id' => $idNumber,
            'question_id' => $answer['question_id'],
            'answer_hash' => $answer['answer_hash']
        ]);
    }

    $pdo->commit();
    $created = true;
} catch (PDOException $error) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('Admin bootstrap database operation failed: ' . $error->getMessage());
    fwrite(STDERR, "Admin setup failed because of a database error. Check the server error log.\n");
} catch (RuntimeException $error) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    fwrite(STDERR, $error->getMessage() . PHP_EOL);
} finally {
    if ($lockAcquired) {
        $pdo->query("SELECT RELEASE_LOCK('org_fee_setup_admin_bootstrap')");
    }
}

if (!$created) {
    exit(1);
}

fwrite(STDOUT, "Admin account created successfully.\n");
