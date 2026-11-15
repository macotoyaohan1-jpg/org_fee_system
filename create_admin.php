
<?php

// Allow this file to run only through the command line.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

// Connect to the database.
require_once __DIR__ . '/backend/db.php';

// Check if the database connection is available.
if (!isset($pdo) || !$pdo instanceof PDO) {
    fwrite(STDERR, "The database connection is unavailable.\n");
    exit(1);
}

// Ask the Admin for an email address.
function create_admin_prompt(string $label): string
{
    fwrite(STDOUT, $label . ': ');
    $value = fgets(STDIN);

    if ($value === false) {
        throw new RuntimeException('Unable to read the requested value.');
    }

    return trim($value);
}

// Ask for a password without displaying the characters.

function create_admin_read_secret(string $label): string
{
    if (PHP_OS_FAMILY !== 'Windows' || !function_exists('shell_exec')) {
        throw new RuntimeException('Hidden password input requires Windows PowerShell.');
    }

    if (!function_exists('iconv')) {
        throw new RuntimeException('PHP iconv extension is required.');
    }

    fwrite(STDOUT, $label . ' (input hidden): ');

    $powershell = '$secret = Read-Host -AsSecureString; '
        . '$pointer = [IntPtr]::Zero; '
        . 'try { '
        . '$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret); '
        . '$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer); '
        . '$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($plain)); '
        . '[Console]::WriteLine("ADMIN_SECRET:" + $encoded); '
        . '} finally { '
        . 'if ($pointer -ne [IntPtr]::Zero) { '
        . '[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) '
        . '} '
        . '}';

    $encodedCommand = base64_encode(
        iconv('UTF-8', 'UTF-16LE', $powershell)
    );

    $output = shell_exec(
        'powershell.exe -NoProfile -EncodedCommand ' . $encodedCommand
    );

    if (!is_string($output)) {
        throw new RuntimeException('Hidden password input failed.');
    }

    if (!preg_match('/ADMIN_SECRET:([A-Za-z0-9+\/=]*)/', $output, $matches)) {
        throw new RuntimeException('The password input could not be decoded.');
    }

    $secret = base64_decode($matches[1], true);

    if (!is_string($secret)) {
        throw new RuntimeException('The password input could not be decoded.');
    }

    return $secret;
}


// Check the length of the email address.
function create_admin_length(string $value): int
{
    return function_exists('mb_strlen')
        ? mb_strlen($value, 'UTF-8')
        : strlen($value);
}

// Check the strength of the password.
function create_admin_password_score(string $password): int
{
    $score = 0;

    $score += strlen($password) >= 8 ? 1 : 0;

    $score += preg_match('/[a-z]/', $password) === 1
        && preg_match('/[A-Z]/', $password) === 1 ? 1 : 0;

    $score += preg_match('/[0-9]/', $password) === 1 ? 1 : 0;

    $score += preg_match('/[^A-Za-z0-9]/', $password) === 1 ? 1 : 0;

    $score += strlen($password) >= 12 ? 1 : 0;

    return $score;
}

// Generate a unique internal Admin ID.
// The Admin does not need to enter this ID.
function create_admin_identity(PDO $pdo): string
{
    $lookup = $pdo->prepare(
        'SELECT 1 FROM users
         WHERE id_number = :id_number
         LIMIT 1'
    );

    for ($attempt = 0; $attempt < 10; $attempt++) {

        // Generate a unique 9-character ID.
        $idNumber = sprintf(
            '%03d-%05d',
            random_int(0, 999),
            random_int(0, 99999)
        );

        $lookup->execute([
            'id_number' => $idNumber
        ]);

        if (!$lookup->fetchColumn()) {
            return $idNumber;
        }
    }

    throw new RuntimeException(
        'Unable to generate a unique Admin ID. Try again.'
    );
}

$lockAcquired = false;
$created = false;

try {

    // Make sure the correct database is being used.
    if ($pdo->query('SELECT DATABASE()')->fetchColumn() !== 'fee_db') {
        throw new RuntimeException(
            'The Admin setup must use the fee_db database.'
        );
    }

    // Prevent multiple Admin setups from running simultaneously.
    $lock = $pdo->query(
        "SELECT GET_LOCK('org_fee_create_initial_admin', 10)"
    )->fetchColumn();

    if ((int) $lock !== 1) {
        throw new RuntimeException(
            'Another Admin setup is in progress. Try again later.'
        );
    }

    $lockAcquired = true;

    // Check if an Admin account already exists.
    $adminCount = $pdo->query(
        "SELECT COUNT(*) FROM users WHERE role = 'ADMIN'"
    )->fetchColumn();

    if ((int) $adminCount > 0) {
        throw new RuntimeException(
            'An Admin account already exists. No account was created.'
        );
    }

    // Ask only for the Admin email.
    fwrite(STDOUT, "\nCreate the initial Admin account.\n\n");

    $email = strtolower(create_admin_prompt('Email Address'));

    if (
        $email === '' ||
        create_admin_length($email) > 100 ||
        filter_var($email, FILTER_VALIDATE_EMAIL) === false
    ) {
        throw new RuntimeException(
            'Enter a valid email address of at most 100 characters.'
        );
    }

    // Ask only for the Admin password.
    $password = create_admin_read_secret('Admin password');

    if (
        strlen($password) < 8 ||
        strlen($password) > 64 ||
        create_admin_password_score($password) < 3
    ) {
        throw new RuntimeException(
            'Password must be 8-64 characters and meet at least three strength criteria.'
        );
    }

    // Securely hash the password.
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    unset($password);

    if ($passwordHash === false) {
        throw new RuntimeException(
            'The Admin password could not be secured.'
        );
    }

    // Generate the internal Admin ID automatically.
    $idNumber = create_admin_identity($pdo);

    // Start the database transaction.
    $pdo->beginTransaction();

    // Check again if an Admin account already exists.
    $adminCount = $pdo->query(
        "SELECT COUNT(*) FROM users WHERE role = 'ADMIN'"
    )->fetchColumn();

    if ((int) $adminCount > 0) {
        throw new RuntimeException(
            'An Admin account was created while setup was in progress.'
        );
    }

    // Check if the generated ID or email is already registered.
    $duplicate = $pdo->prepare(
        'SELECT id_number
         FROM users
         WHERE id_number = :id_number OR email = :email
         LIMIT 1'
    );

    $duplicate->execute([
        'id_number' => $idNumber,
        'email' => $email
    ]);

    if ($duplicate->fetchColumn()) {
        throw new RuntimeException(
            'The internal ID or email address is already in use.'
        );
    }

    // Create the Admin account.
    // Personal information and username are left NULL.
    $insertUser = $pdo->prepare(
        "INSERT INTO users (
            id_number,
            email,
            password_hash,
            role,
            organization_id,
            email_verified_at,
            approval_status,
            account_status,
            privacy_consent,
            approved_at
        ) VALUES (
            :id_number,
            :email,
            :password_hash,
            'ADMIN',
            NULL,
            NOW(),
            'APPROVED',
            'ACTIVE',
            0,
            NOW()
        )"
    );

    $insertUser->execute([
        'id_number' => $idNumber,
        'email' => $email,
        'password_hash' => $passwordHash
    ]);

    // Save the initial password in password history.
    $insertHistory = $pdo->prepare(
        'INSERT INTO password_history (
            user_id,
            password_hash
        ) VALUES (
            :user_id,
            :password_hash
        )'
    );

    $insertHistory->execute([
        'user_id' => $idNumber,
        'password_hash' => $passwordHash
    ]);

    // Save all database changes.
    $pdo->commit();

    $created = true;

} catch (PDOException $error) {

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log(
        'Initial Admin creation database error: ' . $error->getMessage()
    );

    fwrite(
        STDERR,
        "Admin setup failed because of a database error. Check the server error log.\n"
    );

} catch (RuntimeException $error) {

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    fwrite(STDERR, $error->getMessage() . PHP_EOL);

} finally {

    // Release the database setup lock.
    if ($lockAcquired) {
        $pdo->query(
            "SELECT RELEASE_LOCK('org_fee_create_initial_admin')"
        );
    }
}

// Display the result.
if (!$created) {
    exit(1);
}

fwrite(
    STDOUT,
    "\nInitial Admin account created successfully.\n"
);
