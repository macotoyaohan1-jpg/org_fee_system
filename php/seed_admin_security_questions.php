<?php

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once __DIR__ . '/backend/db.php';

function seed_admin_read_secret(string $label): string
{
    if (
        PHP_OS_FAMILY !== 'Windows'
        || !function_exists('shell_exec')
        || !function_exists('iconv')
    ) {
        throw new RuntimeException('Hidden input requires Windows PowerShell and PHP iconv.');
    }

    fwrite(STDOUT, $label . ' (input hidden): ');

    $powershell = '$secret = Read-Host -AsSecureString; '
        . '$pointer = [IntPtr]::Zero; '
        . 'try { '
        . '$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret); '
        . '$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer); '
        . '$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($plain)); '
        . '[Console]::WriteLine("ADMIN_ANSWER:" + $encoded); '
        . '} finally { '
        . 'if ($pointer -ne [IntPtr]::Zero) { '
        . '[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) '
        . '} '
        . '}';

    $powershellUtf16 = iconv('UTF-8', 'UTF-16LE', $powershell);
    if (!is_string($powershellUtf16)) {
        throw new RuntimeException('Unable to prepare hidden input.');
    }

    $output = shell_exec(
        'powershell.exe -NoProfile -EncodedCommand ' . base64_encode($powershellUtf16)
    );

    if (
        !is_string($output)
        || !preg_match('/ADMIN_ANSWER:([A-Za-z0-9+\/=]*)/', $output, $matches)
    ) {
        throw new RuntimeException('Hidden input was not received.');
    }

    $answer = base64_decode($matches[1], true);
    if (!is_string($answer)) {
        throw new RuntimeException('Hidden input could not be decoded.');
    }

    return $answer;
}

function seed_admin_prompt(string $label): string
{
    fwrite(STDOUT, $label . ': ');
    $value = fgets(STDIN);

    if ($value === false) {
        throw new RuntimeException('Unable to read the Admin username.');
    }

    return trim($value);
}

try {
    $username = seed_admin_prompt('Admin username');
    $adminLookup = $pdo->prepare(
        "SELECT id_number
         FROM users
         WHERE username = :username
           AND role = 'ADMIN'
           AND account_status = 'ACTIVE'
           AND email_verified_at IS NOT NULL
         LIMIT 2"
    );
    $adminLookup->execute(['username' => $username]);
    $adminIds = $adminLookup->fetchAll(PDO::FETCH_COLUMN);

    if (count($adminIds) !== 1) {
        throw new RuntimeException('Exactly one active, verified Admin must match that username.');
    }

    $userId = (string) $adminIds[0];
    if ($userId === '' || strlen($userId) > 9) {
        throw new RuntimeException('The Admin ID does not fit the user_id column.');
    }

    $questionQuery = $pdo->query(
        'SELECT question_id, question_text
         FROM security_question_bank
         WHERE question_id IN (1, 4, 6)
         ORDER BY question_id'
    );
    $questions = $questionQuery->fetchAll(PDO::FETCH_ASSOC);
    $questionIds = array_map(
        static fn (array $question): int => (int) $question['question_id'],
        $questions
    );

    if ($questionIds !== [1, 4, 6]) {
        throw new RuntimeException('The required security questions are not available.');
    }

    $answerHashes = [];
    foreach ($questions as $question) {
        $questionId = (int) $question['question_id'];
        fwrite(STDOUT, PHP_EOL . 'Q' . $questionId . ': ' . $question['question_text'] . PHP_EOL);

        $answer = trim(seed_admin_read_secret('Answer'));
        $confirmation = trim(seed_admin_read_secret('Confirm answer'));

        if (
            strlen($answer) < 2
            || strlen($answer) > 50
            || preg_match('/\A[A-Za-z]+(?: [A-Za-z]+)*\z/', $answer) !== 1
        ) {
            $answer = '';
            $confirmation = '';
            throw new RuntimeException('Each answer must be 2-50 letters with single spaces only.');
        }

        if (strtolower($answer) !== strtolower($confirmation)) {
            $answer = '';
            $confirmation = '';
            throw new RuntimeException('The confirmation did not match. No rows were inserted.');
        }

        $answerHash = password_hash(strtolower($answer), PASSWORD_DEFAULT);
        $answer = '';
        $confirmation = '';

        if (!is_string($answerHash) || strlen($answerHash) > 255) {
            throw new RuntimeException('Unable to hash an answer for storage.');
        }

        $answerHashes[$questionId] = $answerHash;
    }

    $pdo->beginTransaction();

    try {
        $adminLock = $pdo->prepare(
            "SELECT id_number
             FROM users
             WHERE id_number = :user_id
               AND username = :username
               AND role = 'ADMIN'
               AND account_status = 'ACTIVE'
               AND email_verified_at IS NOT NULL
             FOR UPDATE"
        );
        $adminLock->execute([
            'user_id' => $userId,
            'username' => $username
        ]);

        if ($adminLock->fetchColumn() === false) {
            throw new RuntimeException('The Admin account changed during setup.');
        }

        $existingQuestions = $pdo->prepare(
            'SELECT question_id
             FROM user_security_questions
             WHERE user_id = :user_id
             FOR UPDATE'
        );
        $existingQuestions->execute(['user_id' => $userId]);

        if ($existingQuestions->fetchAll(PDO::FETCH_COLUMN) !== []) {
            throw new RuntimeException('Security questions already exist for this Admin. No rows were changed.');
        }

        $insert = $pdo->prepare(
            'INSERT INTO user_security_questions
                (user_id, question_id, answer_hash)
             VALUES
                (:user_id, :question_id, :answer_hash)'
        );

        foreach ($answerHashes as $questionId => $answerHash) {
            $insert->execute([
                'user_id' => $userId,
                'question_id' => $questionId,
                'answer_hash' => $answerHash
            ]);
        }

        $pdo->commit();
    } catch (Throwable $error) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $error;
    }

    fwrite(STDOUT, PHP_EOL . 'Added three hashed security answers for the Admin. No plaintext answers were stored.' . PHP_EOL);
} catch (PDOException $error) {
    error_log('Admin security-question seed failed: ' . $error->getMessage());
    fwrite(STDERR, 'Database operation failed; check the PHP error log. No answers were logged.' . PHP_EOL);
    exit(1);
} catch (RuntimeException $error) {
    fwrite(STDERR, $error->getMessage() . PHP_EOL);
    exit(1);
}
