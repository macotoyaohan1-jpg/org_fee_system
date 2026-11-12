<?php

require_once __DIR__ . '/db.php';

if (!isset($pdo) || !$pdo instanceof PDO) {
    throw new RuntimeException('The database connection is unavailable.');
}

function auth_start_session(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}

function auth_redirect(string $location, int $status = 303): void
{
    header('Location: ' . $location, true, $status);
    exit;
}

function auth_csrf_is_valid(): bool
{
    $provided = $_POST['csrf_token'] ?? null;
    $expected = $_SESSION['csrf_token'] ?? null;

    return is_string($provided)
        && is_string($expected)
        && hash_equals($expected, $provided);
}

function auth_flash_login(string $message, ?int $failures = null, int $lockoutSeconds = 0): void
{
    $_SESSION['login_error'] = $message;
    if ($failures !== null) {
        $_SESSION['login_failed_attempts'] = max(0, $failures);
    }
    $_SESSION['login_lockout_seconds'] = max(0, $lockoutSeconds);
}

function auth_record_login_attempt(
    PDO $pdo,
    ?string $userId,
    string $identifier,
    string $ipAddress,
    bool $success
): void {
    $statement = $pdo->prepare(
        'INSERT INTO login_attempts (user_id, username_typed, ip_address, success)
         VALUES (:user_id, :username_typed, :ip_address, :success)'
    );
    $statement->execute([
        'user_id' => $userId,
        'username_typed' => $identifier,
        'ip_address' => $ipAddress,
        'success' => $success ? 1 : 0
    ]);
}

function auth_failure_history(PDO $pdo, ?string $userId, string $normalizedIdentifier): array
{
    if ($userId !== null) {
        $statement = $pdo->prepare(
            'SELECT success, TIMESTAMPDIFF(SECOND, attempted_at, NOW()) AS age_seconds
             FROM login_attempts
             WHERE user_id = :user_id
             ORDER BY attempt_id DESC
             LIMIT 100'
        );
        $statement->execute(['user_id' => $userId]);
    } else {
        $statement = $pdo->prepare(
            'SELECT success, TIMESTAMPDIFF(SECOND, attempted_at, NOW()) AS age_seconds
             FROM login_attempts
             WHERE user_id IS NULL AND LOWER(username_typed) = :identifier
             ORDER BY attempt_id DESC
             LIMIT 100'
        );
        $statement->execute(['identifier' => $normalizedIdentifier]);
    }

    $history = [];
    foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
        if ((int) $row['success'] === 1) {
            break;
        }

        $history[] = ['age_seconds' => max(0, (int) $row['age_seconds'])];
    }

    return $history;
}

function auth_lockout_state(array $failureHistory): array
{
    $failureCount = count($failureHistory);

    if ($failureCount < 3) {
        return ['failures' => $failureCount, 'seconds' => 0];
    }

    if ($failureCount >= 9) {
        $duration = 80;
        $thresholdIndex = 0;
    } elseif ($failureCount >= 6) {
        $duration = 40;
        $thresholdIndex = $failureCount - 6;
    } else {
        $duration = 20;
        $thresholdIndex = $failureCount - 3;
    }

    $thresholdAge = $failureHistory[$thresholdIndex]['age_seconds'] ?? $duration;

    return [
        'failures' => $failureCount,
        'seconds' => max(0, $duration - $thresholdAge)
    ];
}

function auth_ip_block_seconds(PDO $pdo, string $ipAddress): int
{
    $statement = $pdo->prepare(
        'SELECT GREATEST(0, TIMESTAMPDIFF(SECOND, NOW(), blocked_until)) AS seconds
         FROM ip_blocks
         WHERE ip_address = :ip_address AND blocked_until > NOW()
         LIMIT 1'
    );
    $statement->execute(['ip_address' => $ipAddress]);

    return max(0, (int) ($statement->fetchColumn() ?: 0));
}

function auth_find_user(PDO $pdo, string $identifier): ?array
{
    $statement = $pdo->prepare(
        'SELECT id_number, email, username, password_hash, role, approval_status, account_status
         FROM users
         WHERE username = :username OR email = :email
         LIMIT 2'
    );
    $statement->execute([
        'username' => $identifier,
        'email' => $identifier
    ]);
    $users = $statement->fetchAll(PDO::FETCH_ASSOC);

    return count($users) === 1 ? $users[0] : null;
}

function auth_clear_pending_otp(): void
{
    unset(
        $_SESSION['pending_login_user_id'],
        $_SESSION['pending_login_otp_id'],
        $_SESSION['pending_login_started_at'],
        $_SESSION['pending_login_identifier']
    );
}
