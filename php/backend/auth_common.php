<?php

require_once __DIR__ . '/db.php';

if (!isset($pdo) || !$pdo instanceof PDO) {
    throw new RuntimeException('The database connection is unavailable.');
}

// Seed 58: D1=5 and D2=8.
const AUTH_USERNAME_MIN_LENGTH = 8;
const AUTH_USERNAME_MAX_LENGTH = 19;
const AUTH_PASSWORD_MIN_LENGTH = 8;
const AUTH_NAME_MAX_LENGTH = 28;
const AUTH_FORGOT_PASSWORD_FAILURES = 3;
const AUTH_LOCKOUT_D1_SECONDS = 5;
const AUTH_LOCKOUT_TIER_1_SECONDS = 15 + AUTH_LOCKOUT_D1_SECONDS;
const AUTH_LOCKOUT_TIER_2_SECONDS = 30 + (2 * AUTH_LOCKOUT_D1_SECONDS);
const AUTH_LOCKOUT_TIER_3_SECONDS = 60 + (4 * AUTH_LOCKOUT_D1_SECONDS);
const AUTH_OTP_EXPIRY_MINUTES = 5;
// Session Timeout
const AUTH_IDLE_TIMEOUT_SECONDS = 10;
const AUTH_IP_BLOCK_THRESHOLD = 16;
const AUTH_IP_BLOCK_WINDOW_SECONDS = 600;
const AUTH_IP_BLOCK_SECONDS = 600;

function auth_start_session(): void
{
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');

    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_strict_mode', '1');

    $cookie = session_get_cookie_params();
    session_set_cookie_params([
        'lifetime' => $cookie['lifetime'],
        'path' => $cookie['path'],
        'domain' => $cookie['domain'],
        'secure' => !empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off',
        'httponly' => true,
        'samesite' => 'Lax'
    ]);

    session_start();

    $userId = $_SESSION['user_id'] ?? null;
    if (!is_string($userId) || $userId === '') {
        return;
    }

    $now = time();
    $lastActivity = $_SESSION['last_activity_at'] ?? $now;

    if (
        is_int($lastActivity) &&
        $now - $lastActivity >= AUTH_IDLE_TIMEOUT_SECONDS
    ) {
        try {
            auth_log_event(
                $GLOBALS['pdo'],
                'SESSION_IDLE_TIMEOUT',
                null,
                $userId,
                'The session ended after 10 seconds of inactivity.'
            );
        } catch (PDOException $error) {
            error_log('Unable to log idle session timeout: ' . $error->getMessage());
        }

        $_SESSION = [];
        session_regenerate_id(true);
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['login_error'] = 'Your session expired after 10 seconds of inactivity. Please sign in again.';
        return;
    }

    if (basename((string) ($_SERVER['SCRIPT_NAME'] ?? '')) !== 'admin_dashboard_api.php') {
        $_SESSION['last_activity_at'] = $now;
    }
}

function auth_redirect(string $location, int $status = 303): void
{
    header('Location: ' . $location, true, $status);
    exit;
}

function auth_session_timeout_markup(): string
{
    if (!isset($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return '<div id="sessionTimeoutWarning" role="alert" hidden '
        . 'style="position:fixed;right:16px;bottom:16px;z-index:9999;'
        . 'max-width:380px;padding:16px 18px;background:#fff;color:#173323;'
        . 'border:1px solid #d9e4d8;border-radius:12px;'
        . 'box-shadow:0 12px 30px rgba(13,31,22,.18);'
        . 'font-family:Poppins,Arial,sans-serif;">'
        . '<div style="font-size:.82rem;font-weight:600;line-height:1.55;">'
        . '<span>Your session will end in </span>'
        . '<strong id="sessionTimeoutCountdown" style="color:#1c4d2e;">5</strong>'
        . '<span> seconds due to inactivity.</span>'
        . '</div>'
        . '<button type="button" id="staySignedIn" '
        . 'style="display:inline-flex;align-items:center;justify-content:center;'
        . 'width:100%;min-height:43px;margin-top:12px;padding:0 18px;border:0;'
        . 'border-radius:10px;background:linear-gradient(90deg,#1d6c38,#2d8a4d);'
        . 'color:#fff;font-family:inherit;font-size:.88rem;font-weight:700;'
        . 'cursor:pointer;box-shadow:0 6px 16px rgba(28,77,46,.18);">'
        . 'Stay signed in'
        . '</button>'
        . '</div>'
        . '<script>'
        . '(function(){'
        . 'const warning=document.getElementById("sessionTimeoutWarning");'
        . 'const countdown=document.getElementById("sessionTimeoutCountdown");'
        . 'const stayButton=document.getElementById("staySignedIn");'
        . 'if(!warning||!countdown||!stayButton)return;'
        . 'const csrf=' . json_encode((string) ($_SESSION['csrf_token'] ?? '')) . ';'
        . 'const sessionTimeout=' . AUTH_IDLE_TIMEOUT_SECONDS . ';'
        . 'const warningSeconds=Math.min(5,sessionTimeout);'
        . 'let idleTimer;let warningTimer;let remaining=warningSeconds;let lastPing=0;'
        . 'function redirectToLogin(){window.location.assign("login.php");}'
        . 'function ping(force){'
        . 'if(!force&&Date.now()-lastPing<10000)return Promise.resolve();'
        . 'lastPing=Date.now();'
        . 'return fetch("backend/session_activity.php",{method:"POST",'
        . 'credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded"},'
        . 'body:new URLSearchParams({csrf_token:csrf})}).then(function(response){'
        . 'if(response.status===401){redirectToLogin();return;}'
        . 'if(response.status===403){window.location.reload();return;}'
        . 'if(!response.ok)throw new Error("Session could not be renewed.");'
        . '}).catch(function(error){console.error(error.message);});'
        . '}'
        . 'function resetTimer(){'
        . 'window.clearTimeout(idleTimer);window.clearInterval(warningTimer);'
        . 'warning.hidden=true;remaining=warningSeconds;countdown.textContent=String(remaining);'
        . 'idleTimer=window.setTimeout(showWarning,'
        . 'Math.max(0,(sessionTimeout-warningSeconds))*1000);'
        . '}'
        . 'function showWarning(){'
        . 'warning.hidden=false;remaining=warningSeconds;countdown.textContent=String(remaining);'
        . 'warningTimer=window.setInterval(function(){'
        . 'remaining--;countdown.textContent=String(remaining);'
        . 'if(remaining<=0){window.clearInterval(warningTimer);redirectToLogin();}'
        . '},1000);'
        . '}'
        . 'function registerActivity(){resetTimer();ping(true);}'
        . '["pointerdown","keydown","scroll","touchstart"].forEach(function(eventName){'
        . 'document.addEventListener(eventName,registerActivity,{passive:true});'
        . '});'
        . 'stayButton.addEventListener("click",registerActivity);'
        . 'resetTimer();'
        . '})();'
        . '</script>';
}

function auth_csrf_is_valid(): bool
{
    $provided = $_POST['csrf_token'] ?? null;
    $expected = $_SESSION['csrf_token'] ?? null;

    $isValid = is_string($provided)
        && is_string($expected)
        && hash_equals($expected, $provided);

    if (!$isValid) {
        $identifier = $_POST['username'] ?? $_SESSION['pending_login_identifier'] ?? null;
        $userId = $_SESSION['user_id'] ?? $_SESSION['pending_login_user_id'] ?? null;

        try {
            auth_log_event(
                $GLOBALS['pdo'],
                'CSRF_REJECTED',
                is_string($identifier) ? substr($identifier, 0, 100) : null,
                is_string($userId) ? $userId : null,
                'A submitted form did not contain a valid CSRF token.'
            );
        } catch (PDOException $error) {
            error_log('Unable to log rejected CSRF request: ' . $error->getMessage());
        }
    }

    return $isValid;
}

function auth_flash_login(
    string $message,
    ?int $failures = null,
    int $lockoutSeconds = 0,
    ?string $identifier = null,
    bool $failedCredentials = false,
    ?string $attemptKey = null
): void {
    $_SESSION['login_error'] = $message;

    if ($failures !== null) {
        $_SESSION['login_failed_attempts'] = max(0, $failures);
    }

    if ($identifier !== null) {
        $previousAttemptKey = $_SESSION['login_forgot_attempt_key'] ?? null;
        $currentAttemptKey = $attemptKey ?? 'identifier:' . strtolower(trim($identifier));
        $previousIdentifier = $_SESSION['login_forgot_identifier'] ?? null;
        $sameIdentifier = is_string($previousAttemptKey)
            ? hash_equals($previousAttemptKey, $currentAttemptKey)
            : (is_string($previousIdentifier)
                && strtolower(trim($previousIdentifier)) === strtolower(trim($identifier)));

        if (!$sameIdentifier) {
            $_SESSION['login_forgot_session_attempts'] = 0;
        }

        $_SESSION['login_forgot_attempt_key'] = $currentAttemptKey;
        $_SESSION['login_forgot_identifier'] = substr($identifier, 0, 100);

        if ($failedCredentials) {
            $_SESSION['login_forgot_session_attempts'] =
                (int) ($_SESSION['login_forgot_session_attempts'] ?? 0) + 1;
            $_SESSION['login_forgot_last_attempt_at'] = time();
        }
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

function auth_failure_history(
    PDO $pdo,
    ?string $userId,
    string $normalizedIdentifier
): array {
    if ($userId !== null) {
        $statement = $pdo->prepare(
            'SELECT success,
                    TIMESTAMPDIFF(SECOND, attempted_at, NOW()) AS age_seconds
             FROM login_attempts
             WHERE user_id = :user_id
               AND attempted_at >= DATE_SUB(NOW(), INTERVAL '
            . intdiv(AUTH_IP_BLOCK_WINDOW_SECONDS, 60) . ' MINUTE)
             ORDER BY attempt_id DESC
             LIMIT 100'
        );

        $statement->execute(['user_id' => $userId]);
    } else {
        $statement = $pdo->prepare(
            'SELECT success,
                    TIMESTAMPDIFF(SECOND, attempted_at, NOW()) AS age_seconds
             FROM login_attempts
             WHERE user_id IS NULL
               AND LOWER(TRIM(username_typed)) = :identifier
               AND attempted_at >= DATE_SUB(NOW(), INTERVAL '
            . intdiv(AUTH_IP_BLOCK_WINDOW_SECONDS, 60) . ' MINUTE)
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

        $history[] = [
            'age_seconds' => max(0, (int) $row['age_seconds'])
        ];
    }

    return $history;
}

function auth_lockout_state(array $failureHistory): array
{
    $failureCount = count($failureHistory);

    // Lockout begins after three consecutive failures.
    if ($failureCount < 3) {
        return [
            'failures' => $failureCount,
            'seconds' => 0
        ];
    }

    if ($failureCount >= 9) {
        $duration = AUTH_LOCKOUT_TIER_3_SECONDS;
        $thresholdIndex = 0;
    } elseif ($failureCount >= 6) {
        $duration = AUTH_LOCKOUT_TIER_2_SECONDS;
        $thresholdIndex = $failureCount - 6;
    } else {
        $duration = AUTH_LOCKOUT_TIER_1_SECONDS;
        $thresholdIndex = $failureCount - 3;
    }

    // Get the age of the failure that triggered the lockout.
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
         WHERE ip_address = :ip_address
           AND blocked_until > NOW()
         LIMIT 1'
    );

    $statement->execute(['ip_address' => $ipAddress]);

    return max(0, (int) ($statement->fetchColumn() ?: 0));
}

function auth_ip_failure_count(PDO $pdo, string $ipAddress): int
{
    $statement = $pdo->prepare(
        'SELECT COUNT(*)
         FROM login_attempts
         WHERE ip_address = :ip_address
           AND success = 0
           AND attempted_at >= DATE_SUB(NOW(), INTERVAL '
            . intdiv(AUTH_IP_BLOCK_WINDOW_SECONDS, 60) . ' MINUTE)'
    );

    $statement->execute(['ip_address' => $ipAddress]);

    return (int) $statement->fetchColumn();
}

function auth_block_ip(PDO $pdo, string $ipAddress): void
{
    $statement = $pdo->prepare(
        'INSERT INTO ip_blocks (ip_address, reason, blocked_until)
         VALUES (:ip_address, :reason, DATE_ADD(NOW(), INTERVAL '
         . AUTH_IP_BLOCK_SECONDS . ' SECOND))
         ON DUPLICATE KEY UPDATE
            reason = VALUES(reason),
            blocked_until = GREATEST(blocked_until, VALUES(blocked_until))'
    );

    $statement->execute([
        'ip_address' => $ipAddress,
        'reason' => 'At least 16 failed sign-in attempts within 10 minutes.'
    ]);
}

function auth_find_user(PDO $pdo, string $identifier): ?array
{
    $statement = $pdo->prepare(
        'SELECT id_number, email, username, password_hash, role,
                approval_status, account_status, email_verified_at
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

/*
|--------------------------------------------------------------------------
| RECORD SYSTEM ACTIVITY
|--------------------------------------------------------------------------
*/

function auth_log_event(
    PDO $pdo,
    string $eventType,
    ?string $username = null,
    ?string $userId = null,
    string $details = ''
): void {
    // Get the visitor's IP address.
    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';

    // Get the browser information.
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN';

    // Save the activity into the database.
    $statement = $pdo->prepare(
        'INSERT INTO activity_logs
        (event_type, username_typed, user_id, ip_address, user_agent, details)
        VALUES
        (:event_type, :username_typed, :user_id, :ip_address, :user_agent, :details)'
    );

    $statement->execute([
        'event_type' => $eventType,
        'username_typed' => $username ?? 'UNKNOWN',
        'user_id' => $userId,
        'ip_address' => $ipAddress,
        'user_agent' => $userAgent,
        'details' => $details
    ]);
}
