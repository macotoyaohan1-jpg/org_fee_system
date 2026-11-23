<?php

require_once __DIR__ . '/auth_common.php';

use PHPMailer\PHPMailer\Exception as PHPMailerException;
use PHPMailer\PHPMailer\PHPMailer;

class AuthOtpThrottleException extends RuntimeException
{
    public $retryAfter;
    public $resendsRemaining;

    public function __construct(string $message, int $retryAfter, int $resendsRemaining)
    {
        parent::__construct($message);
        $this->retryAfter = max(0, $retryAfter);
        $this->resendsRemaining = max(0, $resendsRemaining);
    }
}


function auth_mail_settings(): array
{
    $settings = [];

    // Support both environment variable names.
    $configPath = getenv('ORG_FEE_MAIL_CONFIG');

    if ($configPath === false || $configPath === '') {
        $configPath = getenv('ORG_FEE_CONFIG');
    }

    // Default location if no environment variable is configured.
    if ($configPath === false || $configPath === '') {
        $configPath = 'C:/xampp/org_fee_config.php';
    }

    if (!is_file($configPath)) {
        throw new RuntimeException(
            'SMTP configuration file was not found: ' . $configPath
        );
    }

    $realConfigPath = realpath($configPath);
    $projectRoot = realpath(dirname(__DIR__, 2));

    if (
        $realConfigPath === false ||
        $projectRoot === false ||
        strpos($realConfigPath, $projectRoot . DIRECTORY_SEPARATOR) === 0
    ) {
        throw new RuntimeException(
            'Mail configuration must be outside the public project directory.'
        );
    }

    $config = require $realConfigPath;

    if (!is_array($config)) {
        throw new RuntimeException('SMTP configuration is invalid.');
    }

    $settings = $config['mail'] ?? $config['smtp'] ?? [];

    $value = static function (
        string $environmentName,
        string $key,
        string $default = ''
    ) use ($settings): string {
        $environmentValue = getenv($environmentName);

        if ($environmentValue !== false && $environmentValue !== '') {
            return $environmentValue;
        }

        $configuredValue = $settings[$key] ?? null;

        return is_string($configuredValue) && $configuredValue !== ''
            ? $configuredValue
            : $default;
    };

    $host = $value('ORG_FEE_SMTP_HOST', 'host', 'smtp.gmail.com');
    $port = $value('ORG_FEE_SMTP_PORT', 'port', '587');
    $username = $value('ORG_FEE_SMTP_USERNAME', 'username');
    $password = $value('ORG_FEE_SMTP_PASSWORD', 'password');

    // Google displays App Passwords in four-character groups. Remove those
    // formatting spaces so SMTP receives the actual 16-character credential.
    if (strtolower(rtrim($host, '.')) === 'smtp.gmail.com') {
        $password = preg_replace('/\s+/', '', $password) ?? $password;
    }

    // Support both from_address and the existing from_email setting.
    $configuredFrom = $settings['from_address']
        ?? $settings['from_email']
        ?? $username;

    $fromAddress = $value(
        'ORG_FEE_SMTP_FROM_ADDRESS',
        'from_address',
        is_string($configuredFrom) ? $configuredFrom : $username
    );

    $fromName = $value(
        'ORG_FEE_SMTP_FROM_NAME',
        'from_name',
        'Student Organization Fee Tracking'
    );

    $numericPort = ctype_digit($port) ? (int) $port : 0;

    if (
        $host === '' ||
        $username === '' ||
        $password === '' ||
        filter_var($fromAddress, FILTER_VALIDATE_EMAIL) === false ||
        $numericPort < 1 ||
        $numericPort > 65535
    ) {
        throw new RuntimeException(
            'SMTP is not configured correctly. Check your SMTP credentials and sender email.'
        );
    }

    return [
        'host' => $host,
        'port' => $numericPort,
        'username' => $username,
        'password' => $password,
        'from_address' => $fromAddress,
        'from_name' => $fromName
    ];
}


function auth_load_phpmailer(): void
{
    $autoloadPath = getenv('ORG_FEE_PHPMAILER_AUTOLOAD');

    $paths = [
        $autoloadPath === false ? '' : $autoloadPath,
        dirname(__DIR__, 2) . '/vendor/autoload.php',
        'C:/xampp/htdocs/Organization_Fee_System/vendor/autoload.php'
    ];

    foreach (array_unique(array_filter($paths)) as $path) {
        if (is_file($path)) {
            require_once $path;

            if (class_exists(PHPMailer::class)) {
                return;
            }
        }
    }

    throw new RuntimeException(
        'PHPMailer is unavailable. Set ORG_FEE_PHPMAILER_AUTOLOAD to its Composer autoloader.'
    );
}


/*
|--------------------------------------------------------------------------
| SEND LOGIN OTP EMAIL
|--------------------------------------------------------------------------
*/

function auth_send_login_otp_email(string $email, string $code): void
{
    auth_load_phpmailer();
    $settings = auth_mail_settings();

    if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        throw new RuntimeException('The account email address is invalid.');
    }

    $mailer = new PHPMailer(true);
    $mailer->isSMTP();
    $mailer->Host = $settings['host'];
    $mailer->SMTPAuth = true;
    $mailer->Username = $settings['username'];
    $mailer->Password = $settings['password'];
    $mailer->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mailer->Port = $settings['port'];
    $mailer->CharSet = 'UTF-8';
    $mailer->setFrom($settings['from_address'], $settings['from_name']);
    $mailer->addAddress($email);
    $mailer->Subject = 'Student Organization Fee System login code';
    $mailer->Body =
        "Student Organization Fee System: Your login code is {$code}. "
        . 'It expires in ' . AUTH_OTP_EXPIRY_MINUTES
        . ' minutes. If you did not request this code, ignore this email and consider changing your password.';

    // Log server replies only. Do not log client commands or credentials.
    $mailer->SMTPDebug = \PHPMailer\PHPMailer\SMTP::DEBUG_SERVER;

    $mailer->Debugoutput = static function ($message, $level) {
        error_log('LOGIN OTP SMTP SERVER: ' . trim($message));
    };

    try {
        $mailer->send();
    } catch (PHPMailerException $error) {

        // Get the detailed SMTP error without exposing login credentials.
        $smtp = $mailer->getSMTPInstance();

        $smtpError = $smtp->getError();
        $lastReply = $smtp->getLastReply();

        // Keep only the SMTP response code and message.
        $smtpCode = $smtpError['smtp_code'] ?? 'Unknown';
        $smtpMessage = $smtpError['smtp_msg'] ?? '';

        error_log(
            'LOGIN OTP SMTP DIAGNOSTIC: ' .
            'Code=' . $smtpCode .
            ' | Message=' . $smtpMessage .
            ' | Last Reply=' . trim($lastReply)
        );

        error_log(
            'Login OTP email delivery failed: ' . $error->getMessage()
        );

        throw new RuntimeException('The verification email could not be sent.');
    }
}


/*
|--------------------------------------------------------------------------
| SEND REGISTRATION OTP EMAIL
|--------------------------------------------------------------------------
*/

function auth_send_registration_otp_email(string $email, string $code): void
{
    auth_load_phpmailer();
    $settings = auth_mail_settings();

    if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        throw new RuntimeException('The account email address is invalid.');
    }

    $mailer = new PHPMailer(true);
    $mailer->isSMTP();
    $mailer->Host = $settings['host'];
    $mailer->SMTPAuth = true;
    $mailer->Username = $settings['username'];
    $mailer->Password = $settings['password'];
    $mailer->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mailer->Port = $settings['port'];
    $mailer->CharSet = 'UTF-8';
    $mailer->setFrom($settings['from_address'], $settings['from_name']);
    $mailer->addAddress($email);
    $mailer->Subject = 'Student Organization Fee System account verification';
    $mailer->Body =
        "Student Organization Fee System: Your account verification code is {$code}. "
        . 'It expires in ' . AUTH_OTP_EXPIRY_MINUTES
        . ' minutes. If you did not request this code, ignore this email and consider changing your password.';

    try {
        $mailer->send();
    } catch (PHPMailerException $error) {
        error_log('Registration OTP email delivery failed: ' . $error->getMessage());
        throw new RuntimeException('The registration verification email could not be sent.');
    }
}


/*
|--------------------------------------------------------------------------
| SEND ADMIN PASSWORD RESET OTP
|--------------------------------------------------------------------------
*/


function auth_send_password_reset_otp_email(string $email, string $code): void
{
    auth_load_phpmailer();
    $settings = auth_mail_settings();

    if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        throw new RuntimeException('The account email address is invalid.');
    }

    $mailer = new PHPMailer(true);
    $mailer->isSMTP();
    $mailer->Host = $settings['host'];
    $mailer->SMTPAuth = true;
    $mailer->Username = $settings['username'];
    $mailer->Password = $settings['password'];
    $mailer->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mailer->Port = $settings['port'];
    $mailer->CharSet = 'UTF-8';
    $mailer->setFrom($settings['from_address'], $settings['from_name']);
    $mailer->addAddress($email);

    $mailer->Subject = 'Student Organization Fee System password reset code';
    $mailer->Body =
        "Student Organization Fee System: Your password reset code is {$code}. "
        . 'It expires in ' . AUTH_OTP_EXPIRY_MINUTES
        . ' minutes. If you did not request this code, ignore this email and consider changing your password.';

    try {
        $mailer->send();
    } catch (PHPMailerException $error) {
        error_log('Account password reset email delivery failed: ' . $error->getMessage());
        throw new RuntimeException('The password reset email could not be sent.');
    }
}

function auth_send_security_alert_email(
    string $email,
    string $subject,
    string $body
): void {
    auth_load_phpmailer();
    $settings = auth_mail_settings();

    if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        throw new RuntimeException('The account email address is invalid.');
    }

    $mailer = new PHPMailer(true);
    $mailer->isSMTP();
    $mailer->Host = $settings['host'];
    $mailer->SMTPAuth = true;
    $mailer->Username = $settings['username'];
    $mailer->Password = $settings['password'];
    $mailer->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mailer->Port = $settings['port'];
    $mailer->CharSet = 'UTF-8';
    $mailer->setFrom($settings['from_address'], $settings['from_name']);
    $mailer->addAddress($email);
    $mailer->Subject = $subject;
    $mailer->Body = $body;

    try {
        $mailer->send();
    } catch (PHPMailerException $error) {
        error_log('Security alert email delivery failed: ' . $error->getMessage());
        throw new RuntimeException('The security alert email could not be sent.');
    }
}

function auth_send_lockout_alert_email(
    string $email,
    int $attempts,
    string $ipAddress,
    string $userAgent,
    int $tier
): void {
    $eventTime = new DateTimeImmutable('now', new DateTimeZone('Asia/Manila'));
    $baseUrl = getenv('ORG_FEE_BASE_URL');
    if ($baseUrl === false || trim($baseUrl) === '') {
        $baseUrl = 'http://localhost/org_fee_system';
    }

    $body = "Student Organization Fee System detected repeated failed sign-in attempts.\n\n"
        . 'Lockout tier: ' . $tier . "\n"
        . 'Failed attempts: ' . $attempts . "\n"
        . 'Date and time (Philippine time): ' . $eventTime->format('Y-m-d H:i:s') . "\n"
        . 'IP address: ' . $ipAddress . "\n"
        . 'Browser or device: ' . $userAgent . "\n\n"
        . 'If this was not you, reset your password now: '
        . rtrim($baseUrl, '/') . '/forgot_password.php';

    auth_send_security_alert_email(
        $email,
        'Failed sign-in attempts on your account',
        $body
    );
}

function auth_send_password_changed_email(
    string $email,
    string $ipAddress,
    string $userAgent
): void {
    $eventTime = new DateTimeImmutable('now', new DateTimeZone('Asia/Manila'));
    $baseUrl = getenv('ORG_FEE_BASE_URL');
    if ($baseUrl === false || trim($baseUrl) === '') {
        $baseUrl = 'http://localhost/org_fee_system';
    }

    $body = "Your Student Organization Fee System password was changed.\n\n"
        . 'Date and time (Philippine time): ' . $eventTime->format('Y-m-d H:i:s') . "\n"
        . 'IP address: ' . $ipAddress . "\n"
        . 'Browser or device: ' . $userAgent . "\n\n"
        . 'If this was not you, reset your password now: '
        . rtrim($baseUrl, '/') . '/forgot_password.php';

    auth_send_security_alert_email(
        $email,
        'Your password was changed',
        $body
    );
}


/*
|--------------------------------------------------------------------------
| ISSUE LOGIN OTP
|--------------------------------------------------------------------------
*/

function auth_issue_login_otp(PDO $pdo, string $userId, string $email, bool $isResend): array
{
    if ($isResend) {
        $pendingUserId = $_SESSION['pending_login_user_id'] ?? null;

        if (
            !is_string($pendingUserId) ||
            $pendingUserId !== $userId
        ) {
            throw new RuntimeException(
                'The login verification session has expired.'
            );
        }
    }

    $pdo->beginTransaction();

    try {
        $userLock = $pdo->prepare(
            'SELECT id_number FROM users WHERE id_number = :user_id FOR UPDATE'
        );

        $userLock->execute(['user_id' => $userId]);

        if ($userLock->fetchColumn() === false) {
            throw new RuntimeException('The account could not be found.');
        }

        $latestStatement = $pdo->prepare(
            'SELECT otp_id, TIMESTAMPDIFF(SECOND, created_at, NOW()) AS age_seconds
             FROM user_otps
             WHERE user_id = :user_id AND purpose = :purpose
             ORDER BY otp_id DESC
             LIMIT 1'
        );

        $latestStatement->execute([
            'user_id' => $userId,
            'purpose' => 'LOGIN'
        ]);

        $latest = $latestStatement->fetch(PDO::FETCH_ASSOC);

        $countStatement = $pdo->prepare(
            'SELECT COUNT(*)
             FROM user_otps
             WHERE user_id = :user_id
               AND purpose = :purpose
               AND created_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)'
        );

        $countStatement->execute([
            'user_id' => $userId,
            'purpose' => 'LOGIN'
        ]);

        $recentSends = (int) $countStatement->fetchColumn();

        $cooldownRemaining = $latest
            ? max(0, 60 - (int) $latest['age_seconds'])
            : 0;

        if ($cooldownRemaining > 0) {
            throw new AuthOtpThrottleException(
                'Please wait before requesting another code.',
                $cooldownRemaining,
                max(0, 3 - max(0, $recentSends - 1))
            );
        }

        if ($recentSends >= 4) {
            $oldestStatement = $pdo->prepare(
                'SELECT GREATEST(
                    1,
                    900 - TIMESTAMPDIFF(SECOND, MIN(created_at), NOW())
                 )
                 FROM user_otps
                 WHERE user_id = :user_id
                   AND purpose = :purpose
                   AND created_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)'
            );

            $oldestStatement->execute([
                'user_id' => $userId,
                'purpose' => 'LOGIN'
            ]);

            throw new AuthOtpThrottleException(
                'The maximum number of verification codes has been reached. Try again later.',
                (int) $oldestStatement->fetchColumn(),
                0
            );
        }

        $code = str_pad(
            (string) random_int(0, 999999),
            6,
            '0',
            STR_PAD_LEFT
        );

        $hash = password_hash($code, PASSWORD_DEFAULT);

        if ($hash === false) {
            throw new RuntimeException('The verification code could not be secured.');
        }

        $insert = $pdo->prepare(
            'INSERT INTO user_otps
                (user_id, otp_hash, purpose, expires_at, attempts, resend_count)
             VALUES
                (:user_id, :otp_hash, :purpose, DATE_ADD(NOW(), INTERVAL '
                . AUTH_OTP_EXPIRY_MINUTES . ' MINUTE), 0, :resend_count)'
        );

        $insert->execute([
            'user_id' => $userId,
            'otp_hash' => $hash,
            'purpose' => 'LOGIN',
            'resend_count' => $recentSends
        ]);

        $otpId = (string) $pdo->lastInsertId();

        auth_send_login_otp_email($email, $code);

        $invalidate = $pdo->prepare(
            'UPDATE user_otps
             SET used_at = NOW()
             WHERE user_id = :user_id
               AND purpose = :purpose
               AND used_at IS NULL
               AND otp_id <> :otp_id'
        );

        $invalidate->execute([
            'user_id' => $userId,
            'purpose' => 'LOGIN',
            'otp_id' => $otpId
        ]);

        $pdo->commit();

        return [
            'otp_id' => $otpId,
            'resends_remaining' => max(0, 3 - $recentSends)
        ];

    } catch (PDOException $error) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        throw $error;

    } catch (RuntimeException $error) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        throw $error;
    }
}


/*
|--------------------------------------------------------------------------
| ISSUE REGISTRATION OTP
|--------------------------------------------------------------------------
*/


function auth_issue_registration_otp(
    PDO $pdo,
    string $userId,
    string $email,
    bool $isResend = false,
    bool $manageTransaction = true
): array {
    // Check the pending registration session before resending.
    if ($isResend) {
        $pendingUserId = $_SESSION['pending_registration_user_id'] ?? null;

        if (
            !is_string($pendingUserId) ||
            $pendingUserId !== $userId
        ) {
            throw new RuntimeException(
                'The registration verification session has expired.'
            );
        }
    }

    if ($manageTransaction) {
        $pdo->beginTransaction();
    } elseif (!$pdo->inTransaction()) {
        throw new RuntimeException(
            'A database transaction is required to issue the registration code.'
        );
    }

    try {
        // Lock the account while issuing its verification code.
        $userLock = $pdo->prepare(
            'SELECT email_verified_at
             FROM users
             WHERE id_number = :user_id
             FOR UPDATE'
        );

        $userLock->execute(['user_id' => $userId]);
        $emailVerified = $userLock->fetchColumn();

        if ($emailVerified === false) {
            throw new RuntimeException('The account could not be found.');
        }

        if ($emailVerified !== null) {
            throw new RuntimeException('This email address is already verified.');
        }

        // Get the latest registration OTP.
        $latestStatement = $pdo->prepare(
            'SELECT otp_id,
                    TIMESTAMPDIFF(SECOND, created_at, NOW()) AS age_seconds
             FROM user_otps
             WHERE user_id = :user_id
               AND purpose = :purpose
             ORDER BY otp_id DESC
             LIMIT 1'
        );

        $latestStatement->execute([
            'user_id' => $userId,
            'purpose' => 'REGISTRATION'
        ]);

        $latest = $latestStatement->fetch(PDO::FETCH_ASSOC);

        // Count registration OTP emails sent within 15 minutes.
        $countStatement = $pdo->prepare(
            'SELECT COUNT(*)
             FROM user_otps
             WHERE user_id = :user_id
               AND purpose = :purpose
               AND created_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)'
        );

        $countStatement->execute([
            'user_id' => $userId,
            'purpose' => 'REGISTRATION'
        ]);

        $recentSends = (int) $countStatement->fetchColumn();

        // Enforce the 60-second resend cooldown.
        $cooldownRemaining = $latest
            ? max(0, 60 - (int) $latest['age_seconds'])
            : 0;

        if ($cooldownRemaining > 0) {
            throw new AuthOtpThrottleException(
                'Please wait before requesting another code.',
                $cooldownRemaining,
                max(0, 3 - max(0, $recentSends - 1))
            );
        }

        // Allow one original code and three resends.
        if ($recentSends >= 4) {
            $oldestStatement = $pdo->prepare(
                'SELECT GREATEST(
                    1,
                    900 - TIMESTAMPDIFF(SECOND, MIN(created_at), NOW())
                 )
                 FROM user_otps
                 WHERE user_id = :user_id
                   AND purpose = :purpose
                   AND created_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)'
            );

            $oldestStatement->execute([
                'user_id' => $userId,
                'purpose' => 'REGISTRATION'
            ]);

            throw new AuthOtpThrottleException(
                'The maximum number of verification codes has been reached. Try again later.',
                (int) $oldestStatement->fetchColumn(),
                0
            );
        }

        // Generate a secure six-digit code.
        $code = str_pad(
            (string) random_int(0, 999999),
            6,
            '0',
            STR_PAD_LEFT
        );

        $hash = password_hash($code, PASSWORD_DEFAULT);

        if ($hash === false) {
            throw new RuntimeException(
                'The verification code could not be secured.'
            );
        }

        // Store only the hashed OTP.
        $insert = $pdo->prepare(
            'INSERT INTO user_otps
                (user_id, otp_hash, purpose, expires_at, attempts, resend_count)
             VALUES
                (:user_id, :otp_hash, :purpose,
                 DATE_ADD(NOW(), INTERVAL '
                . AUTH_OTP_EXPIRY_MINUTES . ' MINUTE), 0, :resend_count)'
        );

        $insert->execute([
            'user_id' => $userId,
            'otp_hash' => $hash,
            'purpose' => 'REGISTRATION',
            'resend_count' => $recentSends
        ]);

        $otpId = (string) $pdo->lastInsertId();

        // Send the registration verification email.
        auth_send_registration_otp_email($email, $code);

        // Invalidate previous unused registration codes.
        $invalidate = $pdo->prepare(
            'UPDATE user_otps
             SET used_at = NOW()
             WHERE user_id = :user_id
               AND purpose = :purpose
               AND used_at IS NULL
               AND otp_id <> :otp_id'
        );

        $invalidate->execute([
            'user_id' => $userId,
            'purpose' => 'REGISTRATION',
            'otp_id' => $otpId
        ]);

        if ($manageTransaction) {
            $pdo->commit();
        }

        return [
            'otp_id' => $otpId,
            'resends_remaining' => max(0, 3 - $recentSends)
        ];

    } catch (Throwable $error) {
        if ($manageTransaction && $pdo->inTransaction()) {
            $pdo->rollBack();
        }

        throw $error;
    }
}
