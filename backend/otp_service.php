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
    $configPath = getenv('ORG_FEE_MAIL_CONFIG');

    if ($configPath === false || $configPath === '') {
        $configPath = 'C:/xampp/org_fee_config.php';
    }

    if (is_file($configPath)) {
        $realConfigPath = realpath($configPath);
        $projectRoot = realpath(dirname(__DIR__));

        if (
            $realConfigPath !== false &&
            $projectRoot !== false &&
            strpos($realConfigPath, $projectRoot . DIRECTORY_SEPARATOR) === 0
        ) {
            throw new RuntimeException('Mail configuration must be outside the public project directory.');
        }

        $config = require $configPath;
        if (is_array($config)) {
            $settings = $config['mail'] ?? $config['smtp'] ?? [];
        }
    }

    $value = static function (string $environmentName, string $key, string $default = '') use ($settings): string {
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
    $fromAddress = $value('ORG_FEE_SMTP_FROM_ADDRESS', 'from_address', $username);
    $fromName = $value('ORG_FEE_SMTP_FROM_NAME', 'from_name', 'Student Organization Fee System');

    if (
        $username === '' ||
        $password === '' ||
        filter_var($fromAddress, FILTER_VALIDATE_EMAIL) === false ||
        !ctype_digit($port)
    ) {
        throw new RuntimeException(
            'SMTP is not configured. Set the ORG_FEE_SMTP_USERNAME, ORG_FEE_SMTP_PASSWORD, and ORG_FEE_SMTP_FROM_ADDRESS settings.'
        );
    }

    return [
        'host' => $host,
        'port' => (int) $port,
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
        dirname(__DIR__) . '/vendor/autoload.php',
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
    $mailer->Subject = 'Your login verification code';
    $mailer->Body = "Your login verification code is {$code}. It expires in 5 minutes.";

    try {
        $mailer->send();
    } catch (PHPMailerException $error) {
        error_log('Login OTP email delivery failed: ' . $error->getMessage());
        throw new RuntimeException('The verification email could not be sent.');
    }
}

function auth_issue_login_otp(PDO $pdo, string $userId, string $email, bool $isResend): array
{
    if ($isResend) {
        $pendingOtpId = $_SESSION['pending_login_otp_id'] ?? null;
        $pendingUserId = $_SESSION['pending_login_user_id'] ?? null;

        if (!is_string($pendingUserId) || !is_string($pendingOtpId) || $pendingUserId !== $userId) {
            throw new RuntimeException('The login verification session has expired.');
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
        $latestStatement->execute(['user_id' => $userId, 'purpose' => 'LOGIN']);
        $latest = $latestStatement->fetch(PDO::FETCH_ASSOC);

        $countStatement = $pdo->prepare(
            'SELECT COUNT(*)
             FROM user_otps
             WHERE user_id = :user_id
               AND purpose = :purpose
               AND created_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)'
        );
        $countStatement->execute(['user_id' => $userId, 'purpose' => 'LOGIN']);
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
            $oldestStatement->execute(['user_id' => $userId, 'purpose' => 'LOGIN']);

            throw new AuthOtpThrottleException(
                'The maximum number of verification codes has been reached. Try again later.',
                (int) $oldestStatement->fetchColumn(),
                0
            );
        }

        $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $hash = password_hash($code, PASSWORD_DEFAULT);

        if ($hash === false) {
            throw new RuntimeException('The verification code could not be secured.');
        }

        $insert = $pdo->prepare(
            'INSERT INTO user_otps (user_id, otp_hash, purpose, expires_at, attempts, resend_count)
             VALUES (:user_id, :otp_hash, :purpose, DATE_ADD(NOW(), INTERVAL 5 MINUTE), 0, :resend_count)'
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
