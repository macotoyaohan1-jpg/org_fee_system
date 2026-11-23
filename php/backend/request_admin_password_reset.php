<?php

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Use the password recovery form.');
}

require_once __DIR__ . '/otp_service.php';
auth_start_session();

function password_reset_request_redirect(): void
{
    auth_redirect('../forgot_password.php');
}

function password_reset_record_failed_answer(PDO $pdo, string $username, ?string $userId): array
{
    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '';
    if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
        $ipAddress = '0.0.0.0';
    }

    auth_record_login_attempt($pdo, $userId, $username, $ipAddress, false);
    auth_log_event(
        $pdo,
        'PASSWORD_RESET_ANSWER_FAILED',
        $username,
        $userId,
        'A password recovery security answer was incorrect.'
    );

    $normalizedUsername = strtolower($username);
    $state = auth_lockout_state(
        auth_failure_history($pdo, $userId, $normalizedUsername)
    );

    if (in_array($state['failures'], [3, 6, 9], true)) {
        $tier = (int) ($state['failures'] / 3);
        auth_log_event(
            $pdo,
            'LOCKOUT_TIER_' . $tier,
            $username,
            $userId,
            'The account reached lockout tier ' . $tier . ' during password recovery.'
        );

        if ($userId !== null) {
            $emailQuery = $pdo->prepare(
                'SELECT email FROM users WHERE id_number = :user_id LIMIT 1'
            );
            $emailQuery->execute(['user_id' => $userId]);
            $email = $emailQuery->fetchColumn();

            if (is_string($email) && filter_var($email, FILTER_VALIDATE_EMAIL)) {
                try {
                    auth_send_lockout_alert_email(
                        $email,
                        $state['failures'],
                        $ipAddress,
                        (string) ($_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN'),
                        $tier
                    );
                    auth_log_event(
                        $pdo,
                        'ALERT_EMAIL_SENT',
                        $username,
                        $userId,
                        'A lockout tier ' . $tier . ' alert was emailed.'
                    );
                } catch (PDOException $error) {
                    error_log('Unable to log recovery lockout alert: ' . $error->getMessage());
                } catch (RuntimeException $error) {
                    error_log('Unable to send recovery lockout alert: ' . $error->getMessage());
                    auth_log_event(
                        $pdo,
                        'ALERT_EMAIL_FAILED',
                        $username,
                        $userId,
                        'Password recovery lockout alert delivery failed.'
                    );
                }
            }
        }
    }

    if (auth_ip_failure_count($pdo, $ipAddress) >= AUTH_IP_BLOCK_THRESHOLD) {
        auth_block_ip($pdo, $ipAddress);
        auth_log_event(
            $pdo,
            'IP_BLOCKED',
            $username,
            $userId,
            'The IP address reached the seeded failed-attempt threshold.'
        );
    }

    return $state;
}

function password_reset_send_code(PDO $pdo, string $userId): string
{
    $pdo->beginTransaction();

    try {
        $userQuery = $pdo->prepare(
            "SELECT email FROM users
             WHERE id_number = :user_id
               AND role IN ('ADMIN', 'TREASURER')
               AND account_status = 'ACTIVE'
               AND email_verified_at IS NOT NULL
             FOR UPDATE"
        );
        $userQuery->execute(['user_id' => $userId]);
        $email = $userQuery->fetchColumn();

        if (!is_string($email) || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw new RuntimeException('The recovery request could not be completed.');
        }

        $latestQuery = $pdo->prepare(
            'SELECT TIMESTAMPDIFF(SECOND, created_at, NOW())
             FROM user_otps
             WHERE user_id = :user_id AND purpose = :purpose
             ORDER BY otp_id DESC
             LIMIT 1'
        );
        $latestQuery->execute([
            'user_id' => $userId,
            'purpose' => 'PASSWORD_RESET'
        ]);
        $latestAge = $latestQuery->fetchColumn();

        $countQuery = $pdo->prepare(
            'SELECT COUNT(*)
             FROM user_otps
             WHERE user_id = :user_id
               AND purpose = :purpose
               AND created_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)'
        );
        $countQuery->execute([
            'user_id' => $userId,
            'purpose' => 'PASSWORD_RESET'
        ]);
        $recentCount = (int) $countQuery->fetchColumn();

        if ($latestAge !== false && (int) $latestAge < 60) {
            throw new AuthOtpThrottleException(
                'Please wait before requesting another recovery code.',
                60 - (int) $latestAge,
                max(0, 3 - max(0, $recentCount - 1))
            );
        }

        if ($recentCount >= 4) {
            $oldestQuery = $pdo->prepare(
                'SELECT GREATEST(
                    1,
                    900 - TIMESTAMPDIFF(SECOND, MIN(created_at), NOW())
                 )
                 FROM user_otps
                 WHERE user_id = :user_id
                   AND purpose = :purpose
                   AND created_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)'
            );
            $oldestQuery->execute([
                'user_id' => $userId,
                'purpose' => 'PASSWORD_RESET'
            ]);
            throw new AuthOtpThrottleException(
                'The maximum number of recovery codes has been reached. Try again later.',
                (int) $oldestQuery->fetchColumn(),
                0
            );
        }

        $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $hash = password_hash($code, PASSWORD_DEFAULT);

        if (!is_string($hash)) {
            throw new RuntimeException('Could not create the recovery code.');
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
            'purpose' => 'PASSWORD_RESET',
            'resend_count' => $recentCount
        ]);
        $otpId = (string) $pdo->lastInsertId();

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
            'purpose' => 'PASSWORD_RESET',
            'otp_id' => $otpId
        ]);

        $pdo->commit();
    } catch (Throwable $error) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $error;
    }

    try {
        auth_send_password_reset_otp_email($email, $code);
    } catch (RuntimeException $error) {
        $invalidateCode = $pdo->prepare(
            'UPDATE user_otps SET used_at = NOW()
             WHERE otp_id = :otp_id AND user_id = :user_id'
        );
        $invalidateCode->execute([
            'otp_id' => $otpId,
            'user_id' => $userId
        ]);
        auth_log_event(
            $pdo,
            'OTP_EMAIL_FAILED',
            null,
            $userId,
            'Password recovery code delivery failed.'
        );
        throw $error;
    }

    $_SESSION['pending_password_reset_user_id'] = $userId;
    $_SESSION['pending_password_reset_otp_id'] = $otpId;
    $_SESSION['pending_password_reset_email'] = $email;
    $_SESSION['password_reset_otp_stage'] = true;
    $_SESSION['password_reset_verified'] = false;
    $_SESSION['password_reset_resends_remaining'] = max(0, 3 - $recentCount);
    $_SESSION['password_reset_resend_seconds'] = 60;

    auth_log_event(
        $pdo,
        'OTP_SENT',
        null,
        $userId,
        'Password recovery verification code sent.'
    );

    return $otpId;
}

if (!auth_csrf_is_valid()) {
    $_SESSION['password_reset_error'] = 'The form expired. Refresh the page and try again.';
    password_reset_request_redirect();
}

$action = $_POST['action'] ?? '';
$username = $_SESSION['pending_password_reset_username'] ?? '';
$userId = $_SESSION['pending_password_reset_user_id'] ?? null;

if ($action === '' && ($_POST['resend'] ?? '') !== '1') {
    $captchaAnswer = $_POST['captcha_answer'] ?? '';
    $captchaExpected = $_SESSION['password_reset_captcha'] ?? '';
    unset($_SESSION['password_reset_captcha']);

    if (
        !is_string($captchaAnswer)
        || !is_string($captchaExpected)
        || $captchaExpected === ''
        || !hash_equals($captchaExpected, strtoupper(trim($captchaAnswer)))
    ) {
        try {
            auth_log_event($pdo, 'CAPTCHA_FAILED', null, null, 'Password recovery CAPTCHA verification failed.');
        } catch (PDOException $error) {
            error_log('Unable to log password recovery CAPTCHA failure: ' . $error->getMessage());
        }
        $_SESSION['password_reset_error'] = 'The CAPTCHA code did not match. Please try again.';
        password_reset_request_redirect();
    }

    $usernameInput = $_POST['username'] ?? '';
    $username = is_string($usernameInput) ? trim($usernameInput) : '';
    if (preg_match('/\A[A-Za-z][A-Za-z0-9]{7,18}\z/', $username) !== 1) {
        $_SESSION['password_reset_error'] = 'Enter a valid username.';
        password_reset_request_redirect();
    }

    $_SESSION['password_reset_username_input'] = $username;
    unset(
        $_SESSION['pending_password_reset_username'],
        $_SESSION['pending_password_reset_question_ids'],
        $_SESSION['pending_password_reset_user_id'],
        $_SESSION['pending_password_reset_otp_id'],
        $_SESSION['pending_password_reset_email'],
        $_SESSION['password_reset_otp_stage'],
        $_SESSION['password_reset_verified'],
        $_SESSION['password_reset_verified_at'],
        $_SESSION['password_reset_security_question_verified'],
        $_SESSION['password_reset_resend_seconds'],
        $_SESSION['password_reset_resends_remaining']
    );

    try {
        $lookup = $pdo->prepare(
            "SELECT id_number
             FROM users
             WHERE username = :username
               AND role IN ('ADMIN', 'TREASURER')
               AND account_status = 'ACTIVE'
               AND email_verified_at IS NOT NULL
             LIMIT 1"
        );
        $lookup->execute(['username' => $username]);
        $foundUserId = $lookup->fetchColumn();

        if ($foundUserId !== false) {
            $questionQuery = $pdo->prepare(
                'SELECT question_id
                 FROM user_security_questions
                 WHERE user_id = :user_id
                   AND question_id IN (1, 4, 6)'
            );
            $questionQuery->execute(['user_id' => (string) $foundUserId]);
            $questionIds = array_map('intval', $questionQuery->fetchAll(PDO::FETCH_COLUMN));
            if ($questionIds !== []) {
                $_SESSION['pending_password_reset_user_id'] = (string) $foundUserId;
                $_SESSION['pending_password_reset_username'] = $username;
                $_SESSION['pending_password_reset_question_ids'] = $questionIds;
            }
        }

        auth_log_event(
            $pdo,
            'RESET_REQUESTED',
            $username,
            is_string($_SESSION['pending_password_reset_user_id'] ?? null)
                ? $_SESSION['pending_password_reset_user_id']
                : null,
            'A password recovery request was started.'
        );
        $_SESSION['password_reset_notice'] =
            'If the account details are valid, you can continue with security-question verification.';
    } catch (PDOException $error) {
        error_log('Password recovery account lookup failed: ' . $error->getMessage());
        $_SESSION['password_reset_error'] = 'Password recovery is temporarily unavailable. Please try again.';
    }

    password_reset_request_redirect();
}

if ($action === 'answer') {
    $username = is_string($username) ? $username : '';
    $userId = is_string($userId) && $userId !== '' ? $userId : null;
    $questionId = filter_var($_POST['question_id'] ?? null, FILTER_VALIDATE_INT);
    $allowedQuestionIds = $_SESSION['pending_password_reset_question_ids'] ?? [];
    $allowedQuestionIds = is_array($allowedQuestionIds)
        ? array_map('intval', $allowedQuestionIds)
        : [];
    $answer = $_POST['security_answer'] ?? '';
    $confirmation = $_POST['confirm_security_answer'] ?? '';
    $answer = is_string($answer) ? trim($answer) : '';
    $confirmation = is_string($confirmation) ? trim($confirmation) : '';

    if (
        $username === ''
        || $userId === null
        || !is_int($questionId)
        || !in_array($questionId, $allowedQuestionIds, true)
        || strlen($answer) < 2
        || strlen($answer) > 50
        || preg_match('/\A[A-Za-z]+(?: [A-Za-z]+)*\z/', $answer) !== 1
        || strtolower($answer) !== strtolower($confirmation)
    ) {
        $_SESSION['password_reset_error'] = 'Enter the same valid answer in both fields and choose one of your questions.';
        password_reset_request_redirect();
    }

    try {
        $clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
        if (filter_var($clientIp, FILTER_VALIDATE_IP) === false) {
            $clientIp = '0.0.0.0';
        }
        $ipLockSeconds = auth_ip_block_seconds($pdo, $clientIp);
        if ($ipLockSeconds > 0) {
            $_SESSION['password_reset_error'] =
                'This network is temporarily blocked. Try again in '
                . $ipLockSeconds
                . ' seconds.';
            password_reset_request_redirect();
        }

        $lockout = auth_lockout_state(
            auth_failure_history($pdo, $userId, strtolower($username))
        );
        if ($lockout['seconds'] > 0) {
            $_SESSION['password_reset_error'] =
                'Too many failed attempts. Try again in '
                . $lockout['seconds']
                . ' seconds.';
            password_reset_request_redirect();
        }

        $isCorrect = false;
        if ($userId !== null) {
            $answerQuery = $pdo->prepare(
                'SELECT answer_hash
                 FROM user_security_questions
                 WHERE user_id = :user_id AND question_id = :question_id
                 LIMIT 1'
            );
            $answerQuery->execute([
                'user_id' => $userId,
                'question_id' => $questionId
            ]);
            $answerHash = $answerQuery->fetchColumn();
            $isCorrect = is_string($answerHash)
                && password_verify(strtolower($answer), $answerHash);
        }

        if (!$isCorrect) {
            $lockout = password_reset_record_failed_answer($pdo, $username, $userId);
            $_SESSION['password_reset_error'] = $lockout['seconds'] > 0
                ? 'Too many failed attempts. Try again in ' . $lockout['seconds'] . ' seconds.'
                : 'The security answer could not be verified. Check it and try again.';
            password_reset_request_redirect();
        }

        auth_log_event(
            $pdo,
            'PASSWORD_RESET_ANSWER_VERIFIED',
            $username,
            $userId,
            'The password recovery security answer was verified.'
        );

        $_SESSION['password_reset_security_question_verified'] = true;
        password_reset_send_code($pdo, $userId);
        $_SESSION['password_reset_notice'] = 'A recovery code was sent to your registered email address.';
    } catch (AuthOtpThrottleException $error) {
        $_SESSION['password_reset_error'] = $error->getMessage();
    } catch (PDOException $error) {
        error_log('Password recovery verification database failure: ' . $error->getMessage());
        $_SESSION['password_reset_error'] = 'Password recovery is temporarily unavailable. Please try again.';
    } catch (RuntimeException $error) {
        error_log('Password recovery verification failed: ' . $error->getMessage());
        $_SESSION['password_reset_error'] = 'The recovery code could not be sent. Please try again later.';
    }

    password_reset_request_redirect();
}

if (($_POST['resend'] ?? '') === '1') {
    if (
        ($_SESSION['password_reset_otp_stage'] ?? false) !== true
        || ($_SESSION['password_reset_security_question_verified'] ?? false) !== true
    ) {
        $_SESSION['password_reset_error'] = 'Verify your security answer before requesting a recovery code.';
        password_reset_request_redirect();
    }

    if (is_string($userId) && $userId !== '') {
        try {
            password_reset_send_code($pdo, $userId);
            $_SESSION['password_reset_notice'] = 'A new recovery code was sent to your registered email address.';
        } catch (AuthOtpThrottleException $error) {
            $_SESSION['password_reset_error'] = $error->getMessage();
            $_SESSION['password_reset_resend_seconds'] = $error->retryAfter;
            $_SESSION['password_reset_resends_remaining'] = $error->resendsRemaining;
        } catch (PDOException $error) {
            error_log('Password recovery code resend failed: ' . $error->getMessage());
            $_SESSION['password_reset_error'] = 'Could not resend the recovery code. Please try again.';
        } catch (RuntimeException $error) {
            error_log('Password recovery code delivery failed: ' . $error->getMessage());
            $_SESSION['password_reset_error'] = 'The recovery code could not be sent. Please try again later.';
            $_SESSION['password_reset_resend_seconds'] = 60;
        }
    } else {
        $_SESSION['password_reset_notice'] =
            'If the account details are valid, a recovery code was sent to the registered email address.';
    }

    password_reset_request_redirect();
}

$_SESSION['password_reset_error'] = 'The password recovery request is invalid. Please try again.';
password_reset_request_redirect();
