<?php

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit('Page Not Found');
}

require_once __DIR__ . '/../php/backend/auth_common.php';

$ipFailureThreshold = AUTH_IP_BLOCK_THRESHOLD;
$ipFailureWindowMinutes = intdiv(AUTH_IP_BLOCK_WINDOW_SECONDS, 60);
$otpFailureThreshold = 5;
$otpFailureWindowMinutes = 10;

function monitor_add_flags(
    PDO $pdo,
    array &$findings,
    string $scanDate,
    string $label,
    string $severity,
    string $target,
    string $description,
    ?string $ipAddress,
    ?string $username,
    array &$counts
): void {
    $flagKey = hash('sha256', $label . '|' . $target . '|' . $scanDate);
    $insert = $pdo->prepare(
        'INSERT IGNORE INTO security_flags
            (flag_key, flag_type, description, related_ip, related_username)
         VALUES
            (:flag_key, :flag_type, :description, :related_ip, :related_username)'
    );

    $insert->execute([
        'flag_key' => $flagKey,
        'flag_type' => $label,
        'description' => $description,
        'related_ip' => $ipAddress,
        'related_username' => $username
    ]);

    if ($insert->rowCount() > 0) {
        $counts['new']++;
    } else {
        $counts['existing']++;
    }

    $findings[] = [
        'label' => $label,
        'severity' => $severity,
        'target' => $target,
        'description' => $description
    ];
}

try {
    $now = new DateTimeImmutable('now', new DateTimeZone('Asia/Manila'));
    $scanDate = $now->format('Y-m-d');
    $findings = [];
    $counts = ['new' => 0, 'existing' => 0];

    $scannedStatement = $pdo->query(
        'SELECT COUNT(*)
         FROM activity_logs
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)'
    );
    $scannedEvents = (int) $scannedStatement->fetchColumn();

    $ipStatement = $pdo->prepare(
        'SELECT ip_address,
                COUNT(*) AS failure_count,
                COUNT(DISTINCT NULLIF(username_typed, \'\')) AS username_count,
                MIN(created_at) AS first_failure,
                MAX(created_at) AS last_failure
         FROM activity_logs
         WHERE event_type = :event_type
           AND ip_address IS NOT NULL
           AND created_at >= DATE_SUB(NOW(), INTERVAL '
            . $ipFailureWindowMinutes . ' MINUTE)
         GROUP BY ip_address
         HAVING COUNT(*) >= :failure_threshold'
    );
    $ipStatement->execute([
        'event_type' => 'LOGIN_FAILED',
        'failure_threshold' => $ipFailureThreshold
    ]);

    foreach ($ipStatement->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $ipAddress = (string) $row['ip_address'];
        $usernameCount = (int) $row['username_count'];
        $description = (int) $row['failure_count']
            . ' failed sign-ins from this IP within '
            . $ipFailureWindowMinutes
            . ' minutes across '
            . $usernameCount
            . ' username(s). First: '
            . $row['first_failure']
            . '; last: '
            . $row['last_failure']
            . '.';
        monitor_add_flags(
            $pdo,
            $findings,
            $scanDate,
            'IP_OVER_THRESHOLD',
            'HIGH',
            $ipAddress,
            $description,
            $ipAddress,
            $usernameCount > 1 ? 'Multiple accounts' : null,
            $counts
        );
    }

    $accountStatement = $pdo->query(
        "SELECT LOWER(TRIM(username_typed)) AS related_username,
                COUNT(*) AS failure_count,
                COUNT(DISTINCT ip_address) AS ip_count,
                MIN(created_at) AS first_failure,
                MAX(created_at) AS last_failure
         FROM activity_logs
         WHERE event_type = 'LOGIN_FAILED'
           AND username_typed IS NOT NULL
           AND TRIM(username_typed) <> ''
           AND ip_address IS NOT NULL
           AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
         GROUP BY LOWER(TRIM(username_typed))
         HAVING COUNT(DISTINCT ip_address) >= 3"
    );

    foreach ($accountStatement->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $username = (string) $row['related_username'];
        $ipCount = (int) $row['ip_count'];
        $description = $row['failure_count']
            . ' failed sign-ins from '
            . $ipCount
            . ' different IP addresses in the last 24 hours. First: '
            . $row['first_failure']
            . '; last: '
            . $row['last_failure']
            . '.';
        monitor_add_flags(
            $pdo,
            $findings,
            $scanDate,
            'ACCOUNT_TARGETED',
            'MED',
            $username,
            $description,
            'Multiple IPs',
            $username,
            $counts
        );
    }

    $otpStatement = $pdo->prepare(
        "SELECT COALESCE(NULLIF(user_id, ''), LOWER(username_typed)) AS account_key,
                MAX(user_id) AS user_id,
                MIN(NULLIF(username_typed, '')) AS related_username,
                COUNT(*) AS failure_count,
                MIN(created_at) AS first_failure,
                MAX(created_at) AS last_failure
         FROM activity_logs
         WHERE event_type = :event_type
           AND created_at >= DATE_SUB(NOW(), INTERVAL "
            . $otpFailureWindowMinutes . ' MINUTE)
         GROUP BY COALESCE(NULLIF(user_id, \'\'), LOWER(username_typed))
         HAVING COUNT(*) >= :failure_threshold'
    );
    $otpStatement->execute([
        'event_type' => 'OTP_FAILED',
        'failure_threshold' => $otpFailureThreshold
    ]);

    foreach ($otpStatement->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $accountKey = (string) $row['account_key'];
        $username = is_string($row['related_username']) && $row['related_username'] !== ''
            ? $row['related_username']
            : 'UNKNOWN';
        $description = (int) $row['failure_count']
            . ' incorrect OTP entries for this account within '
            . $otpFailureWindowMinutes
            . ' minutes. First: '
            . $row['first_failure']
            . '; last: '
            . $row['last_failure']
            . '.';
        monitor_add_flags(
            $pdo,
            $findings,
            $scanDate,
            'OTP_GUESSING',
            'MED',
            $accountKey,
            $description,
            null,
            $username,
            $counts
        );
    }

    $timezoneOffset = (int) $pdo->query(
        'SELECT TIMESTAMPDIFF(MINUTE, UTC_TIMESTAMP(), NOW())'
    )->fetchColumn();
    $offsetSign = $timezoneOffset < 0 ? '-' : '+';
    $absoluteOffset = abs($timezoneOffset);
    $databaseTimezone = new DateTimeZone(sprintf(
        '%s%02d:%02d',
        $offsetSign,
        intdiv($absoluteOffset, 60),
        $absoluteOffset % 60
    ));
    $manilaTimezone = new DateTimeZone('Asia/Manila');

    $loginStatement = $pdo->query(
        "SELECT user_id, username_typed, ip_address, created_at
         FROM activity_logs
         WHERE event_type = 'LOGIN_SUCCESS'
           AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
         ORDER BY created_at ASC"
    );

    foreach ($loginStatement->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $createdAt = DateTimeImmutable::createFromFormat(
            '!Y-m-d H:i:s',
            substr((string) $row['created_at'], 0, 19),
            $databaseTimezone
        );
        if (!$createdAt) {
            throw new RuntimeException('A login event has an invalid timestamp.');
        }

        $manilaTime = $createdAt->setTimezone($manilaTimezone);
        $hour = (int) $manilaTime->format('G');
        if ($hour < 0 || $hour >= 5) {
            continue;
        }

        $userId = is_string($row['user_id']) ? $row['user_id'] : '';
        $username = is_string($row['username_typed']) && $row['username_typed'] !== ''
            ? $row['username_typed']
            : 'UNKNOWN';
        $target = $userId !== '' ? $userId : strtolower($username);
        $ipAddress = is_string($row['ip_address']) ? $row['ip_address'] : null;
        $description = 'Successful sign-in at '
            . $manilaTime->format('Y-m-d H:i:s')
            . ' Philippine time.';

        monitor_add_flags(
            $pdo,
            $findings,
            $scanDate,
            'OFF_HOURS_LOGIN',
            'MED',
            $target,
            $description,
            $ipAddress,
            $username,
            $counts
        );
    }

    echo 'IT 107 Monitoring Report - ' . $now->format('Y-m-d H:i') . " PHT\n";
    echo 'Scanned: ' . number_format($scannedEvents) . " events (last 24 hours)\n";

    foreach ($findings as $finding) {
        echo '[' . $finding['severity'] . '] '
            . str_pad($finding['label'], 20)
            . ' '
            . $finding['target']
            . ' - '
            . $finding['description']
            . "\n";
    }

    if ($findings === []) {
        echo "No suspicious activity detected.\n";
    }

    echo 'New flags written: ' . $counts['new']
        . '  Already flagged today: ' . $counts['existing']
        . "\n";
} catch (Throwable $error) {
    error_log('Security monitoring error: ' . $error->getMessage());
    fwrite(STDERR, "Monitoring failed. Check the PHP error log.\n");
    exit(1);
}
