<?php

// Load the existing Admin authentication system.
require_once __DIR__ . '/auth_guard.php';


/*
|--------------------------------------------------------------------------
| GET TODAY'S SECURITY SUMMARY
|--------------------------------------------------------------------------
*/

function admin_dashboard_get_summary(PDO $pdo): array
{
    // Count today's login attempts.
    $statement = $pdo->query("
        SELECT
            COUNT(*) AS total_attempts,
            SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS successful_logins,
            SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed_logins
        FROM login_attempts
        WHERE DATE(attempted_at) = CURDATE()
    ");

    $summary = $statement->fetch(PDO::FETCH_ASSOC);

    // Count currently active IP blocks.
    $statement = $pdo->query("
        SELECT COUNT(*)
        FROM ip_blocks
        WHERE blocked_until > NOW()
    ");

    $activeBlocks = (int) $statement->fetchColumn();

    // Count security flags detected today.
    $statement = $pdo->query("
        SELECT COUNT(*)
        FROM security_flags
        WHERE DATE(detected_at) = CURDATE()
    ");

    $securityFlags = (int) $statement->fetchColumn();

    // Count accounts whose progressive lockout is still active.
    $userIdStatement = $pdo->query("
        SELECT DISTINCT user_id
        FROM login_attempts
        WHERE user_id IS NOT NULL
          AND attempted_at >= DATE_SUB(NOW(), INTERVAL 180 SECOND)
    ");
    $lockedAccounts = 0;

    foreach ($userIdStatement->fetchAll(PDO::FETCH_COLUMN) as $userId) {
        $history = auth_failure_history($pdo, (string) $userId, '');
        if (auth_lockout_state($history)['seconds'] > 0) {
            $lockedAccounts++;
        }
    }

    $activityCount = static function (string $eventType) use ($pdo): int {
        $activityStatement = $pdo->prepare(
            'SELECT COUNT(*)
             FROM activity_logs
             WHERE event_type = :event_type
               AND DATE(created_at) = CURDATE()'
        );
        $activityStatement->execute(['event_type' => $eventType]);
        return (int) $activityStatement->fetchColumn();
    };

    return [
        'total_attempts' => (int) ($summary['total_attempts'] ?? 0),
        'successful_logins' => (int) ($summary['successful_logins'] ?? 0),
        'failed_logins' => (int) ($summary['failed_logins'] ?? 0),
        'locked_accounts' => $lockedAccounts,
        'active_ip_blocks' => $activeBlocks,
        'otps_sent' => $activityCount('OTP_SENT'),
        'otps_failed' => $activityCount('OTP_FAILED'),
        'alert_emails_sent' => $activityCount('ALERT_EMAIL_SENT'),
        'security_flags' => $securityFlags
    ];
}


/*
|--------------------------------------------------------------------------
| GET FAILED LOGINS PER HOUR
|--------------------------------------------------------------------------
*/

function admin_dashboard_get_failed_logins_chart(PDO $pdo): array
{
    // Get failed login attempts grouped by hour for the last 24 hours.
    $statement = $pdo->query("
        SELECT
            DATE_FORMAT(attempted_at, '%Y-%m-%d %H:00:00') AS login_hour,
            COUNT(*) AS failed_count
        FROM login_attempts
        WHERE success = 0
          AND attempted_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY DATE_FORMAT(attempted_at, '%Y-%m-%d %H:00:00')
        ORDER BY login_hour ASC
    ");

    $results = $statement->fetchAll(PDO::FETCH_ASSOC);

    // Prepare 24 hourly entries, including hours with zero attempts.
    $hourlyData = [];

    for ($i = 23; $i >= 0; $i--) {
        $hour = date('Y-m-d H:00:00', strtotime("-$i hours"));

        $hourlyData[$hour] = 0;
    }

    // Insert the actual database counts.
    foreach ($results as $result) {
        $hour = $result['login_hour'];

        if (array_key_exists($hour, $hourlyData)) {
            $hourlyData[$hour] = (int) $result['failed_count'];
        }
    }

    $labels = [];
    $counts = [];

    foreach ($hourlyData as $hour => $count) {
        $labels[] = date('M d, H:00', strtotime($hour));
        $counts[] = $count;
    }

    return [
        'labels' => $labels,
        'counts' => $counts
    ];
}


/*
|--------------------------------------------------------------------------
| GET TOP FIVE IP ADDRESSES
|--------------------------------------------------------------------------
*/

function admin_dashboard_get_top_ips(PDO $pdo): array
{
    $statement = $pdo->query("
        SELECT
            l.ip_address,
            COUNT(*) AS failed_attempts,
            b.blocked_until,
            CASE
                WHEN b.blocked_until > NOW() THEN 'BLOCKED'
                ELSE 'NOT BLOCKED'
            END AS block_status
        FROM login_attempts l
        LEFT JOIN ip_blocks b
            ON l.ip_address = b.ip_address
        WHERE l.success = 0
          AND l.attempted_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY
            l.ip_address,
            b.blocked_until
        ORDER BY failed_attempts DESC
        LIMIT 5
    ");

    return $statement->fetchAll(PDO::FETCH_ASSOC);
}


/*
|--------------------------------------------------------------------------
| GET RECENT SECURITY FLAGS
|--------------------------------------------------------------------------
*/

function admin_dashboard_get_security_flags(PDO $pdo): array
{
    $statement = $pdo->query("
        SELECT
            flag_type,
            description,
            related_ip,
            related_username,
            detected_at
        FROM security_flags
        ORDER BY detected_at DESC
        LIMIT 20
    ");

    return $statement->fetchAll(PDO::FETCH_ASSOC);
}


/*
|--------------------------------------------------------------------------
| GET ACTIVITY LOGS
|--------------------------------------------------------------------------
*/

function admin_dashboard_get_activity_logs(PDO $pdo, array $filters = []): array
{
    $sql = "
        SELECT
            created_at,
            event_type,
            username_typed,
            ip_address,
            details
        FROM activity_logs
        WHERE 1 = 1
          AND event_type <> 'ADMIN_VIEWED_DASHBOARD'
    ";

    $parameters = [];

    // Filter by starting date.
    if (!empty($filters['start_date'])) {
        $sql .= " AND created_at >= :start_date";

        $parameters['start_date'] = $filters['start_date'] . ' 00:00:00';
    }

    // Filter by ending date.
    if (!empty($filters['end_date'])) {
        $sql .= " AND created_at < :end_date_exclusive";

        $endDate = DateTimeImmutable::createFromFormat('!Y-m-d', $filters['end_date']);
        $parameters['end_date_exclusive'] = $endDate
            ->modify('+1 day')
            ->format('Y-m-d 00:00:00');
    }

    // Filter by event type.
    if (!empty($filters['event_type'])) {
        $sql .= " AND event_type LIKE :event_type";

        $parameters['event_type'] = '%' . $filters['event_type'] . '%';
    }

    // Filter by username.
    if (!empty($filters['username'])) {
        $sql .= " AND username_typed LIKE :username";

        $parameters['username'] = '%' . $filters['username'] . '%';
    }

    // Filter by IP address.
    if (!empty($filters['ip_address'])) {
        $sql .= " AND ip_address LIKE :ip_address";

        $parameters['ip_address'] = '%' . $filters['ip_address'] . '%';
    }

    // Show the newest records first.
    $sql .= " ORDER BY created_at DESC LIMIT 100";

    $statement = $pdo->prepare($sql);
    $statement->execute($parameters);

    return $statement->fetchAll(PDO::FETCH_ASSOC);
}
