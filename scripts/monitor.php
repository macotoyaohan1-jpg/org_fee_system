
<?php

// Allow this script to run only through the command line.
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('Access denied. Run this script through PowerShell.');
}

// Connect to the database.
require_once __DIR__ . '/../backend/db.php';

echo "====================================\n";
echo "   SECURITY LOG MONITORING SCRIPT\n";
echo "====================================\n\n";

try {

    // Find repeated failed login attempts within the last 10 minutes.
    $sql = "
        SELECT
            ip_address,
            COALESCE(NULLIF(username_typed, ''), 'UNKNOWN')
                AS related_username,
            COUNT(*) AS total_attempts,
            MIN(created_at) AS first_attempt,
            MAX(created_at) AS last_attempt
        FROM activity_logs
        WHERE event_type = 'LOGIN_FAILED'
          AND created_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)
        GROUP BY
            ip_address,
            COALESCE(NULLIF(username_typed, ''), 'UNKNOWN')
        HAVING COUNT(*) >= 5
    ";

    $statement = $pdo->query($sql);
    $suspiciousActivities = $statement->fetchAll(PDO::FETCH_ASSOC);

    if (empty($suspiciousActivities)) {
        echo "No suspicious login activity detected.\n";
    } else {

        // Prepare the security alert insertion.
        $insert = $pdo->prepare("
            INSERT IGNORE INTO security_flags
            (
                flag_key,
                flag_type,
                description,
                related_ip,
                related_username
            )
            VALUES
            (
                :flag_key,
                :flag_type,
                :description,
                :related_ip,
                :related_username
            )
        ");

        // Use the current 10-minute interval to prevent duplicates.
        $timeWindow = intdiv(time(), 600);

        foreach ($suspiciousActivities as $activity) {

            $ipAddress = $activity['ip_address'] ?? null;
            $username = $activity['related_username'];

            // Create a unique key for this IP, username, and interval.
            $flagKey = hash(
                'sha256',
                'FAILED_LOGIN|'
                . ($ipAddress ?? 'UNKNOWN')
                . '|'
                . $username
                . '|'
                . $timeWindow
            );

            $description =
                'Detected '
                . $activity['total_attempts']
                . ' failed login attempts within the last 10 minutes. '
                . 'First attempt: '
                . $activity['first_attempt']
                . '. Last attempt: '
                . $activity['last_attempt']
                . '.';

            $insert->execute([
                'flag_key' => $flagKey,
                'flag_type' => 'REPEATED_FAILED_LOGINS',
                'description' => $description,
                'related_ip' => $ipAddress,
                'related_username' => $username
            ]);

            if ($insert->rowCount() > 0) {
                echo "[ALERT] Suspicious login activity detected!\n";
                echo "Username: " . $username . "\n";
                echo "IP Address: " . ($ipAddress ?? 'UNKNOWN') . "\n";
                echo "Failed Attempts: " . $activity['total_attempts'] . "\n\n";
            } else {
                echo "[INFO] Existing alert already recorded for ";
                echo $username . ".\n\n";
            }
        }
    }

    echo "\nMonitoring completed successfully.\n";

} catch (Throwable $exception) {

    // Write technical errors to the PHP error log.
    error_log(
        'Security monitoring error: '
        . $exception->getMessage()
    );

    echo "Monitoring failed. Check the PHP error log.\n";

    exit(1);
}
