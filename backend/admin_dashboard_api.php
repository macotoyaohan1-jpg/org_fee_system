
<?php

// Return JSON instead of an HTML page.
header('Content-Type: application/json; charset=utf-8');

// Allow only GET requests.
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);

    echo json_encode([
        'success' => false,
        'message' => 'Method not allowed.'
    ]);

    exit;
}

try {

    // Load the existing authentication system.
    require_once __DIR__ . '/auth_guard.php';

    // Return JSON auth errors for fetch requests instead of redirecting to a
    // relative login URL under /backend/.
    auth_start_session();
    $userId = $_SESSION['user_id'] ?? null;

    if (!is_string($userId) || $userId === '') {
        http_response_code(401);
        echo json_encode([
            'success' => false,
            'message' => 'Your session has expired. Sign in again and reload the dashboard.'
        ]);
        exit;
    }

    $userStatement = $pdo->prepare(
        'SELECT role, account_status FROM users WHERE id_number = :user_id LIMIT 1'
    );
    $userStatement->execute(['user_id' => $userId]);
    $user = $userStatement->fetch(PDO::FETCH_ASSOC);

    if (!$user || $user['account_status'] !== 'ACTIVE' || $user['role'] !== 'ADMIN') {
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'message' => 'An active administrator session is required to load dashboard data.'
        ]);
        exit;
    }

    // Load the dashboard database functions.
    require_once __DIR__ . '/admin_dashboard_data.php';


    /*
    |--------------------------------------------------------------------------
    | READ FILTER VALUES
    |--------------------------------------------------------------------------
    */

    $filters = [
        'start_date' => trim($_GET['start_date'] ?? ''),
        'end_date' => trim($_GET['end_date'] ?? ''),
        'event_type' => trim($_GET['event_type'] ?? ''),
        'username' => trim($_GET['username'] ?? ''),
        'ip_address' => trim($_GET['ip_address'] ?? '')
    ];


    /*
    |--------------------------------------------------------------------------
    | VALIDATE DATE FILTERS
    |--------------------------------------------------------------------------
    */

    foreach (['start_date', 'end_date'] as $dateField) {

        if ($filters[$dateField] !== '') {

            $date = DateTime::createFromFormat(
                '!Y-m-d',
                $filters[$dateField]
            );

            if (
                !$date ||
                $date->format('Y-m-d') !== $filters[$dateField]
            ) {
                http_response_code(400);

                echo json_encode([
                    'success' => false,
                    'message' => 'Invalid date filter.'
                ]);

                exit;
            }
        }
    }

    // Prevent a start date later than the end date.
    if (
        $filters['start_date'] !== '' &&
        $filters['end_date'] !== '' &&
        $filters['start_date'] > $filters['end_date']
    ) {
        http_response_code(400);

        echo json_encode([
            'success' => false,
            'message' => 'Start date cannot be later than end date.'
        ]);

        exit;
    }


    /*
    |--------------------------------------------------------------------------
    | GET DASHBOARD INFORMATION
    |--------------------------------------------------------------------------
    */

    $dashboardData = [

        'summary' => admin_dashboard_get_summary($pdo),

        'failed_logins_chart' =>
            admin_dashboard_get_failed_logins_chart($pdo),

        'top_ips' =>
            admin_dashboard_get_top_ips($pdo),

        'security_flags' =>
            admin_dashboard_get_security_flags($pdo),

        'activity_logs' =>
            admin_dashboard_get_activity_logs($pdo, $filters)

    ];


    /*
    |--------------------------------------------------------------------------
    | SEND JSON RESPONSE
    |--------------------------------------------------------------------------
    */

    echo json_encode([
        'success' => true,
        'data' => $dashboardData,
        'last_updated' => date('Y-m-d H:i:s')
    ], JSON_INVALID_UTF8_SUBSTITUTE);

    exit;


} catch (Throwable $error) {

    // Record the actual error in the PHP error log.
    error_log('Admin Dashboard API Error: ' . $error->getMessage());

    // Send a safe message to the browser.
    http_response_code(500);

    echo json_encode([
        'success' => false,
        'message' => 'Unable to load dashboard information. Please try again.'
    ]);

    exit;
}
