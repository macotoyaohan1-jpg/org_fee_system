<?php

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// Check the Admin's login session and permissions.
require_once __DIR__ . '/backend/auth_guard.php';

// Allow only an authenticated Admin to access this page.
$user = auth_require_admin($pdo);
auth_log_event(
    $pdo,
    'ADMIN_VIEWED_DASHBOARD',
    null,
    (string) $user['id_number'],
    'The administrator opened the security monitoring dashboard.'
);

// Create a CSRF token for Admin actions.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$csrf = $_SESSION['csrf_token'];

// Get the Admin's name.
$firstName = trim((string)($user['first_name'] ?? ''));
$familyName = trim((string)($user['family_name'] ?? ''));

$adminName = trim($firstName . ' ' . $familyName);

if ($adminName === '') {
    $adminName = 'Admin';
}

// Escape the name before displaying it in HTML.
$adminName = htmlspecialchars($adminName, ENT_QUOTES, 'UTF-8');

// Also support filtering through a normal GET form submission when JavaScript
// is unavailable or blocked in the browser.
require_once __DIR__ . '/backend/admin_dashboard_data.php';

$filterValue = static function (string $key): string {
    return isset($_GET[$key]) && is_string($_GET[$key])
        ? trim($_GET[$key])
        : '';
};

$activityFilters = [
    'start_date' => $filterValue('start_date'),
    'end_date' => $filterValue('end_date'),
    'event_type' => $filterValue('event_type'),
    'username' => $filterValue('username'),
    'ip_address' => $filterValue('ip_address')
];

foreach (['start_date', 'end_date'] as $dateField) {
    if ($activityFilters[$dateField] !== '') {
        $date = DateTime::createFromFormat(
            '!Y-m-d',
            $activityFilters[$dateField]
        );

        if (!$date || $date->format('Y-m-d') !== $activityFilters[$dateField]) {
            $activityFilters[$dateField] = '';
        }
    }
}

if (
    $activityFilters['start_date'] !== '' &&
    $activityFilters['end_date'] !== '' &&
    $activityFilters['start_date'] > $activityFilters['end_date']
) {
    $activityFilters['start_date'] = '';
    $activityFilters['end_date'] = '';
}

$activityLogs = admin_dashboard_get_activity_logs($pdo, $activityFilters);

// Available Admin dashboard views.
$dashboardViews = [
    'overview' => [
        'title' => 'Security Monitoring Dashboard',
        'subtitle' => 'Monitor system activity and security events.'
    ],
    'treasurer-approval' => [
        'title' => 'Treasurer Approval',
        'subtitle' => 'Review and manage Treasurer account applications.'
    ],
    'top-ips' => [
        'title' => 'Top IP Addresses',
        'subtitle' => 'Review IP addresses with the most failed sign-in attempts.'
    ],
    'security-flags' => [
        'title' => 'Security Flags',
        'subtitle' => 'Review security concerns detected and recorded by the system.'
    ],
    'activity-logs' => [
        'title' => 'Activity Logs',
        'subtitle' => 'Search and review the latest recorded system activities.'
    ]
];

$currentView = isset($_GET['view']) && is_string($_GET['view']) && isset($dashboardViews[$_GET['view']])
    ? $_GET['view']
    : 'overview';

$viewIsActive = static fn (string $view): string =>
    $currentView === $view ? ' active' : '';

$escapeHtml = static fn ($value): string => htmlspecialchars(
    (string)($value ?? ''),
    ENT_QUOTES,
    'UTF-8'
);

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Admin Dashboard | Student Organization Fee System</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">

    <link rel="stylesheet" href="css/admin_dashboard.css?v=17">
</head>

<body>

    <div class="dashboard-container">

        <!-- SIDEBAR -->
        <aside class="sidebar">

            <div class="sidebar-brand">
                <h2>Welcome, <?= $adminName ?>!</h2>
                <p>Administrator Panel</p>
            </div>

            <nav class="sidebar-navigation">

                <a href="admin_dashboard.php?view=overview" class="nav-link home-link">
                    <svg
                        class="home-icon"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        aria-hidden="true"
                        focusable="false"
                    >
                        <path d="M3 11l9-8 9 8"></path>
                        <path d="M5 10v10h14V10"></path>
                        <path d="M9 20v-6h6v6"></path>
                    </svg>
                    <span>Home</span>
                </a>

                <a href="admin_dashboard.php?view=treasurer-approval" class="nav-link<?= $viewIsActive('treasurer-approval') ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
                        <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"></path>
                        <circle cx="9" cy="7" r="4"></circle>
                        <path d="M19 8v6"></path>
                        <path d="M22 11h-6"></path>
                    </svg>
                    <span>Treasurer Approval</span>
                </a>

                <a href="admin_dashboard.php?view=top-ips" class="nav-link<?= $viewIsActive('top-ips') ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
                        <circle cx="12" cy="12" r="9"></circle>
                        <path d="M3 12h18"></path>
                        <path d="M12 3a15 15 0 0 1 0 18"></path>
                        <path d="M12 3a15 15 0 0 0 0 18"></path>
                    </svg>
                    <span>Top IP Addresses</span>
                </a>

                <a href="admin_dashboard.php?view=security-flags" class="nav-link<?= $viewIsActive('security-flags') ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                        <path d="M12 8v4"></path>
                        <path d="M12 16h.01"></path>
                    </svg>
                    <span>Security Flags</span>
                </a>

                <a href="admin_dashboard.php?view=activity-logs" class="nav-link<?= $viewIsActive('activity-logs') ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                        <line x1="8" y1="13" x2="16" y2="13"></line>
                        <line x1="8" y1="17" x2="16" y2="17"></line>
                    </svg>
                    <span>Activity Logs</span>
                </a>

                <a href="logout.php" class="nav-link logout-link">
                    <svg
                        class="logout-icon"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        aria-hidden="true"
                        focusable="false"
                    >
                        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
                        <polyline points="16 17 21 12 16 7"></polyline>
                        <line x1="21" y1="12" x2="9" y2="12"></line>
                    </svg>
                    <span>Logout</span>
                </a>

            </nav>

        </aside>


        <!-- MAIN CONTENT -->
        <main class="main-content">

            <!-- TOP HEADER -->
            <header class="dashboard-header">

                <div>
                    <h1><?= $escapeHtml($dashboardViews[$currentView]['title']) ?></h1>
                    <p><?= $escapeHtml($dashboardViews[$currentView]['subtitle']) ?></p>
                </div>

                <div class="admin-information">
                    <span>Welcome, <?= $adminName ?>!</span>
                    <small>Administrator</small>
                </div>

            </header>


            <!-- SECURITY SUMMARY -->
            <section class="dashboard-section"<?= $currentView === 'overview' ? '' : ' hidden' ?>>

                <div class="section-heading">
                    <h2>Today's Security Summary</h2>
                    <p>Overview of security activity for today.</p>
                </div>

                <div class="summary-grid">

                    <article class="summary-card">
                        <p>Login Attempts</p>
                        <h3 id="totalAttempts">0</h3>
                    </article>

                    <article class="summary-card">
                        <p>Successful Logins</p>
                        <h3 id="successfulLogins">0</h3>
                    </article>

                    <article class="summary-card">
                        <p>Failed Logins</p>
                        <h3 id="failedLogins">0</h3>
                    </article>

                    <article class="summary-card">
                        <p>Accounts Locked Now</p>
                        <h3 id="lockedAccounts">0</h3>
                    </article>

                    <article class="summary-card">
                        <p>Active IP Blocks</p>
                        <h3 id="activeIpBlocks">0</h3>
                    </article>

                    <article class="summary-card">
                        <p>OTPs Sent</p>
                        <h3 id="otpsSent">0</h3>
                    </article>

                    <article class="summary-card">
                        <p>OTP Failures</p>
                        <h3 id="otpsFailed">0</h3>
                    </article>

                    <article class="summary-card">
                        <p>Alert Emails Sent</p>
                        <h3 id="alertEmailsSent">0</h3>
                    </article>

                    <article class="summary-card">
                        <p>Security Flags</p>
                        <h3 id="securityFlags">0</h3>
                    </article>

                </div>

            </section>


            <!-- FAILED LOGIN CHART -->
            <section class="dashboard-section"<?= $currentView === 'overview' ? '' : ' hidden' ?>>

                <div class="section-heading">
                    <h2>Failed Logins per Hour</h2>
                    <p>Failed login attempts recorded during the last 24 hours.</p>
                </div>

                <div class="dashboard-panel">
                    <canvas id="failedLoginChart"></canvas>
                </div>

            </section>


            <!-- IP ADDRESS MONITORING -->
            <section class="dashboard-section"<?= $currentView === 'top-ips' ? '' : ' hidden' ?>>

                <div class="section-heading">
                    <h2>Top IP Addresses</h2>
                    <p>IP addresses with the highest number of failed login attempts.</p>
                </div>

                <div class="dashboard-panel table-container">

                    <table>
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Failed Attempts</th>
                                <th>Block Status</th>
                                <th>Blocked Until</th>
                            </tr>
                        </thead>

                        <tbody id="ipAddressTable">

                            <tr>
                                <td colspan="4">Loading data...</td>
                            </tr>

                        </tbody>
                    </table>

                </div>

            </section>


            <!-- SECURITY FLAGS -->
            <section class="dashboard-section"<?= $currentView === 'security-flags' ? '' : ' hidden' ?>>

                <div class="section-heading">
                    <h2>Security Flags</h2>
                    <p>Security concerns detected and recorded by the system.</p>
                </div>

                <div class="dashboard-panel table-container">

                    <table>
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Description</th>
                                <th>Related IP</th>
                                <th>Related Username</th>
                                <th>Date Detected</th>
                            </tr>
                        </thead>

                        <tbody id="securityFlagsTable">

                            <tr>
                                <td colspan="5">Loading data...</td>
                            </tr>

                        </tbody>
                    </table>

                </div>

            </section>


            <!-- ACTIVITY LOGS -->
            <section class="dashboard-section"<?= $currentView === 'activity-logs' ? '' : ' hidden' ?>>

                <div class="section-heading">
                    <h2>Activity Logs</h2>
                    <p>Review the latest 100 recorded system and Treasurer activities.</p>
                </div>

                <!-- FILTERS -->
                <form class="dashboard-panel" id="activityLogFilters" method="get" action="admin_dashboard.php">

                    <input type="hidden" name="view" value="activity-logs">

                    <div class="filter-grid">

                        <div class="filter-group">
                            <label for="filterStartDate">Start Date</label>
                            <input
                                type="date"
                                id="filterStartDate"
                                name="start_date"
                                value="<?= $escapeHtml($activityFilters['start_date']) ?>"
                            >
                        </div>

                        <div class="filter-group">
                            <label for="filterEndDate">End Date</label>
                            <input
                                type="date"
                                id="filterEndDate"
                                name="end_date"
                                value="<?= $escapeHtml($activityFilters['end_date']) ?>"
                            >
                        </div>

                        <div class="filter-group">
                            <label for="filterEventType">Event Type</label>
                            <input
                                type="text"
                                id="filterEventType"
                                name="event_type"
                                value="<?= $escapeHtml($activityFilters['event_type']) ?>"
                                placeholder="Example: LOGIN_FAILED"
                            >
                        </div>

                        <div class="filter-group">
                            <label for="filterUsername">Username</label>
                            <input
                                type="text"
                                id="filterUsername"
                                name="username"
                                value="<?= $escapeHtml($activityFilters['username']) ?>"
                                placeholder="Search username"
                            >
                        </div>

                        <div class="filter-group">
                            <label for="filterIpAddress">IP Address</label>
                            <input
                                type="text"
                                id="filterIpAddress"
                                name="ip_address"
                                value="<?= $escapeHtml($activityFilters['ip_address']) ?>"
                                placeholder="Search IP address"
                            >
                        </div>

                    </div>

                    <div class="filter-actions">

                        <button type="submit" id="applyFilters">
                            Apply Filters
                        </button>

                        <a href="admin_dashboard.php?view=activity-logs" id="resetFilters" class="secondary-button">
                            Reset Filters
                        </a>

                    </div>

                    <p id="filterMessage" role="status" aria-live="polite"></p>

                </form>


                <!-- ACTIVITY TABLE -->
                <div class="dashboard-panel table-container">

                    <table>
                        <thead>
                            <tr>
                                <th>Date and Time</th>
                                <th>Event Type</th>
                                <th>Username</th>
                                <th>IP Address</th>
                                <th>Details</th>
                            </tr>
                        </thead>

                        <tbody id="activityLogsTable">

                            <?php if (!$activityLogs): ?>

                                <tr>
                                    <td colspan="5">No activity records found.</td>
                                </tr>

                            <?php else: ?>

                                <?php foreach ($activityLogs as $log): ?>

                                    <tr>
                                        <td><?= $escapeHtml($log['created_at']) ?></td>
                                        <td><?= $escapeHtml($log['event_type']) ?></td>
                                        <td><?= $escapeHtml($log['username_typed']) ?></td>
                                        <td><?= $escapeHtml($log['ip_address']) ?></td>
                                        <td><?= $escapeHtml($log['details']) ?></td>
                                    </tr>

                                <?php endforeach; ?>

                            <?php endif; ?>

                        </tbody>
                    </table>

                </div>

            </section>


            <!-- TREASURER APPROVAL -->
            <section
                class="dashboard-section"
                <?= $currentView === 'treasurer-approval' ? '' : 'hidden' ?>
                id="treasurerApprovalSection"
            >

                <div class="section-heading">
                    <h2>Pending Treasurer Applications</h2>

                    <p>
                        Review applications from Treasurers who have verified
                        their email addresses.
                    </p>
                </div>

                <!-- CSRF TOKEN -->
                <input
                    type="hidden"
                    id="treasurerApprovalCsrf"
                    value="<?= $escapeHtml($csrf) ?>"
                >

                <!-- STATUS MESSAGE -->
                <p
                    id="treasurerApprovalMessage"
                    role="status"
                    aria-live="polite"
                >
                    Loading Treasurer applications...
                </p>

                <!-- APPLICATION TABLE -->
                <div class="dashboard-panel table-container">

                    <table>

                        <thead>
                            <tr>
                                <th>ID Number</th>
                                <th>Treasurer Name</th>
                                <th>Email Address</th>
                                <th>Organization</th>
                                <th>Application Date</th>
                                <th>Actions</th>
                            </tr>
                        </thead>

                        <tbody id="pendingTreasurersTable">

                            <tr>
                                <td colspan="6">
                                    Loading applications...
                                </td>
                            </tr>

                        </tbody>

                    </table>

                </div>

            </section>


            <!-- LAST UPDATED -->
            <footer class="dashboard-footer">

                <p>
                    Last updated:
                    <span id="lastUpdated">Waiting for data...</span>
                </p>

                <p>
                    Dashboard automatically refreshes every 60 seconds.
                </p>

            </footer>

        </main>

    </div>


    <!-- Chart.js library -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <!-- Dashboard JavaScript -->
    <script src="js/admin_dashboard.js?v=15"></script>

    <?= auth_session_timeout_markup() ?>

</body>
</html>
