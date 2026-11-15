
document.addEventListener('DOMContentLoaded', function () {

    // API location
    const API_URL = new URL('backend/admin_dashboard_api.php', document.baseURI);

    // Treasurer Approval API location
    const TREASURER_API_URL = new URL(
        'backend/admin_treasurer_approval_api.php',
        document.baseURI
    );
    // Chart variable
    let failedLoginChart = null;


    /*
    |--------------------------------------------------------------------------
    | HELPER: FORMAT DATE AND TIME
    |--------------------------------------------------------------------------
    */

    function formatDateTime(value) {

        if (!value) {
            return 'N/A';
        }

        const date = new Date(value.replace(' ', 'T'));

        if (Number.isNaN(date.getTime())) {
            return value;
        }

        return date.toLocaleString();
    }


    /*
    |--------------------------------------------------------------------------
    | HELPER: CREATE TABLE CELL
    |--------------------------------------------------------------------------
    */

    function createCell(value) {

        const cell = document.createElement('td');

        // textContent prevents database values from being treated as HTML.
        cell.textContent =
            value === null || value === undefined || value === ''
                ? 'N/A'
                : String(value);

        return cell;
    }


    /*
    |--------------------------------------------------------------------------
    | HELPER: DISPLAY TABLE MESSAGE
    |--------------------------------------------------------------------------
    */

    function showTableMessage(tableId, message, columnCount) {

        const tableBody = document.getElementById(tableId);

        tableBody.replaceChildren();

        const row = document.createElement('tr');
        const cell = document.createElement('td');

        cell.colSpan = columnCount;
        cell.textContent = message;

        row.appendChild(cell);
        tableBody.appendChild(row);
    }


    /*
    |--------------------------------------------------------------------------
    | DISPLAY SECURITY SUMMARY
    |--------------------------------------------------------------------------
    */

    function displaySummary(summary) {

        document.getElementById('totalAttempts').textContent =
            summary.total_attempts ?? 0;

        document.getElementById('successfulLogins').textContent =
            summary.successful_logins ?? 0;

        document.getElementById('failedLogins').textContent =
            summary.failed_logins ?? 0;

        document.getElementById('activeIpBlocks').textContent =
            summary.active_ip_blocks ?? 0;

        document.getElementById('securityFlags').textContent =
            summary.security_flags ?? 0;
    }


    /*
    |--------------------------------------------------------------------------
    | DISPLAY FAILED LOGIN CHART
    |--------------------------------------------------------------------------
    */

    function displayFailedLoginChart(chartData) {

        const canvas = document.getElementById('failedLoginChart');

        // Chart.js must be loaded before creating the chart.
        if (typeof Chart === 'undefined') {

            console.error('Chart.js could not be loaded.');

            return;
        }

        // Remove the previous chart before refreshing.
        if (failedLoginChart !== null) {
            failedLoginChart.destroy();
        }

        failedLoginChart = new Chart(canvas, {

            type: 'line',

            data: {

                labels: chartData.labels ?? [],

                datasets: [{
                    label: 'Failed Login Attempts',

                    data: chartData.counts ?? [],

                    borderColor: '#7660b5',

                    backgroundColor: 'rgba(118, 96, 181, 0.12)',

                    borderWidth: 2,

                    fill: true,

                    tension: 0.3,

                    pointRadius: 3
                }]

            },

            options: {

                responsive: true,

                maintainAspectRatio: true,

                plugins: {

                    legend: {
                        display: true
                    }

                },

                scales: {

                    y: {
                        beginAtZero: true,

                        ticks: {
                            precision: 0
                        }
                    }

                }

            }

        });
    }


    /*
    |--------------------------------------------------------------------------
    | DISPLAY TOP IP ADDRESSES
    |--------------------------------------------------------------------------
    */

    function displayTopIPs(ipList) {

        const tableBody = document.getElementById('ipAddressTable');

        tableBody.replaceChildren();

        if (!ipList || ipList.length === 0) {

            showTableMessage(
                'ipAddressTable',
                'No failed login attempts recorded in the last 24 hours.',
                4
            );

            return;
        }

        ipList.forEach(function (ip) {

            const row = document.createElement('tr');

            row.appendChild(createCell(ip.ip_address));

            row.appendChild(createCell(ip.failed_attempts));

            const statusCell = document.createElement('td');

            statusCell.textContent = ip.block_status;

            row.appendChild(statusCell);

            row.appendChild(
                createCell(
                    ip.blocked_until
                        ? formatDateTime(ip.blocked_until)
                        : 'N/A'
                )
            );

            tableBody.appendChild(row);

        });
    }


    /*
    |--------------------------------------------------------------------------
    | DISPLAY SECURITY FLAGS
    |--------------------------------------------------------------------------
    */

    function displaySecurityFlags(flags) {

        const tableBody = document.getElementById('securityFlagsTable');

        tableBody.replaceChildren();

        if (!flags || flags.length === 0) {

            showTableMessage(
                'securityFlagsTable',
                'No security flags have been recorded.',
                5
            );

            return;
        }

        flags.forEach(function (flag) {

            const row = document.createElement('tr');

            row.appendChild(createCell(flag.flag_type));

            row.appendChild(createCell(flag.description));

            row.appendChild(createCell(flag.related_ip));

            row.appendChild(createCell(flag.related_username));

            row.appendChild(
                createCell(formatDateTime(flag.detected_at))
            );

            tableBody.appendChild(row);

        });
    }


    /*
    |--------------------------------------------------------------------------
    | DISPLAY ACTIVITY LOGS
    |--------------------------------------------------------------------------
    */

    function displayActivityLogs(logs) {

        const tableBody = document.getElementById('activityLogsTable');

        tableBody.replaceChildren();

        if (!logs || logs.length === 0) {

            showTableMessage(
                'activityLogsTable',
                'No activity records found.',
                5
            );

            return;
        }

        logs.forEach(function (log) {

            const row = document.createElement('tr');

            row.appendChild(
                createCell(formatDateTime(log.created_at))
            );

            row.appendChild(createCell(log.event_type));

            row.appendChild(createCell(log.username_typed));

            row.appendChild(createCell(log.ip_address));

            row.appendChild(createCell(log.details));

            tableBody.appendChild(row);

        });
    }


    /*
    |--------------------------------------------------------------------------
    | GET ACTIVITY LOG FILTERS
    |--------------------------------------------------------------------------
    */

    function getFilters() {

        return {

            start_date:
                document.getElementById('filterStartDate').value,

            end_date:
                document.getElementById('filterEndDate').value,

            event_type:
                document.getElementById('filterEventType').value.trim(),

            username:
                document.getElementById('filterUsername').value.trim(),

            ip_address:
                document.getElementById('filterIpAddress').value.trim()

        };
    }


    /*
    |--------------------------------------------------------------------------
    | LOAD DASHBOARD DATA
    |--------------------------------------------------------------------------
    */

    async function loadDashboard() {

        const startDate = document.getElementById('filterStartDate').value;
        const endDate = document.getElementById('filterEndDate').value;
        const filterMessage = document.getElementById('filterMessage');

        if (startDate && endDate && startDate > endDate) {
            filterMessage.textContent = 'Start date cannot be later than end date.';
            document.getElementById('filterEndDate').focus();
            return;
        }

        filterMessage.textContent = '';

        try {

            const filters = getFilters();

            const query = new URLSearchParams(filters);

            const requestUrl = new URL(API_URL.href);
            query.forEach((value, key) => requestUrl.searchParams.set(key, value));

            const response = await fetch(
                requestUrl.href,
                {
                    method: 'GET',
                    cache: 'no-store',
                    redirect: 'error',

                    credentials: 'same-origin',

                    headers: {
                        'Accept': 'application/json'
                    }
                }
            );

            const responseBody = await response.text();
            let result;
            try {
                result = JSON.parse(responseBody);
            } catch (parseError) {
                const responseIsHtml = response.headers.get('content-type')?.includes('text/html') ||
                    responseBody.trimStart().startsWith('<');
                throw new Error(responseIsHtml
                    ? `The dashboard API returned an HTML page (HTTP ${response.status}). Sign in again, then reload the dashboard.`
                    : `The dashboard API returned invalid JSON (HTTP ${response.status}).`);
            }

            if (!response.ok || !result.success) {

                throw new Error(
                    result.message || 'Unable to load dashboard information.'
                );
            }

            const data = result.data;

            // Update all dashboard sections.
            displaySummary(data.summary);

            displayFailedLoginChart(data.failed_logins_chart);

            displayTopIPs(data.top_ips);

            displaySecurityFlags(data.security_flags);

            displayActivityLogs(data.activity_logs);
            filterMessage.textContent = data.activity_logs.length === 0
                ? 'No activity logs match these filters.'
                : `Showing ${data.activity_logs.length} matching activity log(s), up to 50.`;

            // Show the latest refresh time.
            document.getElementById('lastUpdated').textContent =
                formatDateTime(result.last_updated);

        } catch (error) {

            console.error('Dashboard loading error:', error);

            filterMessage.textContent = error.message;

            document.getElementById('lastUpdated').textContent =
                'Unable to update dashboard.';

            showTableMessage(
                'ipAddressTable',
                'Unable to load IP address information.',
                4
            );

            showTableMessage(
                'securityFlagsTable',
                'Unable to load security flags.',
                5
            );

        }
    }


    /*
    |--------------------------------------------------------------------------
    | APPLY FILTERS BUTTON
    |--------------------------------------------------------------------------
    */

    /*
    |--------------------------------------------------------------------------
    | TREASURER APPROVAL
    |--------------------------------------------------------------------------
    */

    // Load pending Treasurer applications.
    async function loadPendingTreasurers() {

        const tableBody = document.getElementById('pendingTreasurersTable');
        const message = document.getElementById('treasurerApprovalMessage');

        // Do nothing if the Treasurer Approval section is not on this page.
        if (!tableBody || !message) {
            return;
        }

        message.textContent = 'Loading Treasurer applications...';

        try {

            const response = await fetch(TREASURER_API_URL.href, {
                method: 'GET',
                cache: 'no-store',
                redirect: 'error',
                credentials: 'same-origin',
                headers: {
                    'Accept': 'application/json'
                }
            });

            const result = await response.json();

            if (!response.ok || !result.success) {
                throw new Error(
                    result.message || 'Unable to load applications.'
                );
            }

            tableBody.replaceChildren();

            const applications = result.applications ?? [];

            if (applications.length === 0) {

                showTableMessage(
                    'pendingTreasurersTable',
                    'No pending verified Treasurer applications.',
                    6
                );

                message.textContent = 'No applications need review.';
                return;
            }

            applications.forEach(function (application) {

                const row = document.createElement('tr');

                row.appendChild(createCell(application.id_number));
                row.appendChild(createCell(application.full_name));
                row.appendChild(createCell(application.email));
                row.appendChild(createCell(application.organization_name));
                row.appendChild(createCell(
                    formatDateTime(application.created_at)
                ));

                const actionCell = document.createElement('td');

                // Approve button.
                const approveButton = document.createElement('button');
                approveButton.type = 'button';
                approveButton.textContent = 'Approve';
                approveButton.className = 'approval-button approve-button';

                approveButton.addEventListener('click', function () {
                    processTreasurerApplication(
                        application.id_number,
                        'approve'
                    );
                });

                // Reject button.
                const rejectButton = document.createElement('button');
                rejectButton.type = 'button';
                rejectButton.textContent = 'Reject';
                rejectButton.className = 'approval-button reject-button';

                rejectButton.addEventListener('click', function () {
                    processTreasurerApplication(
                        application.id_number,
                        'reject'
                    );
                });

                actionCell.appendChild(approveButton);
                actionCell.appendChild(rejectButton);

                row.appendChild(actionCell);

                tableBody.appendChild(row);

            });

            message.textContent =
                `Found ${applications.length} pending Treasurer application(s).`;

        } catch (error) {

            console.error('Treasurer approval loading error:', error);

            message.textContent = error.message;

            showTableMessage(
                'pendingTreasurersTable',
                'Unable to load Treasurer applications.',
                6
            );

        }
    }


    // Approve or reject a Treasurer application.
    async function processTreasurerApplication(idNumber, action) {

        const actionName = action === 'approve' ? 'approve' : 'reject';

        const confirmed = window.confirm(
            `Are you sure you want to ${actionName} Treasurer ${idNumber}?`
        );

        if (!confirmed) {
            return;
        }

        const csrfToken = document.getElementById(
            'treasurerApprovalCsrf'
        )?.value;

        if (!csrfToken) {
            alert('Security token is missing. Please refresh the page.');
            return;
        }

        const formData = new FormData();

        formData.append('csrf_token', csrfToken);
        formData.append('action', action);
        formData.append('id_number', idNumber);

        try {

            const response = await fetch(TREASURER_API_URL.href, {
                method: 'POST',
                cache: 'no-store',
                redirect: 'error',
                credentials: 'same-origin',
                headers: {
                    'Accept': 'application/json'
                },
                body: formData
            });

            const result = await response.json();

            if (!response.ok || !result.success) {
                throw new Error(
                    result.message || 'Unable to process application.'
                );
            }

            alert(result.message);

            // Refresh the pending applications after processing.
            loadPendingTreasurers();

        } catch (error) {

            console.error('Treasurer approval action error:', error);

            alert(error.message);

        }
    }


    /*
    |--------------------------------------------------------------------------
    | LOAD TREASURER APPROVAL SECTION
    |--------------------------------------------------------------------------
    */

    loadPendingTreasurers();

    /*
    |--------------------------------------------------------------------------
    | INITIAL DASHBOARD LOAD
    |--------------------------------------------------------------------------
    */

    loadDashboard();


    /*
    |--------------------------------------------------------------------------
    | AUTOMATIC REFRESH EVERY 60 SECONDS
    |--------------------------------------------------------------------------
    */

    setInterval(function () {

        loadDashboard();

    }, 60000);

});
