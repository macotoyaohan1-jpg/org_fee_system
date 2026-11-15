
<?php

require_once __DIR__ . '/backend/db.php';
require_once __DIR__ . '/backend/auth_guard.php';

auth_start_session();

$user = auth_require_treasurer($pdo, 'APPROVED');

// Escape HTML output.
function history_e($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

// Get the Treasurer's assigned organization.
$organizationStatement = $pdo->prepare(
    'SELECT o.organization_id, o.organization_name, o.organization_acronym
     FROM organization_treasurers ot
     INNER JOIN organizations o
        ON o.organization_id = ot.organization_id
     WHERE ot.treasurer_id = :treasurer_id
     LIMIT 1'
);

$organizationStatement->execute([
    'treasurer_id' => $user['id_number']
]);

$organization = $organizationStatement->fetch();

if (!$organization) {
    header('Location: access_denied.php');
    exit;
}

$organizationId = (int) $organization['organization_id'];

// Get the search input.
$search = trim($_GET['search'] ?? '');

if (strlen($search) > 100) {
    $search = substr($search, 0, 100);
}

// Build the payment history query.
$sql = "
    SELECT
        mp.payment_id,
        mp.amount_paid,
        mp.payment_method,
        mp.reference_number,
        mp.payment_date,
        mp.remarks,
        mp.recorded_by,

        mr.student_id_number,
        mr.full_name,
        mr.program,
        mr.year_level,
        mr.academic_year,

        CONCAT_WS(
            ' ',
            NULLIF(u.first_name, ''),
            NULLIF(u.middle_name, ''),
            NULLIF(u.family_name, '')
        ) AS recorded_by_name

    FROM membership_payments mp

    INNER JOIN membership_records mr
        ON mr.membership_id = mp.membership_id

    LEFT JOIN users u
        ON u.id_number = mp.recorded_by

    WHERE mr.organization_id = :organization_id
";

$params = [
    'organization_id' => $organizationId
];

// Add search conditions when a search term is entered.
if ($search !== '') {

    $sql .= "
        AND (
            mr.student_id_number LIKE :student_id
            OR mr.full_name LIKE :full_name
            OR mp.payment_method LIKE :payment_method
            OR mp.reference_number LIKE :reference_number
        )
    ";

    $searchTerm = '%' . $search . '%';

    $params['student_id'] = $searchTerm;
    $params['full_name'] = $searchTerm;
    $params['payment_method'] = $searchTerm;
    $params['reference_number'] = $searchTerm;
}

$sql .= "
    ORDER BY mp.payment_date DESC, mp.payment_id DESC
";

$paymentStatement = $pdo->prepare($sql);
$paymentStatement->execute($params);

$payments = $paymentStatement->fetchAll();

// Calculate summary information for the displayed results.
$totalPayments = count($payments);
$totalAmount = 0;

foreach ($payments as $payment) {
    $totalAmount += (float) $payment['amount_paid'];
}

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Payment History | Organization Fee System</title>

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            padding: 30px;
            background: #ffffff;
            color: #1f5f36;
            font-family: Arial, sans-serif;
        }

        .container {
            max-width: 1250px;
            margin: 0 auto;
        }

        h1,
        h2 {
            color: #1f5f36;
        }

        p {
            color: #4f765b;
        }

        .organization-name {
            font-weight: bold;
            color: #286b43;
        }

        .summary-container {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 18px;
            margin: 25px 0;
        }

        .summary-card {
            padding: 22px;
            border: 1px solid #d9eadf;
            border-radius: 10px;
            background: #ffffff;
        }

        .summary-card h3 {
            margin: 0 0 12px;
            color: #4f765b;
            font-size: 14px;
        }

        .summary-value {
            margin: 0;
            color: #1f5f36;
            font-size: 26px;
            font-weight: bold;
        }

        .history-section {
            padding: 22px;
            border: 1px solid #d9eadf;
            border-radius: 10px;
            background: #ffffff;
        }

        .search-form {
            display: flex;
            gap: 10px;
            margin: 20px 0;
        }

        .search-form input {
            flex: 1;
            min-width: 0;
            padding: 12px;
            border: 1px solid #b8d5c1;
            border-radius: 7px;
            color: #1f5f36;
            background: #ffffff;
            font-size: 14px;
        }

        .search-form input:focus {
            outline: 2px solid #8fc5a0;
            border-color: #286b43;
        }

        button,
        .back-button,
        .clear-button {
            display: inline-block;
            padding: 12px 18px;
            border: none;
            border-radius: 7px;
            background: #286b43;
            color: #ffffff;
            font-size: 14px;
            font-weight: bold;
            text-decoration: none;
            cursor: pointer;
        }

        button:hover,
        .back-button:hover {
            background: #155c35;
        }

        .clear-button {
            background: #e8f3eb;
            color: #1f5f36;
        }

        .clear-button:hover {
            background: #d5eadb;
        }

        .table-wrapper {
            width: 100%;
            overflow-x: auto;
        }

        table {
            width: 100%;
            min-width: 1150px;
            border-collapse: collapse;
        }

        th,
        td {
            padding: 13px;
            border-bottom: 1px solid #e1eee5;
            text-align: left;
            vertical-align: top;
            font-size: 13px;
        }

        th {
            background: #edf7f0;
            color: #1f5f36;
            font-weight: bold;
            white-space: nowrap;
        }

        td {
            color: #355e41;
        }

        tr:hover td {
            background: #f8fcf9;
        }

        .amount {
            color: #1f5f36;
            font-weight: bold;
            white-space: nowrap;
        }

        .reference {
            overflow-wrap: anywhere;
        }

        .empty-message {
            padding: 30px;
            text-align: center;
            color: #6b8f76;
        }

        .bottom-actions {
            margin-top: 22px;
        }

        @media (max-width: 650px) {

            body {
                padding: 16px;
            }

            .summary-container {
                grid-template-columns: 1fr;
            }

            .search-form {
                flex-wrap: wrap;
            }

            .search-form input {
                flex-basis: 100%;
            }

            .search-form button,
            .search-form a {
                flex: 1;
                text-align: center;
            }

            .history-section {
                padding: 15px;
            }
        }

    </style>

</head>

<body>

<div class="container">

    <h1>Payment History</h1>

    <p>
        View and monitor all membership fee payments recorded
        for your assigned organization.
    </p>

    <p class="organization-name">
        <?= history_e($organization['organization_name']) ?>
        (<?= history_e($organization['organization_acronym']) ?>)
    </p>

    <div class="summary-container">

        <div class="summary-card">

            <h3>Payments Found</h3>

            <p class="summary-value">
                <?= number_format($totalPayments) ?>
            </p>

        </div>

        <div class="summary-card">

            <h3>Total Amount Received</h3>

            <p class="summary-value">
                &#8369;<?= number_format($totalAmount, 2) ?>
            </p>

        </div>

    </div>

    <div class="history-section">

        <h2>Payment Records</h2>

        <p>
            Search using the Student ID, full name,
            payment method, or reference number.
        </p>

        <form method="GET" action="payment_history.php" class="search-form">

            <input
                type="search"
                name="search"
                placeholder="Search payment records..."
                value="<?= history_e($search) ?>"
                maxlength="100"
            >

            <button type="submit">
                Search
            </button>

            <a href="payment_history.php" class="clear-button">
                Clear
            </a>

        </form>

        <div class="table-wrapper">

            <table>

                <thead>

                    <tr>
                        <th>Payment ID</th>
                        <th>Student ID</th>
                        <th>Full Name</th>
                        <th>Academic Year</th>
                        <th>Amount Paid</th>
                        <th>Payment Method</th>
                        <th>Reference Number</th>
                        <th>Payment Date</th>
                        <th>Recorded By</th>
                        <th>Remarks</th>
                    </tr>

                </thead>

                <tbody>

                    <?php if (empty($payments)): ?>

                        <tr>
                            <td colspan="10" class="empty-message">
                                No payment records found.
                            </td>
                        </tr>

                    <?php else: ?>

                        <?php foreach ($payments as $payment): ?>

                            <tr>

                                <td>
                                    #<?= (int) $payment['payment_id'] ?>
                                </td>

                                <td>
                                    <?= history_e($payment['student_id_number']) ?>
                                </td>

                                <td>
                                    <?= history_e($payment['full_name']) ?>
                                </td>

                                <td>
                                    <?= history_e($payment['academic_year']) ?>
                                </td>

                                <td class="amount">
                                    &#8369;<?= number_format((float) $payment['amount_paid'], 2) ?>
                                </td>

                                <td>
                                    <?= history_e($payment['payment_method']) ?>
                                </td>

                                <td class="reference">
                                    <?= $payment['reference_number'] !== null
                                        && $payment['reference_number'] !== ''
                                        ? history_e($payment['reference_number'])
                                        : '—' ?>
                                </td>

                                <td>
                                    <?= history_e(
                                        date(
                                            'M d, Y h:i A',
                                            strtotime($payment['payment_date'])
                                        )
                                    ) ?>
                                </td>

                                <td>
                                    <?= history_e(
                                        $payment['recorded_by_name'] ?: $payment['recorded_by']
                                    ) ?>
                                </td>

                                <td>
                                    <?= $payment['remarks'] !== null
                                        && $payment['remarks'] !== ''
                                        ? history_e($payment['remarks'])
                                        : '—' ?>
                                </td>

                            </tr>

                        <?php endforeach; ?>

                    <?php endif; ?>

                </tbody>

            </table>

        </div>

    </div>

    <div class="bottom-actions">

        <a href="treasurer_dashboard.php" class="back-button">
            Back to Dashboard
        </a>

    </div>

</div>

</body>
</html>
