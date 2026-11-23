<?php

require_once __DIR__ . '/backend/db.php';
require_once __DIR__ . '/backend/auth_guard.php';

auth_start_session();

$user = auth_require_treasurer($pdo, 'APPROVED');

// Escape output before displaying it in HTML.
function e($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

// Get the organization assigned to the logged-in Treasurer.
$organizationStatement = $pdo->prepare(
    'SELECT
        o.organization_id,
        o.organization_name,
        o.organization_acronym
     FROM organization_treasurers ot
     INNER JOIN organizations o
        ON ot.organization_id = o.organization_id
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

// Get search keyword.
$search = $_GET['search'] ?? '';

if (!is_string($search)) {
    $search = '';
}

$search = trim(substr($search, 0, 100));

// Retrieve members and calculate payment information.
$sql = "
    SELECT
        mr.membership_id,
        mr.student_id_number,
        mr.full_name,
        mr.program,
        mr.year_level,
        mr.academic_year,
        mr.membership_status,
        mr.total_fee,

        COALESCE(payments.total_paid, 0) AS total_paid,
        GREATEST(
            COALESCE(payments.total_paid, 0) - mr.total_fee,
            0
        ) AS excess_payment,

        CASE
            WHEN COALESCE(payments.total_paid, 0) <= 0 THEN 'Unpaid'
            WHEN COALESCE(payments.total_paid, 0) < mr.total_fee
                THEN 'Partially Paid'
            ELSE 'Fully Paid'
        END AS payment_status

    FROM membership_records mr

    LEFT JOIN (
        SELECT
            membership_id,
            SUM(amount_paid) AS total_paid
        FROM membership_payments
        GROUP BY membership_id
    ) payments
        ON payments.membership_id = mr.membership_id

    WHERE mr.organization_id = :organization_id
";

$params = [
    'organization_id' => $organizationId
];

// Add search conditions.
if ($search !== '') {
    $sql .= "
        AND (
            mr.student_id_number LIKE :student_id
            OR mr.full_name LIKE :full_name
            OR mr.program LIKE :program
            OR mr.academic_year LIKE :academic_year
        )
    ";

    $searchValue = '%' . $search . '%';

    $params['student_id'] = $searchValue;
    $params['full_name'] = $searchValue;
    $params['program'] = $searchValue;
    $params['academic_year'] = $searchValue;
}

$sql .= " ORDER BY mr.full_name ASC";

$memberStatement = $pdo->prepare($sql);
$memberStatement->execute($params);

$members = $memberStatement->fetchAll();

// Calculate summary totals.
$totalMembers = count($members);
$totalFees = 0;
$totalPaid = 0;
$totalBalance = 0;
$totalExcessPayments = 0;
$overpaidMemberCount = 0;

foreach ($members as $member) {
    $fee = (float) $member['total_fee'];
    $paid = (float) $member['total_paid'];

    $totalFees += $fee;
    $totalPaid += $paid;
    $totalBalance += $fee - $paid;

    $excessPayment = (float) $member['excess_payment'];
    if ($excessPayment > 0) {
        $overpaidMemberCount++;
        $totalExcessPayments += $excessPayment;
    }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>View Members | Organization Fee System</title>

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
            width: 100%;
            max-width: 1200px;
            margin: 0 auto;
        }

        h1,
        h2 {
            color: #1f5f36;
        }

        h1 {
            margin-bottom: 8px;
        }

        p {
            color: #4f765b;
        }

        .organization-name {
            margin-bottom: 25px;
            font-weight: bold;
        }

        /* Summary cards */

        .summary {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 25px;
        }

        .summary-card {
            padding: 18px;
            border: 1px solid #d9eadf;
            border-radius: 10px;
            background: #ffffff;
        }

        .summary-card h3 {
            margin: 0 0 10px;
            color: #4f765b;
            font-size: 14px;
            font-weight: normal;
        }

        .summary-card p {
            margin: 0;
            color: #1f5f36;
            font-size: 22px;
            font-weight: bold;
        }

        /* Search */

        .search-section {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }

        .search-section input {
            flex: 1;
            min-width: 0;
            padding: 12px;
            border: 1px solid #b8d5c1;
            border-radius: 7px;
            color: #1f5f36;
            font-size: 14px;
        }

        .search-section input:focus {
            outline: 2px solid #8fc5a0;
            border-color: #286b43;
        }

        /* Buttons */

        button,
        .back-button,
        .record-button {
            display: inline-block;
            padding: 10px 15px;
            border: none;
            border-radius: 7px;
            background: #286b43;
            color: #ffffff;
            font-size: 13px;
            font-weight: bold;
            text-decoration: none;
            cursor: pointer;
            white-space: nowrap;
        }

        button:hover,
        .back-button:hover,
        .record-button:hover {
            background: #155c35;
        }

        .clear-button {
            background: #6b8f76;
        }

        .clear-button:hover {
            background: #4f765b;
        }

        .record-button {
            padding: 8px 12px;
            font-size: 12px;
        }

        /* Table */

        .table-container {
            width: 100%;
            overflow-x: auto;
            border: 1px solid #d9eadf;
            border-radius: 10px;
        }

        table {
            width: 100%;
            min-width: 1150px;
            border-collapse: collapse;
        }

        th,
        td {
            padding: 13px 12px;
            border-bottom: 1px solid #e4eee7;
            text-align: left;
            font-size: 13px;
        }

        th {
            background: #edf8f0;
            color: #1f5f36;
            font-weight: bold;
        }

        td {
            color: #315f40;
        }

        tr:last-child td {
            border-bottom: none;
        }

        tbody tr:hover {
            background: #f7fbf8;
        }

        /* Status labels */

        .status {
            display: inline-block;
            padding: 5px 9px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: bold;
            white-space: nowrap;
        }

        .active,
        .paid {
            background: #e1f4e6;
            color: #216b38;
        }

        .inactive {
            background: #f1e8e8;
            color: #914040;
        }

        .partial {
            background: #fff2d6;
            color: #8a6415;
        }

        .unpaid {
            background: #f9e4e4;
            color: #a33333;
        }

        .review {
            background: #fff2d6;
            color: #8a6415;
        }

        .review-alert {
            margin: 0 0 20px;
            padding: 13px 15px;
            border: 1px solid #e8c98c;
            border-radius: 8px;
            background: #fff8e6;
            color: #785315;
        }

        .empty-message {
            padding: 30px;
            text-align: center;
            color: #6b8f76;
        }

        .bottom-actions {
            margin-top: 25px;
        }

        /* Responsive layout */

        @media (max-width: 800px) {

            body {
                padding: 18px;
            }

            .summary {
                grid-template-columns: repeat(2, 1fr);
            }

        }

        @media (max-width: 480px) {

            .summary {
                grid-template-columns: 1fr;
            }

            .search-section {
                flex-direction: column;
            }

            .search-section button,
            .search-section a {
                text-align: center;
            }

        }

    </style>

</head>

<body>

<div class="container">

    <h1>Organization Members</h1>

    <p class="organization-name">
        <?= e($organization['organization_name']) ?>
        (<?= e($organization['organization_acronym']) ?>)
    </p>

    <!-- Membership summary -->

    <div class="summary">

        <div class="summary-card">
            <h3>Members Found</h3>
            <p><?= number_format($totalMembers) ?></p>
        </div>

        <div class="summary-card">
            <h3>Total Expected Collection</h3>
            <p>₱<?= number_format($totalFees, 2) ?></p>
        </div>

        <div class="summary-card">
            <h3>Total Amount Collected</h3>
            <p>₱<?= number_format($totalPaid, 2) ?></p>
        </div>

        <div class="summary-card">
            <h3>Outstanding Balance</h3>
            <p>₱<?= number_format($totalBalance, 2) ?></p>
        </div>

    </div>

    <?php if ($overpaidMemberCount > 0): ?>
        <div class="review-alert">
            <?= number_format($overpaidMemberCount) ?> member record(s) need
            excess-payment review. Total excess: ₱<?= number_format($totalExcessPayments, 2) ?>.
        </div>
    <?php endif; ?>

    <h2>Member Records</h2>

    <!-- Search form -->

    <form method="GET" action="view_members.php" class="search-section">

        <input
            type="text"
            name="search"
            placeholder="Search Student ID, name, program, or academic year..."
            value="<?= e($search) ?>"
            maxlength="100"
        >

        <button type="submit">Search</button>

        <?php if ($search !== ''): ?>

            <a href="view_members.php" class="back-button clear-button">
                Clear
            </a>

        <?php endif; ?>

    </form>

    <!-- Members table -->

    <div class="table-container">

        <?php if (count($members) > 0): ?>

            <table>

                <thead>

                    <tr>
                        <th>Student ID</th>
                        <th>Full Name</th>
                        <th>Program</th>
                        <th>Year Level</th>
                        <th>Academic Year</th>
                        <th>Membership Fee</th>
                        <th>Total Paid</th>
                        <th>Outstanding Balance</th>
                        <th>Excess Payment Review</th>
                        <th>Membership Status</th>
                        <th>Payment Status</th>
                        <th>Action</th>
                    </tr>

                </thead>

                <tbody>

                    <?php foreach ($members as $member): ?>

                        <?php

                            $fee = (float) $member['total_fee'];
                            $paid = (float) $member['total_paid'];

                            $balance = $fee - $paid;
                            $excessPayment = (float) $member['excess_payment'];

                            $membershipStatus =
                                $member['membership_status'] ?? 'INACTIVE';

                            $paymentClass = 'unpaid';

                            if ($member['payment_status'] === 'Fully Paid') {
                                $paymentClass = 'paid';
                            } elseif ($member['payment_status'] === 'Partially Paid') {
                                $paymentClass = 'partial';
                            } elseif ($member['payment_status'] === 'Unpaid') {
                                $paymentClass = 'unpaid';
                            }

                        ?>

                        <tr>

                            <td>
                                <?= e($member['student_id_number']) ?>
                            </td>

                            <td>
                                <?= e($member['full_name']) ?>
                            </td>

                            <td>
                                <?= e($member['program']) ?>
                            </td>

                            <td>
                                <?= e($member['year_level']) ?>
                            </td>

                            <td>
                                <?= e($member['academic_year']) ?>
                            </td>

                            <td>
                                ₱<?= number_format($fee, 2) ?>
                            </td>

                            <td>
                                ₱<?= number_format($paid, 2) ?>
                            </td>

                            <td>
                                ₱<?= number_format($balance, 2) ?>
                            </td>

                            <td>
                                <?php if ($excessPayment > 0): ?>
                                    <span class="status review">
                                        Review: ₱<?= number_format($excessPayment, 2) ?>
                                    </span>
                                <?php else: ?>
                                    —
                                <?php endif; ?>
                            </td>

                            <td>

                                <span class="status <?= $membershipStatus === 'ACTIVE' ? 'active' : 'inactive' ?>">
                                    <?= e($membershipStatus) ?>
                                </span>

                            </td>

                            <td>

                                <span class="status <?= e($paymentClass) ?>">
                                    <?= e($member['payment_status']) ?>
                                </span>

                            </td>

                            <!-- Record Payment button -->

                            <td>

                                <?php if ($balance > 0): ?>

                                    <a
                                        href="record_payment.php?membership_id=<?= (int) $member['membership_id'] ?>"
                                        class="record-button"
                                    >
                                        Record Payment
                                    </a>

                                <?php else: ?>

                                    <span class="status paid">
                                        Completed
                                    </span>

                                <?php endif; ?>

                            </td>

                        </tr>

                    <?php endforeach; ?>

                </tbody>

            </table>

        <?php else: ?>

            <div class="empty-message">

                <?php if ($search !== ''): ?>

                    <p>
                        No members found matching
                        "<strong><?= e($search) ?></strong>".
                    </p>

                <?php else: ?>

                    <p>No member records have been added yet.</p>

                <?php endif; ?>

            </div>

        <?php endif; ?>

    </div>

    <!-- Back to dashboard -->

    <div class="bottom-actions">

        <a href="treasurer_dashboard.php" class="back-button">
            Back to Dashboard
        </a>

    </div>

</div>

<?= auth_session_timeout_markup() ?>
</body>
</html>
