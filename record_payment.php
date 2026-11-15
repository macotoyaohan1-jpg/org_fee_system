
<?php

require_once __DIR__ . '/backend/db.php';
require_once __DIR__ . '/backend/auth_guard.php';

auth_start_session();

$user = auth_require_treasurer($pdo, 'APPROVED');

// Create a CSRF token.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Escape HTML output.
function e($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

// Validate the membership ID.
$membershipId = filter_input(INPUT_GET, 'membership_id', FILTER_VALIDATE_INT);

if (!$membershipId || $membershipId < 1) {
    http_response_code(400);
    exit('Invalid membership record.');
}

// Get the Treasurer's assigned organization.
$organizationStatement = $pdo->prepare(
    'SELECT organization_id
     FROM organization_treasurers
     WHERE treasurer_id = :treasurer_id
     LIMIT 1'
);

$organizationStatement->execute([
    'treasurer_id' => $user['id_number']
]);

$organizationId = $organizationStatement->fetchColumn();

if (!$organizationId) {
    header('Location: access_denied.php');
    exit;
}

$error = '';
$success = isset($_GET['success']) && $_GET['success'] === '1';

// Load the member and their payment totals.
function get_member_payment_details(
    PDO $pdo,
    int $membershipId,
    int $organizationId
): ?array {
    $statement = $pdo->prepare(
        "SELECT
            mr.membership_id,
            mr.student_id_number,
            mr.full_name,
            mr.program,
            mr.year_level,
            mr.academic_year,
            mr.total_fee,
            mr.membership_status,
            COALESCE(SUM(mp.amount_paid), 0) AS total_paid
         FROM membership_records mr
         LEFT JOIN membership_payments mp
            ON mp.membership_id = mr.membership_id
         WHERE mr.membership_id = :membership_id
           AND mr.organization_id = :organization_id
         GROUP BY
            mr.membership_id,
            mr.student_id_number,
            mr.full_name,
            mr.program,
            mr.year_level,
            mr.academic_year,
            mr.total_fee,
            mr.membership_status
         LIMIT 1"
    );

    $statement->execute([
        'membership_id' => $membershipId,
        'organization_id' => $organizationId
    ]);

    $member = $statement->fetch();

    return $member ?: null;
}

$member = get_member_payment_details(
    $pdo,
    $membershipId,
    (int) $organizationId
);

if (!$member) {
    http_response_code(404);
    exit('Member record not found in your assigned organization.');
}

// Process the payment form.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (!auth_csrf_is_valid()) {
        $error = 'Your session verification failed. Please refresh the page and try again.';
    } else {

        $amountInput = trim($_POST['amount_paid'] ?? '');
        $paymentMethod = trim($_POST['payment_method'] ?? '');
        $referenceNumber = trim($_POST['reference_number'] ?? '');
        $paymentDateInput = trim($_POST['payment_date'] ?? '');
        $remarks = trim($_POST['remarks'] ?? '');

        $allowedMethods = [
            'Cash',
            'GCash',
            'Bank Transfer',
            'Other'
        ];

        if (
            $amountInput === '' ||
            !preg_match('/^\d+(\.\d{1,2})?$/', $amountInput) ||
            (float) $amountInput <= 0
        ) {
            $error = 'Enter a valid payment amount greater than zero.';

        } elseif (!in_array($paymentMethod, $allowedMethods, true)) {
            $error = 'Please select a valid payment method.';

        } elseif (strlen($referenceNumber) > 100) {
            $error = 'The reference number must not exceed 100 characters.';

        } elseif (strlen($remarks) > 5000) {
            $error = 'Remarks are too long.';

        } else {

            $paymentDate = DateTime::createFromFormat(
                '!Y-m-d\TH:i',
                $paymentDateInput
            );

            $dateErrors = DateTime::getLastErrors();

            $validDate = $paymentDate !== false
                && (
                    $dateErrors === false ||
                    (
                        $dateErrors['warning_count'] === 0 &&
                        $dateErrors['error_count'] === 0
                    )
                )
                && $paymentDate->format('Y-m-d\TH:i') === $paymentDateInput;

            if (!$validDate) {
                $error = 'Please enter a valid payment date and time.';

            } else {

                try {
                    $pdo->beginTransaction();

                    // Lock the member record while checking the balance.
                    $lockStatement = $pdo->prepare(
                        'SELECT membership_id, total_fee
                         FROM membership_records
                         WHERE membership_id = :membership_id
                           AND organization_id = :organization_id
                         FOR UPDATE'
                    );

                    $lockStatement->execute([
                        'membership_id' => $membershipId,
                        'organization_id' => $organizationId
                    ]);

                    $lockedMember = $lockStatement->fetch();

                    if (!$lockedMember) {
                        throw new RuntimeException('Member record not found.');
                    }

                    // Calculate the latest amount already paid.
                    $paidStatement = $pdo->prepare(
                        'SELECT COALESCE(SUM(amount_paid), 0)
                         FROM membership_payments
                         WHERE membership_id = :membership_id'
                    );

                    $paidStatement->execute([
                        'membership_id' => $membershipId
                    ]);

                    $alreadyPaid = (float) $paidStatement->fetchColumn();
                    $totalFee = (float) $lockedMember['total_fee'];
                    $balance = max($totalFee - $alreadyPaid, 0);
                    $amount = (float) $amountInput;

                    if ($amount > $balance + 0.00001) {
                        throw new RuntimeException(
                            'The payment exceeds the remaining balance of PHP '
                            . number_format($balance, 2) . '.'
                        );
                    }

                    if ($balance <= 0) {
                        throw new RuntimeException(
                            'This member has no remaining balance.'
                        );
                    }

                    // Insert the payment record.
                    $insertStatement = $pdo->prepare(
                        'INSERT INTO membership_payments (
                            membership_id,
                            amount_paid,
                            payment_method,
                            reference_number,
                            payment_date,
                            recorded_by,
                            remarks
                        ) VALUES (
                            :membership_id,
                            :amount_paid,
                            :payment_method,
                            :reference_number,
                            :payment_date,
                            :recorded_by,
                            :remarks
                        )'
                    );

                    $insertStatement->execute([
                        'membership_id' => $membershipId,
                        'amount_paid' => number_format($amount, 2, '.', ''),
                        'payment_method' => $paymentMethod,
                        'reference_number' => $referenceNumber !== ''
                            ? $referenceNumber
                            : null,
                        'payment_date' => $paymentDate->format('Y-m-d H:i:s'),
                        'recorded_by' => $user['id_number'],
                        'remarks' => $remarks !== '' ? $remarks : null
                    ]);

                    // Commit the payment transaction.
                    $pdo->commit();

                    // Record the successful payment activity.
                    // This runs only after the payment has been committed.
                    try {

                        auth_log_event(
                            $pdo,
                            'PAYMENT_RECORDED',
                            null,
                            $user['id_number'],
                            'Recorded a payment of PHP '
                            . number_format($amount, 2)
                            . ' for Membership ID: '
                            . $membershipId
                            . ' using '
                            . $paymentMethod
                        );

                    } catch (Throwable $exception) {

                        // Do not undo a successful payment if logging fails.
                        error_log(
                            'Payment activity logging error: '
                            . $exception->getMessage()
                        );
                    }

                    // Redirect to prevent duplicate form submission.
                    header(
                        'Location: record_payment.php?membership_id='
                        . $membershipId . '&success=1'
                    );
                    exit;

                } catch (RuntimeException $exception) {

                    if ($pdo->inTransaction()) {
                        $pdo->rollBack();
                    }

                    $error = $exception->getMessage();

                } catch (PDOException $exception) {

                    if ($pdo->inTransaction()) {
                        $pdo->rollBack();
                    }

                    error_log('Payment recording error: ' . $exception->getMessage());

                    $error = 'Unable to record the payment. Please try again.';
                }
            }
        }
    }
}

// Refresh the member's payment details.
$member = get_member_payment_details(
    $pdo,
    $membershipId,
    (int) $organizationId
);

if (!$member) {
    http_response_code(404);
    exit('Member record not found.');
}

$totalFee = (float) $member['total_fee'];
$totalPaid = (float) $member['total_paid'];
$outstandingBalance = $totalFee - $totalPaid;
$paymentExcess = max($totalPaid - $totalFee, 0);
$balance = max($outstandingBalance, 0);

$paymentStatus = 'Unpaid';

if ($totalPaid > 0 && $totalPaid >= $totalFee) {
    $paymentStatus = 'Fully Paid';
} elseif ($totalPaid > 0 && $totalPaid < $totalFee) {
    $paymentStatus = 'Partially Paid';
}

// Keep entered values when validation fails.
$formAmount = $_POST['amount_paid'] ?? '';
$formMethod = $_POST['payment_method'] ?? '';
$formReference = $_POST['reference_number'] ?? '';
$formDate = $_POST['payment_date'] ?? date('Y-m-d\TH:i');
$formRemarks = $_POST['remarks'] ?? '';

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Record Payment | Organization Fee System</title>

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
            max-width: 750px;
            margin: 0 auto;
        }

        h1,
        h2 {
            color: #1f5f36;
        }

        p {
            color: #4f765b;
        }

        .member-card,
        .payment-form {
            padding: 22px;
            margin-bottom: 22px;
            border: 1px solid #d9eadf;
            border-radius: 10px;
            background: #ffffff;
        }

        .member-card p {
            margin: 9px 0;
        }

        .balance {
            color: #1f5f36;
            font-size: 24px;
            font-weight: bold;
        }

        .status {
            font-weight: bold;
        }

        .form-group {
            margin-bottom: 17px;
        }

        label {
            display: block;
            margin-bottom: 7px;
            color: #1f5f36;
            font-weight: bold;
        }

        input,
        select,
        textarea {
            width: 100%;
            padding: 12px;
            border: 1px solid #b8d5c1;
            border-radius: 7px;
            color: #1f5f36;
            background: #ffffff;
            font-size: 14px;
        }

        input:focus,
        select:focus,
        textarea:focus {
            outline: 2px solid #8fc5a0;
            border-color: #286b43;
        }

        textarea {
            min-height: 90px;
            resize: vertical;
        }

        .help-text {
            display: block;
            margin-top: 6px;
            color: #6b8f76;
            font-size: 12px;
        }

        button,
        .back-button {
            display: inline-block;
            padding: 12px 20px;
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

        .alert {
            padding: 13px;
            margin-bottom: 18px;
            border-radius: 7px;
        }

        .error {
            background: #f9e4e4;
            color: #a33333;
        }

        .success {
            background: #e1f4e6;
            color: #216b38;
        }

        .warning {
            background: #fff2d6;
            color: #8a6415;
        }

        .bottom-actions {
            margin-top: 20px;
        }

        @media (max-width: 600px) {
            body {
                padding: 16px;
            }
        }
    </style>
</head>

<body>

<div class="container">

    <h1>Record Membership Payment</h1>

    <p>Enter the payment details for the selected member.</p>

    <?php if ($success): ?>
        <div class="alert success">
            Payment recorded successfully!
        </div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="alert error">
            <?= e($error) ?>
        </div>
    <?php endif; ?>

    <div class="member-card">

        <h2>Member Information</h2>

        <p>
            <strong>Student ID:</strong>
            <?= e($member['student_id_number']) ?>
        </p>

        <p>
            <strong>Full Name:</strong>
            <?= e($member['full_name']) ?>
        </p>

        <p>
            <strong>Program:</strong>
            <?= e($member['program']) ?>
        </p>

        <p>
            <strong>Year Level:</strong>
            <?= e($member['year_level']) ?>
        </p>

        <p>
            <strong>Academic Year:</strong>
            <?= e($member['academic_year']) ?>
        </p>

        <hr>

        <p>
            <strong>Membership Fee:</strong>
            ₱<?= number_format($totalFee, 2) ?>
        </p>

        <p>
            <strong>Total Paid:</strong>
            ₱<?= number_format($totalPaid, 2) ?>
        </p>

        <p>
            <strong>Outstanding Balance:</strong>
        </p>

        <p class="balance">
            ₱<?= number_format($outstandingBalance, 2) ?>
        </p>

        <p>
            <strong>Excess Payment:</strong>
            ₱<?= number_format($paymentExcess, 2) ?>
        </p>

        <p>
            <strong>Payment Status:</strong>
            <span class="status"><?= e($paymentStatus) ?></span>
        </p>

        <?php if ($paymentExcess > 0): ?>
            <div class="alert warning">
                Review this member's excess payment of
                ₱<?= number_format($paymentExcess, 2) ?>. Existing payment transactions
                have been preserved.
            </div>
        <?php endif; ?>

    </div>

    <?php if ($balance > 0): ?>

        <div class="payment-form">

            <h2>Payment Details</h2>

            <form method="POST" action="record_payment.php?membership_id=<?= $membershipId ?>">

                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?= e($_SESSION['csrf_token']) ?>"
                >

                <div class="form-group">

                    <label for="amount_paid">Payment Amount (₱)</label>

                    <input
                        type="number"
                        id="amount_paid"
                        name="amount_paid"
                        min="0.01"
                        max="<?= e(number_format($balance, 2, '.', '')) ?>"
                        step="0.01"
                        value="<?= e($formAmount) ?>"
                        placeholder="Enter amount"
                        required
                    >

                    <small class="help-text">
                        Maximum payment allowed: ₱<?= number_format($balance, 2) ?>
                    </small>

                </div>

                <div class="form-group">

                    <label for="payment_method">Payment Method</label>

                    <select id="payment_method" name="payment_method" required>

                        <option value="">Select payment method</option>

                        <?php foreach (['Cash', 'GCash', 'Bank Transfer', 'Other'] as $method): ?>

                            <option
                                value="<?= e($method) ?>"
                                <?= $formMethod === $method ? 'selected' : '' ?>
                            >
                                <?= e($method) ?>
                            </option>

                        <?php endforeach; ?>

                    </select>

                </div>

                <div class="form-group">

                    <label for="reference_number">
                        Reference Number (Optional)
                    </label>

                    <input
                        type="text"
                        id="reference_number"
                        name="reference_number"
                        maxlength="100"
                        value="<?= e($formReference) ?>"
                        placeholder="Enter transaction reference number"
                    >

                </div>

                <div class="form-group">

                    <label for="payment_date">Payment Date and Time</label>

                    <input
                        type="datetime-local"
                        id="payment_date"
                        name="payment_date"
                        value="<?= e($formDate) ?>"
                        required
                    >

                </div>

                <div class="form-group">

                    <label for="remarks">Remarks (Optional)</label>

                    <textarea
                        id="remarks"
                        name="remarks"
                        maxlength="5000"
                        placeholder="Enter additional payment information"
                    ><?= e($formRemarks) ?></textarea>

                </div>

                <button type="submit">
                    Save Payment
                </button>

            </form>

        </div>

    <?php else: ?>

        <div class="alert success">
            <?php if ($paymentExcess > 0): ?>
                This member has an excess payment that needs review.
            <?php else: ?>
                This member has no remaining membership fee balance.
            <?php endif; ?>
        </div>

    <?php endif; ?>

    <div class="bottom-actions">

        <a href="view_members.php" class="back-button">
            Back to Members
        </a>

    </div>

</div>

</body>
</html>
