<?php

require_once __DIR__ . '/backend/db.php';
require_once __DIR__ . '/backend/auth_guard.php';
require_once __DIR__ . '/backend/encryption.php';

auth_start_session();

// Only approved Treasurers can access this page.
$user = auth_require_treasurer($pdo, 'APPROVED');

// Generate CSRF token if one does not exist.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Get the Treasurer's assigned organization.
$statement = $pdo->prepare(
    'SELECT
        o.organization_id,
        o.organization_name,
        o.organization_acronym
     FROM organization_treasurers ot
     INNER JOIN organizations o
        ON o.organization_id = ot.organization_id
     WHERE ot.treasurer_id = :treasurer_id
     LIMIT 1'
);

$statement->execute([
    'treasurer_id' => $user['id_number']
]);

$organization = $statement->fetch(PDO::FETCH_ASSOC);

if (!$organization) {
    auth_redirect('access_denied.php');
}

// Store form messages and values.
$error = '';
$success = $_SESSION['member_success'] ?? '';
unset($_SESSION['member_success']);

$old = [
    'student_id_number' => '',
    'full_name' => '',
    'program' => '',
    'year_level' => '',
    'academic_year' => '',
    'semester' => '',
    'emergency_contact_name' => '',
    'emergency_contact_relationship' => '',
    'emergency_contact_number' => ''
];

$allowedSemesters = [
    '1st Semester',
    '2nd Semester',
    'Summer'
];

// Process the form.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Check CSRF token.
    if (!auth_csrf_is_valid()) {
        $error = 'Invalid form request. Please refresh the page and try again.';
    } else {

        // Get and clean submitted values.
        foreach ($old as $field => $value) {
            $postedValue = $_POST[$field] ?? '';
            $old[$field] = is_string($postedValue)
                ? trim($postedValue)
                : '';
        }

        $studentId = $old['student_id_number'];
        $fullName = $old['full_name'];
        $program = $old['program'];
        $yearLevel = $old['year_level'];
        $academicYear = $old['academic_year'];
        $semester = $old['semester'];

        $contactName = $old['emergency_contact_name'];
        $contactRelationship = $old['emergency_contact_relationship'];
        $contactNumber = $old['emergency_contact_number'];

        // Validate required fields.
        if (
            $studentId === '' ||
            $fullName === '' ||
            $program === '' ||
            $yearLevel === '' ||
            $academicYear === '' ||
            $semester === ''
        ) {
            $error = 'Please complete all required fields.';

        } elseif (
            strlen($studentId) > 30 ||
            strlen($fullName) > 150 ||
            strlen($program) > 100 ||
            strlen($yearLevel) > 20 ||
            strlen($academicYear) > 20
        ) {
            $error = 'One or more fields exceed the allowed length.';

        } elseif (
            !preg_match('/^(\d{4})-(\d{4})$/', $academicYear, $yearMatch) ||
            (int) $yearMatch[2] !== (int) $yearMatch[1] + 1
        ) {
            $error = 'Enter a valid academic year, such as 2026-2027.';

        } elseif (!in_array($semester, $allowedSemesters, true)) {
            $error = 'Please select a valid semester.';

        } elseif (
            ($contactName !== '' && strlen($contactName) > 100) ||
            ($contactRelationship !== '' && strlen($contactRelationship) > 50)
        ) {
            $error = 'Emergency contact information is too long.';

        } elseif (
            $contactNumber !== '' &&
            !preg_match('/^[0-9+\-\s()]{7,30}$/', $contactNumber)
        ) {
            $error = 'Please enter a valid emergency contact number.';

        } elseif (
            $contactNumber !== '' &&
            ($contactName === '' || $contactRelationship === '')
        ) {
            $error = 'Please provide the emergency contact name and relationship.';

        } else {

            try {

                $pdo->beginTransaction();

                $configuredFeeStatement = $pdo->prepare(
                    'SELECT membership_fee
                     FROM organization_fee_settings
                     WHERE organization_id = :organization_id
                       AND academic_year = :academic_year
                       AND semester = :semester
                     LIMIT 1
                     FOR UPDATE'
                );

                $configuredFeeStatement->execute([
                    'organization_id' => $organization['organization_id'],
                    'academic_year' => $academicYear,
                    'semester' => $semester
                ]);

                $configuredFee = $configuredFeeStatement->fetchColumn();

                if ($configuredFee === false) {
                    $pdo->rollBack();
                    $error =
                        'No membership fee is configured for '
                        . $academicYear
                        . ' - '
                        . $semester
                        . '. Please set the organizational fee first.';
                } else {

                    $encryptedContactNumber =
                        encrypt_emergency_contact_number(
                            $contactNumber !== '' ? $contactNumber : null
                        );

                    $statement = $pdo->prepare(
                        'INSERT INTO membership_records (
                            organization_id,
                            student_id_number,
                            full_name,
                            program,
                            year_level,
                            academic_year,
                            semester,
                            emergency_contact_name,
                            emergency_contact_relationship,
                            emergency_contact_number_encrypted,
                            membership_status,
                            total_fee
                        ) VALUES (
                            :organization_id,
                            :student_id_number,
                            :full_name,
                            :program,
                            :year_level,
                            :academic_year,
                            :semester,
                            :emergency_contact_name,
                            :emergency_contact_relationship,
                            :emergency_contact_number_encrypted,
                            :membership_status,
                            :total_fee
                        )'
                    );

                    $statement->execute([
                        'organization_id' => $organization['organization_id'],
                        'student_id_number' => $studentId,
                        'full_name' => $fullName,
                        'program' => $program,
                        'year_level' => $yearLevel,
                        'academic_year' => $academicYear,
                        'semester' => $semester,
                        'emergency_contact_name' =>
                            $contactName !== '' ? $contactName : null,
                        'emergency_contact_relationship' =>
                            $contactRelationship !== '' ? $contactRelationship : null,
                        'emergency_contact_number_encrypted' => $encryptedContactNumber,
                        'membership_status' => 'ACTIVE',
                        'total_fee' => $configuredFee
                    ]);

                    $pdo->commit();

                    try {
                        auth_log_event(
                            $pdo,
                            'MEMBER_ADDED',
                            null,
                            $user['id_number'],
                            'Added a new member with Student ID: '
                            . $studentId
                            . ', Academic Year: '
                            . $academicYear
                            . ', Semester: '
                            . $semester
                            . ', Membership Fee: PHP '
                            . number_format((float) $configuredFee, 2)
                            . ' to organization: '
                            . $organization['organization_acronym']
                        );
                    } catch (Throwable $exception) {
                        error_log(
                            'Member activity logging error: '
                            . $exception->getMessage()
                        );
                    }

                    $_SESSION['member_success'] =
                        'New member successfully added with a membership fee of PHP '
                        . number_format((float) $configuredFee, 2)
                        . '.';

                    auth_redirect('add_member.php');
                }

            } catch (PDOException $exception) {

                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                // Handle duplicate student and academic year.
                if ($exception->getCode() === '23000') {
                    $error =
                        'This student is already registered in your organization for this academic year.';
                } else {
                    $error =
                        'Unable to save the membership record. Please try again.';
                }

            } catch (Throwable $exception) {

                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                $error =
                    'An error occurred while processing the membership record. Please try again.';
            }
        }
    }
}

// Safely display values.
function e($value): string
{
    return htmlspecialchars(
        (string) ($value ?? ''),
        ENT_QUOTES,
        'UTF-8'
    );
}

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Add Member | Student Organization Fee System</title>

    <link rel="stylesheet" href="frontend/css/treasurer_dashboard.css?v=3">

    <style>

        .member-form {
            margin-top: 25px;
        }

        .member-form label {
            display: block;
            color: #286b43;
            font-weight: 600;
            margin-bottom: 7px;
        }

        .member-form input,
        .member-form select {
            width: 100%;
            box-sizing: border-box;
            padding: 12px;
            border: 1px solid #c9dfcf;
            border-radius: 8px;
            margin-bottom: 18px;
            color: #155c35;
            background: #ffffff;
            font-size: 15px;
        }

        .member-form input:focus,
        .member-form select:focus {
            outline: none;
            border-color: #286b43;
            box-shadow: 0 0 0 3px rgba(40, 107, 67, 0.12);
        }

        .organization-box {
            background: #f2f9f4;
            border: 1px solid #d7e9dc;
            border-radius: 10px;
            padding: 15px;
            margin: 20px 0;
            color: #155c35;
        }

        .form-button {
            display: inline-block;
            background: #286b43;
            color: #ffffff;
            border: none;
            padding: 13px 22px;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            font-size: 15px;
        }

        .form-button:hover {
            background: #155c35;
        }

        .back-link {
            display: inline-block;
            margin-top: 20px;
            color: #286b43;
            font-weight: 600;
            text-decoration: none;
        }

        .message {
            padding: 13px;
            border-radius: 8px;
            margin: 18px 0;
        }

        .error-message {
            background: #fff1f0;
            border: 1px solid #e8b8b5;
            color: #9c3028;
        }

        .success-message {
            background: #eff9f1;
            border: 1px solid #b9ddc3;
            color: #155c35;
        }

        .form-note {
            color: #4f8a5e;
            font-size: 13px;
            margin-top: -10px;
            margin-bottom: 18px;
        }

        .section-heading {
            color: #155c35;
            margin-top: 28px;
        }

    </style>

</head>

<body>

<main class="auth-container">

    <section class="form-panel">

        <div class="form-container">

            <h1>Add New Member</h1>

            <p>
                Register a student under your assigned organization.
            </p>

            <div class="organization-box">

                <strong>Assigned Organization</strong>

                <p>
                    <?= e($organization['organization_name']) ?>
                    (<?= e($organization['organization_acronym']) ?>)
                </p>

            </div>

            <?php if ($error !== ''): ?>

                <div class="message error-message">
                    <?= e($error) ?>
                </div>

            <?php endif; ?>

            <?php if ($success !== ''): ?>

                <div class="message success-message">
                    <?= e($success) ?>
                </div>

            <?php endif; ?>

            <form method="POST" class="member-form">

                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?= e($_SESSION['csrf_token']) ?>"
                >

                <h2 class="section-heading">Student Information</h2>

                <label for="student_id_number">Student ID Number *</label>

                <input
                    type="text"
                    id="student_id_number"
                    name="student_id_number"
                    maxlength="30"
                    value="<?= e($old['student_id_number']) ?>"
                    required
                >

                <label for="full_name">Full Name *</label>

                <input
                    type="text"
                    id="full_name"
                    name="full_name"
                    maxlength="150"
                    value="<?= e($old['full_name']) ?>"
                    required
                >

                <label for="program">Program *</label>

                <input
                    type="text"
                    id="program"
                    name="program"
                    maxlength="100"
                    value="<?= e($old['program']) ?>"
                    placeholder="Example: Bachelor of Science in Information Technology"
                    required
                >

                <label for="year_level">Year Level *</label>

                <input
                    type="text"
                    id="year_level"
                    name="year_level"
                    maxlength="20"
                    value="<?= e($old['year_level']) ?>"
                    placeholder="Example: 1st Year"
                    required
                >

                <label for="academic_year">Academic Year *</label>

                <input
                    type="text"
                    id="academic_year"
                    name="academic_year"
                    maxlength="20"
                    value="<?= e($old['academic_year']) ?>"
                    placeholder="Example: 2026-2027"
                    required
                >

                <label for="semester">Semester *</label>

                <select id="semester" name="semester" required>
                    <option value="">Select semester</option>
                    <?php foreach ($allowedSemesters as $semesterOption): ?>
                        <option
                            value="<?= e($semesterOption) ?>"
                            <?= $old['semester'] === $semesterOption ? 'selected' : '' ?>
                        >
                            <?= e($semesterOption) ?>
                        </option>
                    <?php endforeach; ?>
                </select>

                <p class="form-note">
                    The membership fee configured for this academic year and semester
                    will be applied automatically.
                </p>

                <h2 class="section-heading">Emergency Contact</h2>

                <p class="form-note">
                    These fields are optional. The contact number
                    will be encrypted before it is stored.
                </p>

                <label for="emergency_contact_name">
                    Emergency Contact Name
                </label>

                <input
                    type="text"
                    id="emergency_contact_name"
                    name="emergency_contact_name"
                    maxlength="100"
                    value="<?= e($old['emergency_contact_name']) ?>"
                >

                <label for="emergency_contact_relationship">
                    Relationship
                </label>

                <input
                    type="text"
                    id="emergency_contact_relationship"
                    name="emergency_contact_relationship"
                    maxlength="50"
                    value="<?= e($old['emergency_contact_relationship']) ?>"
                    placeholder="Example: Mother"
                >

                <label for="emergency_contact_number">
                    Emergency Contact Number
                </label>

                <input
                    type="tel"
                    id="emergency_contact_number"
                    name="emergency_contact_number"
                    maxlength="30"
                    value="<?= e($old['emergency_contact_number']) ?>"
                    placeholder="Example: 09123456789"
                >

                <button type="submit" class="form-button">
                    Save Member
                </button>

            </form>

            <a href="treasurer_dashboard.php" class="back-link">
                &larr; Back to Treasurer Dashboard
            </a>

        </div>

    </section>

</main>

<?= auth_session_timeout_markup() ?>
</body>
</html>
