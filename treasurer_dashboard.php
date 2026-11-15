
<?php

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

require_once __DIR__ . '/backend/db.php';
require_once __DIR__ . '/backend/auth_guard.php';
require_once __DIR__ . '/backend/encryption.php';

auth_start_session();

$user = auth_current_user($pdo);

if (!$user || ($user['role'] ?? '') !== 'TREASURER') {
    auth_redirect('access_denied.php');
}

function e($value): string
{
    return htmlspecialchars((string) ($value ?? ''), ENT_QUOTES, 'UTF-8');
}

function treasurer_post_value(string $key): string
{
    $value = $_POST[$key] ?? '';
    return is_string($value) ? trim($value) : '';
}

$name = trim(
    ($user['first_name'] ?? '') . ' ' .
    ($user['family_name'] ?? '')
);

if ($name === '') {
    $name = 'Treasurer';
}

$approvalStatus = $user['approval_status'] ?? '';

$dashboardViews = [
    'overview',
    'members',
    'add-member',
    'record-payment',
    'payment-monitoring',
    'payment-history',
    'account-settings'
];

$requestedView = $_GET['view'] ?? 'overview';

if (
    !is_string($requestedView) ||
    !in_array($requestedView, $dashboardViews, true)
) {
    $requestedView = 'overview';
}

$currentView = $requestedView === 'record-payment'
    ? 'payment-monitoring'
    : $requestedView;

$organization = null;
$organizationId = 0;

$statistics = [
    'total_members' => 0,
    'fully_paid' => 0,
    'partially_paid' => 0,
    'unpaid' => 0
];

$allowedSemesters = [
    '1st Semester',
    '2nd Semester',
    'Summer'
];

$allowedYearLevels = [
    '1st Year',
    '2nd Year',
    '3rd Year',
    '4th Year',
    '5th Year'
];

// --------------------------------------------------
// ORGANIZATION ASSIGNMENT
// --------------------------------------------------

if ($approvalStatus === 'APPROVED') {

    $organizationStatement = $pdo->prepare(
        'SELECT
            o.organization_id,
            o.organization_name,
            o.organization_acronym,
            o.organization_type,
            o.department_college
         FROM organization_treasurers ot
         INNER JOIN organizations o
            ON o.organization_id = ot.organization_id
         WHERE ot.treasurer_id = :treasurer_id
         LIMIT 1'
    );

    $organizationStatement->execute([
        'treasurer_id' => $user['id_number']
    ]);

    $organization = $organizationStatement->fetch(PDO::FETCH_ASSOC);

    if ($organization) {
        $organizationId = (int) $organization['organization_id'];
    }
}

$canManageOrganization =
    $approvalStatus === 'APPROVED' &&
    $organization !== null;

if (!$canManageOrganization && $currentView !== 'account-settings') {
    $currentView = 'overview';
}

// --------------------------------------------------
// CSRF TOKEN
// --------------------------------------------------

if ($canManageOrganization || $currentView === 'account-settings') {

    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

// --------------------------------------------------
// ACCOUNT SETTINGS
// --------------------------------------------------

$passwordChangeError = '';
$passwordChangeSuccess = $_SESSION['password_change_success'] ?? '';
unset($_SESSION['password_change_success']);

if (
    $currentView === 'account-settings' &&
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    ($_POST['form_action'] ?? '') === 'change_password'
) {
    $currentPassword = is_string($_POST['current_password'] ?? null)
        ? $_POST['current_password']
        : '';
    $newPassword = is_string($_POST['new_password'] ?? null)
        ? $_POST['new_password']
        : '';
    $confirmPassword = is_string($_POST['confirm_password'] ?? null)
        ? $_POST['confirm_password']
        : '';

    if (!auth_csrf_is_valid()) {
        $passwordChangeError = 'Invalid form request. Please refresh the page and try again.';
    } elseif ($currentPassword === '' || $newPassword === '' || $confirmPassword === '') {
        $passwordChangeError = 'Please complete all password fields.';
    } elseif ($newPassword !== $confirmPassword) {
        $passwordChangeError = 'The new passwords do not match.';
    } elseif (strlen($newPassword) < 8 || strlen($newPassword) > 64) {
        $passwordChangeError = 'Password must be between 8 and 64 characters.';
    } else {
        $passwordScore = 0;
        $passwordScore += strlen($newPassword) >= 8 ? 1 : 0;
        $passwordScore += (
            preg_match('/[a-z]/', $newPassword) === 1 &&
            preg_match('/[A-Z]/', $newPassword) === 1
        ) ? 1 : 0;
        $passwordScore += preg_match('/[0-9]/', $newPassword) === 1 ? 1 : 0;
        $passwordScore += preg_match('/[^A-Za-z0-9]/', $newPassword) === 1 ? 1 : 0;
        $passwordScore += strlen($newPassword) >= 12 ? 1 : 0;

        if ($passwordScore < 3) {
            $passwordChangeError = 'Choose a password with at least three strength criteria.';
        } else {
            try {
                $pdo->beginTransaction();

                $passwordStatement = $pdo->prepare(
                    "SELECT password_hash
                     FROM users
                     WHERE id_number = :user_id
                       AND role = 'TREASURER'
                       AND account_status = 'ACTIVE'
                     LIMIT 1
                     FOR UPDATE"
                );
                $passwordStatement->execute([
                    'user_id' => $user['id_number']
                ]);
                $currentAccountHash = $passwordStatement->fetchColumn();

                if (
                    !is_string($currentAccountHash) ||
                    !password_verify($currentPassword, $currentAccountHash)
                ) {
                    $passwordChangeError = 'Your current password is incorrect.';
                } elseif (password_verify($newPassword, $currentAccountHash)) {
                    $passwordChangeError = 'Choose a password different from your current password.';
                } else {
                    $passwordHistoryStatement = $pdo->prepare(
                        'SELECT password_hash
                         FROM password_history
                         WHERE user_id = :user_id'
                    );
                    $passwordHistoryStatement->execute([
                        'user_id' => $user['id_number']
                    ]);

                    $passwordWasUsed = false;
                    foreach ($passwordHistoryStatement->fetchAll(PDO::FETCH_COLUMN) as $oldPasswordHash) {
                        if (is_string($oldPasswordHash) && password_verify($newPassword, $oldPasswordHash)) {
                            $passwordWasUsed = true;
                            break;
                        }
                    }

                    if ($passwordWasUsed) {
                        $passwordChangeError = 'Choose a password you have not used before.';
                    } else {
                        $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);

                        if (!is_string($newPasswordHash)) {
                            $passwordChangeError = 'Could not secure the new password.';
                        } else {
                            $updatePasswordStatement = $pdo->prepare(
                                'UPDATE users
                                 SET password_hash = :password_hash
                                 WHERE id_number = :user_id'
                            );
                            $updatePasswordStatement->execute([
                                'password_hash' => $newPasswordHash,
                                'user_id' => $user['id_number']
                            ]);

                            $insertPasswordHistoryStatement = $pdo->prepare(
                                'INSERT INTO password_history (user_id, password_hash)
                                 VALUES (:user_id, :password_hash)'
                            );
                            $insertPasswordHistoryStatement->execute([
                                'user_id' => $user['id_number'],
                                'password_hash' => $newPasswordHash
                            ]);

                            $pdo->commit();

                            $passwordChangeSuccess = 'Your password has been changed.';
                            try {
                                auth_log_event(
                                    $pdo,
                                    'ACCOUNT_PASSWORD_CHANGED',
                                    null,
                                    $user['id_number'],
                                    'Treasurer changed their password from dashboard account settings.'
                                );
                            } catch (PDOException $exception) {
                                error_log('Password change activity logging error: ' . $exception->getMessage());
                                $passwordChangeSuccess =
                                    'Your password has been changed, but the activity log could not be saved. Please contact an administrator.';
                            }

                            $_SESSION['password_change_success'] = $passwordChangeSuccess;
                            header('Location: treasurer_dashboard.php?view=account-settings');
                            exit;
                        }
                    }
                }

                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
            } catch (PDOException $exception) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                error_log('Treasurer password change error: ' . $exception->getMessage());
                $passwordChangeError = 'Unable to update your password. Please try again.';
            }
        }
    }
}

// --------------------------------------------------
// ORGANIZATIONAL FEE SETTINGS
// The fee form is now displayed inside Overview.
// --------------------------------------------------

$feeError = '';
$feeSuccess = $_SESSION['fee_success'] ?? '';
unset($_SESSION['fee_success']);

$feeOld = [
    'fee_setting_id' => '',
    'academic_year' => '',
    'semester' => '',
    'membership_fee' => ''
];

$feeSettings = [];

if (
    $canManageOrganization &&
    $currentView === 'overview' &&
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    ($_POST['form_action'] ?? '') === 'save_organization_fee'
) {

    $feeOld['fee_setting_id'] = treasurer_post_value('fee_setting_id');
    $feeOld['academic_year'] = treasurer_post_value('academic_year');
    $feeOld['semester'] = treasurer_post_value('semester');
    $feeOld['membership_fee'] = treasurer_post_value('membership_fee');

    if (!auth_csrf_is_valid()) {

        $feeError = 'Invalid form request. Please refresh the page and try again.';

    } else {

        $academicYear = $feeOld['academic_year'];
        $semester = $feeOld['semester'];
        $membershipFee = $feeOld['membership_fee'];

        $validAcademicYear = false;

        if (preg_match('/^(\d{4})-(\d{4})$/', $academicYear, $matches)) {
            $validAcademicYear =
                (int) $matches[2] === (int) $matches[1] + 1;
        }

        if (
            $academicYear === '' ||
            $semester === '' ||
            $membershipFee === ''
        ) {

            $feeError = 'Please complete all required fields.';

        } elseif (!$validAcademicYear) {

            $feeError = 'Enter a valid academic year, such as 2026-2027.';

        } elseif (
            $feeOld['fee_setting_id'] !== '' &&
            (
                !ctype_digit($feeOld['fee_setting_id']) ||
                (int) $feeOld['fee_setting_id'] < 1
            )
        ) {

            $feeError = 'Invalid organizational fee setting.';

        } elseif (!in_array($semester, $allowedSemesters, true)) {

            $feeError = 'Please select a valid semester.';

        } elseif (
            !preg_match('/^\d{1,8}(\.\d{1,2})?$/', $membershipFee) ||
            (float) $membershipFee < 0 ||
            (float) $membershipFee > 99999999.99
        ) {

            $feeError = 'Enter a valid non-negative membership fee.';

        } else {

            try {

                $pdo->beginTransaction();

                if ($feeOld['fee_setting_id'] !== '') {
                    $existingFeeStatement = $pdo->prepare(
                        'SELECT academic_year, semester
                         FROM organization_fee_settings
                         WHERE fee_setting_id = :fee_setting_id
                           AND organization_id = :organization_id
                         FOR UPDATE'
                    );
                    $existingFeeStatement->execute([
                        'fee_setting_id' => (int) $feeOld['fee_setting_id'],
                        'organization_id' => $organizationId
                    ]);
                    $existingFee = $existingFeeStatement->fetch(PDO::FETCH_ASSOC);

                    if (!$existingFee) {
                        throw new RuntimeException(
                            'The organizational fee setting could not be found.'
                        );
                    }

                    if (
                        $existingFee['academic_year'] !== $academicYear ||
                        $existingFee['semester'] !== $semester
                    ) {
                        throw new RuntimeException(
                            'The academic year and semester cannot be changed while editing a fee.'
                        );
                    }
                }

                $saveFeeStatement = $pdo->prepare(
                    'INSERT INTO organization_fee_settings (
                        organization_id,
                        academic_year,
                        semester,
                        membership_fee
                    ) VALUES (
                        :organization_id,
                        :academic_year,
                        :semester,
                        :membership_fee
                    )
                    ON DUPLICATE KEY UPDATE
                        membership_fee = VALUES(membership_fee),
                        updated_at = CURRENT_TIMESTAMP'
                );

                $saveFeeStatement->execute([
                    'organization_id' => $organizationId,
                    'academic_year' => $academicYear,
                    'semester' => $semester,
                    'membership_fee' => $membershipFee
                ]);

                $matchingMembersStatement = $pdo->prepare(
                    'SELECT
                        COUNT(*) AS matching_member_count,
                        COALESCE(
                            SUM(
                                CASE
                                    WHEN semester IS NULL OR TRIM(semester) = \'\'
                                    THEN 1 ELSE 0
                                END
                            ),
                            0
                        ) AS legacy_member_count
                     FROM membership_records
                     WHERE organization_id = :organization_id
                       AND academic_year = :academic_year
                       AND (
                            semester = :matching_semester
                            OR semester IS NULL
                            OR TRIM(semester) = \'\'
                       )'
                );

                $matchingMembersStatement->execute([
                    'organization_id' => $organizationId,
                    'academic_year' => $academicYear,
                    'matching_semester' => $semester
                ]);

                $matchingMembers = $matchingMembersStatement->fetch(PDO::FETCH_ASSOC);
                $matchingMemberCount = (int) $matchingMembers['matching_member_count'];
                $legacyMemberCount = (int) $matchingMembers['legacy_member_count'];

                $updateMemberFeesStatement = $pdo->prepare(
                    'UPDATE membership_records
                     SET total_fee = :membership_fee,
                         semester = :assigned_semester
                     WHERE organization_id = :organization_id
                       AND academic_year = :academic_year
                       AND (
                            semester = :matching_semester
                            OR semester IS NULL
                            OR TRIM(semester) = \'\'
                       )'
                );

                $updateMemberFeesStatement->execute([
                    'membership_fee' => $membershipFee,
                    'assigned_semester' => $semester,
                    'organization_id' => $organizationId,
                    'academic_year' => $academicYear,
                    'matching_semester' => $semester
                ]);

                $overpaymentReviewStatement = $pdo->prepare(
                    'SELECT
                        COUNT(*) AS overpaid_member_count,
                        COALESCE(
                            SUM(payment_totals.total_paid - mr.total_fee),
                            0
                        ) AS excess_amount
                     FROM membership_records mr
                     LEFT JOIN (
                        SELECT membership_id, SUM(amount_paid) AS total_paid
                        FROM membership_payments
                        GROUP BY membership_id
                     ) payment_totals
                        ON payment_totals.membership_id = mr.membership_id
                     WHERE mr.organization_id = :organization_id
                       AND mr.academic_year = :academic_year
                       AND mr.semester = :semester
                       AND COALESCE(payment_totals.total_paid, 0) > mr.total_fee'
                );
                $overpaymentReviewStatement->execute([
                    'organization_id' => $organizationId,
                    'academic_year' => $academicYear,
                    'semester' => $semester
                ]);
                $overpaymentReview = $overpaymentReviewStatement->fetch(PDO::FETCH_ASSOC);
                $overpaidMemberCount = (int) $overpaymentReview['overpaid_member_count'];
                $excessPaymentAmount = (float) $overpaymentReview['excess_amount'];

                $pdo->commit();

                try {
                    auth_log_event(
                        $pdo,
                        'ORGANIZATION_FEE_UPDATED',
                        null,
                        $user['id_number'],
                        ($feeOld['fee_setting_id'] !== ''
                            ? 'Updated'
                            : 'Set')
                        . ' the membership fee to PHP '
                        . number_format((float) $membershipFee, 2)
                        . ' for '
                        . $academicYear
                        . ' - '
                        . $semester
                        . (
                            $legacyMemberCount > 0
                                ? '; assigned '
                                    . number_format($legacyMemberCount)
                                    . ' legacy member(s) with no semester to '
                                    . $semester
                                : ''
                        )
                        . ' in organization: '
                        . $organization['organization_acronym']
                    );
                } catch (Throwable $exception) {
                    error_log('Fee activity logging error: ' . $exception->getMessage());
                }

                if ($matchingMemberCount > 0) {
                    $_SESSION['fee_success'] =
                        'Organizational fee saved and applied to '
                        . number_format($matchingMemberCount)
                        . ' existing member(s) for the selected academic year and semester.';

                    if ($legacyMemberCount > 0) {
                        $_SESSION['fee_success'] .=
                            ' This includes '
                            . number_format($legacyMemberCount)
                            . ' legacy member(s) that had no semester recorded; they were assigned to '
                            . $semester
                            . '.';
                    }
                } else {
                    $_SESSION['fee_success'] =
                        'Organizational fee saved. No existing members matched the selected academic year and semester; new registrations will use this fee.';
                }

                if ($overpaidMemberCount > 0) {
                    $_SESSION['fee_success'] .=
                        ' Review '
                        . number_format($overpaidMemberCount)
                        . ' member record(s) with excess payments totaling PHP '
                        . number_format($excessPaymentAmount, 2)
                        . '. Payment transactions were not changed.';
                }

                header('Location: treasurer_dashboard.php?view=overview');
                exit;

            } catch (PDOException $exception) {

                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                error_log('Organizational fee setting error: ' . $exception->getMessage());

                $feeError = 'Unable to save the organizational fee. Please try again.';

            } catch (RuntimeException $exception) {

                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                $feeError = $exception->getMessage();
            }
        }
    }
}

// Retrieve fee settings for the Overview panel.
if ($canManageOrganization) {

    $feeSettingsStatement = $pdo->prepare(
        'SELECT
            fee_setting_id,
            academic_year,
            semester,
            membership_fee,
            created_at,
            updated_at
         FROM organization_fee_settings
         WHERE organization_id = :organization_id
         ORDER BY academic_year DESC,
            FIELD(semester, "1st Semester", "2nd Semester", "Summer")'
    );

    $feeSettingsStatement->execute([
        'organization_id' => $organizationId
    ]);

    $feeSettings = $feeSettingsStatement->fetchAll(PDO::FETCH_ASSOC);
}

// --------------------------------------------------
// DELETE MEMBER
// --------------------------------------------------

$deleteError = '';
$deleteSuccess = $_SESSION['delete_success'] ?? '';
unset($_SESSION['delete_success']);

if (
    $canManageOrganization &&
    $currentView === 'members' &&
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    ($_POST['form_action'] ?? '') === 'delete_member'
) {

    $rawMembershipId = treasurer_post_value('membership_id');

    if (!auth_csrf_is_valid()) {

        $deleteError = 'Invalid form request. Please refresh the page and try again.';

    } elseif (
        $rawMembershipId === '' ||
        !ctype_digit($rawMembershipId) ||
        (int) $rawMembershipId < 1
    ) {

        $deleteError = 'Invalid member record.';

    } else {

        $membershipIdToDelete = (int) $rawMembershipId;

        try {

            $pdo->beginTransaction();

            // Lock the member record and verify organization ownership.
            $checkMemberStatement = $pdo->prepare(
                'SELECT membership_id, student_id_number, full_name
                 FROM membership_records
                 WHERE membership_id = :membership_id
                   AND organization_id = :organization_id
                 FOR UPDATE'
            );

            $checkMemberStatement->execute([
                'membership_id' => $membershipIdToDelete,
                'organization_id' => $organizationId
            ]);

            $memberToDelete = $checkMemberStatement->fetch(PDO::FETCH_ASSOC);

            if (!$memberToDelete) {

                throw new RuntimeException(
                    'The member was not found in your assigned organization.'
                );

            }

            // Delete the member's payment transactions first.
            $deletePaymentsStatement = $pdo->prepare(
                'DELETE FROM membership_payments
                 WHERE membership_id = :membership_id'
            );

            $deletePaymentsStatement->execute([
                'membership_id' => $membershipIdToDelete
            ]);

            // Delete the member record.
            $deleteMemberStatement = $pdo->prepare(
                'DELETE FROM membership_records
                 WHERE membership_id = :membership_id
                   AND organization_id = :organization_id'
            );

            $deleteMemberStatement->execute([
                'membership_id' => $membershipIdToDelete,
                'organization_id' => $organizationId
            ]);

            if ($deleteMemberStatement->rowCount() !== 1) {
                throw new RuntimeException('Unable to delete the selected member.');
            }

            $pdo->commit();

            try {
                auth_log_event(
                    $pdo,
                    'MEMBER_DELETED',
                    null,
                    $user['id_number'],
                    'Deleted member: '
                    . $memberToDelete['full_name']
                    . ' (Student ID: '
                    . $memberToDelete['student_id_number']
                    . ') and associated payment transactions.'
                );
            } catch (Throwable $exception) {
                error_log('Member deletion activity logging error: ' . $exception->getMessage());
            }

            $_SESSION['delete_success'] =
                'Member and associated payment transactions deleted successfully.';

            header('Location: treasurer_dashboard.php?view=members');
            exit;

        } catch (RuntimeException $exception) {

            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }

            $deleteError = $exception->getMessage();

        } catch (Throwable $exception) {

            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }

            error_log('Member deletion error: ' . $exception->getMessage());

            $deleteError = 'Unable to delete the member. Please try again.';
        }
    }
}

// --------------------------------------------------
// MEMBERSHIP STATISTICS
// --------------------------------------------------

if ($canManageOrganization) {

    $statisticsStatement = $pdo->prepare(
        'SELECT
            COUNT(*) AS total_members,

            SUM(
                CASE
                    WHEN COALESCE(p.total_paid, 0) > 0
                     AND COALESCE(p.total_paid, 0) >= mr.total_fee
                    THEN 1 ELSE 0
                END
            ) AS fully_paid,

            SUM(
                CASE
                    WHEN mr.total_fee > 0
                     AND COALESCE(p.total_paid, 0) > 0
                     AND COALESCE(p.total_paid, 0) < mr.total_fee
                    THEN 1 ELSE 0
                END
            ) AS partially_paid,

            SUM(
                CASE
                    WHEN COALESCE(p.total_paid, 0) = 0
                    THEN 1 ELSE 0
                END
            ) AS unpaid

         FROM membership_records mr

         LEFT JOIN (
            SELECT membership_id, SUM(amount_paid) AS total_paid
            FROM membership_payments
            GROUP BY membership_id
         ) p ON p.membership_id = mr.membership_id

         WHERE mr.organization_id = :organization_id'
    );

    $statisticsStatement->execute([
        'organization_id' => $organizationId
    ]);

    $statisticsResult = $statisticsStatement->fetch(PDO::FETCH_ASSOC);

    if ($statisticsResult) {
        $statistics = [
            'total_members' => (int) $statisticsResult['total_members'],
            'fully_paid' => (int) $statisticsResult['fully_paid'],
            'partially_paid' => (int) $statisticsResult['partially_paid'],
            'unpaid' => (int) $statisticsResult['unpaid']
        ];
    }
}

// --------------------------------------------------
// MEMBERSHIP MANAGEMENT
// --------------------------------------------------

$members = [];
$memberSearch = $_GET['search'] ?? '';

if (!is_string($memberSearch)) {
    $memberSearch = '';
}

$memberSearch = trim(substr($memberSearch, 0, 100));

$memberAcademicYearFilter = $_GET['academic_year'] ?? '';
if (!is_string($memberAcademicYearFilter)) {
    $memberAcademicYearFilter = '';
}
$memberAcademicYearFilter = trim(substr($memberAcademicYearFilter, 0, 20));

$memberYearLevelFilter = $_GET['year_level'] ?? '';
if (!is_string($memberYearLevelFilter)) {
    $memberYearLevelFilter = '';
}
$memberYearLevelFilter = trim(substr($memberYearLevelFilter, 0, 20));

$memberAcademicYearOptions = [];
$memberYearLevelOptions = [];

if ($canManageOrganization && $currentView === 'members') {
    $memberFilterOptionsStatement = $pdo->prepare(
        'SELECT DISTINCT academic_year, year_level
         FROM membership_records
         WHERE organization_id = :organization_id
         ORDER BY academic_year DESC, year_level ASC'
    );
    $memberFilterOptionsStatement->execute([
        'organization_id' => $organizationId
    ]);

    foreach ($memberFilterOptionsStatement->fetchAll(PDO::FETCH_ASSOC) as $filterOption) {
        $academicYearOption = (string) ($filterOption['academic_year'] ?? '');
        $yearLevelOption = (string) ($filterOption['year_level'] ?? '');

        if ($academicYearOption !== '') {
            $memberAcademicYearOptions[$academicYearOption] = $academicYearOption;
        }

        if ($yearLevelOption !== '') {
            $memberYearLevelOptions[$yearLevelOption] = $yearLevelOption;
        }
    }

    $memberAcademicYearOptions = array_values($memberAcademicYearOptions);
    $memberYearLevelOptions = array_values($memberYearLevelOptions);
    sort($memberYearLevelOptions, SORT_NATURAL | SORT_FLAG_CASE);

    if (
        $memberAcademicYearFilter !== '' &&
        !in_array($memberAcademicYearFilter, $memberAcademicYearOptions, true)
    ) {
        $memberAcademicYearFilter = '';
    }

    if (
        $memberYearLevelFilter !== '' &&
        !in_array($memberYearLevelFilter, $memberYearLevelOptions, true)
    ) {
        $memberYearLevelFilter = '';
    }
}

$totalMembersFound = 0;
$totalFees = 0;
$totalPaid = 0;
$totalBalance = 0;
$totalExcessPayments = 0;
$overpaidMemberCount = 0;

if ($canManageOrganization && $currentView === 'members') {

    $memberSql = "
        SELECT
            mr.membership_id,
            mr.student_id_number,
            mr.full_name,
            mr.program,
            mr.year_level,
            mr.academic_year,
            mr.semester,
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
            SELECT membership_id, SUM(amount_paid) AS total_paid
            FROM membership_payments
            GROUP BY membership_id
        ) payments ON payments.membership_id = mr.membership_id

        WHERE mr.organization_id = :organization_id
    ";

    $memberParams = [
        'organization_id' => $organizationId
    ];

    if ($memberSearch !== '') {

        $memberSql .= "
            AND (
                mr.student_id_number LIKE :student_id
                OR mr.full_name LIKE :full_name
                OR mr.program LIKE :program
                OR mr.year_level LIKE :year_level_search
                OR mr.academic_year LIKE :academic_year
                OR mr.semester LIKE :semester
            )
        ";

        $searchValue = '%' . $memberSearch . '%';

        $memberParams['student_id'] = $searchValue;
        $memberParams['full_name'] = $searchValue;
        $memberParams['program'] = $searchValue;
        $memberParams['year_level_search'] = $searchValue;
        $memberParams['academic_year'] = $searchValue;
        $memberParams['semester'] = $searchValue;
    }

    if ($memberAcademicYearFilter !== '') {
        $memberSql .= ' AND mr.academic_year = :filter_academic_year';
        $memberParams['filter_academic_year'] = $memberAcademicYearFilter;
    }

    if ($memberYearLevelFilter !== '') {
        $memberSql .= ' AND mr.year_level = :filter_year_level';
        $memberParams['filter_year_level'] = $memberYearLevelFilter;
    }

    $memberSql .= ' ORDER BY mr.academic_year DESC, mr.year_level ASC, mr.full_name ASC';

    $memberStatement = $pdo->prepare($memberSql);
    $memberStatement->execute($memberParams);

    $members = $memberStatement->fetchAll(PDO::FETCH_ASSOC);

    $totalMembersFound = count($members);

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
}

// --------------------------------------------------
// ADD NEW MEMBER
// --------------------------------------------------

$memberError = '';
$memberSuccess = $_SESSION['member_success'] ?? '';
unset($_SESSION['member_success']);

$memberOld = [
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

if (
    $canManageOrganization &&
    $currentView === 'add-member' &&
    $_SERVER['REQUEST_METHOD'] === 'POST'
) {

    if (!auth_csrf_is_valid()) {

        $memberError = 'Invalid form request. Please refresh the page and try again.';

    } else {

        foreach ($memberOld as $field => $value) {
            $memberOld[$field] = treasurer_post_value($field);
        }

        $studentId = $memberOld['student_id_number'];
        $fullName = $memberOld['full_name'];
        $program = $memberOld['program'];
        $yearLevel = $memberOld['year_level'];
        $academicYear = $memberOld['academic_year'];
        $semester = $memberOld['semester'];

        $contactName = $memberOld['emergency_contact_name'];
        $contactRelationship = $memberOld['emergency_contact_relationship'];
        $contactNumber = $memberOld['emergency_contact_number'];

        if (
            $studentId === '' ||
            $fullName === '' ||
            $program === '' ||
            $yearLevel === '' ||
            $academicYear === '' ||
            $semester === ''
        ) {

            $memberError = 'Please complete all required fields.';

        } elseif (
            strlen($studentId) > 30 ||
            strlen($fullName) > 150 ||
            strlen($program) > 100 ||
            strlen($yearLevel) > 20 ||
            strlen($academicYear) > 20
        ) {

            $memberError = 'One or more fields exceed the allowed length.';

        } elseif (!in_array($yearLevel, $allowedYearLevels, true)) {

            $memberError = 'Please select a valid year level.';

        } elseif (
            !preg_match('/^(\d{4})-(\d{4})$/', $academicYear, $yearMatch) ||
            (int) $yearMatch[2] !== (int) $yearMatch[1] + 1
        ) {

            $memberError = 'Enter a valid academic year, such as 2026-2027.';

        } elseif (!in_array($semester, $allowedSemesters, true)) {

            $memberError = 'Please select a valid semester.';

        } elseif (
            ($contactName !== '' && strlen($contactName) > 100) ||
            ($contactRelationship !== '' && strlen($contactRelationship) > 50)
        ) {

            $memberError = 'Emergency contact information is too long.';

        } elseif (
            $contactNumber !== '' &&
            !preg_match('/^[0-9+\-\s()]{7,30}$/', $contactNumber)
        ) {

            $memberError = 'Please enter a valid emergency contact number.';

        } elseif (
            $contactNumber !== '' &&
            ($contactName === '' || $contactRelationship === '')
        ) {

            $memberError =
                'Please provide the emergency contact name and relationship.';

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
                    'organization_id' => $organizationId,
                    'academic_year' => $academicYear,
                    'semester' => $semester
                ]);

                $configuredFee = $configuredFeeStatement->fetchColumn();

                if ($configuredFee === false) {

                    $pdo->rollBack();
                    $memberError =
                        'No membership fee has been configured for '
                        . $academicYear
                        . ' - '
                        . $semester
                        . '. Please set the organizational fee first.';

                } else {

                    $encryptedContactNumber =
                        encrypt_emergency_contact_number(
                            $contactNumber !== '' ? $contactNumber : null
                        );

                    $insertMemberStatement = $pdo->prepare(
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

                    $insertMemberStatement->execute([
                        'organization_id' => $organizationId,
                        'student_id_number' => $studentId,
                        'full_name' => $fullName,
                        'program' => $program,
                        'year_level' => $yearLevel,
                        'academic_year' => $academicYear,
                        'semester' => $semester,
                        'emergency_contact_name' => $contactName !== '' ? $contactName : null,
                        'emergency_contact_relationship' => $contactRelationship !== '' ? $contactRelationship : null,
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
                        );
                    } catch (Throwable $exception) {
                        error_log('Member activity logging error: ' . $exception->getMessage());
                    }

                    $_SESSION['member_success'] = 'New member successfully added!';

                    header('Location: treasurer_dashboard.php?view=add-member');
                    exit;
                }

            } catch (PDOException $exception) {

                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                if ($exception->getCode() === '23000') {
                    $memberError =
                        'This student is already registered in your organization for this academic year.';
                } else {
                    error_log('Member registration error: ' . $exception->getMessage());
                    $memberError = 'Unable to save the membership record. Please try again.';
                }

            } catch (Throwable $exception) {

                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                error_log('Member registration error: ' . $exception->getMessage());
                $memberError =
                    'An error occurred while processing the membership record. Please try again.';
            }
        }
    }
}

// --------------------------------------------------
// PAYMENT MONITORING
// --------------------------------------------------

$monitoringMembers = [];

$monitoringTotals = [
    'members' => 0,
    'fees' => 0,
    'paid' => 0,
    'balance' => 0,
    'overpaid_members' => 0,
    'excess_payments' => 0
];

$monitoringSearch = $_GET['search'] ?? '';

if (!is_string($monitoringSearch)) {
    $monitoringSearch = '';
}

$monitoringSearch = trim(substr($monitoringSearch, 0, 100));

if ($canManageOrganization && $currentView === 'payment-monitoring') {

    $monitoringSql = "
        SELECT
            mr.membership_id,
            mr.student_id_number,
            mr.full_name,
            mr.program,
            mr.year_level,
            mr.academic_year,
            mr.semester,
            mr.total_fee,
            mr.membership_status,

            COALESCE(p.total_paid, 0) AS total_paid,

            mr.total_fee - COALESCE(p.total_paid, 0)
                AS balance,

            GREATEST(
                COALESCE(p.total_paid, 0) - mr.total_fee,
                0
            ) AS excess_payment,

            CASE
                WHEN COALESCE(p.total_paid, 0) = 0 THEN 'Unpaid'
                WHEN COALESCE(p.total_paid, 0) < mr.total_fee
                    THEN 'Partially Paid'
                ELSE 'Fully Paid'
            END AS payment_status

        FROM membership_records mr

        LEFT JOIN (
            SELECT membership_id, SUM(amount_paid) AS total_paid
            FROM membership_payments
            GROUP BY membership_id
        ) p ON p.membership_id = mr.membership_id

        WHERE mr.organization_id = :organization_id
    ";

    $monitoringParams = [
        'organization_id' => $organizationId
    ];

    if ($monitoringSearch !== '') {

        $monitoringSql .= "
            AND (
                mr.student_id_number LIKE :student_id
                OR mr.full_name LIKE :full_name
                OR mr.academic_year LIKE :academic_year
                OR mr.semester LIKE :semester
                OR mr.program LIKE :program
            )
        ";

        $searchValue = '%' . $monitoringSearch . '%';

        $monitoringParams['student_id'] = $searchValue;
        $monitoringParams['full_name'] = $searchValue;
        $monitoringParams['academic_year'] = $searchValue;
        $monitoringParams['semester'] = $searchValue;
        $monitoringParams['program'] = $searchValue;
    }

    $monitoringSql .=
        ' ORDER BY mr.academic_year DESC, mr.semester ASC, mr.full_name ASC';

    $monitoringStatement = $pdo->prepare($monitoringSql);
    $monitoringStatement->execute($monitoringParams);

    $monitoringMembers = $monitoringStatement->fetchAll(PDO::FETCH_ASSOC);

    foreach ($monitoringMembers as $record) {
        $monitoringTotals['members']++;
        $monitoringTotals['fees'] += (float) $record['total_fee'];
        $monitoringTotals['paid'] += (float) $record['total_paid'];
        $monitoringTotals['balance'] += (float) $record['balance'];

        $excessPayment = (float) $record['excess_payment'];
        if ($excessPayment > 0) {
            $monitoringTotals['overpaid_members']++;
            $monitoringTotals['excess_payments'] += $excessPayment;
        }
    }
}

// --------------------------------------------------
// RECORD MEMBERSHIP PAYMENT
// --------------------------------------------------

$paymentError = '';
$paymentSuccess = false;
$paymentMember = null;

$membershipId = 0;
$paymentFormAmount = '';
$paymentFormMethod = '';
$paymentFormReference = '';
$paymentFormDate = date('Y-m-d\TH:i');
$paymentFormRemarks = '';

$totalFee = 0;
$totalPaidForMember = 0;
$remainingBalance = 0;
$paymentExcess = 0;
$paymentStatus = 'Unpaid';
$paymentModalOpen =
    $currentView === 'payment-monitoring' &&
    array_key_exists('membership_id', $_GET);

if ($canManageOrganization && $paymentModalOpen) {

    $rawMembershipId = $_GET['membership_id'] ?? '';

    if (is_string($rawMembershipId) && ctype_digit($rawMembershipId)) {
        $membershipId = (int) $rawMembershipId;
    }

    if ($membershipId < 1) {

        $paymentError = 'Invalid membership record.';

    } else {

        $getPaymentMember = static function (
            PDO $pdo,
            int $selectedMembershipId,
            int $selectedOrganizationId
        ): ?array {

            $statement = $pdo->prepare(
                "SELECT
                    mr.membership_id,
                    mr.student_id_number,
                    mr.full_name,
                    mr.program,
                    mr.year_level,
                    mr.academic_year,
                    mr.semester,
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
                    mr.semester,
                    mr.total_fee,
                    mr.membership_status

                 LIMIT 1"
            );

            $statement->execute([
                'membership_id' => $selectedMembershipId,
                'organization_id' => $selectedOrganizationId
            ]);

            $result = $statement->fetch(PDO::FETCH_ASSOC);

            return $result ?: null;
        };

        $paymentMember = $getPaymentMember($pdo, $membershipId, $organizationId);

        if (!$paymentMember) {

            http_response_code(404);
            $paymentError = 'Member record not found in your assigned organization.';

        } else {

            $paymentFormAmount = treasurer_post_value('amount_paid');
            $paymentFormMethod = treasurer_post_value('payment_method');
            $paymentFormReference = treasurer_post_value('reference_number');
            $paymentFormRemarks = treasurer_post_value('remarks');

            if ($_SERVER['REQUEST_METHOD'] === 'POST') {

                if (!auth_csrf_is_valid()) {

                    $paymentError =
                        'Your session verification failed. Please refresh the page and try again.';

                } else {

                    $allowedMethods = [
                        'Cash',
                        'GCash',
                        'Bank Transfer',
                        'Other'
                    ];

                    if (
                        $paymentFormAmount === '' ||
                        !preg_match('/^\d+(\.\d{1,2})?$/', $paymentFormAmount) ||
                        (float) $paymentFormAmount <= 0
                    ) {

                        $paymentError = 'Enter a valid payment amount greater than zero.';

                    } elseif (!in_array($paymentFormMethod, $allowedMethods, true)) {

                        $paymentError = 'Please select a valid payment method.';

                    } elseif (strlen($paymentFormReference) > 100) {

                        $paymentError = 'The reference number must not exceed 100 characters.';

                    } elseif (strlen($paymentFormRemarks) > 5000) {

                        $paymentError = 'Remarks are too long.';

                    } else {

                        $paymentDateInput = treasurer_post_value('payment_date');

                        $paymentDate = DateTime::createFromFormat(
                            '!Y-m-d\TH:i',
                            $paymentDateInput
                        );

                        $dateErrors = DateTime::getLastErrors();

                        $validDate =
                            $paymentDate !== false &&
                            (
                                $dateErrors === false ||
                                (
                                    $dateErrors['warning_count'] === 0 &&
                                    $dateErrors['error_count'] === 0
                                )
                            ) &&
                            $paymentDate->format('Y-m-d\TH:i') === $paymentDateInput;

                        if (!$validDate) {

                            $paymentError = 'Please enter a valid payment date and time.';

                        } else {

                            try {

                                $pdo->beginTransaction();

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

                                $lockedMember = $lockStatement->fetch(PDO::FETCH_ASSOC);

                                if (!$lockedMember) {
                                    throw new RuntimeException('Member record not found.');
                                }

                                $paidStatement = $pdo->prepare(
                                    'SELECT COALESCE(SUM(amount_paid), 0)
                                     FROM membership_payments
                                     WHERE membership_id = :membership_id'
                                );

                                $paidStatement->execute([
                                    'membership_id' => $membershipId
                                ]);

                                $alreadyPaid = (float) $paidStatement->fetchColumn();

                                $lockedTotalFee = (float) $lockedMember['total_fee'];

                                $balance = max($lockedTotalFee - $alreadyPaid, 0);
                                $amount = (float) $paymentFormAmount;

                                if ($amount > $balance + 0.00001) {
                                    throw new RuntimeException(
                                        'The payment exceeds the remaining balance of PHP '
                                        . number_format($balance, 2)
                                        . '.'
                                    );
                                }

                                if ($balance <= 0) {
                                    throw new RuntimeException(
                                        'This member has no remaining balance.'
                                    );
                                }

                                $insertPaymentStatement = $pdo->prepare(
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

                                $insertPaymentStatement->execute([
                                    'membership_id' => $membershipId,
                                    'amount_paid' => number_format($amount, 2, '.', ''),
                                    'payment_method' => $paymentFormMethod,
                                    'reference_number' => $paymentFormReference !== ''
                                        ? $paymentFormReference
                                        : null,
                                    'payment_date' => $paymentDate->format('Y-m-d H:i:s'),
                                    'recorded_by' => $user['id_number'],
                                    'remarks' => $paymentFormRemarks !== ''
                                        ? $paymentFormRemarks
                                        : null
                                ]);

                                $pdo->commit();

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
                                        . $paymentFormMethod
                                    );
                                } catch (Throwable $exception) {
                                    error_log('Payment activity logging error: ' . $exception->getMessage());
                                }

                                header(
                                    'Location: treasurer_dashboard.php?view=payment-monitoring&membership_id='
                                    . $membershipId
                                    . ($monitoringSearch !== ''
                                        ? '&search=' . rawurlencode($monitoringSearch)
                                        : '')
                                    . '&success=1'
                                );
                                exit;

                            } catch (RuntimeException $exception) {

                                if ($pdo->inTransaction()) {
                                    $pdo->rollBack();
                                }

                                $paymentError = $exception->getMessage();

                            } catch (Throwable $exception) {

                                if ($pdo->inTransaction()) {
                                    $pdo->rollBack();
                                }

                                error_log('Payment recording error: ' . $exception->getMessage());

                                $paymentError = 'Unable to record the payment. Please try again.';
                            }
                        }
                    }
                }
            }

            $paymentMember = $getPaymentMember($pdo, $membershipId, $organizationId);

            if ($paymentMember) {

                $totalFee = (float) $paymentMember['total_fee'];
                $totalPaidForMember = (float) $paymentMember['total_paid'];

                $remainingBalance = $totalFee - $totalPaidForMember;
                $paymentExcess = max($totalPaidForMember - $totalFee, 0);

                if ($totalPaidForMember <= 0) {
                    $paymentStatus = 'Unpaid';
                } elseif ($totalPaidForMember >= $totalFee) {
                    $paymentStatus = 'Fully Paid';
                } elseif ($totalPaidForMember > 0) {
                    $paymentStatus = 'Partially Paid';
                }
            }

            $paymentSuccess =
                isset($_GET['success']) &&
                $_GET['success'] === '1';
        }
    }
}

// --------------------------------------------------
// PAYMENT HISTORY
// --------------------------------------------------

$paymentSearch = $_GET['search'] ?? '';

if (!is_string($paymentSearch)) {
    $paymentSearch = '';
}

$paymentSearch = trim(substr($paymentSearch, 0, 100));

$payments = [];
$totalPaymentsFound = 0;
$totalAmountReceived = 0;

if ($canManageOrganization && $currentView === 'payment-history') {

    $paymentSql = "
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
            mr.semester,

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

    $paymentParams = [
        'organization_id' => $organizationId
    ];

    if ($paymentSearch !== '') {

        $paymentSql .= "
            AND (
                mr.student_id_number LIKE :student_id
                OR mr.full_name LIKE :full_name
                OR mp.payment_method LIKE :payment_method
                OR mp.reference_number LIKE :reference_number
            )
        ";

        $searchTerm = '%' . $paymentSearch . '%';

        $paymentParams['student_id'] = $searchTerm;
        $paymentParams['full_name'] = $searchTerm;
        $paymentParams['payment_method'] = $searchTerm;
        $paymentParams['reference_number'] = $searchTerm;
    }

    $paymentSql .= ' ORDER BY mp.payment_date DESC, mp.payment_id DESC';

    $paymentHistoryStatement = $pdo->prepare($paymentSql);
    $paymentHistoryStatement->execute($paymentParams);

    $payments = $paymentHistoryStatement->fetchAll(PDO::FETCH_ASSOC);

    $totalPaymentsFound = count($payments);

    foreach ($payments as $payment) {
        $totalAmountReceived += (float) $payment['amount_paid'];
    }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Treasurer Dashboard | Student Organization Fee System</title>

    <link rel="stylesheet" href="frontend/css/treasurer_dashboard.css?v=10">

    <style>

        .logout-link {
            gap: 10px;
        }

        .logout-icon {
            width: 18px;
            height: 18px;
            flex-shrink: 0;
        }

        .dashboard-view[hidden],
        .fee-settings-panel[hidden] {
            display: none !important;
        }

        .content-panel {
            padding: 22px;
            border: 1px solid rgba(255,255,255,.24);
            border-radius: 14px;
            background: rgba(255,255,255,.96);
            color: #173323;
            box-shadow: 0 8px 22px rgba(0,0,0,.1);
        }

        .content-panel h2,
        .content-panel h3 {
            color: #1c4d2e;
        }

        .content-panel p {
            color: #667b6a;
        }

        .feature-summary-grid {
            display: grid;
            grid-template-columns: repeat(4,minmax(0,1fr));
            gap: 12px;
            margin-bottom: 22px;
        }

        .feature-summary-card {
            min-width: 0;
            padding: 17px;
            border: 1px solid #d9e4d8;
            border-radius: 12px;
            background: #fff;
        }

        .feature-summary-card span {
            display: block;
            margin-bottom: 8px;
            color: #667b6a;
            font-size: .7rem;
        }

        .feature-summary-card strong {
            display: block;
            color: #1c4d2e;
            font-size: 1.25rem;
            overflow-wrap: anywhere;
        }

        .feature-search {
            display: flex;
            gap: 10px;
            margin: 18px 0;
        }

        .feature-search input {
            flex: 1;
            min-width: 0;
        }

        .feature-search select {
            flex: 1;
            min-width: 0;
        }

        .feature-search input,
        .feature-search select,
        .feature-form input,
        .feature-form select,
        .feature-form textarea {
            width: 100%;
            padding: 11px 12px;
            border: 1px solid #c9dfcf;
            border-radius: 10px;
            background: #f8fbf9;
            color: #1f5f36;
            font-family: inherit;
            font-size: .9rem;
        }

        .feature-search input:focus,
        .feature-search select:focus,
        .feature-form input:focus,
        .feature-form select:focus,
        .feature-form textarea:focus {
            outline: 2px solid rgba(40,107,67,.18);
            border-color: #286b43;
        }

        .feature-button {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-height: 43px;
            gap: 9px;
            padding: 0 18px;
            border: 0;
            border-radius: 10px;
            background: linear-gradient(90deg, #1d6c38, #2d8a4d);
            color: #fff;
            font: inherit;
            font-size: .88rem;
            font-weight: 700;
            text-decoration: none;
            cursor: pointer;
            white-space: nowrap;
        }

        .feature-button:hover {
            filter: brightness(1.06);
        }

        .feature-button.secondary {
            background: #eaf4e9;
            color: #1c4d2e;
        }

        .feature-button.secondary:hover {
            background: #d9eadb;
        }

        .feature-button.danger {
            background: #f3d9d9;
            color: #8f2f2f;
        }

        .feature-button.danger:hover {
            background: #ebc1c1;
        }

        .feature-table-wrapper {
            width: 100%;
            overflow-x: auto;
            border: 1px solid #d9e4d8;
            border-radius: 10px;
        }

        .feature-table {
            width: 100%;
            min-width: 1120px;
            border-collapse: collapse;
            background: #fff;
        }

        .organization-fee-list {
            margin-top: 24px;
        }

        .organization-fee-list h3 {
            margin-bottom: 12px;
        }

        .organization-fee-list .feature-table {
            min-width: 650px;
        }

        .organization-fee-list .amount-cell {
            font-size: .95rem;
        }

        .feature-table th,
        .feature-table td {
            padding: 12px;
            border-bottom: 1px solid #e4eee7;
            text-align: left;
            vertical-align: top;
            font-size: .7rem;
        }

        .feature-table th {
            background: #edf8f0;
            color: #1c4d2e;
            font-weight: 600;
            white-space: nowrap;
        }

        .feature-table td {
            color: #315f40;
        }

        .feature-table.payment-monitoring-table {
            min-width: 1020px;
            table-layout: fixed;
        }

        .payment-monitoring-table th,
        .payment-monitoring-table td {
            padding: 10px 8px;
            overflow-wrap: anywhere;
        }

        .payment-monitoring-table th {
            white-space: normal;
            line-height: 1.35;
        }

        .payment-monitoring-table td {
            vertical-align: middle;
        }

        .payment-monitoring-table .feature-status {
            white-space: normal;
            text-align: center;
        }

        .payment-monitoring-table .feature-button {
            width: 100%;
            min-width: 0;
            min-height: 36px;
            padding: 6px 8px;
            font-size: .72rem;
            white-space: normal;
            text-align: center;
        }

        .monitoring-excess {
            display: block;
            margin-top: 5px;
            color: #8a6415;
            font-size: .63rem;
            line-height: 1.35;
        }

        .feature-table tbody tr:hover td {
            background: #f7fbf8;
        }

        .feature-table tbody tr:last-child td {
            border-bottom: none;
        }

        .membership-management-table th:last-child,
        .membership-management-table td:last-child {
            position: sticky;
            right: 0;
        }

        .membership-management-table th:last-child {
            z-index: 3;
            background: #edf8f0;
            box-shadow: -5px 0 8px rgba(0, 0, 0, .05);
        }

        .membership-management-table td:last-child {
            z-index: 2;
            background: #fff;
            box-shadow: -5px 0 8px rgba(0, 0, 0, .05);
        }

        .feature-status {
            display: inline-block;
            padding: 5px 9px;
            border-radius: 20px;
            font-size: .63rem;
            font-weight: 600;
            white-space: nowrap;
        }

        .feature-status.active,
        .feature-status.paid {
            background: #e1f4e6;
            color: #216b38;
        }

        .feature-status.inactive,
        .feature-status.unpaid {
            background: #f9e4e4;
            color: #a33333;
        }

        .feature-status.partial {
            background: #fff2d6;
            color: #8a6415;
        }

        .feature-status.review {
            background: #fff2d6;
            color: #8a6415;
        }

        .feature-empty {
            padding: 28px;
            color: #667b6a;
            text-align: center;
        }

        .feature-message {
            padding: 13px 15px;
            margin: 15px 0;
            border-radius: 9px;
            font-size: .76rem;
            line-height: 1.6;
        }

        .feature-message.error {
            border: 1px solid #e8b8b5;
            background: #fff1f0;
            color: #9c3028;
        }

        .feature-message.success {
            border: 1px solid #b9ddc3;
            background: #eff9f1;
            color: #155c35;
        }

        .feature-message.review {
            border: 1px solid #e8c98c;
            background: #fff8e6;
            color: #785315;
        }

        .feature-form {
            display: grid;
            gap: 15px;
            margin-top: 18px;
        }

        .feature-form label {
            display: block;
            margin-bottom: 7px;
            color: #286b43;
            font-size: .75rem;
            font-weight: 600;
        }

        .feature-form textarea {
            min-height: 95px;
            resize: vertical;
        }

        .feature-form .form-note {
            margin: -7px 0 0;
            color: #667b6a;
            font-size: .68rem;
        }

        .form-section-title {
            margin: 14px 0 0;
            padding-bottom: 9px;
            border-bottom: 1px solid #d9e4d8;
            color: #1c4d2e;
            font-size: .9rem;
        }

        .form-grid {
            display: grid;
            grid-template-columns: repeat(2,minmax(0,1fr));
            gap: 15px;
        }

        .organization-box {
            padding: 15px;
            margin: 18px 0;
            border: 1px solid #d7e9dc;
            border-radius: 10px;
            background: #f2f9f4;
            color: #155c35;
        }

        .organization-box p {
            margin: 6px 0 0;
            color: #315f40;
        }

        .member-information-grid {
            display: grid;
            grid-template-columns: repeat(2,minmax(0,1fr));
            gap: 14px;
            margin: 16px 0;
        }

        .member-information-item {
            min-width: 0;
            padding: 12px;
            border-radius: 9px;
            background: #f5faf6;
        }

        .member-information-item span {
            display: block;
            margin-bottom: 5px;
            color: #667b6a;
            font-size: .67rem;
        }

        .member-information-item strong {
            display: block;
            color: #1c4d2e;
            font-size: .78rem;
            overflow-wrap: anywhere;
        }

        .balance-highlight {
            padding: 17px;
            margin-top: 15px;
            border-radius: 10px;
            background: #edf8f0;
        }

        .balance-highlight span {
            display: block;
            color: #667b6a;
            font-size: .72rem;
        }

        .balance-highlight strong {
            display: block;
            margin-top: 5px;
            color: #1c4d2e;
            font-size: 1.6rem;
        }

        .feature-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 20px;
        }

        .reference-cell {
            max-width: 180px;
            overflow-wrap: anywhere;
        }

        .amount-cell {
            color: #1c4d2e !important;
            font-weight: 700;
            white-space: nowrap;
        }

        .delete-form {
            display: inline;
        }

        .member-action-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 7px;
        }

        .member-action-buttons .feature-button {
            min-height: 34px;
            padding: 0 13px;
            border-radius: 8px;
            font-size: .78rem;
        }

        body.fee-modal-open {
            overflow: hidden;
        }

        .fee-settings-backdrop {
            position: fixed;
            z-index: 1000;
            inset: 0;
            background: rgba(13, 31, 22, .32);
            -webkit-backdrop-filter: blur(6px);
            backdrop-filter: blur(6px);
        }

        .fee-settings-panel {
            position: fixed;
            z-index: 1001;
            top: 50%;
            left: 50%;
            width: min(660px, calc(100vw - 32px));
            max-height: calc(100vh - 40px);
            margin: 0;
            padding: 26px;
            overflow: auto;
            overscroll-behavior: contain;
            transform: translate(-50%, -50%);
            border: 1px solid #dcebdc;
            border-radius: 17px;
            background: #ffffff;
            box-shadow: 0 24px 70px rgba(0, 0, 0, .24);
        }

        .fee-modal-heading {
            display: flex;
            align-items: center;
            gap: 14px;
            margin-bottom: 8px;
        }

        .fee-modal-icon {
            display: grid;
            flex: 0 0 52px;
            width: 52px;
            height: 52px;
            place-items: center;
            border: 1px solid rgba(45, 138, 77, .22);
            border-radius: 14px;
            background: rgba(45, 138, 77, .09);
            color: #1d6c38;
            font-size: 1.65rem;
            font-weight: 700;
        }

        .fee-modal-kicker {
            margin: 0 0 4px !important;
            color: #4f8a5e !important;
            font-size: .68rem !important;
            font-weight: 700;
            letter-spacing: .1em;
            text-transform: uppercase;
        }

        .fee-modal-heading h2 {
            margin: 0;
            color: #1f5f36;
            font-size: 1.35rem;
        }

        .fee-modal-subtitle {
            margin: 0 0 18px;
            color: #4f8a5e;
            font-size: .84rem;
            line-height: 1.6;
        }

        .fee-settings-panel .organization-box {
            margin: 0 0 18px;
        }

        .fee-form-card {
            padding: 18px;
            border: 1px solid rgba(29, 102, 58, .14);
            border-radius: 14px;
            background: linear-gradient(145deg, #ffffff, #f4faf5);
        }

        .fee-form-card .feature-form {
            margin-top: 0;
        }

        .fee-modal-close {
            position: absolute;
            top: 12px;
            right: 12px;
            display: grid;
            width: 36px;
            height: 36px;
            place-items: center;
            padding: 0;
            border: 0;
            border-radius: 50%;
            background: #edf8f0;
            color: #1f5f36;
            font: inherit;
            font-size: 1.5rem;
            line-height: 1;
            cursor: pointer;
        }

        .fee-modal-close:hover {
            background: #dcefe1;
        }

        .fee-modal-close:focus-visible {
            outline: 3px solid rgba(45, 138, 77, .35);
            outline-offset: 2px;
        }

        .fee-form-description {
            margin: 0 0 16px;
            color: #4f8a5e;
            font-size: .84rem;
            line-height: 1.6;
        }

        .fee-amount-input {
            display: flex;
            align-items: center;
            gap: 8px;
            max-width: 420px;
            padding: 0 12px;
            border: 1px solid #c9dfcf;
            border-radius: 10px;
            background: #f8fbf9;
            color: #1f5f36;
        }

        .fee-amount-input span {
            color: #4f8a5e;
            font-weight: 700;
        }

        .feature-form .fee-amount-input input {
            flex: 1;
            min-width: 0;
            padding: 11px 0;
            border: 0;
            background: transparent;
        }

        .feature-form .fee-amount-input input:focus {
            border: 0;
            outline: none;
            box-shadow: none;
        }

        .fee-amount-input:focus-within {
            border-color: #2d8a4d;
            box-shadow: 0 0 0 3px rgba(45, 138, 77, .11);
        }

        #feeSettingsTitle,
        #paymentModalTitle,
        #deleteConfirmationTitle {
            padding-right: 42px;
        }

        #deleteConfirmationPanel {
            width: min(420px, calc(100vw - 32px));
            padding: 22px;
        }

        #deleteConfirmationPanel .feature-actions {
            justify-content: flex-end;
            margin-top: 16px;
        }

        @media (max-width: 1050px) {
            .feature-summary-grid {
                grid-template-columns: repeat(2,minmax(0,1fr));
            }
        }

        @media (max-width: 650px) {
            .feature-summary-grid,
            .form-grid,
            .member-information-grid {
                grid-template-columns: 1fr;
            }

            .feature-search {
                flex-wrap: wrap;
            }

            .feature-search input,
            .feature-search select {
                flex-basis: 100%;
            }

            .feature-search .feature-button {
                flex: 1;
            }

            .content-panel {
                padding: 16px;
            }

            .fee-settings-panel {
                width: calc(100vw - 24px);
                max-height: calc(100vh - 24px);
            }

            .fee-form-card {
                padding: 14px;
            }

            .fee-modal-icon {
                flex-basis: 44px;
                width: 44px;
                height: 44px;
            }
        }

    </style>

</head>

<body>

<div class="dashboard-container">

    <!-- SIDEBAR -->
    <aside class="sidebar">

        <div class="sidebar-brand">
            <a class="sidebar-brand-link" href="treasurer_dashboard.php?view=overview">
                <span class="sidebar-brand-mark">
                    <img src="images/logo.jpg" alt="Organization logo">
                </span>
                <span>Organization<br>Fee System</span>
            </a>
            <p><?= e($organization['organization_acronym'] ?? 'Treasurer Panel') ?></p>
        </div>

        <nav class="sidebar-navigation">

            <a
                href="treasurer_dashboard.php?view=overview"
                aria-current="<?= $currentView === 'overview' ? 'page' : 'false' ?>"
                class="nav-link<?= $currentView === 'overview' ? ' active' : '' ?>"
            >
                Overview
            </a>

            <?php if ($canManageOrganization): ?>

                <a
                    href="treasurer_dashboard.php?view=members"
                    aria-current="<?= $currentView === 'members' ? 'page' : 'false' ?>"
                    class="nav-link<?= $currentView === 'members' ? ' active' : '' ?>"
                >
                    Membership Management
                </a>

                <a
                    href="treasurer_dashboard.php?view=add-member"
                    aria-current="<?= $currentView === 'add-member' ? 'page' : 'false' ?>"
                    class="nav-link<?= $currentView === 'add-member' ? ' active' : '' ?>"
                >
                    Add New Member
                </a>

                <a
                    href="treasurer_dashboard.php?view=payment-monitoring"
                    aria-current="<?= in_array($currentView, ['payment-monitoring', 'record-payment'], true) ? 'page' : 'false' ?>"
                    class="nav-link<?= in_array($currentView, ['payment-monitoring', 'record-payment'], true) ? ' active' : '' ?>"
                >
                    Payment Monitoring
                </a>

                <a
                    href="treasurer_dashboard.php?view=payment-history"
                    aria-current="<?= $currentView === 'payment-history' ? 'page' : 'false' ?>"
                    class="nav-link<?= $currentView === 'payment-history' ? ' active' : '' ?>"
                >
                    Payment History
                </a>

            <?php endif; ?>

            <a
                href="treasurer_dashboard.php?view=account-settings"
                aria-current="<?= $currentView === 'account-settings' ? 'page' : 'false' ?>"
                class="nav-link<?= $currentView === 'account-settings' ? ' active' : '' ?>"
            >
                Account Settings
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
                Logout
            </a>

        </nav>

    </aside>


    <!-- MAIN CONTENT -->
    <main class="main-content">

        <header class="dashboard-header<?= $currentView === 'overview' ? ' dashboard-welcome' : '' ?>">

            <div>

                <?php if ($currentView === 'overview' && $organization): ?>
                    <p class="dashboard-eyebrow">
                        Organization Dashboard · <?= e($organization['organization_acronym']) ?>
                    </p>
                <?php endif; ?>

                <?php
                $pageTitles = [
                    'members' => 'Membership Management',
                    'add-member' => 'Add New Member',
                    'record-payment' => 'Record Membership Payment',
                    'payment-monitoring' => 'Payment Monitoring',
                    'payment-history' => 'Payment History',
                    'account-settings' => 'Account Settings'
                ];
                ?>

                <h1><?= e($currentView === 'overview' ? 'Welcome, ' . $name . '!' : ($pageTitles[$currentView] ?? 'Treasurer Dashboard')) ?></h1>

                <p>
                    Manage your organization's membership records
                    and monitor membership fee payments.
                </p>

            </div>

        </header>


        <?php if ($currentView === 'account-settings'): ?>

            <section class="dashboard-view">

                <section class="dashboard-section">

                    <div class="section-heading">
                        <h2>Account Settings</h2>
                        <p>Update the password for your Treasurer account.</p>
                    </div>

                    <div class="content-panel">

                        <h2>Change Password</h2>
                        <p>
                            Your new password must be 8–64 characters and meet at least
                            three password strength criteria.
                        </p>

                        <?php if ($passwordChangeError !== ''): ?>
                            <div class="feature-message error" role="alert">
                                <?= e($passwordChangeError) ?>
                            </div>
                        <?php endif; ?>

                        <?php if ($passwordChangeSuccess !== ''): ?>
                            <div class="feature-message success" role="status">
                                <?= e($passwordChangeSuccess) ?>
                            </div>
                        <?php endif; ?>

                        <form
                            method="POST"
                            action="treasurer_dashboard.php?view=account-settings"
                            class="feature-form"
                        >

                            <input
                                type="hidden"
                                name="csrf_token"
                                value="<?= e($_SESSION['csrf_token']) ?>"
                            >
                            <input
                                type="hidden"
                                name="form_action"
                                value="change_password"
                            >

                            <div>
                                <label for="current_password">Current Password</label>
                                <input
                                    type="password"
                                    id="current_password"
                                    name="current_password"
                                    autocomplete="current-password"
                                    required
                                >
                            </div>

                            <div>
                                <label for="new_password">New Password</label>
                                <input
                                    type="password"
                                    id="new_password"
                                    name="new_password"
                                    minlength="8"
                                    maxlength="64"
                                    autocomplete="new-password"
                                    required
                                >
                            </div>

                            <div>
                                <label for="confirm_password">Confirm New Password</label>
                                <input
                                    type="password"
                                    id="confirm_password"
                                    name="confirm_password"
                                    minlength="8"
                                    maxlength="64"
                                    autocomplete="new-password"
                                    required
                                >
                            </div>

                            <div class="feature-actions">
                                <button type="submit" class="feature-button">
                                    Change Password
                                </button>
                            </div>

                        </form>

                    </div>

                </section>

            </section>

        <?php elseif ($approvalStatus === 'APPROVED' && $organization): ?>


            <!-- ================================== -->
            <!-- OVERVIEW -->
            <!-- ================================== -->

            <section
                class="dashboard-view"
                <?= $currentView !== 'overview' ? 'hidden' : '' ?>
            >

                <section class="dashboard-section">

                    <div class="section-heading">
                        <h2>Membership Overview</h2>
                        <p>
                            Summary of membership records for your assigned organization.
                        </p>
                    </div>

                    <div class="summary-grid">

                        <article class="summary-card">
                            <p>Total Members</p>
                            <h3><?= number_format($statistics['total_members']) ?></h3>
                        </article>

                        <article class="summary-card">
                            <p>Fully Paid</p>
                            <h3><?= number_format($statistics['fully_paid']) ?></h3>
                        </article>

                        <article class="summary-card">
                            <p>Partially Paid</p>
                            <h3><?= number_format($statistics['partially_paid']) ?></h3>
                        </article>

                        <article class="summary-card">
                            <p>Unpaid</p>
                            <h3><?= number_format($statistics['unpaid']) ?></h3>
                        </article>

                    </div>

                </section>

                <section class="dashboard-section">

                    <div class="section-heading organization-heading">
                        <div>
                            <h2>My Organization</h2>
                            <p>Your currently assigned organization.</p>
                        </div>
                        <button
                            id="openFeeSettingsButton"
                            type="button"
                            class="dashboard-button"
                            aria-controls="feeSettingsPanel"
                            aria-expanded="false"
                            onclick="openFeeSettings()"
                        >
                            Set Organizational Fee
                        </button>
                    </div>

                    <div class="dashboard-panel">

                        <div class="organization-grid">

                            <div class="organization-item">
                                <span>Organization Name</span>
                                <strong><?= e($organization['organization_name']) ?></strong>
                            </div>

                            <div class="organization-item">
                                <span>Organization Acronym</span>
                                <strong><?= e($organization['organization_acronym']) ?></strong>
                            </div>

                            <div class="organization-item">
                                <span>Organization Type</span>
                                <strong><?= e($organization['organization_type']) ?></strong>
                            </div>

                            <div class="organization-item">
                                <span>Department / College</span>
                                <strong><?= e($organization['department_college']) ?></strong>
                            </div>

                        </div>

                        <?php if ($feeSuccess !== ''): ?>
                            <div class="feature-message success" role="status">
                                <?= e($feeSuccess) ?>
                            </div>
                        <?php endif; ?>

                        <section
                            class="organization-fee-list"
                            aria-labelledby="organizationFeeListTitle"
                        >
                            <h3 id="organizationFeeListTitle">Configured Membership Fees</h3>

                            <div class="feature-table-wrapper">
                                <table class="feature-table">
                                    <thead>
                                        <tr>
                                            <th>Academic Year</th>
                                            <th>Semester</th>
                                            <th>Membership Fee</th>
                                            <th>Last Updated</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if (empty($feeSettings)): ?>
                                            <tr>
                                                <td colspan="5" class="feature-empty">
                                                    No organizational fee settings have been added yet.
                                                </td>
                                            </tr>
                                        <?php else: ?>
                                            <?php foreach ($feeSettings as $setting): ?>
                                                <tr>
                                                    <td><?= e($setting['academic_year']) ?></td>
                                                    <td><?= e($setting['semester']) ?></td>
                                                    <td class="amount-cell">
                                                        ₱<?= number_format((float) $setting['membership_fee'], 2) ?>
                                                    </td>
                                                    <td>
                                                        <?= e(date(
                                                            'M d, Y h:i A',
                                                            strtotime($setting['updated_at'])
                                                        )) ?>
                                                    </td>
                                                    <td>
                                                        <button
                                                            type="button"
                                                            class="feature-button secondary"
                                                            aria-label="Edit membership fee for <?= e($setting['academic_year']) ?>, <?= e($setting['semester']) ?>"
                                                            data-fee-setting-id="<?= (int) $setting['fee_setting_id'] ?>"
                                                            data-academic-year="<?= e($setting['academic_year']) ?>"
                                                            data-semester="<?= e($setting['semester']) ?>"
                                                            data-membership-fee="<?= e(number_format((float) $setting['membership_fee'], 2, '.', '')) ?>"
                                                            onclick="editOrganizationFee(this)"
                                                        >
                                                            Edit
                                                        </button>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                        </section>

                    </div>

                </section>

                <!-- QUICK ACTIONS -->
                <section class="dashboard-section">

                    <div class="section-heading">
                        <h2>Quick Actions</h2>
                        <p>Select a feature to manage your organization.</p>
                    </div>

                    <div class="action-grid">

                        <article class="action-card">
                            <div class="action-icon">+</div>
                            <h3>Add New Member</h3>
                            <p>
                                Register a new member using your configured organizational fee.
                            </p>
                            <a href="treasurer_dashboard.php?view=add-member" class="dashboard-button">
                                Add Member
                            </a>
                        </article>

                        <article class="action-card">
                            <div class="action-icon">≡</div>
                            <h3>Membership Management</h3>
                            <p>
                                Search and review your organization's membership records.
                            </p>
                            <a href="treasurer_dashboard.php?view=members" class="dashboard-button">
                                View Members
                            </a>
                        </article>

                        <article class="action-card">
                            <div class="action-icon">₱</div>
                            <h3>Payment Monitoring</h3>
                            <p>
                                Monitor member payment statuses, outstanding balances, and excess payments.
                            </p>
                            <a href="treasurer_dashboard.php?view=payment-monitoring" class="dashboard-button">
                                Monitor Payments
                            </a>
                        </article>

                    </div>

                </section>

                <!-- ORGANIZATIONAL FEE PANEL -->
                <div
                    class="fee-settings-backdrop"
                    id="feeSettingsBackdrop"
                    aria-hidden="true"
                    hidden
                    onclick="toggleFeeSettings()"
                ></div>

                <section
                    class="content-panel fee-settings-panel"
                    id="feeSettingsPanel"
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="feeSettingsTitle"
                    tabindex="-1"
                    hidden
                >

                    <button
                        type="button"
                        class="fee-modal-close"
                        aria-label="Close organizational fee form"
                        onclick="toggleFeeSettings()"
                    >&times;</button>

                    <div class="fee-modal-heading">
                        <span class="fee-modal-icon" aria-hidden="true">₱</span>
                        <div>
                            <p class="fee-modal-kicker">Organization Fee Settings</p>
                            <h2 id="feeSettingsTitle">
                                <?= $feeOld['fee_setting_id'] !== ''
                                    ? 'Edit Membership Fee'
                                    : 'Set Membership Fee' ?>
                            </h2>
                        </div>
                    </div>

                    <p class="fee-modal-subtitle">
                        Set the membership fee for a specific academic year and semester.
                    </p>

                    <div class="organization-box">
                        <strong>Assigned Organization</strong>
                        <p>
                            <?= e($organization['organization_name']) ?>
                            (<?= e($organization['organization_acronym']) ?>)
                        </p>
                    </div>

                    <?php if ($feeError !== ''): ?>
                        <div class="feature-message error" id="feeSettingsError">
                            <?= e($feeError) ?>
                        </div>
                    <?php endif; ?>

                    <div class="fee-form-card">
                        <p class="fee-form-description">
                            Saving an existing term updates its configuration and applies
                            the fee to existing members with the same academic year and
                            semester. Records marked Not specified are not changed.
                        </p>

                        <form
                            method="POST"
                            action="treasurer_dashboard.php?view=overview"
                            class="feature-form"
                        >

                            <input type="hidden" name="csrf_token" value="<?= e($_SESSION['csrf_token']) ?>">
                            <input type="hidden" name="form_action" value="save_organization_fee">
                            <input
                                type="hidden"
                                id="fee_setting_id"
                                name="fee_setting_id"
                                value="<?= e($feeOld['fee_setting_id']) ?>"
                            >
                            <input
                                type="hidden"
                                id="fee_semester_edit"
                                name="semester"
                                value="<?= e($feeOld['semester']) ?>"
                                <?= $feeOld['fee_setting_id'] === '' ? 'disabled' : '' ?>
                            >

                            <div class="form-grid">

                                <div>
                                    <label for="fee_academic_year">Academic Year *</label>
                                    <input
                                        type="text"
                                        id="fee_academic_year"
                                        name="academic_year"
                                        maxlength="20"
                                        placeholder="Example: 2026-2027"
                                        value="<?= e($feeOld['academic_year']) ?>"
                                        pattern="[0-9]{4}-[0-9]{4}"
                                        <?= $feeOld['fee_setting_id'] !== '' ? 'readonly' : '' ?>
                                        required
                                    >
                                </div>

                                <div>
                                    <label for="fee_semester">Semester *</label>
                                    <select
                                        id="fee_semester"
                                        name="semester"
                                        <?= $feeOld['fee_setting_id'] !== '' ? 'disabled' : '' ?>
                                        required
                                    >
                                        <option value="">Select semester</option>

                                        <?php foreach ($allowedSemesters as $semesterOption): ?>
                                            <option
                                                value="<?= e($semesterOption) ?>"
                                                <?= $feeOld['semester'] === $semesterOption ? 'selected' : '' ?>
                                            >
                                                <?= e($semesterOption) ?>
                                            </option>
                                        <?php endforeach; ?>

                                    </select>
                                </div>

                                <div class="fee-amount-field">
                                    <label for="membership_fee">Membership Fee (PHP) *</label>
                                    <div class="fee-amount-input">
                                        <span aria-hidden="true">₱</span>
                                        <input
                                            type="number"
                                            id="membership_fee"
                                            name="membership_fee"
                                            min="0"
                                            max="99999999.99"
                                            step="0.01"
                                            placeholder="Example: 150.00"
                                            value="<?= e($feeOld['membership_fee']) ?>"
                                            required
                                        >
                                    </div>
                                </div>

                            </div>

                            <p class="form-note" id="feeFormNote">
                                <?= $feeOld['fee_setting_id'] !== ''
                                    ? 'Editing changes the membership fee only; the academic year and semester stay the same.'
                                    : 'Example terms: 1st Semester, 2nd Semester, and Summer.' ?>
                            </p>

                            <div class="feature-actions">
                                <button
                                    type="submit"
                                    id="saveOrganizationFeeButton"
                                    class="feature-button"
                                >
                                    <?= $feeOld['fee_setting_id'] !== ''
                                        ? 'Update Membership Fee'
                                        : 'Save Membership Fee' ?>
                                </button>

                                <button
                                    type="button"
                                    class="feature-button secondary"
                                    onclick="toggleFeeSettings()"
                                >
                                    Close
                                </button>
                            </div>

                        </form>
                    </div>

                </section>

            </section>


            <!-- ================================== -->
            <!-- MEMBERSHIP MANAGEMENT -->
            <!-- ================================== -->

            <section
                class="dashboard-view"
                <?= $currentView !== 'members' ? 'hidden' : '' ?>
            >

                <section class="dashboard-section">

                    <div class="section-heading">
                        <h2>Organization Members</h2>
                        <p>
                            <?= e($organization['organization_name']) ?>
                            (<?= e($organization['organization_acronym']) ?>)
                        </p>
                    </div>

                    <?php if ($deleteError !== ''): ?>
                        <div class="feature-message error">
                            <?= e($deleteError) ?>
                        </div>
                    <?php endif; ?>

                    <?php if ($deleteSuccess !== ''): ?>
                        <div class="feature-message success">
                            <?= e($deleteSuccess) ?>
                        </div>
                    <?php endif; ?>

                    <div class="feature-summary-grid">

                        <div class="feature-summary-card">
                            <span>Members Found</span>
                            <strong><?= number_format($totalMembersFound) ?></strong>
                        </div>

                        <div class="feature-summary-card">
                            <span>Total Expected Collection</span>
                            <strong>₱<?= number_format($totalFees, 2) ?></strong>
                        </div>

                        <div class="feature-summary-card">
                            <span>Total Amount Collected</span>
                            <strong>₱<?= number_format($totalPaid, 2) ?></strong>
                        </div>

                        <div class="feature-summary-card">
                            <span>Outstanding Balance</span>
                            <strong>₱<?= number_format($totalBalance, 2) ?></strong>
                        </div>

                    </div>

                    <?php if ($overpaidMemberCount > 0): ?>
                        <div class="feature-message review">
                            <?= number_format($overpaidMemberCount) ?>
                            member record(s) need excess-payment review.
                            Total excess: ₱<?= number_format($totalExcessPayments, 2) ?>.
                        </div>
                    <?php endif; ?>

                    <div class="content-panel">

                        <h2>Member Records</h2>

                        <p>
                            Search by Student ID, full name, program, year level, academic year, or semester.
                        </p>

                        <form method="GET" action="treasurer_dashboard.php" class="feature-search">

                            <input type="hidden" name="view" value="members">

                            <input
                                type="search"
                                name="search"
                                aria-label="Search member records"
                                placeholder="Search member records..."
                                value="<?= e($memberSearch) ?>"
                                maxlength="100"
                            >

                            <select
                                name="academic_year"
                                aria-label="Filter by academic year"
                            >
                                <option value="">All academic years</option>
                                <?php foreach ($memberAcademicYearOptions as $academicYearOption): ?>
                                    <option
                                        value="<?= e($academicYearOption) ?>"
                                        <?= $memberAcademicYearFilter === $academicYearOption ? 'selected' : '' ?>
                                    >
                                        <?= e($academicYearOption) ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>

                            <select
                                name="year_level"
                                aria-label="Filter by year level"
                            >
                                <option value="">All year levels</option>
                                <?php foreach ($memberYearLevelOptions as $yearLevelOption): ?>
                                    <option
                                        value="<?= e($yearLevelOption) ?>"
                                        <?= $memberYearLevelFilter === $yearLevelOption ? 'selected' : '' ?>
                                    >
                                        <?= e($yearLevelOption) ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>

                            <button type="submit" class="feature-button">Search / Filter</button>

                            <?php if (
                                $memberSearch !== '' ||
                                $memberAcademicYearFilter !== '' ||
                                $memberYearLevelFilter !== ''
                            ): ?>
                                <a href="treasurer_dashboard.php?view=members" class="feature-button secondary">
                                    Clear
                                </a>
                            <?php endif; ?>

                        </form>

                        <div class="feature-table-wrapper">

                            <table class="feature-table membership-management-table">

                                <thead>
                                    <tr>
                                        <th>Student ID</th>
                                        <th>Full Name</th>
                                        <th>Program</th>
                                        <th>Year Level</th>
                                        <th>Academic Year</th>
                                        <th>Semester</th>
                                        <th>Membership Fee</th>
                                        <th>Total Paid</th>
                                        <th>Outstanding Balance</th>
                                        <th>Excess Payment Review</th>
                                        <th>Membership Status</th>
                                        <th>Payment Status</th>
                                        <th>Membership Actions</th>
                                    </tr>
                                </thead>

                                <tbody>

                                    <?php if (empty($members)): ?>

                                        <tr>
                                            <td colspan="13" class="feature-empty">
                                                No member records found.
                                            </td>
                                        </tr>

                                    <?php else: ?>

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

                                                <td><?= e($member['student_id_number']) ?></td>
                                                <td><?= e($member['full_name']) ?></td>
                                                <td><?= e($member['program']) ?></td>
                                                <td><?= e($member['year_level']) ?></td>
                                                <td><?= e($member['academic_year']) ?></td>
                                                <td><?= e($member['semester'] ?: 'Not specified') ?></td>

                                                <td>₱<?= number_format($fee, 2) ?></td>
                                                <td>₱<?= number_format($paid, 2) ?></td>
                                                <td>₱<?= number_format($balance, 2) ?></td>
                                                <td>
                                                    <?php if ($excessPayment > 0): ?>
                                                        <span class="feature-status review">
                                                            Review: ₱<?= number_format($excessPayment, 2) ?>
                                                        </span>
                                                    <?php else: ?>
                                                        —
                                                    <?php endif; ?>
                                                </td>

                                                <td>
                                                    <span class="feature-status <?= $membershipStatus === 'ACTIVE' ? 'active' : 'inactive' ?>">
                                                        <?= e($membershipStatus) ?>
                                                    </span>
                                                </td>

                                                <td>
                                                    <span class="feature-status <?= e($paymentClass) ?>">
                                                        <?= e($member['payment_status']) ?>
                                                    </span>
                                                </td>

                                                <td>
                                                    <div class="member-action-buttons">

                                                        <?php if ($balance > 0): ?>
                                                            <a
                                                                href="treasurer_dashboard.php?view=payment-monitoring&membership_id=<?= (int) $member['membership_id'] ?>"
                                                                class="feature-button"
                                                                aria-label="Record payment for <?= e($member['full_name']) ?>"
                                                            >
                                                                Record Payment
                                                            </a>
                                                        <?php else: ?>
                                                            <span class="feature-status paid">Completed</span>
                                                        <?php endif; ?>

                                                        <form
                                                            method="POST"
                                                            action="treasurer_dashboard.php?view=members"
                                                            class="delete-form"
                                                            data-member-name="<?= e($member['full_name']) ?>"
                                                        >

                                                            <input
                                                                type="hidden"
                                                                name="csrf_token"
                                                                value="<?= e($_SESSION['csrf_token']) ?>"
                                                            >

                                                            <input
                                                                type="hidden"
                                                                name="form_action"
                                                                value="delete_member"
                                                            >

                                                            <input
                                                                type="hidden"
                                                                name="membership_id"
                                                                value="<?= (int) $member['membership_id'] ?>"
                                                            >

                                                            <button
                                                                type="button"
                                                                class="feature-button danger"
                                                                aria-haspopup="dialog"
                                                                onclick="openDeleteConfirmation(this.form)"
                                                            >
                                                                Delete Member
                                                            </button>

                                                        </form>

                                                    </div>
                                                </td>

                                            </tr>

                                        <?php endforeach; ?>

                                    <?php endif; ?>

                                </tbody>

                            </table>

                        </div>

                        <div class="feature-actions">
                            <a href="treasurer_dashboard.php?view=add-member" class="feature-button">
                                Add New Member
                            </a>
                        </div>

                    </div>

                    <div
                        class="fee-settings-backdrop"
                        id="deleteConfirmationBackdrop"
                        aria-hidden="true"
                        hidden
                        onclick="closeDeleteConfirmation()"
                    ></div>

                    <section
                        class="content-panel fee-settings-panel"
                        id="deleteConfirmationPanel"
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="deleteConfirmationTitle"
                        aria-describedby="deleteConfirmationMessage"
                        tabindex="-1"
                        hidden
                    >

                        <button
                            type="button"
                            class="fee-modal-close"
                            aria-label="Close delete confirmation"
                            onclick="closeDeleteConfirmation()"
                        >&times;</button>

                        <div class="fee-modal-heading">
                            <span class="fee-modal-icon" aria-hidden="true">!</span>
                            <div>
                                <p class="fee-modal-kicker">Confirm Action</p>
                                <h2 id="deleteConfirmationTitle">Delete Member?</h2>
                            </div>
                        </div>

                        <p class="fee-modal-subtitle" id="deleteConfirmationMessage">
                            Permanently delete
                            <strong id="deleteMemberName"></strong> and all associated
                            payment transactions? This action cannot be undone.
                        </p>

                        <div class="feature-actions">
                            <button
                                type="button"
                                class="feature-button secondary"
                                onclick="closeDeleteConfirmation()"
                            >
                                Cancel
                            </button>
                            <button
                                type="button"
                                class="feature-button danger"
                                onclick="confirmMemberDeletion()"
                            >
                                Delete Permanently
                            </button>
                        </div>

                    </section>

                </section>

            </section>


            <!-- ================================== -->
            <!-- ADD NEW MEMBER -->
            <!-- ================================== -->

            <section
                class="dashboard-view"
                <?= $currentView !== 'add-member' ? 'hidden' : '' ?>
            >

                <section class="dashboard-section">

                    <div class="section-heading">
                        <h2>Add New Member</h2>
                        <p>Register a student under your assigned organization.</p>
                    </div>

                    <div class="content-panel">

                        <div class="organization-box">
                            <strong>Assigned Organization</strong>
                            <p>
                                <?= e($organization['organization_name']) ?>
                                (<?= e($organization['organization_acronym']) ?>)
                            </p>
                        </div>

                        <?php if ($memberError !== ''): ?>
                            <div class="feature-message error">
                                <?= e($memberError) ?>
                            </div>
                        <?php endif; ?>

                        <?php if ($memberSuccess !== ''): ?>
                            <div class="feature-message success">
                                <?= e($memberSuccess) ?>
                            </div>
                        <?php endif; ?>

                        <form
                            method="POST"
                            action="treasurer_dashboard.php?view=add-member"
                            class="feature-form"
                        >

                            <input
                                type="hidden"
                                name="csrf_token"
                                value="<?= e($_SESSION['csrf_token']) ?>"
                            >

                            <h3 class="form-section-title">Student Information</h3>

                            <div class="form-grid">

                                <div>
                                    <label for="student_id_number">Student ID Number *</label>
                                    <input
                                        type="text"
                                        id="student_id_number"
                                        name="student_id_number"
                                        maxlength="30"
                                        value="<?= e($memberOld['student_id_number']) ?>"
                                        required
                                    >
                                </div>

                                <div>
                                    <label for="full_name">Full Name *</label>
                                    <input
                                        type="text"
                                        id="full_name"
                                        name="full_name"
                                        maxlength="150"
                                        value="<?= e($memberOld['full_name']) ?>"
                                        required
                                    >
                                </div>

                                <div>
                                    <label for="program">Program *</label>
                                    <input
                                        type="text"
                                        id="program"
                                        name="program"
                                        maxlength="100"
                                        value="<?= e($memberOld['program']) ?>"
                                        placeholder="Example: Bachelor of Science in Information Technology"
                                        required
                                    >
                                </div>

                                <div>
                                    <label for="year_level">Year Level *</label>
                                    <select id="year_level" name="year_level" required>
                                        <option value="">Select year level</option>
                                        <?php foreach ($allowedYearLevels as $yearLevelOption): ?>
                                            <option
                                                value="<?= e($yearLevelOption) ?>"
                                                <?= $memberOld['year_level'] === $yearLevelOption ? 'selected' : '' ?>
                                            >
                                                <?= e($yearLevelOption) ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>

                                <div>
                                    <label for="academic_year">Academic Year *</label>
                                    <input
                                        type="text"
                                        id="academic_year"
                                        name="academic_year"
                                        maxlength="20"
                                        value="<?= e($memberOld['academic_year']) ?>"
                                        placeholder="Example: 2026-2027"
                                        pattern="[0-9]{4}-[0-9]{4}"
                                        required
                                    >
                                </div>

                                <div>
                                    <label for="semester">Semester *</label>
                                    <select id="semester" name="semester" required>
                                        <option value="">Select semester</option>

                                        <?php foreach ($allowedSemesters as $semesterOption): ?>
                                            <option
                                                value="<?= e($semesterOption) ?>"
                                                <?= $memberOld['semester'] === $semesterOption ? 'selected' : '' ?>
                                            >
                                                <?= e($semesterOption) ?>
                                            </option>
                                        <?php endforeach; ?>

                                    </select>
                                </div>

                            </div>

                            <div class="organization-box">
                                <strong>Membership Fee</strong>
                                <p>
                                    The membership fee will automatically be retrieved
                                    from your organizational fee settings based on the
                                    selected academic year and semester.
                                </p>
                                <p>
                                    You must configure the fee before registering members
                                    for that academic term.
                                </p>
                            </div>

                            <h3 class="form-section-title">Emergency Contact</h3>

                            <p class="form-note">
                                These fields are optional. The contact number
                                will be encrypted before it is stored.
                            </p>

                            <div class="form-grid">

                                <div>
                                    <label for="emergency_contact_name">Emergency Contact Name</label>
                                    <input
                                        type="text"
                                        id="emergency_contact_name"
                                        name="emergency_contact_name"
                                        maxlength="100"
                                        value="<?= e($memberOld['emergency_contact_name']) ?>"
                                    >
                                </div>

                                <div>
                                    <label for="emergency_contact_relationship">Relationship</label>
                                    <input
                                        type="text"
                                        id="emergency_contact_relationship"
                                        name="emergency_contact_relationship"
                                        maxlength="50"
                                        value="<?= e($memberOld['emergency_contact_relationship']) ?>"
                                        placeholder="Example: Mother"
                                    >
                                </div>

                                <div>
                                    <label for="emergency_contact_number">Emergency Contact Number</label>
                                    <input
                                        type="tel"
                                        id="emergency_contact_number"
                                        name="emergency_contact_number"
                                        maxlength="30"
                                        value="<?= e($memberOld['emergency_contact_number']) ?>"
                                        placeholder="Example: 09123456789"
                                    >
                                </div>

                            </div>

                            <div class="feature-actions">

                                <button type="submit" class="feature-button">
                                    Save Member
                                </button>

                                <a
                                    href="treasurer_dashboard.php?view=members"
                                    class="feature-button secondary"
                                >
                                    Cancel
                                </a>

                            </div>

                        </form>

                    </div>

                </section>

            </section>


            <!-- ================================== -->
            <!-- PAYMENT MONITORING -->
            <!-- ================================== -->

            <section
                class="dashboard-view"
                <?= $currentView !== 'payment-monitoring' ? 'hidden' : '' ?>
            >

                <section class="dashboard-section">

                    <div class="section-heading">
                        <h2>Payment Monitoring</h2>
                        <p>
                            Monitor all members, their payment status,
                            total payments, outstanding balances, and excess-payment reviews.
                        </p>
                    </div>

                    <div class="feature-summary-grid">

                        <div class="feature-summary-card">
                            <span>Members Found</span>
                            <strong><?= number_format($monitoringTotals['members']) ?></strong>
                        </div>

                        <div class="feature-summary-card">
                            <span>Total Expected Collection</span>
                            <strong>₱<?= number_format($monitoringTotals['fees'], 2) ?></strong>
                        </div>

                        <div class="feature-summary-card">
                            <span>Total Amount Collected</span>
                            <strong>₱<?= number_format($monitoringTotals['paid'], 2) ?></strong>
                        </div>

                        <div class="feature-summary-card">
                            <span>Outstanding Balance</span>
                            <strong>₱<?= number_format($monitoringTotals['balance'], 2) ?></strong>
                        </div>

                    </div>

                    <?php if ($monitoringTotals['overpaid_members'] > 0): ?>
                        <div class="feature-message review">
                            <?= number_format($monitoringTotals['overpaid_members']) ?>
                            member record(s) need excess-payment review.
                            Total excess: ₱<?= number_format($monitoringTotals['excess_payments'], 2) ?>.
                        </div>
                    <?php endif; ?>

                    <div class="content-panel">

                        <h2>Member Payment Records</h2>

                        <p>
                            This page includes members who have not made any payment yet.
                        </p>

                        <form method="GET" action="treasurer_dashboard.php" class="feature-search">

                            <input type="hidden" name="view" value="payment-monitoring">

                            <input
                                type="search"
                                name="search"
                                aria-label="Search member payment records"
                                placeholder="Search Student ID, name, program, or academic term..."
                                value="<?= e($monitoringSearch) ?>"
                                maxlength="100"
                            >

                            <button type="submit" class="feature-button">Search</button>

                            <?php if ($monitoringSearch !== ''): ?>
                                <a
                                    href="treasurer_dashboard.php?view=payment-monitoring"
                                    class="feature-button secondary"
                                >
                                    Clear
                                </a>
                            <?php endif; ?>

                        </form>

                        <div class="feature-table-wrapper">

                            <table class="feature-table payment-monitoring-table">

                                <colgroup>
                                    <col style="width:9%">
                                    <col style="width:13%">
                                    <col style="width:15%">
                                    <col style="width:9%">
                                    <col style="width:9%">
                                    <col style="width:8%">
                                    <col style="width:8%">
                                    <col style="width:10%">
                                    <col style="width:9%">
                                    <col style="width:10%">
                                </colgroup>

                                <thead>
                                    <tr>
                                        <th>Student ID</th>
                                        <th>Full Name</th>
                                        <th>Program</th>
                                        <th>Academic Year</th>
                                        <th>Semester</th>
                                        <th>Membership Fee</th>
                                        <th>Total Paid</th>
                                        <th>Outstanding Balance</th>
                                        <th>Payment Status</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>

                                <tbody>

                                    <?php if (empty($monitoringMembers)): ?>

                                        <tr>
                                            <td colspan="10" class="feature-empty">
                                                No member payment records found.
                                            </td>
                                        </tr>

                                    <?php else: ?>

                                        <?php foreach ($monitoringMembers as $record): ?>

                                            <?php
                                            $statusClass = 'unpaid';

                                            if ($record['payment_status'] === 'Fully Paid') {
                                                $statusClass = 'paid';
                                            } elseif ($record['payment_status'] === 'Partially Paid') {
                                                $statusClass = 'partial';
                                            } elseif ($record['payment_status'] === 'Unpaid') {
                                                $statusClass = 'unpaid';
                                            }
                                            ?>

                                            <tr>

                                                <td><?= e($record['student_id_number']) ?></td>
                                                <td><?= e($record['full_name']) ?></td>
                                                <td><?= e($record['program']) ?></td>
                                                <td><?= e($record['academic_year']) ?></td>
                                                <td><?= e($record['semester'] ?: 'Not specified') ?></td>

                                                <td>₱<?= number_format((float) $record['total_fee'], 2) ?></td>
                                                <td>₱<?= number_format((float) $record['total_paid'], 2) ?></td>
                                                <td>
                                                    <?php if ((float) $record['excess_payment'] > 0): ?>
                                                        <span>₱<?= number_format((float) $record['balance'], 2) ?></span>
                                                        <small class="monitoring-excess">
                                                            Review excess: ₱<?= number_format((float) $record['excess_payment'], 2) ?>
                                                        </small>
                                                    <?php else: ?>
                                                        ₱<?= number_format((float) $record['balance'], 2) ?>
                                                    <?php endif; ?>
                                                </td>

                                                <td>
                                                    <span class="feature-status <?= e($statusClass) ?>">
                                                        <?= e($record['payment_status']) ?>
                                                    </span>
                                                </td>

                                                <td>
                                                    <?php if ((float) $record['balance'] > 0): ?>
                                                        <a
                                                            href="treasurer_dashboard.php?view=payment-monitoring&membership_id=<?= (int) $record['membership_id'] ?><?= $monitoringSearch !== '' ? '&amp;search=' . rawurlencode($monitoringSearch) : '' ?>"
                                                            class="feature-button"
                                                            aria-label="Record payment for <?= e($record['full_name']) ?>"
                                                        >
                                                            Record Payment
                                                        </a>
                                                    <?php else: ?>
                                                        <span class="feature-status paid">Completed</span>
                                                    <?php endif; ?>
                                                </td>

                                            </tr>

                                        <?php endforeach; ?>

                                    <?php endif; ?>

                                </tbody>

                            </table>

                        </div>

                        <div class="feature-actions">
                            <a href="treasurer_dashboard.php?view=payment-history" class="feature-button">
                                View Payment History
                            </a>
                        </div>

                    </div>

                </section>

            </section>


            <!-- ================================== -->
            <!-- RECORD PAYMENT -->
            <!-- ================================== -->

            <section
                class="dashboard-view"
                <?= !$paymentModalOpen ? 'hidden' : '' ?>
            >

                <div
                    class="fee-settings-backdrop"
                    id="paymentModalBackdrop"
                    aria-hidden="true"
                    <?= !$paymentModalOpen ? 'hidden' : '' ?>
                    onclick="closePaymentModal()"
                ></div>

                <section
                    class="content-panel fee-settings-panel"
                    id="paymentModalPanel"
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="paymentModalTitle"
                    tabindex="-1"
                    <?= !$paymentModalOpen ? 'hidden' : '' ?>
                >

                    <button
                        type="button"
                        class="fee-modal-close"
                        aria-label="Close payment form"
                        onclick="closePaymentModal()"
                    >&times;</button>

                    <div class="fee-modal-heading">
                        <span class="fee-modal-icon" aria-hidden="true">₱</span>
                        <div>
                            <p class="fee-modal-kicker">Payment Recording</p>
                            <h2 id="paymentModalTitle">Record Membership Payment</h2>
                        </div>
                    </div>

                    <p class="fee-modal-subtitle">
                        Enter the payment details for the selected member.
                    </p>

                    <?php if ($paymentError !== ''): ?>
                        <div class="feature-message error">
                            <?= e($paymentError) ?>
                        </div>
                    <?php endif; ?>

                    <?php if ($paymentSuccess): ?>
                        <div class="feature-message success">
                            Payment recorded successfully!
                        </div>
                    <?php endif; ?>

                    <?php if ($paymentMember): ?>

                        <div class="content-panel">

                            <h2>Member Information</h2>

                            <div class="member-information-grid">

                                <div class="member-information-item">
                                    <span>Student ID</span>
                                    <strong><?= e($paymentMember['student_id_number']) ?></strong>
                                </div>

                                <div class="member-information-item">
                                    <span>Full Name</span>
                                    <strong><?= e($paymentMember['full_name']) ?></strong>
                                </div>

                                <div class="member-information-item">
                                    <span>Program</span>
                                    <strong><?= e($paymentMember['program']) ?></strong>
                                </div>

                                <div class="member-information-item">
                                    <span>Year Level</span>
                                    <strong><?= e($paymentMember['year_level']) ?></strong>
                                </div>

                                <div class="member-information-item">
                                    <span>Academic Year</span>
                                    <strong><?= e($paymentMember['academic_year']) ?></strong>
                                </div>

                                <div class="member-information-item">
                                    <span>Semester</span>
                                    <strong><?= e($paymentMember['semester'] ?: 'Not specified') ?></strong>
                                </div>

                                <div class="member-information-item">
                                    <span>Payment Status</span>
                                    <strong><?= e($paymentStatus) ?></strong>
                                </div>

                            </div>

                            <div class="member-information-grid">

                                <div class="member-information-item">
                                    <span>Membership Fee</span>
                                    <strong>₱<?= number_format($totalFee, 2) ?></strong>
                                </div>

                                <div class="member-information-item">
                                    <span>Total Paid</span>
                                    <strong>₱<?= number_format($totalPaidForMember, 2) ?></strong>
                                </div>

                                <div class="member-information-item">
                                    <span>Excess Payment</span>
                                    <strong>₱<?= number_format($paymentExcess, 2) ?></strong>
                                </div>

                            </div>

                            <div class="balance-highlight">
                                <span>Outstanding Balance</span>
                                <strong>₱<?= number_format($remainingBalance, 2) ?></strong>
                            </div>

                        </div>

                        <?php if ($paymentExcess > 0): ?>
                            <div class="feature-message review">
                                This member has an excess payment of
                                ₱<?= number_format($paymentExcess, 2) ?> after the fee update.
                                Review the record; payment transactions have been preserved.
                            </div>
                        <?php endif; ?>

                        <?php if ($remainingBalance > 0): ?>

                            <div class="content-panel" style="margin-top:20px;">

                                <h2>Payment Details</h2>

                                <form
                                    method="POST"
                                    action="treasurer_dashboard.php?view=payment-monitoring&membership_id=<?= $membershipId ?><?= $monitoringSearch !== '' ? '&amp;search=' . rawurlencode($monitoringSearch) : '' ?>"
                                    class="feature-form"
                                >

                                    <input
                                        type="hidden"
                                        name="csrf_token"
                                        value="<?= e($_SESSION['csrf_token']) ?>"
                                    >

                                    <div>
                                        <label for="amount_paid">Payment Amount (₱)</label>
                                        <input
                                            type="number"
                                            id="amount_paid"
                                            name="amount_paid"
                                            min="0.01"
                                            max="<?= e(number_format($remainingBalance, 2, '.', '')) ?>"
                                            step="0.01"
                                            value="<?= e($paymentFormAmount) ?>"
                                            placeholder="Enter amount"
                                            required
                                        >

                                        <p class="form-note">
                                            Maximum payment allowed:
                                            ₱<?= number_format($remainingBalance, 2) ?>
                                        </p>
                                    </div>

                                    <div>
                                        <label for="payment_method">Payment Method</label>
                                        <select id="payment_method" name="payment_method" required>
                                            <option value="">Select payment method</option>

                                            <?php foreach (['Cash', 'GCash', 'Bank Transfer', 'Other'] as $method): ?>
                                                <option
                                                    value="<?= e($method) ?>"
                                                    <?= $paymentFormMethod === $method ? 'selected' : '' ?>
                                                >
                                                    <?= e($method) ?>
                                                </option>
                                            <?php endforeach; ?>

                                        </select>
                                    </div>

                                    <div>
                                        <label for="reference_number">Reference Number (Optional)</label>
                                        <input
                                            type="text"
                                            id="reference_number"
                                            name="reference_number"
                                            maxlength="100"
                                            value="<?= e($paymentFormReference) ?>"
                                            placeholder="Enter transaction reference number"
                                        >
                                    </div>

                                    <div>
                                        <label for="payment_date">Payment Date and Time</label>
                                        <input
                                            type="datetime-local"
                                            id="payment_date"
                                            name="payment_date"
                                            value="<?= e(
                                                $_SERVER['REQUEST_METHOD'] === 'POST'
                                                    ? treasurer_post_value('payment_date')
                                                    : $paymentFormDate
                                            ) ?>"
                                            required
                                        >
                                    </div>

                                    <div>
                                        <label for="remarks">Remarks (Optional)</label>
                                        <textarea
                                            id="remarks"
                                            name="remarks"
                                            maxlength="5000"
                                            placeholder="Enter additional payment information"
                                        ><?= e($paymentFormRemarks) ?></textarea>
                                    </div>

                                    <div class="feature-actions">

                                        <button type="submit" class="feature-button">
                                            Save Payment
                                        </button>

                                        <a
                                            href="treasurer_dashboard.php?view=payment-monitoring<?= $monitoringSearch !== '' ? '&amp;search=' . rawurlencode($monitoringSearch) : '' ?>"
                                            class="feature-button secondary"
                                        >
                                            Back to Monitoring
                                        </a>

                                    </div>

                                </form>

                            </div>

                        <?php else: ?>

                            <div class="feature-message success">
                                This member has no remaining membership fee balance.
                            </div>

                            <div class="feature-actions">
                                <a
                                    href="treasurer_dashboard.php?view=payment-monitoring<?= $monitoringSearch !== '' ? '&amp;search=' . rawurlencode($monitoringSearch) : '' ?>"
                                    class="feature-button"
                                >
                                    Back to Payment Monitoring
                                </a>
                            </div>

                        <?php endif; ?>

                    <?php else: ?>

                        <?php if ($paymentError !== ''): ?>

                            <div class="content-panel">
                                <p>
                                    Please return to Payment Monitoring
                                    and select a valid member record.
                                </p>

                                <a
                                    href="treasurer_dashboard.php?view=payment-monitoring<?= $monitoringSearch !== '' ? '&amp;search=' . rawurlencode($monitoringSearch) : '' ?>"
                                    class="feature-button"
                                >
                                    Back to Payment Monitoring
                                </a>
                            </div>

                        <?php endif; ?>

                    <?php endif; ?>

                </section>

            </section>


            <!-- ================================== -->
            <!-- PAYMENT HISTORY -->
            <!-- ================================== -->

            <section
                class="dashboard-view"
                <?= $currentView !== 'payment-history' ? 'hidden' : '' ?>
            >

                <section class="dashboard-section">

                    <div class="section-heading">
                        <h2>Payment History</h2>
                        <p>
                            View individual payment transactions recorded
                            for your assigned organization.
                        </p>
                        <p>
                            <?= e($organization['organization_name']) ?>
                            (<?= e($organization['organization_acronym']) ?>)
                        </p>
                    </div>

                    <div class="feature-summary-grid">

                        <div class="feature-summary-card">
                            <span>Payments Found</span>
                            <strong><?= number_format($totalPaymentsFound) ?></strong>
                        </div>

                        <div class="feature-summary-card">
                            <span>Total Amount Received</span>
                            <strong>₱<?= number_format($totalAmountReceived, 2) ?></strong>
                        </div>

                    </div>

                    <div class="content-panel">

                        <h2>Payment Transactions</h2>

                        <p>
                            Search using the Student ID, full name,
                            payment method, or reference number.
                        </p>

                        <form method="GET" action="treasurer_dashboard.php" class="feature-search">

                            <input type="hidden" name="view" value="payment-history">

                            <input
                                type="search"
                                name="search"
                                aria-label="Search payment history"
                                placeholder="Search payment records..."
                                value="<?= e($paymentSearch) ?>"
                                maxlength="100"
                            >

                            <button type="submit" class="feature-button">Search</button>

                            <a
                                href="treasurer_dashboard.php?view=payment-history"
                                class="feature-button secondary"
                            >
                                Clear
                            </a>

                        </form>

                        <div class="feature-table-wrapper">

                            <table class="feature-table">

                                <thead>
                                    <tr>
                                        <th>Payment ID</th>
                                        <th>Student ID</th>
                                        <th>Full Name</th>
                                        <th>Academic Year</th>
                                        <th>Semester</th>
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
                                            <td colspan="11" class="feature-empty">
                                                No payment transactions found.
                                            </td>
                                        </tr>

                                    <?php else: ?>

                                        <?php foreach ($payments as $payment): ?>

                                            <tr>

                                                <td>#<?= (int) $payment['payment_id'] ?></td>
                                                <td><?= e($payment['student_id_number']) ?></td>
                                                <td><?= e($payment['full_name']) ?></td>
                                                <td><?= e($payment['academic_year']) ?></td>
                                                <td><?= e($payment['semester'] ?: 'Not specified') ?></td>

                                                <td class="amount-cell">
                                                    ₱<?= number_format((float) $payment['amount_paid'], 2) ?>
                                                </td>

                                                <td><?= e($payment['payment_method']) ?></td>

                                                <td class="reference-cell">
                                                    <?= (
                                                        $payment['reference_number'] !== null &&
                                                        $payment['reference_number'] !== ''
                                                    ) ? e($payment['reference_number']) : '—' ?>
                                                </td>

                                                <td>
                                                    <?php
                                                    $paymentTimestamp = strtotime($payment['payment_date']);
                                                    ?>

                                                    <?= $paymentTimestamp !== false
                                                        ? e(date('M d, Y h:i A', $paymentTimestamp))
                                                        : '—' ?>
                                                </td>

                                                <td>
                                                    <?= e(
                                                        $payment['recorded_by_name']
                                                        ?: $payment['recorded_by']
                                                    ) ?>
                                                </td>

                                                <td>
                                                    <?= (
                                                        $payment['remarks'] !== null &&
                                                        $payment['remarks'] !== ''
                                                    ) ? e($payment['remarks']) : '—' ?>
                                                </td>

                                            </tr>

                                        <?php endforeach; ?>

                                    <?php endif; ?>

                                </tbody>

                            </table>

                        </div>

                        <div class="feature-actions">
                            <a
                                href="treasurer_dashboard.php?view=payment-monitoring"
                                class="feature-button"
                            >
                                Back to Payment Monitoring
                            </a>
                        </div>

                    </div>

                </section>

            </section>


        <?php elseif ($approvalStatus === 'APPROVED' && !$organization): ?>

            <section class="dashboard-section">

                <div class="dashboard-panel status-panel">
                    <div class="status-icon">!</div>
                    <h2>Organization Assignment</h2>
                    <p>
                        Your Treasurer account does not have
                        an assigned organization yet.
                    </p>
                    <p>
                        Please contact the administrator for assistance.
                    </p>
                </div>

            </section>


        <?php elseif ($approvalStatus === 'PENDING'): ?>

            <section class="dashboard-section">

                <div class="dashboard-panel status-panel">
                    <div class="status-icon">...</div>

                    <span class="status-label pending">
                        Pending Approval
                    </span>

                    <h2>Awaiting Approval</h2>

                    <p>
                        Your Treasurer account is pending approval.
                        Dashboard access will be available after
                        your application is approved.
                    </p>
                </div>

            </section>


        <?php else: ?>

            <section class="dashboard-section">

                <div class="dashboard-panel status-panel">
                    <div class="status-icon">!</div>

                    <span class="status-label rejected">
                        Application Not Approved
                    </span>

                    <h2>Application Status</h2>

                    <p>
                        Your Treasurer application was not approved.
                        Contact the organization administrator
                        for more information.
                    </p>
                </div>

            </section>

        <?php endif; ?>


        <footer class="dashboard-footer">

            <p>
                Student Organization Fee and Payment Tracking System
            </p>

            <p>Treasurer Panel</p>

        </footer>

    </main>

</div>

<script>

function setFeeSettingsOpen(isOpen) {
    const panel = document.getElementById('feeSettingsPanel');
    const backdrop = document.getElementById('feeSettingsBackdrop');
    const trigger = document.getElementById('openFeeSettingsButton');

    if (!panel || !backdrop) {
        return;
    }

    panel.hidden = !isOpen;
    backdrop.hidden = !isOpen;
    document.body.classList.toggle('fee-modal-open', isOpen);

    if (trigger) {
        trigger.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    }

    if (isOpen) {
        const academicYearField = document.getElementById('fee_academic_year');
        if (academicYearField) {
            academicYearField.focus();
        }
    } else if (trigger) {
        trigger.focus();
    }
}

function toggleFeeSettings() {
    const panel = document.getElementById('feeSettingsPanel');
    if (panel) {
        setFeeSettingsOpen(panel.hidden);
    }
}

function openFeeSettings() {
    const feeSettingId = document.getElementById('fee_setting_id');
    const academicYear = document.getElementById('fee_academic_year');
    const semester = document.getElementById('fee_semester');
    const editSemester = document.getElementById('fee_semester_edit');
    const membershipFee = document.getElementById('membership_fee');
    const title = document.getElementById('feeSettingsTitle');
    const saveButton = document.getElementById('saveOrganizationFeeButton');
    const errorMessage = document.getElementById('feeSettingsError');
    const formNote = document.getElementById('feeFormNote');

    if (!feeSettingId || !academicYear || !semester || !editSemester || !membershipFee) {
        return;
    }

    feeSettingId.value = '';
    academicYear.value = '';
    academicYear.readOnly = false;
    semester.value = '';
    semester.disabled = false;
    editSemester.value = '';
    editSemester.disabled = true;
    membershipFee.value = '';

    if (title) {
        title.textContent = 'Set Membership Fee';
    }
    if (saveButton) {
        saveButton.textContent = 'Save Membership Fee';
    }
    if (errorMessage) {
        errorMessage.hidden = true;
    }
    if (formNote) {
        formNote.textContent = 'Example terms: 1st Semester, 2nd Semester, and Summer.';
    }

    setFeeSettingsOpen(true);
}

function editOrganizationFee(button) {
    const feeSettingId = document.getElementById('fee_setting_id');
    const academicYear = document.getElementById('fee_academic_year');
    const semester = document.getElementById('fee_semester');
    const editSemester = document.getElementById('fee_semester_edit');
    const membershipFee = document.getElementById('membership_fee');
    const title = document.getElementById('feeSettingsTitle');
    const saveButton = document.getElementById('saveOrganizationFeeButton');
    const errorMessage = document.getElementById('feeSettingsError');
    const formNote = document.getElementById('feeFormNote');

    if (!feeSettingId || !academicYear || !semester || !editSemester || !membershipFee) {
        return;
    }

    feeSettingId.value = button.dataset.feeSettingId || '';
    academicYear.value = button.dataset.academicYear || '';
    academicYear.readOnly = true;
    semester.value = button.dataset.semester || '';
    semester.disabled = true;
    editSemester.value = semester.value;
    editSemester.disabled = false;
    membershipFee.value = button.dataset.membershipFee || '';

    if (title) {
        title.textContent = 'Edit Membership Fee';
    }
    if (saveButton) {
        saveButton.textContent = 'Update Membership Fee';
    }
    if (errorMessage) {
        errorMessage.hidden = true;
    }
    if (formNote) {
        formNote.textContent =
            'Editing changes the membership fee only; the academic year and semester stay the same.';
    }

    setFeeSettingsOpen(true);
}

function closePaymentModal() {
    const url = new URL(window.location.href);
    url.searchParams.delete('membership_id');
    url.searchParams.delete('success');
    url.searchParams.set('view', 'payment-monitoring');
    window.location.assign(url.toString());
}

let pendingDeleteForm = null;
let pendingDeleteTrigger = null;

function openDeleteConfirmation(form) {
    if (!form) {
        return;
    }

    pendingDeleteForm = form;
    pendingDeleteTrigger = form.querySelector('button[type="button"]');

    const memberName = form.getAttribute('data-member-name') || 'this member';
    const nameElement = document.getElementById('deleteMemberName');
    const backdrop = document.getElementById('deleteConfirmationBackdrop');
    const panel = document.getElementById('deleteConfirmationPanel');

    if (!nameElement || !backdrop || !panel) {
        pendingDeleteForm = null;
        pendingDeleteTrigger = null;
        return;
    }

    nameElement.textContent = memberName;
    backdrop.hidden = false;
    panel.hidden = false;
    document.body.classList.add('fee-modal-open');
    panel.focus();
}

function closeDeleteConfirmation() {
    const backdrop = document.getElementById('deleteConfirmationBackdrop');
    const panel = document.getElementById('deleteConfirmationPanel');

    if (backdrop) {
        backdrop.hidden = true;
    }
    if (panel) {
        panel.hidden = true;
    }

    document.body.classList.remove('fee-modal-open');
    pendingDeleteForm = null;

    if (pendingDeleteTrigger) {
        pendingDeleteTrigger.focus();
        pendingDeleteTrigger = null;
    }
}

function confirmMemberDeletion() {
    if (!pendingDeleteForm) {
        return;
    }

    const form = pendingDeleteForm;
    pendingDeleteForm = null;
    pendingDeleteTrigger = null;
    form.submit();
}

document.addEventListener('keydown', function (event) {
    const feePanel = document.getElementById('feeSettingsPanel');
    const paymentPanel = document.getElementById('paymentModalPanel');
    const deletePanel = document.getElementById('deleteConfirmationPanel');

    if (event.key === 'Escape' && feePanel && !feePanel.hidden) {
        setFeeSettingsOpen(false);
    } else if (event.key === 'Escape' && paymentPanel && !paymentPanel.hidden) {
        closePaymentModal();
    } else if (event.key === 'Escape' && deletePanel && !deletePanel.hidden) {
        closeDeleteConfirmation();
    }
});

// Keep the fee form open when validation fails.
<?php if ($feeError !== ''): ?>
document.addEventListener('DOMContentLoaded', function () {
    setFeeSettingsOpen(true);
});
<?php endif; ?>

<?php if ($paymentModalOpen): ?>
document.addEventListener('DOMContentLoaded', function () {
    const panel = document.getElementById('paymentModalPanel');
    if (panel) {
        document.body.classList.add('fee-modal-open');
        panel.focus();
    }
});
<?php endif; ?>

</script>

</body>
</html>
