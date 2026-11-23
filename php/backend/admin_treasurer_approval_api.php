<?php

header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . '/auth_common.php';

// Start the Admin's session.
auth_start_session();

// Send JSON responses consistently.
function treasurer_approval_response(int $status, array $data): void
{
    http_response_code($status);

    echo json_encode(
        $data,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );

    exit;
}

// Only allow GET and POST requests.
$method = $_SERVER['REQUEST_METHOD'] ?? '';

if (!in_array($method, ['GET', 'POST'], true)) {
    header('Allow: GET, POST');

    treasurer_approval_response(405, [
        'success' => false,
        'message' => 'Method not allowed.'
    ]);
}

// Check whether an Admin is logged in.
$sessionUserId = $_SESSION['user_id'] ?? null;

if (!is_string($sessionUserId) || $sessionUserId === '') {
    treasurer_approval_response(401, [
        'success' => false,
        'message' => 'Please log in again.'
    ]);
}

// Verify the Admin account using the database.
$adminStatement = $pdo->prepare("
    SELECT id_number, username, role, account_status
    FROM users
    WHERE id_number = :id_number
    LIMIT 1
");

$adminStatement->execute([
    'id_number' => $sessionUserId
]);

$admin = $adminStatement->fetch();

if (
    !$admin ||
    $admin['role'] !== 'ADMIN' ||
    $admin['account_status'] !== 'ACTIVE'
) {
    treasurer_approval_response(403, [
        'success' => false,
        'message' => 'You are not authorized to perform this action.'
    ]);
}

// GET: Retrieve pending applications with verified email addresses.
if ($method === 'GET') {
    try {
        $statement = $pdo->query("
            SELECT
                users.id_number,
                users.first_name,
                users.middle_name,
                users.family_name,
                users.name_extension,
                users.email,
                users.created_at,
                organizations.organization_name,
                organizations.organization_acronym
            FROM users
            LEFT JOIN organizations
                ON users.organization_id = organizations.organization_id
            WHERE users.role = 'TREASURER'
                AND users.approval_status = 'PENDING'
                AND users.email_verified_at IS NOT NULL
            ORDER BY users.created_at ASC
        ");

        $applications = $statement->fetchAll();

        foreach ($applications as &$application) {
            $application['full_name'] = trim(
                implode(' ', array_filter([
                    $application['first_name'],
                    $application['middle_name'],
                    $application['family_name'],
                    $application['name_extension']
                ], function ($part) {
                    return $part !== null && trim($part) !== '';
                }))
            );

            $application['organization_name'] =
                $application['organization_name'] ?? 'Not assigned';

            $application['organization_acronym'] =
                $application['organization_acronym'] ?? '';
        }

        unset($application);

        treasurer_approval_response(200, [
            'success' => true,
            'applications' => $applications
        ]);

    } catch (Throwable $error) {
        error_log(
            'Treasurer approval list error: ' . $error->getMessage()
        );

        treasurer_approval_response(500, [
            'success' => false,
            'message' => 'Unable to load Treasurer applications.'
        ]);
    }
}

// POST: Approve or reject a Treasurer application.

// Check the CSRF token before processing the action.
if (!auth_csrf_is_valid()) {
    treasurer_approval_response(403, [
        'success' => false,
        'message' => 'Invalid security token. Please refresh the page.'
    ]);
}

$action = $_POST['action'] ?? '';
$targetId = trim($_POST['id_number'] ?? '');

if (!in_array($action, ['approve', 'reject'], true)) {
    treasurer_approval_response(400, [
        'success' => false,
        'message' => 'Invalid approval action.'
    ]);
}

if ($targetId === '' || strlen($targetId) > 9) {
    treasurer_approval_response(400, [
        'success' => false,
        'message' => 'Invalid Treasurer ID number.'
    ]);
}

try {
    // Start a transaction so the decision and audit log stay together.
    $pdo->beginTransaction();

    // Lock the application while the Admin processes it.
    $targetStatement = $pdo->prepare("
        SELECT id_number, approval_status, email_verified_at
        FROM users
        WHERE id_number = :id_number
            AND role = 'TREASURER'
        LIMIT 1
        FOR UPDATE
    ");

    $targetStatement->execute([
        'id_number' => $targetId
    ]);

    $target = $targetStatement->fetch();

    if (!$target) {
        $pdo->rollBack();

        treasurer_approval_response(404, [
            'success' => false,
            'message' => 'Treasurer application not found.'
        ]);
    }

    if ($target['approval_status'] !== 'PENDING') {
        $pdo->rollBack();

        treasurer_approval_response(409, [
            'success' => false,
            'message' => 'This application has already been processed.'
        ]);
    }

    if ($target['email_verified_at'] === null) {
        $pdo->rollBack();

        treasurer_approval_response(409, [
            'success' => false,
            'message' => 'The Treasurer must verify their email first.'
        ]);
    }

    if ($action === 'approve') {

        // Approve the application and record which Admin approved it.
        $updateStatement = $pdo->prepare("
            UPDATE users
            SET
                approval_status = 'APPROVED',
                approved_by = :admin_id,
                approved_at = NOW()
            WHERE id_number = :target_id
                AND role = 'TREASURER'
                AND approval_status = 'PENDING'
        ");

        $updateStatement->execute([
            'admin_id' => $admin['id_number'],
            'target_id' => $targetId
        ]);

        $eventType = 'TREASURER_APPROVED';
        $message = 'Treasurer application approved successfully.';

    } else {

        // Reject the application without recording it as an approval.
        $updateStatement = $pdo->prepare("
            UPDATE users
            SET approval_status = 'REJECTED'
            WHERE id_number = :target_id
                AND role = 'TREASURER'
                AND approval_status = 'PENDING'
        ");

        $updateStatement->execute([
            'target_id' => $targetId
        ]);

        $eventType = 'TREASURER_REJECTED';
        $message = 'Treasurer application rejected successfully.';
    }

    // Record the Admin's decision in the activity logs.
    auth_log_event(
        $pdo,
        $eventType,
        $admin['username'],
        $admin['id_number'],
        'Processed Treasurer application for ID number: ' . $targetId
    );

    // Save the application decision and its audit log.
    $pdo->commit();

    treasurer_approval_response(200, [
        'success' => true,
        'message' => $message
    ]);

} catch (Throwable $error) {

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log(
        'Treasurer approval action error: ' . $error->getMessage()
    );

    treasurer_approval_response(500, [
        'success' => false,
        'message' => 'Unable to process the Treasurer application.'
    ]);
}
