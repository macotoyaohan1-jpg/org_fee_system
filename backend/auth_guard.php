<?php

require_once __DIR__ . '/auth_common.php';

function auth_current_user(PDO $pdo): ?array
{
    $userId = $_SESSION['user_id'] ?? null;
    if (!is_string($userId) || $userId === '') {
        auth_redirect('login.php');
    }

    $statement = $pdo->prepare(
        'SELECT id_number, first_name, middle_name, family_name, role, approval_status, account_status
         FROM users
         WHERE id_number = :user_id
         LIMIT 1'
    );
    $statement->execute(['user_id' => $userId]);
    $user = $statement->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        unset($_SESSION['user_id'], $_SESSION['user_role'], $_SESSION['approval_status']);
        auth_redirect('login.php');
    }

    if ($user['account_status'] !== 'ACTIVE') {
        unset($_SESSION['user_id'], $_SESSION['user_role'], $_SESSION['approval_status']);
        $_SESSION['access_denied_message'] = 'This account is suspended. Contact an administrator for assistance.';
        auth_redirect('access_denied.php');
    }

    return $user;
}

function auth_require_treasurer(PDO $pdo, string $approvalStatus): array
{
    auth_start_session();
    $user = auth_current_user($pdo);

    if (
        $user['role'] !== 'TREASURER' ||
        $user['approval_status'] !== $approvalStatus
    ) {
        auth_redirect('access_denied.php');
    }

    return $user;
}

function auth_require_admin(PDO $pdo): array
{
    auth_start_session();
    $user = auth_current_user($pdo);

    if ($user['role'] !== 'ADMIN') {
        auth_redirect('access_denied.php');
    }

    return $user;
}

