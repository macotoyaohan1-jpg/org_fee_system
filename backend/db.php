<?php

ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', 'C:/xampp/org_fee_system_errors.log');

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');

// Load the database configuration file.
$config = require 'C:/xampp/org_fee_config.php';

try {

    // Connect PHP to the MySQL database.
    $pdo = new PDO(
        "mysql:host=" . $config['host'] .
        ";dbname=" . $config['database'] .
        ";charset=utf8mb4",

        $config['username'],
        $config['password']
    );

    // Show database errors as exceptions.
    $pdo->setAttribute(
        PDO::ATTR_ERRMODE,
        PDO::ERRMODE_EXCEPTION
    );

    // Return database results as associative arrays.
    $pdo->setAttribute(
        PDO::ATTR_DEFAULT_FETCH_MODE,
        PDO::FETCH_ASSOC
    );

    // Disable emulated prepared statements.
    $pdo->setAttribute(
        PDO::ATTR_EMULATE_PREPARES,
        false
    );

} catch (PDOException $e) {
    error_log('Database connection failed: ' . $e->getMessage());
    http_response_code(500);
    exit('The system is temporarily unavailable. Please try again later.');
}
