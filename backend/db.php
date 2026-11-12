
<?php

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

}   catch (PDOException $e) {

    exit('Database Error: ' . $e->getMessage());
}
