<?php
$pageTitle = $pageTitle ?? 'OrgTrack | Student Organization Membership and Payment Management';
$activePage = $activePage ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#10281b">
    <title><?= htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8') ?></title>
    <link rel="stylesheet" href="css/landing.css?v=20261121-79">
    <script src="js/landing.js?v=20261121-18" defer></script>
</head>
<body>
    <div class="page-shell">
        <header class="site-header">
            <div class="header-inner">
                <a class="brand" href="index.php" aria-label="OrgTrack home">
                    <span class="brand-name">OrgTrack</span>
                    <span class="brand-description">
                        Student Organization Membership and Payment Management System
                    </span>
                </a>

                <nav class="site-nav" id="primaryNavigation" aria-label="Main navigation">
                    <!-- Keep the information links pointed at sections on this same landing page. -->
                    <div class="nav-main-links" aria-label="Information pages">
                        <a href="#about">About</a>
                        <a href="#features">Features</a>
                        <a href="#how-it-works">How It Works</a>
                    </div>
                    <div class="nav-account-links" aria-label="Main pages">
                        <a href="index.php#home" <?= $activePage === 'home' ? 'aria-current="page"' : '' ?>>Home</a>
                        <a href="login.php">Login</a>
                        <a href="register.php">Register</a>
                    </div>
                </nav>

                <button
                    class="menu-toggle"
                    id="menuToggle"
                    type="button"
                    aria-controls="primaryNavigation"
                    aria-expanded="false"
                >
                    <span class="menu-icon" aria-hidden="true"></span>
                    <span class="visually-hidden">Toggle navigation</span>
                </button>
            </div>
        </header>
