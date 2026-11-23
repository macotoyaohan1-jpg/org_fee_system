<?php
// This public page needs no database or login; SAMEORIGIN permits its registration modal view.
header('X-Frame-Options: ' . (($_GET['embed'] ?? '') === '1' ? 'SAMEORIGIN' : 'DENY'));
header('X-Content-Type-Options: nosniff');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy Notice | Student Organization Fee System</title>
    <link rel="stylesheet" href="css/auth.css?v=20261121-23">
    <link rel="stylesheet" href="css/privacy-notice.css?v=20261121-5">
    <script src="js/privacy-notice.js?v=20261121-2" defer></script>
</head>
<body class="privacy-notice-body">
    <main class="auth-container privacy-notice-container">
        <section class="form-panel privacy-notice-panel" aria-labelledby="privacyNoticeTitle">
            <div class="form-container">
                <h1 id="privacyNoticeTitle">Privacy Notice</h1>
                <p class="privacy-notice-intro">
                    This notice explains how the Student Organization Fee System
                    collects and uses information submitted during registration
                    and while using the system.
                </p>

                <section aria-labelledby="informationCollectedTitle">
                    <h2 id="informationCollectedTitle">Information collected</h2>
                    <p>
                        The system collects identification, name, birthdate,
                        address, email, account, security-question, emergency-contact,
                        and organization information needed to create and protect
                        an account and process a Treasurer application.
                    </p>
                </section>

                <section aria-labelledby="howInformationIsUsedTitle">
                    <h2 id="howInformationIsUsedTitle">How the information is used</h2>
                    <p>
                        Information is used to verify an applicant's email and
                        identity, review Treasurer applications, manage organization
                        membership and fee records, provide account recovery, and
                        detect or investigate suspicious account activity.
                    </p>
                </section>

                <section aria-labelledby="howInformationIsProtectedTitle">
                    <h2 id="howInformationIsProtectedTitle">How the information is protected</h2>
                    <p>
                        Access is restricted according to account roles. Passwords,
                        security-question answers, and one-time verification codes
                        are stored as hashes. Emergency contact numbers are encrypted.
                    </p>
                </section>

                <section aria-labelledby="retentionTitle">
                    <h2 id="retentionTitle">Retention and questions</h2>
                    <p>
                        Information is retained only as long as needed for system
                        and organization administration and any applicable
                        institutional record-retention requirements. For privacy
                        questions or concerns, contact the system administrator or
                        your institution's designated privacy officer.
                    </p>
                </section>

                <!-- Browser history returns to the exact registration form and field state. -->
                <button class="privacy-notice-back" id="privacyNoticeBack" type="button">Back</button>
            </div>
        </section>
    </main>
</body>
</html>
