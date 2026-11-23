<?php
$pageTitle = 'OrgTrack | Student Organization Membership and Payment Management';
$activePage = 'home';
require __DIR__ . '/includes/public_header.php';
?>

        <main class="main-content">
            <section class="hero" id="home" aria-labelledby="heroTitle">
                <div class="hero-copy">
                    <p class="eyebrow">For student organization treasurers</p>
                    <h1 id="heroTitle">Membership and fee records, organized.</h1>
                    <p class="hero-description">
                        OrgTrack supports treasurers in managing organization details,
                        student information, membership records, and payment records,
                        including paid and partially paid fees.
                    </p>
                    <div class="hero-actions">
                        <a class="button button-primary" href="register.php">Join Us</a>
                    </div>
                </div>
                <img class="hero-photo" src="images/photo.jpg" alt="Two university students talking together on campus">
            </section>

            <section class="content-section" id="about" aria-labelledby="aboutTitle">
                <div class="about-heading">
                    <p class="eyebrow">About the system</p>
                    <h2 id="aboutTitle">About Us</h2>
                </div>
                <div class="section-description about-description-box">
                    <p>The Student Organization Membership Fee and Payment Tracking System is a web-based application designed to simplify and organize the management of student organization membership fees and payment records.</p>
                    <p>The system provides an efficient way for authorized treasurers to manage student information, record membership fee payments, and monitor payment statuses according to academic year and year level. It also incorporates security features to help protect user accounts and maintain the confidentiality of information.</p>
                    <p>Developed to reduce manual recordkeeping and improve accuracy, the system aims to make membership fee management more organized, accessible, and convenient for student organizations.</p>
                </div>
            </section>

            <section class="content-section" id="features" aria-labelledby="featuresTitle">
                <div class="feature-heading">
                    <p class="eyebrow">System capabilities</p>
                    <h2 id="featuresTitle">System Features</h2>
                </div>
                <div class="feature-grid">
                    <article class="information-card"><h3>Student Records Management</h3><p>Easily search, organize, and manage student information for membership fee tracking.</p></article>
                    <article class="information-card"><h3>Membership Fee Tracking</h3><p>Record and monitor student membership fee payments, including fully paid and partially paid amounts.</p></article>
                    <article class="information-card"><h3>Academic Year Management</h3><p>Organize student membership and payment records according to the selected academic year.</p></article>
                    <article class="information-card"><h3>Year Level Organization</h3><p>Categorize students according to their year level for easier membership monitoring.</p></article>
                    <article class="information-card"><h3>Account Security</h3><p>Protect user accounts with email verification, OTP authentication, CAPTCHA, and account lockout protection.</p></article>
                    <article class="information-card"><h3>Role-Based Access</h3><p>Provide separate access permissions for Administrators and Treasurers based on their responsibilities.</p></article>
                </div>
            </section>

            <section class="how-it-works" id="how-it-works" aria-labelledby="howItWorksTitle">
                <div class="guide-heading">
                    <p class="card-eyebrow">User guide</p>
                    <h2 id="howItWorksTitle">How It Works</h2>
                </div>
                <div class="guide-steps">
                    <article>
                        <span>01</span>
                        <h3>Secure Account Access</h3>
                        <p>Authorized users can log in to the system through account authentication and email OTP verification to ensure secure access.</p>
                    </article>
                    <article>
                        <span>02</span>
                        <h3>Manage Student Records</h3>
                        <p>Treasurers can search for students and organize membership records according to academic year and year level.</p>
                    </article>
                    <article>
                        <span>03</span>
                        <h3>Record Membership Payments</h3>
                        <p>Keep track of students' membership fee payments by recording their payment status, including fully paid or partially paid.</p>
                    </article>
                    <article>
                        <span>04</span>
                        <h3>Monitor Payment Records</h3>
                        <p>Access organized membership and payment records to make tracking and managing organization fees easier.</p>
                    </article>
                </div>
            </section>
        </main>

<?php require __DIR__ . '/includes/public_footer.php'; ?>
