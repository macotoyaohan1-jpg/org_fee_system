<?php
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Location: treasurer_dashboard.php', true, 303);
exit;
