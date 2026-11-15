<?php

// Start the session.
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

// Start output buffering to prevent unwanted output.
ob_start();

// Check if PHP GD is available.
if (!extension_loaded('gd')) {
    ob_end_clean();
    http_response_code(500);
    exit('PHP GD extension is not enabled.');
}

// Generate a random six-character CAPTCHA.
$characters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
$captcha = '';

for ($i = 0; $i < 6; $i++) {
    $captcha .= $characters[random_int(0, strlen($characters) - 1)];
}

// Store the CAPTCHA answer in the registration session.
$_SESSION['registration_captcha'] = $captcha;

// Create the CAPTCHA image.
$width = 180;
$height = 60;

$image = imagecreatetruecolor($width, $height);

// Define image colors.
$background = imagecolorallocate($image, 243, 247, 241);
$textColor = imagecolorallocate($image, 35, 75, 48);
$noiseColor = imagecolorallocate($image, 174, 193, 174);

// Fill the background.
imagefill($image, 0, 0, $background);

// Add random noise lines.
for ($i = 0; $i < 8; $i++) {
    imageline(
        $image,
        random_int(0, $width),
        random_int(0, $height),
        random_int(0, $width),
        random_int(0, $height),
        $noiseColor
    );
}

// Calculate CAPTCHA text position.
$fontSize = 5;
$textWidth = imagefontwidth($fontSize) * strlen($captcha);
$x = (int) (($width - $textWidth) / 2);
$y = 22;

// Draw CAPTCHA characters.
imagestring(
    $image,
    $fontSize,
    $x,
    $y,
    $captcha,
    $textColor
);

// Remove buffered output before sending the image.
ob_end_clean();

// Prevent browser caching.
header('Content-Type: image/png');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

// Display the image.
imagepng($image);

// Free image memory.
imagedestroy($image);

exit;
