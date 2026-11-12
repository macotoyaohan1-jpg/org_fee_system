<?php

// Start the session to store the CAPTCHA answer.
session_start();

// Check if PHP GD is available.
if (!extension_loaded('gd')) {
    http_response_code(500);
    exit('PHP GD extension is not enabled.');
}

// Create a random CAPTCHA code.
$characters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

$captcha = '';

for ($i = 0; $i < 6; $i++) {

    $captcha .= $characters[random_int(0, strlen($characters) - 1)];

}

// Store the correct answer in the session.
$_SESSION['login_captcha'] = $captcha;
unset($_SESSION['login_captcha_verified_at']);

// Create the image.
$width = 180;
$height = 60;

$image = imagecreatetruecolor($width, $height);

// Set image colors.
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

// Add CAPTCHA characters.
$fontSize = 5;

$textWidth = imagefontwidth($fontSize) * strlen($captcha);

$x = ($width - $textWidth) / 2;
$y = 22;

imagestring(
    $image,
    $fontSize,
    $x,
    $y,
    $captcha,
    $textColor
);

// Prevent the browser from caching the CAPTCHA.
header('Content-Type: image/png');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// Display the image.
imagepng($image);

// Free image memory.
imagedestroy($image);

exit;
