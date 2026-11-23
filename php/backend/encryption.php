<?php

/**
 * Load the encryption key stored outside the project folder.
 */
function get_emergency_contact_encryption_key(): string
{
    $keyFile = 'C:/xampp/org_fee_encryption.key';

    if (!is_file($keyFile)) {
        throw new RuntimeException('Encryption key file is missing.');
    }

    $encodedKey = file_get_contents($keyFile);

    if ($encodedKey === false) {
        throw new RuntimeException('Unable to read encryption key.');
    }

    $key = base64_decode(trim($encodedKey), true);

    if ($key === false || strlen($key) !== 32) {
        throw new RuntimeException('Invalid encryption key.');
    }

    return $key;
}

/**
 * Encrypt an emergency contact number using AES-256-GCM.
 */
function encrypt_emergency_contact_number(?string $plainText): ?string
{
    if ($plainText === null || trim($plainText) === '') {
        return null;
    }

    $key = get_emergency_contact_encryption_key();

    // AES-GCM uses a 12-byte initialization vector.
    $iv = random_bytes(12);
    $tag = '';

    $encrypted = openssl_encrypt(
        $plainText,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        '',
        16
    );

    if ($encrypted === false) {
        throw new RuntimeException('Emergency contact encryption failed.');
    }

    // Store IV + authentication tag + encrypted data.
    return $iv . $tag . $encrypted;
}

/**
 * Decrypt an emergency contact number.
 */
function decrypt_emergency_contact_number(?string $encryptedData): ?string
{
    if ($encryptedData === null || $encryptedData === '') {
        return null;
    }

    // 12 bytes IV + 16 bytes authentication tag.
    if (strlen($encryptedData) < 28) {
        throw new RuntimeException('Invalid encrypted contact data.');
    }

    $key = get_emergency_contact_encryption_key();

    $iv = substr($encryptedData, 0, 12);
    $tag = substr($encryptedData, 12, 16);
    $cipherText = substr($encryptedData, 28);

    $decrypted = openssl_decrypt(
        $cipherText,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        ''
    );

    if ($decrypted === false) {
        throw new RuntimeException('Emergency contact decryption failed.');
    }

    return $decrypted;
}
