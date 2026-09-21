<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../SecretsManager/libs/PortalSecurity.php';
require_once __DIR__ . '/../SecretsManager/libs/WebAuthn/src/WebAuthn.php';

use lbuchs\WebAuthn\WebAuthn;

function expect(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$rpId = 'symcon.example.com';
$origin = 'https://symcon.example.com';
$challenge = random_bytes(32);
$clientDataJson = json_encode([
    'type'        => 'webauthn.get',
    'challenge'   => SecretsPortalSecurity::base64UrlEncode($challenge),
    'origin'      => $origin,
    'crossOrigin' => false
], JSON_UNESCAPED_SLASHES);

$privateKey = openssl_pkey_new([
    'private_key_type' => OPENSSL_KEYTYPE_EC,
    'curve_name'       => 'prime256v1'
]);
expect($privateKey !== false, 'could not create test EC key');
$details = openssl_pkey_get_details($privateKey);
expect(is_array($details) && isset($details['key']), 'could not export test public key');
$publicKey = (string)$details['key'];

// RP ID hash + UP/UV flags + monotonically increasing signature counter.
$authenticatorData = hash('sha256', $rpId, true) . chr(0x05) . pack('N', 1);
$signedData = $authenticatorData . hash('sha256', (string)$clientDataJson, true);
$signature = '';
expect(openssl_sign($signedData, $signature, $privateKey, OPENSSL_ALGO_SHA256), 'could not sign test assertion');

$verifier = new WebAuthn('Symcon Vault', $rpId, ['none'], true);
expect(
    $verifier->processGet(
        (string)$clientDataJson,
        $authenticatorData,
        $signature,
        $publicKey,
        $challenge,
        0,
        true,
        true
    ),
    'valid assertion was rejected'
);
expect($verifier->getSignatureCounter() === 1, 'signature counter was not extracted');

$rejected = false;
try {
    $badSignature = $signature;
    $badSignature[0] = chr(ord($badSignature[0]) ^ 0x01);
    (new WebAuthn('Symcon Vault', $rpId, ['none'], true))->processGet(
        (string)$clientDataJson,
        $authenticatorData,
        $badSignature,
        $publicKey,
        $challenge,
        0,
        true,
        true
    );
} catch (Throwable $e) {
    $rejected = true;
}
expect($rejected, 'modified signature was accepted');

$rejected = false;
try {
    $wrongOriginData = json_encode([
        'type'        => 'webauthn.get',
        'challenge'   => SecretsPortalSecurity::base64UrlEncode($challenge),
        'origin'      => 'https://evil.example.com',
        'crossOrigin' => false
    ], JSON_UNESCAPED_SLASHES);
    $wrongOriginSignature = '';
    expect(
        openssl_sign(
            $authenticatorData . hash('sha256', (string)$wrongOriginData, true),
            $wrongOriginSignature,
            $privateKey,
            OPENSSL_ALGO_SHA256
        ),
        'could not sign wrong-origin assertion'
    );
    (new WebAuthn('Symcon Vault', $rpId, ['none'], true))->processGet(
        (string)$wrongOriginData,
        $authenticatorData,
        $wrongOriginSignature,
        $publicKey,
        $challenge,
        0,
        true,
        true
    );
} catch (Throwable $e) {
    $rejected = true;
}
expect($rejected, 'wrong origin was accepted');

$rejected = false;
try {
    // BS without BE is forbidden by WebAuthn. The module performs this
    // application-level invariant check after cryptographic verification.
    $invalidBackupData = hash('sha256', $rpId, true) . chr(0x15) . pack('N', 2);
    $invalidBackupSignature = '';
    expect(
        openssl_sign(
            $invalidBackupData . hash('sha256', (string)$clientDataJson, true),
            $invalidBackupSignature,
            $privateKey,
            OPENSSL_ALGO_SHA256
        ),
        'could not sign invalid-backup assertion'
    );
    $parsed = new \lbuchs\WebAuthn\Attestation\AuthenticatorData($invalidBackupData);
    if (!$parsed->getIsBackupEligible() && $parsed->getIsBackup()) {
        throw new RuntimeException('invalid backup flags');
    }
} catch (Throwable $e) {
    $rejected = true;
}
expect($rejected, 'BS without BE was accepted');

$rejected = false;
try {
    $noUvData = hash('sha256', $rpId, true) . chr(0x01) . pack('N', 2);
    $noUvSignature = '';
    openssl_sign($noUvData . hash('sha256', (string)$clientDataJson, true), $noUvSignature, $privateKey, OPENSSL_ALGO_SHA256);
    (new WebAuthn('Symcon Vault', $rpId, ['none'], true))->processGet(
        (string)$clientDataJson,
        $noUvData,
        $noUvSignature,
        $publicKey,
        $challenge,
        1,
        true,
        true
    );
} catch (Throwable $e) {
    $rejected = true;
}
expect($rejected, 'assertion without user verification was accepted');

$rejected = false;
try {
    (new WebAuthn('Symcon Vault', $rpId, ['none'], true))->processGet(
        (string)$clientDataJson,
        $authenticatorData,
        $signature,
        $publicKey,
        $challenge,
        1,
        true,
        true
    );
} catch (Throwable $e) {
    $rejected = true;
}
expect($rejected, 'replayed/non-increasing counter was accepted');

echo "WebAuthnAssertionTest: OK\n";
