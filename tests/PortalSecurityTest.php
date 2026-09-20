<?php

declare(strict_types=1);

require_once __DIR__ . '/../SecretsManager/libs/PortalSecurity.php';

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$binary = random_bytes(64);
$encoded = SecretsPortalSecurity::base64UrlEncode($binary);
check(SecretsPortalSecurity::base64UrlDecode($encoded) === $binary, 'base64url round trip failed');
check(SecretsPortalSecurity::base64UrlDecode('%%%') === null, 'invalid base64url was accepted');
check(SecretsPortalSecurity::base64UrlDecode('') === null, 'empty base64url was accepted');

$error = '';
check(
    SecretsPortalSecurity::validateRpConfiguration('symcon.example.com', 'https://symcon.example.com', $error),
    'valid RP configuration was rejected: ' . $error
);
check(
    SecretsPortalSecurity::validateRpConfiguration('example.com', 'https://symcon.example.com:8443', $error),
    'valid subdomain RP configuration was rejected: ' . $error
);
check(
    !SecretsPortalSecurity::validateRpConfiguration('example.com', 'http://example.com', $error),
    'insecure non-local origin was accepted'
);
check(
    !SecretsPortalSecurity::validateRpConfiguration('example.com', 'https://evil-example.com', $error),
    'suffix-confusion origin was accepted'
);
check(
    !SecretsPortalSecurity::validateRpConfiguration('example.com', 'https://example.com/path', $error),
    'origin with a path was accepted'
);
check(
    !SecretsPortalSecurity::validateRpConfiguration('example.com', 'https://example.com:443', $error),
    'origin with an explicit default port was accepted'
);

$primary = SecretsPortalSecurity::normalizeRpProfile(
    'primary.example.com',
    'https://primary.example.com',
    $error
);
$backup = SecretsPortalSecurity::normalizeRpProfile(
    'backup.example.net',
    'https://backup.example.net',
    $error
);
check(is_array($primary) && is_array($backup), 'valid primary/backup profiles were rejected: ' . $error);
$profiles = [$primary, $backup];
check(
    SecretsPortalSecurity::selectRpProfile($profiles, 'primary.example.com') === $primary,
    'primary host did not select the primary profile'
);
check(
    SecretsPortalSecurity::selectRpProfile($profiles, 'backup.example.net') === $backup,
    'backup host did not select the backup profile'
);
check(
    SecretsPortalSecurity::selectRpProfile($profiles, 'attacker.example') === null,
    'unconfigured Host header selected a WebAuthn profile'
);
check(
    SecretsPortalSecurity::selectRpProfile($profiles, "primary.example.com\r\nX-Test: injected") === null,
    'Host header containing control characters was accepted'
);

$challenge = random_bytes(32);
$clientData = json_encode([
    'type'        => 'webauthn.get',
    'challenge'   => SecretsPortalSecurity::base64UrlEncode($challenge),
    'origin'      => 'https://symcon.example.com',
    'crossOrigin' => false
], JSON_UNESCAPED_SLASHES);

check(
    SecretsPortalSecurity::validateClientData(
        (string)$clientData,
        'webauthn.get',
        $challenge,
        'https://symcon.example.com'
    ) !== null,
    'valid client data was rejected'
);
check(
    SecretsPortalSecurity::validateClientData(
        (string)$clientData,
        'webauthn.create',
        $challenge,
        'https://symcon.example.com'
    ) === null,
    'wrong ceremony type was accepted'
);
check(
    SecretsPortalSecurity::validateClientData(
        (string)$clientData,
        'webauthn.get',
        random_bytes(32),
        'https://symcon.example.com'
    ) === null,
    'wrong challenge was accepted'
);
check(
    SecretsPortalSecurity::validateClientData(
        (string)$clientData,
        'webauthn.get',
        $challenge,
        'https://other.example.com'
    ) === null,
    'wrong origin was accepted'
);

check(SecretsPortalSecurity::sanitizeReturnUrl('/hook/example?x=1') === '/hook/example?x=1', 'valid local return URL was rejected');
check(SecretsPortalSecurity::sanitizeReturnUrl('https://evil.example/') === '/', 'external return URL was accepted');
check(SecretsPortalSecurity::sanitizeReturnUrl('//evil.example/') === '/', 'scheme-relative return URL was accepted');
check(SecretsPortalSecurity::sanitizeReturnUrl('/safe\\evil') === '/', 'backslash return URL was accepted');
check(SecretsPortalSecurity::sanitizeReturnUrl('/safe</script>') === '/safe</script>', 'local return URL changed unexpectedly');

echo "PortalSecurityTest: OK\n";
