<?php

declare(strict_types=1);

$module = file_get_contents(__DIR__ . '/../SecretsManager/module.php');
if (!is_string($module)) {
    throw new RuntimeException('Could not read module.php');
}

$required = [
    'processCreate(',
    'processGet(',
    "'credentialPublicKey'",
    "'signatureCounter'",
    "'webauthn.get'",
    "'webauthn.create'",
    'SecretsPortalSecurity::validateClientData',
    "PORTAL_CHALLENGE_BUFFER = 'PortalChallengesV2'",
    'PORTAL_CHALLENGE_MAX_ENTRIES = 100',
    'StorePortalChallenge(',
    'ConsumePortalChallenge(',
    'GetMigratableLegacyCredentials',
    'VerifyLegacyMigration',
    'httponly',
    "'samesite' => 'Strict'",
    'hash_equals',
    'schemaVersion'
];
foreach ($required as $needle) {
    if (!str_contains($module, $needle)) {
        throw new RuntimeException('Required security control missing: ' . $needle);
    }
}

$forbidden = [
    '"AuthSession_" . md5($_SERVER',
    'Challenge Empfangen',
    'Challenge Erwartet',
    '?register=1&pass=',
    'rawId: btoa(',
    'addslashes($returnUrl)',
    "'PortalAuthChallengeV2_' . \$sid",
    "'PortalRegistrationChallengeV2_' . \$sid",
    "'PortalMigrationChallengeV2_' . \$sid"
];
foreach ($forbidden as $needle) {
    if (str_contains($module, $needle)) {
        throw new RuntimeException('Legacy vulnerable pattern remains: ' . $needle);
    }
}

$verifyStart = strpos($module, 'private function VerifyPortalAccess(): void');
$verifyEnd = strpos($module, 'public function IsPortalAuthenticated(): bool');
if ($verifyStart === false || $verifyEnd === false || $verifyEnd <= $verifyStart) {
    throw new RuntimeException('Could not isolate VerifyPortalAccess');
}
$verify = substr($module, $verifyStart, $verifyEnd - $verifyStart);
foreach (['authenticatorData', 'signature', 'credentialPublicKey', 'processGet('] as $needle) {
    if (!str_contains($verify, $needle)) {
        throw new RuntimeException('Assertion verifier does not use ' . $needle);
    }
}

echo "ModuleSecurityRegressionTest: OK\n";
