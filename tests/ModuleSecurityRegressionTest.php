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
    "'credentialIdV2'",
    '$migrated = $old',
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

$migrationStart = strpos($module, 'private function VerifyLegacyMigration(): void');
$migrationEnd = strpos($module, 'private function ServeRegistrationUI(): void');
if ($migrationStart === false || $migrationEnd === false || $migrationEnd <= $migrationStart) {
    throw new RuntimeException('Could not isolate VerifyLegacyMigration');
}
$migration = substr($module, $migrationStart, $migrationEnd - $migrationStart);
foreach (['$migrated[\'credentialIdV2\']', '$vaultData[self::LOCAL_AUTH_KEY][$deviceKey] = $migrated'] as $needle) {
    if (!str_contains($migration, $needle)) {
        throw new RuntimeException('Rollback-compatible migration control missing: ' . $needle);
    }
}
if (str_contains($migration, "'credentialId' => $credentialId")) {
    throw new RuntimeException('Migration overwrites the legacy rollback credential ID');
}

echo "ModuleSecurityRegressionTest: OK\n";
