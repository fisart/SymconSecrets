<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

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
    "RegisterPropertyString(\"PortalBackupOrigin\", \"\")",
    "RegisterPropertyBoolean(\"PortalDebugEnabled\", false)",
    "RegisterVariableString(\"PortalDebugMessage\", \"Portal debug (last event)\")",
    "'migration-unhandled-exception',",
    'SendPortalDiagnosticJson(',
    "MODULE_VERSION = '5.4.3'",
    "'moduleVersion'    => self::MODULE_VERSION",
    'invalid JSON response',
    'body.diagnostic',
    "'challengeMatches'",
    "'rpIdHashMatches'",
    "'authorizationFailure'",
    'SecretsPortalSecurity::normalizeRpProfile',
    'SecretsPortalSecurity::selectRpProfile',
    'ChallengeMatchesCurrentPortalProfile(',
    "PORTAL_CHALLENGE_BUFFER = 'PortalChallengesV2'",
    'PORTAL_CHALLENGE_MAX_ENTRIES = 192',
    'PORTAL_ASSERTION_CHALLENGES_PER_ORIGIN = 64',
    'PORTAL_PRIVILEGED_CHALLENGES_PER_ORIGIN = 16',
    'StorePortalChallenge(',
    'ConsumePortalChallenge(',
    'GetMigratableLegacyCredentials',
    'VerifyLegacyMigration',
    "'credentialIdV2'",
    '$migrated = $old',
    'httponly',
    "'samesite' => 'Strict'",
    'hash_equals',
    'schemaVersion',
    'EnterAuthorizedCeremonyCommit(',
    'PORTAL_REVOCATION_BUFFER',
    "['portal']",
    "['admin-password']",
    'backupEligibilityVerified',
    'SecretsPortalSecurity::validateBackupFlags',
    'NormalizeCredentialRecordsForRollback(',
    '_decryptVaultWithRevision(',
    'CreatePortalSessionStateLocked(',
    'IsPasskeySessionCredentialCurrent(',
    'GetCredentialSessionBinding(',
    'GetPortalCredentialStateHash(',
    "'credentialBinding'",
    "'credentialGeneration'",
    "\$data['credentialGeneration'] = \$this->GetPortalCredentialGeneration()",
    'GetPortalAuthorizationGeneration(',
    "PORTAL_CREDENTIAL_GENERATION_BUFFER = 'PortalCredentialGenerationV2'",
    "PORTAL_REVOCATION_PENDING_BUFFER = 'PortalRevocationPendingV2'",
    'PORTAL_RATE_MAX_ENTRIES_PER_PARTITION = 320',
    "CreatePortalSession('admin-password', ['admin', 'register', 'migrate', 'portal'], null, \$authorizationGeneration)",
    'abortIfPortalRevocationPending',
    'ReadRequestBody(',
    'SYNC_MAX_REQUEST_BYTES',
    'PORTAL_JSON_MAX_REQUEST_BYTES',
    'VAULT_MAX_BYTES'
];
foreach ($required as $needle) {
    if (!str_contains($module, $needle)) {
        throw new RuntimeException('Required security control missing: ' . $needle);
    }
}

foreach (['is_string($formAction)', 'is_string($submittedPassword)'] as $needle) {
    if (!str_contains($module, $needle)) {
        throw new RuntimeException('Malformed form input is cast before validation: ' . $needle);
    }
}
if (substr_count($module, "['credentialGeneration'] ?? -1") < 6) {
    throw new RuntimeException('Credential generation is not checked at every ceremony/session commit boundary');
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
    "'PortalMigrationChallengeV2_' . \$sid",
    'VAULT_REVISION_KEY',
    'PORTAL_RATE_MAX_ENTRIES = 256'
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

$sessionInsert = strpos($verify, 'CreatePortalSessionStateLocked(');
$portalUnlock = strpos($verify, '$this->LeavePortalStateLock();', $sessionInsert === false ? 0 : $sessionInsert);
if ($sessionInsert === false || $portalUnlock === false || $portalUnlock <= $sessionInsert) {
    throw new RuntimeException('Passkey session is not committed while the portal-state lock is held');
}

$sessionContextStart = strpos($module, 'private function GetPortalSessionContext(');
$sessionContextEnd = strpos($module, 'private function PortalSessionMatchesRequirements(', $sessionContextStart === false ? 0 : $sessionContextStart);
if ($sessionContextStart === false || $sessionContextEnd === false || $sessionContextEnd <= $sessionContextStart) {
    throw new RuntimeException('Could not isolate GetPortalSessionContext');
}
$sessionContext = substr($module, $sessionContextStart, $sessionContextEnd - $sessionContextStart);
if (!str_contains($sessionContext, 'PORTAL_REVOCATION_PENDING_BUFFER')) {
    throw new RuntimeException('Pending revocation does not fail closed for portal-session consumers');
}
if (!str_contains($sessionContext, 'IsPasskeySessionCredentialCurrent(')) {
    throw new RuntimeException('Passkey sessions are not bound to the current live credential');
}
if (!str_contains($sessionContext, "'credentialGeneration'")) {
    throw new RuntimeException('Passkey credential generation is not rechecked at final session acceptance');
}

$vaultSaveStart = strpos($module, 'private function _encryptAndSave(');
$vaultSaveEnd = strpos($module, 'private function _decryptVault()', $vaultSaveStart === false ? 0 : $vaultSaveStart);
if ($vaultSaveStart === false || $vaultSaveEnd === false || $vaultSaveEnd <= $vaultSaveStart) {
    throw new RuntimeException('Could not isolate _encryptAndSave');
}
$vaultSave = substr($module, $vaultSaveStart, $vaultSaveEnd - $vaultSaveStart);
$credentialGenerationPublish = strpos($vaultSave, 'self::PORTAL_CREDENTIAL_GENERATION_BUFFER');
$vaultPublish = strpos($vaultSave, '$this->SetValue("Vault", $vaultData)');
if (
    $credentialGenerationPublish === false ||
    $vaultPublish === false ||
    $credentialGenerationPublish >= $vaultPublish
) {
    throw new RuntimeException('Credential generation is not published before the changed vault');
}

$adminLoginStart = strpos($module, 'private function HandleAdminLogin(): void');
$adminLoginEnd = strpos($module, 'protected function ProcessHookData(): void', $adminLoginStart === false ? 0 : $adminLoginStart);
if ($adminLoginStart === false || $adminLoginEnd === false || $adminLoginEnd <= $adminLoginStart) {
    throw new RuntimeException('Could not isolate HandleAdminLogin');
}
$adminLogin = substr($module, $adminLoginStart, $adminLoginEnd - $adminLoginStart);
foreach (['GetPortalAuthorizationGeneration(', '$authorizationGeneration)'] as $needle) {
    if (!str_contains($adminLogin, $needle)) {
        throw new RuntimeException('Admin password login is not generation-bound: ' . $needle);
    }
}

$registrationPasswordStart = strpos($module, 'private function HandleRegistrationPassword(): void');
$registrationPasswordEnd = strpos($module, 'private function ServeLegacyMigrationUI(): void', $registrationPasswordStart === false ? 0 : $registrationPasswordStart);
if ($registrationPasswordStart === false || $registrationPasswordEnd === false || $registrationPasswordEnd <= $registrationPasswordStart) {
    throw new RuntimeException('Could not isolate HandleRegistrationPassword');
}
$registrationPassword = substr($module, $registrationPasswordStart, $registrationPasswordEnd - $registrationPasswordStart);
foreach (['GetPortalAuthorizationGeneration(', 'ServeRegistrationUI(\'registration-password\', null, $authorizationGeneration)'] as $needle) {
    if (!str_contains($registrationPassword, $needle)) {
        throw new RuntimeException('Registration password authorization is not generation-bound: ' . $needle);
    }
}

$commitStart = strpos($module, 'private function EnterAuthorizedCeremonyCommit(');
$commitEnd = strpos($module, 'private function IsJsonRequest()', $commitStart === false ? 0 : $commitStart);
if ($commitStart === false || $commitEnd === false || $commitEnd <= $commitStart) {
    throw new RuntimeException('Could not isolate EnterAuthorizedCeremonyCommit');
}
$commit = substr($module, $commitStart, $commitEnd - $commitStart);
if (!str_contains($commit, 'PORTAL_REVOCATION_PENDING_BUFFER')) {
    throw new RuntimeException('Ceremony commits do not fail closed while revocation is pending');
}

$migrationStart = strpos($module, 'private function VerifyLegacyMigration(): void');
$migrationEnd = strpos($module, 'private function ServeRegistrationUI(', $migrationStart);
if ($migrationStart === false || $migrationEnd === false || $migrationEnd <= $migrationStart) {
    throw new RuntimeException('Could not isolate VerifyLegacyMigration');
}
$migration = substr($module, $migrationStart, $migrationEnd - $migrationStart);
foreach ([
    '$migrated[\'credentialIdV2\']',
    '$vaultData[self::LOCAL_AUTH_KEY][$deviceKey] = $migrated',
    "EnterAuthorizedCeremonyCommit(\$buffer, 'migrate',"
] as $needle) {
    if (!str_contains($migration, $needle)) {
        throw new RuntimeException('Rollback-compatible migration control missing: ' . $needle);
    }
}
if (str_contains($migration, "'credentialId' => \$credentialId")) {
    throw new RuntimeException('Migration overwrites the legacy rollback credential ID');
}
if (str_contains($migration, 'IsPortalSessionValid(')) {
    throw new RuntimeException('Migration POST incorrectly depends on the browser resending the admin cookie');
}

$migrationRouteStart = strpos($module, '        if ($isMigrate) {');
$migrationRouteEnd = strpos($module, '        if ($isPortal) {', $migrationRouteStart === false ? 0 : $migrationRouteStart);
if ($migrationRouteStart === false || $migrationRouteEnd === false || $migrationRouteEnd <= $migrationRouteStart) {
    throw new RuntimeException('Could not isolate migration route');
}
$migrationRoute = substr($module, $migrationRouteStart, $migrationRouteEnd - $migrationRouteStart);
if (str_contains($migrationRoute, 'IsPortalSessionValid(')) {
    throw new RuntimeException('Migration route performs a redundant cookie check before challenge authorization');
}

$debugStart = strpos($module, 'private function RecordPortalDebug(');
$debugEnd = strpos($module, 'private function LogPortalFailure(', $debugStart === false ? 0 : $debugStart);
if ($debugStart === false || $debugEnd === false || $debugEnd <= $debugStart) {
    throw new RuntimeException('Could not isolate sanitized portal diagnostics');
}
$debug = substr($module, $debugStart, $debugEnd - $debugStart);
foreach (['PortalDebugEnabled', 'self::MODULE_VERSION', 'GetPortalDiagnosticExplanation(', 'SanitizePortalDiagnosticFacts(', 'GetPortalSafeExceptionSummary(', 'facts=', 'get_class($exception)', 'basename($exception->getFile())', 'substr($message, 0, 768)'] as $needle) {
    if (!str_contains($debug, $needle)) {
        throw new RuntimeException('Portal diagnostics control missing: ' . $needle);
    }
}
foreach (['clientDataJSON', 'authenticatorData', 'credentialPublicKey', 'HTTP_COOKIE', 'getTrace'] as $needle) {
    if (str_contains($debug, $needle)) {
        throw new RuntimeException('Sensitive data source present in portal diagnostics: ' . $needle);
    }
}

echo "ModuleSecurityRegressionTest: OK\n";
