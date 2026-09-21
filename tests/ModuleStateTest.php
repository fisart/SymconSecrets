<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if (!defined('KL_MESSAGE')) {
    define('KL_MESSAGE', 0);
    define('KL_WARNING', 1);
    define('KL_ERROR', 2);
}

function IPS_SemaphoreEnter(string $name, int $milliseconds): bool
{
    if (str_contains($name, '.PortalState.') && ($GLOBALS['portalSemaphoreFailures'] ?? 0) > 0) {
        $GLOBALS['portalSemaphoreFailures']--;
        return false;
    }
    return true;
}

function IPS_SemaphoreLeave(string $name): void
{
}

function IPS_SetHidden(int $id, bool $hidden): void
{
}

class IPSModuleStrict
{
    public int $InstanceID;

    /** @var array<string, string> */
    private array $buffers = [];

    /** @var array<string, bool|int|string> */
    private array $properties = [];

    /** @var array<string, string> */
    private array $values = ['Vault' => ''];

    private int $status = 104;

    public function __construct(int $instanceId = 1234)
    {
        $this->InstanceID = $instanceId;
    }

    public function ApplyChanges(): void
    {
    }

    protected function GetBuffer(string $name): string
    {
        return $this->buffers[$name] ?? '';
    }

    protected function SetBuffer(string $name, string $value): void
    {
        $this->buffers[$name] = $value;
    }

    protected function ReadPropertyBoolean(string $name): bool
    {
        return (bool)($this->properties[$name] ?? false);
    }

    protected function ReadPropertyInteger(string $name): int
    {
        return (int)($this->properties[$name] ?? 0);
    }

    protected function ReadPropertyString(string $name): string
    {
        return (string)($this->properties[$name] ?? '');
    }

    protected function LogMessage(string $message, int $severity): void
    {
    }

    protected function GetValue(string $ident): string
    {
        return $this->values[$ident] ?? '';
    }

    protected function SetValue(string $ident, string $value): void
    {
        $this->values[$ident] = $value;
    }

    protected function GetStatus(): int
    {
        return $this->status;
    }

    protected function SetStatus(int $status): void
    {
        $this->status = $status;
    }

    protected function GetIDForIdent(string $ident): int
    {
        return 0;
    }

    protected function RegisterHook(string $ident): void
    {
    }

    protected function UpdateFormField(string $name, string $property, $value): void
    {
    }

    public function testGetBuffer(string $name): string
    {
        return $this->buffers[$name] ?? '';
    }

    /** @param bool|int|string $value */
    public function testSetProperty(string $name, $value): void
    {
        $this->properties[$name] = $value;
    }

    public function testSetBuffer(string $name, string $value): void
    {
        $this->buffers[$name] = $value;
    }

    public function testGetValue(string $ident): string
    {
        return $this->values[$ident] ?? '';
    }

    public function testGetStatus(): int
    {
        return $this->status;
    }
}

require_once __DIR__ . '/../SecretsManager/module.php';

function stateCheck(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

/**
 * @param array<int, mixed> $arguments
 * @return mixed
 */
function invokePrivate(object $object, string $method, array $arguments = [])
{
    $reflection = new ReflectionMethod($object, $method);
    $reflection->setAccessible(true);
    return $reflection->invokeArgs($object, $arguments);
}

$_SERVER['HTTP_USER_AGENT'] = 'SymconSecrets security test';
$_SERVER['HTTP_HOST'] = 'primary.example.com';
$_SERVER['REMOTE_ADDR'] = '192.0.2.1';
$GLOBALS['portalSemaphoreFailures'] = 0;

$module = new SecretsManager(77);
$temporaryKeyFolder = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'symcon-secrets-test-' . bin2hex(random_bytes(8));
stateCheck(mkdir($temporaryKeyFolder, 0700), 'could not create temporary key folder');
$module->testSetProperty('KeyFolderPath', $temporaryKeyFolder);
$module->testSetProperty('OperationMode', 2);
$module->testSetProperty('PortalSessionLifetimeMinutes', 60);
$module->testSetProperty('PortalOrigin', 'https://primary.example.com');
$module->testSetProperty('PortalBackupOrigin', 'https://backup.example.net');

$sid = invokePrivate($module, 'StorePortalChallenge', ['assertion', ['origin' => 'https://primary.example.com']]);
stateCheck(is_string($sid) && $sid !== '', 'challenge was not stored');
$challenge = invokePrivate($module, 'ConsumePortalChallenge', [$sid, 'assertion']);
stateCheck(is_array($challenge), 'valid challenge was not consumed');
stateCheck(invokePrivate($module, 'ConsumePortalChallenge', [$sid, 'assertion']) === null, 'challenge replay was accepted');

$sid = invokePrivate($module, 'StorePortalChallenge', ['registration', ['origin' => 'https://primary.example.com']]);
stateCheck(is_string($sid), 'registration challenge was not stored');
ob_start();
$module->RevokePortalSessions();
ob_end_clean();
stateCheck(invokePrivate($module, 'ConsumePortalChallenge', [$sid, 'registration']) === null, 'revocation left a registration challenge usable');

$migrationSid = invokePrivate($module, 'StorePortalChallenge', ['migration', ['origin' => 'https://primary.example.com']]);
$backupSid = invokePrivate($module, 'StorePortalChallenge', ['assertion', ['origin' => 'https://backup.example.net']]);
stateCheck(is_string($migrationSid) && is_string($backupSid), 'protected challenge buckets could not be created');
for ($i = 0; $i < 80; $i++) {
    stateCheck(
        is_string(invokePrivate($module, 'StorePortalChallenge', ['assertion', ['origin' => 'https://primary.example.com']])),
        'primary assertion challenge bucket rejected bounded replacement'
    );
}
stateCheck(
    is_array(invokePrivate($module, 'ConsumePortalChallenge', [$migrationSid, 'migration'])),
    'public assertion traffic evicted a privileged migration challenge'
);
stateCheck(
    is_array(invokePrivate($module, 'ConsumePortalChallenge', [$backupSid, 'assertion'])),
    'primary-origin assertion traffic evicted the backup-origin challenge'
);

$now = time();
$commonSession = [
    'expires'       => $now + 60,
    'generation'    => 1,
    'origin'        => 'https://primary.example.com',
    'userAgentHash' => hash('sha256', $_SERVER['HTTP_USER_AGENT'])
];
$adminSession = $commonSession + [
    'method' => 'admin-password',
    'scopes' => ['admin', 'register', 'migrate', 'portal']
];
$portalSession = $commonSession + [
    'method' => 'passkey',
    'scopes' => ['portal']
];
stateCheck(
    invokePrivate($module, 'PortalSessionMatchesRequirements', [$adminSession, 'https://primary.example.com', ['migrate'], ['admin-password'], $now]),
    'admin-password migration scope was rejected'
);
stateCheck(
    invokePrivate($module, 'PortalSessionMatchesRequirements', [$adminSession, 'https://primary.example.com', ['portal'], ['admin-password'], $now]),
    'admin-password session did not retain portal fallback authority'
);
stateCheck(
    !invokePrivate($module, 'PortalSessionMatchesRequirements', [$portalSession, 'https://primary.example.com', ['migrate'], ['admin-password'], $now]),
    'ordinary passkey session received migration authority'
);
stateCheck(
    invokePrivate($module, 'PortalSessionMatchesRequirements', [$portalSession, 'https://primary.example.com', ['portal'], ['passkey'], $now]),
    'portal passkey scope was rejected'
);

$rawCredentialId = "\xfb\xff\x00credential";
$vault = [
    '__AUTH__' => [
        'device_test' => [
            'schemaVersion'  => SecretsPortalSecurity::CREDENTIAL_SCHEMA_VERSION,
            'credentialId'   => SecretsPortalSecurity::base64UrlEncode($rawCredentialId),
            'rpId'           => 'primary.example.com',
            'origin'         => 'https://primary.example.com',
            'MigratedAt'     => 1
        ]
    ]
];
$arguments = [&$vault];
stateCheck(invokePrivate($module, 'NormalizeCredentialRecordsForRollback', $arguments), 'credential normalization made no change');
$normalized = $vault['__AUTH__']['device_test'];
stateCheck($normalized['credentialId'] === base64_encode($rawCredentialId), 'rollback credential ID is not padded standard Base64');
stateCheck($normalized['credentialIdV2'] === SecretsPortalSecurity::base64UrlEncode($rawCredentialId), 'canonical credential ID was not retained');
stateCheck(
    SecretsPortalSecurity::base64UrlDecode($normalized['userHandle']) === 'user77',
    'migrated credential did not retain the legacy user handle'
);
stateCheck($normalized['backupEligibilityVerified'] === false, 'pre-hardening backup eligibility was incorrectly trusted');

$initialVault = [
    'runtime_secret' => 'available',
    'record' => ['value' => 'initial']
];
stateCheck(invokePrivate($module, '_encryptAndSave', [$initialVault]), 'could not create test vault');

$module->testSetProperty('PortalEnabled', false);
$module->testSetBuffer('PortalEnabledLastV2', '1');
$generationBeforePendingRevocation = (int)$module->testGetBuffer('PortalRevocationGenerationV2');
$GLOBALS['portalSemaphoreFailures'] = 1;
$module->ApplyChanges();
stateCheck($module->testGetBuffer('PortalRevocationPendingV2') === '1', 'failed disable revocation was not persisted');
stateCheck($module->testGetStatus() === 102, 'pending portal revocation disabled the healthy vault instance');
stateCheck($module->GetSecret('runtime_secret') === 'available', 'pending portal revocation interrupted ordinary secret reads');

$pendingChallenge = [
    'generation' => (int)$module->testGetBuffer('PortalRevocationGenerationV2'),
    'userAgentHash' => hash('sha256', $_SERVER['HTTP_USER_AGENT'])
];
stateCheck(
    !invokePrivate($module, 'EnterAuthorizedCeremonyCommit', [$pendingChallenge]),
    'ceremony commit was authorized while revocation was pending'
);
stateCheck(
    invokePrivate($module, 'CreatePortalSessionStateLocked', [
        'passkey',
        ['portal'],
        'https://primary.example.com',
        'device_pending',
        (int)$module->testGetBuffer('PortalRevocationGenerationV2')
    ]) === null,
    'session was created while revocation was pending'
);
$vaultBeforePendingWrite = $module->testGetValue('Vault');
stateCheck(
    !invokePrivate($module, '_encryptAndSave', [['runtime_secret' => 'replaced'], null, true]),
    'ceremony vault write committed while revocation was pending'
);
stateCheck($module->testGetValue('Vault') === $vaultBeforePendingWrite, 'rejected pending ceremony changed the vault');

$module->testSetProperty('PortalEnabled', true);
$GLOBALS['portalSemaphoreFailures'] = 1;
$module->ApplyChanges();
stateCheck($module->testGetBuffer('PortalRevocationPendingV2') === '1', 'portal reopened while revocation remained pending');
stateCheck($module->testGetStatus() === 102, 'pending revocation disabled ordinary vault access after portal re-enable');

$module->ApplyChanges();
stateCheck($module->testGetBuffer('PortalRevocationPendingV2') === '0', 'pending revocation was not retried');
stateCheck(
    (int)$module->testGetBuffer('PortalRevocationGenerationV2') === $generationBeforePendingRevocation + 1,
    'retried revocation did not advance the session generation'
);

$vaultRevision = null;
$revisionArguments = [&$vaultRevision];
$staleSnapshot = invokePrivate($module, '_decryptVaultWithRevision', $revisionArguments);
stateCheck(is_array($staleSnapshot) && is_string($vaultRevision), 'could not obtain vault snapshot and separate revision');
stateCheck(!array_key_exists('__SEC_INTERNAL_REVISION__', $staleSnapshot), 'vault revision leaked into editable vault data');

$replacementVault = ['record' => ['value' => 'replacement']];
stateCheck(invokePrivate($module, '_encryptAndSave', [$replacementVault]), 'could not write concurrent replacement vault');
$staleSnapshot['record']['value'] = 'stale';
stateCheck(
    !invokePrivate($module, '_encryptAndSave', [$staleSnapshot, $vaultRevision]),
    'stale vault snapshot overwrote a concurrent change'
);
$currentVault = invokePrivate($module, '_decryptVault');
stateCheck(is_array($currentVault) && ($currentVault['record']['value'] ?? '') === 'replacement', 'stale-save rejection changed the vault');

$vaultBeforeOversize = $module->testGetValue('Vault');
$oversizedVault = ['blob' => str_repeat('x', 13 * 1024 * 1024)];
stateCheck(!invokePrivate($module, '_encryptAndSave', [$oversizedVault]), 'oversized encrypted vault was accepted');
stateCheck($module->testGetValue('Vault') === $vaultBeforeOversize, 'oversized save damaged the prior vault');
unset($oversizedVault);

$credentialId = "race-credential";
$credentialVault = [
    '__AUTH__' => [
        'device_race' => [
            'credentialId' => base64_encode($credentialId)
        ]
    ]
];
stateCheck(invokePrivate($module, '_encryptAndSave', [$credentialVault]), 'could not create credential deletion test vault');
$session = invokePrivate($module, 'CreatePortalSessionStateLocked', [
    'passkey',
    ['portal'],
    'https://primary.example.com',
    'device_race',
    (int)$module->testGetBuffer('PortalRevocationGenerationV2')
]);
stateCheck(is_array($session), 'could not create credential-bound session');
$_COOKIE['SEC_PORTAL_V2_77'] = (string)$session['token'];
$module->testSetBuffer('PortalRevocationPendingV2', '1');
stateCheck(
    invokePrivate($module, 'GetPortalSessionContext', [true, ['portal'], ['passkey']]) === null,
    'pending revocation left an existing portal session usable'
);
$module->testSetBuffer('PortalRevocationPendingV2', '0');
stateCheck(invokePrivate($module, 'DeleteLocalPasskey', ['device_race']), 'credential deletion failed');
$remainingSessions = json_decode($module->testGetBuffer('PortalSessionsV2'), true);
stateCheck(
    is_array($remainingSessions) && !array_key_exists((string)$session['tokenHash'], $remainingSessions),
    'credential deletion left its authenticated session active'
);

$allowed = 0;
for ($i = 0; $i < 180; $i++) {
    $_SERVER['REMOTE_ADDR'] = '198.51.100.' . $i;
    if (invokePrivate($module, 'CheckPortalRateLimit', ['assertion', true])) {
        $allowed++;
    }
}
stateCheck($allowed === 100, 'global rate limit did not stop at the configured maximum');
$rateState = json_decode($module->testGetBuffer('PortalRateLimitsV2'), true);
stateCheck(is_array($rateState) && count($rateState) <= 320, 'rate-limit partition exceeded its hard capacity');

$module->testSetBuffer('PortalRateLimitsV2', '{}');
$_SERVER['HTTP_HOST'] = 'primary.example.com';
$primaryChallengeAllowed = 0;
for ($i = 0; $i < 180; $i++) {
    $_SERVER['REMOTE_ADDR'] = '203.0.113.' . $i;
    if (invokePrivate($module, 'CheckPortalRateLimit', ['challenge-issuance', true, 30, 300])) {
        $primaryChallengeAllowed++;
    }
}
$primaryAdminAllowed = 0;
for ($i = 0; $i < 80; $i++) {
    $_SERVER['REMOTE_ADDR'] = '198.18.0.' . $i;
    if (invokePrivate($module, 'CheckPortalRateLimit', ['admin-password', true])) {
        $primaryAdminAllowed++;
    }
}
stateCheck($primaryChallengeAllowed === 180 && $primaryAdminAllowed === 80, 'independent primary-origin rate partitions interfered');

$_SERVER['HTTP_HOST'] = 'backup.example.net';
$_SERVER['REMOTE_ADDR'] = '192.0.2.200';
stateCheck(
    invokePrivate($module, 'CheckPortalRateLimit', ['assertion', true]),
    'primary-origin rate state blocked the backup-origin authentication partition'
);
$partitionedRateState = json_decode($module->testGetBuffer('PortalRateLimitsV2'), true);
stateCheck(is_array($partitionedRateState) && count($partitionedRateState) > 256, 'rate-limit isolation test did not exceed the former shared capacity');

@unlink($temporaryKeyFolder . DIRECTORY_SEPARATOR . 'master.key');
@rmdir($temporaryKeyFolder);

echo "ModuleStateTest: OK\n";
