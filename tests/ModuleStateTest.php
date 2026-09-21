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
    return true;
}

function IPS_SemaphoreLeave(string $name): void
{
}

class IPSModuleStrict
{
    public int $InstanceID;

    /** @var array<string, string> */
    private array $buffers = [];

    /** @var array<string, bool|int|string> */
    private array $properties = [];

    public function __construct(int $instanceId = 1234)
    {
        $this->InstanceID = $instanceId;
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

    public function testGetBuffer(string $name): string
    {
        return $this->buffers[$name] ?? '';
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

$module = new SecretsManager(77);

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

$now = time();
$commonSession = [
    'expires'       => $now + 60,
    'generation'    => 1,
    'origin'        => 'https://primary.example.com',
    'userAgentHash' => hash('sha256', $_SERVER['HTTP_USER_AGENT'])
];
$adminSession = $commonSession + [
    'method' => 'admin-password',
    'scopes' => ['admin', 'register', 'migrate']
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

$allowed = 0;
for ($i = 0; $i < 180; $i++) {
    $_SERVER['REMOTE_ADDR'] = '198.51.100.' . $i;
    if (invokePrivate($module, 'CheckPortalRateLimit', ['assertion', true])) {
        $allowed++;
    }
}
stateCheck($allowed === 100, 'global rate limit did not stop at the configured maximum');
$rateState = json_decode($module->testGetBuffer('PortalRateLimitsV2'), true);
stateCheck(is_array($rateState) && count($rateState) <= 256, 'rate-limit state exceeded its hard capacity');

echo "ModuleStateTest: OK\n";

