<?php
declare(strict_types=1);
require_once __DIR__ . '/../SecretsFrontend/Configuration.php';
require_once __DIR__.'/Codec.php';

/**
 * Fail-closed policy checks for the proposed Connect route. This class does not
 * authenticate a request, establish transport trust, issue credentials, or
 * authorize an operation. Callers must perform those checks against the same
 * authenticated native state at the operation's authorization/commit point.
 * The runtime adapter selects only authenticated approved origins and requires
 * HTTPS evidence. Deployment qualification and independent review remain open.
 */
final class SecretsBackendBackupOriginPolicy
{
    public const FULL_RIGHTS=['read','write','export','admin'];
    public static function rights(array $p): array { return $p['version']===2?self::FULL_RIGHTS:['read','write','export']; }
    public static function full(array $state): bool { $p=$state['policy']['backupOrigin']??null;try{self::validatePolicy($p);return $p['version']===2&&$p['status']==='active';}catch(Throwable $e){return false;} }
    private const ENROLLMENT_ACTIONS = ['register-options', 'register-submit', 'possession-options', 'possession-submit'];

    public static function exactOrigin(string $origin): string
    {
        $normalized = SecretsFrontendConfiguration::origin($origin);
        $host = parse_url($normalized, PHP_URL_HOST);
        if ($normalized === '' || $normalized !== $origin || !is_string($host)
            || filter_var($host, FILTER_VALIDATE_IP) !== false
            || !preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $host)) {
            throw new InvalidArgumentException('Use an exact normalized HTTPS hostname.');
        }
        return $normalized;
    }

    /**
     * State transforms are deliberately separate from authority: invoke only
     * inside a native change callback after exact fresh administrator approval.
     * A random generation ensures re-adding a URL cannot revive old artifacts.
     */
    public static function stage(array $state, string $origin): array
    {
        self::exactOrigin($origin);
        if (!is_string($state['policy']['origin'] ?? null) || $origin === $state['policy']['origin']) {
            throw new RuntimeException('Choose a backup hostname different from the primary hostname.');
        }
        $previous = $state['policy']['backupOrigin'] ?? null;
        if ($previous !== null) {
            self::validatePolicy($previous);
            if ($previous['status'] !== 'revoked') throw new RuntimeException('Revoke or cancel the existing backup origin first.');
        }
        $state['policy']['backupOrigin'] = [
            'version' => 2, 'rights'=>self::FULL_RIGHTS, 'origin' => $origin,
            'generation' => bin2hex(random_bytes(32)), 'status' => 'pending',
        ];
        return $state;
    }

    public static function revoke(array $state, string $origin, string $generation): array
    {
        // Validate the exact policy and generation even for a pending route.
        self::requireRoute($state, $origin, $generation, 'register-options');
        $primary = $state['policy']['origin'] ?? null;
        $hardwarePolicy = $state['policy']['hardware'] ?? null;
        if (!is_string($primary) || $primary === '' || !is_array($hardwarePolicy)
            || array_diff(array_keys($hardwarePolicy), ['write', 'identity', 'export', 'reveal'])
            || array_diff(['write', 'identity', 'export', 'reveal'], array_keys($hardwarePolicy))) throw new RuntimeException('Primary security policy is unavailable.');
        foreach ($hardwarePolicy as $required) if (!is_bool($required)) throw new RuntimeException('Invalid hardware policy.');
        $hardware = in_array(true, $hardwarePolicy, true);
        $trust = $state['policy']['management']['settings']['HardwareTrustVersion'] ?? null;
        $usable = false;
        foreach ($state['identity']['credentials'] ?? [] as $credential) {
            $primaryCredential = !array_key_exists('origin', $credential) || $credential['origin'] === $primary;
            if ($primaryCredential && ($credential['active'] ?? false) === true && ($credential['tested'] ?? false) === true
                && (!$hardware || (($credential['hardware'] ?? false) === true && is_string($trust)
                    && ($credential['trustVersion'] ?? null) === $trust))) { $usable = true; break; }
        }
        if (!$usable) throw new RuntimeException('A tested primary administrator route is required before revoking backup access.');
        $state['policy']['backupOrigin']['status'] = 'revoked';
        foreach ($state['identity']['credentials'] ?? [] as $id => $credential) {
            if (($credential['origin'] ?? null) === $origin && ($credential['originGeneration'] ?? null) === $generation) {
                $state['identity']['credentials'][$id]['active'] = false;
            }
        }
        return $state;
    }

    public static function upgradeReview(array $state): array
    {
        $p=$state['policy']['backupOrigin']??null;self::validatePolicy($p);
        if($p['version']!==1||$p['status']!=='active')throw new RuntimeException('Select an active limited Magic route.');
        $credentials=[];$hardware=in_array(true,$state['policy']['hardware'],true);
        foreach($state['identity']['credentials']as$c)if(($c['active']??false)&&($c['tested']??false)&&($c['origin']??'')===$p['origin']&&($c['originGeneration']??'')===$p['generation']&&$c['administrator']===$state['identity']['ownerId']){
            if($hardware&&(!$c['hardware']||$c['trustVersion']!==$state['policy']['management']['settings']['HardwareTrustVersion']))continue;
            $credentials[$c['id']]=['credential'=>$c['id'],'administrator'=>$c['administrator'],'userHandle'=>$c['userHandle'],'fingerprint'=>hash('sha256',$c['publicKey'])];
        }
        if(!$credentials)throw new RuntimeException('Create and test an eligible Magic passkey before upgrading.');ksort($credentials,SORT_STRING);
        return ['origin'=>$p['origin'],'generation'=>$p['generation'],'rights'=>self::FULL_RIGHTS,'credentials'=>array_values($credentials),'policyDigest'=>hash('sha256',SecretsBackendCodec::json($state['policy']))];
    }
    public static function upgrade(array $state,array $review,string $generation): array
    {
        if(self::upgradeReview($state)!==$review||!preg_match('/^[a-f0-9]{64}$/D',$generation)||$generation===$review['generation'])throw new RuntimeException('Magic approval changed; review it again.');
        $state['policy']['backupOrigin']=['version'=>2,'origin'=>$review['origin'],'generation'=>$generation,'status'=>'active','rights'=>self::FULL_RIGHTS];
        foreach($review['credentials']as$c){$state['identity']['credentials'][$c['credential']]['originGeneration']=$generation;$state['identity']['credentials'][$c['credential']]['rights']=self::FULL_RIGHTS;}
        $state['native']['routeRevision']=SecretsBackendCodec::increment($state['native']['routeRevision']??'0');return $state;
    }
    public static function credentialFull(array $state,array $credential): bool
    {
        if(($credential['origin']??$state['policy']['origin'])===$state['policy']['origin'])return ($credential['active']??false)===true;
        try{self::requireCredential($state,$credential,$state['policy']['backupOrigin']['origin'],$state['policy']['backupOrigin']['generation']);return self::full($state)&&($credential['rights']??[])===self::FULL_RIGHTS;}catch(Throwable $e){return false;}
    }
    private static function validatePolicy($p): void
    {
        if (!is_array($p) || array_diff(array_keys($p), ($p['version']??0)===2?['version','origin','generation','status','rights']:['version','origin','generation','status'])
            || array_diff(['version', 'origin', 'generation', 'status'], array_keys($p))
            || !in_array($p['version'],[1,2],true) ||(($p['version']??0)===2&&($p['rights']??null)!==self::FULL_RIGHTS) || !is_string($p['origin']) || !is_string($p['generation'])
            || !is_string($p['status']) || !in_array($p['status'], ['pending', 'active', 'revoked'], true)
            || !preg_match('/^[a-f0-9]{64}$/D', $p['generation'])) {
            throw new RuntimeException('Backup origin is unavailable or its authorization has changed.');
        }
        self::exactOrigin($p['origin']);
    }

    /** Policy is absent on existing vaults; absence never admits a backup. */
    public static function requireRoute(array $state, string $origin, string $generation, string $action): array
    {
        self::exactOrigin($origin);
        $p = $state['policy']['backupOrigin'] ?? null;
        self::validatePolicy($p);
        if (!hash_equals($p['generation'], $generation) || $p['origin'] !== $origin) throw new RuntimeException('Backup origin is unavailable or its authorization has changed.');
        if ($p['status'] === 'revoked' || ($p['status'] === 'pending' && !in_array($action, self::ENROLLMENT_ACTIONS, true))) {
            throw new RuntimeException('Backup origin is not active for this action.');
        }
        return $p;
    }

    /** Legacy credentials without an origin are valid only on the primary route. */
    public static function requireCredential(array $state, array $credential, string $origin, string $generation,bool $allowUntested=false): void
    {
        self::requireRoute($state, $origin, $generation, 'authenticate');
        if (($credential['active'] ?? false) !== true || (!$allowUntested&&($credential['tested'] ?? false) !== true)
            || ($credential['origin'] ?? null) !== $origin || ($credential['originGeneration'] ?? null) !== $generation
            || !is_string($credential['administrator'] ?? null) || $credential['administrator'] === ''
            || !is_string($credential['id'] ?? null) || $credential['id'] === '') {
            throw new RuntimeException('Credential is not authorized for this backup origin.');
        }
    }
}
