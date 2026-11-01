<?php
declare(strict_types=1);
require_once __DIR__ . '/NativeStore.php';
require_once __DIR__ . '/NativeOperations.php';

/** Symcon lifecycle adapter for native vaults; V1 is never its fallback. */
trait SecretsBackendNativeBackend
{
    private function nativeInitialized(): bool { return $this->ReadAttributeBoolean('GuidedV2Only') && $this->ReadAttributeString('NativeVaultUUID') !== ''; }
    private function nativeStore(): SecretsBackendNativeStore
    {
        $binding = json_decode($this->ReadAttributeString('StorageBinding'), true);
        if (!is_array($binding) || ($binding['kind'] ?? '') !== 'native' || ($binding['backend'] ?? 0) !== $this->InstanceID
            || ($binding['uuid'] ?? '') !== $this->ReadAttributeString('NativeVaultUUID')) throw new RuntimeException('Native storage binding is incomplete; resume initialization in the wizard.');
        $paths = SecretsBackendNativePlatform::paths($binding['paths']['vault'], $binding['paths']['keys'], IPS_GetKernelDir());
        if ($paths['vaultDirectory'] !== $binding['paths']['vault'] || $paths['keyDirectory'] !== $binding['paths']['keys']) throw new RuntimeException('Native storage path binding changed.');
        $store = new SecretsBackendNativeStore($paths['vaultDirectory'], $paths['keyDirectory'], $this->GetBuffer('Runtime'),
            fn() => $this->GetBuffer('Runtime'));
        $id = $store->identity();
        if ($id['deploymentId'] !== $binding['uuid'] || $id['binding']['backend'] !== $this->InstanceID
            || $id['binding']['frontend'] !== $this->ReadPropertyInteger('FrontendInstanceID') || $id['binding']['origin'] !== $this->ReadPropertyString('AdminOrigin')) throw new RuntimeException('Native vault identity or instance binding changed.');
        return $store;
    }
    private function nativeProfile(): array { return SecretsBackendSecurityConfiguration::nativeProfile($this->configuration(), $this->frontendSecurity()); }
    private function nativeApplication(): SecretsBackendApplication
    {
        if (!$this->ReadPropertyBoolean('Enabled') || !$this->nativeInitialized()) throw new RuntimeException('Initialize and enable the native backend in the HTML wizard.');
        $store = $this->nativeStore(); $current = $store->read(); $profile = $current['state']['policy']['management'];
        if (!is_array($profile) || ($profile['version'] ?? '') !== 'native-1') throw new RuntimeException('Native security profile is unavailable.');
        SecretsBackendSecurityConfiguration::verify($profile, $this->frontendSecurity());
        if (!SecretsBackendSecurityConfiguration::sameFoundation($profile['settings'], $this->configuration())) throw new RuntimeException('Pinned native foundation changed. Restore the reviewed settings or use recovery.');
        $active = $profile['settings'];
        return new SecretsBackendApplication($store, ['origin' => $active['AdminOrigin'], 'frontend' => $active['FrontendInstanceID'], 'backend' => $this->InstanceID,
            'hardwareRoots' => $active['HardwareRootsDirectory'], 'hardwareAAGUIDs' => json_decode($active['HardwareAAGUIDs'], true, 8, JSON_THROW_ON_ERROR),
            'hardwareTrustVersion' => $active['HardwareTrustVersion'], 'managementProfile' => $profile, 'candidateProfile' => fn() => $this->nativeProfile(), 'nativeOps' => new SecretsBackendNativeOperations($store, $this->nativePeer($store), function(array $approved):void{foreach(SecretsBackendSecurityConfiguration::HARDWARE as$key)IPS_SetProperty($this->InstanceID,$key,$approved['settings'][$key]);IPS_ApplyChanges($this->InstanceID);$this->Recover();})]);
    }
    private function nativeApply(): void
    {
        $this->SetTimerInterval('Recovery', 0);
        $this->SetTimerInterval('NativeJobs', 0);
        $this->syncNativePeerHook($this->ReadPropertyBoolean('Enabled') && $this->nativeInitialized());
        if (!$this->nativeInitialized()) { $this->nativeUnavailable(); return; }
        try {
            $store = $this->nativeStore(); $store->invalidate();
            if (!$this->ReadPropertyBoolean('Enabled')) { $this->SetStatus(104); $this->SetValue('Status', 'Native vault disabled; sessions and approvals invalidated.'); return; }
            $this->SetStatus(201); $this->SetValue('Status', 'Native encrypted vault: recovery check pending.');
            if (IPS_GetKernelRunlevel() === 10103) $this->SetTimerInterval('Recovery', 100);
        } catch (Throwable $e) { $this->SetStatus(200); $this->SetValue('Status', 'Native vault locked: ' . $e->getMessage()); }
    }
    private function nativeRecover(): bool
    {
        $this->SetTimerInterval('Recovery', 0);
        if (!$this->nativeInitialized()) { $this->nativeUnavailable(); return false; }
        if (!$this->ReadPropertyBoolean('Enabled')) return false;
        try {
            if ($this->GetBuffer('Runtime') === '') $this->SetBuffer('Runtime', SecretsBackendCodec::b64(random_bytes(32)));
            $this->syncNativePeerHook(true);
            $store = $this->nativeStore(); $store->recover(function(array $state):void{
                $profile=$state['policy']['management'];SecretsBackendSecurityConfiguration::verify($profile,$this->frontendSecurity());
                if(!SecretsBackendSecurityConfiguration::sameFoundation($profile['settings'],$this->configuration()))throw new RuntimeException('Pinned native foundation changed.');
            });
            $this->SetTimerInterval('NativeJobs', 10000);
            $this->SetStatus(102); $this->SetValue('Status', 'Native encrypted vault ready. Standalone; optional peers can be paired in the HTML page.');
            $this->SetValue('StorageStatus', 'Private encrypted snapshot journal and separate keys. Independent full-state rollback detection is unavailable in standalone mode.');
            return true;
        } catch (Throwable $e) { $this->SetStatus(200); $this->SetValue('Status', 'Native vault locked: ' . $e->getMessage()); return false; }
    }
    /** Public metadata only; no key, credential, session or secret value. */
    public function GetNativeInfo(): string
    {
        $result = ['nativeMode' => $this->ReadAttributeBoolean('GuidedV2Only'), 'initialized' => $this->nativeInitialized(), 'ready' => false,
            'platform' => SecretsBackendNativePlatform::capabilities(), 'backend' => $this->InstanceID];
        if ($result['initialized']) {
            try { $store = $this->nativeStore(); $meta = $store->metadata(); $result += $meta; $result['ready'] = $this->ReadPropertyBoolean('Enabled');
                $result['enrollmentNeeded'] = count($store->read()['state']['identity']['credentials']) === 0;
            } catch (Throwable $e) { $result['message'] = $e->getMessage(); }
        }
        return SecretsBackendCodec::json($result);
    }
    /** Privileged local initialization, invoked only after the frontend consumes its reviewed console grant. */
    public function InitializeNativeStorage(int $FrontendInstanceID, string $ExpectedDigest, bool $PrivateACLConfirmed, bool $PersistenceConfirmed, string $AdministratorLabel): string
    {
        $lock = 'SECB.Runtime.' . $this->InstanceID;
        if (!IPS_SemaphoreEnter($lock, 500)) throw new RuntimeException('Native initialization is busy.');
        try {
            if (!$this->ReadAttributeBoolean('GuidedV2Only') || $this->ReadPropertyInteger('FrontendInstanceID') !== $FrontendInstanceID
                || !hash_equals(hash('sha256', SecretsFrontendConfiguration::encode($this->initialSettingsSnapshot())), $ExpectedDigest)) throw new RuntimeException('Native initialization settings changed after review.');
            $this->frontendSecurity();
            $paths = SecretsBackendNativePlatform::paths($this->ReadPropertyString('DataDirectory'), $this->ReadPropertyString('KeyDirectory'), IPS_GetKernelDir());
            $persistence = SecretsBackendNativePlatform::persistence($paths['vaultDirectory'], $paths['keyDirectory'], IPS_GetKernelDir());
            if (!$PersistenceConfirmed && ($persistence['vault']['confirmationRequired'] || $persistence['keys']['confirmationRequired'])) throw new RuntimeException('Confirm that these Docker folders persist across container replacement, or choose persistent folders.');
            $plan = ['paths' => $paths, 'origin' => $this->ReadPropertyString('AdminOrigin'), 'frontend' => $FrontendInstanceID, 'backend' => $this->InstanceID, 'privateACLConfirmed' => $PrivateACLConfirmed];
            $digest = hash('sha256', SecretsBackendNativeStore::canonical($plan)); $saved = $this->ReadAttributeString('NativeInitPlan');
            if ($this->nativeInitialized()) throw new RuntimeException('Native storage already exists; initialization never replaces it.');
            if ($saved !== '' && !hash_equals($saved, $digest)) throw new RuntimeException('An interrupted native initialization has different bindings; inspect recovery first.');
            $resume = $saved !== ''; $uuid = $this->ReadAttributeString('NativeInitUUID');
            if ($uuid === '') { $uuid = SecretsBackendCodec::uuid(); $this->WriteAttributeString('NativeInitUUID', $uuid); }
            $this->WriteAttributeString('NativeInitPlan', $digest);
            $profile = $this->nativeProfile();
            $id = SecretsBackendNativeStore::initialize($paths['vaultDirectory'], $paths['keyDirectory'],
                ['origin' => $plan['origin'], 'frontend' => $FrontendInstanceID, 'backend' => $this->InstanceID, 'privateACLConfirmed' => $PrivateACLConfirmed], $profile, $uuid, $resume);
            $this->WriteAttributeString('StorageBinding', SecretsBackendCodec::json(['kind' => 'native', 'backend' => $this->InstanceID, 'uuid' => $uuid, 'paths' => ['vault' => $paths['vaultDirectory'], 'keys' => $paths['keyDirectory']]]));
            $this->WriteAttributeString('NativeVaultUUID', $id['deploymentId']);
            IPS_SetProperty($this->InstanceID, 'Enabled', true);
        } finally { IPS_SemaphoreLeave($lock); }
        IPS_ApplyChanges($this->InstanceID);
        if (!$this->Recover()) throw new RuntimeException('Native storage was created but recovery needs inspection. No initialization is replayed.');
        $code = $this->nativeApplication()->beginEnrollment($AdministratorLabel, false);
        return SecretsBackendCodec::json(['initialized' => true, 'ready' => true, 'vaultId' => $id['deploymentId'], 'enrollmentCode' => $code,
            'message' => 'Native encrypted vault created. Register the first administrator passkey now.']);
    }
}
