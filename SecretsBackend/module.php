<?php
declare(strict_types=1);
require_once __DIR__ . '/Application.php';
require_once __DIR__ . '/SecurityConfiguration.php';
require_once __DIR__ . '/StoragePaths.php';
require_once __DIR__ . '/NativeBackend.php';
require_once __DIR__ . '/NativeRuntime.php';
require_once __DIR__ . '/LegacyRuntime.php';

class SecretsBackend extends IPSModule
{
    use SecretsBackendNativeBackend;
    use SecretsBackendNativeRuntime;
    use SecretsBackendLegacyRuntime;
    public const FRONTEND = '{8D6AE8F7-EA3A-4513-AA14-C3F9613B0E83}';
    private const STRINGS = ['DataDirectory', 'KeyDirectory', 'AdminOrigin', 'AnchorURL', 'AnchorPublicKey', 'AnchorKeyID', 'ClientCertificatePath', 'ClientKeyPath', 'AnchorCAFile', 'HardwareRootsDirectory', 'HardwareAAGUIDs', 'HardwareTrustVersion'];
    public function Create(): void
    {
        parent::Create();
        $this->RegisterAttributeString('StorageBinding', '');
        $this->RegisterAttributeBoolean('ProvisioningSealed', false);
        $this->RegisterAttributeBoolean('GuidedV2Only', true);
        foreach (['NativeVaultUUID', 'NativeInitUUID', 'NativeInitPlan'] as $attribute) $this->RegisterAttributeString($attribute, '');
        $this->RegisterPropertyBoolean('Enabled', false); $this->RegisterPropertyBoolean('DebugEnabled', false);
        $this->RegisterPropertyInteger('FrontendInstanceID', 0);
        foreach (self::STRINGS as $name) {
            $default = match ($name) {
                'DataDirectory' => SecretsBackendNativePlatform::defaults($this->InstanceID, IPS_GetKernelDir())['vaultDirectory'],
                'KeyDirectory' => SecretsBackendNativePlatform::defaults($this->InstanceID, IPS_GetKernelDir())['keyDirectory'],
                'HardwareAAGUIDs' => '[]', 'HardwareTrustVersion' => 'none', default => '',
            };
            $this->RegisterPropertyString($name, $default);
        }
        $this->RegisterVariableBoolean('DebugEnabled', 'Debug logging', '~Switch', 0); $this->EnableAction('DebugEnabled');
        $this->RegisterVariableString('Status', 'Backend status', '', 10);
        $this->RegisterVariableString('StorageStatus', 'Vault / key storage', '', 20);
        $this->RegisterVariableString('Debug', 'Debug', '~TextBox', 50);
        $this->RegisterTimer('Recovery', 0, 'SECB_Recover($_IPS[\'TARGET\']);');
        $this->RegisterTimer('NativeJobs', 0, 'SECB_RunNativeJobs($_IPS[\'TARGET\']);');
        $this->RegisterMessage(0, 10103);
    }
    public function ApplyChanges(): void
    {
        $lock = 'SECB.Runtime.' . $this->InstanceID;
        if (!IPS_SemaphoreEnter($lock, 500)) throw new RuntimeException('Runtime transition is busy; repeat apply after recovery.');
        try {
        parent::ApplyChanges();
        $approvedHandoff=$this->GetBuffer('ApprovedStorageHandoff');$this->SetBuffer('ApprovedStorageHandoff','');
        if($approvedHandoff!==''&&hash_equals($approvedHandoff,SecretsBackendSecurityConfiguration::digest($this->configuration())))return;
        $this->SetBuffer('ApplyingNativeSettings','1');
        $this->SetBuffer('Runtime', SecretsBackendCodec::b64(random_bytes(32))); $this->SetBuffer('Setup', '');
        $this->SetBuffer('RecoveryDelay', '1000');
        if ($this->ReadAttributeBoolean('GuidedV2Only') && ($this->ReadAttributeString('StorageBinding') === '' || ((json_decode($this->ReadAttributeString('StorageBinding'), true)['kind'] ?? '') === 'native'))) { $this->SetValue('DebugEnabled', $this->ReadPropertyBoolean('DebugEnabled')); $this->nativeApply(); return; }
        if ($this->ReadAttributeString('StorageBinding') !== '') {
            try { $this->store(true)->invalidate(); }
            catch (Throwable $exception) {
                $this->SetStatus(200); $this->SetValue('Status', 'Reload invalidation failed; backend locked. Retry recovery.');
                $this->SetTimerInterval('Recovery', $this->ReadPropertyBoolean('Enabled') ? 1000 : 0);
                throw $exception;
            }
        }
        $this->SetValue('DebugEnabled', $this->ReadPropertyBoolean('DebugEnabled'));
        if ($this->ReadAttributeBoolean('GuidedV2Only')) { $this->nativeUnavailable(); return; }
        $this->SetTimerInterval('Recovery', $this->ReadPropertyBoolean('Enabled') && IPS_GetKernelRunlevel() === 10103 ? 100 : 0);
        $this->SetStatus($this->ReadPropertyBoolean('Enabled') ? 200 : 104);
        $this->SetValue('Status', $this->ReadPropertyBoolean('Enabled') ? 'Recovery check pending.' : 'Disabled. Storage wizard can be authorized from this console.');
        } finally { $this->SetBuffer('ApplyingNativeSettings','');IPS_SemaphoreLeave($lock); }
    }
    public function MessageSink($TimeStamp, $SenderID, $Message, $Data): void
    {
        if ((int)$SenderID === 0 && (int)$Message === 10103 && $this->ReadPropertyBoolean('Enabled') && (!$this->ReadAttributeBoolean('GuidedV2Only') || $this->nativeInitialized())) $this->SetTimerInterval('Recovery', 100);
    }
    private function nativeUnavailable(): void
    {
        $this->SetTimerInterval('Recovery', 0);
        $this->SetStatus(201);
        $this->SetValue('Status', 'Native vault not initialized. Open the HTML setup wizard; no additional database or anchor service is required.');
        $this->SetValue('StorageStatus', 'Native encrypted storage has not been created yet.');
    }
    private function configuration(): array
    {
        $settings = ['Enabled' => $this->ReadPropertyBoolean('Enabled'), 'DebugEnabled' => $this->ReadPropertyBoolean('DebugEnabled'), 'FrontendInstanceID' => $this->ReadPropertyInteger('FrontendInstanceID')];
        foreach (self::STRINGS as $name) $settings[$name] = $this->ReadPropertyString($name);
        return self::validate($settings);
    }
    private static function validate(array $settings): array
    {
        $names = array_merge(['Enabled', 'DebugEnabled', 'FrontendInstanceID'], self::STRINGS);
        if (array_diff(array_keys($settings), $names) || array_diff($names, array_keys($settings))) throw new InvalidArgumentException('Invalid backend configuration fields.');
        foreach (self::STRINGS as $key) if (!is_string($settings[$key]) || strlen($settings[$key]) > 4096) throw new InvalidArgumentException('Invalid backend text setting.');
        foreach (['Enabled', 'DebugEnabled'] as $key) if (!is_bool($settings[$key])) throw new InvalidArgumentException('Invalid Boolean setting.');
        if (!is_int($settings['FrontendInstanceID']) || $settings['FrontendInstanceID'] < 0) throw new InvalidArgumentException('Invalid frontend instance.');
        $settings['AdminOrigin'] = SecretsFrontendConfiguration::origin($settings['AdminOrigin']);
        $models = json_decode($settings['HardwareAAGUIDs'], true, 8, JSON_THROW_ON_ERROR);
        if (!is_array($models) || array_values($models) !== $models || count($models) > 100) throw new InvalidArgumentException('Hardware model list must be an array.');
        foreach ($models as $model) if (!is_string($model) || !preg_match('/^[a-f0-9]{32}$/D', $model)) throw new InvalidArgumentException('Use exact lowercase AAGUID hex values.');
        return $settings;
    }
    private function paths(): array
    {
        $paths = SecretsBackendStoragePaths::pair($this->ReadPropertyString('DataDirectory'), $this->ReadPropertyString('KeyDirectory'), IPS_GetKernelDir(), false, true);
        return ['vault' => $paths['vaultDirectory'], 'keys' => $paths['keyDirectory']];
    }
    private function boundPaths(): array
    {
        $raw = $this->ReadAttributeString('StorageBinding');
        if ($raw === '') return $this->paths();
        $binding = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        if (($binding['backend'] ?? 0) !== $this->InstanceID) throw new RuntimeException('Storage binding belongs to a different backend instance.');
        return $binding['paths'];
    }
    private function identity(): array
    {
        $paths = $this->boundPaths();
        if (!is_file($paths['vault'] . '/vault.sqlite') || is_link($paths['vault'] . '/vault.sqlite') || (fileperms($paths['vault'] . '/vault.sqlite') & 0077) !== 0) throw new RuntimeException('Private storage has not been created.');
        $db = new PDO('sqlite:' . $paths['vault'] . '/vault.sqlite');
        $identity = $db->query("SELECT value FROM metadata WHERE name='identity'")->fetchColumn();
        return json_decode($identity, true, 8, JSON_THROW_ON_ERROR);
    }
    private function bootstrap(): ?array
    {
        $paths = $this->boundPaths(); $file = $paths['keys'] . '/management-bootstrap.json';
        if (!is_file($file)) {
            if ($this->ReadAttributeBoolean('ProvisioningSealed')) throw new RuntimeException('Pinned provisioning file is missing; independent recovery is required.');
            return null;
        }
        $identity = $this->identity();
        $data = json_decode(SecretsBackendCodec::open(SecretsBackendCodec::privateFile($file), SecretsBackendCodec::privateFile($paths['keys'] . '/master.key'),
            'management-bootstrap:' . $identity['deploymentId']), true, 32, JSON_THROW_ON_ERROR);
        if (($data['backend'] ?? 0) !== $this->InstanceID || $data['deployment'] !== $identity['deploymentId']) throw new RuntimeException('Duplicate deployment or different backend binding.');
        return $data;
    }
    private function frontendSecurity(): array
    {
        $id = $this->ReadPropertyInteger('FrontendInstanceID');
        if ($id <= 0 || !IPS_InstanceExists($id) || strtoupper(IPS_GetInstance($id)['ModuleInfo']['ModuleID'] ?? '') !== self::FRONTEND) throw new RuntimeException('Select the dedicated frontend.');
        if (IPS_GetProperty($id, 'BackendInstanceID') !== $this->InstanceID
            || SecretsFrontendConfiguration::origin(IPS_GetProperty($id, 'AdminOrigin')) !== SecretsFrontendConfiguration::origin($this->ReadPropertyString('AdminOrigin'))) throw new RuntimeException('The frontend must reciprocally bind this backend and its exact HTTPS origin.');
        return ['instance' => $id, 'backend' => IPS_GetProperty($id, 'BackendInstanceID'),
            'origin' => SecretsFrontendConfiguration::origin(IPS_GetProperty($id, 'AdminOrigin')),
            'proxies' => json_decode(IPS_GetProperty($id, 'TrustedHTTPSProxyIPs'), true, 8, JSON_THROW_ON_ERROR)];
    }
    private function candidate(): array { return SecretsBackendSecurityConfiguration::profile($this->configuration(), $this->frontendSecurity()); }
    private function assertOwnership(): void
    {
        $paths = $this->boundPaths();
        foreach (IPS_GetInstanceListByModuleID('{52165EDD-B2C0-40EC-8A59-42A97319B6E2}') as $other) {
            if ($other === $this->InstanceID) continue;
            foreach (['DataDirectory' => 'vault', 'KeyDirectory' => 'keys'] as $field => $kind) {
                $otherPath = IPS_GetProperty($other, $field);
                if ($otherPath !== '' && realpath($otherPath) !== false && realpath($otherPath) === realpath($paths[$kind])) throw new RuntimeException('Another backend instance claims this storage.');
            }
        }
    }
    protected function anchor(array $identity, array $paths, array $settings): SecretsBackendAnchorClient
    {
        return new SecretsBackendAnchorClient($identity + ['url' => $settings['AnchorURL'], 'anchorPublicKey' => $settings['AnchorPublicKey'],
            'anchorKeyId' => $settings['AnchorKeyID'], 'signingKeyFile' => $paths['keys'] . '/anchor-sign.key', 'clientCertificate' => $settings['ClientCertificatePath'],
            'clientKey' => $settings['ClientKeyPath'], 'caFile' => $settings['AnchorCAFile']]);
    }
    protected function store(bool $allowDrift = false): SecretsBackendStore
    {
        require_once __DIR__ . '/Store.php';
        $paths = $this->boundPaths(); $identity = $this->identity(); $bootstrap = $this->bootstrap();
        if ($bootstrap !== null) {
            if (!$allowDrift && !SecretsBackendSecurityConfiguration::sameFoundation($bootstrap['profile']['settings'], $this->configuration())) throw new RuntimeException('Provisioned foundation settings changed; ordinary apply/import cannot replace anchor trust or storage.');
            $settings = $bootstrap['profile']['settings'];
        } else $settings = $this->configuration();
        if (!$allowDrift) $this->assertOwnership();
        return $this->openStore($paths, $this->GetBuffer('Runtime'), $this->anchor($identity, $paths, $settings));
    }
    protected function openStore(array $paths, string $runtime, SecretsBackendAnchorClient $anchor): SecretsBackendStore
    {
        return new SecretsBackendStore($paths['vault'], $paths['keys'], $runtime, $anchor);
    }
    public function Recover(): bool
    {
        // Finish an already-authorized path/property handoff before taking the
        // lifecycle semaphore: IPS_ApplyChanges needs that same semaphore.
        if($this->ReadAttributeBoolean('GuidedV2Only')&&$this->nativeInitialized()&&$this->ReadPropertyBoolean('Enabled')){
            try{$this->nativeStore();}catch(Throwable $e){$this->SetStatus(200);$this->SetValue('Status','Native vault locked: '.$e->getMessage());return false;}
        }
        $lock = 'SECB.Runtime.' . $this->InstanceID;
        if (!IPS_SemaphoreEnter($lock, 100)) return false;
        try {
        $this->SetTimerInterval('Recovery', 0);
        if ($this->ReadAttributeBoolean('GuidedV2Only')) return $this->nativeRecover();
        if (!$this->ReadPropertyBoolean('Enabled')) return false;
        try {
            $this->configuration();
            if ($this->GetBuffer('Runtime') === '') $this->SetBuffer('Runtime', SecretsBackendCodec::b64(random_bytes(32)));
            $head = $this->store()->recover();
            $this->SetBuffer('RecoveryDelay', '1000');
            $this->SetValue('Status', 'Development backend active; anchored commit ' . $head['index'] . '. Release verification remains pending.');
            $this->SetValue('StorageStatus', 'Separate encrypted vault and key storage are available.'); $this->SetStatus(102); $this->debug('recovery-ok'); return true;
        } catch (Throwable $exception) {
            $this->SetStatus(200); $this->SetValue('Status', 'Locked: ' . $exception->getMessage()); $this->debug('recovery-locked');
            $this->scheduleRecovery();
            return false;
        }
        } finally { IPS_SemaphoreLeave($lock); }
    }
    private function scheduleRecovery(): void
    {
        if (!$this->ReadPropertyBoolean('Enabled') || $this->ReadAttributeBoolean('GuidedV2Only')) return;
        $delay = max(1000, min(30000, (int)$this->GetBuffer('RecoveryDelay')));
        $this->SetTimerInterval('Recovery', $delay); $this->SetBuffer('RecoveryDelay', (string)min(30000, $delay * 2));
    }
    private function initialSettingsSnapshot(): array
    {
        $settings = ['Enabled' => $this->ReadPropertyBoolean('Enabled'), 'DebugEnabled' => $this->ReadPropertyBoolean('DebugEnabled'), 'FrontendInstanceID' => $this->ReadPropertyInteger('FrontendInstanceID')];
        foreach (self::STRINGS as $key) $settings[$key] = $this->ReadPropertyString($key);
        return $settings;
    }
    /** Privileged local settings helper; never dispatched by HandleFrontendRequest. */
    public function GetInitialSetupInfo(): string
    {
        $empty = true;
        foreach (['DataDirectory', 'KeyDirectory'] as $field) { $path = $this->ReadPropertyString($field); if ($path !== '' && (is_link($path) || (is_dir($path) && count(scandir($path) ?: []) > 2) || (file_exists($path) && !is_dir($path)))) $empty = false; }
        return SecretsFrontendConfiguration::encode(['backend' => $this->InstanceID, 'canConfigure' => !$this->ReadAttributeBoolean('ProvisioningSealed') && $this->ReadAttributeString('StorageBinding') === '' && ($empty || $this->ReadAttributeString('NativeInitPlan') !== '') && !$this->nativeInitialized() && !IPS_HasChanges($this->InstanceID),
            'frontend' => $this->ReadPropertyInteger('FrontendInstanceID'), 'origin' => $this->ReadPropertyString('AdminOrigin'), 'vaultDirectory' => $this->ReadPropertyString('DataDirectory'), 'keyDirectory' => $this->ReadPropertyString('KeyDirectory'),
            'nativeInitializationPending' => $this->ReadAttributeString('NativeInitPlan') !== '' && !$this->nativeInitialized(), 'digest' => hash('sha256', SecretsFrontendConfiguration::encode($this->initialSettingsSnapshot())), 'quorumConnected' => false]);
    }
    /** Initial settings only. No files/credentials, no enable, no trust pin or rights changes. */
    public function ConfigureInitialSetup(int $FrontendInstanceID, string $ExpectedDigest, string $SettingsJSON): bool
    {
        $lock = 'SECB.Runtime.' . $this->InstanceID;
        if (!IPS_SemaphoreEnter($lock, 500)) throw new RuntimeException('Backend setup is busy.');
        $setupLock = 'SECB.Setup.' . $this->InstanceID;
        if (!IPS_SemaphoreEnter($setupLock, 500)) { IPS_SemaphoreLeave($lock); throw new RuntimeException('An existing storage operation is busy.'); }
        try {
            $info = json_decode($this->GetInitialSetupInfo(), true, 16, JSON_THROW_ON_ERROR);
            if (!$info['canConfigure'] || !hash_equals($info['digest'], $ExpectedDigest) || !in_array($info['frontend'], [0, $FrontendInstanceID], true)) throw new RuntimeException('Backend changed or is already commissioned. Repeat discovery.');
            if (!IPS_InstanceExists($FrontendInstanceID) || strtoupper(IPS_GetInstance($FrontendInstanceID)['ModuleInfo']['ModuleID'] ?? '') !== self::FRONTEND || IPS_HasChanges($FrontendInstanceID)) throw new RuntimeException('Use the dedicated frontend with applied settings.');
            $data = SecretsFrontendConfiguration::decode($SettingsJSON);
            if (count($data) !== 4 || array_diff(array_keys($data), ['origin', 'vaultDirectory', 'keyDirectory', 'debugEnabled']) || !is_bool($data['debugEnabled'] ?? null) || !is_string($data['origin'] ?? null) || !is_string($data['vaultDirectory'] ?? null) || !is_string($data['keyDirectory'] ?? null)) throw new RuntimeException('Invalid initial settings.');
            require_once __DIR__ . '/../SecretsFrontend/Commissioning.php';
            $paths = SecretsBackendNativePlatform::paths($data['vaultDirectory'], $data['keyDirectory'], IPS_GetKernelDir(), $this->ReadAttributeString('NativeInitPlan') === '');
            $origin = SecretsFrontendConfiguration::origin($data['origin']);
            if ($origin === '' || $origin !== SecretsFrontendConfiguration::origin(IPS_GetProperty($FrontendInstanceID, 'AdminOrigin'))) throw new RuntimeException('Pinned frontend origin changed.');
            // Consume the initial mode before configuration changes. A partial apply remains disabled.
            $this->WriteAttributeBoolean('GuidedV2Only', true);
            $this->SetBuffer('Setup', ''); $this->UpdateFormField('SetupCredential', 'value', '');
            foreach (['Enabled' => false, 'DebugEnabled' => $data['debugEnabled'], 'FrontendInstanceID' => $FrontendInstanceID, 'AdminOrigin' => $origin, 'DataDirectory' => $paths['vaultDirectory'], 'KeyDirectory' => $paths['keyDirectory']] as $key => $value) IPS_SetProperty($this->InstanceID, $key, $value);
        } finally { IPS_SemaphoreLeave($setupLock); IPS_SemaphoreLeave($lock); }
        IPS_ApplyChanges($this->InstanceID);
        $this->SetValue('StorageStatus', 'Settings prepared by HTML wizard. Native encrypted storage has not been initialized yet.');
        return true;
    }
    public function BeginStorageSetup(): string
    {
        if ($this->ReadAttributeBoolean('GuidedV2Only')) throw new RuntimeException('The native wizard initializes storage directly. These earlier V1 controls are not used.');
        if ($this->ReadAttributeString('StorageBinding') !== '') throw new RuntimeException('This instance is already bound to storage; initial setup cannot replace an existing deployment.');
        $settings = $this->configuration(); $paths = $this->paths();
        if ($settings['FrontendInstanceID'] <= 0 || $settings['AdminOrigin'] === '' || $paths['vault'] === '' || $paths['keys'] === '') throw new RuntimeException('Select the new frontend, exact HTTPS origin and two separate absolute directory paths first.');
        if (is_file($paths['vault'] . '/vault.sqlite')) throw new RuntimeException('A vault already exists. Setup never replaces storage.');
        $raw = SecretsBackendCodec::b64(random_bytes(32));
        $this->SetBuffer('Setup', SecretsBackendCodec::json(['hash' => hash('sha256', $raw), 'expires' => time() + 600, 'tries' => 0,
            'binding' => hash('sha256', SecretsBackendCodec::json([$paths, $settings['AdminOrigin'], $settings['FrontendInstanceID']])), 'plan' => '']));
        $this->UpdateFormField('SetupCredential', 'value', $raw); $this->debug('setup-authorized'); return $raw;
    }
    public function CancelStorageSetup(): void { $this->SetBuffer('Setup', ''); $this->UpdateFormField('SetupCredential', 'value', ''); $this->debug('setup-cancelled'); }
    private function setup(string $action, array $data): array
    {
        $lock = 'SECB.Setup.' . $this->InstanceID;
        if (!IPS_SemaphoreEnter($lock, 500)) throw new RuntimeException('Setup is busy.');
        try {
            $setup = json_decode($this->GetBuffer('Setup'), true);
            if (!is_array($setup) || ($setup['expires'] ?? 0) < time() || ($setup['tries'] ?? 5) >= 5) throw new RuntimeException('Setup credential expired. Issue a new one in the backend console.');
            $setup['tries']++; $this->SetBuffer('Setup', SecretsBackendCodec::json($setup));
            if (!is_string($data['code'] ?? null) || !hash_equals($setup['hash'], hash('sha256', $data['code']))) throw new RuntimeException('Invalid setup credential.');
            $paths = $this->paths(); $settings = $this->configuration();
            if ($setup['binding'] !== hash('sha256', SecretsBackendCodec::json([$paths, $settings['AdminOrigin'], $settings['FrontendInstanceID']]))) throw new RuntimeException('Setup settings changed; issue a new credential.');
            if ($action === 'setupPreview') {
                if (array_keys($data) !== ['code']) throw new RuntimeException('Invalid setup preview.');
                $setup['plan'] = SecretsBackendCodec::b64(random_bytes(32)); $this->SetBuffer('Setup', SecretsBackendCodec::json($setup));
                return ['data' => ['planId' => $setup['plan'], 'vaultDirectory' => $paths['vault'], 'keyDirectory' => $paths['keys'],
                    'permissions' => 'Vault/key directories 0700; key files 0600; runs as the Symcon service account.']];
            }
            if (count($data) !== 2 || !is_string($data['planId'] ?? null) || $setup['plan'] === '' || !hash_equals($setup['plan'], $data['planId'])) throw new RuntimeException('Review the exact storage plan before creation.');
            $this->SetBuffer('Setup', ''); $this->UpdateFormField('SetupCredential', 'value', ''); // Consume BEFORE filesystem changes.
            $info = $this->initializeStorage($paths, $settings);
            $this->WriteAttributeString('StorageBinding', SecretsBackendCodec::json(['backend' => $this->InstanceID, 'paths' => $paths]));
            $this->SetValue('StorageStatus', 'Both storages created. Provision the independent anchor before enabling access.'); $this->debug('storage-created');
            return ['data' => ['created' => true, 'provisioning' => $info]];
        } finally {
            if (isset($data['code']) && is_string($data['code']) && function_exists('sodium_memzero')) sodium_memzero($data['code']);
            IPS_SemaphoreLeave($lock);
        }
    }
    protected function initializeStorage(array $paths, array $settings): array
    {
        require_once __DIR__ . '/Store.php';
        // Recheck after review and immediately before any key/state creation.
        $checked = SecretsBackendStoragePaths::pair($paths['vault'], $paths['keys'], IPS_GetKernelDir());
        return SecretsBackendStore::initialize($checked['vaultDirectory'], $checked['keyDirectory'], $settings['AdminOrigin'], $settings['FrontendInstanceID']);
    }
    public function BeginAdminEnrollment(string $Label, bool $Hardware): string
    {
        if ($this->ReadAttributeBoolean('GuidedV2Only')) throw new RuntimeException('Manual enrollment codes are disabled in native mode.');
        $code = ($this->ReadAttributeBoolean('GuidedV2Only') ? $this->nativeApplication() : $this->application())->beginEnrollment($Label, $Hardware);
        $this->UpdateFormField('EnrollmentCredential', 'value', $code); $this->debug('enrollment-authorized'); return $code;
    }
    /** Independent initial provisioning ONLY; never a fallback for existing administrator rights. */
    public function SecurityConfigurationDigest(): string
    {
        $digest = SecretsBackendSecurityConfiguration::digest($this->candidate());
        $this->UpdateFormField('ProvisioningDigest', 'value', $digest); return $digest;
    }
    public function SealInitialSecurityConfiguration(string $ExpectedDigest): bool
    {
        if (!$this->ReadPropertyBoolean('Enabled') || IPS_HasChanges($this->InstanceID)) throw new RuntimeException('Apply provisioning settings and recover the backend first.');
        $store = $this->store(); $current = $store->read();
        if ($current['state']['identity']['credentials'] || $current['state']['policy']['management'] !== null) throw new RuntimeException('Initial provisioning is closed; normal updates require action approval.');
        $profile = $this->candidate();
        if (!hash_equals(SecretsBackendSecurityConfiguration::digest($profile), $ExpectedDigest)) throw new RuntimeException('Review the exact current provisioning digest.');
        $paths = $this->boundPaths(); $file = $paths['keys'] . '/management-bootstrap.json';
        $bootstrap = $this->bootstrap();
        if ($bootstrap === null) {
            SecretsBackendCodec::writeNew($file, SecretsBackendCodec::seal(SecretsBackendCodec::json(['backend' => $this->InstanceID,
                'deployment' => $store->identity()['deploymentId'], 'profile' => $profile]), SecretsBackendCodec::privateFile($paths['keys'] . '/master.key'),
                'management-bootstrap:' . $store->identity()['deploymentId']));
        } elseif (SecretsBackendSecurityConfiguration::digest($bootstrap['profile']) !== $ExpectedDigest) throw new RuntimeException('Provisioning was already pinned to different settings.');
        $this->WriteAttributeBoolean('ProvisioningSealed', true);
        try { $store->change($current['head'], SecretsBackendCodec::uuid(), $ExpectedDigest, static function ($state) use ($profile) {
            $state['policy']['management'] = $profile; return $state;
        }, ['action' => 'provisioning', 'actor' => 'independent-console-provisioning', 'target' => $ExpectedDigest, 'backend' => $this->InstanceID, 'frontend' => $this->ReadPropertyInteger('FrontendInstanceID')]);
        } catch (Throwable $exception) { $this->SetStatus(200); $this->scheduleRecovery(); throw $exception; }
        return true;
    }
    private function application(): SecretsBackendApplication
    {
        if (!$this->ReadPropertyBoolean('Enabled')) throw new RuntimeException('Backend is disabled.');
        $store = $this->store(); $current = $store->read(); $profile = $current['state']['policy']['management'];
        if (!is_array($profile)) throw new RuntimeException('Seal initial security configuration explicitly in the backend console before enrollment.');
        SecretsBackendSecurityConfiguration::verify($profile, $this->frontendSecurity());
        $active = $profile['settings'];
        return new SecretsBackendApplication($store, ['origin' => $active['AdminOrigin'], 'frontend' => $active['FrontendInstanceID'], 'backend' => $this->InstanceID,
            'hardwareRoots' => $active['HardwareRootsDirectory'], 'hardwareAAGUIDs' => json_decode($active['HardwareAAGUIDs'], true, 8, JSON_THROW_ON_ERROR),
            'hardwareTrustVersion' => $active['HardwareTrustVersion'], 'managementProfile' => $profile,
            'candidateProfile' => fn() => $this->candidate()]);
    }
    /** Local backend entry point; browser routes never accept an instance ID or arbitrary function. */
    public function HandleFrontendRequest(int $FrontendInstanceID, string $RequestJSON): string
    {
        set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
            if (!(error_reporting() & $severity)) return false;
            throw new ErrorException($message, 0, $severity, $file, $line);
        });
        try {
            if ($FrontendInstanceID <= 0 || $FrontendInstanceID !== $this->ReadPropertyInteger('FrontendInstanceID') || !IPS_InstanceExists($FrontendInstanceID)
                || strtoupper(IPS_GetInstance($FrontendInstanceID)['ModuleInfo']['ModuleID'] ?? '') !== self::FRONTEND
                || IPS_GetProperty($FrontendInstanceID, 'BackendInstanceID') !== $this->InstanceID) throw new RuntimeException('Frontend/backend binding is invalid.');
            $request = SecretsFrontendConfiguration::decode($RequestJSON);
            if (count($request) !== 6 || !is_string($request['action'] ?? null) || !is_array($request['data'] ?? null)
                || !is_string($request['origin'] ?? null) || !is_string($request['cookie'] ?? null) || !is_string($request['csrf'] ?? null) || !is_string($request['remote'] ?? null)
                || (!$this->ReadAttributeBoolean('GuidedV2Only') && $request['origin'] !== $this->configuration()['AdminOrigin'])) throw new RuntimeException('Invalid frontend envelope.');
            $action = $request['action'];
            if ($this->ReadAttributeBoolean('GuidedV2Only')) {
                if ($this->nativeInitialized()) {
                    if ($action === 'status') $this->Recover();
                    $result = $this->nativeApplication($request['origin'])->handle($action, $request['data'], $request);
                    if ($action === 'status') $result['data'] += ['nativeBackendImplemented' => true, 'initialized' => true];
                } else {
                    if ($action !== 'status' || $request['data'] !== []) throw new RuntimeException('Initialize the native vault in the HTML setup wizard first.');
                    $result = ['data' => ['ready' => false, 'guidedV2Only' => true, 'nativeBackendImplemented' => true, 'message' => 'Native vault not initialized; complete the HTML setup wizard.']];
                }
            }
            elseif (in_array($action, ['setupPreview', 'setupCreate'], true)) $result = $this->setup($action, $request['data']);
            elseif ($action === 'status' && (!is_file($this->paths()['vault'] . '/vault.sqlite') || !$this->ReadPropertyBoolean('Enabled') || $this->GetBuffer('Runtime') === '')) {
                $result = ['data' => ['ready' => false, 'storageCreated' => is_file($this->paths()['vault'] . '/vault.sqlite'), 'message' => 'Complete storage setup and independent anchor recovery in the backend console.']];
            } else $result = $this->application()->handle($action, $request['data'], $request);
            return SecretsBackendCodec::json(['status' => 200, 'data' => $result['data'], 'cookie' => $result['cookie'] ?? '']);
        } catch (Throwable $exception) {
            $this->debug('request-rejected');
            if (!$this->ReadAttributeBoolean('GuidedV2Only')) { try {
                if ($this->store(true)->recoveryRequired()) { $this->SetStatus(200); $this->scheduleRecovery(); }
            } catch (Throwable $ignored) { if ($this->ReadPropertyBoolean('Enabled')) $this->scheduleRecovery(); } }
            elseif (!$this->nativeInitialized()) $this->nativeUnavailable();
            else { try { $this->nativeStore()->read(); } catch (Throwable $ignored) { $this->SetStatus(200); $this->SetTimerInterval('NativeJobs', 0); } }
            $this->SetValue('Status', 'Request refused: ' . $exception->getMessage());
            // No exception text, secret input or filesystem details are sent to unauthenticated clients.
            return SecretsBackendCodec::json(['status' => 403, 'data' => ['error' => 'Request refused. Check login, revision, approval and backend status.'], 'cookie' => '']);
        } finally {
            restore_error_handler();
        }
    }
    public function ExportConfiguration(): string
    {
        $json = SecretsFrontendConfiguration::encode(['schema' => 'SECB.Config.v1', 'configuration' => $this->configuration()]);
        $this->UpdateFormField('ExportJSON', 'value', $json); return $json;
    }
    public function ImportConfiguration(string $JSON): bool
    {
        $data = SecretsFrontendConfiguration::decode($JSON);
        if (count($data) !== 2 || ($data['schema'] ?? '') !== 'SECB.Config.v1' || !is_array($data['configuration'] ?? null)) throw new InvalidArgumentException('Expected SECB.Config.v1.');
        if (IPS_HasChanges($this->InstanceID)) throw new RuntimeException('Apply or discard pending console edits before import.');
        $settings = self::validate($data['configuration']); $settings['Enabled'] = false;
        if ($this->nativeInitialized()) {
            $approved = $this->nativeStore()->storageHandoff()['profile']['settings'];
        } elseif ($this->ReadAttributeBoolean('GuidedV2Only') && $this->ReadAttributeString('StorageBinding') === '' && !$this->ReadAttributeBoolean('ProvisioningSealed')) {
            if ($this->ReadAttributeString('NativeInitPlan') !== '') {
                throw new RuntimeException('Resolve the interrupted native setup before importing configuration.');
            }
            $kernel = IPS_GetKernelDir();
            $defaults = SecretsBackendNativePlatform::defaults($this->InstanceID, $kernel);
            SecretsBackendNativePlatform::paths(
                $settings['DataDirectory'] === '' ? $defaults['vaultDirectory'] : $settings['DataDirectory'],
                $settings['KeyDirectory'] === '' ? $defaults['keyDirectory'] : $settings['KeyDirectory'],
                $kernel
            );
            $approved = null;
        } else {
            $approved = $this->bootstrap()['profile']['settings'] ?? null;
        }
        if ($approved !== null && !SecretsBackendSecurityConfiguration::sameFoundation($approved, $settings)) {
            throw new RuntimeException('Import cannot replace provisioned anchor trust, pairing or storage. Hardware settings are staged for explicit approval.');
        }
        foreach ($settings as $key => $value) IPS_SetProperty($this->InstanceID, $key, $value);
        IPS_ApplyChanges($this->InstanceID); $this->debug('configuration-imported-disabled'); return true;
    }
    public function RequestAction($Ident, $Value): void
    {
        if ($Ident !== 'DebugEnabled' || !is_bool($Value) || IPS_HasChanges($this->InstanceID)) throw new InvalidArgumentException('Unsupported action or unapplied settings.');
        IPS_SetProperty($this->InstanceID, 'DebugEnabled', $Value); IPS_ApplyChanges($this->InstanceID);
    }
    public function ClearDebug(): void { $this->SetValue('Debug', ''); }
    private function debug(string $code): void
    {
        if (!$this->ReadPropertyBoolean('DebugEnabled')) return;
        $allowed = ['setup-authorized', 'setup-cancelled', 'storage-created', 'recovery-ok', 'recovery-locked', 'request-rejected', 'enrollment-authorized', 'configuration-imported-disabled'];
        if (!in_array($code, $allowed, true)) return;
        $lines = array_filter(explode("\n", (string)$this->GetValue('Debug'))); $lines[] = gmdate('Y-m-d H:i:s') . ' UTC | ' . $code;
        $this->SetValue('Debug', implode("\n", array_slice($lines, -50)));
    }
    public function GetConfigurationForm(): string
    {
        $form = json_decode((string)file_get_contents(__DIR__ . '/form.json'), true, 32, JSON_THROW_ON_ERROR);
        $native = $this->ReadAttributeBoolean('GuidedV2Only');
        $initialized = $native && $this->nativeInitialized();
        $sealed = $this->ReadAttributeBoolean('ProvisioningSealed') || $initialized;
        if (!$native) { try { $sealed = $sealed || $this->bootstrap() !== null; } catch (Throwable $ignored) { $sealed = true; } }
        $fill = function (array &$items) use (&$fill, $sealed, $native, $initialized): void { foreach ($items as &$element) {
            if ($sealed && in_array($element['name'] ?? '', SecretsBackendSecurityConfiguration::FOUNDATION, true)) $element['enabled'] = false;
            if ($native && (preg_match('/(?:BeginStorageSetup|BeginAdminEnrollment|SealInitialSecurityConfiguration)/',$element['onClick']??'') || in_array($element['name']??'',['SetupCredential','EnrollmentCredential'],true))) $element['visible']=false;
            if ($native && (($element['name'] ?? '') === 'Enabled' || preg_match('/^SECB_(?:BeginStorageSetup|SecurityConfigurationDigest|SealInitialSecurityConfiguration|Recover|BeginAdminEnrollment)\(/', $element['onClick'] ?? ''))) $element['enabled'] = false;
            if ($native && ($element['name'] ?? '') === 'Enabled') { $element['enabled'] = $initialized; $element['caption'] = 'Enable native vault'; }
            if ($native && ($element['onClick'] ?? '') === 'SECB_Recover($id);') { $element['enabled'] = $initialized; $element['caption'] = 'Check native encrypted storage / recover'; }
            if (($element['name'] ?? '') === 'BackendWizardURL') {
                $id = $this->ReadPropertyInteger('FrontendInstanceID');
                if ($id > 0 && IPS_InstanceExists($id) && strtoupper(IPS_GetInstance($id)['ModuleInfo']['ModuleID'] ?? '') === self::FRONTEND) { try { $element['value'] = SecretsFrontendConfiguration::origin(IPS_GetProperty($id, 'AdminOrigin')) . '/hook/secrets_frontend_' . $id; } catch (Throwable $ignored) {} }
            }
            if (isset($element['items'])) $fill($element['items']);
        } }; $fill($form['elements']); $fill($form['actions']);
        return SecretsBackendCodec::json($form);
    }
}
