<?php
declare(strict_types=1);
require_once __DIR__ . '/Application.php';

class SecretsBackend extends IPSModule
{
    public const FRONTEND = '{8D6AE8F7-EA3A-4513-AA14-C3F9613B0E83}';
    private const STRINGS = ['DataDirectory', 'KeyDirectory', 'AdminOrigin', 'AnchorURL', 'AnchorPublicKey', 'AnchorKeyID', 'ClientCertificatePath', 'ClientKeyPath', 'AnchorCAFile', 'HardwareRootsDirectory', 'HardwareAAGUIDs', 'HardwareTrustVersion'];
    public function Create(): void
    {
        parent::Create();
        $this->RegisterPropertyBoolean('Enabled', false); $this->RegisterPropertyBoolean('DebugEnabled', false);
        $this->RegisterPropertyInteger('FrontendInstanceID', 0);
        foreach (self::STRINGS as $name) $this->RegisterPropertyString($name, $name === 'HardwareAAGUIDs' ? '[]' : ($name === 'HardwareTrustVersion' ? 'none' : ''));
        $this->RegisterVariableBoolean('DebugEnabled', 'Debug logging', '~Switch', 0); $this->EnableAction('DebugEnabled');
        $this->RegisterVariableString('Status', 'Backend status', '', 10);
        $this->RegisterVariableString('StorageStatus', 'Vault / key storage', '', 20);
        $this->RegisterVariableString('Debug', 'Debug', '~TextBox', 50);
        $this->RegisterTimer('Recovery', 0, 'SECB_Recover($_IPS[\'TARGET\']);');
        $this->RegisterMessage(0, 10103);
    }
    public function ApplyChanges(): void
    {
        parent::ApplyChanges(); $this->SetBuffer('Runtime', ''); $this->SetBuffer('Setup', '');
        $this->SetValue('DebugEnabled', $this->ReadPropertyBoolean('DebugEnabled'));
        $this->SetTimerInterval('Recovery', $this->ReadPropertyBoolean('Enabled') && IPS_GetKernelRunlevel() === 10103 ? 100 : 0);
        $this->SetStatus($this->ReadPropertyBoolean('Enabled') ? 200 : 104);
        $this->SetValue('Status', $this->ReadPropertyBoolean('Enabled') ? 'Recovery check pending.' : 'Disabled. Storage wizard can be authorized from this console.');
    }
    public function MessageSink($TimeStamp, $SenderID, $Message, $Data): void
    {
        if ((int)$SenderID === 0 && (int)$Message === 10103 && $this->ReadPropertyBoolean('Enabled')) $this->SetTimerInterval('Recovery', 100);
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
        $paths = ['vault' => rtrim($this->ReadPropertyString('DataDirectory'), '/'), 'keys' => rtrim($this->ReadPropertyString('KeyDirectory'), '/')];
        $kernel = rtrim(IPS_GetKernelDir(), '/') . '/';
        foreach ($paths as $path) {
            if ($path !== '' && ($path[0] !== '/' || str_contains($path, "\0") || preg_match('~(?:^|/)\.{1,2}(?:/|$)~', $path) || str_starts_with($path . '/', $kernel))) throw new RuntimeException('Storage must use private absolute paths outside the Symcon kernel/web/module tree.');
        }
        return $paths;
    }
    private function identity(): array
    {
        $paths = $this->paths();
        if (!is_file($paths['vault'] . '/vault.sqlite') || is_link($paths['vault'] . '/vault.sqlite') || (fileperms($paths['vault'] . '/vault.sqlite') & 0077) !== 0) throw new RuntimeException('Private storage has not been created.');
        $db = new PDO('sqlite:' . $paths['vault'] . '/vault.sqlite');
        $identity = $db->query("SELECT value FROM metadata WHERE name='identity'")->fetchColumn();
        return json_decode($identity, true, 8, JSON_THROW_ON_ERROR);
    }
    private function store(): SecretsBackendStore
    {
        $paths = $this->paths(); $identity = $this->identity();
        $anchor = new SecretsBackendAnchorClient($identity + ['url' => $this->ReadPropertyString('AnchorURL'), 'anchorPublicKey' => $this->ReadPropertyString('AnchorPublicKey'),
            'anchorKeyId' => $this->ReadPropertyString('AnchorKeyID'), 'signingKeyFile' => $paths['keys'] . '/anchor-sign.key', 'clientCertificate' => $this->ReadPropertyString('ClientCertificatePath'),
            'clientKey' => $this->ReadPropertyString('ClientKeyPath'), 'caFile' => $this->ReadPropertyString('AnchorCAFile')]);
        return new SecretsBackendStore($paths['vault'], $paths['keys'], $this->GetBuffer('Runtime'), $anchor);
    }
    public function Recover(): bool
    {
        $this->SetTimerInterval('Recovery', 0);
        if (!$this->ReadPropertyBoolean('Enabled')) return false;
        try {
            $this->configuration();
            if ($this->GetBuffer('Runtime') === '') $this->SetBuffer('Runtime', SecretsBackendCodec::b64(random_bytes(32)));
            $head = $this->store()->recover();
            $this->SetValue('Status', 'Development backend active; anchored commit ' . $head['index'] . '. Release verification remains pending.');
            $this->SetValue('StorageStatus', 'Separate encrypted vault and key storage are available.'); $this->SetStatus(102); $this->debug('recovery-ok'); return true;
        } catch (Throwable $exception) {
            $this->SetStatus(200); $this->SetValue('Status', 'Locked: ' . $exception->getMessage()); $this->debug('recovery-locked');
            if ($this->ReadPropertyBoolean('Enabled')) $this->SetTimerInterval('Recovery', 30000);
            return false;
        }
    }
    public function BeginStorageSetup(): string
    {
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
            $this->SetValue('StorageStatus', 'Both storages created. Provision the independent anchor before enabling access.'); $this->debug('storage-created');
            return ['data' => ['created' => true, 'provisioning' => $info]];
        } finally {
            if (isset($data['code']) && is_string($data['code']) && function_exists('sodium_memzero')) sodium_memzero($data['code']);
            IPS_SemaphoreLeave($lock);
        }
    }
    protected function initializeStorage(array $paths, array $settings): array
    {
        return SecretsBackendStore::initialize($paths['vault'], $paths['keys'], $settings['AdminOrigin'], $settings['FrontendInstanceID']);
    }
    public function BeginAdminEnrollment(string $Label, bool $Hardware): string
    {
        $code = $this->application()->beginEnrollment($Label, $Hardware);
        $this->UpdateFormField('EnrollmentCredential', 'value', $code); $this->debug('enrollment-authorized'); return $code;
    }
    private function application(): SecretsBackendApplication
    {
        if (!$this->ReadPropertyBoolean('Enabled')) throw new RuntimeException('Backend is disabled.');
        return new SecretsBackendApplication($this->store(), ['origin' => $this->ReadPropertyString('AdminOrigin'), 'frontend' => $this->ReadPropertyInteger('FrontendInstanceID'), 'backend' => $this->InstanceID,
            'hardwareRoots' => $this->ReadPropertyString('HardwareRootsDirectory'), 'hardwareAAGUIDs' => json_decode($this->ReadPropertyString('HardwareAAGUIDs'), true, 8, JSON_THROW_ON_ERROR),
            'hardwareTrustVersion' => $this->ReadPropertyString('HardwareTrustVersion')]);
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
                || $request['origin'] !== $this->ReadPropertyString('AdminOrigin')) throw new RuntimeException('Invalid frontend envelope.');
            $action = $request['action'];
            if (in_array($action, ['setupPreview', 'setupCreate'], true)) $result = $this->setup($action, $request['data']);
            elseif ($action === 'status' && (!is_file($this->paths()['vault'] . '/vault.sqlite') || !$this->ReadPropertyBoolean('Enabled') || $this->GetBuffer('Runtime') === '')) {
                $result = ['data' => ['ready' => false, 'storageCreated' => is_file($this->paths()['vault'] . '/vault.sqlite'), 'message' => 'Complete storage setup and independent anchor recovery in the backend console.']];
            } else $result = $this->application()->handle($action, $request['data'], $request);
            return SecretsBackendCodec::json(['status' => 200, 'data' => $result['data'], 'cookie' => $result['cookie'] ?? '']);
        } catch (Throwable $exception) {
            $this->debug('request-rejected');
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
    public function GetConfigurationForm(): string { return (string)file_get_contents(__DIR__ . '/form.json'); }
}
