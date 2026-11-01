<?php
declare(strict_types=1);
require_once __DIR__ . '/Commissioning.php';

/** A console-authorized, ten-minute, settings-only bootstrap for fresh instances. */
trait SecretsFrontendGuidedSetup
{
    private function guidedActive(): bool
    {
        $grant = json_decode($this->GetBuffer('GuidedSetup'), true);
        return is_array($grant) && ($grant['expires'] ?? 0) >= time() && ($grant['failed'] ?? 5) < 5;
    }
    private function setupName(int $id, string $fallback): string { return function_exists('IPS_GetName') ? IPS_GetName($id) . ' · ' . $id : $fallback . ' · ' . $id; }
    private function initialBackend(int $id): array
    {
        if ($id <= 0 || !IPS_InstanceExists($id) || strtoupper(IPS_GetInstance($id)['ModuleInfo']['ModuleID'] ?? '') !== self::BACKEND || !function_exists('SECB_GetInitialSetupInfo')) throw new RuntimeException('Choose a new SecretsBackend instance.');
        return json_decode(SECB_GetInitialSetupInfo($id), true, 16, JSON_THROW_ON_ERROR);
    }
    public function BeginGuidedSetup(string $Address, string $ProxyIPs): string
    {
        $lock = 'SECF.GuidedSetup.' . $this->InstanceID;
        if (!IPS_SemaphoreEnter($lock, 500)) throw new RuntimeException('Setup is busy; wait before issuing a new authorization.');
        try { return $this->startGuidedSetup($Address, $ProxyIPs); } finally { IPS_SemaphoreLeave($lock); }
    }
    private function startGuidedSetup(string $Address, string $ProxyIPs): string
    {
        if (IPS_HasChanges($this->InstanceID)) throw new RuntimeException('Apply or discard pending frontend edits first.');
        $origin = SecretsFrontendCommissioning::address($Address);
        $proxies = SecretsFrontendCommissioning::proxies($ProxyIPs);
        $roster = [];
        foreach (IPS_GetInstanceListByModuleID(self::BACKEND) as $id) {
            try { $info = $this->initialBackend((int)$id); } catch (Throwable $ignored) { continue; }
            if ($info['canConfigure'] && in_array($info['frontend'], [0, $this->InstanceID], true)) $roster[(string)$id] = $info['digest'];
        }
        $paired = $this->ReadPropertyInteger('BackendInstanceID');
        if (!$roster || count($roster) > 32 || ($paired > 0 && !array_key_exists((string)$paired, $roster))) throw new RuntimeException('Use an uncommissioned backend. Existing deployments require their normal administrator/recovery procedure.');
        // Origin/proxy trust comes from this privileged console action, never Host/forwarded headers.
        foreach (['Enabled' => true, 'AdminOrigin' => $origin, 'TrustedHTTPSProxyIPs' => SecretsFrontendConfiguration::encode($proxies)] as $key => $value) IPS_SetProperty($this->InstanceID, $key, $value);
        $this->WriteAttributeBoolean('GuidedV2Only', true);
        $this->WriteAttributeBoolean('GuidedConfigured', false);
        IPS_ApplyChanges($this->InstanceID);
        $code = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $this->SetBuffer('GuidedSetup', SecretsFrontendConfiguration::encode(['hash' => hash('sha256', $code), 'expires' => time() + 600, 'failed' => 0,
            'origin' => $origin, 'frontendDigest' => SecretsFrontendCommissioning::digest($this->settings()), 'backends' => $roster, 'plan' => null]));
        if (!$this->Refresh()) { $this->forgetGuidedSetup(); throw new RuntimeException('The setup page could not be registered. Check WebhookControl.'); }
        $this->UpdateFormField('SetupAccessCode', 'value', $code);
        $this->UpdateFormField('WizardURL', 'value', $origin . $this->path());
        return $code;
    }
    private function forgetGuidedSetup(): void { $this->SetBuffer('GuidedSetup', ''); $this->UpdateFormField('SetupAccessCode', 'value', ''); }
    public function CancelGuidedSetup(): void
    {
        $lock = 'SECF.GuidedSetup.' . $this->InstanceID;
        if (!IPS_SemaphoreEnter($lock, 500)) throw new RuntimeException('Setup is busy; cancellation has not completed.');
        try { $this->forgetGuidedSetup(); } finally { IPS_SemaphoreLeave($lock); }
    }
    private function deploymentDefaults(string $origin): array
    {
        try {
            $saved = json_decode($this->ReadAttributeString('DeploymentDraft'), true, 12, JSON_THROW_ON_ERROR);
            if (is_array($saved)) return SecretsFrontendDeployment::validate($saved, $origin);
        } catch (Throwable $ignored) { }
        return SecretsFrontendDeployment::defaults($origin);
    }
    private function discovered(string $module, string $fallback): array
    {
        $out = [];
        foreach (IPS_GetInstanceListByModuleID($module) as $id) if (!IPS_HasChanges($id)) $out[] = ['id' => (int)$id, 'name' => $this->setupName((int)$id, $fallback)];
        return $out;
    }
    private function guidedCheck(array &$grant, array $data): void
    {
        if (!$this->guidedActive() || ($grant['origin'] ?? '') !== $this->settings()['AdminOrigin'] || ($grant['frontendDigest'] ?? '') !== SecretsFrontendCommissioning::digest($this->settings()) || IPS_HasChanges($this->InstanceID)) throw new RuntimeException('Setup authorization expired or settings changed. Start again in the frontend console.');
        if (!is_string($data['code'] ?? null) || !hash_equals($grant['hash'], hash('sha256', $data['code']))) {
            $grant['failed']++; $this->SetBuffer('GuidedSetup', SecretsFrontendConfiguration::encode($grant));
            throw new RuntimeException('Invalid setup authorization.');
        }
    }
    private function guidedSelection(array $grant, array $data): array
    {
        $choice = SecretsFrontendCommissioning::choice($data);
        if (isset($choice['deployment'])) $choice['deployment'] = SecretsFrontendDeployment::validate($choice['deployment'], $grant['origin']);
        $id = $choice['backend'];
        if (!array_key_exists((string)$id, $grant['backends'])) throw new RuntimeException('Backend was not authorized by the console. Repeat discovery.');
        $info = $this->initialBackend($id);
        if (!$info['canConfigure'] || !in_array($info['frontend'], [0, $this->InstanceID], true) || !hash_equals($grant['backends'][(string)$id], $info['digest'])) throw new RuntimeException('Backend changed or is already commissioned. Start again in the console.');
        foreach (['portal' => self::PORTAL, 'documentation' => self::DOCS] as $field => $module) {
            $other = $choice[$field];
            if ($other > 0 && (!IPS_InstanceExists($other) || strtoupper(IPS_GetInstance($other)['ModuleInfo']['ModuleID'] ?? '') !== $module || IPS_HasChanges($other))) throw new RuntimeException('An integration instance changed. Repeat discovery.');
        }
        if ($choice['addPortalLink'] && $choice['portal'] === 0) throw new RuntimeException('Select a Portal or clear the link option.');
        if ($choice['initialize'] && SecretsBackendNativePlatform::capabilities()['missing']) throw new RuntimeException('The supplied PHP is missing native vault functions: ' . implode(', ', SecretsBackendNativePlatform::capabilities()['missing']));
        return array_replace($choice, SecretsBackendNativePlatform::paths($choice['vaultDirectory'], $choice['keyDirectory'], IPS_GetKernelDir(), !($info['nativeInitializationPending'] ?? false)), ['origin' => $grant['origin'], 'backendDigest' => $info['digest']]);
    }
    private function guidedRequest(string $action, array $data): array
    {
        $lock = 'SECF.GuidedSetup.' . $this->InstanceID;
        if (!IPS_SemaphoreEnter($lock, 500)) throw new RuntimeException('Setup is busy.');
        try {
            $grant = json_decode($this->GetBuffer('GuidedSetup'), true) ?? [];
            $this->guidedCheck($grant, $data);
            if ($action === 'guidedCancel') { if (array_keys($data) !== ['code']) throw new RuntimeException('Invalid cancellation.'); $this->forgetGuidedSetup(); return ['cancelled' => true]; }
            if ($action === 'guidedDiscover') {
                if (array_keys($data) !== ['code']) throw new RuntimeException('Invalid discovery request.');
                $backends = [];
                foreach ($grant['backends'] as $id => $digest) {
                    $info = $this->initialBackend((int)$id);
                    if ($info['canConfigure'] && hash_equals($digest, $info['digest'])) $backends[] = ['id' => (int)$id, 'name' => $this->setupName((int)$id, 'SecretsBackend'),
                        'defaults' => ['vaultDirectory' => (!$info['vaultDirectory'] || $info['vaultDirectory'] === '/var/lib/symcon-secrets-development/' . $id . '/vault') ? SecretsFrontendCommissioning::defaults((int)$id)['vaultDirectory'] : $info['vaultDirectory'], 'keyDirectory' => (!$info['keyDirectory'] || $info['keyDirectory'] === '/var/lib/symcon-secrets-development-keys/' . $id) ? SecretsFrontendCommissioning::defaults((int)$id)['keyDirectory'] : $info['keyDirectory']]];
                }
                $portals = $this->discovered(self::PORTAL, 'Portal'); $documentation = $this->discovered(self::DOCS, 'Dokumentation');
                $pick = static function (array $items, int $current): int { $ids = array_column($items, 'id'); return in_array($current, $ids, true) ? $current : (count($ids) === 1 ? $ids[0] : 0); };
                $portal = $pick($portals, $this->ReadPropertyInteger('PortalInstanceID'));
                return ['backends' => $backends, 'portals' => $portals, 'documentation' => $documentation,
                    'origin' => $grant['origin'], 'proxyIPs' => $this->settings()['TrustedHTTPSProxyIPs'], 'theme' => $this->settings()['Theme'],
                    'defaults' => ['backend' => $pick($backends, $this->ReadPropertyInteger('BackendInstanceID')), 'portal' => $portal,
                        'documentation' => $pick($documentation, $this->ReadPropertyInteger('DocumentationInstanceID')), 'theme' => $this->settings()['Theme'],
                        'proxyIPs' => $this->settings()['TrustedHTTPSProxyIPs'], 'debugEnabled' => $this->ReadPropertyBoolean('DebugEnabled'), 'addPortalLink' => $portal > 0,
                        'initialize' => true, 'administratorLabel' => 'Administrator', 'backendEnabled' => false, 'connectionTrust' => 'not-configured', 'hardwareTrust' => 'not-configured'],
                    'requirements' => SecretsFrontendCommissioning::requirements(), 'expires' => $grant['expires']];
            }
            if ($action === 'guidedPreview') {
                if (count($data) !== 2 || !is_array($data['configuration'] ?? null)) throw new RuntimeException('Invalid setup preview.');
                $plan = $this->guidedSelection($grant, $data['configuration']);
                $planId = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
                $grant['plan'] = ['id' => $planId, 'configuration' => $plan]; $this->SetBuffer('GuidedSetup', SecretsFrontendConfiguration::encode($grant));
                return ['planId' => $planId, 'configuration' => $plan, 'writable' => ['vault' => SecretsFrontendCommissioning::writable($plan['vaultDirectory']), 'keys' => SecretsFrontendCommissioning::writable($plan['keyDirectory'])],
                    'deploymentPlan' => isset($plan['deployment']) ? SecretsFrontendDeployment::describe($plan['deployment'], $grant['origin']) : null,
                    'persistence' => SecretsBackendNativePlatform::persistence($plan['vaultDirectory'], $plan['keyDirectory'], IPS_GetKernelDir()),
                    'native' => SecretsBackendNativePlatform::capabilities(), 'quorumConnected' => false, 'message' => $plan['initialize'] ? 'Create a new encrypted native vault at these exact paths, then register the first passkey. Existing vaults are never replaced.' : 'Save settings only; no storage or credentials will be created.'];
            }
            if ($action !== 'guidedApply' || count($data) !== 2 || !is_string($data['planId'] ?? null) || !is_array($grant['plan']) || !hash_equals($grant['plan']['id'], $data['planId'])) throw new RuntimeException('Review the exact setup plan first.');
            $plan = $grant['plan']['configuration'];
            $choice = array_intersect_key($plan, array_flip(['backend', 'portal', 'documentation', 'theme', 'vaultDirectory', 'keyDirectory', 'proxyIPs', 'addPortalLink', 'debugEnabled', 'deployment', 'initialize', 'privateACLConfirmed', 'persistenceConfirmed', 'administratorLabel']));
            $this->guidedSelection($grant, $choice); // Recheck every fixed identity/digest immediately before consumption.
            $this->forgetGuidedSetup(); // Consume before any configuration or integration side effect.
            try {
                SECB_ConfigureInitialSetup($plan['backend'], $this->InstanceID, $plan['backendDigest'], SecretsFrontendConfiguration::encode(['origin' => $plan['origin'], 'vaultDirectory' => $plan['vaultDirectory'], 'keyDirectory' => $plan['keyDirectory'], 'debugEnabled' => $plan['debugEnabled']]));
                if (IPS_HasChanges($this->InstanceID) || !hash_equals($grant['frontendDigest'], SecretsFrontendCommissioning::digest($this->settings()))) throw new RuntimeException('Frontend changed while applying.');
                foreach (['DebugEnabled' => $plan['debugEnabled'], 'BackendInstanceID' => $plan['backend'], 'PortalInstanceID' => $plan['portal'], 'DocumentationInstanceID' => $plan['documentation'], 'Theme' => $plan['theme'], 'TrustedHTTPSProxyIPs' => SecretsFrontendConfiguration::encode($plan['proxyIPs'])] as $key => $value) IPS_SetProperty($this->InstanceID, $key, $value);
                IPS_ApplyChanges($this->InstanceID);
                if (!$this->Refresh()) throw new RuntimeException('Frontend settings were saved but its hook needs inspection.');
                if ($plan['addPortalLink']) $this->AddToPortal();
            } catch (Throwable $exception) {
                // No rollback/replay of uncertain applies. Quorum mode blocks every vault route.
                $this->SetValue('Status', 'Setup incomplete. Inspect the applied settings and start a fresh console authorization. No vault was activated.');
                throw new RuntimeException('Setup could not finish. Settings may be partly applied; no vault was activated. Review the instances and issue a fresh setup code.');
            }
            if (isset($plan['deployment'])) $this->WriteAttributeString('DeploymentDraft', SecretsFrontendConfiguration::encode($plan['deployment']));
            $native = null;
            if ($plan['initialize']) {
                if (!function_exists('SECB_InitializeNativeStorage')) throw new RuntimeException('Update the separate backend module to the native implementation first.');
                $info = $this->initialBackend($plan['backend']);
                $native = json_decode(SECB_InitializeNativeStorage($plan['backend'], $this->InstanceID, $info['digest'], $plan['privateACLConfirmed'], $plan['persistenceConfirmed'], $plan['administratorLabel']), true, 16, JSON_THROW_ON_ERROR);
            }
            $this->WriteAttributeBoolean('GuidedConfigured', true);
            return ['configured' => true, 'quorumConnected' => false, 'vaultCreated' => $native !== null, 'native' => $native, 'portalRegistered' => $plan['addPortalLink'],
                'message' => $native['message'] ?? 'Settings saved. Use the native initialization option to create the encrypted vault.',
                'configurationExport' => ['deployment' => isset($plan['deployment']) ? SecretsFrontendDeployment::describe($plan['deployment'], $grant['origin']) : null, 'frontend' => json_decode($this->ExportConfiguration(), true, 16, JSON_THROW_ON_ERROR), 'backend' => json_decode(SECB_ExportConfiguration($plan['backend']), true, 16, JSON_THROW_ON_ERROR)]];
        } finally { IPS_SemaphoreLeave($lock); }
    }
    public function BeginAdministratorEnrollment(string $Label, bool $Hardware): string
    {
        if (!function_exists('SECB_GetNativeInfo') || !function_exists('SECB_BeginAdminEnrollment')) throw new RuntimeException('Update the native backend first.');
        $id = $this->backend(); $info = json_decode(SECB_GetNativeInfo($id), true);
        if (!($info['nativeMode'] ?? false) || !($info['initialized'] ?? false)) throw new RuntimeException('Initialize the native vault in the HTML wizard first.');
        $code = SECB_BeginAdminEnrollment($id, $Label, $Hardware);
        $this->UpdateFormField('AdministratorEnrollmentCode', 'value', $code); return $code;
    }
    private function gateway(array $request): array
    {
        if (in_array($request['action'], ['guidedDiscover', 'guidedPreview', 'guidedApply', 'guidedCancel'], true)) {
            try { return ['status' => 200, 'data' => $this->guidedRequest($request['action'], $request['data']), 'cookie' => '']; }
            catch (Throwable $exception) { return ['status' => 403, 'data' => ['error' => $exception->getMessage()], 'cookie' => '']; }
        }
        if ($this->ReadAttributeBoolean('GuidedV2Only')) {
            $id = $this->ReadPropertyInteger('BackendInstanceID'); $native = null;
            if ($id > 0 && function_exists('SECB_GetNativeInfo')) { try { $native = json_decode(SECB_GetNativeInfo($this->backend()), true); } catch (Throwable $ignored) {} }
            if (($native['nativeMode'] ?? false) && ($native['initialized'] ?? false) && function_exists('SECB_HandleFrontendRequest')) return json_decode(SECB_HandleFrontendRequest($id, $this->InstanceID, SecretsFrontendConfiguration::encode($request)), true, 96, JSON_THROW_ON_ERROR);
            return ['status' => $request['action'] === 'status' ? 200 : 503,
                'data' => $request['action'] === 'status' ? ['ready' => false, 'configured' => $this->ReadAttributeBoolean('GuidedConfigured'), 'guidedV2Only' => true, 'nativeBackendImplemented' => true, 'setupAvailable' => $this->guidedActive(), 'message' => 'Initialize the native encrypted vault in the HTML setup wizard.'] : ['error' => 'Native vault not initialized. Open the setup assistant; V1 fallback is disabled.'], 'cookie' => ''];
        }
        if (!function_exists('SECB_HandleFrontendRequest')) throw new RuntimeException('The separate backend API is not installed.');
        return json_decode(SECB_HandleFrontendRequest($this->backend(), $this->InstanceID, SecretsFrontendConfiguration::encode($request)), true, 32, JSON_THROW_ON_ERROR);
    }
}
