<?php
declare(strict_types=1);
require_once __DIR__ . '/Http.php';
require_once __DIR__ . '/GuidedSetup.php';
require_once __DIR__ . '/../libs/SystemPortalNavigation.php';

class SecretsFrontend extends IPSModule
{
    use SecretsFrontendGuidedSetup;
    private const BACKEND = '{52165EDD-B2C0-40EC-8A59-42A97319B6E2}';
    private const PORTAL = '{922E5A10-A048-463D-A973-97B4BBD9096B}';
    private const DOCS = '{FBEB2EF6-8D23-49D7-A256-6D0C8D973B24}';
    private const HOOKS = '{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}';
    public function Create(): void
    {
        parent::Create();
        $this->RegisterAttributeBoolean('GuidedV2Only', true);
        $this->RegisterAttributeString('BootstrapIdentity', SecretsBackendCodec::uuid());
        $this->RegisterAttributeBoolean('BootstrapJournalConfirmed', false);
        $this->RegisterAttributeBoolean('GuidedConfigured', false);
        $this->RegisterAttributeString('DeploymentDraft', '');
        foreach (SecretsFrontendConfiguration::DEFAULTS as $key => $default) {
            if (is_bool($default)) $this->RegisterPropertyBoolean($key, $default);
            elseif (is_int($default)) $this->RegisterPropertyInteger($key, $default);
            else $this->RegisterPropertyString($key, is_array($default) ? '[]' : $default);
        }
        $this->RegisterVariableBoolean('DebugEnabled', 'Debug logging', '~Switch', 0); $this->EnableAction('DebugEnabled');
        $this->RegisterVariableString('FrontendURL', 'Frontend URL', '', 10);
        $this->RegisterVariableString('Status', 'Frontend status', '', 20);
        $this->RegisterVariableString('IntegrationStatus', 'Portal / documentation / backup', '~TextBox', 30);
        $this->RegisterVariableString('Debug', 'Debug', '~TextBox', 50);
        $this->RegisterVariableString('BackendAvailability', 'Backend availability', '~TextBox', 35);
        $this->RegisterVariableBoolean('BackendError', 'Backend error', '~Alert', 36);
        $this->RegisterVariableBoolean('FrontendError', 'Frontend error', '~Alert', 37);
        $this->SetValue('BackendError', true);
        $this->SetValue('FrontendError', true);
        $this->RegisterTimer('BackendAvailability', 0, 'SECF_CheckBackendAvailability($_IPS[\'TARGET\']);');
        $this->RegisterTimer('BootstrapRecovery', 0, 'SECF_RecoverBootstrap($_IPS[\'TARGET\']);');
        $this->RegisterTimer('Setup', 0, 'SECF_Refresh($_IPS[\'TARGET\']);'); $this->RegisterMessage(0, 10103);
    }
    public function ApplyChanges(): void
    {
        parent::ApplyChanges();
        $this->SetValue('BackendError', true);
        $this->SetValue('FrontendError', true);
        $this->SetTimerInterval('BackendAvailability', $this->ReadPropertyBoolean('Enabled') ? 30000 : 0);
        $this->forgetGuidedSetup();
        $this->SetTimerInterval('BootstrapRecovery', 1000);
        $this->SetValue('DebugEnabled', $this->ReadPropertyBoolean('DebugEnabled'));
        $this->SetTimerInterval('Setup', IPS_GetKernelRunlevel() === 10103 ? 100 : 0);
        if (!$this->ReadPropertyBoolean('Enabled')) $this->SetStatus(104);
    }
    public function MessageSink($TimeStamp, $SenderID, $Message, $Data): void
    {
        if ((int)$SenderID === 0 && (int)$Message === 10103) { $this->forgetGuidedSetup(); $this->SetTimerInterval('Setup', 100); $this->SetTimerInterval('BootstrapRecovery', 1000); }
    }
    /** Independent observer: can report a stopped or unloaded backend watchdog. */
    public function CheckBackendAvailability(): string
    {
        $out = ['ready'=>false, 'state'=>'UNAVAILABLE', 'checkedAt'=>time()];
        try {
            if (!$this->ReadPropertyBoolean('Enabled')) $out['state']='DISABLED';
            else {
                $id=$this->ReadPropertyInteger('BackendInstanceID');
                if (!IPS_InstanceExists($id) || !function_exists('SECB_GetAvailability')) $out['state']='BACKEND_API_UNAVAILABLE';
                else {
                    $out=json_decode(SECB_GetAvailability($id),true,16,JSON_THROW_ON_ERROR);
                    if (!is_array($out) || !isset($out['state'],$out['ready'])) throw new RuntimeException('Invalid health response.');
                    if ($out['stale']??true) { $out['state']='HEARTBEAT_STALE'; $out['ready']=false; }
                    elseif ((int)IPS_GetInstance($id)['InstanceStatus'] !== 102) { $out['state']='BACKEND_NOT_READY'; $out['ready']=false; }
                    elseif (!$out['ready'] && $out['state']==='READY') $out['state']='NOT_READY';
                }
            }
        } catch (Throwable $e) { $out=['ready'=>false,'state'=>'BACKEND_CHECK_FAILED','checkedAt'=>time()]; }
        $json=json_encode($out,JSON_THROW_ON_ERROR);
        $before=$this->GetBuffer('BackendAvailabilityState');
        if ($before!==$out['state'] && function_exists('IPS_LogMessage'))
            IPS_LogMessage('SecretsFrontend '.$this->InstanceID,'Backend availability: '.$out['state']);
        $this->SetBuffer('BackendAvailabilityState',$out['state']);
        $this->SetValue('BackendAvailability',$json);
        $this->SetValue('BackendError', !($out['ready'] ?? false));
        $this->updateFrontendError();
        return $json;
    }
    /** Local module readiness; external HTTPS reachability requires a remote observer. */
    private function updateFrontendError(): void
    {
        $this->SetValue('FrontendError', !$this->ReadPropertyBoolean('Enabled')
            || IPS_GetKernelRunlevel() !== 10103
            || IPS_HasChanges($this->InstanceID)
            || (int)IPS_GetInstance($this->InstanceID)['InstanceStatus'] !== 102);
    }
    private function settings(): array
    {
        $settings = [];
        foreach (SecretsFrontendConfiguration::DEFAULTS as $key => $default) {
            $settings[$key] = is_bool($default) ? $this->ReadPropertyBoolean($key) : (is_int($default) ? $this->ReadPropertyInteger($key) : $this->ReadPropertyString($key));
            if (is_array($default)) $settings[$key] = json_decode($settings[$key], true, 12, JSON_THROW_ON_ERROR);
        }
        return SecretsFrontendConfiguration::validate($settings);
    }
    private function path(): string { return '/hook/secrets_frontend_' . $this->InstanceID; }
    /** Applied HTTPS origin and this actual instance ID; no code or session in the URL. */
    public function GetWizardURL(): string
    {
        $origin = SecretsFrontendConfiguration::origin($this->ReadPropertyString('AdminOrigin'));
        if ($origin === '') throw new RuntimeException('Start HTML setup with the trusted Symcon HTTPS address first.');
        return $origin . $this->path();
    }
    /** Form-only preview: combine the entered address with this instance's own ID. */
    public function GetSetupWizardURL(string $Address): string
    {
        return SecretsFrontendCommissioning::address($Address) . $this->path();
    }
    private const SETUP_ADDRESS_HELP='Include https:// at the start and the public port if required, for example https://secrets.example.com:46910. You can paste the full Symcon console address.';
    private function setupAddressPreview(string $address): array
    {
        try{return ['url'=>$this->GetSetupWizardURL($address),'message'=>'Address ready. Select Step 1: Open setup.'];}
        catch(Throwable $error){return ['url'=>'','message'=>self::SETUP_ADDRESS_HELP];}
    }
    public function PreviewWizardURL(string $Address): void
    {
        $preview=$this->setupAddressPreview($Address);
        $this->UpdateFormField('WizardURL','value',$preview['url']);
        $this->UpdateFormField('OpenBootstrap','enabled',$preview['url']!=='');
        $this->UpdateFormField('SetupAddressStatus','caption',$preview['message']);
    }
    /** Console boundary: output is either a validated URL or a plain dialog message. */
    public function OpenBootstrapFromConsole(string $Address='',bool $JournalStorageConfirmed=false,bool $Recovery=false): string
    {
        $address=trim($Address)!==''?$Address:$this->ReadPropertyString('AdminOrigin');
        $preview=$this->setupAddressPreview($address);
        if($preview['url']===''){
            $this->PreviewWizardURL($address);
            return 'Step 1: Correct the trusted Symcon address. Include the HTTPS prefix and any required public port. See the example below the address field.';
        }
        try{
            $url=$this->OpenBootstrap($address,'',$Recovery,$JournalStorageConfirmed);
            $this->UpdateFormField('WizardURL','value',$url);
            $this->UpdateFormField('SetupAddressStatus','caption','Setup opened. Continue in the browser.');
            return $url;
        }catch(Throwable $error){
            $this->UpdateFormField('SetupAddressStatus','caption','Setup could not be opened: '.$error->getMessage());
            // No URL-like content here: automatic button dispatch must show a dialog.
            return 'Setup could not be opened. Review the message below the trusted address, correct the problem and try again.';
        }
    }
    private function updateWizardLinks(): void
    {
        $url = $this->GetWizardURL();
        $this->SetValue('FrontendURL', $url);
        $this->UpdateFormField('WizardURL', 'value', $url);
    }
    private function backend(): int
    {
        $id = $this->ReadPropertyInteger('BackendInstanceID');
        if ($id <= 0 || !IPS_InstanceExists($id) || strtoupper(IPS_GetInstance($id)['ModuleInfo']['ModuleID'] ?? '') !== self::BACKEND
            || IPS_GetProperty($id, 'FrontendInstanceID') !== $this->InstanceID || SecretsFrontendConfiguration::origin((string)IPS_GetProperty($id, 'AdminOrigin')) !== $this->settings()['AdminOrigin']) throw new RuntimeException('Select the separate SecretsBackend and configure its matching frontend and HTTPS origin.');
        return $id;
    }
    public function Refresh(): bool
    {
        $this->SetTimerInterval('Setup', 0);
        try {
            $settings = $this->settings();
            if ($settings['Enabled'] && $settings['AdminOrigin'] === '') throw new RuntimeException('Configure an exact administrator HTTPS origin.');
            if ($settings['Enabled'] && !$this->guidedActive() && !$this->ReadAttributeBoolean('GuidedV2Only')) $this->backend();
            $this->syncHook($settings['Enabled']);
            if ($settings['AdminOrigin'] !== '') $this->updateWizardLinks();
            $this->SetValue('Status', !$settings['Enabled'] ? 'Disabled.' : ($this->ReadAttributeBoolean('GuidedV2Only') ? 'Native HTML setup and administration available; the backend checks every operation.' : 'Development frontend available. Backend authorizes every administrative operation.'));
            $this->SetValue('IntegrationStatus', 'Portal: use Add to Portal below. Documentation: bundled manual and catalog entry. Central backup: registration review required; exports contain configuration only.');
            $this->SetStatus($settings['Enabled'] ? 102 : 104); $this->updateFrontendError(); $this->debug('configuration-checked'); return true;
        } catch (Throwable $exception) {
            // An invalid configuration must remove only this instance's old hook.
            try { $this->syncHook(false); } catch (Throwable $ignored) { }
            $this->SetStatus(200); $this->SetValue('FrontendError', true); $this->SetValue('Status', $exception->getMessage()); $this->debug('configuration-refused'); return false;
        }
    }
    private function syncHook(bool $enabled): void
    {
        if (!IPS_SemaphoreEnter('SECF.WebhookControl', 1000)) throw new RuntimeException('Webhook registry is busy.');
        try {
            $ids = IPS_GetInstanceListByModuleID(self::HOOKS);
            if (count($ids) !== 1 || IPS_HasChanges((int)$ids[0])) throw new RuntimeException('Use one WebhookControl without unapplied edits.');
            $id = (int)$ids[0]; $hooks = json_decode(IPS_GetProperty($id, 'Hooks'), true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($hooks) || array_values($hooks) !== $hooks || count($hooks) > 2048) throw new RuntimeException('Invalid webhook registry.');
            $next = []; $found = false;
            foreach ($hooks as $hook) {
                if (($hook['Hook'] ?? '') === $this->path()) {
                    if ((int)($hook['TargetID'] ?? 0) !== $this->InstanceID) throw new RuntimeException('Webhook path belongs to a different object.');
                    if (!$enabled || $found) continue; $found = true;
                }
                $next[] = $hook;
            }
            if ($enabled && !$found) $next[] = ['Hook' => $this->path(), 'TargetID' => $this->InstanceID];
            if ($hooks !== $next) { IPS_SetProperty($id, 'Hooks', SecretsFrontendConfiguration::encode($next)); IPS_ApplyChanges($id); }
        } finally { IPS_SemaphoreLeave('SECF.WebhookControl'); }
    }
    public function AddToPortal(): bool
    {
        $portal = $this->ReadPropertyInteger('PortalInstanceID');
        if ($portal <= 0 || !IPS_InstanceExists($portal) || strtoupper(IPS_GetInstance($portal)['ModuleInfo']['ModuleID'] ?? '') !== self::PORTAL) throw new RuntimeException('Select the existing Portal instance.');
        if (!$this->ReadPropertyBoolean('Enabled') || !$this->Refresh()) throw new RuntimeException('Enable and validate the frontend first.');
        if (!IPS_SemaphoreEnter('SECF.Portal.' . $portal, 1000)) throw new RuntimeException('Portal registration is busy.');
        try {
            if (IPS_HasChanges($portal)) throw new RuntimeException('Apply or discard pending Portal edits before registration.');
            $rows = json_decode(IPS_GetProperty($portal, 'AdditionalPages'), true, 16, JSON_THROW_ON_ERROR);
            if (!is_array($rows) || array_values($rows) !== $rows || count($rows) >= 100) throw new RuntimeException('Invalid or full Portal additional-pages list.');
            foreach ($rows as $row) if (($row['Hook'] ?? '') === $this->path()) {
                if (($row['TargetID'] ?? 0) !== $this->InstanceID) throw new RuntimeException('Conflicting Portal registration.');
                return true;
            }
            $rows[] = ['Name' => 'Secrets administration', 'Description' => 'Separate development vault, passkeys and hardware approvals.', 'Cluster' => 'admin', 'Hook' => $this->path(), 'TargetID' => $this->InstanceID];
            IPS_SetProperty($portal, 'AdditionalPages', SecretsFrontendConfiguration::encode($rows)); IPS_ApplyChanges($portal);
            $this->debug('portal-registered'); return true;
        } finally { IPS_SemaphoreLeave('SECF.Portal.' . $portal); }
    }
    public function GetPortalRegistration(): string
    {
        return SecretsFrontendConfiguration::encode(['Name' => 'Secrets administration', 'Description' => 'Separate development vault, passkeys and hardware approvals.', 'Cluster' => 'admin', 'Hook' => $this->path(), 'TargetID' => $this->InstanceID]);
    }
    private function documentationPath(): string
    {
        $id = $this->ReadPropertyInteger('DocumentationInstanceID');
        return $id > 0 && IPS_InstanceExists($id) && strtoupper(IPS_GetInstance($id)['ModuleInfo']['ModuleID'] ?? '') === self::DOCS && IPS_GetProperty($id, 'Enabled') === true ? '/hook/alarm_documentation_' . $id : '';
    }
    // Symcon generates an untyped HookInstance override; keep this entry point untyped.
    public function ProcessHookData()
    {
        try {
            $settings = $this->settings(); $input = '';
            if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
                $stream = fopen('php://input', 'rb'); $input = $stream === false ? '' : stream_get_contents($stream, 65537); if (is_resource($stream)) fclose($stream);
                if (!is_string($input) || strlen($input) > 65536) { http_response_code(413); header('Cache-Control: no-store'); echo 'Request too large.'; return; }
            }
            $caller=(int)($GLOBALS['_IPS']['INSTANCE']??0);$callerModule='not supplied';
            if($caller>0&&IPS_InstanceExists($caller))$callerModule=(string)(IPS_GetInstance($caller)['ModuleInfo']['ModuleID']??'not supplied');
            $native=$this->bootstrapNative();$backup=$native['backupOrigin']??null;$setup=$this->bootstrapState();$recoveryUI=false;
            if(in_array($_SERVER['REQUEST_METHOD']??'', ['GET','HEAD'],true)&&($setup['mode']??'')==='recovery'&&($setup['expires']??0)>=time()&&($setup['runtime']??'')===$this->BootstrapRuntime()){try{$journal=$this->bootstrapJournal();$recoveryUI=$journal->locked(fn()=>$journal->read('decision-'.hash('sha256',$setup['intent']))===null);}catch(Throwable $ignored){}}
            $connect=is_array($backup)&&in_array($backup['status']??'', ['pending','active'],true)?SecretsFrontendConnectDiscovery::local():[];
            $portal = AFSystemPortalNavigationV1::path(0, $settings['PortalInstanceID']);
            $reply = SecretsFrontendHttp::response($settings, $this->InstanceID, $_SERVER, $this->path(), $portal, $this->documentationPath(), $input, function (array $request): array {
                return $this->gateway($request);
            }, ['vaultInitialized'=>($native['initialized']??false)===true,'setupMode'=>$recoveryUI?'recovery':'initial','guidedV2Only' => $this->ReadAttributeBoolean('GuidedV2Only'), 'backupOrigin'=>$backup,'connectDiscovery'=>$connect,'transportDiagnostic'=>['instance'=>$caller,'module'=>$callerModule]]);
            http_response_code($reply['status']); foreach ($reply['headers'] as $name => $value) header($name . ': ' . $value); echo $reply['body'];
        } catch (Throwable $exception) { http_response_code(503); header('Cache-Control: no-store'); echo 'Frontend configuration is unavailable.'; $this->debug('request-refused'); }
    }
    public function ExportConfiguration(): string
    {
        $raw = $this->ReadAttributeString('DeploymentDraft');
        $draft = $raw === '' ? null : json_decode($raw, true, 12, JSON_THROW_ON_ERROR);
        if ($draft !== null && !is_array($draft)) throw new RuntimeException('Invalid deployment draft.');
        $json = SecretsFrontendConfiguration::export($this->settings(), $draft); $this->UpdateFormField('ExportJSON', 'value', $json); return $json;
    }
    public function ImportConfiguration(string $JSON): bool
    {
        if (IPS_HasChanges($this->InstanceID)) throw new RuntimeException('Apply or discard pending console edits before import.');
        $settings = SecretsFrontendConfiguration::import($JSON);
        $this->WriteAttributeBoolean('GuidedConfigured', false);
        $data = SecretsFrontendConfiguration::decode($JSON);
        if (($data['schema'] ?? '') === 'SECF.Config.v2') $this->WriteAttributeBoolean('GuidedV2Only', true);
        $this->WriteAttributeString('DeploymentDraft', ($data['schema'] ?? '') === 'SECF.Config.v2' ? SecretsFrontendConfiguration::encode(SecretsFrontendDeployment::validate($data['deploymentDraft'], $settings['AdminOrigin'])) : '');
        foreach ($settings as $key => $value) IPS_SetProperty($this->InstanceID, $key, is_array($value) ? SecretsFrontendConfiguration::encode($value) : $value);
        IPS_ApplyChanges($this->InstanceID); $this->debug('configuration-imported-disabled'); return true;
    }
    public function RequestAction($Ident, $Value): void
    {
        if ($Ident !== 'DebugEnabled' || !is_bool($Value) || IPS_HasChanges($this->InstanceID)) throw new InvalidArgumentException('Unsupported action or pending settings.');
        IPS_SetProperty($this->InstanceID, 'DebugEnabled', $Value); IPS_ApplyChanges($this->InstanceID);
    }
    public function ClearDebug(): void { $this->SetValue('Debug', ''); }
    private function debug(string $code): void
    {
        if (!$this->ReadPropertyBoolean('DebugEnabled') || !in_array($code, ['configuration-checked', 'configuration-refused', 'portal-registered', 'request-refused', 'configuration-imported-disabled'], true)) return;
        $lines = array_filter(explode("\n", (string)$this->GetValue('Debug'))); $lines[] = gmdate('Y-m-d H:i:s') . ' UTC | ' . $code;
        $this->SetValue('Debug', implode("\n", array_slice($lines, -50)));
    }
    public function ApproveMagicFullAccess(string $Digest): void
    {
        if(IPS_HasChanges($this->InstanceID))throw new RuntimeException('Apply pending settings first.');
        if(!SECB_ApproveConnectUpgradeFromConsole($this->backend(),$this->InstanceID,$Digest))throw new RuntimeException('Magic access could not be upgraded.');
        $this->SetValue('Status','Full Magic access approved. Sign in again at the Magic address.');$this->ReloadForm();
    }
    public function RefreshBootstrapForm(): void { $this->ReloadForm(); }
    public function GetConfigurationForm(): string
    {
        $form=json_decode((string)file_get_contents(__DIR__.'/form.json'),true,32,JSON_THROW_ON_ERROR);
        $origin=$this->ReadPropertyString('AdminOrigin');$preview=$this->setupAddressPreview($origin);$url=$preview['url'];
        $requirements=$this->bootstrapStorageRequirements();
        $recoveryAvailable=($this->bootstrapNative()['initialized']??false)===true;
        foreach($form['actions']as&$element){
            if(($element['name']??'')==='OpenRecoveryBootstrap')$element['enabled']=$recoveryAvailable;
            if(($element['name']??'')==='RecoveryAvailability')$element['visible']=!$recoveryAvailable;
            if(($element['name']??'')==='BootstrapJournalStorage'){$element['visible']=$requirements['confirmationRequired']&&!$this->ReadAttributeBoolean('BootstrapJournalConfirmed');$element['value']=$this->ReadAttributeBoolean('BootstrapJournalConfirmed');$element['caption']='I verified private access and persistence across container replacement for setup records: '.$requirements['data'].' and keys: '.$requirements['keys'];}
            if(($element['name']??'')==='SetupAddress'){$element['value']=$origin;$element['visible']=true;}
            if(($element['name']??'')==='OpenBootstrap')$element['enabled']=$url!=='';
            if(($element['name']??'')==='SetupAddressStatus')$element['caption']=$preview['message'];
            if(($element['name']??'')==='WizardURL')$element['value']=$url;
        }unset($element);
        try{$magic=json_decode(SECB_GetConnectUpgradeReview($this->backend(),$this->InstanceID),true,32,JSON_THROW_ON_ERROR);$review=$magic['review'];
            $form['actions'][]=['type'=>'ExpansionPanel','caption'=>'Magic URL · approve full access','items'=>[
                ['type'=>'Label','caption'=>'Grant read, write, export and full administration at '.$review['origin'].'. Only the tested credentials listed below are upgraded. Existing Magic sessions expire.'],
                ['type'=>'Label','caption'=>SecretsFrontendConfiguration::encode($review['credentials'])],
                ['type'=>'Label','caption'=>'Hardware policy is enforced. Approve this upgrade at the primary address with an eligible hardware key.','visible'=>!$magic['consoleApprovalAllowed']],
                ['type'=>'Button','caption'=>'Approve full Magic access','enabled'=>$magic['consoleApprovalAllowed'],'confirm'=>'Approve full administration for exactly these tested Magic credentials?','onClick'=>'SECF_ApproveMagicFullAccess($id, '.var_export($magic['digest'],true).');']
            ]];
        }catch(Throwable $ignored){}
        $route=$this->bootstrapNative()['backupOrigin']??null;
        if(($route['version']??0)===2&&($route['status']??'')==='active'){
            $form['actions'][]=['type'=>'ExpansionPanel','caption'=>'Magic URL','items'=>[
                ['type'=>'ValidationTextBox','caption'=>'Full administration address','value'=>$route['origin'].$this->path(),'enabled'=>false],
                ['type'=>'Button','caption'=>'Open Magic URL','onClick'=>'echo SECF_OpenBootstrapFromConsole($id, '.var_export($route['origin'],true).', false, false);'],
                ['type'=>'Button','caption'=>'Recover administrator access using Magic','onClick'=>'echo SECF_OpenBootstrapFromConsole($id, '.var_export($route['origin'],true).', false, true);']
            ]];
        }
        $approvals=[];
        try{$views=json_decode($this->GetBootstrapConsoleView(),true);foreach($views as$v){
            $literal=static fn(string $text)=>var_export($text,true);
            $payload='SECF_ApproveBootstrapCandidate($id, '.$literal($v['candidate']).', '.$literal($v['digest']).', '.$literal($v['proof']).');';
            $approvals[]=['type'=>'Button','caption'=>'Step 3: Approve '.$v['comparison'],'confirm'=>'Compare all four groups with the browser: '.$v['comparison'].' · '.$v['purpose'].' · frontend '.$v['frontend'].' · '.$v['origin'].'. Approve exactly this request?','onClick'=>$payload];
            $approvals[]=['type'=>'Button','caption'=>'Reject '.$v['comparison'],'onClick'=>'SECF_RejectBootstrapCandidate($id, '.$literal($v['candidate']).', '.$literal($v['digest']).');'];
        }}catch(Throwable $ignored){}
        foreach($form['actions']as$index=>$element){
            if(($element['name']??'')==='RefreshCandidates'){array_splice($form['actions'],$index+1,0,$approvals);break;}
        }
        try{$j=$this->bootstrapJournal();$j->locked(function()use($j,&$form):void{foreach($j->decisions()as$d){
            if($d['status']!=='ACCEPTED'||$d['frontend']!==$this->InstanceID||$d['plan']['backend']!==0||$j->read('creating-'.$d['operation'])===null||$j->read('created-'.$d['operation'])!==null)continue;
            $field='ResolveBackend'.str_replace('-','',$d['operation']);
            $form['actions'][]=['type'=>'ExpansionPanel','caption'=>'Resolve uncertain backend creation','items'=>[
                ['type'=>'Label','caption'=>'Operation '.$d['operation'].' · vault '.$d['plan']['vault'].'. Inspect the exact newly created disabled empty backend before selecting it.'],
                ['type'=>'SelectInstance','name'=>$field,'caption'=>'Inspected new backend','validModules'=>[self::BACKEND]],
                ['type'=>'Button','caption'=>'Bind this backend and resume the accepted setup','confirm'=>'Bind this inspected empty backend to operation '.$d['operation'].'?','onClick'=>'SECF_ResolveBootstrapBackend($id, '.var_export($d['operation'],true).', $'.$field.'); SECF_RecoverBootstrap($id);']
            ]];
        }});}catch(Throwable $ignored){}
        return SecretsFrontendConfiguration::encode($form);
    }
}
