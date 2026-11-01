<?php
declare(strict_types=1);
require_once __DIR__ . '/NativeStore.php';
require_once __DIR__ . '/NativeOperations.php';
require_once __DIR__ . '/BootstrapJournal.php';

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
                if(($state['native']['genesisFormat']??'')!=='SECF.Genesis.1'||!$state['identity']['credentials'])throw new RuntimeException('Legacy or incomplete native genesis requires explicit recovery.');
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
    /** The former empty-vault initializer is closed, including cached local callers. */
    public function InitializeNativeStorage(int $FrontendInstanceID, string $ExpectedDigest, bool $PrivateACLConfirmed, bool $PersistenceConfirmed, string $AdministratorLabel): string
    {
        throw new RuntimeException('Manual-code initialization has been removed. Open the console-approved passkey setup.');
    }
    /** Read the durable authorization ourselves; never trust a browser admission object. */
    public function CompleteBootstrap(int $FrontendInstanceID,string $Intent,string $Runtime,string $Worker): bool
    {
        $journal=SecretsBootstrapJournal::forKernel(IPS_GetKernelDir());
        return $journal->locked(function()use($journal,$FrontendInstanceID,$Intent,$Runtime,$Worker):bool{
            $d=$journal->read('decision-'.hash('sha256',$Intent));
            if(!$d||$d['status']!=='ACCEPTED'||$d['frontend']!==$FrontendInstanceID)throw new RuntimeException('No accepted bootstrap operation.');
            $plan=$d['plan'];$created=$journal->read('created-'.$d['operation']);$target=$plan['backend']?:($created['backend']??0);
            if($target!==$this->InstanceID||$plan['frontendInstance']!==$FrontendInstanceID||SecretsBootstrapVerifier::digest($plan)!==$d['planDigest'])throw new RuntimeException('Accepted backend/plan binding failed.');
            $check=function()use($journal,$d,$Runtime,$Worker,$FrontendInstanceID):void{
                $journal->checkFence($d['operation'],$Runtime,$Worker);
                if(!function_exists('SECF_BootstrapRuntime')||SECF_BootstrapRuntime($FrontendInstanceID)!==$Runtime)throw new RuntimeException('The setup worker runtime changed.');
            };$check();
            if(!$this->nativeInitialized()){
                $info=json_decode($this->GetInitialSetupInfo(),true);
                $expected=['origin'=>$plan['origin'],'vaultDirectory'=>$plan['vaultDirectory'],'keyDirectory'=>$plan['keyDirectory'],'debugEnabled'=>$plan['debugEnabled']];
                if($this->ReadAttributeString('NativeInitPlan')===''){
                    if($plan['backend']>0&&$info['digest']!==$plan['backendDigest'])throw new RuntimeException('Accepted backend configuration changed.');
                    $this->ConfigureInitialSetup($FrontendInstanceID,$info['digest'],SecretsBackendCodec::json($expected));
                }
                if($this->ReadPropertyInteger('FrontendInstanceID')!==$FrontendInstanceID||$this->ReadPropertyString('AdminOrigin')!==$plan['origin']||$this->ReadPropertyString('DataDirectory')!==$plan['vaultDirectory']||$this->ReadPropertyString('KeyDirectory')!==$plan['keyDirectory'])throw new RuntimeException('Accepted native settings changed.');
                $lock='SECB.Runtime.'.$this->InstanceID;if(!IPS_SemaphoreEnter($lock,1000))throw new RuntimeException('Native initialization is busy.');
                try{
                    $check();$binding=['origin'=>$plan['origin'],'frontend'=>$FrontendInstanceID,'backend'=>$this->InstanceID,'privateACLConfirmed'=>$plan['privateACLConfirmed']];
                    $admission=['format'=>'SECF.Genesis.1','operation'=>$d['operation'],'vault'=>$plan['vault'],'candidateDigest'=>$d['candidateDigest'],'planDigest'=>$d['planDigest'],'binding'=>$binding,
                        'registration'=>$d['registration'],'registrationContext'=>$d['registrationContext'],'assertion'=>$d['assertion'],'challenge'=>$d['challenge']];
                    $resume=$this->ReadAttributeString('NativeInitPlan')!=='';
                    if($resume&&$this->ReadAttributeString('NativeInitPlan')!==SecretsBootstrapVerifier::digest($admission))throw new RuntimeException('Interrupted initialization has a different admission.');
                    $profile=$this->nativeProfile();$savedProfile=$journal->read('profile-'.$d['operation']);
                    if($savedProfile!==null&&SecretsBootstrapVerifier::digest($savedProfile)!==SecretsBootstrapVerifier::digest($profile))throw new RuntimeException('Accepted native security foundation changed during recovery.');
                    $journal->write('profile-'.$d['operation'],$profile);
                    $this->WriteAttributeString('NativeInitPlan',SecretsBootstrapVerifier::digest($admission));$this->WriteAttributeString('NativeInitUUID',$plan['vault']);
                    $paths=SecretsBackendNativePlatform::paths($plan['vaultDirectory'],$plan['keyDirectory'],IPS_GetKernelDir());
                    $check();$id=SecretsBackendNativeStore::initialize($paths['vaultDirectory'],$paths['keyDirectory'],$binding,$profile,$plan['vault'],$admission,$resume,static function(string $point)use($check):void{if($point==='before_marker')$check();});
                    $check();$this->WriteAttributeString('StorageBinding',SecretsBackendCodec::json(['kind'=>'native','backend'=>$this->InstanceID,'uuid'=>$plan['vault'],'paths'=>['vault'=>$paths['vaultDirectory'],'keys'=>$paths['keyDirectory']]]));
                    $this->WriteAttributeString('NativeVaultUUID',$id['deploymentId']);IPS_SetProperty($this->InstanceID,'Enabled',true);
                }finally{IPS_SemaphoreLeave($lock);}
                IPS_ApplyChanges($this->InstanceID);
            }
            $check();try{$this->nativeApplication();}catch(Throwable $e){if(!$this->Recover())throw new RuntimeException('The accepted native vault needs recovery.');}
            $state=$this->nativeStore()->read()['state'];
            if(($state['native']['initializationOperation']??'')!==$d['operation']||($state['native']['candidateDigest']??'')!==$d['candidateDigest']||($state['native']['vaultId']??'')!==$plan['vault'])throw new RuntimeException('Committed genesis differs from the accepted operation.');
            return true;
        });
    }
    /** Privileged console snapshot; a policy change invalidates recovery at identity commit. */
    public function GetBootstrapRecoveryInfo(int $FrontendInstanceID): string
    {
        if($FrontendInstanceID!==$this->ReadPropertyInteger('FrontendInstanceID'))throw new RuntimeException('Wrong recovery frontend.');
        $store=$this->nativeStore();$current=$store->read();
        if(in_array(true,$current['state']['policy']['hardware'],true))throw new RuntimeException('Hardware policy is enforced. Independent hardware recovery must be separately qualified; ordinary passkey recovery is blocked.');
        return SecretsBackendCodec::json(['backend'=>$this->InstanceID,'vault'=>$store->identity()['deploymentId'],'owner'=>$current['state']['identity']['ownerId'],'head'=>$current['head'],
            'policyDigest'=>SecretsBootstrapVerifier::digest($current['state']['policy']),'vaultDirectory'=>$this->ReadPropertyString('DataDirectory'),'keyDirectory'=>$this->ReadPropertyString('KeyDirectory'),'digest'=>SecretsBootstrapVerifier::digest($current['state']['policy'])]);
    }
    public function CompleteBootstrapRecovery(int $FrontendInstanceID,string $AdmissionJSON): string
    {
        if($FrontendInstanceID!==$this->ReadPropertyInteger('FrontendInstanceID'))throw new RuntimeException('Wrong recovery frontend.');
        $a=SecretsFrontendConfiguration::decodeBounded($AdmissionJSON,65536,32);
        SecretsBootstrapVerifier::exact($a,['intent','operation','candidateDigest','planDigest','registration','registrationContext','assertion','challenge','recovery','runtime']);
        $j=SecretsBootstrapJournal::forKernel(IPS_GetKernelDir());
        return $j->locked(function()use($a,$j,$FrontendInstanceID):string{
            if($j->read('decision-'.hash('sha256',$a['intent']))!==null||SECF_BootstrapRuntime($FrontendInstanceID)!==$a['runtime'])throw new RuntimeException('Recovery was cancelled, decided or restarted.');
            $currentInfo=json_decode($this->GetBootstrapRecoveryInfo($FrontendInstanceID),true);
            if(SecretsBootstrapVerifier::digest($currentInfo)!==SecretsBootstrapVerifier::digest($a['recovery']))throw new RuntimeException('Recovery snapshot or policy changed.');
            if($a['registrationContext']['owner']!==$currentInfo['owner']||$a['registrationContext']['origin']!==$this->ReadPropertyString('AdminOrigin'))throw new RuntimeException('Recovery identity binding failed.');
            $entry=SecretsBootstrapVerifier::registration($a['registration'],$a['registrationContext']);$entry['counter']=SecretsBootstrapVerifier::assertion($entry,$a['assertion'],$a['challenge'],$this->ReadPropertyString('AdminOrigin'));$entry['tested']=true;
            $store=$this->nativeStore();$store->change($currentInfo['head'],$a['operation'],SecretsBootstrapVerifier::digest($a),static function(array $state)use($entry,$currentInfo):array{
                if(in_array(true,$state['policy']['hardware'],true)||SecretsBootstrapVerifier::digest($state['policy'])!==$currentInfo['policyDigest']||isset($state['identity']['credentials'][$entry['id']]))throw new RuntimeException('Recovery rights or policy changed.');
                $state['identity']['credentials'][$entry['id']]=$entry;$state['identity']['revocation']=SecretsBackendCodec::increment($state['identity']['revocation']);return $state;
            },['action'=>'console-recovery','actor'=>'independent-console','target'=>$entry['id'],'frontend'=>$FrontendInstanceID,'backend'=>$this->InstanceID]);
            $j->write('decision-'.hash('sha256',$a['intent']),['status'=>'RECOVERED','intent'=>$a['intent'],'frontend'=>$FrontendInstanceID,'operation'=>$a['operation']]);
            return SecretsBackendCodec::json(['committed'=>true]);
        });
    }
    public function BootstrapLogin(int $FrontendInstanceID,string $Intent,string $Runtime): string
    {
        $journal=SecretsBootstrapJournal::forKernel(IPS_GetKernelDir());
        return $journal->locked(function()use($journal,$FrontendInstanceID,$Intent,$Runtime):string{
            $d=$journal->read('decision-'.hash('sha256',$Intent));
            if(!$d||$d['status']!=='ACCEPTED'||$d['frontend']!==$FrontendInstanceID||SECF_BootstrapRuntime($FrontendInstanceID)!==$Runtime||!$journal->read('result-'.$d['operation']))throw new RuntimeException('Bootstrap login context unavailable. Use normal passkey login.');
            if($journal->read('login-'.$d['operation'])!==null)throw new RuntimeException('Login response is never replayed. Use normal passkey login.');
            $journal->write('login-'.$d['operation'],['operation'=>$d['operation'],'runtime'=>$Runtime]);
            $state=$this->nativeStore()->read()['state'];
            $id=$d['registration']['rawId'];
            if(($state['native']['initializationOperation']??'')!==$d['operation'])throw new RuntimeException('Wrong initialization operation.');
            return SecretsBackendCodec::json($this->nativeApplication()->bootstrapSession($id));
        });
    }
}
