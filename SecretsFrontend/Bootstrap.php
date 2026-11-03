<?php
declare(strict_types=1);
require_once __DIR__ . '/Commissioning.php';
require_once __DIR__ . '/../SecretsBackend/BootstrapJournal.php';

/** Console-opened candidate protocol. Nothing in a URL authorizes setup. */
trait SecretsFrontendBootstrap
{
    private function bootstrapState(): array { return json_decode($this->GetBuffer('Bootstrap'),true)??[]; }
    private function bootstrapSave(array $s): void { $this->SetBuffer('Bootstrap',SecretsBackendCodec::json($s)); }
    public function BootstrapRuntime(): string { return $this->GetBuffer('BootstrapRuntime'); }
    private function bootstrapClock(array &$s): void
    {
        $now=time();if($now<($s['lastClock']??$now))throw new RuntimeException('Clock moved backwards; reopen the setup from the console.');
        $s['lastClock']=$now;$this->bootstrapSave($s);
    }
    private function bootstrapStorageRequirements(): array
    {
        $base=rtrim(str_replace('\\','/',IPS_GetKernelDir()),'/');$data=$base.'/secrets-native-data/bootstrap';$keys=$base.'/secrets-native-keys/bootstrap';
        $p=SecretsBackendNativePlatform::persistence($data,$keys,IPS_GetKernelDir());
        return ['data'=>$data,'keys'=>$keys,'confirmationRequired'=>PHP_OS_FAMILY==='Windows'||$p['vault']['confirmationRequired']||$p['keys']['confirmationRequired']];
    }
    private function bootstrapJournal(bool $create=false): SecretsBootstrapJournal { return SecretsBootstrapJournal::forKernel(IPS_GetKernelDir(),$create); }
    private function bootstrapLock(callable $fn)
    {
        $lock='SECF.Bootstrap.'.$this->InstanceID;
        if(!IPS_SemaphoreEnter($lock,1000))throw new RuntimeException('Setup is busy.');
        try{return $fn();}finally{IPS_SemaphoreLeave($lock);}
    }
    private function bootstrapNative(): ?array
    {
        $id=$this->ReadPropertyInteger('BackendInstanceID');
        if($id>0&&function_exists('SECB_GetNativeInfo')){try{return json_decode(SECB_GetNativeInfo($id),true);}catch(Throwable $ignored){}}
        return null;
    }
    public function OpenBootstrap(string $Address='',string $ProxyIPs='',bool $Recovery=false,bool $JournalStorageConfirmed=false): string
    {
        return $this->bootstrapLock(function()use($Address,$ProxyIPs,$Recovery,$JournalStorageConfirmed):string{
            if(IPS_HasChanges($this->InstanceID))throw new RuntimeException('Apply or discard pending edits first.');
            $origin=$Address!==''?SecretsFrontendCommissioning::address($Address):$this->settings()['AdminOrigin'];
            $native=$this->bootstrapNative();$initialized=($native['initialized']??false)===true;
            if($initialized&&$origin!==$this->settings()['AdminOrigin']){$p=$native['backupOrigin']??null;if(($p['version']??0)!==2||($p['status']??'')!=='active'||($p['origin']??'')!==$origin)throw new RuntimeException('Use an approved full-access HTTPS address.');}
            if($initialized&&!$Recovery)return $origin.$this->path();
            $recovery=$Recovery?json_decode(SECB_GetBootstrapRecoveryInfo($this->backend(),$this->InstanceID),true,32,JSON_THROW_ON_ERROR):null;
            if($origin==='')throw new RuntimeException('Enter your trusted Symcon HTTPS address.');
            $proxies=$ProxyIPs!==''?SecretsFrontendCommissioning::proxies($ProxyIPs):$this->settings()['TrustedHTTPSProxyIPs'];
            $storage=$this->bootstrapStorageRequirements();
            if($storage['confirmationRequired']&&!$JournalStorageConfirmed&&!$this->ReadAttributeBoolean('BootstrapJournalConfirmed'))throw new RuntimeException('Verify private access and persistent storage for the displayed setup-record and key folders in the console.');
            if($JournalStorageConfirmed)$this->WriteAttributeBoolean('BootstrapJournalConfirmed',true);
            $journal=$this->bootstrapJournal(true);
            $journal->locked(function()use($journal):void{
                foreach($journal->decisions()as$d)if($d['status']==='ACCEPTED'&&$d['frontend']===$this->InstanceID&&$journal->read('result-'.$d['operation'])===null)throw new RuntimeException('An accepted setup is pending. Resolve that operation before opening another.');
            });
            $old=$this->bootstrapState();if($old)$journal->locked(fn()=>$journal->write('decision-'.hash('sha256',$old['intent']),['status'=>'CANCELLED','intent'=>$old['intent'],'frontend'=>$this->InstanceID]));
            $roster=[];
            foreach(IPS_GetInstanceListByModuleID(self::BACKEND)as$id){try{$info=$this->initialBackend((int)$id);}catch(Throwable $e){continue;}
                if($info['canConfigure']&&!$info['nativeInitializationPending']&&in_array($info['frontend'],[0,$this->InstanceID],true))$roster[(string)$id]=$info;
            }
            if($recovery!==null)$roster=[(string)$recovery['backend']=>$recovery];
            if(count($roster)>32)throw new RuntimeException('Too many eligible backends.');
            foreach(['Enabled'=>true,'AdminOrigin'=>$Recovery?$this->settings()['AdminOrigin']:$origin,'TrustedHTTPSProxyIPs'=>SecretsFrontendConfiguration::encode($proxies)]as$k=>$v)IPS_SetProperty($this->InstanceID,$k,$v);
            $this->WriteAttributeBoolean('GuidedV2Only',true);IPS_ApplyChanges($this->InstanceID);
            $s=['intent'=>SecretsBackendCodec::b64(random_bytes(32)),'runtime'=>$this->BootstrapRuntime(),'origin'=>$origin,'frontend'=>$this->ReadAttributeString('BootstrapIdentity'),
                'mode'=>$Recovery?'recovery':'initial','recovery'=>$recovery,'expires'=>time()+900,'lastClock'=>time(),'frontDigest'=>SecretsBootstrapVerifier::digest($this->settings()),'roster'=>$roster,'vault'=>$recovery['vault']??SecretsBackendCodec::uuid(),
                'owner'=>$recovery['owner']??SecretsBackendCodec::b64(random_bytes(32)),'compareKey'=>SecretsBackendCodec::b64(random_bytes(32)),'viewKey'=>SecretsBackendCodec::b64(random_bytes(32)),
                'resumeKey'=>SecretsBackendCodec::b64(random_bytes(32)),'prepares'=>[],'candidates'=>[]];
            $journal->locked(fn()=>$journal->write('intent-'.hash('sha256',$s['intent']),['intent'=>$s['intent'],'frontend'=>$this->InstanceID,'origin'=>$origin,'vault'=>$s['vault']]));
            $this->bootstrapSave($s);if(!$this->Refresh())throw new RuntimeException('The setup hook could not be registered.');
            return $origin.$this->path();
        });
    }
    public function OpenRecoveryBootstrap(): string { return $this->OpenBootstrap('', '', true); }
    /** Console-only view. Button payloads contain immutable literal snapshots. */
    public function GetBootstrapConsoleView(): string
    {
        return $this->bootstrapLock(function():string{
            $s=$this->bootstrapState();$out=[];if(!$s)return '[]';$this->bootstrapClock($s);
            foreach($s['candidates']as$id=>$c){if($c['expires']<time()||$s['expires']<time())continue;
                $view=['candidate'=>$id,'digest'=>$c['digest'],'intent'=>$s['intent'],'runtime'=>$s['runtime'],'view'=>SecretsBackendCodec::uuid(),'expires'=>time()+60];
                $proof=SecretsBackendCodec::b64(SecretsBackendCodec::json($view));
                $proof.='.'.hash_hmac('sha256',"SECF.BOOTSTRAP.VIEW.1\0".$proof,SecretsBackendCodec::unb64($s['viewKey'],32));
                $out[]=['candidate'=>$id,'digest'=>$c['digest'],'comparison'=>$c['comparison'],'purpose'=>$s['mode']==='recovery'?'Recover administrator access':'Initial setup','origin'=>$s['origin'],'frontend'=>$this->InstanceID,'expires'=>$c['expires'],'proof'=>$proof];
            }return SecretsBackendCodec::json($out);
        });
    }
    public function ApproveBootstrapCandidate(string $Candidate,string $Digest,string $ViewProof): bool
    {
        return $this->bootstrapLock(function()use($Candidate,$Digest,$ViewProof):bool{
            $s=$this->bootstrapState();$this->bootstrapValid($s);$c=$s['candidates'][$Candidate]??null;
            $parts=explode('.',$ViewProof);if(count($parts)!==2||!hash_equals(hash_hmac('sha256',"SECF.BOOTSTRAP.VIEW.1\0".$parts[0],SecretsBackendCodec::unb64($s['viewKey'],32)),$parts[1]))throw new RuntimeException('Console view proof failed.');
            $v=SecretsFrontendConfiguration::decode(SecretsBackendCodec::unb64($parts[0]));
            if(!$c||$c['digest']!==$Digest||$v['candidate']!==$Candidate||$v['digest']!==$Digest||$v['intent']!==$s['intent']||$v['runtime']!==$s['runtime']||$v['expires']<time()||$c['expires']<time())throw new RuntimeException('The displayed request expired or changed.');
            foreach($s['candidates']as$id=>$other)if(($other['approved']??false)&&$id!==$Candidate)throw new RuntimeException('Another candidate was already approved.');
            if($c['approved'])return true;
            $s['candidates'][$Candidate]['approved']=true;$s['candidates'][$Candidate]['expires']=min($s['expires'],time()+600);$this->bootstrapSave($s);return true;
        });
    }
    public function RejectBootstrapCandidate(string $Candidate,string $Digest): void
    {
        $this->bootstrapLock(function()use($Candidate,$Digest):void{$s=$this->bootstrapState();$this->bootstrapValid($s);if(($s['candidates'][$Candidate]['digest']??'')!==$Digest)throw new RuntimeException('Candidate changed.');unset($s['candidates'][$Candidate]);$this->bootstrapSave($s);});
    }
    public function CancelBootstrap(): string
    {
        return $this->bootstrapLock(function():string{$s=$this->bootstrapState();if(!$s){
            try{$j=$this->bootstrapJournal();$pending=$j->locked(function()use($j):bool{foreach($j->decisions()as$d)if($d['status']==='ACCEPTED'&&$d['frontend']===$this->InstanceID&&$j->read('result-'.$d['operation'])===null)return true;return false;});if($pending)return 'Setup is already durably authorized. Check its completion status.';}catch(Throwable $e){throw new RuntimeException('Cancellation status is unknown; inspect setup recovery.');}
            return 'No active setup.';
        }$j=$this->bootstrapJournal();return $j->locked(function()use($j,$s):string{
            $name='decision-'.hash('sha256',$s['intent']);$d=$j->read($name);
            if(($d['status']??'')==='ACCEPTED')return 'Setup is already durably authorized. Check its completion status.';
            $j->write($name,['status'=>'CANCELLED','intent'=>$s['intent'],'frontend'=>$this->InstanceID]);$this->SetBuffer('Bootstrap','');return 'Cancelled; no setup operation was authorized.';
        });});
    }
    private function bootstrapValid(array &$s): void
    {
        if(!$s||$s['runtime']!==$this->BootstrapRuntime()||$s['frontDigest']!==SecretsBootstrapVerifier::digest($this->settings())||IPS_HasChanges($this->InstanceID))throw new RuntimeException('Setup context changed. Reopen it from the console.');
        $this->bootstrapClock($s);if($s['expires']<time())throw new RuntimeException('Setup authorization expired.');
    }
    private function bootstrapCookieName(): string
    {
        return '__Host-SECFB_'.str_replace('-','',$this->ReadAttributeString('BootstrapIdentity')).'_'.substr(hash('sha256',$this->bootstrapState()['origin']??$this->settings()['AdminOrigin']),0,16);
    }
    private function bootstrapContext(array $r,array $ctx): void
    {
        if($r['origin']!==($this->bootstrapState()['origin']??$this->settings()['AdminOrigin'])||!hash_equals($ctx['csrf'],$r['csrf']))throw new RuntimeException('Bootstrap CSRF binding failed.');
        preg_match_all('/(?:^|;\s*)'.preg_quote($this->bootstrapCookieName(),'/').'=([A-Za-z0-9_-]{43})(?=;|$)/',$r['cookie'],$m);
        if(count($m[1])!==1||!hash_equals($ctx['cookieHash'],hash('sha256',$m[1][0])))throw new RuntimeException('Bootstrap cookie binding failed.');
    }
    private function bootstrapPrepare(array &$s,array $data): array
    {
        $reuse=($data['reuse']??false)===true;SecretsBootstrapVerifier::exact($data,$reuse?['reuse']:[]);
        $s['prepares']=array_filter($s['prepares'],fn($p)=>$p['expires']>=time());
        $s['candidates']=array_filter($s['candidates'],fn($p)=>$p['expires']>=time());
        if(count($s['prepares'])+count($s['candidates'])>=8)throw new RuntimeException('Too many pending candidates; use the console to reject unknown requests.');
        $auth=SecretsBootstrapVerifier::webauthn($s['origin']);$user=SecretsBackendCodec::b64(random_bytes(32));
        $args=$reuse?$auth->getGetArgs([],90,true,true,true,true,true,true):$auth->getCreateArgs(SecretsBackendCodec::unb64($user),'Administrator','Administrator',90,'preferred',true,null,[]);
        $id=SecretsBackendCodec::b64(random_bytes(32));$cookie=SecretsBackendCodec::b64(random_bytes(32));$csrf=SecretsBackendCodec::b64(random_bytes(32));
        $p=['reuse'=>$reuse,'challenge'=>SecretsBackendCodec::b64($auth->getChallenge()->getBinaryString()),'origin'=>$s['origin'],'owner'=>$s['owner'],'userHandle'=>$user,'expires'=>min(time()+90,$s['expires']),
            'cookieHash'=>hash('sha256',$cookie),'csrf'=>$csrf];$s['prepares'][$id]=$p;$this->bootstrapSave($s);
        return ['data'=>['prepare'=>$id,'options'=>$args->publicKey,'csrf'=>$csrf,'intent'=>$s['intent'],'frontend'=>$s['frontend']],
            'cookie'=>$this->bootstrapCookieName().'='.$cookie.'; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=900'];
    }
    private function bootstrapSubmit(array &$s,array $data,array $r): array
    {
        SecretsBootstrapVerifier::exact($data,['prepare','key','credential','signature']);
        $p=$s['prepares'][$data['prepare']]??null;if(!$p||$p['expires']<time())throw new RuntimeException('Candidate preparation expired.');$this->bootstrapContext($r,$p);
        $key=SecretsBootstrapVerifier::publicKey($data['key']);
        $domain=$p['reuse']?'SECF.BOOTSTRAP.REUSE.1':'SECF.BOOTSTRAP.SUBMIT.1';
        $bytes=$domain."\n".$s['origin']."\n".$this->path()."\n".$s['frontend']."\n".$s['intent']."\n".$data['prepare']."\n".$p['challenge']."\n".$key['digest']."\n".SecretsBootstrapVerifier::digest($data['credential'])."\n";
        SecretsBootstrapVerifier::verifySignature($bytes,$data['signature'],$data['key']);
        $registration=array_intersect_key($p,array_flip(['challenge','origin','owner','userHandle']));$credential=$data['credential'];
        if($p['reuse']){
            $rawId=$credential['rawId']??'';if(!is_string($rawId)||strlen($rawId)>2048)throw new RuntimeException('Invalid prepared credential identity.');SecretsBackendCodec::unb64($rawId);
            $j=$this->bootstrapJournal();$prior=$j->locked(fn()=>$j->read('prepared-key-'.hash('sha256',$rawId)));
            if(!$prior||$prior['origin']!==$s['origin'])throw new RuntimeException('No matching previously prepared passkey. Prepare a new one.');
            $registration=$prior['context'];$registration['owner']=$s['owner'];$registration['reuseChallenge']=$p['challenge'];$registration['reuseAssertion']=$credential;
            $credential=$prior['registration'];
        }
        $entry=SecretsBootstrapVerifier::registration($credential,$registration);
        if(!$p['reuse']){
            $j=$this->bootstrapJournal();$j->locked(fn()=>$j->write('prepared-key-'.hash('sha256',$entry['id']),['origin'=>$s['origin'],'registration'=>$credential,'context'=>$registration]));
        }
        $id=SecretsBackendCodec::b64(random_bytes(32));
        $descriptor=['format'=>'SECF.BootstrapCandidate.v1','mode'=>$s['mode'],'frontendIdentity'=>$s['frontend'],'frontendInstance'=>(string)$this->InstanceID,'origin'=>$s['origin'],'rpId'=>(string)parse_url($s['origin'],PHP_URL_HOST),
            'intentId'=>$s['intent'],'runtimeGeneration'=>$s['runtime'],'backendSelectionDigest'=>SecretsBootstrapVerifier::digest($s['roster']),'candidateId'=>$id,'credentialId'=>$entry['id'],
            'credentialPublicKeyDigest'=>hash('sha256',$entry['publicKey']),'browserPublicKeyDigest'=>$key['digest'],'registrationTranscriptDigest'=>SecretsBootstrapVerifier::digest(['registration'=>$credential,'context'=>$registration]),
            'hardwarePolicyDigest'=>$s['recovery']['policyDigest']??hash('sha256','initial-default-no-hardware'),'existingVaultBinding'=>$s['recovery']['vault']??null,'expiresAt'=>(string)min($s['expires'],time()+300)];
        $digest=SecretsBootstrapVerifier::digest($descriptor);$comparison=strtoupper(substr(hash_hmac('sha256',"SECF.BOOTSTRAP.COMPARE.v1\0".SecretsBackendCodec::json($descriptor),SecretsBackendCodec::unb64($s['compareKey'],32)),0,16));
        $c=['descriptor'=>$descriptor,'digest'=>$digest,'comparison'=>implode('–',str_split($comparison,4)),'entry'=>$entry,'registration'=>$credential,'registrationContext'=>$registration,'key'=>$data['key'],
            'expires'=>(int)$descriptor['expiresAt'],'epoch'=>'0','nonce'=>SecretsBackendCodec::b64(random_bytes(32)),'nonceExpires'=>time()+90,'requests'=>[],'approved'=>false,'csrf'=>$p['csrf'],'cookieHash'=>$p['cookieHash'],'plan'=>null,'operation'=>SecretsBackendCodec::uuid()];
        unset($s['prepares'][$data['prepare']]);$s['candidates'][$id]=$c;$this->bootstrapSave($s);
        return ['data'=>['candidate'=>$id,'candidateDigest'=>$digest,'keyDigest'=>$key['digest'],'comparison'=>$c['comparison'],'epoch'=>'0','nonce'=>$c['nonce'],'expires'=>$c['expires']], 'cookie'=>''];
    }
    private function bootstrapResumeFields(array $s,string $id,array $c): array
    {
        return ['version'=>'SECF.Bootstrap.ResumeChallenge.1','origin'=>$s['origin'],'path'=>$this->path(),'frontend'=>$s['frontend'],'intent'=>$s['intent'],'candidate'=>$id,'candidateDigest'=>$c['digest'],
            'keyDigest'=>SecretsBootstrapVerifier::publicKey($c['key'])['digest'],'runtime'=>$s['runtime'],'epoch'=>$c['epoch']];
    }
    private function bootstrapResumeMac(array $b,array $s): string
    {
        $parts=['SECF.BOOTSTRAP.RESUME.1'];foreach(['version','origin','path','frontend','intent','candidate','candidateDigest','keyDigest','runtime','epoch','resume','challenge','expires']as$k)$parts[]=$b[$k];
        return SecretsBackendCodec::b64(hash_hmac('sha256',implode("\n",$parts)."\n",SecretsBackendCodec::unb64($s['resumeKey'],32),true));
    }
    private function bootstrapPlan(array $s,array $data): array
    {
        SecretsBootstrapVerifier::exact($data,['backend','portal','documentation','theme','vaultDirectory','keyDirectory','addPortalLink','debugEnabled','privateACLConfirmed','persistenceConfirmed']);
        $choice=SecretsFrontendCommissioning::choice($data+['proxyIPs'=>$this->settings()['TrustedHTTPSProxyIPs'],'initialize'=>true,'administratorLabel'=>'Administrator']);
        $paths=SecretsBackendNativePlatform::paths($choice['vaultDirectory'],$choice['keyDirectory'],IPS_GetKernelDir(),$s['mode']==='initial');
        $choice=array_replace($choice,$paths);
        $id=$choice['backend'];$info=$s['roster'][(string)$id]??null;
        if($id===0&&$s['roster'])throw new RuntimeException('Select one of the console-approved backends.');
        if($s['mode']==='recovery'){
            if($id!==$s['recovery']['backend']||$choice['vaultDirectory']!==$s['recovery']['vaultDirectory']||$choice['keyDirectory']!==$s['recovery']['keyDirectory'])throw new RuntimeException('Recovery cannot replace the existing vault or storage.');
        }elseif($id>0){$current=$this->initialBackend($id);if(!$info||!$current['canConfigure']||$current['digest']!==$info['digest'])throw new RuntimeException('Backend changed after console approval.');}
        foreach(['portal'=>self::PORTAL,'documentation'=>self::DOCS]as$k=>$module)if($choice[$k]>0&&(!IPS_InstanceExists($choice[$k])||IPS_HasChanges($choice[$k])||strtoupper(IPS_GetInstance($choice[$k])['ModuleInfo']['ModuleID']??'')!==$module))throw new RuntimeException('Integration selection changed.');
        $persistence=SecretsBackendNativePlatform::persistence($paths['vaultDirectory'],$paths['keyDirectory'],IPS_GetKernelDir());
        if(SecretsBackendNativePlatform::capabilities()['missing'])throw new RuntimeException('Required native PHP functions are missing.');
        return array_replace($choice,$paths,['origin'=>$s['origin'],'backendDigest'=>$info['digest']??'','vault'=>$s['vault'],'owner'=>$s['owner'],'frontendIdentity'=>$s['frontend'],'frontendInstance'=>$this->InstanceID,
            'persistence'=>$persistence,'mode'=>$s['mode'],'recovery'=>$s['recovery']]);
    }
    private function bootstrapDiscovery(array $s): array
    {
        $backends=[];foreach($s['roster']as$id=>$info)$backends[]=['id'=>(int)$id,'name'=>$this->setupName((int)$id,'SecretsBackend'),'defaults'=>['vaultDirectory'=>$info['vaultDirectory'],'keyDirectory'=>$info['keyDirectory']]];
        $defaults=SecretsBackendNativePlatform::defaults(0,IPS_GetKernelDir());
        if(!$backends){$base=rtrim(str_replace('\\','/',IPS_GetKernelDir()),'/');$defaults=['vaultDirectory'=>$base.'/secrets-native-data/'.$s['vault'],'keyDirectory'=>$base.'/secrets-native-keys/'.$s['vault']];$backends[]=['id'=>0,'name'=>'Create a new native backend','defaults'=>$defaults];}
        $pick=static fn($items,$current)=>in_array($current,array_column($items,'id'),true)?$current:(count($items)===1?$items[0]['id']:0);
        $portals=$this->discovered(self::PORTAL,'Portal');$docs=$this->discovered(self::DOCS,'Dokumentation');
        return ['backends'=>$backends,'portals'=>$portals,'documentation'=>$docs,'origin'=>$s['origin'],'mode'=>$s['mode'],'requirements'=>SecretsFrontendCommissioning::requirements(),
            'defaults'=>['backend'=>$pick($backends,$this->ReadPropertyInteger('BackendInstanceID')),'portal'=>$pick($portals,$this->ReadPropertyInteger('PortalInstanceID')),'documentation'=>$pick($docs,$this->ReadPropertyInteger('DocumentationInstanceID')),'theme'=>$this->settings()['Theme'],'debugEnabled'=>$this->ReadPropertyBoolean('DebugEnabled')]];
    }
    private function bootstrapRequest(array $r): array
    {
        return $this->bootstrapLock(function()use($r):array{
            $s=$this->bootstrapState();$this->bootstrapValid($s);$data=$r['data'];$action=$r['action'];
            if($action==='bootstrapPrepare')return $this->bootstrapPrepare($s,$data);
            if($action==='bootstrapSubmit')return $this->bootstrapSubmit($s,$data,$r);
            $id=$data['candidate']??null;$c=is_string($id)?($s['candidates'][$id]??null):null;
            if(!$c||$c['expires']<time())throw new RuntimeException('Candidate expired or unavailable.');$this->bootstrapContext($r,$c);
            if($action==='bootstrapResumeOptions'){
                SecretsBootstrapVerifier::exact($data,['candidate']);$b=$this->bootstrapResumeFields($s,$id,$c)+['resume'=>SecretsBackendCodec::b64(random_bytes(32)),'challenge'=>SecretsBackendCodec::b64(random_bytes(32)),'expires'=>(string)min(time()+90,$c['expires'],$s['expires'])];$b['mac']=$this->bootstrapResumeMac($b,$s);return ['data'=>$b,'cookie'=>''];
            }
            if($action!=='bootstrapProof')throw new RuntimeException('Unknown bootstrap action.');
            $proof=SecretsBootstrapVerifier::message($data,$c['key']);$body=$proof['body'];
            foreach(['origin'=>$s['origin'],'path'=>$this->path(),'frontend'=>$s['frontend'],'intent'=>$s['intent'],'candidateDigest'=>$c['digest'],'epoch'=>$c['epoch']]as$k=>$v)if($data[$k]!==$v)throw new RuntimeException('Bootstrap proof context changed.');
            if(isset($c['requests'][$data['request']]))throw new RuntimeException('Request was already processed; recover transport and check the same operation.');
            if(count($c['requests'])>=256)throw new RuntimeException('Bootstrap transport budget exhausted.');
            if($data['purpose']==='resume'){
                $expected=$this->bootstrapResumeFields($s,$id,$c);SecretsBootstrapVerifier::exact($body,array_merge(array_keys($expected),['resume','challenge','expires','mac']));
                if(strlen(SecretsBackendCodec::json($body))>8192)throw new RuntimeException('Resume challenge too large.');
                foreach($body as$v)if(!is_string($v)||preg_match('/[^\x20-\x7e]/',$v))throw new RuntimeException('Invalid resume challenge.');
                foreach($expected as$k=>$v)if($body[$k]!==$v)throw new RuntimeException('Resume binding changed.');
                SecretsBackendCodec::unb64($body['resume'],32);SecretsBackendCodec::unb64($body['challenge'],32);SecretsBootstrapVerifier::counter($body['expires']);
                if($body['expires']<(string)time()|| (int)$body['expires']>min(time()+90,$s['expires'],$c['expires'])||$data['operation']!=='-'||$data['nonce']!==$body['challenge']||!hash_equals($this->bootstrapResumeMac($body,$s),$body['mac']))throw new RuntimeException('Invalid resume proof.');
                $c['epoch']=SecretsBackendCodec::increment($c['epoch']);SecretsBootstrapVerifier::counter($c['epoch']);$result=['resumed'=>true];
            }else{
                if($c['nonceExpires']<time()||!hash_equals($c['nonce'],$data['nonce']))throw new RuntimeException('Nonce expired; recover the transport.');
                $business=in_array($data['action'],['applyOptions','applyVerify','operationStatus','cancel'],true);
                if($data['operation']!==($business?$c['operation']:'-'))throw new RuntimeException('Wrong setup operation.');
                $result=$this->bootstrapAction($s,$id,$c,$data['action'],$body);
            }
            $c['requests'][$data['request']]=$proof['digest'];$c['nonce']=SecretsBackendCodec::b64(random_bytes(32));$c['nonceExpires']=time()+90;$s['candidates'][$id]=$c;$this->bootstrapSave($s);
            if($action==='bootstrapProof'&&$data['action']==='applyVerify'&&($result['status']??'')==='ACCEPTED_PENDING'){
                if($this->RecoverBootstrap()){
                    try{$login=json_decode(SECB_BootstrapLogin($c['plan']['backend']?:$this->ReadPropertyInteger('BackendInstanceID'),$this->InstanceID,$s['intent'],$this->BootstrapRuntime()),true,24,JSON_THROW_ON_ERROR);
                        return ['data'=>['status'=>'COMMITTED','operation'=>$c['operation']]+$login['data'],'cookie'=>$login['cookie']];
                    }catch(Throwable $e){return ['data'=>['status'=>'COMMITTED','operation'=>$c['operation'],'loginRequired'=>true],'cookie'=>''];}
                }
                return ['data'=>['status'=>'RECOVERY_REQUIRED','operation'=>$c['operation'],'message'=>'Accepted setup needs recovery. Do not start another setup.'],'cookie'=>''];
            }
            return ['data'=>$result+['nonce'=>$c['nonce'],'epoch'=>$c['epoch']],'cookie'=>''];
        });
    }
    private function bootstrapAction(array &$s,string $id,array &$c,string $action,array $body): array
    {
        if($action==='candidateStatus'){SecretsBootstrapVerifier::exact($body,[]);return ['approved'=>$c['approved'],'comparison'=>$c['comparison'],'operation'=>$c['operation']]+($c['approved']?['discovery'=>$this->bootstrapDiscovery($s)]:[]);}
        if(!$c['approved'])throw new RuntimeException('Approve this exact candidate in the trusted console first.');
        $j=$this->bootstrapJournal();$result=$j->locked(function()use($j,&$s,$id,&$c,$action,$body):array{
            $name='decision-'.hash('sha256',$s['intent']);$decision=$j->read($name);
            if($action==='cancel'){
                SecretsBootstrapVerifier::exact($body,[]);if(($decision['status']??'')==='ACCEPTED')return ['status'=>'ACCEPTED_PENDING','message'=>'Already durably authorized; completion status must be checked.'];
                $j->write($name,['status'=>'CANCELLED','intent'=>$s['intent'],'frontend'=>$this->InstanceID]);return ['status'=>'CANCELLED'];
            }
            if($action==='operationStatus'){SecretsBootstrapVerifier::exact($body,[]);$result=$j->read('result-'.$c['operation']);return ['status'=>$result['status']??(($decision['status']??'')==='ACCEPTED'?'ACCEPTED_PENDING':($decision['status']??'NOT_ACCEPTED')),'operation'=>$c['operation']];}
            if($decision!==null)throw new RuntimeException('Setup already decided. Check its existing operation.');
            if($action==='planPreview'){
                $plan=$this->bootstrapPlan($s,$body);$c['plan']=$plan;$c['planDigest']=SecretsBootstrapVerifier::digest($plan);unset($c['challenge']);return ['configuration'=>$plan,'planDigest'=>$c['planDigest']];
            }
            if($action==='applyOptions'){
                SecretsBootstrapVerifier::exact($body,['planDigest']);if(!$c['plan']||$body['planDigest']!==$c['planDigest'])throw new RuntimeException('Review the current plan first.');
                $plan=$c['plan'];if((PHP_OS_FAMILY==='Windows'&&!$plan['privateACLConfirmed'])||((($plan['persistence']['vault']['confirmationRequired']??false)||($plan['persistence']['keys']['confirmationRequired']??false))&&!$plan['persistenceConfirmed']))throw new RuntimeException('Confirm the unresolved storage/ACL conditions.');
                $auth=SecretsBootstrapVerifier::webauthn($s['origin']);$args=$auth->getGetArgs([SecretsBackendCodec::unb64($c['entry']['id'])],90,true,true,true,true,true,true);
                $c['challenge']=['challenge'=>SecretsBackendCodec::b64($auth->getChallenge()->getBinaryString()),'planDigest'=>$c['planDigest'],'expires'=>min(time()+90,$c['expires'],$s['expires'])];return ['options'=>$args->publicKey];
            }
            if($action!=='applyVerify')throw new RuntimeException('Unknown candidate action.');
            SecretsBootstrapVerifier::exact($body,['planDigest','credential']);$challenge=$c['challenge']??null;
            if(!$challenge||$challenge['expires']<time()||$challenge['planDigest']!==$body['planDigest']||$c['planDigest']!==$body['planDigest'])throw new RuntimeException('Final plan challenge expired or changed.');
            SecretsBootstrapVerifier::assertion($c['entry'],$body['credential'],$challenge['challenge'],$s['origin']);
            $this->bootstrapValid($s);if($c['expires']<time())throw new RuntimeException('Candidate authorization expired.');
            $choice=array_intersect_key($c['plan'],array_flip(['backend','portal','documentation','theme','vaultDirectory','keyDirectory','addPortalLink','debugEnabled','privateACLConfirmed','persistenceConfirmed']));
            $fresh=$this->bootstrapPlan($s,$choice);if(SecretsBootstrapVerifier::digest($fresh)!==$c['planDigest'])throw new RuntimeException('The plan changed before acceptance.');
            if($s['mode']==='recovery'){
                $recovery=['intent'=>$s['intent'],'operation'=>$c['operation'],'candidateDigest'=>$c['digest'],'planDigest'=>$c['planDigest'],'registration'=>$c['registration'],'registrationContext'=>$c['registrationContext'],'assertion'=>$body['credential'],'challenge'=>$challenge['challenge'],'recovery'=>$s['recovery'],'runtime'=>$s['runtime']];
                return ['internalRecovery'=>$recovery];
            }
            $decision=['status'=>'ACCEPTED','protocol'=>'SECF.Bootstrap.1','intent'=>$s['intent'],'frontend'=>$this->InstanceID,'frontendIdentity'=>$s['frontend'],'origin'=>$s['origin'],'operation'=>$c['operation'],'candidateDigest'=>$c['digest'],
                'keyDigest'=>SecretsBootstrapVerifier::publicKey($c['key'])['digest'],'frontSettings'=>$this->settings(),'plan'=>$c['plan'],'planDigest'=>$c['planDigest'],'registration'=>$c['registration'],'registrationContext'=>$c['registrationContext'],'assertion'=>$body['credential'],'challenge'=>$challenge['challenge'],'authorizedAt'=>time()];
            $j->reserve($decision);$j->write($name,$decision);
            // Completion runs after this request's nonce/context is saved, under a fresh worker.
            return ['status'=>'ACCEPTED_PENDING','operation'=>$c['operation']];
        });
        if(isset($result['internalRecovery'])){
            // Module calls can run in separate PHP contexts: never hold the journal
            // file lock across a call whose callee acquires that same lock.
            SECB_CompleteBootstrapRecovery($c['plan']['backend'],$this->InstanceID,SecretsBackendCodec::json($result['internalRecovery']));
            return ['status'=>'COMMITTED','loginRequired'=>true,'operation'=>$c['operation']];
        }
        return $result;
    }
    /** Explicit console resolution of the object-create/file-commit gap; never a browser action. */
    public function ResolveBootstrapBackend(string $Operation,int $Backend): bool
    {
        SecretsBootstrapVerifier::uuid($Operation);$j=$this->bootstrapJournal();
        return $j->locked(function()use($j,$Operation,$Backend):bool{
            $found=null;foreach($j->decisions()as$d)if($d['status']==='ACCEPTED'&&$d['frontend']===$this->InstanceID&&$d['operation']===$Operation)$found=$d;
            if(!$found||$found['plan']['backend']!==0||$j->read('creating-'.$Operation)===null||$j->read('created-'.$Operation)!==null||$j->read('result-'.$Operation)!==null)throw new RuntimeException('No ambiguous backend creation matches this operation.');
            $info=$this->initialBackend($Backend);
            if(!$info['canConfigure']||$info['nativeInitializationPending']||IPS_GetProperty($Backend,'Enabled')||!in_array($info['frontend'],[0,$this->InstanceID],true))throw new RuntimeException('Select the exact new disabled empty native backend after inspection. Existing deployments are never adopted.');
            $j->write('created-'.$Operation,['backend'=>$Backend,'vault'=>$found['plan']['vault']]);return true;
        });
    }
    /** Current worker only. Called after acceptance and by the recovery timer, never by a status ID. */
    public function RecoverBootstrap(): bool
    {
        $this->SetTimerInterval('BootstrapRecovery',0);
        $base=rtrim(str_replace('\\','/',IPS_GetKernelDir()),'/');if(!is_dir($base.'/secrets-native-data/bootstrap'))return true;
        try{
            $j=$this->bootstrapJournal();$decisions=$j->locked(fn()=>$j->decisions());
            foreach($decisions as$d){
                if($d['status']!=='ACCEPTED'||$d['frontend']!==$this->InstanceID)continue;
                $target=$j->locked(function()use($j,$d):?int{
                    if($j->read('result-'.$d['operation'])!==null)return null;
                    if($d['frontendIdentity']!==$this->ReadAttributeString('BootstrapIdentity')||$d['origin']!==$this->settings()['AdminOrigin']||IPS_HasChanges($this->InstanceID))throw new RuntimeException('Accepted setup configuration changed; recovery is required.');
                    foreach(['Enabled','AdminOrigin','TrustedHTTPSProxyIPs']as$key)if($this->settings()[$key]!==$d['frontSettings'][$key])throw new RuntimeException('The accepted frontend trust settings changed.');
                    $plan=$d['plan'];$id=$plan['backend'];
                    if($id===0){
                        $created=$j->read('created-'.$d['operation']);
                        if($created===null){
                            if($j->read('creating-'.$d['operation'])!==null)throw new RuntimeException('Backend creation result is UNKNOWN; resolve the reserved operation in the console.');
                            $j->write('creating-'.$d['operation'],['operation'=>$d['operation'],'module'=>self::BACKEND,'vault'=>$plan['vault']]);
                            $id=IPS_CreateInstance(self::BACKEND);
                            $j->write('created-'.$d['operation'],['backend'=>$id,'vault'=>$plan['vault']]);
                        }else{$id=$created['backend'];}
                    }
                    return $id;
                });
                if($target===null)continue;$plan=$d['plan'];$id=$target;
                // Applying a frontend reload invalidates its volatile authorization.
                // It must run outside the shared journal lock, before taking a worker fence.
                $settings=['BackendInstanceID'=>$id,'PortalInstanceID'=>$plan['portal'],'DocumentationInstanceID'=>$plan['documentation'],'Theme'=>$plan['theme'],'DebugEnabled'=>$plan['debugEnabled']];
                $change=false;foreach($settings as$k=>$v)if(IPS_GetProperty($this->InstanceID,$k)!==$v){IPS_SetProperty($this->InstanceID,$k,$v);$change=true;}
                if($change)IPS_ApplyChanges($this->InstanceID);
                $runtime=$this->BootstrapRuntime();$worker=$j->locked(fn()=>$j->fence($d['operation'],$runtime));
                if(!function_exists('SECB_CompleteBootstrap'))throw new RuntimeException('Update the native backend to the code-free setup implementation.');
                if(!SECB_CompleteBootstrap($id,$this->InstanceID,$d['intent'],$runtime,$worker))throw new RuntimeException('Backend did not confirm the accepted genesis.');
                $j->locked(function()use($j,$d,$worker,$plan,$id):void{
                    $j->checkFence($d['operation'],$this->BootstrapRuntime(),$worker);
                    if(IPS_HasChanges($this->InstanceID)||$this->ReadPropertyInteger('BackendInstanceID')!==$id||$this->ReadPropertyInteger('PortalInstanceID')!==$plan['portal'])throw new RuntimeException('Accepted frontend binding changed.');
                    if($plan['addPortalLink'])$this->AddToPortal();
                    $j->write('result-'.$d['operation'],['status'=>'COMMITTED','operation'=>$d['operation'],'vault'=>$plan['vault'],'backend'=>$id,'candidateDigest'=>$d['candidateDigest']]);
                });
                $this->WriteAttributeBoolean('GuidedConfigured',true);$this->SetValue('Status','Native vault initialized with the approved administrator. Sign in with your passkey.');
            }
            return true;
        }catch(Throwable $e){$this->SetValue('Status','Setup recovery required: '.$e->getMessage());$this->SetTimerInterval('BootstrapRecovery',30000);return false;}
    }
}
