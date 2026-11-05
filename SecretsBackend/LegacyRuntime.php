<?php
declare(strict_types=1);
require_once __DIR__.'/LegacyAPI.php';

/** Symcon public method signatures matching the old SEC application interface. */
trait SecretsBackendLegacyRuntime
{
    private function legacyService(int $source, ?SecretsBackendNativeStore $store = null): SecretsBackendLegacyAPI
    {
        if($source!==$this->InstanceID)throw new RuntimeException('Old manager contexts are disabled on this native-only branch.');
        $store ??= $this->nativeStore();$this->nativeApplication(null,$store);
        return new SecretsBackendLegacyAPI($store,$source,function(array $permission)use($source):void{
            if(!IPS_InstanceExists($source)||IPS_HasChanges($source))throw new RuntimeException('The native backend is unavailable or has unapplied settings.');
        },$this->InstanceID);
    }
    /** Permission/readiness metadata only: no key names, values, paths or exception text. */
    public function GetLegacyAPIStatus(): string
    {
        $out=['backend'=>$this->InstanceID,'readAllowed'=>false,'grantPresent'=>false,'defaultReadAccess'=>false,'grantEnabled'=>false,'readApproved'=>false,'writesFrozen'=>null,'code'=>'BACKEND_UNAVAILABLE'];
        try{
            if(!$this->ReadPropertyBoolean('Enabled'))$out['code']='BACKEND_DISABLED';
            elseif(IPS_HasChanges($this->InstanceID))$out['code']='PENDING_SETTINGS';
            else{
                $service=$this->legacyService($this->InstanceID);$state=$this->nativeStore()->read()['state'];
                $p=SecretsBackendLegacyAPI::access($state,$this->InstanceID,$this->InstanceID);
                $out['grantPresent']=array_key_exists((string)$this->InstanceID,$state['native']['legacyAccess']??[]);$out['defaultReadAccess']=($p['defaultReadAccess']??false)===true;
                if(is_array($p))$out=array_replace($out,['grantEnabled'=>($p['enabled']??false)===true,'readApproved'=>($p['read']??false)===true,'writesFrozen'=>($p['frozen']??true)===true]);
                if(!is_array($p))$out['code']='READ_GRANT_MISSING';
                elseif(!$out['grantEnabled'])$out['code']='READ_GRANT_DISABLED';
                elseif(($p['treeId']??'')!==$state['native']['globalTreeId'])$out['code']='GLOBAL_IDENTITY_CHANGED';
                elseif(!$out['readApproved'])$out['code']='READ_NOT_APPROVED';
                else{$service->permission($state,'read');$out['readAllowed']=true;$out['code']='READ_ALLOWED';}
            }
        }catch(Throwable $error){$out['code']='BACKEND_UNAVAILABLE';}
        $out['meaning']=match($out['code']){
            'READ_ALLOWED'=>$out['defaultReadAccess']?'Local application reads are enabled by default on this backend. No separate read grant is needed; writes remain frozen.':'Application read access uses the existing explicit grant. An empty successful GetKeys result means no available top-level Global application records; it does not list Local records or count nested values.',
            'READ_GRANT_MISSING'=>'No application read grant is approved for this backend instance. Browser administrator sign-in does not authorize a local PHP script.',
            'READ_GRANT_DISABLED'=>'The application access grant for this backend is disabled.',
            'READ_NOT_APPROVED'=>'The backend access grant does not include reading application secrets.',
            'GLOBAL_IDENTITY_CHANGED'=>'The grant belongs to a different Global tree identity and needs a fresh exact approval.',
            'BACKEND_DISABLED'=>'The new backend is disabled.',
            'PENDING_SETTINGS'=>'Backend settings have unapplied changes.',
            default=>'The native backend could not validate its current storage, runtime or pinned security configuration. No automatic recovery or permission change was attempted.'};
        $out['nextStep']=in_array($out['code'],['READ_GRANT_MISSING','READ_GRANT_DISABLED','READ_NOT_APPROVED','GLOBAL_IDENTITY_CHANGED'],true)
            ?'In Automation access -> Existing SEC applications, select This backend and review its explicit access override. The backend ID is detected automatically. Leave writes frozen for read-only scripts.'
            :($out['code']==='READ_ALLOWED'?'Run the read again and inspect lastFailure if it fails. Read failures are logged without printing into consumer JSON; a fallback [] does not prove an empty vault.':'Check the backend status and applied settings.');
        $last=json_decode($this->GetBuffer('LegacyAPILastFailure'),true);if(is_array($last))$out['lastFailure']=$last;
        if(method_exists($this,'GetEmergencyStatus')){$emergency=json_decode($this->GetEmergencyStatus(),true);$out['emergencyGlobalReadAvailable']=($emergency['mode']??'')==='REMOTE'&&($emergency['ready']??false);$out['activeReadSource']=$emergency['activeSource']??'';}
        return SecretsBackendCodec::json($out);
    }
    public function CallLegacyAPI(int $SourceInstanceID,string $Method,string $ArgumentsJSON): string
    {
        return $this->executeLegacyAPI($SourceInstanceID,$Method,$ArgumentsJSON,null);
    }
    /** Adapter-only binding check is part of the same fresh operation, not a separate status scan. */
    public function CallBoundLegacyAPI(string $ExpectedVaultID,string $Method,string $ArgumentsJSON): string
    {
        return $this->executeLegacyAPI($this->InstanceID,$Method,$ArgumentsJSON,$ExpectedVaultID);
    }
    private function executeLegacyAPI(int $SourceInstanceID,string $Method,string $ArgumentsJSON,?string $expectedVault): string
    {
        if(!in_array($Method,SecretsBackendLegacyAPI::DATA_METHODS,true))throw new RuntimeException('This legacy administration operation requires its native approved workflow.');
        if(strlen($ArgumentsJSON)>SecretsBackendNativePlatform::budget())throw new InvalidArgumentException('Legacy arguments exceed the native memory budget.');
        $args=json_decode($ArgumentsJSON,true,32,JSON_THROW_ON_ERROR);if(!is_array($args)||!array_is_list($args))throw new InvalidArgumentException('Legacy arguments must be a positional array.');
        $counts=['GetKeys'=>0,'GetSecret'=>1,'GetExplorerFields'=>1,'SetRecordFields'=>3,'ExportLocalSecrets'=>0,'ImportLocalSecrets'=>1,'EncryptAndSave'=>1];
        if(count($args)!==$counts[$Method])throw new InvalidArgumentException('Legacy argument count differs.');
        $failure=null;$localValidated=false;
        try{
            if($SourceInstanceID!==$this->InstanceID)throw new RuntimeException('Old manager context refused.');
            $store=$this->nativeStore();
            [$value,$output]=$store->withActiveSnapshot(function()use($store,$SourceInstanceID,$Method,$args,$expectedVault,&$localValidated):array{
                if($expectedVault!==null&&!hash_equals($store->identity()['deploymentId'],$expectedVault))throw new RuntimeException('The pinned native vault changed.',1005);
                $service=$this->legacyService($SourceInstanceID,$store);$localValidated=true;
                if(in_array($Method,['GetKeys','GetSecret','GetExplorerFields'],true))$service->permission($store->read()['state'],'read');
                if(in_array($Method,['GetKeys','GetSecret','GetExplorerFields'],true)&&!str_starts_with((string)($args[0]??''),'__'))$this->emergencyLocalGate($store);
                return [$service->{$Method}(...$args),$service->output()];
            });
            $this->SetBuffer('LegacyAPILastError','');
        }
        catch(Throwable $error){
            if($SourceInstanceID===$this->InstanceID&&(!$localValidated||$error instanceof SecretsBackendEmergencyNeeded)&&$error->getCode()!==1005){
                try{
                    SecretsBackendEmergency::arguments($Method,$args);
                    $value=$this->emergencyRead($Method,$args,$expectedVault);
                    $this->SetBuffer('LegacyAPILastError','');
                    return SecretsBackendCodec::json(['value'=>$value,'output'=>'','error'=>null,'source'=>'emergency-peer']);
                }catch(Throwable $fallbackError){/* Preserve the ordinary failed-call contract; no plaintext error detail. */}
            }
            $output=$Method==='EncryptAndSave'?'❌ Error: Encryption failed.':'';
            $failure=['code'=>match($error->getCode()){2101=>'APPLICATION_RECORD_MISSING',1005=>'PINNED_VAULT_CHANGED',default=>'LEGACY_API_REFUSED'},'meaning'=>'The read/write request failed authorization or backend validation. The fallback value does not prove an empty vault.'];
            $this->SetBuffer('LegacyAPILastError','Legacy '.$Method.' refused; check approved access, binding, freeze, Global conflicts and backend readiness.');
            $value=match($Method){'GetKeys'=>'[]','GetExplorerFields'=>[],'SetRecordFields','ImportLocalSecrets'=>false,'EncryptAndSave'=>null,default=>''};
        }
        return SecretsBackendCodec::json(['value'=>$value,'output'=>$output??'','error'=>$failure]);
    }
    private function legacyFailedRead(string $method,string $code): void
    {
        if(!preg_match('/^[A-Z_]{1,48}$/D',$code))$code='LEGACY_API_REFUSED';
        $this->SetBuffer('LegacyAPILastFailure',json_encode(['method'=>$method,'code'=>$code,'at'=>time()],JSON_THROW_ON_ERROR));
        $lock='SECB.LegacyAPILog.'.$this->InstanceID;if(!IPS_SemaphoreEnter($lock,1))return;
        try{if((int)$this->GetBuffer('LegacyAPILogAt')>time()-60)return;$this->SetBuffer('LegacyAPILogAt',(string)time());
            if(function_exists('IPS_LogMessage'))IPS_LogMessage('SecretsBackend '.$this->InstanceID,'Application read refused ('.$code.'). Run SECB_GetLegacyAPIStatus('.$this->InstanceID.'); fallback values do not prove an empty vault.');
        }catch(Throwable $ignored){}finally{IPS_SemaphoreLeave($lock);}
    }
    private function legacyValue(string $method,array $args)
    {
        $result=json_decode($this->CallLegacyAPI($this->InstanceID,$method,SecretsBackendCodec::json($args)),true,32,JSON_THROW_ON_ERROR);if($method==='EncryptAndSave'&&($result['output']??'')!=='')echo $result['output'];
        if(($result['error']??null)!==null&&in_array($method,['GetKeys','GetSecret','GetExplorerFields','ExportLocalSecrets'],true))$this->legacyFailedRead($method,$result['error']['code']??'LEGACY_API_REFUSED');
        elseif(($result['error']??null)===null)$this->SetBuffer('LegacyAPILastFailure','');
        return $result['value'];
    }
    public function GetKeys(): string { return $this->legacyValue(__FUNCTION__,[]); }
    public function GetSecret(string $ident): string { return $this->legacyValue(__FUNCTION__,[$ident]); }
    public function SetRecordFields(string $path,array $fields,string $scope): bool { return $this->legacyValue(__FUNCTION__,[$path,$fields,$scope]); }
    public function ExportLocalSecrets(): string { return $this->legacyValue(__FUNCTION__,[]); }
    public function ImportLocalSecrets(string $json): bool { return $this->legacyValue(__FUNCTION__,[$json]); }
    public function GetExplorerFields(string $ident): array { return $this->legacyValue(__FUNCTION__,[$ident]); }
    private function legacyOrigin(array $server): string
    {
        $front=$this->ReadPropertyInteger('FrontendInstanceID');
        if(!IPS_GetProperty($front,'Enabled')||IPS_HasChanges($front))throw new RuntimeException('Legacy browser access requires an enabled frontend with applied settings.');
        $proxies=json_decode(IPS_GetProperty($front,'TrustedHTTPSProxyIPs'),true,8,JSON_THROW_ON_ERROR);
        $proxy=in_array($server['REMOTE_ADDR']??'',$proxies,true);
        $host=$proxy&&isset($server['HTTP_X_FORWARDED_HOST'])?$server['HTTP_X_FORWARDED_HOST']:($server['HTTP_HOST']??'');
        $origin=SecretsFrontendConfiguration::origin('https://'.$host);$primary=$this->ReadPropertyString('AdminOrigin');
        if($origin!==$primary){
            $state=$this->nativeStore()->read()['state'];$p=$state['policy']['backupOrigin']??null;
            if(!SecretsBackendBackupOriginPolicy::full($state)||$origin!==($p['origin']??'')||!SecretsFrontendConnectDiscovery::secureRoute($server,$origin,$proxies,SecretsFrontendConnectDiscovery::local()))throw new RuntimeException('Unknown or unverified legacy browser origin.');
        }
        return $origin;
    }
    public function CheckLegacyPortalSession(int $SourceInstanceID,string $ServerJSON): bool
    {
        try{
            if(strlen($ServerJSON)>16384)return false;$server=json_decode($ServerJSON,true,8,JSON_THROW_ON_ERROR);
            $service=$this->legacyService($SourceInstanceID);$service->permission($this->nativeStore()->read()['state'],'portal');
            $origin=$this->legacyOrigin($server);
            return $this->nativeApplication($origin)->portalAuthenticated(['cookie'=>(string)($server['HTTP_COOKIE']??''),'origin'=>$origin]);
        }catch(Throwable $error){return false;}
    }
    public function GetLegacyLoginURL(int $SourceInstanceID,string $ReturnPath,string $ServerJSON): string
    {
        if(strlen($ServerJSON)>16384)throw new InvalidArgumentException('Browser context too large.');
        $server=json_decode($ServerJSON,true,8,JSON_THROW_ON_ERROR);
        if(!preg_match('~^/hook/[A-Za-z0-9_-]+$~D',$ReturnPath))throw new InvalidArgumentException('Return to one local hook path without query parameters.');
        $service=$this->legacyService($SourceInstanceID);$service->permission($this->nativeStore()->read()['state'],'portal');
        $origin=$this->legacyOrigin($server);
        return $origin.'/hook/secrets_frontend_'.$this->ReadPropertyInteger('FrontendInstanceID').'#legacy-return='.rawurlencode($ReturnPath);
    }
    /** Native browser-session integration; no old manager or old credential store is involved. */
    public function IsNativePortalAuthenticated(): bool
    {
        try{$this->nativeApplication();$server=json_decode(self::legacyServerJSON(),true,8,JSON_THROW_ON_ERROR);$origin=$this->legacyOrigin($server);return $this->nativeApplication($origin)->portalAuthenticated(['cookie'=>(string)($server['HTTP_COOKIE']??''),'origin'=>$origin]);}catch(Throwable $error){return false;}
    }
    public function GetNativePortalLoginURL(string $ReturnPath,string $ServerJSON): string
    {
        $this->nativeApplication();if(strlen($ServerJSON)>16384)throw new InvalidArgumentException('Browser context too large.');
        if($ReturnPath!==''&&(!preg_match('~^/hook/[A-Za-z0-9_-]+$~D',$ReturnPath)||preg_match('~^/hook/secrets(?:_frontend|_peer)?_~',$ReturnPath)))throw new InvalidArgumentException('Choose a plain local application hook.');
        $server=json_decode($ServerJSON,true,8,JSON_THROW_ON_ERROR);$origin=$this->legacyOrigin($server);
        return $origin.'/hook/secrets_frontend_'.$this->ReadPropertyInteger('FrontendInstanceID').($ReturnPath===''?'':'#legacy-return='.rawurlencode($ReturnPath));
    }
    public function IsPortalAuthenticated(): bool { return $this->CheckLegacyPortalSession($this->InstanceID,self::legacyServerJSON()); }
    public static function legacyServerJSON(): string
    {
        return SecretsBackendCodec::json(array_intersect_key($_SERVER,array_flip(['HTTP_HOST','HTTP_COOKIE','REMOTE_ADDR','HTTPS','REQUEST_SCHEME','HTTP_X_FORWARDED_HOST','HTTP_X_FORWARDED_PROTO','HTTP_FORWARDED'])));
    }
    private function legacyAdministration(string $method): void
    {
        throw new RuntimeException($method.' is retained for API discovery but is unavailable in native mode. Use the new Secrets administration approval, enrollment, backup or peer workflow.');
    }
    public function SaveAuthToken(string $token): void { $this->legacyAdministration(__FUNCTION__); }
    public function ShowToken(): void { $this->legacyAdministration(__FUNCTION__); }
    public function SaveHookPass(string $pass): void { $this->legacyAdministration(__FUNCTION__); }
    public function SaveSlavePass(string $url,string $pass): void { $this->legacyAdministration(__FUNCTION__); }
    public function UpdateUI(): void { $this->legacyAdministration(__FUNCTION__); }
    public function CheckDirectory(): void { echo $this->CheckLocalSecretStore(); }
    public function GenerateToken(): void { $this->legacyAdministration(__FUNCTION__); }
    public function LoadVault(): void { $this->legacyAdministration(__FUNCTION__); }
    public function EncryptAndSave(string $jsonInput): void { $this->legacyValue(__FUNCTION__,[$jsonInput]); }
    public function ClearVault(): void { $this->SetBuffer('LegacyUI',''); }
    public function RevokePortalSessions(): void { $this->legacyAdministration(__FUNCTION__); }
    public function ResetPortalLoginPageRateLimit(): void { $this->legacyAdministration(__FUNCTION__); }
    public function ResetPortalChallengeRateLimit(): void { $this->legacyAdministration(__FUNCTION__); }
    public function RemoveAllPasskeys(): void { $this->legacyAdministration(__FUNCTION__); }
    public function SyncSlaves(): void { $this->legacyAdministration(__FUNCTION__); }
    public function CheckLocalSecretStore(): string { return $this->GetNativeInfo(); }
    public function InitializeSlaveSecretStore(string $syncToken): bool { $this->legacyAdministration(__FUNCTION__);return false; }
}
