<?php
declare(strict_types=1);
require_once __DIR__.'/LegacyAPI.php';

/** Symcon public method signatures matching the old SEC application interface. */
trait SecretsBackendLegacyRuntime
{
    private function legacyService(int $source): SecretsBackendLegacyAPI
    {
        $this->nativeApplication();
        return new SecretsBackendLegacyAPI($this->nativeStore(),$source,function(array $permission)use($source):void{
            if(!IPS_InstanceExists($source)||IPS_HasChanges($source))throw new RuntimeException('Legacy source is unavailable or has unapplied settings.');
            if($source===$this->InstanceID)return;
            $info=IPS_GetInstance($source);
            if(($info['InstanceStatus']??0)!==102||strtoupper($info['ModuleInfo']['ModuleID']??'')!==SecretsBackendLegacyImport::MODULE
                ||IPS_GetProperty($source,'NativeBackendInstanceID')!==$this->InstanceID
                ||IPS_GetProperty($source,'OperationMode')!==$permission['mode'])throw new RuntimeException('Legacy instance/backend/role binding differs from its approval.');
        });
    }
    /** Permission/readiness metadata only: no key names, values, paths or exception text. */
    public function GetLegacyAPIStatus(): string
    {
        $out=['backend'=>$this->InstanceID,'readAllowed'=>false,'grantPresent'=>false,'grantEnabled'=>false,'readApproved'=>false,'writesFrozen'=>null,'code'=>'BACKEND_UNAVAILABLE'];
        try{
            if(!$this->ReadPropertyBoolean('Enabled'))$out['code']='BACKEND_DISABLED';
            elseif(IPS_HasChanges($this->InstanceID))$out['code']='PENDING_SETTINGS';
            else{
                $service=$this->legacyService($this->InstanceID);$state=$this->nativeStore()->read()['state'];
                $p=$state['native']['legacyAccess'][(string)$this->InstanceID]??null;
                if(is_array($p))$out=array_replace($out,['grantPresent'=>true,'grantEnabled'=>($p['enabled']??false)===true,'readApproved'=>($p['read']??false)===true,'writesFrozen'=>($p['frozen']??true)===true]);
                if(!is_array($p))$out['code']='READ_GRANT_MISSING';
                elseif(!$out['grantEnabled'])$out['code']='READ_GRANT_DISABLED';
                elseif(($p['treeId']??'')!==$state['native']['globalTreeId'])$out['code']='GLOBAL_IDENTITY_CHANGED';
                elseif(!$out['readApproved'])$out['code']='READ_NOT_APPROVED';
                else{$service->permission($state,'read');$out['readAllowed']=true;$out['code']='READ_ALLOWED';}
            }
        }catch(Throwable $error){$out['code']='BACKEND_UNAVAILABLE';}
        $out['meaning']=match($out['code']){
            'READ_ALLOWED'=>'Application read access is approved. An empty successful GetKeys result means no available top-level Global application records; it does not list Local records or count nested values.',
            'READ_GRANT_MISSING'=>'No application read grant is approved for this backend instance. Browser administrator sign-in does not authorize a local PHP script.',
            'READ_GRANT_DISABLED'=>'The application access grant for this backend is disabled.',
            'READ_NOT_APPROVED'=>'The backend access grant does not include reading application secrets.',
            'GLOBAL_IDENTITY_CHANGED'=>'The grant belongs to a different Global tree identity and needs a fresh exact approval.',
            'BACKEND_DISABLED'=>'The new backend is disabled.',
            'PENDING_SETTINGS'=>'Backend settings have unapplied changes.',
            default=>'The native backend could not validate its current storage, runtime or pinned security configuration. No automatic recovery or permission change was attempted.'};
        $out['nextStep']=in_array($out['code'],['READ_GRANT_MISSING','READ_GRANT_DISABLED','READ_NOT_APPROVED','GLOBAL_IDENTITY_CHANGED'],true)
            ?'In Automation access -> Existing SEC applications, approve this backend ID with Read application secrets. For a read-only script leave write, bulk and protected-page rights off and keep writes frozen.'
            :($out['code']==='READ_ALLOWED'?'Run the read again. If it warns, the operation failed after this status check; do not treat its fallback [] as an empty vault.':'Check the backend status and applied settings.');
        return SecretsBackendCodec::json($out);
    }
    public function CallLegacyAPI(int $SourceInstanceID,string $Method,string $ArgumentsJSON): string
    {
        if(!in_array($Method,SecretsBackendLegacyAPI::DATA_METHODS,true))throw new RuntimeException('This legacy administration operation requires its native approved workflow.');
        if(strlen($ArgumentsJSON)>SecretsBackendNativePlatform::budget())throw new InvalidArgumentException('Legacy arguments exceed the native memory budget.');
        $args=json_decode($ArgumentsJSON,true,32,JSON_THROW_ON_ERROR);if(!is_array($args)||!array_is_list($args))throw new InvalidArgumentException('Legacy arguments must be a positional array.');
        $counts=['GetKeys'=>0,'GetSecret'=>1,'GetExplorerFields'=>1,'SetRecordFields'=>3,'ExportLocalSecrets'=>0,'ImportLocalSecrets'=>1,'EncryptAndSave'=>1];
        if(count($args)!==$counts[$Method])throw new InvalidArgumentException('Legacy argument count differs.');
        $failure=null;
        try{$service=$this->legacyService($SourceInstanceID);$value=$service->{$Method}(...$args);$output=$service->output();$this->SetBuffer('LegacyAPILastError','');}
        catch(Throwable $error){
            $output=$Method==='EncryptAndSave'?'❌ Error: Encryption failed.':'';
            $failure=['code'=>'LEGACY_API_REFUSED','meaning'=>'The read/write request failed authorization or backend validation. The fallback value does not prove an empty vault.'];
            $this->SetBuffer('LegacyAPILastError','Legacy '.$Method.' refused; check approved access, binding, freeze, Global conflicts and backend readiness.');
            $value=match($Method){'GetKeys'=>'[]','GetExplorerFields'=>[],'SetRecordFields','ImportLocalSecrets'=>false,'EncryptAndSave'=>null,default=>''};
        }
        return SecretsBackendCodec::json(['value'=>$value,'output'=>$output??'','error'=>$failure]);
    }
    private function legacyValue(string $method,array $args)
    {
        $result=json_decode($this->CallLegacyAPI($this->InstanceID,$method,SecretsBackendCodec::json($args)),true,32,JSON_THROW_ON_ERROR);if(($result['output']??'')!=='')echo $result['output'];
        if(($result['error']??null)!==null&&in_array($method,['GetKeys','GetSecret','GetExplorerFields','ExportLocalSecrets'],true))trigger_error('SecretsBackend: legacy read refused. Run SECB_GetLegacyAPIStatus('.$this->InstanceID.') for permission and backend diagnostics; the fallback value is not evidence of an empty vault.',E_USER_WARNING);
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
            if($SourceInstanceID!==$this->InstanceID&&IPS_GetProperty($SourceInstanceID,'PortalEnabled')!==true)return false;
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
        if($SourceInstanceID!==$this->InstanceID&&IPS_GetProperty($SourceInstanceID,'PortalEnabled')!==true)throw new RuntimeException('Protected-page access is disabled on this instance.');
        return $origin.'/hook/secrets_frontend_'.$this->ReadPropertyInteger('FrontendInstanceID').'#legacy-return='.rawurlencode($ReturnPath);
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
