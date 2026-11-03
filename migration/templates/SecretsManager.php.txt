<?php
declare(strict_types=1);
/** Replacement-branch adapter: the original GUID and SEC prefix remain in module.json. */
class SecretsManager extends IPSModuleStrict
{
    public function Create(): void
    {
        parent::Create();
        $this->RegisterPropertyInteger('NativeBackendInstanceID',0);
        $this->RegisterAttributeString('NativeBackendBinding','');
        $this->RegisterPropertyInteger('OperationMode',0);
        $this->RegisterPropertyString('KeyFolderPath','');
        $this->RegisterPropertyInteger('PortalSessionLifetimeHours',72);
        $this->RegisterPropertyBoolean('PortalEnabled',false);
        $this->RegisterPropertyString('PortalOrigin','');
        $this->RegisterPropertyString('PortalBackupOrigin','');
        $this->RegisterPropertyInteger('PortalSessionLifetimeMinutes',60);
        $this->RegisterPropertyBoolean('PortalDebugEnabled',false);
        $this->RegisterPropertyString('HookUser','');
        $this->RegisterPropertyBoolean('AllowKeyTransport',false);
        $this->RegisterPropertyString('SlaveURLs','[]');
        $this->RegisterVariableString('Vault','Encrypted Vault');
        $this->RegisterVariableString('PortalDebugMessage','Portal debug (last event)');
    }
    private function backend(): int
    {
        $id=$this->ReadPropertyInteger('NativeBackendInstanceID');
        if(IPS_HasChanges($this->InstanceID)||$id<=0||!IPS_InstanceExists($id)||strtoupper(IPS_GetInstance($id)['ModuleInfo']['ModuleID']??'')!=='{52165EDD-B2C0-40EC-8A59-42A97319B6E2}')throw new RuntimeException('No ready native backend is bound. The old manager is disabled; no fallback exists.');
        $info=json_decode(SECB_GetNativeInfo($id),true,32,JSON_THROW_ON_ERROR);
        if(!($info['initialized']??false)||!($info['ready']??false)||!is_string($info['vaultId']??null))throw new RuntimeException('The native backend is not ready.');
        $raw=$this->ReadAttributeString('NativeBackendBinding');
        if($raw!==''){$pin=json_decode($raw,true,8,JSON_THROW_ON_ERROR);if(($pin['backend']??0)!==$id||($pin['vault']??'')!==$info['vaultId'])throw new RuntimeException('The pinned native vault changed; automatic reassignment is refused.');}
        else $this->WriteAttributeString('NativeBackendBinding',json_encode(['backend'=>$id,'vault'=>$info['vaultId']],JSON_THROW_ON_ERROR));
        return $id;
    }
    private function discoverBackend(): int
    {
        $pin=$this->ReadAttributeString('NativeBackendBinding');if($pin!==''){ $p=json_decode($pin,true,8,JSON_THROW_ON_ERROR);return (int)$p['backend']; }
        $ready=[];foreach(IPS_GetInstanceListByModuleID('{52165EDD-B2C0-40EC-8A59-42A97319B6E2}')as$id){
            try{if(IPS_HasChanges($id))continue;$info=json_decode(SECB_GetNativeInfo((int)$id),true,32,JSON_THROW_ON_ERROR);if(($info['initialized']??false)&&($info['ready']??false))$ready[]=(int)$id;}catch(Throwable $ignored){}
        }
        if(count($ready)!==1)throw new RuntimeException('Choose the intended native backend by name when several are ready. No old manager fallback is available.');return $ready[0];
    }
    public function GetReplacementInfo(): string
    {
        $out=['engine'=>'native-only','oldImplementationEnabled'=>false,'oldStorageUsed'=>false,'oldSynchronizationEnabled'=>false,'instance'=>$this->InstanceID,'ready'=>false];
        try{$out['backend']=$this->backend();$out['ready']=true;}catch(Throwable $error){$out['reason']='Native backend is unavailable, ambiguous or differs from its pinned vault. The old manager remains disabled.';}
        return json_encode($out,JSON_THROW_ON_ERROR);
    }
    public function ApplyChanges(): void
    {
        parent::ApplyChanges();
        try{
            if($this->ReadPropertyInteger('NativeBackendInstanceID')===0){$id=$this->discoverBackend();IPS_SetProperty($this->InstanceID,'NativeBackendInstanceID',$id);IPS_ApplyChanges($this->InstanceID);return;}
            $this->backend();$path='/hook/secrets_'.$this->InstanceID;
            if(!IPS_SemaphoreEnter('SECF.WebhookControl',1000))throw new RuntimeException('Webhook registry busy.');
            try{
                $ids=IPS_GetInstanceListByModuleID('{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}');if(count($ids)!==1||IPS_HasChanges($ids[0]))throw new RuntimeException('One applied Webhook Control is required.');
                $hooks=json_decode(IPS_GetProperty($ids[0],'Hooks'),true,16,JSON_THROW_ON_ERROR);if(!is_array($hooks)||!array_is_list($hooks)||count($hooks)>2048)throw new RuntimeException('Invalid webhook registry.');
                $found=false;foreach($hooks as$hook)if(($hook['Hook']??'')===$path){if(($hook['TargetID']??0)!==$this->InstanceID)throw new RuntimeException('Legacy hook belongs to another instance.');$found=true;}
                if(!$found){$hooks[]=['Hook'=>$path,'TargetID'=>$this->InstanceID];IPS_SetProperty($ids[0],'Hooks',json_encode($hooks,JSON_THROW_ON_ERROR));IPS_ApplyChanges($ids[0]);}
            }finally{IPS_SemaphoreLeave('SECF.WebhookControl');}
            $this->SetStatus(102);
        }catch(Throwable $error){$this->SetStatus(200);}
    }
    public function GetConfigurationForm(): string
    {
        return json_encode(['elements'=>[
            ['type'=>'Label','caption'=>'Native Secrets manager using the preserved SEC interface and instance ID. The old implementation is disabled. Its saved files and Vault variable are inactive rollback material only.'],
            ['type'=>'SelectInstance','name'=>'NativeBackendInstanceID','caption'=>'New Secrets backend','validModules'=>['{52165EDD-B2C0-40EC-8A59-42A97319B6E2}']],
            ['type'=>'Label','caption'=>'A unique ready native backend is selected automatically and its vault identity is pinned. With several, select the intended backend by name. All data, login and synchronization come from the native system. Restore the previous branch and saved configuration for rollback.'],
        ],'actions'=>[['type'=>'Label','caption'=>'Use the new administration page for setup, permissions, passkeys and peer connections.']]],JSON_THROW_ON_ERROR);
    }
    private function call(string $method,array $args)
    {
        try{
            $backend=$this->backend();$raw=SECB_CallLegacyAPI($backend,$backend,$method,json_encode($args,JSON_THROW_ON_ERROR));
            $result=json_decode($raw,true,32,JSON_THROW_ON_ERROR);
        }catch(Throwable $error){
            $result=['value'=>match($method){'GetKeys'=>'[]','GetExplorerFields'=>[],'SetRecordFields','ImportLocalSecrets'=>false,'EncryptAndSave'=>null,default=>''},'output'=>$method==='EncryptAndSave'?'❌ Error: Encryption failed.':'','error'=>true];
        }
        if(($result['output']??'')!=='')echo $result['output'];
        if(($result['error']??null)!==null&&in_array($method,['GetKeys','GetSecret','GetExplorerFields','ExportLocalSecrets'],true))trigger_error('SecretsManager: new backend refused the legacy read. Check its approved application access and backend status; the fallback value is not evidence of an empty vault.',E_USER_WARNING);
        return $result['value'];
    }
    public function GetKeys(): string { return $this->call(__FUNCTION__,[]); }
    public function GetSecret(string $ident): string { return $this->call(__FUNCTION__,[$ident]); }
    public function SetRecordFields(string $path,array $fields,string $scope): bool { return $this->call(__FUNCTION__,[$path,$fields,$scope]); }
    public function ExportLocalSecrets(): string { return $this->call(__FUNCTION__,[]); }
    public function ImportLocalSecrets(string $json): bool { return $this->call(__FUNCTION__,[$json]); }
    public function GetExplorerFields(string $ident): array { return $this->call(__FUNCTION__,[$ident]); }
    private static function server(): string
    {
        return json_encode(array_intersect_key($_SERVER,array_flip(['HTTP_HOST','HTTP_COOKIE','REMOTE_ADDR','HTTPS','REQUEST_SCHEME','HTTP_X_FORWARDED_HOST','HTTP_X_FORWARDED_PROTO','HTTP_FORWARDED'])),JSON_THROW_ON_ERROR);
    }
    public function IsPortalAuthenticated(): bool
    {
        try{return SECB_IsNativePortalAuthenticated($this->backend());}catch(Throwable $error){return false;}
    }
    protected function ProcessHookData(): void
    {
        header('Cache-Control: no-store');header('X-Content-Type-Options: nosniff');header('Referrer-Policy: no-referrer');
        try{
            if(($_SERVER['REQUEST_METHOD']??'GET')!=='GET')throw new RuntimeException('Legacy sync and credential endpoints are unavailable.');
            $path=parse_url($_SERVER['REQUEST_URI']??'',PHP_URL_PATH);if($path!=='/hook/secrets_'.$this->InstanceID)throw new RuntimeException('Invalid legacy hook.');
            if(array_diff(array_keys($_GET),['portal','return'])||isset($_GET['portal'])&&$_GET['portal']!=='1')throw new RuntimeException('Legacy administrative/sync requests are unavailable.');
            $return=$_GET['return']??'';if(!is_string($return)||($return!==''&&(!preg_match('~^/hook/[A-Za-z0-9_-]+$~D',$return)||preg_match('~^/hook/secrets(?:_frontend|_peer)?_~',$return))))throw new RuntimeException('Invalid return page.');
            $url=SECB_GetNativePortalLoginURL($this->backend(),$return,self::server());
            header('Location: '.($return!==''&&$this->IsPortalAuthenticated()?$return:$url));http_response_code(303);
        }catch(Throwable $error){http_response_code(403);echo 'Access refused. Use the new Secrets administration page.';}
    }
    private function denied(): void { throw new RuntimeException('This legacy administration operation requires the new approved administration workflow.'); }
    public function SaveAuthToken(string $token): void { $this->denied(); }
    public function ShowToken(): void { $this->denied(); }
    public function SaveHookPass(string $pass): void { $this->denied(); }
    public function SaveSlavePass(string $url,string $pass): void { $this->denied(); }
    public function UpdateUI(): void { $this->denied(); }
    public function CheckDirectory(): void { echo $this->CheckLocalSecretStore(); }
    public function GenerateToken(): void { $this->denied(); }
    public function LoadVault(): void { $this->denied(); }
    public function EncryptAndSave(string $jsonInput): void { $this->call(__FUNCTION__,[$jsonInput]); }
    public function ClearVault(): void { $this->SetBuffer('LegacyUI',''); }
    public function RevokePortalSessions(): void { $this->denied(); }
    public function ResetPortalLoginPageRateLimit(): void { $this->denied(); }
    public function ResetPortalChallengeRateLimit(): void { $this->denied(); }
    public function RemoveAllPasskeys(): void { $this->denied(); }
    public function SyncSlaves(): void { $this->denied(); }
    public function CheckLocalSecretStore(): string { return SECB_GetNativeInfo($this->backend()); }
    public function InitializeSlaveSecretStore(string $syncToken): bool { $this->denied();return false; }
    public function RequestAction($Ident,$Value): void { $this->denied(); }
}
