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
        $this->RegisterTimer('NativeBindingRetry',0,'SEC_RetryNativeBinding($_IPS[\'TARGET\']);');
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
    private function binding(): ?array
    {
        $raw=$this->ReadAttributeString('NativeBackendBinding');if($raw==='')return null;
        try{$pin=json_decode($raw,true,8,JSON_THROW_ON_ERROR);}catch(Throwable $error){throw new RuntimeException('Invalid native binding.',1008);}
        if(!is_array($pin)||!is_int($pin['backend']??null)||$pin['backend']<=0||!is_string($pin['vault']??null)||$pin['vault']==='')throw new RuntimeException('Invalid native binding.',1008);
        return $pin;
    }
    private function backend(): int
    {
        if(IPS_HasChanges($this->InstanceID))throw new RuntimeException('Apply or discard pending instance settings.',1001);
        $id=$this->ReadPropertyInteger('NativeBackendInstanceID');if($id===0)$id=$this->discoverBackend();
        if($id<=0||!IPS_InstanceExists($id)||strtoupper(IPS_GetInstance($id)['ModuleInfo']['ModuleID']??'')!=='{52165EDD-B2C0-40EC-8A59-42A97319B6E2}')throw new RuntimeException('The selected native backend is unavailable.',1003);
        $pin=$this->binding();if($pin!==null&&$pin['backend']!==$id)throw new RuntimeException('The pinned native backend changed.',1005);
        if(!function_exists('SECB_GetNativeInfo'))throw new RuntimeException('Native backend API is unavailable.',1009);
        $info=json_decode(SECB_GetNativeInfo($id),true,32,JSON_THROW_ON_ERROR);
        if(!($info['initialized']??false)||!($info['ready']??false)||!is_string($info['vaultId']??null))throw new RuntimeException('The native backend is not ready.',1004);
        if($pin!==null&&$pin['vault']!==$info['vaultId'])throw new RuntimeException('The pinned native vault changed.',1005);
        if($pin===null)$this->WriteAttributeString('NativeBackendBinding',json_encode(['backend'=>$id,'vault'=>$info['vaultId']],JSON_THROW_ON_ERROR));
        return $id;
    }
    private function discoverBackend(): int
    {
        $pin=$this->binding();if($pin!==null)return $pin['backend'];
        if(!function_exists('SECB_GetNativeInfo'))throw new RuntimeException('Native backend API is unavailable.',1009);
        $ready=[];foreach(IPS_GetInstanceListByModuleID('{52165EDD-B2C0-40EC-8A59-42A97319B6E2}')as$id){
            try{if(IPS_HasChanges($id))continue;$info=json_decode(SECB_GetNativeInfo((int)$id),true,32,JSON_THROW_ON_ERROR);if(($info['initialized']??false)&&($info['ready']??false))$ready[]=(int)$id;}catch(Throwable $ignored){}
        }
        if(!$ready)throw new RuntimeException('No ready native backend; automatic retry is pending.',1006);
        if(count($ready)!==1)throw new RuntimeException('Choose the intended native backend by name.',1007);
        return $ready[0];
    }
    private static function failureCode(Throwable $error): string
    {
        return match($error->getCode()){
            1001=>'PENDING_SETTINGS',1003=>'BACKEND_UNAVAILABLE',1004=>'BACKEND_NOT_READY',1005=>'PINNED_VAULT_CHANGED',
            1006=>'NO_READY_BACKEND',1007=>'AMBIGUOUS_BACKENDS',1008=>'INVALID_BINDING',1009=>'BACKEND_API_UNAVAILABLE',default=>'BACKEND_CALL_FAILED'};
    }
    public function GetReplacementInfo(): string
    {
        $out=['engine'=>'native-only','oldImplementationEnabled'=>false,'oldStorageUsed'=>false,'oldSynchronizationEnabled'=>false,'instance'=>$this->InstanceID,'ready'=>false,
            'configuredBackend'=>$this->ReadPropertyInteger('NativeBackendInstanceID'),'pendingChanges'=>IPS_HasChanges($this->InstanceID),'code'=>'BACKEND_UNAVAILABLE'];
        try{$out['backend']=$this->backend();$out['ready']=true;$out['code']='BOUND';
            if(function_exists('SECB_GetLegacyAPIStatus')){try{$out['access']=json_decode(SECB_GetLegacyAPIStatus($out['backend']),true,32,JSON_THROW_ON_ERROR);}catch(Throwable $ignored){$out['access']=['code'=>'DIAGNOSTICS_UNAVAILABLE'];}}
        }catch(Throwable $error){$out['code']=self::failureCode($error);}
        $last=json_decode($this->GetBuffer('LegacyAPILastFailure'),true);if(is_array($last))$out['lastFailure']=$last;
        return json_encode($out,JSON_THROW_ON_ERROR);
    }
    public function RetryNativeBinding(): void { $this->ApplyChanges(); }
    public function ApplyChanges(): void
    {
        parent::ApplyChanges();$this->SetTimerInterval('NativeBindingRetry',0);
        try{
            // Automatic binding lives in an attribute; never change/apply our own properties recursively.
            $this->backend();$path='/hook/secrets_'.$this->InstanceID;
            if(!IPS_SemaphoreEnter('SECF.WebhookControl',1000))throw new RuntimeException('Webhook registry busy.');
            try{
                $ids=IPS_GetInstanceListByModuleID('{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}');if(count($ids)!==1||IPS_HasChanges($ids[0]))throw new RuntimeException('One applied Webhook Control is required.');
                $hooks=json_decode(IPS_GetProperty($ids[0],'Hooks'),true,16,JSON_THROW_ON_ERROR);if(!is_array($hooks)||!array_is_list($hooks)||count($hooks)>2048)throw new RuntimeException('Invalid webhook registry.');
                $found=false;foreach($hooks as$hook)if(($hook['Hook']??'')===$path){if(($hook['TargetID']??0)!==$this->InstanceID)throw new RuntimeException('Legacy hook belongs to another instance.');$found=true;}
                if(!$found){$hooks[]=['Hook'=>$path,'TargetID'=>$this->InstanceID];IPS_SetProperty($ids[0],'Hooks',json_encode($hooks,JSON_THROW_ON_ERROR));IPS_ApplyChanges($ids[0]);}
            }finally{IPS_SemaphoreLeave('SECF.WebhookControl');}
            $this->SetStatus(102);
        }catch(Throwable $error){$this->SetStatus(200);if(!in_array($error->getCode(),[1001,1005,1007,1008],true))$this->SetTimerInterval('NativeBindingRetry',5000);}
    }
    public function GetConfigurationForm(): string
    {
        $info=json_decode($this->GetReplacementInfo(),true);$state=$info['code'].(isset($info['backend'])?' · backend '.$info['backend']:'');if(isset($info['access']['code']))$state.=' · '.$info['access']['code'];
        return json_encode(['elements'=>[
            ['type'=>'Label','caption'=>'Native connection: '.$state],
            ['type'=>'Label','caption'=>'Native Secrets manager using the preserved SEC interface and instance ID. The old implementation is disabled. Its saved files and Vault variable are inactive rollback material only.'],
            ['type'=>'SelectInstance','name'=>'NativeBackendInstanceID','caption'=>'New Secrets backend','validModules'=>['{52165EDD-B2C0-40EC-8A59-42A97319B6E2}']],
            ['type'=>'Label','caption'=>'A unique ready native backend is selected automatically and its vault identity is pinned. With several, select the intended backend by name. All data, login and synchronization come from the native system. Restore the previous branch and saved configuration for rollback.'],
        ],'actions'=>[['type'=>'Button','caption'=>'Show native connection status','onClick'=>'echo SEC_GetReplacementInfo($id);'],['type'=>'Label','caption'=>'Use the new administration page for setup, permissions, passkeys and peer connections.']]],JSON_THROW_ON_ERROR);
    }
    private function failedRead(string $method,string $code): void
    {
        if(!preg_match('/^[A-Z_]{1,48}$/D',$code))$code='LEGACY_API_REFUSED';
        $this->SetBuffer('LegacyAPILastFailure',json_encode(['method'=>$method,'code'=>$code,'at'=>time()],JSON_THROW_ON_ERROR));
        $lock='SEC.LegacyAPILog.'.$this->InstanceID;if(!IPS_SemaphoreEnter($lock,1))return;
        try{if((int)$this->GetBuffer('LegacyAPILogAt')>time()-60)return;$this->SetBuffer('LegacyAPILogAt',(string)time());
            if(function_exists('IPS_LogMessage'))IPS_LogMessage('SecretsManager '.$this->InstanceID,'Application read refused ('.$code.'). Run SEC_GetReplacementInfo('.$this->InstanceID.'); fallback values do not prove an empty vault.');
        }catch(Throwable $ignored){}finally{IPS_SemaphoreLeave($lock);}
    }
    private function call(string $method,array $args)
    {
        try{
            $backend=$this->backend();$raw=SECB_CallLegacyAPI($backend,$backend,$method,json_encode($args,JSON_THROW_ON_ERROR));
            $result=json_decode($raw,true,32,JSON_THROW_ON_ERROR);if(!is_array($result)||!array_key_exists('value',$result))throw new RuntimeException('Invalid native API response.');
        }catch(Throwable $error){
            $result=['value'=>match($method){'GetKeys'=>'[]','GetExplorerFields'=>[],'SetRecordFields','ImportLocalSecrets'=>false,'EncryptAndSave'=>null,default=>''},'output'=>$method==='EncryptAndSave'?'❌ Error: Encryption failed.':'','error'=>['code'=>self::failureCode($error)]];
        }
        if($method==='EncryptAndSave'&&($result['output']??'')!=='')echo $result['output'];
        if(($result['error']??null)!==null&&in_array($method,['GetKeys','GetSecret','GetExplorerFields','ExportLocalSecrets'],true))$this->failedRead($method,$result['error']['code']??'LEGACY_API_REFUSED');
        elseif(($result['error']??null)===null)$this->SetBuffer('LegacyAPILastFailure','');
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
