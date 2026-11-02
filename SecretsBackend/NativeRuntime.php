<?php
declare(strict_types=1);
require_once __DIR__ . '/NativePeer.php';

trait SecretsBackendNativeRuntime
{
    private function nativePeer(?SecretsBackendNativeStore $store=null): SecretsBackendNativePeer
    {
        return new SecretsBackendNativePeer($store??$this->nativeStore(),$this->ReadPropertyString('AdminOrigin').'/hook/secrets_peer_'.$this->InstanceID,
            function(array $target,string $bytes):string{
                $id=(int)$target['backend'];
                if(function_exists('SECB_GetNativePublicDescriptor')&&function_exists('SECB_ReceiveNativePeer')&&IPS_InstanceExists($id)
                    &&strtoupper(IPS_GetInstance($id)['ModuleInfo']['ModuleID']??'')==='{52165EDD-B2C0-40EC-8A59-42A97319B6E2}'){
                    try{$local=json_decode(SECB_GetNativePublicDescriptor($id),true);}catch(Throwable $ignored){$local=null;}
                    if(is_array($local)&&SecretsBackendNativePeer::authority($local)===SecretsBackendNativePeer::authority($target))return SECB_ReceiveNativePeer($id,$bytes);
                }
                return self::nativeHTTPS($target['endpoint'],$bytes);
            });
    }
    public static function nativeHTTPS(string $endpoint,string $bytes): string
    {
        SecretsBackendNativePeer::endpoint($endpoint);
        if(!function_exists('curl_init'))throw new SecretsBackendNativePeerDeliveryFailure('transport');
        $h=curl_init($endpoint);$response='';$tooLarge=false;
        try{
            curl_setopt_array($h,[CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$bytes,CURLOPT_HTTPHEADER=>['Content-Type: application/json','Accept: application/json'],
                CURLOPT_FOLLOWLOCATION=>false,CURLOPT_CONNECTTIMEOUT_MS=>1500,CURLOPT_TIMEOUT_MS=>4500,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,
                CURLOPT_WRITEFUNCTION=>static function($handle,string $chunk)use(&$response,&$tooLarge):int{if(strlen($response)+strlen($chunk)>65536){$tooLarge=true;return 0;}$response.=$chunk;return strlen($chunk);}]);
            if(defined('CURLOPT_PROTOCOLS_STR'))curl_setopt($h,CURLOPT_PROTOCOLS_STR,'https');elseif(defined('CURLOPT_PROTOCOLS'))curl_setopt($h,CURLOPT_PROTOCOLS,CURLPROTO_HTTPS);
            $ok=curl_exec($h);$code=(int)curl_errno($h);$http=(int)curl_getinfo($h,CURLINFO_RESPONSE_CODE);
            if($ok===false||$http!==200)throw SecretsBackendNativePeerDeliveryFailure::transport($code,$http,$tooLarge);
            return $response;
        }finally{curl_close($h);}
    }
    public function GetNativePublicDescriptor(): string
    {
        if(!$this->nativeInitialized())throw new RuntimeException('Native vault is not initialized.');return SecretsBackendCodec::json($this->nativePeer()->descriptor());
    }
    public function ReceiveNativePeer(string $EnvelopeJSON): string
    {
        if(!$this->ReadPropertyBoolean('Enabled')||!$this->nativeInitialized())throw new RuntimeException('Native peer receiver is disabled.');
        $this->nativeApplication(); // Verify the pinned active security profile before accepting peer effects.
        return $this->nativePeer()->receive($EnvelopeJSON);
    }
    public function RunNativeJobs(): string
    {
        $lock='SECB.NativeJobs.'.$this->InstanceID;if(!IPS_SemaphoreEnter($lock,1))return '[]';
        try{if(!$this->ReadPropertyBoolean('Enabled')||!$this->nativeInitialized())return '[]';$this->nativeApplication();$store=$this->nativeStore();$peer=$this->nativePeer($store);$result=$peer->dispatch(1);$effects=new SecretsBackendNativeEffects($store,static fn($effect)=>self::nativeProviderHTTPS($effect));$result[]=$effects->tick();return SecretsBackendCodec::json($result);}
        catch(Throwable $e){$this->debug('request-rejected');return '[{"status":"RECOVERY_REQUIRED"}]';}
        finally{IPS_SemaphoreLeave($lock);}
    }
    public static function nativeProviderHTTPS(array $effect): array
    {
        if(!function_exists('curl_init'))throw new RuntimeException('The supplied PHP has no bounded provider HTTPS transport.');
        $url=parse_url($effect['endpoint']);if(!is_array($url)||($url['scheme']??'')!=='https'||isset($url['user'])||isset($url['pass']))throw new RuntimeException('Invalid protected provider endpoint.');
        $h=curl_init($effect['endpoint']);$body='';try{
            curl_setopt_array($h,[CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$effect['body'],CURLOPT_HTTPHEADER=>$effect['headers'],CURLOPT_FOLLOWLOCATION=>false,CURLOPT_CONNECTTIMEOUT_MS=>1500,CURLOPT_TIMEOUT_MS=>4500,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_WRITEFUNCTION=>static function($handle,string $chunk)use(&$body):int{if(strlen($body)+strlen($chunk)>65536)return 0;$body.=$chunk;return strlen($chunk);}]);
            if(defined('CURLOPT_PROTOCOLS_STR'))curl_setopt($h,CURLOPT_PROTOCOLS_STR,'https');elseif(defined('CURLOPT_PROTOCOLS'))curl_setopt($h,CURLOPT_PROTOCOLS,CURLPROTO_HTTPS);
            if(curl_exec($h)===false)throw new RuntimeException('Provider effect outcome is unknown.');return ['status'=>(int)curl_getinfo($h,CURLINFO_RESPONSE_CODE),'body'=>$body];
        }finally{curl_close($h);}
    }
    private function syncNativePeerHook(bool $enabled): void
    {
        $lock='SECF.WebhookControl';if(!IPS_SemaphoreEnter($lock,1000))throw new RuntimeException('Webhook registry is busy.');
        try{
            $ids=IPS_GetInstanceListByModuleID('{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}');if(count($ids)!==1||IPS_HasChanges((int)$ids[0]))throw new RuntimeException('Use one WebhookControl with applied settings.');
            $control=(int)$ids[0];$hooks=json_decode(IPS_GetProperty($control,'Hooks'),true,16,JSON_THROW_ON_ERROR);if(!is_array($hooks)||!array_is_list($hooks)||count($hooks)>2048)throw new RuntimeException('Invalid webhook registry.');
            $path='/hook/secrets_peer_'.$this->InstanceID;$out=[];$found=false;
            foreach($hooks as$hook){if(($hook['Hook']??'')===$path){if((int)($hook['TargetID']??0)!==$this->InstanceID)throw new RuntimeException('Native peer hook belongs to another object.');if($enabled){$out[]=$hook;$found=true;}}else$out[]=$hook;}
            if($enabled&&!$found)$out[]=['Hook'=>$path,'TargetID'=>$this->InstanceID];
            if($out!==$hooks){IPS_SetProperty($control,'Hooks',SecretsBackendCodec::json($out));IPS_ApplyChanges($control);}
        }finally{IPS_SemaphoreLeave($lock);}
    }
    // Symcon generates an untyped HookInstance override, so this signature stays untyped.
    protected function ProcessHookData()
    {
        header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store');header('X-Content-Type-Options: nosniff');
        try{
            $path='/hook/secrets_peer_'.$this->InstanceID;$uri=(string)($_SERVER['REQUEST_URI']??$path);
            if(($_SERVER['REQUEST_METHOD']??'GET')!=='POST'||parse_url($uri,PHP_URL_PATH)!==$path||($_SERVER['QUERY_STRING']??'')!=='')throw new RuntimeException('Only the fixed native POST endpoint is supported.');
            $types=[];foreach(['CONTENT_TYPE','HTTP_CONTENT_TYPE']as$key){$value=trim((string)($_SERVER[$key]??''));if($value!=='')$types[strtolower(trim(explode(';',$value,2)[0]))]=true;}
            if(count($types)!==1||!isset($types['application/json']))throw new RuntimeException('Native JSON envelope required.');
            $limit=SecretsBackendNativePlatform::budget()*2+65536;$bytes=file_get_contents('php://input',false,null,0,$limit+1);
            if(!is_string($bytes)||strlen($bytes)>$limit)throw new RuntimeException('Native envelope exceeds its bound.');
            $reply=$this->ReceiveNativePeer($bytes);http_response_code(200);echo $reply;
        }catch(Throwable $e){http_response_code(403);echo '{"error":"Native peer request refused."}';}
    }
    private function nativeCapability(array $state,string $token,string $scope,array $path,bool $write): array
    {
        SecretsBackendCodec::unb64($token,32);SecretsBackendTree::path($path);$hash=hash('sha256',$token);
        foreach($state['native']['machines']as$grant){
            if(!$grant['active']||!hash_equals($grant['hash'],$hash))continue;
            $target=SecretsBackendNativeOperations::machineTarget($state,$scope);
            if($grant['scope']!==$scope||($grant['treeId']??'')!==$target['treeId']||($write&&(!$grant['write']||!$target['writable']))||count($path)<count($grant['path'])||array_slice($path,0,count($grant['path']))!==$grant['path'])throw new RuntimeException('Machine capability does not permit this exact scope/path/action.');
            return $grant;
        }throw new RuntimeException('Machine capability is missing or revoked.');
    }
    public function ReadNativeSecret(string $CapabilityToken,string $Scope,string $PathJSON): string
    {
        if(!$this->ReadPropertyBoolean('Enabled')||!$this->nativeInitialized())throw new RuntimeException('Native vault is disabled.');
        $this->nativeApplication();
        if(strlen($Scope)>48||strlen($PathJSON)>4096)throw new RuntimeException('Invalid machine path.');$path=json_decode($PathJSON,true,32,JSON_THROW_ON_ERROR);if(!is_array($path))throw new RuntimeException('Path must be an array.');
        $store=$this->nativeStore();$store->rate('machine:'.hash('sha256',$CapabilityToken),120);$current=$store->read();$grant=$this->nativeCapability($current['state'],$CapabilityToken,$Scope,$path,false);
        $store->authorize('machine-read',hash('sha256',$Scope.':'.$PathJSON),$current,function(array $checked)use($CapabilityToken,$Scope,$path):void{$this->nativeCapability($checked['state'],$CapabilityToken,$Scope,$path,false);},['action'=>'machine-read','actor'=>$grant['id'],'target'=>$Scope.':'.$PathJSON]);
        $target=SecretsBackendNativeOperations::machineTarget($current['state'],$Scope);
        return SecretsBackendCodec::json(['value'=>SecretsBackendTree::value(SecretsBackendTree::at($target['node'],$path)),'revision'=>$target['revision']]);
    }
    public function WriteNativeSecret(string $CapabilityToken,string $Scope,string $PathJSON,string $ValueJSON,string $ExpectedRevision,string $Sequence,string $OperationID): string
    {
        if(!$this->ReadPropertyBoolean('Enabled')||!$this->nativeInitialized())throw new RuntimeException('Native vault is disabled.');
        $this->nativeApplication();
        if(strlen($Scope)>48||strlen($PathJSON)>4096||strlen($ValueJSON)>49152)throw new RuntimeException('Invalid bounded machine write.');
        $path=json_decode($PathJSON,true,32,JSON_THROW_ON_ERROR);if(!is_array($path))throw new RuntimeException('Path must be an array.');SecretsBackendTree::path($path);SecretsBackendNativePeer::uuid($OperationID);SecretsBackendNativePeer::decimal($Sequence);
        $node=SecretsBackendTree::parse($ValueJSON);$store=$this->nativeStore();$store->rate('machine:'.hash('sha256',$CapabilityToken),120);$current=$store->read();$grant=$this->nativeCapability($current['state'],$CapabilityToken,$Scope,$path,true);
        $digest=hash('sha256',SecretsBackendNativeStore::canonical([$Scope,$path,$ValueJSON,$ExpectedRevision,$Sequence]));
        if(($grant['lastWriteId']??'')===$OperationID){if(($grant['lastWriteDigest']??'')!==$digest)throw new RuntimeException('Machine operation ID reused with different bytes.');return SecretsBackendCodec::json(['committed'=>true,'operationId'=>$OperationID,'sequence'=>$Sequence]);}
        $store->change($current['head'],$OperationID,$digest,function(array $s)use($CapabilityToken,$Scope,$path,$ExpectedRevision,$Sequence,$node,$OperationID,$digest):array{
            $g=$this->nativeCapability($s,$CapabilityToken,$Scope,$path,true);
            $target=SecretsBackendNativeOperations::machineTarget($s,$Scope);
            if($target['revision']!==$ExpectedRevision||$Sequence!==SecretsBackendCodec::increment($g['sequence']))throw new RuntimeException('Machine revision/sequence conflict.');
            if(!$target['writable'])throw new RuntimeException('The selected tree is frozen or owned by another vault.');
            if($target['kind']==='owned'){SecretsBackendTree::edit($s['native']['trees'][$target['treeId']]['node'],$path,$node,'replace');$s['native']['trees'][$target['treeId']]['revision']=SecretsBackendCodec::increment($target['revision']);$s=SecretsBackendNativePeer::queueOwned($s,$target['treeId']);}
            else SecretsBackendTree::edit($s['vault'][$Scope],$path,$node,'replace');
            $s['vault']['revision']=SecretsBackendCodec::increment($s['vault']['revision']);
            $s['native']['machines'][$g['id']]['sequence']=$Sequence;$s['native']['machines'][$g['id']]['lastWriteId']=$OperationID;$s['native']['machines'][$g['id']]['lastWriteDigest']=$digest;
            if($Scope==='global'){$s['stream']['globalRevision']=SecretsBackendCodec::increment($s['stream']['globalRevision']);$s=SecretsBackendNativePeer::queueGlobal($s);}return $s;
        },['action'=>'machine-write','actor'=>$grant['id'],'target'=>$Scope.':'.$PathJSON]);return SecretsBackendCodec::json(['committed'=>true,'operationId'=>$OperationID,'sequence'=>$Sequence]);
    }
}
