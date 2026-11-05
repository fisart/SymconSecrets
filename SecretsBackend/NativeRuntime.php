<?php
declare(strict_types=1);
require_once __DIR__ . '/NativePeer.php';
require_once __DIR__ . '/NativeLegacyHTTPS.php';
require_once __DIR__.'/PeerWork.php';
require_once __DIR__.'/../SecretsFrontend/ConnectDiscovery.php';

trait SecretsBackendNativeRuntime
{
    private ?SecretsBackendPeerWork $peerWork=null;
    private float $peerRequestStarted=0.0;
    private function nativePeer(?SecretsBackendNativeStore $store=null,?string $origin=null): SecretsBackendNativePeer
    {
        $created=microtime(true);$requestWork=null;
        return new SecretsBackendNativePeer($store??$this->nativeStore(),($origin??$this->ReadPropertyString('AdminOrigin')).'/hook/secrets_peer_'.$this->InstanceID,
            function(array $target,string $bytes,array $policy=['mode'=>'strict'])use($created,&$requestWork):string{
                $id=(int)$target['backend'];
                if((json_decode($bytes,true,16)['kind']??'')!=='MESH_STATUS'&&function_exists('SECB_GetNativePublicDescriptor')&&function_exists('SECB_ReceiveNativePeer')&&IPS_InstanceExists($id)
                    &&strtoupper(IPS_GetInstance($id)['ModuleInfo']['ModuleID']??'')==='{52165EDD-B2C0-40EC-8A59-42A97319B6E2}'){
                    try{$local=json_decode(SECB_GetNativePublicDescriptor($id),true);}catch(Throwable $ignored){$local=null;}
                    if(is_array($local)&&SecretsBackendNativePeer::authority($local)===SecretsBackendNativePeer::authority($target))return SECB_ReceiveNativePeer($id,$bytes);
                }
                if($this->peerWork===null&&$requestWork===null)$requestWork=new SecretsBackendPeerWork(null,SecretsBackendPeerWork::phpBudget((int)ini_get('max_execution_time'),microtime(true)-($this->peerRequestStarted>0?$this->peerRequestStarted:$created)));
                return $this->timedPeerHTTPS($target,$bytes,$policy,$requestWork);
            },true,fn(array $state)=>$this->meshRuntimeStatus($state));
    }
    private function meshRuntimeStatus(array $state):array
    {
        $unknown=['state'=>'unknown','age'=>null];$now=time();
        $indicator=static function(array $h)use($now):array{$at=(int)($h['checkedAt']??0);$age=$at>0&&$now>=$at?$now-$at:null;return ['state'=>$age===null||$age>90||($h['stale']??false)?'unknown':(($h['ready']??false)?'ok':'error'),'age'=>$age===null?null:min(86400,$age)];};
        $vault=$indicator(json_decode($this->GetAvailability(),true));$frontend=$unknown;
        $id=$this->ReadPropertyInteger('FrontendInstanceID');
        try{
            if(!IPS_InstanceExists($id))$frontend=['state'=>'error','age'=>0];
            else{
                $h=json_decode(GetValueString(IPS_GetObjectIDByIdent('FrontendHealth',$id)),true,8,JSON_THROW_ON_ERROR);
                if(($h['backend']??null)!==$this->InstanceID||IPS_GetProperty($id,'BackendInstanceID')!==$this->InstanceID||!IPS_GetProperty($id,'Enabled')||IPS_HasChanges($id)||(int)IPS_GetInstance($id)['InstanceStatus']!==102)$h['ready']=false;
                $frontend=$indicator($h);
            }
        }catch(Throwable $ignored){}
        $backend=['state'=>$this->ReadPropertyBoolean('Enabled')&&IPS_GetKernelRunlevel()===10103&&!IPS_HasChanges($this->InstanceID)&&(int)IPS_GetInstance($this->InstanceID)['InstanceStatus']===102?'ok':'error','age'=>0];
        $p=$state['policy']['backupOrigin']??null;$backup=['state'=>'none','age'=>0];
        if($p!==null&&($p['status']??'')!=='revoked'){
            $backup=$unknown;
            if(($p['status']??'')==='active'){try{$c=SecretsFrontendConnectDiscovery::local();$backup=['state'=>($c['available']??false)&&($c['origin']??null)===$p['origin']?'ok':'error','age'=>0];}catch(Throwable $ignored){}}
        }
        $emergency=json_decode($this->GetEmergencyStatus(),true);return ['components'=>['frontend'=>$frontend,'backend'=>$backend,'vault'=>$vault],'backupService'=>$backup,'source'=>$indicator($emergency),'activeSource'=>($emergency['mode']??'')==='REMOTE'?($emergency['sourceVault']??null):null,'fallback'=>($emergency['mode']??'')==='REMOTE'&&($emergency['ready']??false)&&!($emergency['stale']??true)];
    }
    public static function nativeHTTPS(string $endpoint,string $bytes,array $policy=['mode'=>'strict']): string
    {
        return SecretsBackendNativeLegacyHTTPS::post($endpoint,$bytes,$policy,SecretsBackendNativeLegacyHTTPS::timeout($endpoint));
    }
    public function GetNativePublicDescriptor(): string
    {
        if(!$this->nativeInitialized())throw new RuntimeException('Native vault is not initialized.');return SecretsBackendCodec::json($this->nativePeer()->descriptor());
    }
    public function ReceiveNativePeer(string $EnvelopeJSON): string
    {
        $envelope=json_decode($EnvelopeJSON,true,16);
        if(is_array($envelope)&&($envelope['format']??'')===SecretsBackendEmergency::FORMAT){
            if(!$this->ReadPropertyBoolean('Enabled')||!$this->nativeInitialized())throw new SecretsBackendEmergencyUnavailable('Native peer receiver unavailable.');
            try{$this->nativeApplication();}catch(Throwable $e){throw new SecretsBackendEmergencyUnavailable('Remote vault unavailable.');}
            return SecretsBackendEmergency::serve($this->nativeStore(),$EnvelopeJSON);
        }
        if(!$this->ReadPropertyBoolean('Enabled')||!$this->nativeInitialized())throw new RuntimeException('Native peer receiver is disabled.');
        $this->nativeApplication(); // Verify the pinned active security profile before accepting peer effects.
        return $this->nativePeer()->receive($EnvelopeJSON);
    }
    public function RunNativeJobs(): string
    {
        $started=microtime(true);
        $lock='SECB.NativeJobs.'.$this->InstanceID;if(!IPS_SemaphoreEnter($lock,1))return '[]';
        try{
            if(!$this->ReadPropertyBoolean('Enabled')||!$this->nativeInitialized())return '[]';
            $this->nativeApplication();$store=$this->nativeStore();$peer=$this->nativePeer($store);
            $this->peerWork=new SecretsBackendPeerWork(null,SecretsBackendPeerWork::phpBudget((int)ini_get('max_execution_time'),microtime(true)-$started));
            $this->SetBuffer('PeerBudgetMs',(string)$this->peerWork->budgetMilliseconds());
            $effects=new SecretsBackendNativeEffects($store,function($effect){$this->peerWork->providerAttempt();return self::nativeProviderHTTPS($effect);});
            $phases=[
                'delivery'=>fn():array=>$peer->dispatch(1),
                'health'=>fn():array=>[(new SecretsBackendNativeHealth($store,$peer))->tick()],
                'mesh'=>function()use($store,$peer):array{try{return [(new SecretsBackendMeshStatus($store,$peer))->tick()];}catch(Throwable $ignored){return [['status'=>'MESH_UNAVAILABLE']];}},
                'providers'=>fn():array=>[$effects->tick()]
            ];
            return SecretsBackendCodec::json($this->peerWork->run((int)$this->GetBuffer('NativeJobsPhase'),$phases,fn(int $next)=>$this->SetBuffer('NativeJobsPhase',(string)$next)));
        }catch(Throwable $e){$this->debug('request-rejected');return '[{"status":"RECOVERY_REQUIRED"}]';}
        finally{$this->peerWork=null;IPS_SemaphoreLeave($lock);}
    }
    protected function peerHTTPSPost(string $endpoint,string $bytes,array $policy,float $timeout):string
    {
        return SecretsBackendNativeLegacyHTTPS::post($endpoint,$bytes,$policy,$timeout);
    }
    private function timedPeerHTTPS(array $target,string $bytes,array $policy,?SecretsBackendPeerWork $requestWork=null):string
    {
        $timeout=($this->peerWork??$requestWork)?->attempt($target['endpoint'])??SecretsBackendNativeLegacyHTTPS::timeout($target['endpoint']);
        $started=microtime(true);$outcome='unconfirmed';
        try{$reply=$this->peerHTTPSPost($target['endpoint'],$bytes,$policy,$timeout);$outcome='response';return $reply;}
        catch(SecretsBackendNativePeerDeliveryFailure $e){$outcome=in_array($e->problem,SecretsBackendNativePeerDeliveryFailure::PROBLEMS,true)?$e->problem:'unconfirmed';throw $e;}
        finally{
            try{
                $rows=json_decode($this->GetBuffer('PeerTimings'),true);$rows=is_array($rows)?$rows:[];
                $route=SecretsBackendNativeLegacyHTTPS::timeout($target['endpoint'])===25.0?'backup':'primary';
                $kind=json_decode($bytes,true,16)['kind']??'';$kind=in_array($kind,['MESH_STATUS','HEALTH','SYNC','RESYNC','STATUS','PAIR_REQUEST','PAIR_ACCEPT','ROUTES','EMERGENCY_OFFER','REVOKE','GLOBAL_ENABLE','TREE_SYNC'],true)?$kind:'other';
                $rows[$target['vaultId'].':'.$route]=['peerId'=>$target['vaultId'],'route'=>$route,'kind'=>$kind,'at'=>gmdate('c'),'elapsedMs'=>min(86400000,max(0,(int)round(1000*(microtime(true)-$started)))),'timeoutMs'=>(int)round(1000*$timeout),'outcome'=>$outcome];
                $this->SetBuffer('PeerTimings',SecretsBackendCodec::json(array_slice($rows,-64,null,true)));
            }catch(Throwable $ignored){}
        }
    }
    /** Local metadata only. HTTP response timing is not proof of a valid signed peer reply. */
    public function GetTransportDiagnostics():string
    {
        $rows=json_decode($this->GetBuffer('PeerTimings'),true);
        return SecretsBackendCodec::json(['schema'=>'SECB.TransportDiagnostics.v1','limits'=>SecretsBackendPeerWork::limits($this->GetBuffer('PeerBudgetMs')!==''?(int)$this->GetBuffer('PeerBudgetMs'):null),'requests'=>is_array($rows)?array_values(array_slice($rows,-64,null,true)):[]]);
    }
    public function ExportTransportDiagnostics():string
    {
        $json=$this->GetTransportDiagnostics();$this->UpdateFormField('ExportJSON','value',$json);return $json;
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
    private function nativePairingPage(?string $host=null): string
    {
        if(!$this->ReadPropertyBoolean('Enabled')||!$this->nativeInitialized())throw new RuntimeException('Native peer receiver is disabled.');
        $this->nativeApplication();$id=$this->ReadPropertyInteger('FrontendInstanceID');if($id<=0)throw new RuntimeException('No paired frontend.');
                $origin=$this->ReadPropertyString('AdminOrigin');if($host!==null){$candidate=SecretsFrontendConfiguration::origin('https://'.$host);$s=$this->nativeStore()->read()['state'];if($candidate!==$origin){$p=$s['policy']['backupOrigin']??null;if(!SecretsBackendBackupOriginPolicy::full($s)||$candidate!==$p['origin'])throw new RuntimeException('Unknown peer landing origin.');$origin=$candidate;}}
        return $origin.'/hook/secrets_frontend_'.$id;
    }
    private function nativePeerTransportOrigin(array $server): string
    {
        $ips=json_decode(IPS_GetProperty($this->ReadPropertyInteger('FrontendInstanceID'),'TrustedHTTPSProxyIPs'),true,8,JSON_THROW_ON_ERROR);$proxy=in_array($server['REMOTE_ADDR']??'',$ips,true);$host=$proxy&&isset($server['HTTP_X_FORWARDED_HOST'])?$server['HTTP_X_FORWARDED_HOST']:($server['HTTP_HOST']??'');
        $origin=SecretsFrontendConfiguration::origin('https://'.$host);$primary=$this->ReadPropertyString('AdminOrigin');
        if($origin===$primary)return $origin;
        $s=$this->nativeStore()->read()['state'];$p=$s['policy']['backupOrigin']??null;
        if(!SecretsBackendBackupOriginPolicy::full($s)||$origin!==$p['origin'])throw new RuntimeException('Unknown or revoked peer origin.');
        if(!SecretsFrontendConnectDiscovery::secureRoute($server,$origin,$ips,SecretsFrontendConnectDiscovery::local()))throw new RuntimeException('Magic peer transport is unverified.');return $origin;
    }
    protected function ProcessHookData()
    {
        header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store');header('X-Content-Type-Options: nosniff');
        $emergency=false;
        try{
            $transportOrigin=$this->nativePeerTransportOrigin($_SERVER);$path='/hook/secrets_peer_'.$this->InstanceID;$uri=(string)($_SERVER['REQUEST_URI']??$path);
            if(in_array($_SERVER['REQUEST_METHOD']??'', ['GET','HEAD'],true)&&parse_url($uri,PHP_URL_PATH)===$path&&($_SERVER['QUERY_STRING']??'')===''){
                header('Location: '.$this->nativePairingPage(substr($transportOrigin,8)));http_response_code(303);return;
            }
            if(($_SERVER['REQUEST_METHOD']??'GET')!=='POST'||parse_url($uri,PHP_URL_PATH)!==$path||($_SERVER['QUERY_STRING']??'')!=='')throw new RuntimeException('Only the fixed native POST endpoint is supported.');
            $types=[];foreach(['CONTENT_TYPE','HTTP_CONTENT_TYPE']as$key){$value=trim((string)($_SERVER[$key]??''));if($value!=='')$types[strtolower(trim(explode(';',$value,2)[0]))]=true;}
            if(count($types)!==1||!isset($types['application/json']))throw new RuntimeException('Native JSON envelope required.');
            $limit=SecretsBackendNativePlatform::budget()*2+65536;$bytes=file_get_contents('php://input',false,null,0,$limit+1);
            if(!is_string($bytes)||strlen($bytes)>$limit)throw new RuntimeException('Native envelope exceeds its bound.');
            $decoded=json_decode($bytes,true,16);$emergency=is_array($decoded)&&($decoded['format']??'')===SecretsBackendEmergency::FORMAT;
            $reply=$this->ReceiveNativePeer($bytes);http_response_code(200);echo $reply;
        }catch(Throwable $e){
            // An unavailable remote vault is retryable, including a Connect route whose
            // origin lookup could not open that vault. Malformed/denied healthy requests stay 403.
            if(!$emergency&&($_SERVER['REQUEST_METHOD']??'')==='POST'){
                $probe=file_get_contents('php://input',false,null,0,32769);
                if(is_string($probe)&&strlen($probe)<=32768){$m=json_decode($probe,true,16);$emergency=is_array($m)&&($m['format']??'')===SecretsBackendEmergency::FORMAT;}
            }
            $unavailable=$e instanceof SecretsBackendEmergencyUnavailable;
            if($emergency&&!$unavailable){try{$this->nativeApplication();}catch(Throwable $ignored){$unavailable=true;}}
            http_response_code($unavailable?503:403);echo '{"error":"Native peer request refused."}';
        }
    }
    private function nativeCapability(array $state,string $token,string $scope,array $path,bool $write): array
    {
        SecretsBackendCodec::unb64($token,32);SecretsBackendTree::path($path);$hash=hash('sha256',$token);
        foreach($state['native']['machines']as$grant){
            if(!$grant['active']||!hash_equals($grant['hash'],$hash))continue;
            $target=SecretsBackendNativeOperations::machineTarget($state,$scope);
            if($grant['scope']!==$scope||($grant['treeId']??'')!==$target['treeId']||($write&&(!$grant['write']||!$target['writable']))||count($path)<count($grant['path'])||array_slice($path,0,count($grant['path']))!==$grant['path'])throw new RuntimeException('Machine capability does not permit this exact scope/path/action.');
            if($scope==='global')SecretsBackendSharedGlobal::assertPath($state,$path,!$write);
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
        return SecretsBackendCodec::json(['value'=>SecretsBackendTree::value(SecretsBackendTree::at($Scope==='global'?SecretsBackendSharedGlobal::available($current['state']):$target['node'],$path)),'revision'=>$target['revision']]);
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
