<?php
declare(strict_types=1);
require_once __DIR__ . '/NativePeer.php';

/** OAuth refresh slots retain uncertainty; ordinary timeouts never authorize a fresh request. */
final class SecretsBackendNativeEffects
{
    private $transport;
    public function __construct(private SecretsBackendNativeStore $store,?callable $transport=null){$this->transport=$transport;}
    public static function configure(array $op,array $state): array
    {
        SecretsBackendNativePeer::exact($op,['kind','id','name','endpoint','clientId','authentication','secretScope','secretPath','refreshScope','refreshPath','resultScope','resultPath','accessField','automatic','idempotencySupported','idempotencyHeader']);
        SecretsBackendNativePeer::name($op['name']);$p=parse_url($op['endpoint']);
        if(!is_array($p)||($p['scheme']??'')!=='https'||!isset($p['host'])||isset($p['user'])||isset($p['pass'])||isset($p['fragment'])||isset($p['query'])||strlen($op['endpoint'])>1024)throw new RuntimeException('Use the exact HTTPS token endpoint without credentials, query or fragment.');
        if(!is_string($op['clientId'])||$op['clientId']===''||strlen($op['clientId'])>512||preg_match('/[\x00-\x1f]/',$op['clientId'])||!in_array($op['authentication'],['basic','body','none'],true))throw new RuntimeException('Choose the OAuth client and authentication method.');
        foreach(['secret','refresh','result']as$kind){if(!in_array($op[$kind.'Scope'],['global','local'],true)||!is_array($op[$kind.'Path']))throw new RuntimeException('Select exact local/global token references.');SecretsBackendTree::path($op[$kind.'Path']);}
        self::token($state,$op['refreshScope'],$op['refreshPath']);if($op['authentication']!=='none')self::token($state,$op['secretScope'],$op['secretPath']);
        if(SecretsBackendTree::at($state['vault'][$op['resultScope']],$op['resultPath'])['type']!=='object')throw new RuntimeException('Select an object record for the refreshed token.');
        if(!is_string($op['accessField'])||$op['accessField']===''||strlen($op['accessField'])>64||preg_match('/[\x00-\x1f]/',$op['accessField']))throw new RuntimeException('Choose an access-token field name.');
        if(!is_bool($op['automatic'])||!is_bool($op['idempotencySupported'])||!preg_match('/^[A-Za-z][A-Za-z0-9-]{0,63}$/D',$op['idempotencyHeader']))throw new RuntimeException('Invalid automatic refresh/idempotency settings.');
        if($op['automatic']&&!$op['idempotencySupported'])throw new RuntimeException('Automatic refresh requires confirmed provider idempotency for uncertain responses. Manual approved refresh remains available.');
        if($op['id']==='')$op['id']=SecretsBackendCodec::uuid();else{SecretsBackendNativePeer::uuid($op['id']);if(!isset($state['native']['providers'][$op['id']]))throw new RuntimeException('Unknown provider.');}
        $op['targetGlobalTreeId']=in_array('global',[$op['resultScope'],$op['refreshScope']],true)?$state['native']['globalTreeId']:'';
        if(!self::targetWritable($state,$op))throw new RuntimeException('This provider cannot write a frozen or transferred global tree.');
        $op['configurationGeneration']=SecretsBackendCodec::uuid();return $op;
    }
    public static function targetWritable(array $state,array $provider): bool
    {
        if(!in_array('global',[$provider['resultScope'],$provider['refreshScope']],true))return true;
        return $state['native']['globalWritable']&&($provider['targetGlobalTreeId']??'')===$state['native']['globalTreeId'];
    }
    private static function inputsMatch(array $state,array $provider,array $effect): bool
    {
        try{return self::targetWritable($state,$provider)&&hash('sha256',self::token($state,$provider['refreshScope'],$provider['refreshPath']))===$effect['refreshDigest']
            &&hash('sha256',$provider['authentication']==='none'?'':self::token($state,$provider['secretScope'],$provider['secretPath']))===$effect['clientDigest'];}
        catch(Throwable $ignored){return false;}
    }
    public static function token(array $state,string $scope,array $path): string
    {
        if($scope==='global')SecretsBackendSharedGlobal::assertPath($state,$path);
        $value=SecretsBackendTree::value(SecretsBackendTree::at($state['vault'][$scope],$path));if(!is_string($value)||$value===''||strlen($value)>16384)throw new RuntimeException('The selected token reference is not a bounded nonempty string.');return $value;
    }
    public function prepare(array $state,string $providerId): array
    {
        $p=$state['native']['providers'][$providerId]??null;if(!is_array($p)||!$p['active'])throw new RuntimeException('Select an active provider.');
        if(!self::targetWritable($state,$p))throw new RuntimeException('Provider target ownership changed. Reconfigure it explicitly for the current writable lineage.');
        if(($p['activeEffect']??null)!==null)throw new RuntimeException('Resolve the existing provider effect before starting another.');
        $refresh=self::token($state,$p['refreshScope'],$p['refreshPath']);$refreshDigest=hash('sha256',$refresh);$policy=self::policyDigest($p);
        $id=$this->store->opaque('oauth-effect:'.$p['id'].':'.$p['refreshGeneration'].':'.$policy.':'.$refreshDigest);
        $external=$this->store->opaque('oauth-predecessor:'.$p['endpoint'].':'.$p['clientId'].':'.$refreshDigest);
        if(isset($state['native']['externalPredecessors'][$external])||isset($state['native']['effects'][$id]))throw new RuntimeException('This provider predecessor already has an outcome or unresolved uncertainty. It is not sent again.');
        $body=['grant_type'=>'refresh_token','refresh_token'=>$refresh];$headers=['Content-Type: application/x-www-form-urlencoded','Accept: application/json'];
        if($p['authentication']==='basic')$headers[]='Authorization: Basic '.base64_encode(urlencode($p['clientId']).':'.urlencode(self::token($state,$p['secretScope'],$p['secretPath'])));
        else{$body['client_id']=$p['clientId'];if($p['authentication']==='body')$body['client_secret']=self::token($state,$p['secretScope'],$p['secretPath']);}
        if($p['idempotencySupported'])$headers[]=$p['idempotencyHeader'].': '.$id;
        $wire=http_build_query($body,'','&',PHP_QUERY_RFC1738);
        return ['id'=>$id,'providerId'=>$providerId,'state'=>'PREPARED','policyDigest'=>$policy,'refreshDigest'=>$refreshDigest,'clientDigest'=>hash('sha256',$p['authentication']==='none'?'':self::token($state,$p['secretScope'],$p['secretPath'])),'externalKey'=>$external,'requestDigest'=>hash('sha256',$p['endpoint'].':'.SecretsBackendCodec::json($headers).':'.$wire),
            'endpoint'=>$p['endpoint'],'headers'=>$headers,'body'=>$wire,'idempotencySupported'=>$p['idempotencySupported'],'boot'=>$this->store->read()['owner']['bootId'],'attempts'=>0,'nextAt'=>time(),'createdAt'=>gmdate('c')];
    }
    public static function policyDigest(array $p): string { return SecretsBackendNativePeer::digest(array_diff_key($p,array_flip(['activeEffect','status','nextAt','refreshGeneration','lastResult']))); }
    public static function add(array $state,array $effect): array
    {
        $p=$state['native']['providers'][$effect['providerId']]??null;
        if(!is_array($p)||!$p['active']||self::policyDigest($p)!==$effect['policyDigest']||($p['activeEffect']??null)!==null||!self::inputsMatch($state,$p,$effect)||isset($state['native']['externalPredecessors'][$effect['externalKey']]))throw new RuntimeException('Provider policy, token predecessor or effect slot changed.');
        if(count($state['native']['effects'])>=128){foreach($state['native']['effects']as$id=>$e)if(in_array($e['state'],['COMPLETE','ERROR'],true)){unset($state['native']['effects'][$id]);if(count($state['native']['effects'])<96)break;}}
        if(count($state['native']['effects'])>=128)throw new RuntimeException('Too many unresolved external effects.');
        $state['native']['effects'][$effect['id']]=$effect;$state['native']['externalPredecessors'][$effect['externalKey']]=$effect['id'];$state['native']['providers'][$p['id']]['activeEffect']=$effect['id'];$state['native']['providers'][$p['id']]['status']='PREPARED';return $state;
    }
    private function mutate(callable $fn,string $action,string $target): void
    {
        $current=$this->store->read();$id=SecretsBackendCodec::uuid();$this->store->change($current['head'],$id,hash('sha256',$action.':'.$target.':'.$id),$fn,['action'=>$action,'target'=>$target]);
    }
    public function tick(): array
    {
        $current=$this->store->read();$state=$current['state'];$effect=null;
        foreach($state['native']['effects']as$e)if(in_array($e['state'],['PREPARED','SENT_UNKNOWN','RETRY_SAFE'],true)&&$e['nextAt']<=time()){$effect=$e;break;}
        if($effect===null){foreach($state['native']['providers']as$p)if($p['active']&&$p['automatic']&&self::targetWritable($state,$p)&&$p['nextAt']>0&&$p['nextAt']<=time()&&($p['activeEffect']??null)===null){$effect=$this->prepare($state,$p['id']);$this->mutate(static fn($s)=>self::add($s,$effect),'oauth-prepare',$effect['id']);break;}}
        if($effect===null)return ['status'=>'IDLE'];
        $captured=$this->store->readCapturedEffect($effect['id'],$effect['requestDigest']);
        if($captured!==null)return $this->complete($effect,$captured);
        if($effect['state']==='SENT_UNKNOWN'&&!$effect['idempotencySupported'])return $this->quarantine($effect,'NO_CONFIRMED_RESPONSE');
        if($effect['boot']!==$current['owner']['bootId']&&!$effect['idempotencySupported'])return $this->quarantine($effect,'RESTART_REQUIRES_RECONCILIATION');
        $p=$state['native']['providers'][$effect['providerId']]??null;
        if(!is_array($p)||!$p['active']||self::policyDigest($p)!==$effect['policyDigest']||!self::inputsMatch($state,$p,$effect))return $this->quarantine($effect,'POLICY_OR_PREDECESSOR_CHANGED');
        $this->mutate(static function($s)use($effect){$e=$s['native']['effects'][$effect['id']]??null;$p=$s['native']['providers'][$effect['providerId']]??null;if(!is_array($e)||!in_array($e['state'],['PREPARED','SENT_UNKNOWN','RETRY_SAFE'],true)||!is_array($p)||!$p['active']||self::policyDigest($p)!==$effect['policyDigest']||!self::inputsMatch($s,$p,$effect))throw new RuntimeException('Provider effect was superseded.');$s['native']['effects'][$effect['id']]['state']='SENT_UNKNOWN';$s['native']['effects'][$effect['id']]['attempts']++;$s['native']['providers'][$p['id']]['status']='SENT_UNKNOWN';return $s;},'oauth-sent',$effect['id']);
        try{
            if($this->transport===null)throw new RuntimeException('No supplied HTTPS transport.');
            $response=($this->transport)($effect);if(!is_array($response)||!is_int($response['status']??null)||!is_string($response['body']??null)||strlen($response['body'])>65536)throw new RuntimeException('Unbounded or invalid provider response.');
            $result=['httpStatus'=>$response['status'],'body'=>SecretsBackendCodec::b64($response['body'])];
            $this->store->captureEffect($effect['id'],$effect['requestDigest'],$result);return $this->complete($effect,$result);
        }catch(Throwable $e){
            $latest=$this->store->read()['state']['native']['effects'][$effect['id']];
            if($effect['idempotencySupported']&&$latest['attempts']<3){$this->mutate(static function($s)use($effect){$s['native']['effects'][$effect['id']]['state']='RETRY_SAFE';$s['native']['effects'][$effect['id']]['nextAt']=time()+30;return $s;},'oauth-retry',$effect['id']);return ['status'=>'RETRY_SAFE','effectId'=>$effect['id']];}
            return $this->quarantine($effect,'RESPONSE_UNKNOWN');
        }
    }
    private function quarantine(array $effect,string $reason): array
    {
        $this->mutate(static function($s)use($effect,$reason){$s['native']['effects'][$effect['id']]['state']='QUARANTINED';$s['native']['effects'][$effect['id']]['reason']=$reason;$s['native']['providers'][$effect['providerId']]['status']='QUARANTINED';return $s;},'oauth-quarantine',$effect['id']);return ['status'=>'QUARANTINED','effectId'=>$effect['id'],'reason'=>$reason];
    }
    public function complete(array $effect,array $captured): array
    {
        $s=$this->store->read()['state'];$p=$s['native']['providers'][$effect['providerId']]??null;
        if(!is_array($p)||!$p['active']||$p['activeEffect']!==$effect['id']||self::policyDigest($p)!==$effect['policyDigest']||!self::inputsMatch($s,$p,$effect))return $this->quarantine($effect,'CAPTURED_RESULT_NEEDS_REVIEW');
        try{$r=SecretsFrontendConfiguration::decode(SecretsBackendCodec::unb64($captured['body']));}catch(Throwable $e){return $this->quarantine($effect,'MALFORMED_CAPTURED_RESPONSE');}
        $success=$captured['httpStatus']>=200&&$captured['httpStatus']<300;
        if(!$success&&(!in_array($captured['httpStatus'],[400,401],true)||!in_array($r['error']??'', ['invalid_request','invalid_client','invalid_grant','unauthorized_client','unsupported_grant_type','invalid_scope'],true)))return $this->quarantine($effect,'AMBIGUOUS_PROVIDER_ERROR');
        if($success&&(!is_string($r['access_token']??null)||$r['access_token']===''||strlen($r['access_token'])>16384||isset($r['refresh_token'])&&(!is_string($r['refresh_token'])||$r['refresh_token']===''||strlen($r['refresh_token'])>16384)||isset($r['expires_in'])&&(!is_int($r['expires_in'])||$r['expires_in']<0||$r['expires_in']>31536000)))return $this->quarantine($effect,'INVALID_CAPTURED_TOKEN_RESPONSE');
        $this->mutate(static function($s)use($effect,$captured,$success,$r){$p=$s['native']['providers'][$effect['providerId']];if(!$p['active']||$p['activeEffect']!==$effect['id']||self::policyDigest($p)!==$effect['policyDigest']||!self::inputsMatch($s,$p,$effect))throw new RuntimeException('Captured provider completion was superseded.');
            if($success){$record=SecretsBackendTree::value(SecretsBackendTree::at($s['vault'][$p['resultScope']],$p['resultPath']));if(!$record instanceof stdClass)throw new RuntimeException('Provider token destination changed type.');$record->{$p['accessField']}=$r['access_token'];if(isset($r['token_type'])&&is_string($r['token_type'])&&strlen($r['token_type'])<80)$record->token_type=$r['token_type'];if(isset($r['expires_in']))$record->expires_at=time()+$r['expires_in'];
                SecretsBackendTree::edit($s['vault'][$p['resultScope']],$p['resultPath'],SecretsBackendTree::parse(SecretsBackendCodec::json($record)),'replace');
                if(isset($r['refresh_token']))SecretsBackendTree::edit($s['vault'][$p['refreshScope']],$p['refreshPath'],SecretsBackendTree::parse(SecretsBackendCodec::json($r['refresh_token'])),'replace');
                $s['vault']['revision']=SecretsBackendCodec::increment($s['vault']['revision']);$s['native']['providers'][$p['id']]['refreshGeneration']=SecretsBackendCodec::increment($p['refreshGeneration']);
                if($p['resultScope']==='global'||isset($r['refresh_token'])&&$p['refreshScope']==='global'){$s['stream']['globalRevision']=SecretsBackendCodec::increment($s['stream']['globalRevision']);$s=SecretsBackendNativePeer::queueGlobal($s);}
            }
            $s['native']['effects'][$effect['id']]['state']=$success?'COMPLETE':'ERROR';$s['native']['effects'][$effect['id']]['httpStatus']=$captured['httpStatus'];unset($s['native']['effects'][$effect['id']]['body'],$s['native']['effects'][$effect['id']]['headers']);
            unset($s['native']['externalPredecessors'][$effect['externalKey']]);$s['native']['providers'][$p['id']]['activeEffect']=null;$s['native']['providers'][$p['id']]['status']=$success?'READY':'ERROR';
            $s['native']['providers'][$p['id']]['nextAt']=$success&&isset($r['expires_in'])&&$p['automatic']?time()+max(15,$r['expires_in']-60):0;return $s;
        },'oauth-complete',$effect['id']);return ['status'=>$success?'COMPLETE':'ERROR','effectId'=>$effect['id']];
    }
}
