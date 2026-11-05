<?php
declare(strict_types=1);
require_once __DIR__.'/Emergency.php';

/** No value cache. Version evidence is kept separately from the unavailable local vault. */
final class SecretsBackendEmergencyClient
{
    private array $backoff;
    public function __construct(private SecretsBackendEmergencyCapsule $capsule,private string $binding,private $transport,array $backoff=[]) { $this->backoff=$backoff; }
    public function backoff(): array { return $this->backoff; }
    private function exchange(array $c,string $source,string $method,array $args,string $phase,float $deadline): array {
        $key=sodium_crypto_box_keypair();$nonce=SecretsBackendCodec::b64(random_bytes(32));
        $q=['source'=>$source,'grantId'=>$c['grantId'],'token'=>$c['token'],'nonce'=>$nonce,'replyKey'=>SecretsBackendCodec::b64(sodium_crypto_box_publickey($key)),'phase'=>$phase,'method'=>$method,'args'=>$args];
        $request=['format'=>SecretsBackendEmergency::FORMAT,'receiver'=>$c['peerId'],'payload'=>SecretsBackendCodec::b64(sodium_crypto_box_seal(SecretsBackendCodec::json($q),SecretsBackendCodec::unb64($c['descriptor']['boxKey'],32)))];
        $bytes=SecretsBackendCodec::json($request);$failure=null;
        foreach(array_slice($c['routes'],0,2)as$url){
            SecretsBackendNativePeer::endpoint($url);
            if(parse_url($url,PHP_URL_PATH)!=='/hook/secrets_peer_'.$c['descriptor']['backend'])throw new SecretsBackendEmergencyRefused('ENDPOINT_BINDING');
            $left=$deadline-microtime(true);if($left<0.1)throw new SecretsBackendNativePeerDeliveryFailure('timeout');
            $policy=SecretsBackendNativeLegacyHTTPS::origin($url)===SecretsBackendNativeLegacyHTTPS::origin($c['descriptor']['endpoint'])?$c['httpsPolicy']:['mode'=>'strict'];
            try{$raw=($this->transport)($url,$bytes,$policy,min(1.5,$left));}
            catch(SecretsBackendNativePeerDeliveryFailure $e){
                if($e->problem==='http'&&!in_array($e->httpStatus,[429,502,503,504],true))throw new SecretsBackendEmergencyRefused('REMOTE_REFUSED');
                if(in_array($e->problem,['invalid-reply','response-size'],true))throw new SecretsBackendEmergencyRefused('INVALID_RESPONSE');
                $failure=$e;continue;
            }
            try{
                if(!is_string($raw)||strlen($raw)>65536)throw new RuntimeException('Response bound.');$r=json_decode($raw,true,16,JSON_THROW_ON_ERROR);
                SecretsBackendNativePeer::exact($r,['format','sender','payload','signature']);
                if($r['format']!=='SECB.EmergencyReply.1'||$r['sender']!==$c['peerId'])throw new RuntimeException('Response identity.');
                $sig=$r['signature'];unset($r['signature']);
                if(!sodium_crypto_sign_verify_detached(SecretsBackendCodec::unb64($sig,64),'SECB.EMERGENCY.REPLY.1\0'.SecretsBackendNativeStore::canonical($r),SecretsBackendCodec::unb64($c['descriptor']['signKey'],32)))throw new RuntimeException('Response signature.');
                $plain=sodium_crypto_box_seal_open(SecretsBackendCodec::unb64($r['payload']),$key);if(!is_string($plain)||strlen($plain)>40000)throw new RuntimeException('Response encryption.');
                $reply=json_decode($plain,true,32,JSON_THROW_ON_ERROR);
                if(!is_array($reply)||($reply['nonce']??'')!==$nonce||($reply['requestDigest']??'')!==hash('sha256',$bytes))throw new RuntimeException('Response binding.');
                if(($reply['status']??'')!=='OK'){
                    SecretsBackendNativePeer::exact($reply,['nonce','requestDigest','status']);
                    if(!in_array($reply['status'],['DENIED','MISSING','CONFLICT'],true))throw new RuntimeException('Response status.');
                    throw new SecretsBackendEmergencyRefused('REMOTE_'.$reply['status']);
                }
                SecretsBackendNativePeer::exact($reply,$phase==='read'?['nonce','requestDigest','status','stamp','value']:['nonce','requestDigest','status','stamp']);
                SecretsBackendEmergency::stamp($reply['stamp']);
                if($phase==='read'&&(($method==='GetExplorerFields'&&!is_array($reply['value']))||($method!=='GetExplorerFields'&&!is_string($reply['value']))))throw new RuntimeException('Response value type.');
                unset($this->backoff[$c['peerId']]);return $reply;
            }catch(SecretsBackendEmergencyRefused $e){throw $e;}catch(Throwable $e){throw new SecretsBackendEmergencyRefused('INVALID_RESPONSE');}
        }throw $failure??new SecretsBackendNativePeerDeliveryFailure('transport');
    }
    public function read(string $method,array $args,?string $expectedVault=null,bool $probeOnly=false): array {
        SecretsBackendEmergency::arguments($method,$args);$access=$this->capsule->load($this->binding);
        if($expectedVault!==null&&!hash_equals($access['source'],$expectedVault))throw new SecretsBackendEmergencyRefused('PINNED_VAULT_CHANGED');
        $deadline=microtime(true)+8.0;$observed=[];$candidates=[];$skipped=0;
        foreach($access['clients']as$id=>$c){
            if(($this->backoff[$id]['next']??0)>time()||microtime(true)>$deadline-1.7){++$skipped;continue;}
            try{$reply=$this->exchange($c,$access['source'],$method,$args,'probe',$deadline-1.5);}
            catch(SecretsBackendNativePeerDeliveryFailure $e){$failures=min(8,($this->backoff[$id]['failures']??0)+1);$this->backoff[$id]=['failures'=>$failures,'next'=>time()+min(60,2**$failures)];++$skipped;continue;}
            $stamp=$reply['stamp'];$this->capsule->observe($this->binding,$access['authorization'],$stamp);$observed[]=$stamp;$candidates[]=['client'=>$c,'stamp'=>$stamp];
        }
        if(!$candidates)throw new SecretsBackendEmergencyRefused('NO_REACHABLE_APPROVED_PEER');
        $floor=$this->capsule->load($this->binding)['floor'];$eligible=[];
        foreach($candidates as$c){
            if(!in_array(SecretsBackendEmergency::compare($c['stamp']['clock'],$floor['clock']),[0,1],true))continue;
            $dominates=true;foreach($observed as$s){$relation=SecretsBackendEmergency::compare($c['stamp']['clock'],$s['clock']);if(!in_array($relation,[0,1],true)){$dominates=false;break;}if($relation===0&&!hash_equals($c['stamp']['digest'],$s['digest']))throw new SecretsBackendEmergencyRefused('INCONSISTENT_HISTORY');}
            if($dominates)$eligible[]=$c;
        }
        if(!$eligible)throw new SecretsBackendEmergencyRefused('KNOWN_OLDER_OR_CONCURRENT');
        foreach($eligible as$selected){
            if(microtime(true)>=$deadline)break;
            try{$reply=$probeOnly?['stamp'=>$selected['stamp']]:$this->exchange($selected['client'],$access['source'],$method,$args,'read',$deadline);}
            catch(SecretsBackendNativePeerDeliveryFailure $e){$id=$selected['client']['peerId'];$failures=min(8,($this->backoff[$id]['failures']??0)+1);$this->backoff[$id]=['failures'=>$failures,'next'=>time()+min(60,2**$failures)];++$skipped;continue;}
            foreach($observed as$s){$relation=SecretsBackendEmergency::compare($reply['stamp']['clock'],$s['clock']);if(!in_array($relation,[0,1],true)||($relation===0&&!hash_equals($reply['stamp']['digest'],$s['digest'])))throw new SecretsBackendEmergencyRefused('KNOWN_OLDER_OR_CONCURRENT');}
            $this->capsule->accept($this->binding,$access['authorization'],$reply['stamp']);
            return ['value'=>$reply['value']??null,'source'=>$selected['client']['peerId'],'name'=>$selected['client']['name'],'checkedAt'=>time(),'freshness'=>'best-available-not-guaranteed-current','unreachableOrUnprobed'=>$skipped];
        }
        throw new SecretsBackendEmergencyRefused('NO_REACHABLE_APPROVED_PEER');
    }
}
