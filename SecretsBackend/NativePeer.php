<?php
declare(strict_types=1);
require_once __DIR__ . '/NativeStore.php';
require_once __DIR__ . '/Tree.php';
require_once __DIR__ . '/NativeTransfer.php';
require_once __DIR__ . '/../SecretsFrontend/Configuration.php';

/** Public delivery diagnostics contain fixed categories and numeric codes only. */
final class SecretsBackendNativePeerDeliveryFailure extends RuntimeException
{
    public const PROBLEMS=['dns','connect','timeout','certificate','tls','http','response-size','invalid-reply','transport','unconfirmed'];
    public function __construct(public readonly string $problem, public readonly int $httpStatus=0, public readonly int $curlCode=0)
    { parent::__construct('Native peer delivery is unconfirmed.'); }
    public static function transport(int $curlCode,int $httpStatus,bool $tooLarge=false): self
    {
        $problem=$tooLarge?'response-size':($curlCode===0?'http':match($curlCode){5,6=>'dns',7=>'connect',28=>'timeout',51,58,60,77,82,83,90,91=>'certificate',35,59,64,66,80=>'tls',default=>'unconfirmed'});
        return new self($problem,$httpStatus,$curlCode);
    }
}

/** Optional bilateral encrypted synchronization. Every vault remains independently usable. */
final class SecretsBackendNativePeer
{
    use SecretsBackendNativeTransfer;
    private $transport;
    public function __construct(private SecretsBackendNativeStore $store, private string $endpoint, ?callable $transport = null) { self::endpoint($endpoint); $this->transport = $transport; }
    public static function exact(array $value, array $keys): void { if (array_diff(array_keys($value),$keys) || array_diff($keys,array_keys($value))) throw new RuntimeException('Unexpected native protocol fields.'); }
    public static function uuid(string $value): void { if (!preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/D',$value)) throw new RuntimeException('Invalid native UUID.'); }
    public static function decimal(string $value): void { if (!preg_match('/^(?:0|[1-9][0-9]{0,17})$/D',$value)) throw new RuntimeException('Invalid native sequence.'); }
    public static function endpoint(string $url): void
    {
        $p=parse_url($url); if (!is_array($p)||($p['scheme']??'')!=='https'||!isset($p['host'])||isset($p['user'],$p['pass'])||isset($p['query'])||isset($p['fragment'])||!preg_match('~^/hook/secrets_peer_[1-9][0-9]*$~D',$p['path']??'')) throw new RuntimeException('Use the complete HTTPS native peer URL supplied by the other vault.');
        if (isset($p['user'])||isset($p['pass'])||strlen($url)>512) throw new RuntimeException('Invalid peer endpoint.');
    }
    public function descriptor(): array
    {
        $i=$this->store->identity();$state=$this->store->read()['state'];return ['vaultId'=>$i['deploymentId'],'treeId'=>$state['native']['globalTreeId'],'backend'=>(string)$i['binding']['backend'],'endpoint'=>$this->endpoint,'signKey'=>$i['signPublicKey'],'boxKey'=>$i['boxPublicKey']];
    }
    public static function descriptorCheck(array $d): void
    {
        self::exact($d,['vaultId','treeId','backend','endpoint','signKey','boxKey']);self::uuid($d['vaultId']);self::uuid($d['treeId']);
        if(!preg_match('/^[1-9][0-9]{0,8}$/D',$d['backend']))throw new RuntimeException('Invalid peer backend binding.');
        self::endpoint($d['endpoint']);if(parse_url($d['endpoint'],PHP_URL_PATH)!=='/hook/secrets_peer_'.$d['backend'])throw new RuntimeException('Peer endpoint/backend mismatch.');
        SecretsBackendCodec::unb64($d['signKey'],32);SecretsBackendCodec::unb64($d['boxKey'],32);
    }
    public static function digest(array $value): string { return hash('sha256',SecretsBackendNativeStore::canonical($value)); }
    public static function comparison(array $pair): string { return strtoupper(implode(' ',str_split(substr(self::digest($pair),0,20),5))); }
    private function signed(array $value): array { $value['signature']=$this->store->sign('SECB.NATIVE.PEER.1:'.SecretsBackendNativeStore::canonical($value));return $value; }
    private static function verify(array $value,string $key): void
    {
        $sig=$value['signature']??'';unset($value['signature']);
        if(!is_string($sig)||!sodium_crypto_sign_verify_detached(SecretsBackendCodec::unb64($sig,64),'SECB.NATIVE.PEER.1:'.SecretsBackendNativeStore::canonical($value),SecretsBackendCodec::unb64($key,32)))throw new RuntimeException('Native peer signature is invalid.');
    }
    public function invitation(): array
    {
        $i=['format'=>'SECB.Invitation.1','id'=>SecretsBackendCodec::uuid(),'issuer'=>$this->descriptor(),'secret'=>SecretsBackendCodec::b64(random_bytes(32)),'expires'=>(string)(time()+900),'scope'=>'global'];
        return $this->signed($i);
    }
    public static function invitationText(array $i): string { return 'SECBPAIR1.'.SecretsBackendCodec::b64(SecretsBackendCodec::json($i)); }
    public static function readInvitation(string $text): array
    {
        if(!str_starts_with($text,'SECBPAIR1.')||strlen($text)>16384)throw new RuntimeException('Paste the invitation generated by the other vault.');
        $i=SecretsFrontendConfiguration::decode(SecretsBackendCodec::unb64(substr($text,10)));
        self::exact($i,['format','id','issuer','secret','expires','scope','signature']);self::uuid($i['id']);self::descriptorCheck($i['issuer']);
        if($i['format']!=='SECB.Invitation.1'||$i['scope']!=='global'||!preg_match('/^[0-9]{1,12}$/D',$i['expires'])||(int)$i['expires']<time()||(int)$i['expires']>time()+3600)throw new RuntimeException('The invitation expired or has invalid scope.');
        SecretsBackendCodec::unb64($i['secret'],32);self::verify($i,$i['issuer']['signKey']);return $i;
    }
    public function pairOperation(string $text,string $name): array
    {
        $i=self::readInvitation($text);if($i['issuer']['vaultId']===$this->descriptor()['vaultId'])throw new RuntimeException('A vault cannot pair with itself.');
        $pair=['id'=>SecretsBackendCodec::uuid(),'epoch'=>'1','a'=>$i['issuer'],'b'=>$this->descriptor(),'scope'=>'global','cachedReads'=>true];
        return ['kind'=>'nativePair','invitationId'=>$i['id'],'expires'=>$i['expires'],'name'=>self::name($name),'pair'=>$pair,
            'proof'=>hash_hmac('sha256','SECB.Pair.Request:'.SecretsBackendNativeStore::canonical($pair),SecretsBackendCodec::unb64($i['secret'],32)),
            'requestId'=>SecretsBackendCodec::uuid()];
    }
    public static function name(string $name): string { if($name===''||strlen($name)>80||preg_match('/[\x00-\x1f]/',$name))throw new RuntimeException('Choose a short peer name.');return $name; }
    public static function peerRecord(array $pair,array $remote,string $name,string $state): array
    {
        return ['id'=>$remote['vaultId'],'pairingId'=>$pair['id'],'epoch'=>$pair['epoch'],'descriptor'=>$remote,'pair'=>$pair,'name'=>$name,'active'=>$state==='ACTIVE','state'=>$state,'lastSync'=>null];
    }
    public static function job(array $peer,string $kind,array $payload,string $sequence='0',?string $id=null): array
    {
        return ['id'=>$id??SecretsBackendCodec::uuid(),'ackId'=>SecretsBackendCodec::uuid(),'receiverId'=>$peer['id'],'pairingId'=>$peer['pairingId'],'epoch'=>$peer['epoch'],
            'kind'=>$kind,'sequence'=>$sequence,'payload'=>$payload,'status'=>'queued','attempts'=>0,'nextAttemptAt'=>0];
    }
    /** A replacement pairing cannot send a notification bound to its retired predecessor. */
    public static function retireRevocation(array $state,string $peerId): array
    {
        $old=$state['pairing']['peers'][$peerId]??null;if(!is_array($old)||$old['state']!=='REVOKED')return $state;
        $state['outbox']['jobs']=array_values(array_filter($state['outbox']['jobs'],static fn($j)=>!($j['receiverId']===$peerId&&$j['kind']==='REVOKE'&&$j['pairingId']===$old['pairingId'])));return $state;
    }
    public static function queueGlobal(array $state,?string $only=null): array
    {
        if(!($state['native']['globalWritable']??true))throw new RuntimeException('This shared tree is frozen or owned by another vault.');
        foreach($state['pairing']['peers']as$peer){
            if(!$peer['active']||($only!==null&&$peer['id']!==$only))continue;
            if(count($state['outbox']['jobs'])>=128)throw new RuntimeException('Peer outbox is full; synchronize or explicitly resolve pending deliveries first.');
            $seq=SecretsBackendCodec::increment($state['stream']['next'][$peer['id']]??'0');$state['stream']['next'][$peer['id']]=$seq;
            $node=$state['vault']['global'];$digest=self::digest($node);
            $payload=['treeId'=>$state['native']['globalTreeId'],'owner'=>$state['native']['vaultId'],'ownershipEpoch'=>$state['native']['ownershipEpoch'],'revision'=>$state['stream']['globalRevision'],
                'previousDigest'=>$state['stream']['queuedDigest'][$peer['id']]??str_repeat('0',64),'nodeDigest'=>$digest,'node'=>$node];
            $state['stream']['queuedDigest'][$peer['id']]=$digest;
            $state['outbox']['jobs'][]=self::job($peer,'SYNC',$payload,$seq);
        }return $state;
    }
    private function envelope(array $target,string $kind,string $pairId,string $epoch,string $id,string $sequence,array $payload): array
    {
        $header=['format'=>'SECB.Peer.1','kind'=>$kind,'sender'=>$this->descriptor()['vaultId'],'receiver'=>$target['vaultId'],'pairingId'=>$pairId,'epoch'=>$epoch,'id'=>$id,'sequence'=>$sequence,
            'payload'=>SecretsBackendCodec::b64(sodium_crypto_box_seal(SecretsBackendCodec::json($payload),SecretsBackendCodec::unb64($target['boxKey'],32)))];
        return $this->signed($header);
    }
    private static function logical(array $message,array $payload): string
    {
        unset($message['payload'],$message['signature']);return self::digest(['header'=>$message,'payload'=>$payload]);
    }
    public function receive(string $json): string
    {
        $m=SecretsFrontendConfiguration::decodeBounded($json,$this->store->metadata()['capacityBytes']*2+65536,96);
        self::exact($m,['format','kind','sender','receiver','pairingId','epoch','id','sequence','payload','signature']);
        foreach(['sender','receiver','pairingId','id']as$key){if(!is_string($m[$key]))throw new RuntimeException('Invalid peer identity.');self::uuid($m[$key]);}
        self::decimal($m['epoch']);self::decimal($m['sequence']);
        if($m['format']!=='SECB.Peer.1'||$m['receiver']!==$this->descriptor()['vaultId']||!in_array($m['kind'],['PAIR_REQUEST','PAIR_ACCEPT','SYNC','STATUS','RESYNC','REVOKE','OWNER_OFFER','TREE_SYNC'],true))throw new RuntimeException('Wrong native peer purpose or recipient.');
        if($m['kind']==='TREE_SYNC')return $this->receiveOwnedTree($m);
        $current=$this->store->read();$peer=$current['state']['pairing']['peers'][$m['sender']]??null;
        if($m['kind']!=='PAIR_REQUEST'){
            if(!is_array($peer)||$peer['pairingId']!==$m['pairingId']||$peer['epoch']!==$m['epoch']||(!$peer['active']&&!in_array($m['kind'],['PAIR_ACCEPT','REVOKE'],true)))throw new RuntimeException('Inactive or incorrectly bound pairing.');
            self::verify($m,$peer['descriptor']['signKey']);
        }
        $payload=SecretsFrontendConfiguration::decodeBounded($this->store->openPeer($m['payload']),$this->store->metadata()['capacityBytes'],96);
        $digest=self::logical($m,$payload);
        if($m['kind']==='PAIR_REQUEST'){
            self::exact($payload,['invitationId','expires','pair','proof']);$pair=$payload['pair'];self::pairCheck($pair);
            if(self::digest($pair['a'])!==self::digest($this->descriptor())||$pair['b']['vaultId']!==$m['sender']||$pair['id']!==$m['pairingId']||$pair['epoch']!==$m['epoch']||$m['sequence']!=='0')throw new RuntimeException('Pairing descriptor was swapped.');
            self::verify($m,$pair['b']['signKey']);$invite=$current['state']['native']['invites'][$payload['invitationId']]??null;
            if($peer!==null&&($peer['requestDigest']??'')===$digest){$target=$peer['descriptor'];$status=$peer['state'];}
            else{
                if(!is_array($invite)||($invite['usedBy']??null)!==null||(int)$invite['expires']<time()||$invite['expires']!==$payload['expires']
                    ||!hash_equals(hash_hmac('sha256','SECB.Pair.Request:'.SecretsBackendNativeStore::canonical($pair),SecretsBackendCodec::unb64($invite['secret'],32)),$payload['proof']))throw new RuntimeException('Pairing invitation is invalid, consumed or expired.');
                if(($peer!==null&&$peer['state']!=='REVOKED')||count($current['state']['pairing']['peers'])>=32)throw new RuntimeException('Peer already exists or pairing capacity reached.');
                $target=$pair['b'];$status='PENDING_APPROVAL';
                $this->store->change($current['head'],$m['id'],$digest,static function($s)use($m,$payload,$pair,$digest){
                    $invite=$s['native']['invites'][$payload['invitationId']]??null;if(!is_array($invite)||($invite['usedBy']??null)!==null||(int)$invite['expires']<time())throw new RuntimeException('Invitation changed during pairing.');
                    $s['native']['invites'][$payload['invitationId']]['usedBy']=$m['sender'];unset($s['native']['invites'][$payload['invitationId']]['secret']);
                    $s=self::retireRevocation($s,$m['sender']);
                    $row=self::peerRecord($pair,$pair['b'],'Peer '.substr($m['sender'],0,8),'PENDING_APPROVAL');$row+=['requestDigest'=>$digest,'requestId'=>$m['id'],'invitationId'=>$payload['invitationId'],'expires'=>$payload['expires']];
                    $s['pairing']['peers'][$m['sender']]=$row;return $s;
                },['action'=>'peer-request','actor'=>$m['sender'],'target'=>$pair['id']]);
            }
            return $this->reply($m,$target,$digest,['status'=>$status,'pairDigest'=>self::digest($pair)]);
        }
        if($m['kind']==='PAIR_ACCEPT'){
            self::exact($payload,['pairDigest','requestId']);
            if(!in_array($peer['state'],['PENDING_REMOTE','ACTIVE'],true))throw new RuntimeException('A revoked pairing cannot be reactivated by an old acceptance.');
            if($payload['pairDigest']!==self::digest($peer['pair'])||$payload['requestId']!==$peer['requestId'])throw new RuntimeException('Acceptance refers to a different approval.');
            if(!$peer['active'])$this->store->change($current['head'],$m['id'],$digest,static function($s)use($m){$s['pairing']['peers'][$m['sender']]['active']=true;$s['pairing']['peers'][$m['sender']]['state']='ACTIVE';return self::queueGlobal($s,$m['sender']);},['action'=>'peer-activate','actor'=>$m['sender'],'target'=>$peer['pairingId']]);
            return $this->reply($m,$peer['descriptor'],$digest,['status'=>'ACTIVE','pairDigest'=>self::digest($peer['pair'])]);
        }
        if($m['kind']==='OWNER_OFFER')return $this->receiveOwnerOffer($m,$payload,$peer,$current,$digest);
        if($m['kind']==='STATUS'){
            self::exact($payload,['treeId']);if($payload['treeId']!==$peer['descriptor']['treeId'])throw new RuntimeException('Peer cannot query another owner’s cursor.');$received=$current['state']['native']['received'][$payload['treeId']]??null;$nonce=SecretsBackendCodec::b64(random_bytes(32));
            $this->store->put(hash('sha256','resync:'.$nonce),'resync',['peer'=>$m['sender'],'treeId'=>$payload['treeId']],time()+120);
            return $this->reply($m,$peer['descriptor'],$digest,['status'=>'CURSOR','challenge'=>$nonce,'sequence'=>$received['sequence']??'0','revision'=>$received['revision']??'0','nodeDigest'=>$received['nodeDigest']??str_repeat('0',64)]);
        }
        if($m['kind']==='REVOKE'){
            self::exact($payload,['reason']);$this->store->change($current['head'],$m['id'],$digest,static fn($s)=>self::revoke($s,$m['sender']),['action'=>'peer-revoke','actor'=>$m['sender'],'target'=>$peer['pairingId']]);
            return $this->reply($m,$peer['descriptor'],$digest,['status'=>'REVOKED']);
        }
        $isResync=$m['kind']==='RESYNC';
        self::exact($payload,array_merge(['treeId','owner','ownershipEpoch','revision','previousDigest','nodeDigest','node'],$isResync?['challenge']:[]));
        if($payload['treeId']!==$peer['descriptor']['treeId']||$payload['owner']!==$m['sender']||$payload['ownershipEpoch']!=='1'||($payload['node']['type']??'')!=='object')throw new RuntimeException('Peer cannot write this tree or scope.');
        self::decimal($payload['revision']);if(!hash_equals(self::digest($payload['node']),$payload['nodeDigest']))throw new RuntimeException('Peer payload digest mismatch.');
        $normalized=SecretsBackendTree::parseBounded(SecretsBackendCodec::json(SecretsBackendTree::value($payload['node'])),$this->store->metadata()['capacityBytes']);
        if(self::digest($normalized)!==self::digest($payload['node']))throw new RuntimeException('Invalid typed peer tree.');
        $old=$current['state']['native']['received'][$payload['treeId']]??null;
        if($old!==null&&($old['owner']!==$m['sender']||$old['epoch']!==$payload['ownershipEpoch']))throw new RuntimeException('The old owner is no longer allowed to update this tree.');
        if($old!==null&&$m['sequence']===$old['sequence']){
            if(($old['requestDigest']??'')!==$digest||($old['requestId']??'')!==$m['id'])throw new RuntimeException('Conflicting duplicate peer sequence.');
            return $this->reply($m,$peer['descriptor'],$digest,$old['receipt']);
        }
        if((!$isResync&&$m['sequence']!==SecretsBackendCodec::increment($old['sequence']??'0'))||($isResync&&self::compare($m['sequence'],$old['sequence']??'0')<=0)||$payload['previousDigest']!==($old['nodeDigest']??str_repeat('0',64)))throw new RuntimeException('Peer delivery gap; request authenticated resynchronization.');
        if($old!==null&&(self::compare($payload['revision'],$old['revision'])<0||($payload['revision']===$old['revision']&&$payload['nodeDigest']!==$old['nodeDigest'])))throw new RuntimeException('Peer restore is stale or divergent.');
        
        $receipt=['status'=>'APPLIED','treeId'=>$payload['treeId'],'revision'=>$payload['revision'],'sequence'=>$m['sequence'],'nodeDigest'=>$payload['nodeDigest']];
        $this->store->change($current['head'],$m['id'],$digest,function($s)use($m,$payload,$digest,$receipt,$isResync){
            if($isResync){$challenge=$this->store->get(hash('sha256','resync:'.$payload['challenge']),'resync',true);if($challenge!==['peer'=>$m['sender'],'treeId'=>$payload['treeId']])throw new RuntimeException('Wrong resynchronization recipient.');}
            $peer=$s['pairing']['peers'][$m['sender']]??null;if(!is_array($peer)||!$peer['active']||$peer['epoch']!==$m['epoch'])throw new RuntimeException('Pairing was revoked before publication.');
            $s['native']['received'][$payload['treeId']]=['owner'=>$m['sender'],'epoch'=>$payload['ownershipEpoch'],'revision'=>$payload['revision'],'sequence'=>$m['sequence'],'nodeDigest'=>$payload['nodeDigest'],'node'=>$payload['node'],
                'pairingId'=>$m['pairingId'],'requestId'=>$m['id'],'requestDigest'=>$digest,'receipt'=>$receipt,'at'=>gmdate('c')];$s['pairing']['peers'][$m['sender']]['lastSync']=gmdate('c');return $s;
        },['action'=>'peer-receive','actor'=>$m['sender'],'target'=>$payload['treeId']]);
        return $this->reply($m,$peer['descriptor'],$digest,$receipt);
    }
    public static function compare(string $a,string $b): int { return strlen($a)<=>strlen($b) ?: strcmp($a,$b); }
    public static function revoke(array $state,string $peerId): array
    {
        if(isset($state['pairing']['peers'][$peerId])){$state['pairing']['peers'][$peerId]['active']=false;$state['pairing']['peers'][$peerId]['state']='REVOKED';}
        foreach($state['native']['subscriptions']??[]as$id=>$sub)if($sub['ownerDescriptor']['vaultId']===$peerId)$state['native']['subscriptions'][$id]['active']=false;
        foreach($state['native']['trees']as$id=>$tree)unset($state['native']['trees'][$id]['subscribers'][$peerId]);
        $state['outbox']['jobs']=array_values(array_filter($state['outbox']['jobs'],static fn($j)=>$j['receiverId']!==$peerId));return $state;
    }
    public static function pairCheck(array $p): void
    {
        self::exact($p,['id','epoch','a','b','scope','cachedReads']);self::uuid($p['id']);self::descriptorCheck($p['a']);self::descriptorCheck($p['b']);
        if($p['epoch']!=='1'||$p['scope']!=='global'||$p['cachedReads']!==true||$p['a']['vaultId']===$p['b']['vaultId'])throw new RuntimeException('Invalid pairing scope/epoch.');
    }
    private function reply(array $request,array $target,string $digest,array $body): string
    {
        $body=['requestId'=>$request['id'],'requestKind'=>$request['kind'],'requestDigest'=>$digest]+$body;
        return SecretsBackendCodec::json($this->envelope($target,'REPLY',$request['pairingId'],$request['epoch'],$request['id'],$request['sequence'],$body));
    }
    public function exchange(array $peer,string $kind,array $payload,string $id,string $sequence='0'): array
    {
        $target=$peer['descriptor'];$m=$this->envelope($target,$kind,$peer['pairingId'],$peer['epoch'],$id,$sequence,$payload);$bytes=SecretsBackendCodec::json($m);
        if($this->transport===null)throw new SecretsBackendNativePeerDeliveryFailure('transport');
        $response=($this->transport)($target,$bytes);
        try{$reply=SecretsFrontendConfiguration::decodeBounded($response,65536,32);self::exact($reply,['format','kind','sender','receiver','pairingId','epoch','id','sequence','payload','signature']);
        if($reply['format']!=='SECB.Peer.1'||$reply['kind']!=='REPLY'||$reply['sender']!==$target['vaultId']||$reply['receiver']!==$this->descriptor()['vaultId']||$reply['pairingId']!==$peer['pairingId']||$reply['epoch']!==$peer['epoch']||$reply['id']!==$id||$reply['sequence']!==$sequence)throw new RuntimeException('Peer reply was misbound.');
        self::verify($reply,$target['signKey']);$body=SecretsFrontendConfiguration::decode($this->store->openPeer($reply['payload']));
        if(($body['requestId']??'')!==$id||($body['requestKind']??'')!==$kind||($body['requestDigest']??'')!==self::logical($m,$payload))throw new RuntimeException('Peer acknowledgement does not match the immutable request.');
        return $body;
        }catch(Throwable $e){throw new SecretsBackendNativePeerDeliveryFailure('invalid-reply');}
    }
    public function dispatch(int $maximum=2): array
    {
        $results=[];
        for($n=0;$n<$maximum;++$n){$current=$this->store->read();$job=null;
            $seen=[];foreach($current['state']['outbox']['jobs']as$item){if(isset($seen[$item['receiverId']]))continue;$seen[$item['receiverId']]=true;
                try{$backoff=$this->store->get('backoff:'.$item['id'],'delivery-backoff');}catch(Throwable $ignored){$backoff=['nextAttemptAt'=>0,'attempts'=>0];}
                if(($item['status']??'')==='queued'&&$backoff['nextAttemptAt']<=time()){$job=$item;break;}}
            if($job===null)break;$peer=$current['state']['pairing']['peers'][$job['receiverId']]??null;
            if($job['kind']==='TREE_SYNC'){$tree=$current['state']['native']['trees'][$job['treeId']]??null;$subscriber=$tree['subscribers'][$job['receiverId']]??null;if(!is_array($tree)||$tree['frozen']||!is_array($subscriber))break;$peer=['id'=>$job['receiverId'],'pairingId'=>$subscriber['subscriptionId'],'epoch'=>$tree['epoch'],'descriptor'=>$subscriber['descriptor'],'active'=>true];}
            if(!is_array($peer)||$peer['pairingId']!==$job['pairingId']||$peer['epoch']!==$job['epoch']||(!$peer['active']&&!in_array($job['kind'],['PAIR_REQUEST','REVOKE'],true)))break;
            try{$reply=$this->exchange($peer,$job['kind'],$job['payload'],$job['id'],$job['sequence']);
                $expected=match($job['kind']){'PAIR_REQUEST'=>['PENDING_APPROVAL','ACTIVE'],'PAIR_ACCEPT'=>['ACTIVE'],'SYNC','RESYNC'=>['APPLIED'],'REVOKE'=>['REVOKED'],'OWNER_OFFER'=>['OFFER_RECEIVED'],'TREE_SYNC'=>['TREE_APPLIED'],default=>[]};
                if(!in_array($reply['status']??'',$expected,true))throw new RuntimeException('Peer did not acknowledge the expected operation.');
                if(in_array($job['kind'],['SYNC','RESYNC','TREE_SYNC'],true)&&(($reply['treeId']??'')!==($job['payload']['treeId']??$job['payload']['tree']['treeId'])||($reply['revision']??'')!==($job['payload']['revision']??$job['payload']['tree']['revision'])||($reply['sequence']??'')!==$job['sequence']||($reply['nodeDigest']??'')!==($job['payload']['nodeDigest']??$job['payload']['tree']['nodeDigest'])))throw new RuntimeException('Peer receipt names another snapshot.');
                $latest=$this->store->read();$this->store->change($latest['head'],$job['ackId'],self::digest($reply),static function($s)use($job,$reply){
                    $s['outbox']['jobs']=array_values(array_filter($s['outbox']['jobs'],static fn($x)=>$x['id']!==$job['id']));
                    $s['native']['deliveryReceipts'][$job['receiverId']]=array_replace($reply,['pairingId'=>$job['pairingId']]);return $s;
                },['action'=>'peer-receipt','actor'=>$job['receiverId'],'target'=>$job['id']]);$results[]=['id'=>$job['id'],'status'=>'ACKNOWLEDGED'];
            }catch(Throwable $e){
                $key='backoff:'.$job['id'];try{$backoff=$this->store->get($key,'delivery-backoff');}catch(Throwable $ignored){$backoff=['attempts'=>0];}
                $attempts=min(20,$backoff['attempts']+1);$body=['attempts'=>$attempts,'lastAttemptAt'=>time(),'nextAttemptAt'=>time()+min(300,2**$attempts),
                    'problem'=>$e instanceof SecretsBackendNativePeerDeliveryFailure&&in_array($e->problem,SecretsBackendNativePeerDeliveryFailure::PROBLEMS,true)?$e->problem:'unconfirmed',
                    'httpStatus'=>$e instanceof SecretsBackendNativePeerDeliveryFailure?$e->httpStatus:0,'curlCode'=>$e instanceof SecretsBackendNativePeerDeliveryFailure?$e->curlCode:0];
                try{$this->store->replace($key,'delivery-backoff',$body,time()+3600);}catch(Throwable $ignored){$this->store->put($key,'delivery-backoff',$body,time()+3600);}
                $results[]=['id'=>$job['id'],'status'=>'RETRY_PENDING'];break;
            }
        }return $results;
    }
    /** Reads local retry records only. Never returns payloads, response bodies or exception text. */
    public function deliveryStatus(array $state): array
    {
        $out=[];foreach($state['outbox']['jobs']as$job){
            if(isset($out[$job['receiverId']]))continue;
            $safe=['jobId'=>$job['id'],'kind'=>$job['kind'],'attempts'=>0,'lastAttemptAt'=>0,'nextAttemptAt'=>0,'problem'=>'not-attempted','httpStatus'=>0,'curlCode'=>0];
            try{$b=$this->store->get('backoff:'.$job['id'],'delivery-backoff');
                foreach(['attempts','lastAttemptAt','nextAttemptAt','httpStatus','curlCode']as$key)$safe[$key]=max(0,(int)($b[$key]??0));
                $safe['problem']=in_array($b['problem']??'',SecretsBackendNativePeerDeliveryFailure::PROBLEMS,true)?$b['problem']:'unconfirmed';
            }catch(Throwable $ignored){}
            $out[$job['receiverId']]=$safe;
        }return $out;
    }
}
