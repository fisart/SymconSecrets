<?php
declare(strict_types=1);
require_once __DIR__ . '/NativeStore.php';
require_once __DIR__ . '/PeerName.php';
require_once __DIR__ . '/AutomaticSetup.php';
require_once __DIR__ . '/Tree.php';
require_once __DIR__ . '/SharedGlobal.php';
require_once __DIR__ . '/NativeHealth.php';
require_once __DIR__ . '/MeshStatus.php';
require_once __DIR__ . '/BackupOriginPolicy.php';
require_once __DIR__ . '/NativeTransfer.php';
require_once __DIR__ . '/NativeLegacyHTTPS.php';
require_once __DIR__ . '/../SecretsFrontend/Configuration.php';

/** Public delivery diagnostics contain fixed categories and numeric codes only. */
final class SecretsBackendNativePeerDeliveryFailure extends RuntimeException
{
    public array $attempts=[];
    public const PROBLEMS=['dns','connect','timeout','certificate','tls','http','response-size','invalid-reply','transport','unconfirmed'];
    public const CERTIFICATE_REASONS=['issuer-untrusted','chain-unverified','hostname-mismatch','expired','not-yet-valid','self-signed','revoked','ca-store-unavailable','pin-mismatch','unknown'];
    public function __construct(public readonly string $problem, public readonly int $httpStatus=0, public readonly int $curlCode=0,
        public readonly int $tlsVerifyResult=-1, public readonly string $certificateReason='unknown', public readonly array $caTrust=[])
    { parent::__construct('Native peer delivery is unconfirmed.'); }
    public static function transport(int $curlCode,int $httpStatus,bool $tooLarge=false,int $tlsVerifyResult=-1,string $error='',array $caTrust=[]): self
    {
        $problem=$tooLarge?'response-size':($curlCode===0?'http':match($curlCode){5,6=>'dns',7=>'connect',28=>'timeout',51,58,60,77,82,83,90,91=>'certificate',35,59,64,66,80=>'tls',default=>'unconfirmed'});
        $error=strtolower($error);$reason='unknown';
        foreach(['no alternative certificate subject name'=>'hostname-mismatch','does not match target host'=>'hostname-mismatch','certificate has expired'=>'expired','certificate is not yet valid'=>'not-yet-valid','self-signed certificate'=>'self-signed','unable to get local issuer certificate'=>'issuer-untrusted','unable to verify the first certificate'=>'chain-unverified','certificate revoked'=>'revoked']as$phrase=>$candidate)if(str_contains($error,$phrase)){$reason=$candidate;break;}
        return new self($problem,$httpStatus,$curlCode,$tlsVerifyResult,$reason,$caTrust);
    }
    public static function tlsDetails(array $data): array
    {
        $safe=['tlsVerifyResult'=>max(-1,(int)($data['tlsVerifyResult']??-1)),'certificateReason'=>in_array($data['certificateReason']??'',self::CERTIFICATE_REASONS,true)?$data['certificateReason']:'unknown','caTrust'=>[]];
        foreach(['fileSpecified','fileReadable','directorySpecified','directoryReadable']as$key)$safe['caTrust'][$key]=is_bool($data['caTrust'][$key]??null)?$data['caTrust'][$key]:null;
        $source=$data['caTrust']['source']??'unavailable';$safe['caTrust']['source']=in_array($source,['curl-configured','openssl-configured','environment-configured','curl-default','openssl-default','system','bundled','native','certificate-pinned','unavailable'],true)?$source:'unavailable';
        return $safe;
    }
}

/** Optional bilateral encrypted synchronization. Every vault remains independently usable. */
final class SecretsBackendNativePeer
{
    use SecretsBackendNativeTransfer;
    private $transport;
    public function __construct(private SecretsBackendNativeStore $store, private string $endpoint, ?callable $transport = null, private bool $automaticGlobal=true,private $meshComponents=null,private $setupClock=null,private $setupDiagnostics=null) { self::endpoint($endpoint); $this->transport = $transport; }
    public function setupRuntimeDiagnostics():array { try{return $this->setupDiagnostics!==null?($this->setupDiagnostics)():[];}catch(Throwable $ignored){return [];} }
    public function automaticSetup(?callable $sync=null):SecretsBackendAutomaticSetup { return new SecretsBackendAutomaticSetup($this->store,$this,$sync,$this->setupClock); }
    public function meshReport(array $state,bool $detailed=true,bool $mailbox=false):array {
        try{$runtime=$this->meshComponents!==null?($this->meshComponents)($state):[];}catch(Throwable $ignored){$runtime=[];}
        $report=(new SecretsBackendMeshStatus($this->store,$this))->report($state,$runtime);if(!$detailed)foreach($report['links']as&$l)foreach(['primary','backup']as$k)$l[$k]=array_intersect_key($l[$k],array_flip(['state','age']));unset($l);if($mailbox){$report['mailbox']=SecretsBackendMailbox::local($state,true,(bool)$this->store->pendingBackupCandidates());while(strlen(SecretsBackendCodec::json($report))>24000&&$report['mailbox']['rows']){array_pop($report['mailbox']['rows']);$report['mailbox']['partial']=true;}while(strlen(SecretsBackendCodec::json($report))>24000&&$report['links']){array_pop($report['links']);$report['truncated']=true;}}return $report;
    }
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
    public function invitation(bool $SharedGlobal=false): array
    {
        $i=['format'=>'SECB.Invitation.1','id'=>SecretsBackendCodec::uuid(),'issuer'=>$this->descriptor(),'secret'=>SecretsBackendCodec::b64(random_bytes(32)),'expires'=>(string)(time()+900),'scope'=>$SharedGlobal?SecretsBackendSharedGlobal::SCOPE:'global'];
        return $this->signed($i);
    }
    public static function invitationText(array $i): string { return 'SECBPAIR1.'.SecretsBackendCodec::b64(SecretsBackendCodec::json($i)); }
    public static function readInvitation(string $text): array
    {
        if(!str_starts_with($text,'SECBPAIR1.')||strlen($text)>16384)throw new RuntimeException('Paste the invitation generated by the other vault.');
        $i=SecretsFrontendConfiguration::decode(SecretsBackendCodec::unb64(substr($text,10)));
        self::exact($i,['format','id','issuer','secret','expires','scope','signature']);self::uuid($i['id']);self::descriptorCheck($i['issuer']);
        if($i['format']!=='SECB.Invitation.1'||!in_array($i['scope'],['global',SecretsBackendSharedGlobal::SCOPE],true)||!preg_match('/^[0-9]{1,12}$/D',$i['expires'])||(int)$i['expires']<time()||(int)$i['expires']>time()+3600)throw new RuntimeException('The invitation expired or has invalid scope.');
        SecretsBackendCodec::unb64($i['secret'],32);self::verify($i,$i['issuer']['signKey']);return $i;
    }
    public function pairOperation(string $text,string $name): array
    {
        $i=self::readInvitation($text);if($i['issuer']['vaultId']===$this->descriptor()['vaultId'])throw new RuntimeException('A vault cannot pair with itself.');
        $pair=['id'=>SecretsBackendCodec::uuid(),'epoch'=>'1','a'=>$i['issuer'],'b'=>$this->descriptor(),'scope'=>$i['scope'],'cachedReads'=>true];
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
    public static function shared(array $peer): bool { return ($peer['globalMode']??$peer['pair']['scope']??'')===SecretsBackendSharedGlobal::SCOPE; }
    public static function queueGlobal(array $state,?string $only=null): array
    {
        foreach($state['pairing']['peers']as$p)if($p['active']&&self::shared($p)){$state=SecretsBackendSharedGlobal::enable($state);break;}
        $state=SecretsBackendSharedGlobal::capture($state);
        if(!($state['native']['globalWritable']??true))throw new RuntimeException('This shared tree is frozen or owned by another vault.');
        foreach($state['pairing']['peers']as$peer){
            if(!$peer['active']||($only!==null&&$peer['id']!==$only)||(isset($state['native']['sharedGlobal'])&&!self::shared($peer)))continue;
            if(count($state['outbox']['jobs'])>=128)throw new RuntimeException('Peer outbox is full; synchronize or explicitly resolve pending deliveries first.');
            $seq=SecretsBackendCodec::increment($state['stream']['next'][$peer['id']]??'0');$state['stream']['next'][$peer['id']]=$seq;
            $payload=self::globalPayload($state,$peer,$state['stream']['queuedDigest'][$peer['id']]??str_repeat('0',64));$digest=$payload['nodeDigest'];
            $state['stream']['queuedDigest'][$peer['id']]=$digest;
            $state['outbox']['jobs'][]=self::job($peer,'SYNC',$payload,$seq);
        }return $state;
    }
    public static function globalPayload(array $s,array $peer,string $previous): array
    {
        $node=$s['vault']['global'];$extra=[];
        if(self::shared($peer))$extra=['merge'=>$s['native']['sharedGlobal']];
        elseif(isset($s['native']['sharedGlobal']))throw new RuntimeException('Approve shared Global access before sending merged secrets to an old connection.');
        return ['treeId'=>$s['native']['globalTreeId'],'owner'=>$s['native']['vaultId'],'ownershipEpoch'=>$s['native']['ownershipEpoch'],'revision'=>$s['stream']['globalRevision'],'previousDigest'=>$previous,'nodeDigest'=>self::digest($extra?['node'=>$node]+$extra:$node),'node'=>$node]+$extra;
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
        // These handlers perform local verification/metadata work only. Use one
        // fresh locked snapshot for the whole authenticated reply, not dozens of
        // decrypt/reload cycles for its nested cache reads. Never include a
        // handler that performs outbound I/O in this list.
        $header=strlen($json)<=65536?json_decode($json,true,16):null;
        if(is_array($header)&&in_array($header['kind']??null,['SETUP_HELLO','SETUP_INFO','HEALTH','MESH_STATUS'],true)){
            $failure=null;
            $reply=$this->store->withActiveSnapshot(function()use($json,&$failure):?string{
                try{return $this->receiveEnvelope($json);}catch(Throwable $e){$failure=$e;return null;}
            });
            // Rejected signed requests must still consume their rate allowance.
            if($failure!==null)throw $failure;
            return $reply;
        }
        return $this->receiveEnvelope($json);
    }
    private function receiveEnvelope(string $json): string
    {
        $m=SecretsFrontendConfiguration::decodeBounded($json,$this->store->metadata()['capacityBytes']*2+65536,96);
        self::exact($m,['format','kind','sender','receiver','pairingId','epoch','id','sequence','payload','signature']);
        foreach(['sender','receiver','pairingId','id']as$key){if(!is_string($m[$key]))throw new RuntimeException('Invalid peer identity.');self::uuid($m[$key]);}
        self::decimal($m['epoch']);self::decimal($m['sequence']);
        if($m['format']!=='SECB.Peer.1'||$m['receiver']!==$this->descriptor()['vaultId']||!in_array($m['kind'],['SETUP_INFO','SETUP_ENROLL','SETUP_OFFER','SETUP_HELLO','SETUP_ADVANCE','SETUP_PRUNE','MESH_STATUS','EMERGENCY_OFFER','HEALTH','ROUTES','GLOBAL_ENABLE','PAIR_REQUEST','PAIR_ACCEPT','SYNC','STATUS','RESYNC','REVOKE','OWNER_OFFER','TREE_SYNC'],true))throw new RuntimeException('Wrong native peer purpose or recipient.');
        if(in_array($m['kind'],['SETUP_HELLO','SETUP_ADVANCE','SETUP_PRUNE'],true)){
            $cur=$this->store->read();$policy=$cur['state']['native']['setupProposal']??null;$sender=null;
            if($policy&&$policy['id']===$m['pairingId'])foreach($policy['members']as$member)if($member['descriptor']['vaultId']===$m['sender'])$sender=$member['descriptor'];
            if(!$sender)throw new RuntimeException('Unknown setup policy or sender.');self::verify($m,$sender['signKey']);
            $payload=SecretsFrontendConfiguration::decodeBounded($this->store->openPeer($m['payload']),32768,32);$digest=self::logical($m,$payload);
            return $this->reply($m,$sender,$digest,$this->automaticSetup()->receive($m['kind'],$m,$payload,$cur['state']));
        }
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
            if((!hash_equals(self::authority($pair['a']),self::authority($this->descriptor()))||$pair['a']['treeId']!==$this->descriptor()['treeId']||!in_array($pair['a']['endpoint'],$this->ownRoutes($current['state']),true))||$pair['b']['vaultId']!==$m['sender']||$pair['id']!==$m['pairingId']||$pair['epoch']!==$m['epoch']||$m['sequence']!=='0')throw new RuntimeException('Pairing descriptor was swapped.');
            self::verify($m,$pair['b']['signKey']);$invite=$current['state']['native']['invites'][$payload['invitationId']]??null;
            if($peer!==null&&($peer['requestDigest']??'')===$digest){$target=$peer['descriptor'];$status=$peer['state'];}
            else{
                if(!is_array($invite)||($invite['usedBy']??null)!==null||(int)$invite['expires']<time()||$invite['expires']!==$payload['expires']||($invite['scope']??'global')!==$pair['scope']
                    ||!hash_equals(hash_hmac('sha256','SECB.Pair.Request:'.SecretsBackendNativeStore::canonical($pair),SecretsBackendCodec::unb64($invite['secret'],32)),$payload['proof']))throw new RuntimeException('Pairing invitation is invalid, consumed or expired.');
                if(($peer!==null&&$peer['state']!=='REVOKED')||count($current['state']['pairing']['peers'])>=32)throw new RuntimeException('Peer already exists or pairing capacity reached.');
                $target=$pair['b'];$status='PENDING_APPROVAL';
                $this->store->change($current['head'],$m['id'],$digest,static function($s)use($m,$payload,$pair,$digest){
                    $invite=$s['native']['invites'][$payload['invitationId']]??null;if(!is_array($invite)||($invite['usedBy']??null)!==null||(int)$invite['expires']<time())throw new RuntimeException('Invitation changed during pairing.');
                    $s['native']['invites'][$payload['invitationId']]['usedBy']=$m['sender'];unset($s['native']['invites'][$payload['invitationId']]['secret']);
                    $s=self::retireRevocation($s,$m['sender']);
                    $row=self::peerRecord($pair,$pair['b'],SecretsBackendPeerName::address($pair['b']['endpoint']),'PENDING_APPROVAL');$row+=['requestDigest'=>$digest,'requestId'=>$m['id'],'invitationId'=>$payload['invitationId'],'expires'=>$payload['expires']];
                    // Preserve only an already approved local TLS policy for this exact HTTPS authority.
                    $previous=$s['pairing']['peers'][$m['sender']]??null;
                    if(isset($previous['httpsPolicy'])&&SecretsBackendNativeLegacyHTTPS::origin($previous['descriptor']['endpoint'])===SecretsBackendNativeLegacyHTTPS::origin($row['descriptor']['endpoint']))$row['httpsPolicy']=$previous['httpsPolicy'];
                    $s['pairing']['peers'][$m['sender']]=$row;unset($s['stream']['next'][$m['sender']],$s['stream']['queuedDigest'][$m['sender']],$s['native']['deliveryReceipts'][$m['sender']]);return $s;
                },['action'=>'peer-request','actor'=>$m['sender'],'target'=>$pair['id']]);
            }
            return $this->reply($m,$target,$digest,['status'=>$status,'pairDigest'=>self::digest($pair)]);
        }
        if($m['kind']==='EMERGENCY_OFFER'){
            require_once __DIR__.'/Emergency.php';self::exact($payload,['grantId','package']);
            $c=SecretsBackendEmergency::importGrant($current['state'],$payload['package']);
            if($c['peerId']!==$m['sender']||$c['grantId']!==$payload['grantId'])throw new RuntimeException('Emergency offer is misbound.');
            $this->store->change($current['head'],$m['id'],$digest,static function($s)use($m,$payload){
                $c=SecretsBackendEmergency::importGrant($s,$payload['package']);
                $s['native']['emergencyOffers'][$m['sender']]=['grantId'=>$c['grantId'],'package'=>$payload['package']];return $s;
            },['action'=>'emergency-offer','actor'=>$m['sender'],'target'=>$payload['grantId']]);
            return $this->reply($m,$peer['descriptor'],$digest,['status'=>'EMERGENCY_OFFER_RECEIVED','grantId'=>$payload['grantId']]);
        }
        if($m['kind']==='SETUP_INFO'){self::exact($payload,['format']);if($payload['format']!==SecretsBackendAutomaticSetup::FORMAT)throw new RuntimeException('Invalid setup discovery purpose.');return $this->reply($m,$peer['descriptor'],$digest,['status'=>'SETUP_INFO']+$this->automaticSetup()->info($current['state']));}
        if($m['kind']==='SETUP_ENROLL'){
            self::exact($payload,['policy','token']);$setup=$this->automaticSetup();
            if(in_array($payload['policy']['id']??'', $current['state']['native']['setupRevokedPlans']??[],true))return $this->reply($m,$peer['descriptor'],$digest,['status'=>'SETUP_STOPPED']);
            $this->store->change($current['head'],$m['id'],$digest,fn($s)=>$setup->enroll($s,$payload['policy'],$payload['token'],null,$m['sender']),['action'=>'setup-enroll-trusted-mesh','actor'=>$m['sender'],'target'=>$m['pairingId']]);
            return $this->reply($m,$peer['descriptor'],$digest,['status'=>'SETUP_ENROLLED']);
        }
        if($m['kind']==='SETUP_OFFER'){
            self::exact($payload,['policy']);$setup=$this->automaticSetup();
            if(in_array($payload['policy']['id']??'', $current['state']['native']['setupRevokedPlans']??[],true))return $this->reply($m,$peer['descriptor'],$digest,['status'=>'SETUP_STOPPED']);
            $this->store->change($current['head'],$m['id'],$digest,fn($s)=>$setup->offer($s,$payload['policy']),['action'=>'setup-proposal','actor'=>$m['sender'],'target'=>$m['pairingId']]);
            return $this->reply($m,$peer['descriptor'],$digest,['status'=>'SETUP_OFFER_RECEIVED']);
        }
        if($m['kind']==='ROUTES'){
            self::exact($payload,['revision','endpoints']);self::decimal($payload['revision']);
            if(!is_array($payload['endpoints'])||!array_is_list($payload['endpoints'])||count($payload['endpoints'])<1||count($payload['endpoints'])>2||count(array_unique($payload['endpoints']))!==count($payload['endpoints']))throw new RuntimeException('Invalid approved routes.');
            foreach($payload['endpoints']as$endpoint){self::endpoint($endpoint);if(parse_url($endpoint,PHP_URL_PATH)!=='/hook/secrets_peer_'.$peer['descriptor']['backend'])throw new RuntimeException('Route changed backend identity.');}
            $old=$peer['routes']??null;
            if($old!==null&&(self::compare($payload['revision'],$old['revision'])<0||($payload['revision']===$old['revision']&&self::digest($payload)!==self::digest($old))))throw new RuntimeException('Stale or conflicting routes.');
            if($old!==$payload)$this->store->change($current['head'],$m['id'],$digest,static function($s)use($m,$payload){$s['pairing']['peers'][$m['sender']]['routes']=$payload;return $s;},['action'=>'peer-routes','actor'=>$m['sender'],'target'=>$m['pairingId']]);
            return $this->reply($m,$peer['descriptor'],$digest,['status'=>'ROUTES_ACCEPTED','revision'=>$payload['revision']]);
        }
        if($m['kind']==='GLOBAL_ENABLE'){
            self::exact($payload,['mode']);if($payload['mode']!==SecretsBackendSharedGlobal::SCOPE||!$peer['active'])throw new RuntimeException('Shared Global requires an active connection.');
            if(!self::shared($peer))$this->store->change($current['head'],$m['id'],$digest,static function($s)use($m){$s['pairing']['peers'][$m['sender']]['globalMode']=SecretsBackendSharedGlobal::SCOPE;$s=SecretsBackendSharedGlobal::enable($s);return self::queueGlobal($s,$m['sender']);},['action'=>'global-connect','actor'=>$m['sender'],'target'=>$m['pairingId']]);
            return $this->reply($m,$peer['descriptor'],$digest,['status'=>'GLOBAL_ENABLED','mode'=>SecretsBackendSharedGlobal::SCOPE]);
        }
        if($m['kind']==='PAIR_ACCEPT'){
            self::exact($payload,['pairDigest','requestId']);
            if(!in_array($peer['state'],['PENDING_REMOTE','ACTIVE'],true))throw new RuntimeException('A revoked pairing cannot be reactivated by an old acceptance.');
            if($payload['pairDigest']!==self::digest($peer['pair'])||$payload['requestId']!==$peer['requestId'])throw new RuntimeException('Acceptance refers to a different approval.');
            if(!$peer['active'])$this->store->change($current['head'],$m['id'],$digest,static function($s)use($m){$s['pairing']['peers'][$m['sender']]['active']=true;$s['pairing']['peers'][$m['sender']]['state']='ACTIVE';return self::queueGlobal($s,$m['sender']);},['action'=>'peer-activate','actor'=>$m['sender'],'target'=>$peer['pairingId']]);
            return $this->reply($m,$peer['descriptor'],$digest,['status'=>'ACTIVE','pairDigest'=>self::digest($peer['pair'])]);
        }
        if($m['kind']==='OWNER_OFFER'&&isset($current['state']['native']['sharedGlobal']))throw new RuntimeException('Shared Global does not accept single-owner offers.');
        if($m['kind']==='OWNER_OFFER')return $this->receiveOwnerOffer($m,$payload,$peer,$current,$digest);
        if($m['kind']==='MESH_STATUS'){
            self::exact($payload,['format']);if(!in_array($payload['format'],[SecretsBackendMeshStatus::FORMAT,SecretsBackendMeshStatus::DETAILS,SecretsBackendMeshStatus::MAILBOX],true)||!self::shared($peer)||$peer['state']!=='ACTIVE')throw new RuntimeException('Wrong mesh status scope.');
            return $this->reply($m,$peer['descriptor'],$digest,['status'=>'MESH_STATUS','report'=>$this->meshReport($current['state'],$payload['format']!==SecretsBackendMeshStatus::FORMAT,$payload['format']===SecretsBackendMeshStatus::MAILBOX)]);
        }
        if($m['kind']==='HEALTH'){
            self::exact($payload,['format']);if($payload['format']!==SecretsBackendNativeHealth::FORMAT||!self::shared($peer))throw new RuntimeException('Wrong health protocol or sharing scope.');
            return $this->reply($m,$peer['descriptor'],$digest,['status'=>'GLOBAL_HEALTH','format'=>SecretsBackendNativeHealth::FORMAT]+SecretsBackendNativeHealth::stamp($current['state']));
        }
        if($m['kind']==='STATUS'){
            self::exact($payload,['treeId']);if($payload['treeId']!==$peer['descriptor']['treeId'])throw new RuntimeException('Peer cannot query another owner’s cursor.');$received=$current['state']['native']['received'][$payload['treeId']]??null;$nonce=SecretsBackendCodec::b64(random_bytes(32));if(($received['pairingId']??null)!==$m['pairingId'])$received=null;
            $this->store->put(hash('sha256','resync:'.$nonce),'resync',['peer'=>$m['sender'],'treeId'=>$payload['treeId']],time()+120);
            return $this->reply($m,$peer['descriptor'],$digest,['status'=>'CURSOR','challenge'=>$nonce,'sequence'=>$received['sequence']??'0','revision'=>$received['revision']??'0','nodeDigest'=>$received['nodeDigest']??str_repeat('0',64)]);
        }
        if($m['kind']==='REVOKE'){
            self::exact($payload,['reason']);$this->store->change($current['head'],$m['id'],$digest,static fn($s)=>self::revoke($s,$m['sender']),['action'=>'peer-revoke','actor'=>$m['sender'],'target'=>$peer['pairingId']]);
            return $this->reply($m,$peer['descriptor'],$digest,['status'=>'REVOKED']);
        }
        $isResync=$m['kind']==='RESYNC';$shared=isset($payload['merge']);if($shared&&!self::shared($peer))throw new RuntimeException('Shared Global negotiation is incomplete.');
        self::exact($payload,array_merge(['treeId','owner','ownershipEpoch','revision','previousDigest','nodeDigest','node'],$isResync?['challenge']:[],$shared?['merge']:[]));
        if($shared){SecretsBackendSharedGlobal::validate($payload['merge']);if(self::digest(SecretsBackendSharedGlobal::view($payload['merge'])['node'])!==self::digest($payload['node']))throw new RuntimeException('Shared Global projection does not match its versions.');}
        if($payload['treeId']!==$peer['descriptor']['treeId']||$payload['owner']!==$m['sender']||$payload['ownershipEpoch']!=='1'||($payload['node']['type']??'')!=='object')throw new RuntimeException('Peer cannot write this tree or scope.');
        self::decimal($payload['revision']);if(!hash_equals(self::digest($shared?['node'=>$payload['node'],'merge'=>$payload['merge']]:$payload['node']),$payload['nodeDigest']))throw new RuntimeException('Peer payload digest mismatch.');
        if($shared&&isset($current['state']['native']['sharedGlobal'])){
            $local=SecretsBackendNativeHealth::stamp($current['state']);
            if(SecretsBackendNativeStore::canonical($local['clock'])===SecretsBackendNativeStore::canonical($payload['merge']['clock'])&&!hash_equals($local['digest'],self::digest($payload['merge'])))throw new RuntimeException('Global history differs for the same version clock.');
        }
        $normalized=SecretsBackendTree::parseBounded(SecretsBackendCodec::json(SecretsBackendTree::value($payload['node'])),$this->store->metadata()['capacityBytes']);
        if(self::digest($normalized)!==self::digest($payload['node']))throw new RuntimeException('Invalid typed peer tree.');
        $old=$current['state']['native']['received'][$payload['treeId']]??null;
        if($old!==null&&($old['owner']!==$m['sender']||$old['epoch']!==$payload['ownershipEpoch']))throw new RuntimeException('The old owner is no longer allowed to update this tree.');
        $cursor=($old['pairingId']??null)===$m['pairingId']?$old:null;
        if($cursor!==null&&$m['sequence']===$cursor['sequence']){
            if(($old['requestDigest']??'')!==$digest||($old['requestId']??'')!==$m['id'])throw new RuntimeException('Conflicting duplicate peer sequence.');
            return $this->reply($m,$peer['descriptor'],$digest,$old['receipt']);
        }
        if((!$isResync&&$m['sequence']!==SecretsBackendCodec::increment($cursor['sequence']??'0'))||($isResync&&self::compare($m['sequence'],$cursor['sequence']??'0')<=0)||$payload['previousDigest']!==($cursor['nodeDigest']??str_repeat('0',64))){if($shared&&!$isResync)return $this->reply($m,$peer['descriptor'],$digest,['status'=>'RESYNC_REQUIRED']);throw new RuntimeException('Peer delivery gap; request authenticated resynchronization.');}
        if($old!==null&&(self::compare($payload['revision'],$old['revision'])<0||($payload['revision']===$old['revision']&&$payload['nodeDigest']!==$old['nodeDigest'])))throw new RuntimeException('Peer restore is stale or divergent.');
        
        $receipt=['status'=>'APPLIED','treeId'=>$payload['treeId'],'revision'=>$payload['revision'],'sequence'=>$m['sequence'],'nodeDigest'=>$payload['nodeDigest']];
        $this->store->change($current['head'],$m['id'],$digest,function($s)use($m,$payload,$digest,$receipt,$isResync,$shared){
            if($isResync){$challenge=$this->store->get(hash('sha256','resync:'.$payload['challenge']),'resync',true);if($challenge!==['peer'=>$m['sender'],'treeId'=>$payload['treeId']])throw new RuntimeException('Wrong resynchronization recipient.');}
            $peer=$s['pairing']['peers'][$m['sender']]??null;if(!is_array($peer)||!$peer['active']||$peer['epoch']!==$m['epoch'])throw new RuntimeException('Pairing was revoked before publication.');
            $s['native']['received'][$payload['treeId']]=['owner'=>$m['sender'],'epoch'=>$payload['ownershipEpoch'],'revision'=>$payload['revision'],'sequence'=>$m['sequence'],'nodeDigest'=>$payload['nodeDigest'],'node'=>$payload['node'],
                'shared'=>$shared,'pairingId'=>$m['pairingId'],'requestId'=>$m['id'],'requestDigest'=>$digest,'receipt'=>$receipt,'at'=>gmdate('c')];$s['pairing']['peers'][$m['sender']]['lastSync']=gmdate('c');
            if($shared){$before=self::digest($s['native']['sharedGlobal']??[]);$s=SecretsBackendSharedGlobal::receive($s,$payload['merge']);if(self::digest($s['native']['sharedGlobal'])!==$before)$s=self::queueGlobal($s);else $s=SecretsBackendNativeHealth::feedback($s,$m['sender'],$payload['merge']);}
            return $s;
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
        if($p['epoch']!=='1'||!in_array($p['scope'],['global',SecretsBackendSharedGlobal::SCOPE],true)||$p['cachedReads']!==true||$p['a']['vaultId']===$p['b']['vaultId'])throw new RuntimeException('Invalid pairing scope/epoch.');
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
        $routes=$peer['routes']['endpoints']??[$target['endpoint']];$failure=null;$attempts=[];foreach($routes as$endpoint){$route=$target;$route['endpoint']=$endpoint;
        $started=microtime(true);$responded=false;try{$policy=SecretsBackendNativeLegacyHTTPS::origin($endpoint)===SecretsBackendNativeLegacyHTTPS::origin($target['endpoint'])?($peer['httpsPolicy']??['mode'=>'strict']):['mode'=>'strict'];$response=($this->transport)($route,$bytes,$policy);$responded=true;
$reply=SecretsFrontendConfiguration::decodeBounded($response,65536,32);self::exact($reply,['format','kind','sender','receiver','pairingId','epoch','id','sequence','payload','signature']);
        if($reply['format']!=='SECB.Peer.1'||$reply['kind']!=='REPLY'||$reply['sender']!==$target['vaultId']||$reply['receiver']!==$this->descriptor()['vaultId']||$reply['pairingId']!==$peer['pairingId']||$reply['epoch']!==$peer['epoch']||$reply['id']!==$id||$reply['sequence']!==$sequence)throw new RuntimeException('Peer reply was misbound.');
        self::verify($reply,$target['signKey']);$body=SecretsFrontendConfiguration::decode($this->store->openPeer($reply['payload']));
        if(($body['requestId']??'')!==$id||($body['requestKind']??'')!==$kind||($body['requestDigest']??'')!==self::logical($m,$payload))throw new RuntimeException('Peer acknowledgement does not match the immutable request.');
        return $body;
        }catch(Throwable $e){$failure=$e instanceof SecretsBackendNativePeerDeliveryFailure?$e:new SecretsBackendNativePeerDeliveryFailure($responded?'invalid-reply':'unconfirmed');$attempts[]=['route'=>$endpoint,'elapsedMs'=>(int)round((microtime(true)-$started)*1000),'code'=>in_array($failure->problem,SecretsBackendNativePeerDeliveryFailure::PROBLEMS,true)?$failure->problem:'unconfirmed','httpStatus'=>max(0,min(599,$failure->httpStatus)),'certificateReason'=>in_array($failure->certificateReason,SecretsBackendNativePeerDeliveryFailure::CERTIFICATE_REASONS,true)?$failure->certificateReason:'unknown'];$failure->attempts=$attempts;}}throw $failure??new SecretsBackendNativePeerDeliveryFailure('transport');
    }
    private function recoverGlobalGap(array $peer,array $job): void
    {
        $cursor=$this->exchange($peer,'STATUS',['treeId'=>$job['payload']['treeId']],SecretsBackendCodec::uuid());
        if(($cursor['status']??'')!=='CURSOR')throw new RuntimeException('Peer cursor is unavailable.');
        $cur=$this->store->read();$this->store->change($cur['head'],SecretsBackendCodec::uuid(),self::digest($cursor),static function($s)use($peer,$cursor){
            $p=$s['pairing']['peers'][$peer['id']]??null;if(!$p||!$p['active']||$p['pairingId']!==$peer['pairingId']||!self::shared($p))throw new RuntimeException('Connection changed during automatic resynchronization.');
            if(self::compare($cursor['revision'],$s['stream']['globalRevision'])>0)throw new RuntimeException('Restored sender cannot overwrite a newer receiver.');
            $seq=SecretsBackendCodec::increment($s['stream']['next'][$p['id']]??'0');if(self::compare($seq,$cursor['sequence'])<=0)$seq=SecretsBackendCodec::increment($cursor['sequence']);
            $s['outbox']['jobs']=array_values(array_filter($s['outbox']['jobs'],static fn($j)=>$j['receiverId']!==$p['id']||!in_array($j['kind'],['SYNC','RESYNC'],true)));
            $payload=self::globalPayload($s,$p,$cursor['nodeDigest'])+['challenge'=>$cursor['challenge']];$s['stream']['next'][$p['id']]=$seq;$s['stream']['queuedDigest'][$p['id']]=$payload['nodeDigest'];$s['outbox']['jobs'][]=self::job($p,'RESYNC',$payload,$seq);return $s;
        },['action'=>'global-resynchronize','actor'=>'background','target'=>$peer['pairingId']]);
    }
    public function ownRoutes(array $state): array
    {
        $primary=$this->store->identity()['binding']['origin'].'/hook/secrets_peer_'.$this->descriptor()['backend'];$routes=[];
        $backup=$state['native']['setupPeerBackupOrigin']??(SecretsBackendBackupOriginPolicy::full($state)?$state['policy']['backupOrigin']['origin']:null);
        if(is_string($backup)&&preg_match('~^https://[a-z0-9]{32}\.ipmagic\.de$~D',$backup))$routes[]=$backup.'/hook/secrets_peer_'.$this->descriptor()['backend'];
        $routes[]=$primary;return array_values(array_unique(isset($state['native']['setupPeerBackupOrigin'])?[$primary,...$routes]:$routes));
    }
    private function queueRoutes(): void
    {
        $cur=$this->store->read();$payload=['revision'=>$cur['state']['native']['routeRevision']??'0','endpoints'=>$this->ownRoutes($cur['state'])];
        foreach($cur['state']['pairing']['peers']as$p){
            if(!$p['active']||($p['routeReceipt']??null)===$payload['revision'])continue;
            foreach($cur['state']['outbox']['jobs']as$j)if($j['receiverId']===$p['id']&&$j['kind']==='ROUTES')continue 2;
            if(count($cur['state']['outbox']['jobs'])>=128)return;
            $this->store->change($cur['head'],SecretsBackendCodec::uuid(),self::digest($payload),static function($s)use($p,$payload){$s['outbox']['jobs'][]=self::job($p,'ROUTES',$payload);return $s;},['action'=>'peer-routes-queued','actor'=>'background','target'=>$p['pairingId']]);return;
        }
    }
    private function queueAutomaticGlobal(): void
    {
        $cur=$this->store->read();foreach($cur['state']['pairing']['peers']as$p){
            if(!$p['active']||self::shared($p))continue;
            foreach($cur['state']['outbox']['jobs']as$j)if($j['receiverId']===$p['id']&&$j['kind']==='GLOBAL_ENABLE')continue 2;
            if(count($cur['state']['outbox']['jobs'])>=128)return;
            $this->store->change($cur['head'],SecretsBackendCodec::uuid(),self::digest(['auto-global'=>$p['pairingId']]),static function($s)use($p){$s['outbox']['jobs'][]=self::job($p,'GLOBAL_ENABLE',['mode'=>SecretsBackendSharedGlobal::SCOPE]);return $s;},['action'=>'global-connect-queued','actor'=>'background','target'=>$p['pairingId']]);return;
        }
    }
    public function dispatch(int $maximum=2,?string $onlyPeer=null,bool $retryNow=false,?string $onlyPairing=null,array $onlyKinds=[]): array
    {
        if($this->automaticGlobal){$this->queueAutomaticGlobal();$this->queueRoutes();}
        $results=[];
        for($n=0;$n<$maximum;++$n){$current=$this->store->read();$job=null;
            $seen=[];foreach($current['state']['outbox']['jobs']as$item){if(($onlyKinds&&!in_array($item['kind'],$onlyKinds,true))||($onlyPeer!==null&&$item['receiverId']!==$onlyPeer)||($onlyPairing!==null&&$item['pairingId']!==$onlyPairing)||isset($seen[$item['receiverId']]))continue;$seen[$item['receiverId']]=true;
                try{$backoff=$this->store->get('backoff:'.$item['id'],'delivery-backoff');}catch(Throwable $ignored){$backoff=['nextAttemptAt'=>0,'attempts'=>0];}
                if(($item['status']??'')==='queued'&&($retryNow||$backoff['nextAttemptAt']<=time())){$job=$item;break;}}
            if($job===null)break;$peer=$current['state']['pairing']['peers'][$job['receiverId']]??null;
            if($job['kind']==='TREE_SYNC'){$tree=$current['state']['native']['trees'][$job['treeId']]??null;$subscriber=$tree['subscribers'][$job['receiverId']]??null;if(!is_array($tree)||$tree['frozen']||!is_array($subscriber))break;$peer=['id'=>$job['receiverId'],'pairingId'=>$subscriber['subscriptionId'],'epoch'=>$tree['epoch'],'descriptor'=>$subscriber['descriptor'],'active'=>true];}
            if(!is_array($peer)||$peer['pairingId']!==$job['pairingId']||$peer['epoch']!==$job['epoch']||(!$peer['active']&&!in_array($job['kind'],['PAIR_REQUEST','REVOKE'],true)))break;
            try{$reply=$this->exchange($peer,$job['kind'],$job['payload'],$job['id'],$job['sequence']);
                if($this->automaticGlobal&&$job['kind']==='SYNC'&&($reply['status']??'')==='RESYNC_REQUIRED'){$this->recoverGlobalGap($peer,$job);$results[]=['id'=>$job['id'],'status'=>'RESYNCHRONIZING'];continue;}
                $expected=match($job['kind']){'SETUP_ENROLL'=>['SETUP_ENROLLED','SETUP_STOPPED'],'SETUP_OFFER'=>['SETUP_OFFER_RECEIVED','SETUP_STOPPED'],'EMERGENCY_OFFER'=>['EMERGENCY_OFFER_RECEIVED'],'ROUTES'=>['ROUTES_ACCEPTED'],'GLOBAL_ENABLE'=>['GLOBAL_ENABLED'],'PAIR_REQUEST'=>['PENDING_APPROVAL','ACTIVE'],'PAIR_ACCEPT'=>['ACTIVE'],'SYNC','RESYNC'=>['APPLIED'],'REVOKE'=>['REVOKED'],'OWNER_OFFER'=>['OFFER_RECEIVED'],'TREE_SYNC'=>['TREE_APPLIED'],default=>[]};
                if(!in_array($reply['status']??'',$expected,true))throw new RuntimeException('Peer did not acknowledge the expected operation.');
                if(in_array($job['kind'],['SYNC','RESYNC','TREE_SYNC'],true)&&(($reply['treeId']??'')!==($job['payload']['treeId']??$job['payload']['tree']['treeId'])||($reply['revision']??'')!==($job['payload']['revision']??$job['payload']['tree']['revision'])||($reply['sequence']??'')!==$job['sequence']||($reply['nodeDigest']??'')!==($job['payload']['nodeDigest']??$job['payload']['tree']['nodeDigest'])))throw new RuntimeException('Peer receipt names another snapshot.');
                $latest=$this->store->read();$this->store->change($latest['head'],$job['ackId'],self::digest($reply),static function($s)use($job,$reply){
                    $s['outbox']['jobs']=array_values(array_filter($s['outbox']['jobs'],static fn($x)=>$x['id']!==$job['id']));
                    if($job['kind']==='EMERGENCY_OFFER'){if(($reply['grantId']??'')!==$job['payload']['grantId'])throw new RuntimeException('Wrong emergency offer receipt.');return $s;}
                    if($job['kind']==='ROUTES'){if(($reply['revision']??null)!==$job['payload']['revision'])throw new RuntimeException('Wrong route receipt.');$p=$s['pairing']['peers'][$job['receiverId']]??null;if(!$p||!$p['active']||$p['pairingId']!==$job['pairingId'])throw new RuntimeException('Connection changed during route publication.');$s['pairing']['peers'][$job['receiverId']]['routeReceipt']=$reply['revision'];return $s;}
                    if($job['kind']==='GLOBAL_ENABLE'){$p=$s['pairing']['peers'][$job['receiverId']]??null;if(!$p||!$p['active']||$p['pairingId']!==$job['pairingId'])throw new RuntimeException('Connection changed during automatic Global setup.');if(($reply['mode']??'')!==SecretsBackendSharedGlobal::SCOPE)throw new RuntimeException('Peer does not support shared Global.');$s['pairing']['peers'][$job['receiverId']]['globalMode']=SecretsBackendSharedGlobal::SCOPE;return self::queueGlobal(SecretsBackendSharedGlobal::enable($s),$job['receiverId']);}
                    $s['native']['deliveryReceipts'][$job['receiverId']]=array_replace($reply,['pairingId'=>$job['pairingId']]);return $s;
                },['action'=>'peer-receipt','actor'=>$job['receiverId'],'target'=>$job['id']]);$results[]=['id'=>$job['id'],'status'=>'ACKNOWLEDGED'];
            }catch(Throwable $e){
                $key='backoff:'.$job['id'];try{$backoff=$this->store->get($key,'delivery-backoff');}catch(Throwable $ignored){$backoff=['attempts'=>0];}
                $attempts=min(20,$backoff['attempts']+1);$body=['attempts'=>$attempts,'lastAttemptAt'=>time(),'nextAttemptAt'=>time()+min(300,2**$attempts),
                    'problem'=>$e instanceof SecretsBackendNativePeerDeliveryFailure&&in_array($e->problem,SecretsBackendNativePeerDeliveryFailure::PROBLEMS,true)?$e->problem:'unconfirmed',
                    'httpStatus'=>$e instanceof SecretsBackendNativePeerDeliveryFailure?$e->httpStatus:0,'curlCode'=>$e instanceof SecretsBackendNativePeerDeliveryFailure?$e->curlCode:0,'routeAttempts'=>$e instanceof SecretsBackendNativePeerDeliveryFailure?$e->attempts:[]];
                $body+=SecretsBackendNativePeerDeliveryFailure::tlsDetails($e instanceof SecretsBackendNativePeerDeliveryFailure?['tlsVerifyResult'=>$e->tlsVerifyResult,'certificateReason'=>$e->certificateReason,'caTrust'=>$e->caTrust]:[]);
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
            $safe['routeAttempts']=$b['routeAttempts']??[];$safe+=SecretsBackendNativePeerDeliveryFailure::tlsDetails($b??[]);unset($b);
            $out[$job['receiverId']]=$safe;
        }return $out;
    }
}
