<?php
declare(strict_types=1);
require_once __DIR__.'/../SecretsFrontend/ConnectDiscovery.php';

/** Explicit, fixed-roster delegation. Credentials stay in the encrypted native journal. */
final class SecretsBackendAutomaticSetup
{
    public const FORMAT='SECB.AutomaticSetup.1';
    public const MAX=8;
    public const CAPABILITY_SECONDS=3600;
    public const CONFIRMATION_SECONDS=900;
    public const RETRY_SECONDS=90;
    private const PURPOSE='pair-routes-emergency-v1';
    public function __construct(private SecretsBackendNativeStore $store,private SecretsBackendNativePeer $peer,private $emergencySync=null,private $clock=null){}
    private function now():int { return $this->clock!==null?($this->clock)():time(); }
    private static function uuid(string $id):void { SecretsBackendNativePeer::uuid($id); }
    private static function key(array $d):string { return SecretsBackendNativePeer::authority($d).':'.$d['treeId']; }
    private static function digest(array $p):string { return SecretsBackendNativePeer::digest($p); }
    public static function routes(array $d,array $routes):void {
        if(!array_is_list($routes)||count($routes)<1||count($routes)>2||count(array_unique($routes))!==count($routes))throw new RuntimeException('Invalid setup routes.');
        $origin=SecretsBackendNativeLegacyHTTPS::origin($d['endpoint']);
        foreach($routes as$url){SecretsBackendNativePeer::endpoint($url);if(parse_url($url,PHP_URL_PATH)!=='/hook/secrets_peer_'.$d['backend']||(!preg_match('/^[a-z0-9]{32}\.ipmagic\.de$/D',(string)parse_url($url,PHP_URL_HOST))&&SecretsBackendNativeLegacyHTTPS::origin($url)!==$origin))throw new RuntimeException('Setup route changed the approved server.');}
    }
    public static function validate(array $p):void {
        SecretsBackendNativePeer::exact($p,['format','id','coordinator','purpose','members','signature']);
        if($p['format']!==self::FORMAT||$p['purpose']!==self::PURPOSE||!is_array($p['members'])||!array_is_list($p['members'])||count($p['members'])<1||count($p['members'])>self::MAX||strlen(SecretsBackendCodec::json($p))>16000)throw new RuntimeException('Invalid automatic setup plan.');
        self::uuid($p['id']);self::uuid($p['coordinator']);$ids=[];$signer=null;
        foreach($p['members']as$m){SecretsBackendNativePeer::exact($m,['descriptor','routes','frontend']);$d=$m['descriptor'];SecretsBackendNativePeer::descriptorCheck($d);self::routes($d,$m['routes']);
            if(isset($ids[$d['vaultId']])||($m['frontend']!==null&&(!is_int($m['frontend'])||$m['frontend']<1||$m['frontend']>99999999)))throw new RuntimeException('Invalid setup member.');$ids[$d['vaultId']]=true;if($d['vaultId']===$p['coordinator'])$signer=$d;
        }
        if(!$signer)throw new RuntimeException('Setup coordinator is absent.');$v=$p;unset($v['signature']);
        if(!sodium_crypto_sign_verify_detached(SecretsBackendCodec::unb64($p['signature'],64),'SECB.SETUP.POLICY.1:'.SecretsBackendNativeStore::canonical($v),SecretsBackendCodec::unb64($signer['signKey'],32)))throw new RuntimeException('Setup plan signature invalid.');
    }
    private static function member(array $p,string $id):array { foreach($p['members']as$m)if($m['descriptor']['vaultId']===$id)return $m;throw new RuntimeException('Server is outside the approved setup plan.'); }
    private function checkLocal(array $p,array $s):void {
        self::validate($p);if(in_array($p['id'],$s['native']['setupRevokedPlans']??[],true))throw new RuntimeException('This setup plan was stopped on this server.');$own=self::member($p,$s['native']['vaultId']);if(!in_array($own['descriptor']['endpoint'],$this->peer->ownRoutes($s),true)||self::key($own['descriptor'])!==self::key($this->peer->descriptor()))throw new RuntimeException('Setup plan has a different local vault identity.');
        foreach($p['members']as$m){$q=$s['pairing']['peers'][$m['descriptor']['vaultId']]??null;if($q&&($q['state']==='REVOKED'||self::key($q['descriptor'])!==self::key($m['descriptor'])))throw new RuntimeException('A setup member was revoked or changed identity. Review a new plan.');}
    }
    public static function enabled(array $s):bool {
        $a=$s['native']['automaticSetup']??null;if(!is_array($a)||!($a['enabled']??false)||($a['revocation']??null)!==$s['identity']['revocation']||!($s['identity']['credentials'][$a['credential']]['active']??false))return false;
        foreach($a['policy']['members']as$m)if($m['descriptor']['vaultId']===$s['native']['vaultId']&&$m['descriptor']['treeId']!==$s['native']['globalTreeId'])return false;
        foreach($a['bindings']as$id=>$binding){$p=$s['pairing']['peers'][$id]??null;if($p&&($p['state']==='REVOKED'||self::key($p['descriptor'])!==$binding['key']||($binding['pairing']!==null&&$p['pairingId']!==$binding['pairing'])))return false;}
        return true;
    }
    private function active(array $s,?string $id=null):array {
        if(!self::enabled($s))throw new RuntimeException('Automatic setup is not authorized on this server.');$a=$s['native']['automaticSetup'];if($id!==null&&$a['policy']['id']!==$id)throw new RuntimeException('Automatic setup generation changed.');$this->checkLocal($a['policy'],$s);return $a;
    }
    private function ownDescriptor():array { $d=$this->peer->descriptor();$d['endpoint']=$this->store->identity()['binding']['origin'].'/hook/secrets_peer_'.$d['backend'];return $d; }
    public function info(array $s):array {
        $members=[['descriptor'=>$this->ownDescriptor(),'routes'=>$this->peer->ownRoutes($s),'frontend'=>(int)$this->store->identity()['binding']['frontend']]];
        foreach($s['pairing']['peers']as$p)if($p['active']&&$p['state']==='ACTIVE'){$d=$p['descriptor'];$routes=$p['routes']['endpoints']??[$d['endpoint']];foreach($routes as$url)if(!preg_match('/^[a-z0-9]{32}\.ipmagic\.de$/D',(string)parse_url($url,PHP_URL_HOST))){$d['endpoint']=$url;break;}$members[]=['descriptor'=>$d,'routes'=>$routes,'frontend'=>null];}
        return ['members'=>array_slice($members,0,self::MAX)];
    }
    private const DISCOVERY='automatic-setup-discovery';
    public function discoveryPending():bool { try{$r=$this->store->get(self::DISCOVERY,self::DISCOVERY);return !isset($r['policy'])&&($r['expires']??0)>time();}catch(Throwable $ignored){return false;} }
    private function saveDiscovery(array $r):void { try{$this->store->replace(self::DISCOVERY,self::DISCOVERY,$r,time()+3600);}catch(Throwable $ignored){$this->store->put(self::DISCOVERY,self::DISCOVERY,$r,time()+3600);} }
    private static function discoveryView(array $r):array {
        return isset($r['policy'])?['complete'=>true,'policy'=>$r['policy']]:['complete'=>false,'found'=>count($r['members']),'checked'=>count($r['checked']),'waiting'=>array_values($r['problems']??[]),'message'=>'Discovery is running in the background. Slow or unavailable servers are retried; confirmed progress is retained.'];
    }
    /** The browser only starts/observes work. Never hold its request open for peer I/O. */
    public function preview(string $session):array {
        $s=$this->store->read()['state'];if(isset($s['native']['setupProposal']))return ['complete'=>true,'policy'=>$s['native']['setupProposal']];
        try{$r=$this->store->get(self::DISCOVERY,self::DISCOVERY);}catch(Throwable $ignored){$r=['members'=>[],'checked'=>[],'problems'=>[],'retry'=>[],'expires'=>time()+1200];foreach($this->info($s)['members']as$m)$r['members'][$m['descriptor']['vaultId']]=$m;$this->saveDiscovery($r);}
        if(($r['expires']??0)<time()&&!isset($r['policy'])){$this->store->delete(self::DISCOVERY);return ['complete'=>false,'blocked'=>true,'message'=>'Discovery has not completed after 20 minutes. No authorization was granted. Existing connections remain active. Select Finish setup again to retry.','waiting'=>array_values($r['problems']??[])];}
        if(isset($r['policy'])&&in_array($r['policy']['id'],$s['native']['setupRevokedPlans']??[],true)){$this->store->delete(self::DISCOVERY);return $this->preview($session);}
        return self::discoveryView($r);
    }
    private function discover():array {
        $s=$this->store->read()['state'];$r=$this->store->get(self::DISCOVERY,self::DISCOVERY);
        if(isset($s['native']['setupProposal'])){$r['policy']=$s['native']['setupProposal'];$this->saveDiscovery($r);return ['status'=>'SETUP_PLAN_RECEIVED'];}
        $merge=static function(array $rows)use(&$r):void{foreach($rows as$m){SecretsBackendNativePeer::exact($m,['descriptor','routes','frontend']);if($m['frontend']!==null&&(!is_int($m['frontend'])||$m['frontend']<1||$m['frontend']>99999999))throw new RuntimeException('Invalid setup frontend.');SecretsBackendNativePeer::descriptorCheck($m['descriptor']);self::routes($m['descriptor'],$m['routes']);$id=$m['descriptor']['vaultId'];$old=$r['members'][$id]??null;if($old&&self::key($old['descriptor'])!==self::key($m['descriptor']))throw new RuntimeException('Servers reported conflicting vault identities.');if(!$old||$m['frontend']!==null)$r['members'][$id]=$m;}if(count($r['members'])>self::MAX)throw new RuntimeException('Automatic setup supports at most eight explicitly reviewed servers.');};
        $merge($this->info($s)['members']);
        foreach($s['pairing']['peers']as$p)if($p['active']&&$p['state']==='ACTIVE'&&!isset($r['checked'][$p['id']])&&($r['retry'][$p['id']]??0)<=$this->now()){
            try{
                $reply=$this->peer->exchange($p,'SETUP_INFO',['format'=>self::FORMAT],SecretsBackendCodec::uuid());
                if(($reply['status']??'')!=='SETUP_INFO'||!is_array($reply['members']??null)||count($reply['members'])>self::MAX)throw new RuntimeException('Incompatible setup reply.');
                $merge($reply['members']);$r['checked'][$p['id']]=true;unset($r['problems'][$p['id']],$r['retry'][$p['id']]);
            }catch(Throwable $e){
                $problem=$e instanceof SecretsBackendNativePeerDeliveryFailure?$e->problem:'invalid-reply';$r['retry'][$p['id']]=$this->now()+self::RETRY_SECONDS;
                $r['problems'][$p['id']]=['server'=>SecretsBackendPeerName::display($p),'step'=>'Discover server list','reason'=>$problem,'retryAt'=>$r['retry'][$p['id']],'message'=>self::problemText($problem).($e instanceof SecretsBackendNativePeerDeliveryFailure&&$e->httpStatus?' HTTP '.$e->httpStatus.'.':'')];
            }
            $this->saveDiscovery($r);return ['status'=>'SETUP_DISCOVERY_PENDING'];
        }
        foreach($s['pairing']['peers']as$p)if($p['active']&&$p['state']==='ACTIVE'&&!isset($r['checked'][$p['id']]))return ['status'=>'SETUP_DISCOVERY_RETRY'];
        ksort($r['members']);$p=['format'=>self::FORMAT,'id'=>SecretsBackendCodec::uuid(),'coordinator'=>$s['native']['vaultId'],'purpose'=>self::PURPOSE,'members'=>array_values($r['members'])];$p['signature']=$this->store->sign('SECB.SETUP.POLICY.1:'.SecretsBackendNativeStore::canonical($p));$this->checkLocal($p,$s);$r['policy']=$p;$this->saveDiscovery($r);return ['status'=>'SETUP_DISCOVERY_COMPLETE'];
    }
    public function diagnostics(array $state):array {
        $status=$this->status($state);$discovery=null;
        try{$r=$this->store->get(self::DISCOVERY,self::DISCOVERY);$discovery=['found'=>count($r['members']),'checked'=>count($r['checked']),'complete'=>isset($r['policy']),'waiting'=>array_values($r['problems']??[])];}catch(Throwable $ignored){}
        return ['authorized'=>$status['authorized'],'running'=>$status['running']??false,'completedAt'=>$status['completedAt']??null,'members'=>$status['members'],'discovery'=>$discovery];
    }
    public static function problemText(string $problem):string { return match($problem){'timeout'=>'The server did not reply within the generous request allowance. It will be retried automatically.','connect'=>'Could not connect to the server. It will be retried automatically.','dns'=>'The server hostname could not be resolved. It will be retried automatically.','certificate'=>'HTTPS certificate verification failed. Correct the certificate or approved route.','tls'=>'The secure connection could not be established. It will be retried automatically.','http'=>'The server refused the HTTP request. Check its connection status and installed Secrets version.','invalid-reply'=>'The reply could not be authenticated or understood. Check that both servers use the same current Secrets version.',default=>'Delivery was not confirmed. It will be retried automatically.'}; }
    public function authorize(array $s,array $p,array $session):array {
        $this->checkLocal($p,$s);if(isset($s['native']['automaticSetup'])&&($s['native']['automaticSetup']['enabled']??false)&&$s['native']['automaticSetup']['policy']['id']!==$p['id'])throw new RuntimeException('Stop the existing setup authorization before approving a different plan.');
        $s=$this->offer($s,$p);$bindings=[];foreach($p['members']as$m){$id=$m['descriptor']['vaultId'];if($id===$s['native']['vaultId'])continue;$q=$s['pairing']['peers'][$id]??null;$bindings[$id]=['key'=>self::key($m['descriptor']),'pairing'=>$q['pairingId']??null];}
        $s['native']['automaticSetup']=['policy'=>$p,'enabled'=>true,'generation'=>SecretsBackendCodec::uuid(),'master'=>SecretsBackendCodec::b64(random_bytes(32)),'credential'=>$session['credential'],'revocation'=>$s['identity']['revocation'],'bindings'=>$bindings,'issued'=>[],'requested'=>true,'run'=>$p['id'],'dispatch'=>true,'completedAt'=>null,'lastProblem'=>null,'seenRuns'=>[$p['id']]];return $s;
    }
    public function offer(array $s,array $p):array {
        $this->checkLocal($p,$s);$old=$s['native']['setupProposal']??null;if($old&&$old['id']!==$p['id'])throw new RuntimeException('A different setup plan is already awaiting review.');
        $s['native']['setupProposal']=$p;$sent=$s['native']['setupProposalSent']??[];
        foreach($s['pairing']['peers']as$q)if($q['active']&&$q['state']==='ACTIVE'&&!isset($sent[$q['id']])&&in_array($q['id'],array_column(array_column($p['members'],'descriptor'),'vaultId'),true)){if(count($s['outbox']['jobs'])>=128)throw new RuntimeException('Wait for pending peer delivery before starting setup.');$s['outbox']['jobs'][]=SecretsBackendNativePeer::job($q,'SETUP_OFFER',['policy'=>$p]);$sent[$q['id']]=true;}
        $s['native']['setupProposalSent']=$sent;return $s;
    }
    private function commit(string $action,callable $fn):void {
        $c=$this->store->read();$this->store->change($c['head'],SecretsBackendCodec::uuid(),hash('sha256',$action.SecretsBackendCodec::json($c['head'])),$fn,['action'=>'automatic-setup-'.$action,'actor'=>'delegated-setup','target'=>'fixed-roster']);
    }
    private static function pairId(array $policy,string $a,string $b):string { $ids=[$a,$b];sort($ids);$h=substr(hash('sha256',$policy['id'].implode(':',$ids)),0,32);$h[12]='4';$h[16]='8';return substr($h,0,8).'-'.substr($h,8,4).'-'.substr($h,12,4).'-'.substr($h,16,4).'-'.substr($h,20); }
    private function ensurePair(array $s,string $id):array {
        $a=$this->active($s);$m=self::member($a['policy'],$id);$old=$s['pairing']['peers'][$id]??null;
        if($old){if(!$old['active']||$old['state']!=='ACTIVE')throw new RuntimeException('An existing manual connection needs review.');return $s;}
        $own=self::member($a['policy'],$s['native']['vaultId'])['descriptor'];$other=$m['descriptor'];$ds=[$own,$other];usort($ds,static fn($x,$y)=>strcmp($x['vaultId'],$y['vaultId']));
        $pair=['id'=>self::pairId($a['policy'],$own['vaultId'],$id),'epoch'=>'1','a'=>$ds[0],'b'=>$ds[1],'scope'=>SecretsBackendSharedGlobal::SCOPE,'cachedReads'=>true];
        $q=SecretsBackendNativePeer::peerRecord($pair,$other,SecretsBackendPeerName::address($other['endpoint']),'ACTIVE');$q['httpsPolicy']=['mode'=>'strict'];$q['routes']=['revision'=>'0','endpoints'=>$m['routes']];
        if(count($s['pairing']['peers'])>=32)throw new RuntimeException('Peer capacity reached.');$s['pairing']['peers'][$id]=$q;$s['native']['automaticSetup']['bindings'][$id]['pairing']=$pair['id'];return SecretsBackendNativePeer::queueGlobal(SecretsBackendSharedGlobal::enable($s),$id);
    }
    private function contactKey(array $a,string $id):string { return 'setup-contact:'.$a['policy']['id'].':'.$a['generation'].':'.$id; }
    private function contacts(array $a):array {
        $out=[];foreach($a['policy']['members']as$m){$id=$m['descriptor']['vaultId'];try{$out[$id]=$this->store->get($this->contactKey($a,$id),'setup-contact');}catch(Throwable $ignored){}}
        return $out;
    }
    private function saveContact(array $a,string $id,array $body):void {
        $key=$this->contactKey($a,$id);try{$this->store->replace($key,'setup-contact',$body,time()+self::CAPABILITY_SECONDS);}catch(Throwable $ignored){$this->store->put($key,'setup-contact',$body,time()+self::CAPABILITY_SECONDS);}
    }
    private function response(array $s,string $caller):array {
        $a=$s['native']['automaticSetup']??null;$ok=self::enabled($s);$client=$s['native']['emergencyClients'][$caller]??null;$offer=$s['native']['emergencyOffers'][$caller]??null;
        $out=['status'=>'SETUP_HELLO','authorized'=>$ok,'frontend'=>(int)$this->store->identity()['binding']['frontend'],'routes'=>$this->peer->ownRoutes($s),'routeRevision'=>$s['native']['routeRevision']??'0','backupStatus'=>$s['policy']['backupOrigin']['status']??'none','backupReady'=>$this->backupReady($s),'clientGrant'=>$client['grantId']??null,'offerGrant'=>$offer['grantId']??null,'ready'=>self::enabled($s)&&($a['completedAt']??null)!==null,'generation'=>$ok?$a['generation']:null];
        if($ok){$out['expires']=$this->now()+self::CAPABILITY_SECONDS;$out['token']=hash_hmac('sha256',$caller.':'.$a['policy']['id'].':'.$a['generation'].':'.$out['expires'],SecretsBackendCodec::unb64($a['master'],32));}
        return $out;
    }
    private function token(array $s,string $caller,array $p):array {
        $a=$this->active($s);if(!is_int($p['expires']??null)||$p['expires']<$this->now()||$p['expires']>$this->now()+self::CAPABILITY_SECONDS||!is_string($p['token']??null)||!hash_equals(hash_hmac('sha256',$caller.':'.$a['policy']['id'].':'.$a['generation'].':'.$p['expires'],SecretsBackendCodec::unb64($a['master'],32)),$p['token']))throw new RuntimeException('Setup capability expired or was revoked.');return $a;
    }
    /** Called only after the outer envelope is verified against the locally pinned policy member. */
    public function receive(string $kind,array $m,array $p,array $s):array {
        $policy=$s['native']['setupProposal']??null;if(!$policy||$m['pairingId']!==$policy['id']||$m['epoch']!=='1'||$m['sequence']!=='0')throw new RuntimeException('Setup request belongs to another plan.');$this->checkLocal($policy,$s);self::member($policy,$m['sender']);
        $this->store->rate('automatic-setup:'.$m['sender'],12);
        if($kind==='SETUP_HELLO'){SecretsBackendNativePeer::exact($p,['format']);if($p['format']!==self::FORMAT)throw new RuntimeException('Invalid setup status purpose.');return $this->response($s,$m['sender']);}
        if($kind==='SETUP_ADVANCE'){
            SecretsBackendNativePeer::exact($p,['token','expires','run']);self::uuid($p['run']);$this->token($s,$m['sender'],$p);
            if(!in_array($p['run'],$s['native']['automaticSetup']['seenRuns'],true)||!isset($s['pairing']['peers'][$m['sender']]))$this->commit('request',function($v)use($m,$p){$this->token($v,$m['sender'],$p);$v=$this->ensurePair($v,$m['sender']);$a=&$v['native']['automaticSetup'];if(!in_array($p['run'],$a['seenRuns'],true)){$a['requested']=true;$a['run']=$p['run'];$a['dispatch']=false;$a['completedAt']=null;$a['seenRuns']=array_slice([...$a['seenRuns'],$p['run']],-32);}return $v;});
            return ['status'=>'SETUP_ADVANCED'];
        }
        if($kind==='SETUP_PRUNE'){
            SecretsBackendNativePeer::exact($p,['token','expires','keep','retire']);$this->token($s,$m['sender'],$p);self::uuid($p['keep']);if(!is_array($p['retire'])||!array_is_list($p['retire'])||count($p['retire'])>64||in_array($p['keep'],$p['retire'],true))throw new RuntimeException('Invalid cleanup plan.');foreach($p['retire']as$id)self::uuid($id);
            if(($s['native']['emergencyClients'][$m['sender']]['grantId']??null)!==$p['keep'])throw new RuntimeException('The accepted emergency grant changed.');
            if(array_diff($p['retire'],$s['native']['setupRetiredIncoming'][$m['sender']]??[]))$this->commit('confirm-cleanup',function($v)use($m,$p){$this->token($v,$m['sender'],$p);if(($v['native']['emergencyClients'][$m['sender']]['grantId']??null)!==$p['keep'])throw new RuntimeException('The accepted emergency grant changed.');$ids=$v['native']['setupRetiredIncoming'][$m['sender']]??[];$ids=array_values(array_unique([...$ids,...$p['retire']]));if(count($ids)>128)throw new RuntimeException('Cleanup retention capacity reached.');$v['native']['setupRetiredIncoming'][$m['sender']]=$ids;return $v;});
            return ['status'=>'SETUP_PRUNED','keep'=>$p['keep'],'digest'=>self::digest($p['retire'])];
        }
        throw new RuntimeException('Unsupported automatic setup action.');
    }
    public function start():void {
        $this->commit('start',function($s){$this->active($s);$a=&$s['native']['automaticSetup'];if(!$a['requested'])$a['run']=SecretsBackendCodec::uuid();$a['requested']=true;$a['dispatch']=true;$a['completedAt']=null;return $s;});
        $a=$this->active($this->store->read()['state']);foreach($this->contacts($a)as$id=>$c){$c['at']=0;$c['nextAction']='check';$this->saveContact($a,$id,$c);}
    }
    private function cursorKey(array $a):string { return 'setup-cursor:'.$a['policy']['id'].':'.$a['generation']; }
    private function rotateToNext(string $id):void {
        $a=$this->active($this->store->read()['state']);$ids=array_values(array_filter(array_column(array_column($a['policy']['members'],'descriptor'),'vaultId'),fn($x)=>$x!==$this->peer->descriptor()['vaultId']));$next=(array_search($id,$ids,true)+1)%max(1,count($ids));$key=$this->cursorKey($a);try{$this->store->replace($key,'setup-cursor',['next'=>$next],time()+3600);}catch(Throwable $ignored){$this->store->put($key,'setup-cursor',['next'=>$next],time()+3600);}
    }
    private function retryKey(string $id,string $policy):string { return 'automatic-setup-retry:'.$policy.':'.$id; }
    private function exchange(array $target,string $kind,array $payload):array {
        $this->rotateToNext($target['descriptor']['vaultId']);$key=$this->retryKey($target['descriptor']['vaultId'],$target['pairingId']);$pending='setup-pending:'.$target['pairingId'].':'.$target['descriptor']['vaultId'];try{$this->store->replace($pending,'setup-pending',['at'=>$this->now()],time()+150);}catch(Throwable $ignored){$this->store->put($pending,'setup-pending',['at'=>$this->now()],time()+150);}
        try{$r=$this->peer->exchange($target,$kind,$payload,SecretsBackendCodec::uuid());try{$this->store->delete($key);$this->store->delete($pending);}catch(Throwable $ignored){}return $r;}
        catch(Throwable $e){try{$this->store->delete($pending);}catch(Throwable $ignored){}$r=['at'=>$this->now(),'next'=>$this->now()+self::RETRY_SECONDS,'problem'=>$e instanceof SecretsBackendNativePeerDeliveryFailure?$e->problem:'unconfirmed'];try{$this->store->replace($key,'automatic-setup-retry',$r,time()+self::RETRY_SECONDS+120);}catch(Throwable $ignored){$this->store->put($key,'automatic-setup-retry',$r,time()+self::RETRY_SECONDS+120);}throw $e;}
    }
    private function target(array $s,array $member):array {
        $d=$member['descriptor'];$q=$s['pairing']['peers'][$d['vaultId']]??null;
        $routes=$q['routes']['endpoints']??$member['routes'];self::routes($d,$routes);
        return ['descriptor'=>$d,'pairingId'=>$s['native']['automaticSetup']['policy']['id'],'epoch'=>'1','routes'=>['endpoints'=>$routes],'httpsPolicy'=>$q['httpsPolicy']??['mode'=>'strict']];
    }
    private function backupReady(array $s):bool {
        if(!SecretsBackendBackupOriginPolicy::full($s))return false;$p=$s['policy']['backupOrigin'];$hardware=in_array(true,$s['policy']['hardware'],true);
        foreach($s['identity']['credentials']as$c)if(($c['active']??false)&&($c['tested']??false)&&($c['origin']??null)===$p['origin']&&$c['administrator']===$s['identity']['ownerId']&&SecretsBackendBackupOriginPolicy::credentialFull($s,$c)&&(!$hardware||($c['hardware']&&$c['trustVersion']===$s['policy']['management']['settings']['HardwareTrustVersion'])))return true;
        return false;
    }
    private function localReady(array $s):bool {
        if(!self::enabled($s)||!$this->backupReady($s))return false;$a=$s['native']['automaticSetup'];$contacts=$this->contacts($a);
        if(SecretsBackendNativeHealth::stamp($s)['conflicts']>0)return false;
        $health=(new SecretsBackendNativeHealth($this->store,$this->peer))->statuses($s);
        foreach($a['policy']['members']as$m){$id=$m['descriptor']['vaultId'];if($id===$s['native']['vaultId'])continue;$q=$s['pairing']['peers'][$id]??null;$c=$contacts[$id]??null;
            if(!$q||!$q['active']||!SecretsBackendNativePeer::shared($q)||!$c||$this->now()-$c['at']>self::CONFIRMATION_SECONDS||!$c['authorized']||!isset($s['native']['emergencyClients'][$id])||($health[$id]['synchronization']??'')!=='verified')return false;
            $found=false;foreach($s['native']['emergencyGrants']??[]as$g)if($g['source']===$id&&$g['active']&&$g['id']===$c['clientGrant']&&$g['pairingId']===$q['pairingId'])$found=true;if(!$found)return false;
            if(($q['routeReceipt']??null)!==($s['native']['routeRevision']??'0'))return false;
        }
        return !count($s['outbox']['jobs']);
    }
    /** One bounded local change or one outbound exchange per worker phase. */
    public function tick():array {
        try{if($this->discoveryPending())return $this->discover();return $this->step();}catch(Throwable $e){return ['status'=>'SETUP_RETRY_PENDING'];}
    }
    private function step():array {
        $s=$this->store->read()['state'];if(!self::enabled($s)||!($s['native']['automaticSetup']['requested']??false))return ['status'=>'SETUP_IDLE'];$a=$this->active($s);$contacts=$this->contacts($a);$own=$s['native']['vaultId'];
        if(!isset($s['policy']['backupOrigin'])){
            $found=SecretsFrontendConnectDiscovery::local();
            if(($found['available']??false)&&preg_match('~^https://[a-z0-9]{32}\.ipmagic\.de$~D',$found['origin'])){
                $this->commit('prepare-backup',function($v)use($found){$this->active($v);if(isset($v['policy']['backupOrigin']))return $v;return SecretsBackendBackupOriginPolicy::stage($v,$found['origin']);});return ['status'=>'SETUP_BACKUP_DEVICE_STEP'];
            }
        }
        foreach(SecretsBackendEmergency::publicMetadata($s)['offers']as$o){try{self::member($a['policy'],$o['peerId']);}catch(Throwable $ignored){continue;}$ops=new SecretsBackendNativeOperations($this->store,$this->peer);$op=$ops->normalize(['kind'=>'nativeEmergencyAccept','peerId'=>$o['peerId'],'digest'=>$o['digest']],$s,false);$this->commit('accept-emergency',function($v)use($ops,$op){$this->active($v);return $ops->apply($op,$v,true);});if($this->emergencySync!==null)($this->emergencySync)();return ['status'=>'SETUP_EMERGENCY_ACCEPTED'];}
        $members=array_values(array_filter($a['policy']['members'],static fn($m)=>$m['descriptor']['vaultId']!==$own));$cursor=0;try{$cursor=$this->store->get($this->cursorKey($a),'setup-cursor')['next'];}catch(Throwable $ignored){}
        for($offset=0;$offset<count($members);$offset++){$m=$members[($cursor+$offset)%count($members)];$id=$m['descriptor']['vaultId'];$c=$contacts[$id]??null;
            try{$retry=$this->store->get($this->retryKey($id,$a['policy']['id']),'automatic-setup-retry');if($retry['next']>$this->now())continue;}catch(Throwable $ignored){}
            try{$target=$this->target($s,$m);}catch(Throwable $e){$this->rotateToNext($id);$key=$this->retryKey($id,$a['policy']['id']);$retry=['at'=>$this->now(),'next'=>$this->now()+self::RETRY_SECONDS,'problem'=>'route-changed'];try{$this->store->replace($key,'automatic-setup-retry',$retry,time()+210);}catch(Throwable $ignored){$this->store->put($key,'automatic-setup-retry',$retry,time()+210);}continue;}
            if(!$c||((($c['nextAction']??'check')==='check'||!$c['authorized'])&&$this->now()-$c['at']>=self::RETRY_SECONDS)||($c['authorized']&&$c['expires']<$this->now()+120)){
                $r=$this->exchange($target,'SETUP_HELLO',['format'=>self::FORMAT]);$this->validateHello($r,$m['descriptor']);
                $old=$contacts[$id]??[];$this->saveContact($a,$id,$r+['at'=>$this->now(),'nextAction'=>'work','advancedRun'=>($old['generation']??null)===$r['generation']?($old['advancedRun']??null):null]);return ['status'=>$r['authorized']?'SETUP_SERVER_AUTHORIZED':'SETUP_APPROVAL_REQUIRED','server'=>$id];
            }
            if(!$c['authorized'])continue;
            if(($c['nextAction']??null)!=='check'){$c['nextAction']='check';$this->saveContact($a,$id,$c);}
            if(($a['dispatch']??false)&&($c['advancedRun']??null)!==$a['run']){
                $r=$this->exchange($target,'SETUP_ADVANCE',['token'=>$c['token'],'expires'=>$c['expires'],'run'=>$a['run']]);if(($r['status']??'')!=='SETUP_ADVANCED')throw new RuntimeException('Setup run was not acknowledged.');
                if(!isset($s['pairing']['peers'][$id]))$this->commit('connect',fn($v)=>$this->ensurePair($v,$id));$c['advancedRun']=$a['run'];$this->saveContact($a,$id,$c);return ['status'=>'SETUP_CONNECTED','server'=>$id];
            }
            $q=$s['pairing']['peers'][$id]??null;if(!$q||!$q['active'])continue;
            $grants=array_values(array_filter($s['native']['emergencyGrants']??[],static fn($g)=>$g['active']&&$g['source']===$id&&$g['pairingId']===$q['pairingId']));$accepted=null;foreach($grants as$g)if($g['id']===$c['clientGrant'])$accepted=$g;
            if($accepted){$retire=array_values(array_map(static fn($g)=>$g['id'],array_filter($grants,static fn($g)=>$g['id']!==$accepted['id'])));if($retire){
                $r=$this->exchange($target,'SETUP_PRUNE',['token'=>$c['token'],'expires'=>$c['expires'],'keep'=>$accepted['id'],'retire'=>$retire]);if(($r['status']??'')!=='SETUP_PRUNED'||($r['keep']??null)!==$accepted['id']||($r['digest']??null)!==self::digest($retire))throw new RuntimeException('Cleanup confirmation changed.');
                $this->commit('retire-grants',function($v)use($id,$accepted,$retire){$this->active($v);$g=$v['native']['emergencyGrants'][$accepted['id']]??null;if(!$g||!$g['active']||$g['source']!==$id)throw new RuntimeException('Kept grant changed.');foreach($retire as$gid)if(($v['native']['emergencyGrants'][$gid]['source']??null)===$id)$v['native']['emergencyGrants'][$gid]['active']=false;unset($v['native']['automaticSetup']['issued'][$id]);return $v;});return ['status'=>'SETUP_DUPLICATES_RETIRED','server'=>$id];
            }if(isset($a['issued'][$id])){$this->rotateToNext($id);$this->commit('discard-issued',function($v)use($id){$this->active($v);unset($v['native']['automaticSetup']['issued'][$id]);return $v;});return ['status'=>'SETUP_CREDENTIAL_CONFIRMED','server'=>$id];}continue;}
            if($c['offerGrant']!==null&&in_array($c['offerGrant'],array_column($grants,'id'),true))continue;
            $pending=false;foreach($s['outbox']['jobs']as$j)if($j['receiverId']===$id&&$j['kind']==='EMERGENCY_OFFER')$pending=true;if($pending)continue;
            $this->rotateToNext($id);$issued=$a['issued'][$id]??null;
            if($issued){$this->commit('resend-offer',function($v)use($id,$issued){$this->active($v);$v['outbox']['jobs'][]=SecretsBackendNativePeer::job($v['pairing']['peers'][$id],'EMERGENCY_OFFER',['grantId'=>$issued['id'],'package'=>$issued['package']]);return $v;});}
            else{$grant=SecretsBackendEmergency::grant($s,$id);$package=SecretsBackendEmergency::exportGrant($this->store,$this->peer,$grant);$this->commit('grant-emergency',function($v)use($id,$grant,$package){$this->active($v);$v=SecretsBackendEmergency::applyGrant($v,$grant);$v['outbox']['jobs'][]=SecretsBackendNativePeer::job($v['pairing']['peers'][$id],'EMERGENCY_OFFER',['grantId'=>$grant['id'],'package'=>$package]);$v['native']['automaticSetup']['issued'][$id]=['id'=>$grant['id'],'package'=>$package];return $v;});}return ['status'=>'SETUP_EMERGENCY_SENT','server'=>$id];
        }
        if($this->localReady($s)){
            $remoteReady=true;foreach($contacts as$c)if(!$c['ready'])$remoteReady=false;
            if($a['completedAt']===null||($remoteReady&&$a['requested'])){$this->commit('complete',function($v)use($remoteReady){$this->active($v);$v['native']['automaticSetup']['requested']=!$remoteReady;$v['native']['automaticSetup']['completedAt']=$this->now();return $v;});return ['status'=>'SETUP_COMPLETE'];}
        }
        return ['status'=>'SETUP_WAITING'];
    }
    private function validateHello(array $r,array $d):void {
        SecretsBackendNativePeer::exact($r,['requestId','requestKind','requestDigest','status','authorized','frontend','routes','routeRevision','backupStatus','backupReady','clientGrant','offerGrant','ready','generation',...(($r['authorized']??false)?['expires','token']:[])]);
        if($r['status']!=='SETUP_HELLO'||!is_bool($r['authorized'])||!is_bool($r['ready'])||!is_bool($r['backupReady'])||!is_int($r['frontend'])||$r['frontend']<1||$r['frontend']>99999999||!in_array($r['backupStatus'],['none','pending','active','revoked'],true))throw new RuntimeException('Invalid setup progress.');self::routes($d,$r['routes']);SecretsBackendNativePeer::decimal($r['routeRevision']);foreach(['clientGrant','offerGrant','generation']as$k)if($r[$k]!==null)self::uuid($r[$k]);if($r['authorized']&&(!is_int($r['expires'])||$r['expires']<$this->now()||$r['expires']>$this->now()+self::CAPABILITY_SECONDS+60||!is_string($r['token'])||!preg_match('/^[a-f0-9]{64}$/D',$r['token'])))throw new RuntimeException('Invalid setup capability.');
    }
    public function status(array $s):array {
        $a=$s['native']['automaticSetup']??null;$p=$a['policy']??$s['native']['setupProposal']??null;if(!$p)return ['authorized'=>false,'policy'=>null,'members'=>[]];$members=[];$contacts=$a?$this->contacts($a):[];
        foreach($p['members']as$m){$id=$m['descriptor']['vaultId'];$own=$id===$s['native']['vaultId'];$c=$contacts[$id]??null;$at=$c['at']??0;$front=$own?(int)$this->store->identity()['binding']['frontend']:($c['frontend']??$m['frontend']);$origin=SecretsBackendNativeLegacyHTTPS::origin($m['descriptor']['endpoint']);$pending=false;try{$this->store->get('setup-pending:'.$p['id'].':'.$id,'setup-pending');$pending=true;}catch(Throwable $ignored){}$retry=null;try{$retry=$this->store->get($this->retryKey($id,$p['id']),'automatic-setup-retry');}catch(Throwable $ignored){}
            $members[]=['id'=>$id,'name'=>SecretsBackendPeerName::address($m['descriptor']['endpoint']),'local'=>$own,'url'=>$front!==null?$origin.'/hook/secrets_frontend_'.$front:null,'authorized'=>$own?self::enabled($s):($c['authorized']??null),'fresh'=>$own||($at>0&&$this->now()-$at<self::CONFIRMATION_SECONDS),'deliveryPending'=>$pending,'deliveryProblem'=>$retry['problem']??null,'checkedAt'=>$own?$this->now():($at?:null),'backupStatus'=>$own?($s['policy']['backupOrigin']['status']??'none'):($c['backupStatus']??'unknown'),'backupReady'=>$own?$this->backupReady($s):($c['backupReady']??false),'ready'=>$own?($a['completedAt']??null)!==null:($c['ready']??false)];
        }
        return ['authorized'=>self::enabled($s),'policy'=>$p,'members'=>$members,'running'=>$a['requested']??false,'completedAt'=>$a['completedAt']??null];
    }
}
