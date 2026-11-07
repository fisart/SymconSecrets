<?php
declare(strict_types=1);
require_once __DIR__.'/../SecretsFrontend/ConnectDiscovery.php';

/** Fixed-roster mesh delegation. Protected Global setup secrets never enter application APIs. */
final class SecretsBackendAutomaticSetup
{
    public const FORMAT='SECB.AutomaticSetup.1';
    public const AUTOMATIC_FORMAT='SECB.AutomaticSetup.2';
    private const REQUEST='automatic-setup-request';
    private const REPORT='automatic-setup-report';
    public const MAX=8;
    public const CAPABILITY_SECONDS=3600;
    public const CONFIRMATION_SECONDS=900;
    // Setup proofs use the same bounded window before and after a node stops its worker.
    public const VERIFICATION_SECONDS=1800;
    public const RETRY_SECONDS=90;
    private bool $failureRecorded=false;
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
        SecretsBackendNativePeer::exact($p,['format','id','coordinator','purpose','members','signature',...(($p['format']??'')===self::AUTOMATIC_FORMAT?['credentialHash']:[])]);
        if(($p['format']??'')===self::AUTOMATIC_FORMAT&&(!is_string($p['credentialHash'])||!preg_match('/^[a-f0-9]{64}$/D',$p['credentialHash'])))throw new RuntimeException('Invalid setup credential binding.');
        if(!in_array($p['format'],[self::FORMAT,self::AUTOMATIC_FORMAT],true)||$p['purpose']!==self::PURPOSE||!is_array($p['members'])||!array_is_list($p['members'])||count($p['members'])<1||count($p['members'])>self::MAX||strlen(SecretsBackendCodec::json($p))>16000)throw new RuntimeException('Invalid automatic setup plan.');
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
        $a=$s['native']['automaticSetup']??null;if(!is_array($a)||!($a['enabled']??false)||($a['revocation']??null)!==$s['identity']['revocation']||($a['credential']!==null&&!($s['identity']['credentials'][$a['credential']]['active']??false)))return false;
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
        if(!($r['automatic']??false)&&isset($s['native']['setupProposal'])){$r['policy']=$s['native']['setupProposal'];$this->saveDiscovery($r);return ['status'=>'SETUP_PLAN_RECEIVED'];}
        $merge=static function(array $rows)use(&$r):void{foreach($rows as$m){SecretsBackendNativePeer::exact($m,['descriptor','routes','frontend']);if($m['frontend']!==null&&(!is_int($m['frontend'])||$m['frontend']<1||$m['frontend']>99999999))throw new RuntimeException('Invalid setup frontend.');SecretsBackendNativePeer::descriptorCheck($m['descriptor']);self::routes($m['descriptor'],$m['routes']);$id=$m['descriptor']['vaultId'];$old=$r['members'][$id]??null;if($old&&self::key($old['descriptor'])!==self::key($m['descriptor']))throw new RuntimeException('Servers reported conflicting vault identities.');if(!$old||$m['frontend']!==null)$r['members'][$id]=$m;}if(count($r['members'])>self::MAX)throw new RuntimeException('Automatic setup supports at most eight explicitly reviewed servers.');};
        $merge($this->info($s)['members']);
        foreach($s['pairing']['peers']as$p)if($p['active']&&$p['state']==='ACTIVE'&&!isset($r['checked'][$p['id']])&&($r['retry'][$p['id']]??0)<=$this->now()){
            try{
                $reply=$this->peer->exchange($p,'SETUP_INFO',['format'=>self::FORMAT],SecretsBackendCodec::uuid());
                if(($reply['status']??'')!=='SETUP_INFO'||!is_array($reply['members']??null)||count($reply['members'])>self::MAX)throw new RuntimeException('Incompatible setup reply.');
                $merge($reply['members']);$r['checked'][$p['id']]=true;unset($r['problems'][$p['id']],$r['retry'][$p['id']]);
            }catch(Throwable $e){
                $problem=$e instanceof SecretsBackendNativePeerDeliveryFailure&&in_array($e->problem,SecretsBackendNativePeerDeliveryFailure::PROBLEMS,true)?$e->problem:'invalid-reply';$r['retry'][$p['id']]=$this->now()+self::RETRY_SECONDS;
                $r['problems'][$p['id']]=['server'=>SecretsBackendPeerName::display($p),'step'=>'Discover server list','reason'=>$problem,'retryAt'=>$r['retry'][$p['id']],'message'=>self::problemText($problem).($e instanceof SecretsBackendNativePeerDeliveryFailure&&$e->httpStatus?' HTTP '.$e->httpStatus.'.':'')];
            }
            $this->saveDiscovery($r);return ['status'=>'SETUP_DISCOVERY_PENDING'];
        }
        foreach($s['pairing']['peers']as$p)if($p['active']&&$p['state']==='ACTIVE'&&!isset($r['checked'][$p['id']]))return ['status'=>'SETUP_DISCOVERY_RETRY'];
        ksort($r['members']);$p=['format'=>self::FORMAT,'id'=>SecretsBackendCodec::uuid(),'coordinator'=>$s['native']['vaultId'],'purpose'=>self::PURPOSE,'members'=>array_values($r['members'])];$p['signature']=$this->store->sign('SECB.SETUP.POLICY.1:'.SecretsBackendNativeStore::canonical($p));$this->checkLocal($p,$s);$r['policy']=$p;$this->saveDiscovery($r);return ['status'=>'SETUP_DISCOVERY_COMPLETE'];
    }
    public function requestPending():bool { try{$this->store->get(self::REQUEST,self::REQUEST);return true;}catch(Throwable $e){return false;} }
    private function cache(string $key,array $value,int $seconds=86400):void { try{$this->store->replace($key,$key,$value,time()+$seconds);}catch(Throwable $e){$this->store->put($key,$key,$value,time()+$seconds);} }
    public function requestStart(array $session):void {
        $s=$this->store->read()['state'];
        if(!SecretsBackendBackupOriginPolicy::credentialFull($s,$s['identity']['credentials'][$session['credential']]??[]))throw new RuntimeException('Full administrator access required.');
        if(self::enabled($s)&&($s['native']['automaticSetup']['policy']['format']??'')===self::AUTOMATIC_FORMAT){$this->start();return;}
        if($s['native']['setupDelegationStopped']??false){$this->store->delete(self::REQUEST);$this->store->delete(self::DISCOVERY);$this->commit('local-restart',function($v){unset($v['native']['setupDelegationStopped']);return $v;});}
        if($this->requestPending())return;
        $this->store->delete(self::DISCOVERY);
        $this->cache(self::REQUEST,['credential'=>$session['credential'],'revocation'=>$s['identity']['revocation'],'expires'=>time()+1800]);
        $this->cache(self::REPORT,['state'=>'running','startedAt'=>time(),'steps'=>[],'errors'=>[]]);
    }
    private function advanceRequest():array {
        $request=$this->store->get(self::REQUEST,self::REQUEST);if($request['expires']<time()){$this->store->delete(self::REQUEST);$this->store->delete(self::DISCOVERY);throw new RuntimeException('Discovery did not complete within 20 minutes.');}$s=$this->store->read()['state'];
        if(($s['native']['setupDelegationStopped']??false)||$request['revocation']!==$s['identity']['revocation']||!SecretsBackendBackupOriginPolicy::credentialFull($s,$s['identity']['credentials'][$request['credential']]??[])){$this->store->delete(self::REQUEST);$this->store->delete(self::DISCOVERY);throw new RuntimeException('Setup administrator authorization was revoked.');}
        // Ignore old per-node proposals while discovering the current trusted group.
        try{$r=$this->store->get(self::DISCOVERY,self::DISCOVERY);}catch(Throwable $e){$r=['members'=>[],'checked'=>[],'problems'=>[],'retry'=>[],'expires'=>time()+1200,'automatic'=>true];foreach($this->info($s)['members']as$m)$r['members'][$m['descriptor']['vaultId']]=$m;$this->saveDiscovery($r);}
        if(!isset($r['policy'])){if($r['expires']<time()){$this->store->delete(self::REQUEST);$this->store->delete(self::DISCOVERY);throw new RuntimeException('Discovery did not complete within 20 minutes.');}return $this->discover();}
        $token=SecretsBackendCodec::b64(random_bytes(32));$p=$r['policy'];$p['format']=self::AUTOMATIC_FORMAT;$p['credentialHash']=hash('sha256',$token);unset($p['signature']);$p['signature']=$this->store->sign('SECB.SETUP.POLICY.1:'.SecretsBackendNativeStore::canonical($p));
        $this->commit('automatic-start',function($v)use($p,$request,$token){if($v['identity']['revocation']!==$request['revocation']||!SecretsBackendBackupOriginPolicy::credentialFull($v,$v['identity']['credentials'][$request['credential']]??[]))throw new RuntimeException('Setup administrator authorization was revoked.');return $this->enroll($v,$p,$token,$request['credential']);});
        $this->store->delete(self::REQUEST);return ['status'=>'SETUP_STARTED'];
    }
    /** Only called from an authenticated existing shared-Global connection, or a local full admin. */
    public function enroll(array $s,array $p,string $token,?string $credential=null,?string $sender=null):array {
        $this->checkLocal($p,$s);if($sender!==null&&($s['native']['setupDelegationStopped']??false))throw new RuntimeException('Automatic mesh delegation was stopped on this server.');SecretsBackendCodec::unb64($token,32);
        if($p['format']!==self::AUTOMATIC_FORMAT||!hash_equals($p['credentialHash'],hash('sha256',$token)))throw new RuntimeException('Setup credential does not match the signed plan.');
        if($sender!==null){$peer=$s['pairing']['peers'][$sender]??null;if(!$peer||!$peer['active']||$peer['state']!=='ACTIVE'||!SecretsBackendNativePeer::shared($peer)||self::key(self::member($p,$sender)['descriptor'])!==self::key($peer['descriptor']))throw new RuntimeException('Setup sender is not a trusted Global connection.');}
        $old=$s['native']['automaticSetup']??null;
        if(($old['policy']['id']??null)===$p['id'])return $s; // replay never restores revoked/suspended authority
        if(($old['policy']['format']??null)===self::AUTOMATIC_FORMAT)throw new RuntimeException('A different automatic setup plan is already installed.');
        unset($s['native']['automaticSetup'],$s['native']['setupProposal'],$s['native']['setupProposalSent']);
        $s['outbox']['jobs']=array_values(array_filter($s['outbox']['jobs'],static fn($j)=>!in_array($j['kind'],['SETUP_OFFER','SETUP_ENROLL'],true)));
        // Dedicated Global control secret: encrypted, replicated in sealed setup envelopes,
        // excluded from application Global/Local reads, exports and public diagnostics.
        $s['native']['globalSetupSecret']=['planId'=>$p['id'],'token'=>$token];
        $s=$this->authorize(SecretsBackendSharedGlobal::enable($s),$p,['credential'=>$credential]);
        $s['native']['automaticSetup']['master']=SecretsBackendCodec::b64(hash_hmac('sha256','SECB.SETUP.NODE.2:'.$s['native']['vaultId'],$token,true));
        $s['native']['automaticSetup']['startedAt']=time();return $s;
    }
    private function report():array { try{return $this->store->get(self::REPORT,self::REPORT);}catch(Throwable $e){return ['state'=>'idle','steps'=>[],'errors'=>[]];} }
    private function publicReport():array {
        $r=$this->report();try{$d=$this->store->get(self::DISCOVERY,self::DISCOVERY);$r['discovery']=['found'=>count($d['members']),'confirmed'=>count($d['checked']),'waiting'=>array_values($d['problems']??[])];}catch(Throwable $e){}return $r;
    }
    private function recordResult(array $result):void {
        $r=$this->report();$r['state']=$result['status']==='SETUP_COMPLETE'?'complete':'running';$r['updatedAt']=time();$r['steps']=array_slice([...$r['steps'],['at'=>time()]+$result],-64);$this->cache(self::REPORT,$r);
    }
    private function recordError(Throwable $e,string $step,?array $target=null):void {
        $this->failureRecorded=true;
        $r=$this->report();$known=['Setup administrator authorization was revoked.','Discovery did not complete within 20 minutes.','Mesh setup did not complete within 60 minutes. See each server and connection in the report.','A different automatic setup plan is already installed.','Automatic mesh delegation was stopped on this server.','Automatic setup is not authorized on this server.','Setup plan has a different local vault identity.','A setup member was revoked or changed identity. Review a new plan.','An existing manual connection needs review.','Peer capacity reached.'];
        $r['state']='incomplete';$r['updatedAt']=time();$row=['at'=>time(),'server'=>$target?SecretsBackendPeerName::address($target['descriptor']['endpoint']):SecretsBackendPeerName::address($this->ownDescriptor()['endpoint']),'direction'=>$target?$this->ownDescriptor()['vaultId'].' → '.$target['descriptor']['vaultId']:'local','step'=>$step,'code'=>$e instanceof SecretsBackendNativePeerDeliveryFailure&&in_array($e->problem,SecretsBackendNativePeerDeliveryFailure::PROBLEMS,true)?$e->problem:'local-operation-failed','message'=>in_array($e->getMessage(),$known,true)?$e->getMessage():($e instanceof SecretsBackendNativePeerDeliveryFailure?self::problemText($e->problem):'The operation failed; no successful result was confirmed.'),'httpStatus'=>$e instanceof SecretsBackendNativePeerDeliveryFailure?$e->httpStatus:null,'attempts'=>$e instanceof SecretsBackendNativePeerDeliveryFailure?$e->attempts:[],'reference'=>substr(hash('sha256',get_class($e).':'.$e->getMessage()),0,16),'retryAt'=>time()+self::RETRY_SECONDS,'exception'=>get_class($e),'source'=>basename($e->getFile()).':'.$e->getLine()];
        $row['attemptNumber']=1;foreach($r['errors']as$previous)if($previous['server']===$row['server']&&$previous['step']===$row['step'])$row['attemptNumber']=max($row['attemptNumber'],($previous['attemptNumber']??1)+1);$r['errors']=array_slice([...$r['errors'],$row],-32);$this->cache(self::REPORT,$r);
    }
    public function diagnostics(array $state):array {
        $status=$this->status($state);$discovery=null;
        try{$r=$this->store->get(self::DISCOVERY,self::DISCOVERY);$discovery=['found'=>count($r['members']),'checked'=>count($r['checked']),'complete'=>isset($r['policy']),'waiting'=>array_values($r['problems']??[])];}catch(Throwable $ignored){}
        return ['report'=>$status['report']??null,'authorized'=>$status['authorized'],'running'=>$status['running']??false,'completedAt'=>$status['completedAt']??null,'localCompletedAt'=>$status['localCompletedAt']??null,'members'=>$status['members'],'discovery'=>$discovery];
    }
    public static function problemText(string $problem):string { return match($problem){'timeout'=>'The server did not reply within the generous request allowance. It will be retried automatically.','connect'=>'Could not connect to the server. It will be retried automatically.','dns'=>'The server hostname could not be resolved. It will be retried automatically.','certificate'=>'HTTPS certificate verification failed. Correct the certificate or approved route.','tls'=>'The secure connection could not be established. It will be retried automatically.','http'=>'The server rejected this operation. See the operation, HTTP status, attempted routes and retry time in the report.','invalid-reply'=>'The reply could not be authenticated or understood. Check that both servers use the same current Secrets version.',default=>'Delivery was not confirmed. It will be retried automatically.'}; }
    public function authorize(array $s,array $p,array $session):array {
        $this->checkLocal($p,$s);if(isset($s['native']['automaticSetup'])&&($s['native']['automaticSetup']['enabled']??false)&&$s['native']['automaticSetup']['policy']['id']!==$p['id'])throw new RuntimeException('Stop the existing setup authorization before approving a different plan.');
        $s=$this->offer($s,$p);$bindings=[];foreach($p['members']as$m){$id=$m['descriptor']['vaultId'];if($id===$s['native']['vaultId'])continue;$q=$s['pairing']['peers'][$id]??null;$bindings[$id]=['key'=>self::key($m['descriptor']),'pairing'=>$q['pairingId']??null];}
        $s['native']['automaticSetup']=['policy'=>$p,'enabled'=>true,'generation'=>SecretsBackendCodec::uuid(),'master'=>SecretsBackendCodec::b64(random_bytes(32)),'credential'=>$session['credential'],'revocation'=>$s['identity']['revocation'],'bindings'=>$bindings,'issued'=>[],'requested'=>true,'run'=>$p['id'],'dispatch'=>true,'completedAt'=>null,'meshCompletedAt'=>null,'lastProblem'=>null,'seenRuns'=>[$p['id']]];return $s;
    }
    public function offer(array $s,array $p):array {
        $this->checkLocal($p,$s);$old=$s['native']['setupProposal']??null;if($old&&$old['id']!==$p['id'])throw new RuntimeException('A different setup plan is already awaiting review.');
        $s['native']['setupProposal']=$p;$sent=$s['native']['setupProposalSent']??[];
        foreach($s['pairing']['peers']as$q)if($q['active']&&$q['state']==='ACTIVE'&&!isset($sent[$q['id']])&&in_array($q['id'],array_column(array_column($p['members'],'descriptor'),'vaultId'),true)){if(count($s['outbox']['jobs'])>=128)throw new RuntimeException('Wait for pending peer delivery before starting setup.');$automatic=$p['format']===self::AUTOMATIC_FORMAT;$s['outbox']['jobs'][]=SecretsBackendNativePeer::job($q,$automatic?'SETUP_ENROLL':'SETUP_OFFER',['policy'=>$p]+($automatic?['token'=>$s['native']['globalSetupSecret']['token']]:[]));$sent[$q['id']]=true;}
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
        $out=['status'=>'SETUP_HELLO','authorized'=>$ok,'frontend'=>(int)$this->store->identity()['binding']['frontend'],'routes'=>$this->peer->ownRoutes($s),'routeRevision'=>$s['native']['routeRevision']??'0','backupStatus'=>$s['policy']['backupOrigin']['status']??'none','backupReady'=>$this->backupReady($s),'clientGrant'=>$client['grantId']??null,'offerGrant'=>$offer['grantId']??null,'ready'=>self::enabled($s)&&($a['completedAt']??null)!==null&&$this->localReady($s),'generation'=>$ok?$a['generation']:null];
        if(($a['policy']['format']??'')===self::AUTOMATIC_FORMAT){$out['details']=$this->localDetails($s);$out['run']=$a['run'];}
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
            $newRun=!in_array($p['run'],$s['native']['automaticSetup']['seenRuns'],true);$started=false;
            if($newRun||!isset($s['pairing']['peers'][$m['sender']]))$this->commit('request',function($v)use($m,$p,&$started){$this->token($v,$m['sender'],$p);$v=$this->ensurePair($v,$m['sender']);$a=&$v['native']['automaticSetup'];if(!in_array($p['run'],$a['seenRuns'],true)){$started=true;$a['requested']=true;$a['startedAt']=time();$a['run']=$p['run'];$a['dispatch']=false;$a['completedAt']=null;$a['meshCompletedAt']=null;$a['seenRuns']=array_slice([...$a['seenRuns'],$p['run']],-32);}return $v;});
            if($started)$this->cache(self::REPORT,['state'=>'running','run'=>$p['run'],'startedAt'=>time(),'steps'=>[['at'=>time(),'status'=>'SETUP_RUN_STARTED']],'errors'=>[]]);
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
        $this->commit('start',function($s){$this->active($s);$a=&$s['native']['automaticSetup'];$a['run']=SecretsBackendCodec::uuid();$a['requested']=true;$a['dispatch']=true;$a['startedAt']=time();$a['completedAt']=null;$a['meshCompletedAt']=null;return $s;});
        $this->cache(self::REPORT,['state'=>'running','startedAt'=>time(),'steps'=>[],'errors'=>[]]);
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
        catch(Throwable $e){$this->recordError($e,$kind,$target);try{$this->store->delete($pending);}catch(Throwable $ignored){}$r=['at'=>$this->now(),'next'=>$this->now()+self::RETRY_SECONDS,'problem'=>$e instanceof SecretsBackendNativePeerDeliveryFailure&&in_array($e->problem,SecretsBackendNativePeerDeliveryFailure::PROBLEMS,true)?$e->problem:'unconfirmed'];try{$this->store->replace($key,'automatic-setup-retry',$r,time()+self::RETRY_SECONDS+120);}catch(Throwable $ignored){$this->store->put($key,'automatic-setup-retry',$r,time()+self::RETRY_SECONDS+120);}throw $e;}
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
        if(!self::enabled($s))return false;$a=$s['native']['automaticSetup'];$contacts=$this->contacts($a);
        if(SecretsBackendNativeHealth::stamp($s)['conflicts']>0)return false;
        $health=(new SecretsBackendNativeHealth($this->store,$this->peer,$this->clock))->statuses($s,self::VERIFICATION_SECONDS);
        foreach($a['policy']['members']as$m){$id=$m['descriptor']['vaultId'];if($id===$s['native']['vaultId'])continue;$q=$s['pairing']['peers'][$id]??null;$c=$contacts[$id]??null;
            if(!$q||!$q['active']||!SecretsBackendNativePeer::shared($q)||!$c||$this->now()<$c['at']||$this->now()-$c['at']>=self::CONFIRMATION_SECONDS||!$c['authorized']||!isset($s['native']['emergencyClients'][$id])||($health[$id]['synchronization']??'')!=='verified')return false;
            $found=false;$grants=0;foreach($s['native']['emergencyGrants']??[]as$g)if($g['source']===$id&&$g['active']&&$g['pairingId']===$q['pairingId']){++$grants;if($g['id']===$c['clientGrant'])$found=true;}if(!$found||$grants!==1||isset($a['issued'][$id]))return false;
            if(($q['routeReceipt']??null)!==($s['native']['routeRevision']??'0'))return false;
            if(($a['policy']['format']??'')===self::AUTOMATIC_FORMAT){if(($c['run']??null)!==$a['run'])return false;$mesh=new SecretsBackendMeshStatus($this->store,$this->peer,$this->clock);if($mesh->route($s,$q,false,self::VERIFICATION_SECONDS)['state']!=='ok'||$mesh->route($s,$q,true,self::VERIFICATION_SECONDS)['state']!=='ok')return false;}
        }
        return !count($s['outbox']['jobs']);
    }
    /** One bounded local change or one outbound exchange per worker phase. */
    public function tick():array {
        $this->failureRecorded=false;
        try{$result=$this->requestPending()?$this->advanceRequest():($this->discoveryPending()?$this->discover():$this->step());if(!in_array($result['status'],['SETUP_IDLE','SETUP_WAITING','SETUP_SERVER_CHECKED'],true))$this->recordResult($result);return $result;}catch(Throwable $e){if(!$this->failureRecorded)$this->recordError($e,'Advance mesh setup');return ['status'=>'SETUP_RETRY_PENDING'];}
    }
    private function step():array {
        $s=$this->store->read()['state'];if(!self::enabled($s)||!($s['native']['automaticSetup']['requested']??false))return ['status'=>'SETUP_IDLE'];$a=$this->active($s);$contacts=$this->contacts($a);$own=$s['native']['vaultId'];
        if(time()-($a['startedAt']??time())>3600){$this->commit('deadline',function($v){$v['native']['automaticSetup']['requested']=false;return $v;});throw new RuntimeException('Mesh setup did not complete within 60 minutes. See each server and connection in the report.');}
        {
            $found=SecretsFrontendConnectDiscovery::local();
            if(($found['available']??false)&&($s['native']['setupPeerBackupOrigin']??null)!==$found['origin']&&preg_match('~^https://[a-z0-9]{32}\.ipmagic\.de$~D',$found['origin'])){
                $this->commit('prepare-peer-backup',function($v)use($found){$this->active($v);$v['native']['setupPeerBackupOrigin']=$found['origin'];$v['native']['routeRevision']=SecretsBackendCodec::increment($v['native']['routeRevision']??'0');return $v;});return ['status'=>'SETUP_PEER_BACKUP_CONFIGURED'];
            }
        }
        $enrolling=[];foreach($s['outbox']['jobs']as$j)if($j['kind']==='SETUP_ENROLL')$enrolling[$j['receiverId']]=true;
        if($enrolling){
            $delivery=$this->peer->dispatch(1,null,false,null,['SETUP_ENROLL']);
            if($delivery)return ['status'=>$delivery[0]['status']==='ACKNOWLEDGED'?'SETUP_ENROLLMENT_DELIVERED':'SETUP_ENROLLMENT_RETRY_PENDING','jobId'=>$delivery[0]['id']];
        }
        foreach(SecretsBackendEmergency::publicMetadata($s)['offers']as$o){try{self::member($a['policy'],$o['peerId']);}catch(Throwable $ignored){continue;}$ops=new SecretsBackendNativeOperations($this->store,$this->peer);$op=$ops->normalize(['kind'=>'nativeEmergencyAccept','peerId'=>$o['peerId'],'digest'=>$o['digest']],$s,false);$this->commit('accept-emergency',function($v)use($ops,$op){$this->active($v);return $ops->apply($op,$v,true);});if($this->emergencySync!==null)($this->emergencySync)();return ['status'=>'SETUP_EMERGENCY_ACCEPTED'];}
        // Completion must not wait behind an endless rotation of due status polls.
        if($this->store->withActiveSnapshot(fn($current)=>$this->localReady($current['state']))){
            $remoteReady=true;foreach($a['policy']['members']as$m){$id=$m['descriptor']['vaultId'];if($id===$own)continue;$c=$contacts[$id]??null;if(!$c||!$c['ready']||(($a['policy']['format']??'')===self::AUTOMATIC_FORMAT&&($c['run']??null)!==$a['run'])||$this->now()-$c['at']>=self::CONFIRMATION_SECONDS)$remoteReady=false;}
            if($a['completedAt']===null||($remoteReady&&$a['requested'])){$this->commit('complete',function($v)use($remoteReady){$this->active($v);if(!$this->localReady($v))throw new RuntimeException('Setup verification changed before completion.');$v['native']['automaticSetup']['requested']=!$remoteReady;$v['native']['automaticSetup']['completedAt']??=$this->now();if($remoteReady)$v['native']['automaticSetup']['meshCompletedAt']=$this->now();return $v;});return ['status'=>$remoteReady?'SETUP_COMPLETE':'SETUP_LOCAL_COMPLETE'];}
        }
        $members=array_values(array_filter($a['policy']['members'],static fn($m)=>$m['descriptor']['vaultId']!==$own));$cursor=0;try{$cursor=$this->store->get($this->cursorKey($a),'setup-cursor')['next'];}catch(Throwable $ignored){}
        for($offset=0;$offset<count($members);$offset++){$m=$members[($cursor+$offset)%count($members)];$id=$m['descriptor']['vaultId'];$c=$contacts[$id]??null;
            if(isset($enrolling[$id]))continue; // Never ask for capabilities before their authority has been delivered.
            try{$retry=$this->store->get($this->retryKey($id,$a['policy']['id']),'automatic-setup-retry');if($retry['next']>$this->now())continue;}catch(Throwable $ignored){}
            try{$target=$this->target($s,$m);}catch(Throwable $e){$this->rotateToNext($id);$key=$this->retryKey($id,$a['policy']['id']);$retry=['at'=>$this->now(),'next'=>$this->now()+self::RETRY_SECONDS,'problem'=>'route-changed'];try{$this->store->replace($key,'automatic-setup-retry',$retry,time()+210);}catch(Throwable $ignored){$this->store->put($key,'automatic-setup-retry',$retry,time()+210);}continue;}
            if(!$c||((($c['nextAction']??'check')==='check'||!$c['authorized'])&&$this->now()-$c['at']>=self::RETRY_SECONDS)||($c['authorized']&&$c['expires']<$this->now()+120)){
                $r=$this->exchange($target,'SETUP_HELLO',['format'=>self::FORMAT]);$this->validateHello($r,$m['descriptor']);
                $old=$contacts[$id]??[];$this->saveContact($a,$id,$r+['at'=>$this->now(),'nextAction'=>'work','advancedRun'=>($old['generation']??null)===$r['generation']?($old['advancedRun']??null):null]);return ['status'=>$r['authorized']?((($old['authorized']??false)&&($old['generation']??null)===$r['generation'])?'SETUP_SERVER_CHECKED':'SETUP_SERVER_AUTHORIZED'):'SETUP_APPROVAL_REQUIRED','server'=>$id];
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
        return ['status'=>'SETUP_WAITING'];
    }
    private function validateHello(array $r,array $d):void {
        SecretsBackendNativePeer::exact($r,['requestId','requestKind','requestDigest','status','authorized','frontend','routes','routeRevision','backupStatus','backupReady','clientGrant','offerGrant','ready','generation',...(($r['authorized']??false)?['expires','token']:[]),...(isset($r['details'])?['details']:[]),...(isset($r['run'])?['run']:[])]);
        if(isset($r['run']))self::uuid($r['run']);
        if(isset($r['details'])&&(!is_array($r['details'])||strlen(SecretsBackendCodec::json($r['details']))>16000))throw new RuntimeException('Invalid setup report.');
        if($r['status']!=='SETUP_HELLO'||!is_bool($r['authorized'])||!is_bool($r['ready'])||!is_bool($r['backupReady'])||!is_int($r['frontend'])||$r['frontend']<1||$r['frontend']>99999999||!in_array($r['backupStatus'],['none','pending','active','revoked'],true))throw new RuntimeException('Invalid setup progress.');self::routes($d,$r['routes']);SecretsBackendNativePeer::decimal($r['routeRevision']);foreach(['clientGrant','offerGrant','generation']as$k)if($r[$k]!==null)self::uuid($r[$k]);if($r['authorized']&&(!is_int($r['expires'])||$r['expires']<$this->now()||$r['expires']>$this->now()+self::CAPABILITY_SECONDS+60||!is_string($r['token'])||!preg_match('/^[a-f0-9]{64}$/D',$r['token'])))throw new RuntimeException('Invalid setup capability.');
    }
    /** Display only: missing acceptance evidence is unknown, not a revoked grant. */
    private function emergencySendStatus(array $s,?array $p,?array $c,SecretsBackendMeshStatus $mesh):?bool {
        if(!$p||!$p['active']||$p['state']!=='ACTIVE'||!SecretsBackendNativePeer::shared($p))return false;
        $ids=[];foreach($s['native']['emergencyGrants']??[]as$g)if($g['source']===$p['id']&&$g['active']&&$g['pairingId']===$p['pairingId'])$ids[]=$g['id'];
        if(!$ids)return false;
        $at=$c['at']??0;$confirmedAt=0;$accepted=null;
        if($at>0&&$this->now()>=$at&&$this->now()-$at<self::CONFIRMATION_SECONDS&&($c['run']??null)===($s['native']['automaticSetup']['run']??null)){$confirmedAt=$at;$accepted=in_array($c['clientGrant']??null,$ids,true);}
        $r=$mesh->peerReport($p);
        if($r!==null&&$r['age']!==null&&$this->now()-$r['age']>=$confirmedAt){
            if($r['age']>=$r['report']['ttl'])return null;
            foreach($r['report']['links']as$l)if($l['id']===$s['native']['vaultId'])return $l['paired']&&$l['consumes']&&in_array($l['clientGrant'],$ids,true);
            return $r['report']['truncated']?null:false;
        }
        return $accepted;
    }
    private function localDetails(array $s):array {
        $a=$s['native']['automaticSetup']??null;$health=(new SecretsBackendNativeHealth($this->store,$this->peer,$this->clock))->statuses($s,self::VERIFICATION_SECONDS);$mesh=new SecretsBackendMeshStatus($this->store,$this->peer,$this->clock);$delivery=$this->peer->deliveryStatus($s);$contacts=$a?$this->contacts($a):[];$links=[];
        foreach($a['policy']['members']??[]as$m){$id=$m['descriptor']['vaultId'];if($id===$s['native']['vaultId'])continue;$q=$s['pairing']['peers'][$id]??null;$grant=$this->emergencySendStatus($s,$q,$contacts[$id]??null,$mesh);$client=$s['native']['emergencyClients'][$id]??null;
            $links[]=['server'=>SecretsBackendPeerName::address($m['descriptor']['endpoint']),'connected'=>$q&&$q['active']&&$q['state']==='ACTIVE','primary'=>$q?$mesh->route($s,$q,false,self::VERIFICATION_SECONDS):['state'=>'none'],'backup'=>$q?$mesh->route($s,$q,true,self::VERIFICATION_SECONDS):['state'=>'none'],'delivery'=>$delivery[$id]??null,'synchronization'=>$health[$id]['synchronization']??'unknown','emergencyReceive'=>$q&&$q['active']&&$q['state']==='ACTIVE'&&SecretsBackendNativePeer::shared($q)&&is_array($client)&&$client['pairingId']===$q['pairingId'],'emergencySend'=>$grant,'routesAcknowledged'=>$q&&($q['routeReceipt']??null)===($s['native']['routeRevision']??'0')];
        }
        $r=$this->report();return ['backupRoute'=>isset($s['native']['setupPeerBackupOrigin'])?'configured':'not-configured','backupRouteProblem'=>isset($s['native']['setupPeerBackupOrigin'])?null:'The local Symcon Connect service has not supplied an active HTTPS Magic route. Check Connect Control on this server.','links'=>$links,'queuedMessages'=>count($s['outbox']['jobs']),'conflicts'=>count(SecretsBackendSharedGlobal::metadata($s)['conflicts']??[]),'errors'=>array_slice($r['errors']??[],-3),'receiver'=>$this->peer->setupRuntimeDiagnostics()];
    }
    public function status(array $s):array {
        // One local lock includes contact caches, delivery state and the report. No peer I/O.
        return $this->store->withActiveSnapshot(fn($current)=>$this->statusSnapshot($current['state']));
    }
    private function statusSnapshot(array $s):array {
        $a=$s['native']['automaticSetup']??null;$p=$a['policy']??$s['native']['setupProposal']??null;if(!$p)return ['authorized'=>false,'policy'=>null,'members'=>[],'running'=>$this->requestPending(),'report'=>$this->publicReport()];$members=[];$contacts=$a?$this->contacts($a):[];
        $enrollmentState=$s;$enrollmentState['outbox']['jobs']=array_values(array_filter($s['outbox']['jobs'],static fn($j)=>$j['kind']==='SETUP_ENROLL'));$enrollment=$this->peer->deliveryStatus($enrollmentState);
        foreach($p['members']as$m){$id=$m['descriptor']['vaultId'];$own=$id===$s['native']['vaultId'];$c=$contacts[$id]??null;$at=$c['at']??0;$front=$own?(int)$this->store->identity()['binding']['frontend']:($c['frontend']??$m['frontend']);$origin=SecretsBackendNativeLegacyHTTPS::origin($m['descriptor']['endpoint']);$pending=false;foreach($s['outbox']['jobs']as$j)if($j['kind']==='SETUP_ENROLL'&&$j['receiverId']===$id)$pending=true;try{$this->store->get('setup-pending:'.$p['id'].':'.$id,'setup-pending');$pending=true;}catch(Throwable $ignored){}$retry=null;try{$retry=$this->store->get($this->retryKey($id,$p['id']),'automatic-setup-retry');}catch(Throwable $ignored){}
            $members[]=['id'=>$id,'name'=>SecretsBackendPeerName::address($m['descriptor']['endpoint']),'local'=>$own,'url'=>$front!==null?$origin.'/hook/secrets_frontend_'.$front:null,'authorized'=>$own?self::enabled($s):($c['authorized']??null),'fresh'=>$own||($at>0&&$this->now()>=$at&&$this->now()-$at<self::CONFIRMATION_SECONDS),'enrollment'=>$enrollment[$id]??null,'deliveryPending'=>$pending,'deliveryProblem'=>$retry['problem']??null,'checkedAt'=>$own?$this->now():($at?:null),'backupStatus'=>$own?($s['policy']['backupOrigin']['status']??'none'):($c['backupStatus']??'unknown'),'backupReady'=>$own?$this->backupReady($s):($c['backupReady']??false),'ready'=>$own?(($a['completedAt']??null)!==null&&$this->localReady($s)):(($c['ready']??false)&&(($a['policy']['format']??'')!==self::AUTOMATIC_FORMAT||($c['run']??null)===$a['run'])),'details'=>$own?$this->localDetails($s):($c['details']??null)];
        }
        $report=$this->publicReport();$running=$this->requestPending()||($a['requested']??false);
        $completedAt=$running?null:($a['meshCompletedAt']??(($report['state']??'')==='complete'?($a['completedAt']??null):null));
        // Runtime restarts and cache expiry erase the step log, not durable completion.
        if($completedAt!==null&&$report['state']==='idle')$report=array_merge($report,['state'=>'complete','completedAt'=>$completedAt,'historyAvailable'=>false]);
        return ['observedAt'=>$this->now(),'authorized'=>self::enabled($s),'policy'=>$p,'members'=>$members,'running'=>$running,'completedAt'=>$completedAt,'localCompletedAt'=>$a['completedAt']??null,'verificationWindowSeconds'=>self::VERIFICATION_SECONDS,'report'=>$report];
    }
}
