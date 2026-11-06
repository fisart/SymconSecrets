<?php
declare(strict_types=1);
require_once __DIR__.'/Fixture.php';
function realBridge(array $args,string $input=''):string {
    $p=proc_open(array_merge(['python3',__DIR__.'/anchor_bridge.py'],$args),[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    fwrite($pipes[0],$input);fclose($pipes[0]);$out=stream_get_contents($pipes[1]);fclose($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[2]);
    if(proc_close($p)!==0)throw new RuntimeException($err);return $out;
}
function realFixture(?callable $fault=null):array {
    $dir=sys_get_temp_dir().'/audit-real-'.bin2hex(random_bytes(8));mkdir($dir,0700);
    $info=SecretsBackendStore::initialize($dir.'/data',$dir.'/keys','https://secrets.example.test',123,'DELETE');
    file_put_contents($dir.'/provision.json',SecretsBackendCodec::json($info));
    $witness=json_decode(realBridge([$dir.'/anchor',$dir.'/provision.json']),true);
    $settings=$info+$witness+['signingKeyFile'=>$dir.'/keys/anchor-sign.key'];
    $client=new SecretsBackendAnchorClient($settings,static fn($wire)=>realBridge([$dir.'/anchor'],$wire));
    $runtime=SecretsBackendCodec::b64(random_bytes(32));$store=new SecretsBackendStore($dir.'/data',$dir.'/keys',$runtime,$client,'DELETE',$fault);$store->recover();
    return [$store,$client,$dir,$settings,$runtime];
}
function appFor(SecretsBackendStore $store):SecretsBackendApplication {return new SecretsBackendApplication($store,['origin'=>'https://secrets.example.test','frontend'=>123,'backend'=>456]);}
function enrollAudit(SecretsBackendApplication $app,array $request):array {
    $key=secKey();$code=$app->beginEnrollment('Audit',false);$o=secOptions($app->handle('enrollmentOptions',['code'=>$code],$request));
    $app->handle('enrollmentVerify',['challengeId'=>$o['challengeId'],'credential'=>secRegistration($key,$o['options']['challenge'])],$request);return $key;
}
$request=['origin'=>'https://secrets.example.test','cookie'=>'','csrf'=>'','remote'=>'127.0.0.1'];

// Race 1: real witness, two Store connections, deterministic interleaving.
[$store,$client,$dir,$settings,$runtime]=realFixture();
$app=appFor($store);$key=enrollAudit($app,$request);$spare=enrollAudit($app,$request);
$store->change($store->head(),SecretsBackendCodec::uuid(),hash('sha256','seed'),static function($s){$s['vault']['global']=SecretsBackendTree::parse('{"Service":{"Password":"AUDIT_REVEAL_CANARY"}}');return $s;});
$o=secOptions($app->handle('authOptions',[],$request));$login=$app->handle('authVerify',['challengeId'=>$o['challengeId'],'credential'=>secAssertion($key,$o['options']['challenge'],1)],$request);
$request['cookie']=explode(';',$login['cookie'])[0];$request['csrf']=$login['data']['csrf'];
$o=secOptions($app->handle('prepare',['operation'=>['kind'=>'reveal','scope'=>'global','path'=>['Service'],'revision'=>'0']],$request));
$revocationIndex='';$revealDecision=[];
$observeClient=new SecretsBackendAnchorClient($settings,static function($wire)use($dir,&$revealDecision){
    $req=json_decode($wire,true)['request'];$result=realBridge([$dir.'/anchor'],$wire);
    if($req['operation']==='authorize'&&$req['body']['kind']==='reveal')$revealDecision=json_decode($result,true)['response']['result'];
    return $result;
});
$revealer=new SecretsBackendStore($dir.'/data',$dir.'/keys',$runtime,$observeClient,'DELETE');
class AuditPDO extends PDO {
    public $afterCommit=null;
    public function exec(string $statement):int|false {
        $result=parent::exec($statement);
        if($statement==='COMMIT'&&$this->afterCommit!==null)($this->afterCommit)($this);
        return $result;
    }
}
$db=new AuditPDO('sqlite:'.$dir.'/data/vault.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);
$db->exec('PRAGMA synchronous=FULL');$db->exec('PRAGMA busy_timeout=2000');
$expectedIndex=SecretsBackendCodec::increment($store->head()['index']);
$db->afterCommit=static function($db)use($store,$key,$expectedIndex,&$revocationIndex){
    $pending=$db->query("SELECT value FROM metadata WHERE name='pending'")->fetchColumn();
    if($pending!==''||$store->head()['index']!==$expectedIndex)return;
    $db->afterCommit=null;
    $h=$store->change($store->head(),SecretsBackendCodec::uuid(),hash('sha256','revoke-after-counter-publish'),static function($s)use($key){$s['identity']['credentials'][$key['id']]['active']=false;$s['identity']['revocation']=SecretsBackendCodec::increment($s['identity']['revocation']);return $s;});
    $revocationIndex=$h['index'];
};
$property=new ReflectionProperty(SecretsBackendStore::class,'db');$property->setValue($revealer,$db);
secRejectReason(static fn()=>appFor($revealer)->handle('approve',['challengeId'=>$o['challengeId'],'credential'=>secAssertion($key,$o['options']['challenge'],2)],$request), 'Reveal state changed before authorization');
secExpect($revocationIndex !== '' && $revealDecision === [], 'A revoked authority received a new reveal grant.');
echo "PASS A02 reveal revocation between counter publication and final authorization (real witness)\n";

// Metadata variant: session validated against A, authorize silently chooses B.
// Use spare credential, since first credential is now revoked.
$o=secOptions($app->handle('authOptions',[],['origin'=>'https://secrets.example.test','cookie'=>'','csrf'=>'','remote'=>'127.0.0.1']));
$login=$app->handle('authVerify',['challengeId'=>$o['challengeId'],'credential'=>secAssertion($spare,$o['options']['challenge'],1)],['origin'=>'https://secrets.example.test','cookie'=>'','csrf'=>'','remote'=>'127.0.0.1']);
$request['cookie']=explode(';',$login['cookie'])[0];$request['csrf']=$login['data']['csrf'];
$first=true;$metaDecision=[];
$raceClient=new SecretsBackendAnchorClient($settings,static function($wire)use($dir,$store,&$first,&$revocationIndex,&$metaDecision){
    $req=json_decode($wire,true)['request'];$result=realBridge([$dir.'/anchor'],$wire);
    if($first&&$req['operation']==='read'){
        $first=false;$h=$store->change($store->head(),SecretsBackendCodec::uuid(),hash('sha256','invalidate-sessions-before-metadata-authorize'),static function($s){$s['identity']['revocation']=SecretsBackendCodec::increment($s['identity']['revocation']);return $s;});$revocationIndex=$h['index'];
    }
    if($req['operation']==='authorize')$metaDecision=json_decode($result,true)['response']['result'];
    return $result;
});
$raceStore=new SecretsBackendStore($dir.'/data',$dir.'/keys',$runtime,$raceClient,'DELETE');
secRejectReason(static fn()=>appFor($raceStore)->handle('list',[],$request), 'Authorization state changed');
secExpect($metaDecision === [], 'Invalidated session received a new metadata grant.');
echo "PASS A02 metadata session invalidation before grant claim (real witness)\n";

// Race 2: old pending advance lands after recovery read but before acquire CAS.
$captured='';$hold=false;
[$base,$baseClient,$dir2,$settings2,$runtime2]=realFixture();
$delayClient=new SecretsBackendAnchorClient($settings2,static function($wire)use($dir2,&$captured,&$hold){
    $req=json_decode($wire,true)['request'];if($hold&&$req['operation']==='advance'){$captured=$wire;throw new RuntimeException('Audit delayed advance');}return realBridge([$dir2.'/anchor'],$wire);
});
$writer=new SecretsBackendStore($dir2.'/data',$dir2.'/keys',$runtime2,$delayClient,'DELETE');$hold=true;
secReject(static fn()=>$writer->change($writer->head(),SecretsBackendCodec::uuid(),hash('sha256','delayed'),static fn($s)=>$s),'Delay not injected');
$deliver=true;
$recoveryClient=new SecretsBackendAnchorClient($settings2,static function($wire)use($dir2,&$deliver,&$captured){
    $req=json_decode($wire,true)['request'];if($deliver&&$req['operation']==='acquire'){$deliver=false;realBridge([$dir2.'/anchor'],$captured);}return realBridge([$dir2.'/anchor'],$wire);
});
$recovery=new SecretsBackendStore($dir2.'/data',$dir2.'/keys',SecretsBackendCodec::b64(random_bytes(32)),$recoveryClient,'DELETE');
secRejectReason(static fn()=>$recovery->recover(), 'Acquisition definitively rejected');
$recovery->recover();
secExpect($recovery->read()['head']['index']==='1', 'Recoverable winning delayed advance did not recover.');
echo "PASS A03 definitively rejected acquisition rechecks recoverable new head (real witness)\n";

// A previously irrevocably authorized exact response may finish after a later revocation.
[$allowed,$allowedClient,$dir3,$settings3,$runtime3]=realFixture();
$validated=$allowed->read();$revokedAfterGrant=false;
$clientAfterGrant=new SecretsBackendAnchorClient($settings3,static function($wire)use($dir3,$allowed,&$revokedAfterGrant){
 $result=realBridge([$dir3.'/anchor'],$wire);$req=json_decode($wire,true)['request'];
 if($req['operation']==='authorize'){$allowed->change($allowed->head(),SecretsBackendCodec::uuid(),hash('sha256','after-grant'),static function($s){$s['identity']['revocation']=SecretsBackendCodec::increment($s['identity']['revocation']);return $s;});$revokedAfterGrant=true;}
 return $result;
});
$authorizedStore=new SecretsBackendStore($dir3.'/data',$dir3.'/keys',$runtime3,$clientAfterGrant,'DELETE');
$grant=$authorizedStore->authorize('metadata',hash('sha256','exact-old-snapshot'),$validated,static function($s):void{});
secExpect($revokedAfterGrant&&$grant['result']['status']==='AUTHORIZED'&&$grant['result']['head']['index']===$validated['head']['index'], 'Already authorized exact snapshot could not finish.');
echo "PASS A02 already authorized exact snapshot may finish after a later revocation\n";

// Login also must not adopt a newer permission state after its counter commit.
[$loginBase,$loginClient,$loginDir,$loginSettings,$loginRuntime]=realFixture();
$loginApp=appFor($loginBase);$emptyRequest=['origin'=>'https://secrets.example.test','cookie'=>'','csrf'=>'','remote'=>'login-race'];
$loginKey=enrollAudit($loginApp,$emptyRequest);enrollAudit($loginApp,$emptyRequest);
$o=secOptions($loginApp->handle('authOptions',[],$emptyRequest));
$loginWorker=new SecretsBackendStore($loginDir.'/data',$loginDir.'/keys',$loginRuntime,$loginClient,'DELETE');
$loginDb=new AuditPDO('sqlite:'.$loginDir.'/data/vault.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);
$loginDb->exec('PRAGMA synchronous=FULL');$loginDb->exec('PRAGMA busy_timeout=2000');
$expectedLoginIndex=SecretsBackendCodec::increment($loginBase->head()['index']);$loginRevoked=false;
$loginDb->afterCommit=static function($db)use($loginBase,$loginKey,$expectedLoginIndex,&$loginRevoked){
 if($db->query("SELECT value FROM metadata WHERE name='pending'")->fetchColumn()!==''||$loginBase->head()['index']!==$expectedLoginIndex)return;
 $db->afterCommit=null;$loginBase->change($loginBase->head(),SecretsBackendCodec::uuid(),hash('sha256','revoke-before-login-grant'),static function($s)use($loginKey){$s['identity']['credentials'][$loginKey['id']]['active']=false;$s['identity']['revocation']=SecretsBackendCodec::increment($s['identity']['revocation']);return $s;});$loginRevoked=true;
};
$property->setValue($loginWorker,$loginDb);
secRejectReason(static fn()=>appFor($loginWorker)->handle('authVerify',['challengeId'=>$o['challengeId'],'credential'=>secAssertion($loginKey,$o['options']['challenge'],1)],$emptyRequest),'Login state changed before authorization');
secExpect($loginRevoked,'Login race was not scheduled.');
echo "PASS A02 login revocation between counter publication and session authorization (real witness)\n";
