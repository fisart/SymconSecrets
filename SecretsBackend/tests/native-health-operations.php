<?php
// Extend the converged three-platform fixture to the user's four-platform mesh.
$root=sys_get_temp_dir().'/sec-health-four-'.bin2hex(random_bytes(8));$roots[]=$root;$vault=SecretsBackendCodec::uuid();$binding=['origin'=>'https://global.example.test','frontend'=>103,'backend'=>8003,'privateACLConfirmed'=>true];
SecretsBackendNativeStore::initialize($root.'/data',$root.'/keys',$binding,[],$vault,secGenesis($binding,$vault));$s=new SecretsBackendNativeStore($root.'/data',$root.'/keys','health-fourth');$s->recover();$transport=(new ReflectionProperty($peers[0],'transport'))->getValue($peers[0]);$p=new SecretsBackendNativePeer($s,'https://global.example.test/hook/secrets_peer_8003',$transport);$stores[]=$s;$peers[]=$p;$ops[]=new SecretsBackendNativeOperations($s,$p);$routes[$p->descriptor()['endpoint']]=$p;
foreach([[0,3],[1,2],[1,3],[2,3]]as[$a,$b]){$invite=$operation($a,['kind'=>'nativeInvite']);$operation($b,['kind'=>'nativePair','invitation'=>SecretsBackendNativePeer::invitationText($invite['invitation']),'name'=>'Mesh partner']);$peers[$b]->dispatch(1);$operation($a,['kind'=>'nativeAcceptPair','peerId'=>$peers[$b]->descriptor()['vaultId']]);$pump();}
$ok(count(array_unique($models()))===1,'The four-platform full mesh did not converge.');
$now=time();$clock=static function()use(&$now):int{return $now;};$health=new SecretsBackendNativeHealth($stores[0],$peers[0],$clock);$id1=$peers[1]->descriptor()['vaultId'];$id2=$peers[2]->descriptor()['vaultId'];
$get=static fn()=> $stores[0]->read()['state'];
$probe=static function()use($health):void{$health->tick();$health->tick();$health->tick();};
$ok($health->statuses($get())[$id1]['synchronization']==='unknown','An untested connection appeared verified.');
$head=$stores[0]->head();$audits=count($get()['operations']['audit']);$beforeWire=count($wire);$probe();
foreach($health->statuses($get())as$h)$ok($h['synchronization']==='verified'&&$h['connection']==='reachable'&&$h['lastVerifiedAt']===$now,'Matching Global state was not freshly verified.');
$ok($stores[0]->head()===$head&&count($get()['operations']['audit'])===$audits,'Read-only health probes changed the reviewed head or audit retention.');
$health->tick();$ok(count($wire)===$beforeWire+3,'The worker ignored the one-minute cadence.');
// The wizard must accept real whole-history verification without obsolete ACKs.
require_once __DIR__.'/../../SecretsFrontend/MonitoringView.php';
$sharingView=static function(array $state)use($ops,$health):array{
    $n=(new ReflectionMethod(SecretsBackendNativeOperations::class,'pairingStatus'))->invoke($ops[0],$state);$statuses=$health->statuses($state);
    foreach($n['peers']as&$p){unset($p['health']);if(isset($statuses[$p['id']]))$p['health']=$statuses[$p['id']];}unset($p);
    $n['pairingSent']=[];$n['pairingReceived']=[];
    return SecretsFrontendMonitoringView::decorate($n);
};
$view=$sharingView($get());
foreach($view['peers']as$p){$sharing=$p['display']['sharing'];$ok($sharing['ready']&&$sharing['verified']&&!$sharing['sent']&&!$sharing['received'],'Current verified Global history was blocked by missing historical receipts or invented an ACK.');}
$ok($stores[0]->head()===$head,'Wizard readiness changed durable state.');

$public=json_encode($health->statuses($get()));$ok(!str_contains($public,'digest')&&!str_contains($public,'clock')&&!str_contains($public,'GLOBAL-CANARY'),'Health metadata exposed private comparison material.');
$now+=395;$h=$health->statuses($get())[$id1];$ok($h['synchronization']==='verified'&&$h['staleAfterSeconds']===900,'Normal high-latency cycle raised a stale warning.');
$now+=505;$h=$health->statuses($get())[$id1];$ok($h['synchronization']==='unknown'&&$h['problem']==='check-overdue','A stopped worker retained green beyond the generous bound.');
foreach($sharingView($get())['peers']as$p)$ok(!$p['display']['sharing']['ready'],'Expired verification left the wizard ready.');
$blockPrimary=true;for($round=0;$round<3;$round++){$probe();$now+=60;}
$h=$health->statuses($get())[$id1];$ok($h['connection']==='unreachable'&&$h['synchronization']==='unknown'&&$h['failedChecks']===3&&$h['lastVerifiedAt']!==null,'Failed checks did not expire old verification.');
$blockPrimary=false;$probe();$ok($health->statuses($get())[$id1]['synchronization']==='verified','Recovery did not clear stale reachability.');
$ok($health->statuses($get())[$id1]['staleAfterSeconds']===900,'Failures raised the learned freshness window.');
$now+=400;$probe();$h=$health->statuses($get())[$id1];$ok($h['staleAfterSeconds']===1200,'Actual successful check cadence did not update the allowance.');
$now+=1199;$ok($health->statuses($get())[$id1]['synchronization']==='verified','Learned allowance expired early.');
$now++;$ok($health->statuses($get())[$id1]['problem']==='check-overdue','Learned allowance failed to expire.');$probe();
$ok($health->statuses($get())[$id1]['staleAfterSeconds']===1200,'Late recovery inflated the learned allowance.');
// Local-only edits do not change shared fingerprints; Global edits invalidate green immediately.
$cur=$stores[0]->read();$stores[0]->change($cur['head'],SecretsBackendCodec::uuid(),hash('sha256','private-health-edit'),static function($s){SecretsBackendTree::edit($s['vault']['local'],['Health local'],SecretsBackendTree::parse('"PRIVATE-HEALTH-CANARY"'),'create');$s['vault']['revision']=SecretsBackendCodec::increment($s['vault']['revision']);return $s;});
$ok($health->statuses($get())[$id1]['synchronization']==='verified','A private Local edit invalidated Global health.');
$edit(0,['Health pending'],'"HEALTH-GLOBAL-CANARY"','create');$ok($health->statuses($get())[$id1]['synchronization']==='synchronizing','A new Global edit retained a stale verified status.');
$now+=60;$probe();$pending=count($get()['outbox']['jobs']);for($round=0;$round<3;$round++){$now+=60;$probe();}
$ok($health->statuses($get())[$id1]['synchronization']==='mismatch','A persistent mismatch was not escalated.');$ok(count($get()['outbox']['jobs'])===$pending,'Repeated checks duplicated pending repair messages.');
$pump();$now+=60;$probe();$ok($health->statuses($get())[$id1]['synchronization']==='verified','Convergence did not clear the mismatch.');
// Lose the only remote-to-local publication: read-only probing must discover it,
// then the ordinary causal protocol must return the newer remote state.
$edit(1,['Health lost remote'],'"REMOTE-HEALTH-CANARY"','create');$cur=$stores[1]->read();$stores[1]->change($cur['head'],SecretsBackendCodec::uuid(),hash('sha256','health-drop'),static function($s){$s['outbox']['jobs']=[];return $s;});
$now+=60;$probe();$ok(count($get()['outbox']['jobs'])>0,'Remote-only change did not queue causal repair.');$pump();$ok(count(array_unique($models()))===1&&str_contains(json_encode($get()['vault']['global']),'REMOTE-HEALTH-CANARY'),'Lost remote publication was not recovered automatically.');
// Equal clock plus different history is a hard mismatch: never select a winner.
$now+=60;$probe();$s1=$stores[1]->read();$originalModel=$s1['state']['native']['sharedGlobal'];$originalNode=$s1['state']['vault']['global'];
$stores[1]->change($s1['head'],SecretsBackendCodec::uuid(),hash('sha256','health-inconsistency'),static function($s){foreach($s['native']['sharedGlobal']['records']as&$record)foreach($record['versions']as&$v)if(($v['node']['type']??'')==='string'){$v['node']['value']='INCONSISTENT-HEALTH-CANARY';break 2;}unset($record,$v);$s['vault']['global']=SecretsBackendSharedGlobal::view($s['native']['sharedGlobal'])['node'];return $s;});
$before=$models()[0];$now+=60;$probe();$h=$health->statuses($get())[$id1];$ok($h['synchronization']==='mismatch'&&$h['problem']==='inconsistent-state','Same-clock history mismatch was not identified.');$ok($models()[0]===$before&&count($get()['outbox']['jobs'])===0,'Monitoring overwrote or republished inconsistent secrets.');
$cur=$stores[1]->read();$stores[1]->change($cur['head'],SecretsBackendCodec::uuid(),hash('sha256','health-restore-fixture'),static function($s)use($originalModel,$originalNode){$s['native']['sharedGlobal']=$originalModel;$s['vault']['global']=$originalNode;return $s;});$now+=60;$probe();
// Truncated history with the same causal clock must not enter through ordinary
// SYNC either, even if its transport revision was increased.
$cur=$stores[1]->read();$originalModel=$cur['state']['native']['sharedGlobal'];$originalNode=$cur['state']['vault']['global'];
$stores[1]->change($cur['head'],SecretsBackendCodec::uuid(),hash('sha256','health-truncated-history'),static function($s)use($id1){foreach($s['native']['sharedGlobal']['records']as$key=>$r)if($r['path']===['Health lost remote']){unset($s['native']['sharedGlobal']['records'][$key]);break;}$s['vault']['global']=SecretsBackendSharedGlobal::view($s['native']['sharedGlobal'])['node'];$s['stream']['globalRevision']=SecretsBackendCodec::increment($s['stream']['globalRevision']);$target=array_key_first($s['pairing']['peers']);return SecretsBackendNativePeer::queueGlobal($s,$target);});
$beforeHead=$stores[0]->head();$peers[1]->dispatch(1,null,true);$ok($stores[0]->head()===$beforeHead&&str_contains(json_encode($get()['vault']['global']),'REMOTE-HEALTH-CANARY'),'Ordinary synchronization accepted truncated same-clock history.');
$cur=$stores[1]->read();$stores[1]->change($cur['head'],SecretsBackendCodec::uuid(),hash('sha256','restore-truncated-fixture'),static function($s)use($originalModel,$originalNode){$s['native']['sharedGlobal']=$originalModel;$s['vault']['global']=$originalNode;$s['outbox']['jobs']=[];return $s;});
// Matching conflict versions are synchronized; resolving them is a separate task.
$edit(0,['Health conflict'],'"base"','create');$pump();$edit(0,['Health conflict'],'"health-left"');$edit(1,['Health conflict'],'"health-right"');$pump();$now+=60;$probe();
$h=$health->statuses($get())[$id1];$ok($h['synchronization']==='verified'&&$h['remoteConflicts']===1&&$h['problem']===null,'Conflicts were confused with synchronization failure.');
// A valid old signed response cannot answer a new check, even for the same peer.
$transport=(new ReflectionProperty($peers[0],'transport'))->getValue($peers[0]);$captured=[];$replay=false;
$proxy=new SecretsBackendNativePeer($stores[0],$peers[0]->descriptor()['endpoint'],static function($target,$body,$policy)use($transport,&$captured,&$replay){if($replay)return $captured[$target['vaultId']];return $captured[$target['vaultId']]=$transport($target,$body,$policy);});
$replayHealth=new SecretsBackendNativeHealth($stores[0],$proxy,$clock);$now+=60;$replayHealth->tick();$replayHealth->tick();$replayHealth->tick();$replay=true;$now+=60;$replayHealth->tick();$replayHealth->tick();$replayHealth->tick();
$ok($replayHealth->statuses($get())[$id1]['problem']==='invalid-reply','A replayed signed response refreshed health.');
$unsafeProxy=new SecretsBackendNativePeer($stores[0],$peers[0]->descriptor()['endpoint'],static function(){throw new SecretsBackendNativePeerDeliveryFailure('DO-NOT-EXPOSE-CANARY');});$unsafeHealth=new SecretsBackendNativeHealth($stores[0],$unsafeProxy,$clock);$now+=60;$unsafeHealth->tick();$ok(!str_contains(json_encode($unsafeHealth->statuses($get())),'DO-NOT-EXPOSE-CANARY'),'Raw transport diagnostic leaked.');
$now+=60;$probe();$ok($health->statuses($get())[$id1]['synchronization']==='verified','Fresh proof did not recover from rejected replay.');
// Signed-request replay at the receiver is read-only: no outbox/audit mutation.
$remote=$stores[1]->read();$p=$get()['pairing']['peers'][$id1];$peers[0]->exchange($p,'HEALTH',['format'=>SecretsBackendNativeHealth::FORMAT],SecretsBackendCodec::uuid());$lastRequest=$wire[count($wire)-1];$peers[1]->receive($lastRequest);$peers[1]->receive($lastRequest);$ok($stores[1]->head()===$remote['head'],'A replayed health request mutated its receiver.');$remoteHealth=(new SecretsBackendNativeHealth($stores[1],$peers[1],$clock))->statuses($stores[1]->read()['state']);foreach($remoteHealth as$h)$ok($h['synchronization']==='unknown','An inbound/replayed request established outbound liveness.');
// Revoke while a check is in flight; its reply must not resurrect status or queue work.
$revokingProxy=new SecretsBackendNativePeer($stores[0],$peers[0]->descriptor()['endpoint'],static function($target,$body,$policy)use($transport,$stores){$reply=$transport($target,$body,$policy);$cur=$stores[0]->read();$stores[0]->change($cur['head'],SecretsBackendCodec::uuid(),hash('sha256','health-revoke'),static fn($s)=>SecretsBackendNativePeer::revoke($s,$target['vaultId']));return $reply;});
$now+=60;$revokingHealth=new SecretsBackendNativeHealth($stores[0],$revokingProxy,$clock);$result=$revokingHealth->tick();$ok($result['status']==='HEALTH_CONNECTION_CHANGED','An in-flight check ignored revocation.');$ok(count($revokingHealth->statuses($get()))===2,'Revoked health was still displayed.');
$replacement=$get();$replacement['pairing']['peers'][$id1]['active']=true;$replacement['pairing']['peers'][$id1]['state']='ACTIVE';$replacement['pairing']['peers'][$id1]['pairingId']=SecretsBackendCodec::uuid();$ok($health->statuses($replacement)[$id1]['lastVerifiedAt']===null,'A replacement pairing inherited old verification.');
// Restart never resurrects cached green status.
$endpoint=$peers[0]->descriptor()['endpoint'];$savedModel=$models()[0];$stores[0]->invalidate();$stores[0]=new SecretsBackendNativeStore($roots[0].'/data',$roots[0].'/keys','health-restart');$stores[0]->recover();$peers[0]=new SecretsBackendNativePeer($stores[0],$endpoint,$transport);$routes[$endpoint]=$peers[0];$afterRestart=(new SecretsBackendNativeHealth($stores[0],$peers[0],$clock))->statuses($stores[0]->read()['state']);foreach($afterRestart as$h)$ok($h['synchronization']==='unknown'&&$h['lastVerifiedAt']===null,'Restart revived a cached health proof.');$ok($models()[0]===$savedModel,'Restart changed shared history.');
echo "PASS four-platform mesh background Global health: fresh encrypted checks, cadence/freshness, no approval-head growth, failover/recovery, causal repair, persistent/inconsistent mismatch, conflicts, replay, revocation, secret-free metadata and restart fencing\n";
