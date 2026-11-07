<?php
// Reproduce the live report after one node has already finished: successful route
// and digest checks are 350 seconds old, with no failed probes. Use wall time so
// this regression also tests the previous implementation without a clock change.
$testStore=$stores[0];$testPeer=$peers[0];$testNow=time();
$testWorker=new SecretsBackendAutomaticSetup($testStore,$testPeer);
$testState=$testStore->read()['state'];$testSetup=$testState['native']['automaticSetup'];
$savedCaches=[];
$seed=static function(string $key,string $type,array $value)use($testStore,&$savedCaches):void{
    $savedCaches[$key]=[$type,$testStore->get($key,$type)];
    $testStore->replace($key,$type,$value,time()+3600);
};
foreach($testState['pairing']['peers']as$id=>$q){
    $key='setup-contact:'.$testSetup['policy']['id'].':'.$testSetup['generation'].':'.$id;
    $c=$testStore->get($key,'setup-contact');$c['at']=$testNow-95;$c['expires']=$testNow+3000;$c['ready']=true;$c['nextAction']='check';$c['run']=$testSetup['run'];
    $seed($key,'setup-contact',$c);
    $key='peer-health:'.$q['pairingId'];$h=$testStore->get($key,'peer-health');
    $h['lastAttemptAt']=$h['lastSuccessAt']=$h['lastVerifiedAt']=$testNow-350;$h['failures']=0;$h['problem']=null;$h['synchronization']='verified';$h['localDigest']=SecretsBackendNativeHealth::stamp($testState)['digest'];
    $seed($key,'peer-health',$h);
    foreach($q['routes']['endpoints']as$url){$key='mesh:'.hash('sha256',$q['pairingId'].':'.$q['epoch'].':'.$url);$r=$testStore->get($key,'mesh-status');$r['at']=$r['lastSuccessAt']=$testNow-350;$r['state']='ok';$r['problem']=null;$r['failedChecks']=0;$seed($key,'mesh-status',$r);}
}
$testStatus=$testWorker->status($testState);$local=array_values(array_filter($testStatus['members'],static fn($m)=>$m['local']))[0];
secExpect($local['ready'],'A finished node discarded successful setup verification after only 350 seconds.');
foreach($local['details']['links']as$l)secExpect($l['primary']['state']==='ok'&&$l['backup']['state']==='ok'&&$l['synchronization']==='verified','Setup details disagree with setup readiness.');
// Routine monitoring still expires on its own cadence; setup does not authorize
// emergency reads or turn genuine failures into successful verification.
$testQ=reset($testState['pairing']['peers']);
secExpect((new SecretsBackendMeshStatus($testStore,$testPeer))->route($testState,$testQ,false)['state']==='unknown','Setup changed ordinary route monitoring.');
secExpect((new SecretsBackendNativeHealth($testStore,$testPeer))->statuses($testState)[$testQ['id']]['synchronization']==='unknown','Setup changed ordinary synchronization monitoring.');
$routeKey='mesh:'.hash('sha256',$testQ['pairingId'].':'.$testQ['epoch'].':'.$testQ['routes']['endpoints'][0]);$goodRoute=$testStore->get($routeKey,'mesh-status');
$badRoute=$goodRoute;$badRoute['state']='error';$badRoute['problem']='timeout';$badRoute['failedChecks']=1;$badRoute['at']=$testNow;
$testStore->replace($routeKey,'mesh-status',$badRoute,time()+3600);
secExpect(!(new ReflectionMethod($testWorker,'localReady'))->invoke($testWorker,$testState),'A real route failure was hidden by the longer setup window.');
$badRoute=$goodRoute;$badRoute['at']=$badRoute['lastSuccessAt']=$testNow-1800;$testStore->replace($routeKey,'mesh-status',$badRoute,time()+3600);
secExpect(!(new ReflectionMethod($testWorker,'localReady'))->invoke($testWorker,$testState),'Setup retained verification beyond its 30-minute bound.');
$testStore->replace($routeKey,'mesh-status',$goodRoute,time()+3600);
$healthKey='peer-health:'.$testQ['pairingId'];$goodHealth=$testStore->get($healthKey,'peer-health');$badHealth=$goodHealth;$badHealth['synchronization']='unknown';$badHealth['problem']='timeout';$badHealth['failures']=1;
$testStore->replace($healthKey,'peer-health',$badHealth,time()+3600);
secExpect(!(new ReflectionMethod($testWorker,'localReady'))->invoke($testWorker,$testState),'A failed synchronization check retained setup readiness.');
$testStore->replace($healthKey,'peer-health',$goodHealth,time()+3600);
// A ready run must complete before another due HELLO poll. In the old ordering
// each 30-second pass polls the next node and can starve this local decision.
$commit(0,static function($v){$v['native']['automaticSetup']['requested']=true;return $v;});
$pending=$testWorker->status($testStore->read()['state']);
secExpect($pending['running']&&$pending['completedAt']===null&&$pending['localCompletedAt']!==null,'Local completion was exposed as whole-mesh completion.');
$GLOBALS['fixtureNode']=0;$beforeAttempts=$attempts;
secExpect($testWorker->tick()['status']==='SETUP_COMPLETE','Due status polling starved a fully verified mesh completion.');
secExpect($attempts===$beforeAttempts,'Finishing a verified run unnecessarily contacted another server.');
$finished=$testWorker->status($testStore->read()['state']);
secExpect(!$finished['running']&&$finished['completedAt']!==null&&$finished['report']['state']==='complete','Finished run returned contradictory completion metadata.');
// Simulate loss of ephemeral setup history/contacts after completion (restart/expiry).
$oldReport=$testStore->get('automatic-setup-report','automatic-setup-report');
$testStore->delete('automatic-setup-report');
foreach($testState['pairing']['peers']as$id=>$q)$testStore->delete('setup-contact:'.$testSetup['policy']['id'].':'.$testSetup['generation'].':'.$id);
$withoutHistory=$testWorker->status($testStore->read()['state']);
secExpect($withoutHistory['completedAt']===$finished['completedAt']&&$withoutHistory['report']['state']==='complete'&&$withoutHistory['report']['historyAvailable']===false,'Losing the step log erased durable whole-mesh completion.');
secExpect(!$withoutHistory['members'][0]['ready'],'Historical completion manufactured current setup readiness.');
$mesh=new SecretsBackendMeshStatus($testStore,$testPeer);
$send=new ReflectionMethod($testWorker,'emergencySendStatus');
$meshKey='mesh:'.hash('sha256',$testQ['pairingId'].':'.$testQ['epoch'].':report');
$oldMesh=$testStore->get($meshKey,'mesh-status');
$meshRecord=$oldMesh;$meshRecord['at']=$testNow;
$targetLink=null;
foreach($meshRecord['report']['links']as$i=>$l)if($l['id']===$testState['native']['vaultId'])$targetLink=$i;
secExpect($targetLink!==null,'Fixture lacks the consuming peer report.');
$matching=null;foreach($testState['native']['emergencyGrants']as$g)if($g['source']===$testQ['id']&&$g['active'])$matching=$g['id'];
$meshRecord['report']['links'][$targetLink]['paired']=true;$meshRecord['report']['links'][$targetLink]['consumes']=true;$meshRecord['report']['links'][$targetLink]['clientGrant']=$matching;
$testStore->replace($meshKey,'mesh-status',$meshRecord,time()+3600);
secExpect($send->invoke($testWorker,$testState,$testQ,null,$mesh)===true,'Fresh exact mesh grant acceptance was lost with setup contacts.');
$localAfterCacheLoss=array_values(array_filter($testWorker->status($testStore->read()['state'])['members'],static fn($m)=>$m['local']))[0];
$linkAfterCacheLoss=array_values(array_filter($localAfterCacheLoss['details']['links'],static fn($l)=>$l['server']===SecretsBackendPeerName::address($testQ['descriptor']['endpoint'])))[0];
secExpect($linkAfterCacheLoss['emergencySend']===true,'Setup report did not use fresh exact mesh acceptance.');
$meshRecord['at']=$testNow-$meshRecord['report']['ttl'];$testStore->replace($meshKey,'mesh-status',$meshRecord,time()+3600);
secExpect($send->invoke($testWorker,$testState,$testQ,null,$mesh)===null,'Stale acceptance was reported as approved or revoked.');
$c=['at'=>$testNow-901,'run'=>$testSetup['run'],'clientGrant'=>$matching];
secExpect($send->invoke($testWorker,$testState,$testQ,$c,$mesh)===null,'Expired HELLO acceptance was reused.');
$c['at']=$testNow-300;
secExpect($send->invoke($testWorker,$testState,$testQ,$c,$mesh)===null,'Older setup acceptance overrode a newer expired mesh observation.');
$c['at']=$testNow-5;
secExpect($send->invoke($testWorker,$testState,$testQ,$c,$mesh)===true,'Fresh setup acceptance was ignored.');
$meshRecord['at']=$testNow;$meshRecord['report']['links'][$targetLink]['clientGrant']=SecretsBackendCodec::uuid();$testStore->replace($meshKey,'mesh-status',$meshRecord,time()+3600);
secExpect($send->invoke($testWorker,$testState,$testQ,$c,$mesh)===false,'Newer mismatched grant was hidden by older setup acceptance.');
$meshRecord['report']['links']=[];$meshRecord['report']['truncated']=true;$testStore->replace($meshKey,'mesh-status',$meshRecord,time()+3600);
secExpect($send->invoke($testWorker,$testState,$testQ,null,$mesh)===null,'Partial report invented rejection.');
$meshRecord['report']['truncated']=false;$testStore->replace($meshKey,'mesh-status',$meshRecord,time()+3600);
secExpect($send->invoke($testWorker,$testState,$testQ,null,$mesh)===false,'Complete report with no consumer was approved.');
$revoked=$testState;foreach($revoked['native']['emergencyGrants']as&$g)if($g['source']===$testQ['id'])$g['active']=false;unset($g);
secExpect($send->invoke($testWorker,$revoked,$testQ,$c,$mesh)===false,'Revoked local grants retained a displayed approval.');
$repaired=$testQ;$repaired['pairingId']=SecretsBackendCodec::uuid();
secExpect($send->invoke($testWorker,$testState,$repaired,$c,$mesh)===false,'Old grant crossed a pairing change.');
$testStore->replace($meshKey,'mesh-status',$oldMesh,time()+3600);
$testStore->put('automatic-setup-report','automatic-setup-report',$oldReport,time()+3600);
echo "PASS persistent setup result: missing log/contacts, exact grant observations, stale/partial evidence, newer rejection, revocation and pairing changes\n";
foreach($savedCaches as$key=>[$type,$value]){$testStore->delete($key);$testStore->put($key,$type,$value,time()+3600);}
echo "PASS setup completion regression: finished-node freshness, bounded verification, real failure rejection, independent monitoring, poll starvation and local/mesh completion timestamps\n";
