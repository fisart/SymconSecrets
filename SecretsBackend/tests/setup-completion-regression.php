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
foreach($savedCaches as$key=>[$type,$value])$testStore->replace($key,$type,$value,time()+3600);
echo "PASS setup completion regression: finished-node freshness, bounded verification, real failure rejection, independent monitoring, poll starvation and local/mesh completion timestamps\n";
