<?php
require_once __DIR__.'/../EmergencyClient.php';
// Extend the fixture to five fully meshed nodes; emergency authority is still bilateral.
$ordinaryTransport=(new ReflectionProperty($peers[0],'transport'))->getValue($peers[0]);
for($i=3;$i<5;++$i){
    $extra=sys_get_temp_dir().'/sec-emergency-five-'.bin2hex(random_bytes(8));$roots[]=$extra;$vid=SecretsBackendCodec::uuid();$b=['origin'=>'https://global.example.test','frontend'=>100+$i,'backend'=>8000+$i,'privateACLConfirmed'=>true];
    SecretsBackendNativeStore::initialize($extra.'/data',$extra.'/keys',$b,[],$vid,secGenesis($b,$vid));$st=new SecretsBackendNativeStore($extra.'/data',$extra.'/keys','emergency-extra-'.$i);$st->recover();
    $peer=new SecretsBackendNativePeer($st,'https://global.example.test/hook/secrets_peer_'.(8000+$i),$ordinaryTransport);$stores[]=$st;$peers[]=$peer;$ops[]=new SecretsBackendNativeOperations($st,$peer);$routes[$peer->descriptor()['endpoint']]=$peer;
    for($a=0;$a<$i;++$a){$inv=$operation($a,['kind'=>'nativeInvite']);$operation($i,['kind'=>'nativePair','invitation'=>SecretsBackendNativePeer::invitationText($inv['invitation']),'name'=>'Emergency mesh peer']);$peers[$i]->dispatch(1);$operation($a,['kind'=>'nativeAcceptPair','peerId'=>$vid]);$pump();}
}
$inv=$operation(1,['kind'=>'nativeInvite']);$operation(2,['kind'=>'nativePair','invitation'=>SecretsBackendNativePeer::invitationText($inv['invitation']),'name'=>'Mesh peer']);$peers[2]->dispatch(1);$operation(1,['kind'=>'nativeAcceptPair','peerId'=>$peers[2]->descriptor()['vaultId']]);$pump();
foreach($stores as$st)$ok(count(array_filter($st->read()['state']['pairing']['peers'],static fn($p)=>$p['active']))===4,'Fixture was not fully meshed.');
$ok(count($stores)===5&&count(array_unique($models()))===1,'Five-vault fixture did not converge.');
$source=$peers[0]->descriptor()['vaultId'];$binding=hash('sha256','fixture-binding');
$capsule=new SecretsBackendEmergencyCapsule($roots[0].'/emergency');
$remoteGrants=[];
foreach([1,2]as$i){
    $g=$operation($i,['kind'=>'nativeEmergencyGrant','peerId'=>$source]);$remoteGrants[$i]=$g['grant'];
    $package=SecretsBackendEmergency::exportGrant($stores[$i],$peers[$i],$g['grant']);
    $bad=json_decode($package,true);$bad['source']=SecretsBackendCodec::uuid();$no(fn()=>SecretsBackendEmergency::importGrant($stores[0]->read()['state'],json_encode($bad)),'Wrong source accepted emergency grant.');
    $operation(0,['kind'=>'nativeEmergencyImport','package'=>$package]);
}
$sync=static function(bool $create=false)use($stores,$capsule,$binding):bool{$s=$stores[0]->read()['state'];return $capsule->synchronize($s,$binding,SecretsBackendEmergency::clients($s),true,SecretsBackendNativeHealth::stamp($s),$create);};
$sync(true);$calls=[];$offline=[];
$transport=static function($url,$body,$policy,$timeout)use($stores,$peers,&$calls,&$offline):string{
    $calls[]=$url;foreach($peers as$i=>$p)if($p->descriptor()['endpoint']===$url){if(isset($offline[$i]))throw new SecretsBackendNativePeerDeliveryFailure('connect');return SecretsBackendEmergency::serve($stores[$i],$body);}throw new RuntimeException('Unexpected transport target.');
};
$client=static fn(array $backoff=[])=>new SecretsBackendEmergencyClient($capsule,$binding,$transport,$backoff);
$r=$client()->read('GetSecret',['Account'],$source);$ok(is_string($r['value'])&&str_contains($r['value'],'GLOBAL-CANARY'),'Emergency Global read failed.');
$ok($r['freshness']==='best-available-not-guaranteed-current','Emergency read claimed strict freshness.');
$ok(!str_contains(file_get_contents($roots[0].'/emergency/access.sealed'),'GLOBAL-CANARY')&&!str_contains(file_get_contents($roots[0].'/emergency/access.sealed'),$remoteGrants[1]['token']),'Emergency storage leaked plaintext.');
foreach([['GetSecret',['__LOCAL__']],['GetExplorerFields',['__LOCAL__/x']],['ExportLocalSecrets',[]],['SetRecordFields',['Account',[],'global']]]as[$method,$args])$no(fn()=>$client()->read($method,$args,$source),'Emergency path allowed Local or writes.');
$no(fn()=>$client()->read('GetSecret',['Account'],SecretsBackendCodec::uuid()),'Pinned source identity was ignored.');
$no(fn()=>$client()->read('GetSecret',['missing-record'],$source),'Missing remote secret became a successful fallback.');
$edit(0,['Account','User'],'"new-checkpoint-user"');$sync();
$no(fn()=>$client()->read('GetSecret',['Account'],$source),'Known older replicas were accepted.');
$peers[0]->dispatch(16,$peers[2]->descriptor()['vaultId'],true);
$r=$client()->read('GetSecret',['Account'],$source);$ok($r['source']===$peers[2]->descriptor()['vaultId']&&str_contains($r['value'],'new-checkpoint-user'),'Newer eligible peer was not selected.');
// The caller cannot open its master key, yet independent credentials still work.
rename($roots[0].'/keys/master.key',$roots[0].'/keys/master.saved');
try{
    $no(fn()=>new SecretsBackendNativeStore($roots[0].'/data',$roots[0].'/keys','unavailable'),'Missing master key unexpectedly opened local vault.');
    $r=$client()->read('GetSecret',['Account'],$source);$ok(str_contains($r['value'],'new-checkpoint-user'),'Emergency path depended on local vault keys.');
}finally{rename($roots[0].'/keys/master.saved',$roots[0].'/keys/master.key');}
$pump();$sync();
// A peer can disappear after its successful probe. Try another equally current approved peer.
$failReadOnce=true;$racingTransport=static function($url,$bytes,$policy,$timeout)use($transport,$stores,$peers,&$failReadOnce):string{
    if($url===$peers[1]->descriptor()['endpoint']){$m=json_decode($bytes,true);$q=json_decode($stores[1]->openPeer($m['payload']),true);if($q['phase']==='read'&&$failReadOnce){$failReadOnce=false;throw new SecretsBackendNativePeerDeliveryFailure('connect');}}
    return $transport($url,$bytes,$policy,$timeout);
};
$r=(new SecretsBackendEmergencyClient($capsule,$binding,$racingTransport))->read('GetSecret',['Account'],$source);$ok($r['source']===$peers[2]->descriptor()['vaultId'],'Peer failure after probe prevented eligible fallback.');
$offline[1]=true;$c=$client();$r=$c->read('GetSecret',['Account'],$source);$ok($r['source']===$peers[2]->descriptor()['vaultId'],'Unreachable peer blocked another approved peer.');
$before=count($calls);$client($c->backoff())->read('GetSecret',['Account'],$source);$ok(count($calls)===$before+2,'Circuit breaker repeatedly called the unavailable peer.');unset($offline[1]);
$overloaded=static function($url,$bytes,$policy,$timeout)use($transport,$peers):string{if($url===$peers[1]->descriptor()['endpoint'])throw new SecretsBackendNativePeerDeliveryFailure('http',503);return $transport($url,$bytes,$policy,$timeout);};
$r=(new SecretsBackendEmergencyClient($capsule,$binding,$overloaded))->read('GetSecret',['Account'],$source);$ok($r['source']===$peers[2]->descriptor()['vaultId'],'An overloaded provider blocked another approved peer.');
// A denied grant is terminal; it is never bypassed with another authority.
$operation(1,['kind'=>'nativeEmergencyRevoke','id'=>$remoteGrants[1]['id']]);$before=count($calls);
$no(fn()=>$client()->read('GetSecret',['Account'],$source),'Revocation was bypassed by another peer.');$ok(count($calls)===$before+1,'Denied access fell through to another peer.');
$operation(0,['kind'=>'nativeEmergencyRemove','peerId'=>$peers[1]->descriptor()['vaultId']]);$sync();
$r=$client()->read('GetSecret',['Account'],$source);$ok($r['source']===$peers[2]->descriptor()['vaultId'],'Two-node source/peer configuration required a quorum.');
// A forged reply and incompatible causal observations cannot release a value.
$forger=static function($url,$bytes,$policy,$timeout)use($transport):string{$r=json_decode($transport($url,$bytes,$policy,$timeout),true);$r['signature']=SecretsBackendCodec::b64(random_bytes(64));return json_encode($r);};
$no(fn()=>(new SecretsBackendEmergencyClient($capsule,$binding,$forger))->read('GetSecret',['Account'],$source),'Forged provider signature accepted.');
$isolated=new SecretsBackendEmergencyCapsule($roots[0].'/causal-test');$state=$stores[0]->read()['state'];$stamp=SecretsBackendNativeHealth::stamp($state);$isolated->synchronize($state,$binding,SecretsBackendEmergency::clients($state),true,$stamp,true);$a=$isolated->load($binding);
$left=$stamp;$right=$stamp;$left['clock'][$source]=SecretsBackendCodec::increment($stamp['clock'][$source]??'0');$right['clock'][$peers[2]->descriptor()['vaultId']]=SecretsBackendCodec::increment($stamp['clock'][$peers[2]->descriptor()['vaultId']]??'0');
$isolated->observe($binding,$a['authorization'],$left);$isolated->observe($binding,$a['authorization'],$right);$no(fn()=>$isolated->accept($binding,$a['authorization'],$left),'Incomparable observation was forgotten.');$no(fn()=>$isolated->accept($binding,$a['authorization'],$right),'Concurrent history was selected.');
$bad=$stamp;$bad['digest']=str_repeat('0',64);$same=new SecretsBackendEmergencyCapsule($roots[0].'/same-clock-test');$same->synchronize($state,$binding,SecretsBackendEmergency::clients($state),true,$stamp,true);$no(fn()=>$same->observe($binding,$same->load($binding)['authorization'],$bad),'Same-clock different content was accepted.');
// Replay/misbound and in-flight local revocation both prevent value release.
$captured=null;$proxy=static function($url,$bytes,$policy,$timeout)use($transport,&$captured):string{return $captured??= $transport($url,$bytes,$policy,$timeout);};
$badClient=new SecretsBackendEmergencyClient($capsule,$binding,$proxy);$no(fn()=>$badClient->read('GetSecret',['Account'],$source),'Probe response replayed as a read response.');
$revoker=static function($url,$bytes,$policy,$timeout)use($transport,$capsule):string{$reply=$transport($url,$bytes,$policy,$timeout);$capsule->invalidate();return $reply;};
$no(fn()=>(new SecretsBackendEmergencyClient($capsule,$binding,$revoker))->read('GetSecret',['Account'],$source),'Local revocation during transport released a value.');$sync();
$capsule->invalidate(true);$no(fn()=>$client()->read('GetSecret',['Account'],$source),'Manual emergency stop was ignored.');$sync();$no(fn()=>$client()->read('GetSecret',['Account'],$source),'Background synchronization cleared manual stop.');$sync(true);
$no(fn()=>(new SecretsBackendEmergencyClient($capsule,hash('sha256','changed'),$transport))->read('GetSecret',['Account'],$source),'Changed local configuration used saved credentials.');
// Remote advance updates the checkpoint; a recovered but behind local vault is not selected.
$edit(2,['Account','User'],'"remote-newer-user"');$r=$client()->read('GetSecret',['Account'],$source);$ok(str_contains($r['value'],'remote-newer-user'),'Remote change was not served.');
$ok(!$sync(),'Behind local vault cleared newer emergency checkpoint.');$pump();$ok($sync(),'Caught-up local vault remained fenced.');
$metadata=SecretsBackendEmergency::publicMetadata($stores[0]->read()['state']);$ok(!str_contains(json_encode($metadata),$remoteGrants[2]['token'])&&!str_contains(json_encode($metadata),'GLOBAL-CANARY'),'Emergency metadata exposed values or credentials.');
$operation(0,['kind'=>'nativeEmergencyRemove','peerId'=>$peers[2]->descriptor()['vaultId']]);$sync();$no(fn()=>$client()->read('GetSecret',['Account'],$source),'Unconfigured standalone source performed emergency reads.');
foreach([2,3,4]as$i){$g=$operation($i,['kind'=>'nativeEmergencyGrant','peerId'=>$source]);$pump();$offers=SecretsBackendEmergency::publicMetadata($stores[0]->read()['state'])['offers'];$offer=array_values(array_filter($offers,static fn($o)=>$o['peerId']===$peers[$i]->descriptor()['vaultId']))[0];$operation(0,['kind'=>'nativeEmergencyAccept','peerId'=>$offer['peerId'],'digest'=>$offer['digest']]);}
$sync(true);$r=$client()->read('GetSecret',['Account'],$source);$ok(is_string($r['value'])&&count($capsule->load($binding)['clients'])===3,'Three approved alternatives in a five-node mesh failed.');
// Conflicting Global versions are errors even though peers are reachable and approved.
$edit(0,['Account','User'],'"conflict-one"');$edit(2,['Account','User'],'"conflict-two"');$pump();
$no(fn()=>$client()->read('GetSecret',['Account'],$source),'A conflicting remote record was silently selected.');
$conflicts=SecretsBackendSharedGlobal::metadata($stores[0]->read()['state'])['conflicts'];$c=array_values(array_filter($conflicts,static fn($c)=>$c['path']===['Account','User']))[0];
$operation(0,['kind'=>'nativeGlobalResolve','path'=>$c['path'],'digest'=>$c['digest'],'choices'=>[['id'=>$c['versions'][0]['id'],'name'=>'User']]]);$pump();$sync();
// A provider capacity limit is temporary unavailability, not an authorization denial.
$g=$operation(4,['kind'=>'nativeEmergencyGrant','peerId'=>$source])['grant'];$bucket=intdiv(time(),60);
foreach([$bucket,$bucket+1]as$b)$stores[4]->put('rate:'.hash('sha256','emergency:'.$g['id'].':'.$b),'rate',['count'=>120],time()+180);
$q=['source'=>$source,'grantId'=>$g['id'],'token'=>$g['token'],'nonce'=>SecretsBackendCodec::b64(random_bytes(32)),'replyKey'=>SecretsBackendCodec::b64(sodium_crypto_box_publickey(sodium_crypto_box_keypair())),'phase'=>'probe','method'=>'GetKeys','args'=>[]];
$request=['format'=>SecretsBackendEmergency::FORMAT,'receiver'=>$peers[4]->descriptor()['vaultId'],'payload'=>SecretsBackendCodec::b64(sodium_crypto_box_seal(json_encode($q),SecretsBackendCodec::unb64($peers[4]->descriptor()['boxKey'],32)))];
$busy=false;try{SecretsBackendEmergency::serve($stores[4],json_encode($request));}catch(SecretsBackendEmergencyUnavailable $e){$busy=true;}$ok($busy,'Provider rate limit was not retryable unavailability.');
echo "PASS emergency access: independent encrypted credentials, exact peer grants, Global-only reads, causal selection, local key loss, one-peer availability, terminal denial/revocation, replay, source binding, circuit breaker and catch-up\n";
