<?php
$magic=[];$beforePairs=[];
foreach($stores as$i=>$s){$state=$s->read()['state'];foreach($state['pairing']['peers']as$p)$beforePairs[$i][$p['id']]=$p['pair'];$magic[$i]='https://'.str_repeat(chr(97+$i),32).'.ipmagic.de/hook/secrets_peer_'.(8000+$i);$routes[$magic[$i]]=$peers[$i];$cur=$s->read();$s->change($cur['head'],SecretsBackendCodec::uuid(),hash('sha256','route-fixture-'.$i),static function($state)use($magic,$i){$state['policy']['backupOrigin']=['version'=>2,'origin'=>'https://'.parse_url($magic[$i],PHP_URL_HOST),'generation'=>str_repeat((string)($i+1),64),'status'=>'active','rights'=>SecretsBackendBackupOriginPolicy::FULL_RIGHTS];$state['native']['routeRevision']='1';return $state;});}
$pump();foreach($stores as$i=>$s)foreach($s->read()['state']['pairing']['peers']as$p){$ok($p['routes']['revision']==='1'&&str_ends_with(parse_url($p['routes']['endpoints'][0],PHP_URL_HOST),'.ipmagic.de'),'Magic address was not signed and published: '.json_encode($p['routes']??null));$ok($p['pair']===$beforePairs[$i][$p['id']],'Adding an address changed the approved pair identity.');}
$blockPrimary=true;$primaryAttempts=0;$edit(0,['Magic transport'],'"GLOBAL-WITH-PRIMARY-BLOCKED"','create');$pump();$edit(1,['Magic transport'],'"EDITED-THROUGH-MAGIC"');$pump();$ok($primaryAttempts===0&&count(array_unique($models()))===1,'Synchronization contacted the blocked primary hostname.');
// Two previously unconnected peers pair through Magic with stable vault keys.
foreach([1,2]as$i){$transport=(new ReflectionProperty($peers[$i],'transport'))->getValue($peers[$i]);$ops[$i]=new SecretsBackendNativeOperations($stores[$i],new SecretsBackendNativePeer($stores[$i],$magic[$i],$transport));}
$invite=$operation(1,['kind'=>'nativeInvite']);$parsed=SecretsBackendNativePeer::readInvitation(SecretsBackendNativePeer::invitationText($invite['invitation']));$ok($parsed['issuer']['endpoint']===$magic[1],'New invitation required the primary URL.');
$operation(2,['kind'=>'nativePair','invitation'=>SecretsBackendNativePeer::invitationText($invite['invitation']),'name'=>'Magic paired']);$peers[2]->dispatch(1,null,true);$operation(1,['kind'=>'nativeAcceptPair','peerId'=>$peers[2]->descriptor()['vaultId']]);$pump();$ok($primaryAttempts===0&&count(array_unique($models()))===1,'Pairing through Magic contacted a primary hostname.');
foreach($stores as$i=>$store){$health=new SecretsBackendNativeHealth($store,$peers[$i]);$health->tick();$health->tick();foreach($health->statuses($store->read()['state'])as$h)$ok($h['synchronization']==='verified','Magic health did not verify matching shared state.');}$ok($primaryAttempts===0,'Health checking contacted the blocked primary hostname.');
$peer=$stores[0]->read()['state']['pairing']['peers'][$peers[1]->descriptor()['vaultId']];
$no(fn()=>$peers[0]->exchange($peer,'ROUTES',['revision'=>'0','endpoints'=>[$magic[0]]],SecretsBackendCodec::uuid()),'Stale route proof was accepted.');
$no(fn()=>$peers[0]->exchange($peer,'ROUTES',['revision'=>'2','endpoints'=>['https://evil.example/hook/secrets_peer_9999']],SecretsBackendCodec::uuid()),'Route changed the recipient backend.');
// Exact same sealed operation can retry through the primary after a lost Magic ACK.
$blockPrimary=false;$targetId=$peers[0]->descriptor()['vaultId'];$s=$stores[1];$pin=str_repeat('a',64);
$target=$s->read()['state']['pairing']['peers'][$targetId];
$tlsOperation=['kind'=>'nativePeerHTTPSPolicy','peerId'=>$targetId,'pairingId'=>$target['pairingId'],'endpoint'=>$target['descriptor']['endpoint'],'policy'=>['mode'=>'pinned','fingerprint'=>$pin]];
$no(fn()=>$operation(1,array_replace($tlsOperation,['policy'=>['mode'=>'pinned']])),'An unpinned bypass was accepted.');
$no(fn()=>$operation(1,array_replace($tlsOperation,['pairingId'=>SecretsBackendCodec::uuid()])),'Stale pairing was accepted for a trust change.');
$no(fn()=>$operation(1,array_replace($tlsOperation,['endpoint'=>$magic[0]])),'A primary pin was accepted for an alternative endpoint.');
$approved=$operation(1,$tlsOperation);
$ok(SecretsBackendNativeOperations::actionClass($approved['kind'])==='identity'&&$ops[1]->summary($approved)['tlsFingerprint']===$pin,'The administrator review did not bind the certificate fingerprint.');
$ok($s->read()['state']['pairing']['peers'][$targetId]===array_replace($target,['httpsPolicy'=>$tlsOperation['policy']]),'Changing the primary TLS policy changed the peer identity or routes.');
$edit(1,['Magic transport'],'"IMMUTABLE-RETRY"');$drop=$targetId;$start=count($wire);$policyStart=count($tlsPolicies);$peers[1]->dispatch(1,$targetId,true);
$attempts=array_slice($wire,$start);$policies=array_slice($tlsPolicies,$policyStart);$ok(count($attempts)===2&&$attempts[0]===$attempts[1],'Failover changed the immutable operation.');$ok($policies[0]['policy']===['mode'=>'strict']&&$policies[1]['policy']===$tlsOperation['policy'],'Primary pin was copied to the Magic hostname or lost during fallback.');$pump();
$operation(1,array_replace($tlsOperation,['policy'=>['mode'=>'strict']]));
$ok($s->read()['state']['pairing']['peers'][$targetId]['httpsPolicy']===['mode'=>'strict'],'Standard certificate verification could not be restored.');
echo "PASS Magic peer outage: signed address publication, immutable pair identity, zero-primary synchronization and new pairing, stale/wrong route refusal, lost-ACK failover and per-host TLS policy\n";
