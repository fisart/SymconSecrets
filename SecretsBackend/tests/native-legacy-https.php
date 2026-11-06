<?php
declare(strict_types=1);
require_once __DIR__.'/Fixture.php';
require_once __DIR__.'/../NativeOperations.php';
$GLOBALS['oldConfigs']=[];$GLOBALS['oldPending']=[];
function IPS_GetInstanceListByModuleID(string $module): array { return array_keys($GLOBALS['oldConfigs']); }
function IPS_GetConfiguration(int $id): string { return json_encode($GLOBALS['oldConfigs'][$id]); }
function IPS_HasChanges(int $id): bool { return $GLOBALS['oldPending'][$id]??false; }
function IPS_GetInstance(int $id): array { return ['InstanceStatus'=>102]; }
$checks=0;$ok=static function(bool $v,string $why)use(&$checks):void{if(!$v)throw new RuntimeException($why);++$checks;};
$no=static function(callable $f,string $why)use(&$checks):void{try{$f();}catch(Throwable $e){++$checks;return;}throw new RuntimeException($why);};
$url='https://peer.example:46901/hook/secrets_peer_123';$pin=str_repeat('a1',32);
$row=['Url'=>'https://peer.example:46901/hook/secrets_456?pass=DO-NOT-COPY','TlsMode'=>'pinned','Fingerprint'=>implode(':',str_split(strtoupper($pin),2)),'KeyTransport'=>'sync','HookPass'=>'DO-NOT-COPY'];
$config=['OperationMode'=>1,'SlaveURLs'=>json_encode([$row]),'AuthToken'=>'DO-NOT-COPY'];
$ok(SecretsBackendNativeLegacyHTTPS::proposal($url)['policy']===['mode'=>'strict'],'Default must retain strict PHP-stream TLS.');
$GLOBALS['oldConfigs'][100]=$config;$proposal=SecretsBackendNativeLegacyHTTPS::proposal($url);
$ok($proposal===['policy'=>['mode'=>'pinned','fingerprint'=>$pin],'source'=>'old manager'],'Applied old same-origin SHA256 policy was not reused.');
$ok(!str_contains(json_encode($proposal),'DO-NOT-COPY'),'Legacy credentials leaked into transport review.');
$ok(SecretsBackendNativeLegacyHTTPS::proposal(str_replace(':46901',':46902',$url))['policy']['mode']==='strict','Fingerprint crossed ports.');
$ok(SecretsBackendNativeLegacyHTTPS::proposal(str_replace('peer.example','sub.peer.example',$url))['policy']['mode']==='strict','Fingerprint crossed hostnames.');
$GLOBALS['oldPending'][100]=true;$ok(SecretsBackendNativeLegacyHTTPS::proposal($url)['policy']['mode']==='strict','Unapplied old settings were used.');$GLOBALS['oldPending']=[];
foreach([0,2]as$mode){$GLOBALS['oldConfigs'][100]['OperationMode']=$mode;$ok(SecretsBackendNativeLegacyHTTPS::proposal($url)['policy']['mode']==='strict','A receiver/standalone was treated as an outgoing sync source.');}
$GLOBALS['oldConfigs'][100]=$config;
foreach(['manual','invalid']as$mode){$GLOBALS['oldConfigs'][100]['SlaveURLs']=json_encode([array_replace($row,['KeyTransport'=>$mode])]);$ok(SecretsBackendNativeLegacyHTTPS::proposal($url)['policy']['mode']==='strict','An unused sync route was imported.');}
$GLOBALS['oldConfigs'][100]=$config;$GLOBALS['oldConfigs'][101]=array_replace($config,['SlaveURLs'=>json_encode([array_replace($row,['Fingerprint'=>str_repeat('b',64)])])]);
$no(static fn()=>SecretsBackendNativeLegacyHTTPS::proposal($url),'Conflicting old fingerprints silently selected a winner.');unset($GLOBALS['oldConfigs'][101]);
$roots=[];
try{
 $stores=[];$peers=[];$ops=[];$routes=[];$policies=[];
 $transport=static function(array $target,string $bytes,array $policy)use(&$routes,&$policies):string{$policies[]=$policy;return $routes[$target['endpoint']]->receive($bytes);};
 foreach([123,124]as$id){$root=sys_get_temp_dir().'/sec-legacy-https-'.bin2hex(random_bytes(8));$roots[]=$root;$binding=['origin'=>'https://peer.example:46901','frontend'=>$id+100,'backend'=>$id,'privateACLConfirmed'=>true];$uuid=SecretsBackendCodec::uuid();SecretsBackendNativeStore::initialize($root.'/data',$root.'/keys',$binding,[],$uuid,secGenesis($binding,$uuid));$store=new SecretsBackendNativeStore($root.'/data',$root.'/keys','https-fixture');$store->recover();$peer=new SecretsBackendNativePeer($store,'https://peer.example:46901/hook/secrets_peer_'.$id,$transport);$stores[]=$store;$peers[]=$peer;$ops[]=new SecretsBackendNativeOperations($store,$peer);$routes[$peer->descriptor()['endpoint']]=$peer;}
 $apply=static function(int $side,array $op)use(&$ops,&$stores):array{$current=$stores[$side]->read();return $stores[$side]->change($current['head'],SecretsBackendCodec::uuid(),SecretsBackendNativePeer::digest($op),static fn($s)=>$ops[$side]->apply($op,$s));};
 $invite=$ops[0]->normalize(['kind'=>'nativeInvite'],$stores[0]->read()['state'],false);$apply(0,$invite);
 $request=$ops[1]->normalize(['kind'=>'nativePair','invitation'=>SecretsBackendNativePeer::invitationText($invite['invitation']),'name'=>'Old trusted platform'],$stores[1]->read()['state'],false);
 $summary=$ops[1]->summary($request);$ok($summary['tlsMode']==='pinned'&&$summary['tlsFingerprint']===$pin&&$summary['tlsSource']==='old manager','Pairing approval did not display exact TLS policy.');
 $tampered=$request;$tampered['httpsReview']['policy']['fingerprint']=str_repeat('b',64);$no(static fn()=>$ops[1]->normalize($tampered,$stores[1]->read()['state'],true),'Reviewed pin could be changed without invalidating the approval seal.');
 $GLOBALS['oldConfigs'][100]['SlaveURLs']=json_encode([array_replace($row,['Fingerprint'=>str_repeat('b',64)])]);$head=$stores[1]->head();$no(static fn()=>$apply(1,$request),'A changed old fingerprint committed after review.');$ok($head===$stores[1]->head(),'Failed transport review mutated vault state.');
 $GLOBALS['oldConfigs'][100]=$config;$apply(1,$request);$peers[1]->dispatch(1);
 $id=$peers[1]->descriptor()['vaultId'];$accept=$ops[0]->normalize(['kind'=>'nativeAcceptPair','peerId'=>$id],$stores[0]->read()['state'],false);$ok($ops[0]->summary($accept)['tlsFingerprint']===$pin,'Other direction omitted its local pin approval.');$apply(0,$accept);
 $GLOBALS['oldConfigs']=[];$peers[0]->dispatch(8);$peers[1]->dispatch(8);
 foreach([0,1]as$side){$p=array_values($stores[$side]->read()['state']['pairing']['peers'])[0];$ok($p['active']&&$p['httpsPolicy']===['mode'=>'pinned','fingerprint'=>$pin],'Approved transport was lost after old module deletion.');$ok(SecretsBackendNativeLegacyHTTPS::proposal($p['descriptor']['endpoint'],[$p])['source']==='saved connection','Re-pair proposal cannot retain its approved local transport.');}
 // Both directions retain approved transport through an explicitly removed/replaced pair.
 foreach([0,1]as$side){$peer=array_values($stores[$side]->read()['state']['pairing']['peers'])[0];$revoke=$ops[$side]->normalize(['kind'=>'nativeRevokePeer','peerId'=>$peer['id']],$stores[$side]->read()['state'],false);$apply($side,$revoke);}
 $invite=$ops[0]->normalize(['kind'=>'nativeInvite'],$stores[0]->read()['state'],false);$apply(0,$invite);
 $request=$ops[1]->normalize(['kind'=>'nativePair','invitation'=>SecretsBackendNativePeer::invitationText($invite['invitation']),'name'=>'Saved trusted platform'],$stores[1]->read()['state'],false);$ok($request['httpsReview']['source']==='saved connection','Replacement sender lost approved pin after old-module removal.');$apply(1,$request);$peers[1]->dispatch(1);
 $accept=$ops[0]->normalize(['kind'=>'nativeAcceptPair','peerId'=>$id],$stores[0]->read()['state'],false);$ok($accept['httpsReview']['source']==='saved connection'&&$accept['httpsReview']['policy']['fingerprint']===$pin,'Incoming replacement discarded its local approved pin.');$apply(0,$accept);$peers[0]->dispatch(8);$peers[1]->dispatch(8);
 $ok(count($policies)>=3&&!array_filter($policies,static fn($p)=>$p!==['mode'=>'pinned','fingerprint'=>$pin]),'Peer delivery did not use its sealed local TLS policy.');
 echo "PASS $checks legacy HTTPS checks: same applied origin, no copied credentials, conflict/pending/unused rejection, exact approval seal, changed-settings rejection, bilateral stored policy and old-module removal\n";
}finally{$remove=static function($p)use(&$remove){if(is_dir($p)&&!is_link($p)){foreach(scandir($p)as$n)if($n!=='.'&&$n!=='..')$remove($p.'/'.$n);rmdir($p);}elseif(file_exists($p))unlink($p);};foreach($roots as$root)$remove($root);}
