<?php
declare(strict_types=1);
require_once __DIR__.'/Fixture.php';
require_once __DIR__.'/../NativeOperations.php';
// Each fixture's local Connect core provides its own route; no browser enrollment.
$GLOBALS['fixtureNode']=0;
function IPS_GetInstanceListByModuleID(string $module):array {return [2000+$GLOBALS['fixtureNode']];}
function IPS_GetInstance(int $id):array {return ['InstanceStatus'=>102];}
function CC_GetConnectURL(int $id):string {return 'https://'.str_repeat(dechex($id-2000+1),32).'.ipmagic.de';}
$roots=[];$stores=[];$peers=[];$ops=[];$routes=[];$workers=[];$now=time();$attempts=0;$mutating=[];$failDiscovery=false;$failedRoutes=[];
$clock=static function()use(&$now):int{return $now;};
$transport=static function($d,$bytes,$policy)use(&$routes,&$attempts,&$mutating,&$failDiscovery,&$failedRoutes){$attempts++;if(in_array($d['endpoint'],$failedRoutes,true))throw new SecretsBackendNativePeerDeliveryFailure('timeout');$m=json_decode($bytes,true);if($failDiscovery&&$m['kind']==='SETUP_INFO'){$failDiscovery=false;throw new SecretsBackendNativePeerDeliveryFailure('timeout');}$mutating[]=$m['kind'];if(!isset($routes[$d['endpoint']]))throw new SecretsBackendNativePeerDeliveryFailure('connect');try{return $routes[$d['endpoint']]->receive($bytes);}catch(Throwable $e){fwrite(STDERR,$m['kind'].': '.$e->getMessage()."\n");throw $e;}};
$commit=static function(int $i,callable $fn)use(&$stores){$s=$stores[$i];$c=$s->read();$s->change($c['head'],SecretsBackendCodec::uuid(),hash('sha256',random_bytes(16)),$fn);};
$operation=static function(int $i,array $raw)use(&$stores,&$ops,$commit){$s=$stores[$i]->read()['state'];$op=$ops[$i]->normalize($raw,$s,false);$commit($i,fn($v)=>$ops[$i]->apply($op,$v));return $op;};
$pump=static function()use(&$peers,&$stores){for($j=0;$j<12;$j++){foreach($peers as$p)$p->dispatch(1,null,true);$pending=0;foreach($stores as$s){$v=$s->read()['state'];$pending+=count($v['outbox']['jobs']);foreach($v['pairing']['peers']as$p)if($p['active']&&($p['routeReceipt']??null)!==($v['native']['routeRevision']??'0'))$pending++;}if(!$pending)return;}};
try{
 for($i=0;$i<4;$i++){
  $root=sys_get_temp_dir().'/sec-auto-'.bin2hex(random_bytes(6));$roots[]=$root;$binding=['origin'=>'https://setup-'.$i.'.example.test','frontend'=>100+$i,'backend'=>9000+$i,'privateACLConfirmed'=>true];$id=SecretsBackendCodec::uuid();SecretsBackendNativeStore::initialize($root.'/data',$root.'/keys',$binding,[],$id,secGenesis($binding,$id));$s=new SecretsBackendNativeStore($root.'/data',$root.'/keys','runtime-'.$i);$s->recover();
  $p=new SecretsBackendNativePeer($s,$binding['origin'].'/hook/secrets_peer_'.(9000+$i),$transport,true,null,$clock);$stores[]=$s;$peers[]=$p;$ops[]=new SecretsBackendNativeOperations($s,$p);$workers[]=$p->automaticSetup();$routes[$p->descriptor()['endpoint']]=$p;$routes['https://'.str_repeat(dechex($i+1),32).'.ipmagic.de/hook/secrets_peer_'.(9000+$i)]=$p;
 }
 foreach([[0,1],[0,2],[1,3]]as[$a,$b]){$invite=$operation($a,['kind'=>'nativeInvite'])['invitation'];$operation($b,['kind'=>'nativePair','invitation'=>SecretsBackendNativePeer::invitationText($invite),'name'=>'Server '.$a]);$peers[$b]->dispatch(1);$operation($a,['kind'=>'nativeAcceptPair','peerId'=>$peers[$b]->descriptor()['vaultId']]);$pump();}
 // Three edges connect all four; no automatic authority has been granted.
 for($i=0;$i<4;$i++)secExpect($workers[$i]->tick()['status']==='SETUP_IDLE','Unapproved worker ran.');
 $before=$attempts;$preview=$workers[0]->preview('test-session');secExpect(!$preview['complete']&&$attempts===$before,'Browser discovery blocked on network work.');
 $failDiscovery=true;$workers[0]->tick();$preview=$workers[0]->preview('test-session');secExpect(!$preview['complete']&&$preview['waiting'][0]['reason']==='timeout'&&str_contains($preview['waiting'][0]['message'],'retried automatically'),'Timeout lost detailed progress or falsely required a software update.');
 $workers[0]->tick();$progress=$workers[0]->preview('test-session');secExpect($progress['checked']===1,'An unavailable server blocked discovery of another server.');$now+=95;
 $preview=null;for($i=0;$i<12;$i++){$before=$attempts;$preview=$workers[0]->preview('test-session');secExpect($attempts===$before,'Browser discovery attempted slow peer I/O.');if($preview['complete'])break;$workers[0]->tick();}
 $policy=$preview['policy'];secExpect(count($policy['members'])===4,'Discovery did not include the indirect fourth server.');SecretsBackendAutomaticSetup::validate($policy);
 $bad=$policy;$bad['members'][0]['descriptor']['boxKey']=SecretsBackendCodec::b64(random_bytes(32));secReject(fn()=>SecretsBackendAutomaticSetup::validate($bad),'Changed plan retained its signature.');
 // Start from one full administrator session; no remote authorize() calls.
 $credential=array_key_first($stores[0]->read()['state']['identity']['credentials']);
 $workers[0]->requestStart(['credential'=>$credential]);
 for($turn=0;$turn<15;$turn++){$now+=95;$workers[0]->tick();$pump();}
 $policy=$stores[0]->read()['state']['native']['automaticSetup']['policy'];
 secExpect($policy['format']===SecretsBackendAutomaticSetup::AUTOMATIC_FORMAT,'Single button did not select automatic setup.');
 foreach($stores as$i=>$store){$v=$store->read()['state'];secExpect(SecretsBackendAutomaticSetup::enabled($v),'Remote node was not automatically enrolled: '.$i);secExpect($i===0||$v['native']['automaticSetup']['credential']===null,'Remote enrollment required a local credential.');secExpect($v['native']['globalSetupSecret']['token']===$stores[0]->read()['state']['native']['globalSetupSecret']['token'],'Protected Global setup credential was not shared.');}
 // Replay and token tampering cannot change or restore local authority.
 $targetState=$stores[1]->read()['state'];$token=$targetState['native']['globalSetupSecret']['token'];
 secReject(fn()=>$workers[1]->enroll($targetState,$policy,SecretsBackendCodec::b64(random_bytes(32)),null,$peers[0]->descriptor()['vaultId']),'Changed Global credential was accepted.');
 $suspended=$targetState;$suspended['native']['automaticSetup']['enabled']=false;
 secExpect(!SecretsBackendAutomaticSetup::enabled($workers[1]->enroll($suspended,$policy,$token,null,$peers[0]->descriptor()['vaultId'])),'Replay re-enabled suspended setup.');
 $untrusted=$targetState;$untrusted['pairing']['peers'][$peers[0]->descriptor()['vaultId']]['active']=false;
 secReject(fn()=>$workers[1]->enroll($untrusted,$policy,$token,null,$peers[0]->descriptor()['vaultId']),'Inactive pairing could provision authority.');
 // Advance the injected protocol clock while clearing only test rate buckets.
 $statuses=[];
 for($turn=0;$turn<45;$turn++){
  if(true){$now+=95;foreach($stores as$s)foreach($peers as$p)$s->delete('rate:'.hash('sha256','automatic-setup:'.$p->descriptor()['vaultId'].':'.intdiv(time(),60)));}
  foreach($workers as$i=>$w){$GLOBALS['fixtureNode']=$i;$before=$attempts;$head=$stores[$i]->head();$r=$w->tick();if(in_array($r['status'],['SETUP_SERVER_AUTHORIZED','SETUP_APPROVAL_REQUIRED'],true))secExpect($stores[$i]->head()===$head,'Progress observation invalidated administrator approvals.');secExpect($attempts-$before<=2,'Setup stacked outbound tasks beyond one exchange/failover.');$statuses[]=$r['status'];}
  $pump();
 }
 foreach($stores as$i=>$s){$v=$s->read()['state'];secExpect(count(array_filter($v['pairing']['peers'],static fn($p)=>$p['active']))===3,'Full mesh did not form on server '.$i.'. '.json_encode(array_count_values($statuses)));secExpect(count(SecretsBackendEmergency::clients($v))===3,'Emergency clients missing on server '.$i.'. '.json_encode(array_count_values($statuses)));$pub=$workers[$i]->status($v);secExpect(!str_contains(json_encode($pub),$v['native']['automaticSetup']['master']),'Master capability leaked into public status.');}
 // Verify the automatically discovered peer-only Magic routes.
 foreach($stores as$i=>$s)secExpect(($s->read()['state']['native']['setupPeerBackupOrigin']??null)==='https://'.str_repeat(dechex($i+1),32).'.ipmagic.de','Local core Magic discovery failed.');
 for($turn=0;$turn<80;$turn++){
  if(true){$now+=95;foreach($stores as$s)foreach($peers as$p)$s->delete('rate:'.hash('sha256','automatic-setup:'.$p->descriptor()['vaultId'].':'.intdiv(time(),60)));}
  foreach($peers as$i=>$p){$GLOBALS['fixtureNode']=$i;(new SecretsBackendNativeHealth($stores[$i],$p))->tick();(new SecretsBackendMeshStatus($stores[$i],$p))->tick();$workers[$i]->tick();}$pump();
  $complete=true;foreach($stores as$store){$a=$store->read()['state']['native']['automaticSetup'];if($a['completedAt']===null||$a['requested'])$complete=false;}if($complete)break;
 }
 foreach($stores as$i=>$s){$a=$s->read()['state']['native']['automaticSetup'];secExpect($a['completedAt']!==null,'Setup did not complete without browser device steps on server '.$i);secExpect(!$a['requested'],'Setup did not stop its own work after all servers completed.');}
 foreach($stores as$s){$v=$s->read()['state'];secExpect(!isset($v['policy']['backupOrigin']),'Mesh setup changed browser backup-login policy.');}
 // An unavailable peer produces both route attempts and an unconfirmed outcome.
 $savedGeneration=$stores[0]->read()['state']['native']['automaticSetup']['generation'];$workers[0]->start();
 $failedRoutes=[$peers[1]->descriptor()['endpoint'],'https://'.str_repeat('2',32).'.ipmagic.de/hook/secrets_peer_9001'];
 for($j=0;$j<12;$j++){$now+=95;$GLOBALS['fixtureNode']=0;$workers[0]->tick();}
 $report=$workers[0]->status($stores[0]->read()['state'])['report'];$routeFailures=array_filter($report['errors'],static fn($e)=>count($e['attempts'])===2&&$e['code']==='timeout');secExpect(count($routeFailures)>0,'No detailed primary+backup timeout report was retained.');
 secExpect($stores[0]->read()['state']['native']['automaticSetup']['generation']===$savedGeneration,'Retry discarded established authority.');$failedRoutes=[];
 foreach($stores as$i=>$store){$v=$store->read()['state'];secExpect(!str_contains(json_encode($workers[$i]->diagnostics($v)),$v['native']['globalSetupSecret']['token']),'Report leaked the protected Global token.');}
 // Capabilities cannot run arbitrary actions, survive revocation, or alter Global values.
 $target=['descriptor'=>$peers[1]->descriptor(),'pairingId'=>$policy['id'],'epoch'=>'1'];$hello=$peers[0]->exchange($target,'SETUP_HELLO',['format'=>SecretsBackendAutomaticSetup::FORMAT],SecretsBackendCodec::uuid());
 $before=$stores[1]->head();
 secReject(fn()=>$peers[2]->exchange($target,'SETUP_ADVANCE',['token'=>$hello['token'],'expires'=>$hello['expires'],'run'=>SecretsBackendCodec::uuid()],SecretsBackendCodec::uuid()),'Another caller reused a setup capability.');
 secReject(fn()=>$peers[0]->exchange($target,'SETUP_ADVANCE',['token'=>$hello['token'],'expires'=>$now-1,'run'=>SecretsBackendCodec::uuid()],SecretsBackendCodec::uuid()),'Expired setup capability was accepted.');
 secExpect($stores[1]->head()===$before,'Refused setup capability changed approved state.');
 $sample=$stores[0]->read()['state'];$sample['identity']['credentials'][$sample['native']['automaticSetup']['credential']]['active']=false;secExpect(!SecretsBackendAutomaticSetup::enabled($sample),'Credential revocation retained setup authority.');
 secReject(fn()=>$peers[0]->exchange($target,'SETUP_ADVANCE',['token'=>$hello['token'],'expires'=>$hello['expires'],'run'=>SecretsBackendCodec::uuid(),'operation'=>['kind'=>'nativeEnrollment']],SecretsBackendCodec::uuid()),'Setup capability accepted an arbitrary management action.');
 $commit(1,static function($v){$v['native']['automaticSetup']['enabled']=false;return $v;});
 secReject(fn()=>$peers[0]->exchange($target,'SETUP_ADVANCE',['token'=>$hello['token'],'expires'=>$hello['expires'],'run'=>SecretsBackendCodec::uuid()],SecretsBackendCodec::uuid()),'Stopped capability still worked.');
 foreach($stores as$s){$v=$s->read()['state'];secExpect(json_encode(SecretsBackendTree::value($v['vault']['global']))==='{}','Setup wrote application Global secrets.');}
 echo "PASS automatic mesh: four encrypted servers from sparse topology, one initiating administrator, protected Global credential, deterministic full mesh, reciprocal emergency grants, automatic Magic discovery without browser keys, detailed two-route failure reporting, private capabilities and restricted/revoked commands\n";
}finally{$remove=static function($p)use(&$remove){if(is_dir($p)&&!is_link($p)){foreach(scandir($p)as$n)if($n!=='.'&&$n!=='..')$remove($p.'/'.$n);rmdir($p);}elseif(file_exists($p)||is_link($p))unlink($p);};foreach($roots as$r)if(is_dir($r))$remove($r);}
