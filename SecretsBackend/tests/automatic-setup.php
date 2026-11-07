<?php
declare(strict_types=1);
require_once __DIR__.'/Fixture.php';
require_once __DIR__.'/../NativeOperations.php';
$roots=[];$stores=[];$peers=[];$ops=[];$routes=[];$workers=[];$now=time();$attempts=0;$mutating=[];$failDiscovery=false;
$clock=static function()use(&$now):int{return $now;};
$transport=static function($d,$bytes,$policy)use(&$routes,&$attempts,&$mutating,&$failDiscovery){$attempts++;$m=json_decode($bytes,true);if($failDiscovery&&$m['kind']==='SETUP_INFO'){$failDiscovery=false;throw new SecretsBackendNativePeerDeliveryFailure('timeout');}$mutating[]=$m['kind'];if(!isset($routes[$d['endpoint']]))throw new SecretsBackendNativePeerDeliveryFailure('connect');try{return $routes[$d['endpoint']]->receive($bytes);}catch(Throwable $e){fwrite(STDERR,$m['kind'].': '.$e->getMessage()."\n");throw $e;}};
$commit=static function(int $i,callable $fn)use(&$stores){$s=$stores[$i];$c=$s->read();$s->change($c['head'],SecretsBackendCodec::uuid(),hash('sha256',random_bytes(16)),$fn);};
$operation=static function(int $i,array $raw)use(&$stores,&$ops,$commit){$s=$stores[$i]->read()['state'];$op=$ops[$i]->normalize($raw,$s,false);$commit($i,fn($v)=>$ops[$i]->apply($op,$v));return $op;};
$pump=static function()use(&$peers,&$stores){for($j=0;$j<12;$j++){foreach($peers as$p)$p->dispatch(1,null,true);$pending=0;foreach($stores as$s){$v=$s->read()['state'];$pending+=count($v['outbox']['jobs']);foreach($v['pairing']['peers']as$p)if($p['active']&&($p['routeReceipt']??null)!==($v['native']['routeRevision']??'0'))$pending++;}if(!$pending)return;}};
try{
 for($i=0;$i<4;$i++){
  $root=sys_get_temp_dir().'/sec-auto-'.bin2hex(random_bytes(6));$roots[]=$root;$binding=['origin'=>'https://setup-'.$i.'.example.test','frontend'=>100+$i,'backend'=>9000+$i,'privateACLConfirmed'=>true];$id=SecretsBackendCodec::uuid();SecretsBackendNativeStore::initialize($root.'/data',$root.'/keys',$binding,[],$id,secGenesis($binding,$id));$s=new SecretsBackendNativeStore($root.'/data',$root.'/keys','runtime-'.$i);$s->recover();
  $p=new SecretsBackendNativePeer($s,$binding['origin'].'/hook/secrets_peer_'.(9000+$i),$transport,true,null,$clock);$stores[]=$s;$peers[]=$p;$ops[]=new SecretsBackendNativeOperations($s,$p);$workers[]=$p->automaticSetup();$routes[$p->descriptor()['endpoint']]=$p;
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
 // Local policy opt-in is a separate authority on every installation.
 $authorize=static function(int $i)use($commit,$workers,$stores,$policy){$s=$stores[$i]->read()['state'];$credential=array_key_first($s['identity']['credentials']);$commit($i,fn($v)=>$workers[$i]->authorize($v,$policy,['credential'=>$credential]));};
 $authorize(0);$pump();secExpect(!SecretsBackendAutomaticSetup::enabled($stores[3]->read()['state']),'Proposal forwarding approved a remote server.');
 $first=$workers[0]->tick();secExpect(in_array($first['status'],['SETUP_APPROVAL_REQUIRED','SETUP_RETRY_PENDING'],true),'Unapproved peer status was incorrect.');
 for($i=1;$i<4;$i++){$authorize($i);$pump();}
 // Existing duplicate grants, one of which is accepted on the receiving server.
 $g1=$operation(0,['kind'=>'nativeEmergencyGrant','peerId'=>$peers[1]->descriptor()['vaultId']])['grant'];$g2=$operation(0,['kind'=>'nativeEmergencyGrant','peerId'=>$peers[1]->descriptor()['vaultId']])['grant'];
 // Manual policy edits suspend automatic setup; explicitly reauthorize the same roster.
 secExpect(!SecretsBackendAutomaticSetup::enabled($stores[0]->read()['state']),'Manual permission edit did not suspend setup.');$authorize(0);$pump();
 // Advance the injected protocol clock while clearing only test rate buckets.
 $statuses=[];
 for($turn=0;$turn<45;$turn++){
  if(true){$now+=95;foreach($stores as$s)foreach($peers as$p)$s->delete('rate:'.hash('sha256','automatic-setup:'.$p->descriptor()['vaultId'].':'.intdiv(time(),60)));}
  foreach($workers as$i=>$w){$before=$attempts;$head=$stores[$i]->head();$r=$w->tick();if(in_array($r['status'],['SETUP_SERVER_AUTHORIZED','SETUP_APPROVAL_REQUIRED'],true))secExpect($stores[$i]->head()===$head,'Progress observation invalidated administrator approvals.');secExpect($attempts-$before<=2,'Setup stacked outbound tasks beyond one exchange/failover.');$statuses[]=$r['status'];}
  $pump();
 }
 foreach($stores as$i=>$s){$v=$s->read()['state'];secExpect(count(array_filter($v['pairing']['peers'],static fn($p)=>$p['active']))===3,'Full mesh did not form on server '.$i.'. '.json_encode(array_count_values($statuses)));secExpect(count(SecretsBackendEmergency::clients($v))===3,'Emergency clients missing on server '.$i.'. '.json_encode(array_count_values($statuses)));$pub=$workers[$i]->status($v);secExpect(!str_contains(json_encode($pub),$v['native']['automaticSetup']['master']),'Master capability leaked into public status.');}
 $v=$stores[0]->read()['state'];$active=array_filter($v['native']['emergencyGrants'],static fn($g)=>$g['source']===$peers[1]->descriptor()['vaultId']&&$g['active']);secExpect(count($active)===1,'Obsolete grants were not retired. '.json_encode(array_count_values($statuses)));
 $receiver=$stores[1]->read()['state'];$old=array_values(array_filter([$g1,$g2],static fn($g)=>!$v['native']['emergencyGrants'][$g['id']]['active']));foreach($old as$g)secReject(fn()=>SecretsBackendEmergency::importGrant($receiver,SecretsBackendEmergency::exportGrant($stores[0],$peers[0],$g)),'Retired credential could be reimported after cleanup.');
 // Device enrollment is an explicit prerequisite; the coordinator cannot create administrator keys.
 foreach($stores as$i=>$s){$v=$s->read()['state'];secExpect(($v['policy']['backupOrigin']['status']??'none')!=='active','Coordinator activated an untested Magic credential.');$origin='https://'.str_repeat(dechex($i+1),32).'.ipmagic.de';$routes[$origin.'/hook/secrets_peer_'.(9000+$i)]=$peers[$i];$commit($i,static function($v)use($origin){$generation=bin2hex(random_bytes(32));$v['policy']['backupOrigin']=['version'=>2,'status'=>'active','origin'=>$origin,'generation'=>$generation,'rights'=>SecretsBackendBackupOriginPolicy::FULL_RIGHTS];$c=reset($v['identity']['credentials']);$c['id']=SecretsBackendCodec::b64(random_bytes(24));$c['origin']=$origin;$c['originGeneration']=$generation;$c['rights']=SecretsBackendBackupOriginPolicy::FULL_RIGHTS;$c['tested']=true;$v['identity']['credentials'][$c['id']]=$c;$v['native']['routeRevision']='1';return $v;});}
 for($turn=0;$turn<36;$turn++){
  if(true){$now+=95;foreach($stores as$s)foreach($peers as$p)$s->delete('rate:'.hash('sha256','automatic-setup:'.$p->descriptor()['vaultId'].':'.intdiv(time(),60)));}
  foreach($peers as$i=>$p){(new SecretsBackendNativeHealth($stores[$i],$p,$clock))->tick();$workers[$i]->tick();}$pump();
 }
 foreach($stores as$i=>$s){$a=$s->read()['state']['native']['automaticSetup'];secExpect($a['completedAt']!==null,'Setup did not complete after explicit device steps on server '.$i);secExpect(!$a['requested'],'Setup did not stop its own work after all servers completed.');}
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
 echo "PASS automatic setup: four encrypted servers from sparse topology, independent opt-in, deterministic full mesh, reciprocal emergency grants, duplicate retirement/tombstones, private capabilities, suspended manual edits and restricted/revoked commands\n";
}finally{$remove=static function($p)use(&$remove){if(is_dir($p)&&!is_link($p)){foreach(scandir($p)as$n)if($n!=='.'&&$n!=='..')$remove($p.'/'.$n);rmdir($p);}elseif(file_exists($p)||is_link($p))unlink($p);};foreach($roots as$r)if(is_dir($r))$remove($r);}
