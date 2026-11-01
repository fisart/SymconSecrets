<?php
declare(strict_types=1);
require_once __DIR__ . '/../NativeOperations.php';
require_once __DIR__ . '/../NativeRuntime.php';
final class NativePeerMachineProbe
{
    use SecretsBackendNativeRuntime;
    public function __construct(private SecretsBackendNativeStore $fixture){}
    private function nativeStore(): SecretsBackendNativeStore { return $this->fixture; }
    private function nativeInitialized(): bool { return true; }
    private function nativeApplication(): void {}
    private function ReadPropertyBoolean(string $name): bool { return $name==='Enabled'; }
}
$checks=0;$roots=[];$ok=static function(bool $v,string $why)use(&$checks):void{if(!$v)throw new RuntimeException($why);++$checks;};
$no=static function(callable $f,string $why)use(&$checks):void{try{$f();}catch(Throwable $e){++$checks;return;}throw new RuntimeException($why);};
$op=static function(SecretsBackendNativeOperations $ops,SecretsBackendNativeStore $s,array $raw):array{$current=$s->read();$normalized=$ops->normalize($raw,$current['state'],false);$s->change($current['head'],SecretsBackendCodec::uuid(),SecretsBackendNativePeer::digest($normalized),static fn($state)=>$ops->apply($normalized,$state));return $normalized;};
try{
 foreach([1,2,3,5]as$count){
    $stores=[];$peers=[];$ops=[];$routes=[];$drop=null;$wire=[];
    $transport=static function(array $target,string $body)use(&$routes,&$drop,&$wire):string{$wire[]=[$target,$body];$reply=$routes[$target['endpoint']]->receive($body);if($drop===$target['vaultId']){$drop=null;throw new RuntimeException('Lost response after receiver commit');}return $reply;};
    for($i=0;$i<$count;++$i){$root=sys_get_temp_dir().'/sec-native-peers-'.bin2hex(random_bytes(8));$roots[]=$root;$id=SecretsBackendCodec::uuid();$binding=['origin'=>'https://peers.example.test','frontend'=>100+$i,'backend'=>6000+$i,'privateACLConfirmed'=>true];SecretsBackendNativeStore::initialize($root.'/data',$root.'/keys',$binding,[],$id);$s=new SecretsBackendNativeStore($root.'/data',$root.'/keys','runtime-'.$i);$s->recover();$p=new SecretsBackendNativePeer($s,'https://peers.example.test/hook/secrets_peer_'.(6000+$i),$transport);$stores[]=$s;$peers[]=$p;$ops[]=new SecretsBackendNativeOperations($s,$p);$routes[$p->descriptor()['endpoint']]=$p;}
    $ok(count($stores)===$count,'Standalone/roster size failed.');
    for($i=1;$i<$count;++$i){$invite=$op($ops[0],$stores[0],['kind'=>'nativeInvite']);$text=SecretsBackendNativePeer::invitationText($invite['invitation']);$op($ops[$i],$stores[$i],['kind'=>'nativePair','invitation'=>$text,'name'=>'Owner']);$peers[$i]->dispatch(2);
      $remote=$peers[$i]->descriptor()['vaultId'];$ok($stores[0]->read()['state']['pairing']['peers'][$remote]['state']==='PENDING_APPROVAL','Invitation alone activated a peer.');
      $op($ops[0],$stores[0],['kind'=>'nativeAcceptPair','peerId'=>$remote]);$peers[0]->dispatch(8);$peers[$i]->dispatch(8);
      $ok($stores[$i]->read()['state']['pairing']['peers'][$peers[0]->descriptor()['vaultId']]['active'],'Bilateral approval did not activate exact pairing.');
    }
    $current=$stores[0]->read();$stores[0]->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','write-'.$count),static function($s){$s['vault']['global']=SecretsBackendTree::parse('{"Shared":"GLOBAL-CANARY"}');$s['vault']['local']=SecretsBackendTree::parse('{"Local":"LOCAL-NEVER-SHARE"}');$s['vault']['revision']='1';$s['stream']['globalRevision']='1';return SecretsBackendNativePeer::queueGlobal($s);});
    if($count>1){$drop=$peers[1]->descriptor()['vaultId'];$job=$stores[0]->read()['state']['outbox']['jobs'][0];$peers[0]->dispatch(1);$receiverHead=$stores[1]->head();$stores[0]->delete('backoff:'.$job['id']);$peers[0]->dispatch(16);$ok($stores[1]->head()===$receiverHead,'Lost receipt re-applied the received snapshot.');}
    for($i=1;$i<$count;++$i){$r=$stores[$i]->read()['state']['native']['received'][$peers[0]->descriptor()['treeId']];$json=SecretsBackendCodec::json(SecretsBackendTree::value($r['node']));$ok(str_contains($json,'GLOBAL-CANARY')&&!str_contains($json,'LOCAL-NEVER-SHARE'),'Local-only data entered peer synchronization.');
      $scope='received:'.$peers[0]->descriptor()['treeId'];$grant=$op($ops[$i],$stores[$i],['kind'=>'nativeMachineGrant','name'=>'Shared reader','scope'=>$scope,'path'=>['Shared'],'write'=>false]);$machine=new NativePeerMachineProbe($stores[$i]);
      $ok(str_contains($machine->ReadNativeSecret($grant['token'],$scope,'["Shared"]'),'GLOBAL-CANARY'),'Machine integration could not read its received shared tree.');
      $no(static fn()=>$machine->ReadNativeSecret($grant['token'],'global','["Shared"]'),'Received-tree capability crossed to a local owner tree.');
      $no(static fn()=>$op($ops[$i],$stores[$i],['kind'=>'nativeMachineGrant','name'=>'Forbidden received writer','scope'=>$scope,'path'=>['Shared'],'write'=>true]),'Received tree was granted machine write access.');
    }
    if($count===2){
      $large=json_encode(['RecordA'=>str_repeat('a',36000),'RecordB'=>str_repeat('b',36000)]);$current=$stores[0]->read();
      $stores[0]->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256',$large),static function($s)use($large){$s['vault']['global']=SecretsBackendTree::parseBounded($large,100000);$s['vault']['revision']='2';$s['stream']['globalRevision']='2';return SecretsBackendNativePeer::queueGlobal($s);});
      $peers[0]->dispatch(8);$r=$stores[1]->read()['state']['native']['received'][$peers[0]->descriptor()['treeId']];
      $ok(strlen(SecretsBackendCodec::json(SecretsBackendTree::value($r['node'])))>65536,'Aggregate shared tree was incorrectly limited to one web-request size.');
      $recoveryKey=SecretsBackendCodec::b64(random_bytes(32));$bytes=SecretsBackendNativeBackup::encrypt($stores[0],$recoveryKey);$material=SecretsBackendNativeBackup::decrypt($bytes,$recoveryKey,$stores[0]->metadata()['capacityBytes']);
      $ok($material['state']['stream']['globalRevision']==='2','Large aggregate tree backup did not verify.');
    }
    if($count>1){$peerId=$peers[1]->descriptor()['vaultId'];$op($ops[0],$stores[0],['kind'=>'nativeResync','peerId'=>$peerId]);$peers[0]->dispatch(4);$ok(count($stores[0]->read()['state']['outbox']['jobs'])===0,'Authenticated resynchronization failed.');
      if($count>=3){
        $treeId=$peers[0]->descriptor()['treeId'];$offer=$op($ops[0],$stores[0],['kind'=>'nativeTransferOffer','treeId'=>$treeId,'peerId'=>$peerId]);
        $ok(!$stores[0]->read()['state']['native']['globalWritable'],'Old owner was not frozen before transfer delivery.');$peers[0]->dispatch(8);
        $incoming=$stores[1]->read()['state']['native']['transfers'][$offer['certificate']['id']]??null;$ok(($incoming['state']??'')==='PENDING_APPROVAL','Owner offer auto-activated or was lost.');
        $op($ops[1],$stores[1],['kind'=>'nativeTransferAccept','transferId'=>$offer['certificate']['id']]);$peers[1]->dispatch(16);
        $op($ops[1],$stores[1],['kind'=>'nativeSharedSave','treeId'=>$treeId,'path'=>['Shared'],'revision'=>'1','mode'=>'replace','json'=>'"NEW-OWNER-CANARY"']);$peers[1]->dispatch(16);
        $scope='owned:'.$treeId;$grant=$op($ops[1],$stores[1],['kind'=>'nativeMachineGrant','name'=>'Owned shared writer','scope'=>$scope,'path'=>['Shared'],'write'=>true]);$machine=new NativePeerMachineProbe($stores[1]);
        $machine->WriteNativeSecret($grant['token'],$scope,'["Shared"]','"NEW-OWNER-CANARY-MACHINE"','2','1',SecretsBackendCodec::uuid());$peers[1]->dispatch(16);
        $ok(str_contains($machine->ReadNativeSecret($grant['token'],$scope,'["Shared"]'),'NEW-OWNER-CANARY-MACHINE'),'Owned-tree machine publication failed.');
        $ok(str_contains(SecretsBackendCodec::json($stores[0]->read()['state']['vault']['global']),'NEW-OWNER-CANARY'),'Old owner did not follow the authenticated new owner.');
        for($i=2;$i<$count;++$i){$copy=$stores[$i]->read()['state']['native']['received'][$treeId];$ok($copy['owner']===$peerId&&str_contains(SecretsBackendCodec::json($copy['node']),'NEW-OWNER-CANARY'),'Subscriber did not follow scoped ownership transfer.');}
        $ok(str_contains(SecretsBackendCodec::json($stores[0]->read()['state']['vault']['local']),'LOCAL-NEVER-SHARE'),'Ownership transfer changed local-only data.');
      }
      $capturedAccept=null;$capturedTree=null;
      foreach($wire as[$target,$bytes]){$m=json_decode($bytes,true);if($m['kind']==='PAIR_ACCEPT'&&$m['receiver']===$peerId)$capturedAccept=$bytes;if($m['kind']==='TREE_SYNC'&&$m['sender']===$peerId&&$target['vaultId']===$peers[0]->descriptor()['vaultId'])$capturedTree=[$target,$bytes];}
      $op($ops[0],$stores[0],['kind'=>'nativeRevokePeer','peerId'=>$peerId]);$peers[0]->dispatch(2);$ok(!$stores[1]->read()['state']['pairing']['peers'][$peers[0]->descriptor()['vaultId']]['active'],'Revocation did not reach the receiver.');
      $no(static fn()=>$peers[1]->receive($capturedAccept),'Old acceptance reactivated a revoked pairing.');
      if($capturedTree!==null){$target=$capturedTree[0];if($target['vaultId']===$peers[0]->descriptor()['vaultId'])$no(static fn()=>$peers[0]->receive($capturedTree[1]),'Transferred tree continued delivery after owner connection revocation.');}
      $sample=json_decode($capturedAccept,true);$sample['receiver']=$peers[0]->descriptor()['vaultId'];$no(static fn()=>$peers[0]->receive(json_encode($sample)),'Recipient-swapped peer message was accepted.');
      $sample=json_decode($capturedAccept,true);$sample['id']=SecretsBackendCodec::uuid();$no(static fn()=>$peers[1]->receive(json_encode($sample)),'Forged peer signature was accepted.');
    }
 }
 $no(static fn()=>SecretsBackendNativePeer::endpoint('http://untrusted.example/hook/secrets_peer_1'),'Plaintext peer endpoint accepted.');
 $no(static fn()=>SecretsBackendNativePeer::endpoint('https://a:b@x.example/hook/secrets_peer_1'),'Credential-bearing peer URL accepted.');
 echo 'PASS '.$checks." native standalone/2/3/5-vault pairing, exact bilateral approval, encrypted ordered delivery, lost-receipt idempotence, local isolation, resynchronization and revocation checks\n";
}finally{$remove=static function($p)use(&$remove){if(is_dir($p)&&!is_link($p)){foreach(scandir($p)as$n)if($n!=='.'&&$n!=='..')$remove($p.'/'.$n);rmdir($p);}elseif(file_exists($p)||is_link($p))unlink($p);};foreach($roots as$r)$remove($r);}
