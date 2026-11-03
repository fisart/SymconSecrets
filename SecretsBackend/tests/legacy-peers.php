<?php
declare(strict_types=1);
require_once __DIR__.'/Fixture.php';
require_once __DIR__.'/../NativeOperations.php';
$roots=[];$stores=[];$peers=[];$ops=[];$routes=[];$apis=[];$checks=0;
$ok=static function(bool $condition,string $why)use(&$checks):void{secExpect($condition,$why);++$checks;};
$operation=static function(int $i,array $raw)use(&$stores,&$ops):void{$cur=$stores[$i]->read();$op=$ops[$i]->normalize($raw,$cur['state'],false);$stores[$i]->change($cur['head'],SecretsBackendCodec::uuid(),SecretsBackendNativePeer::digest($op),fn($s)=>$ops[$i]->apply($op,$s));};
$pump=static function()use(&$peers,&$stores):void{for($i=0;$i<40;$i++){foreach($peers as$p)$p->dispatch(1,null,true);$count=0;foreach($stores as$s)$count+=count($s->read()['state']['outbox']['jobs']);if(!$count)return;}throw new RuntimeException('Peer exchange did not settle.');};
try{
    for($i=0;$i<2;$i++){
        $root=sys_get_temp_dir().'/sec-legacy-peers-'.bin2hex(random_bytes(8));$roots[]=$root;$id=SecretsBackendCodec::uuid();$binding=['origin'=>'https://legacy.example.test','frontend'=>100+$i,'backend'=>200+$i,'privateACLConfirmed'=>true];
        SecretsBackendNativeStore::initialize($root.'/data',$root.'/keys',$binding,[],$id,secGenesis($binding,$id));$store=new SecretsBackendNativeStore($root.'/data',$root.'/keys','runtime-'.$i);$store->recover();$stores[]=$store;
        $peer=new SecretsBackendNativePeer($store,$binding['origin'].'/hook/secrets_peer_'.(200+$i),static function($target,$body)use(&$routes){return $routes[$target['endpoint']]->receive($body);});
        $peers[]=$peer;$routes[$peer->descriptor()['endpoint']]=$peer;$ops[]=new SecretsBackendNativeOperations($store,$peer);
    }
    $cur=$stores[0]->read();$invite=$ops[0]->normalize(['kind'=>'nativeInvite'],$cur['state'],false);$stores[0]->change($cur['head'],SecretsBackendCodec::uuid(),SecretsBackendNativePeer::digest($invite),fn($s)=>$ops[0]->apply($invite,$s));
    $operation(1,['kind'=>'nativePair','invitation'=>SecretsBackendNativePeer::invitationText($invite['invitation']),'name'=>'Replacement peer']);$peers[1]->dispatch(1);
    $operation(0,['kind'=>'nativeAcceptPair','peerId'=>$peers[1]->descriptor()['vaultId']]);$pump();
    for($i=0;$i<2;$i++){
        $permission=['kind'=>'nativeLegacyAccess','instance'=>49800,'mode'=>1,'enabled'=>true,'read'=>true,'write'=>true,'portal'=>false,'frozen'=>false,'bulk'=>false];$operation($i,$permission);
        $apis[]=new SecretsBackendLegacyAPI($stores[$i],49800,static function(array $p):void{});
    }
    $ok($apis[0]->SetRecordFields('Account',['Password'=>'GLOBAL-LEGACY'],'global'),'Legacy peer writer failed.');$pump();
    $ok($apis[0]->GetSecret('Account')===$apis[1]->GetSecret('Account'),'Legacy Global write did not synchronize.');
    foreach($apis as$i=>$api)$ok($api->SetRecordFields('Private',['token'=>'LOCAL-'.$i],'local'),'Local legacy writer failed.');$pump();
    foreach($apis as$i=>$api)$ok(str_contains($api->GetSecret('__LOCAL__'),'LOCAL-'.$i)&&!str_contains($api->GetSecret('__LOCAL__'),'LOCAL-'.(1-$i)),'Local secrets crossed to the peer.');
    $ok($apis[0]->SetRecordFields('Unrelated',['value'=>'AVAILABLE'],'global'),'Unrelated write failed.');$pump();
    $ok($apis[0]->SetRecordFields('Account',['Password'=>'LEFT'],'global'),'First concurrent writer failed.');$ok($apis[1]->SetRecordFields('Account',['Password'=>'RIGHT'],'global'),'Second concurrent writer failed.');$pump();
    foreach($apis as$i=>$api){secReject(static fn()=>$api->GetSecret('Account'),'Legacy reader chose a conflicted Global value.');++$checks;$ok(str_contains($api->GetSecret('Unrelated'),'AVAILABLE'),'A Global conflict blocked unrelated values.');
        $head=$stores[$i]->read()['head'];secReject(static fn()=>$api->SetRecordFields('Account',['Password'=>'OVERRIDE'],'global'),'Legacy writer silently resolved a Global conflict.');++$checks;$ok($stores[$i]->read()['head']===$head,'Rejected conflict write changed journal state.');}
    $permission['frozen']=true;$operation(0,$permission);secReject(static fn()=>$apis[0]->SetRecordFields('Private',['token'=>'blocked'],'local'),'Freeze missed local legacy writes.');++$checks;
    $permission['enabled']=false;$operation(1,$permission);secReject(static fn()=>$apis[1]->GetSecret('Unrelated'),'Revoked legacy reader retained access.');++$checks;
    echo 'PASS '.$checks." legacy peer checks: encrypted Global propagation, per-installation Local isolation, concurrent conflict refusal, unaffected records, atomic rejected writes, freeze and revocation\n";
}finally{
    $remove=static function($p)use(&$remove){if(is_dir($p)&&!is_link($p)){foreach(scandir($p)as$n)if($n!=='.'&&$n!=='..')$remove($p.'/'.$n);rmdir($p);}elseif(file_exists($p))unlink($p);};foreach($roots as$r)$remove($r);
}
