<?php
declare(strict_types=1);
require_once __DIR__.'/Fixture.php';
require_once __DIR__.'/../NativeOperations.php';
$roots=[];$stores=[];$peers=[];$routes=[];$inReceiver=false;$loads=[];
$transport=static function($target,$bytes,$policy)use(&$routes,&$inReceiver,&$loads):string{
    secExpect(!$inReceiver,'A status receiver performed outbound I/O while holding its snapshot.');
    $inReceiver=true;$before=$GLOBALS['loadProbe']??0;$writes=$GLOBALS['saveProbe']??0;
    try{return $routes[$target['endpoint']]->receive($bytes);}
    finally{$loads[]=['kind'=>json_decode($bytes,true)['kind'],'loads'=>($GLOBALS['loadProbe']??0)-$before,'writes'=>($GLOBALS['saveProbe']??0)-$writes];$inReceiver=false;}
};
try{
    for($i=0;$i<4;$i++){
        $root=sys_get_temp_dir().'/sec-status-load-'.bin2hex(random_bytes(6));$roots[]=$root;
        $binding=['origin'=>'https://load-'.$i.'.example.test','frontend'=>100+$i,'backend'=>9000+$i,'privateACLConfirmed'=>true];$id=SecretsBackendCodec::uuid();
        SecretsBackendNativeStore::initialize($root.'/data',$root.'/keys',$binding,[],$id,secGenesis($binding,$id));
        $store=new SecretsBackendNativeStore($root.'/data',$root.'/keys','status-load-'.$i);$store->recover();$stores[]=$store;
        $peer=new SecretsBackendNativePeer($store,$binding['origin'].'/hook/secrets_peer_'.(9000+$i),$transport);$peers[]=$peer;$routes[$peer->descriptor()['endpoint']]=$peer;
    }
    $token=SecretsBackendCodec::b64(random_bytes(32));$plan=['format'=>SecretsBackendAutomaticSetup::AUTOMATIC_FORMAT,'id'=>SecretsBackendCodec::uuid(),'coordinator'=>$peers[0]->descriptor()['vaultId'],'purpose'=>'pair-routes-emergency-v1','members'=>[],'credentialHash'=>hash('sha256',$token)];
    foreach($peers as$i=>$peer)$plan['members'][]=['descriptor'=>$peer->descriptor(),'routes'=>[$peer->descriptor()['endpoint']],'frontend'=>100+$i];
    $plan['signature']=$stores[0]->sign('SECB.SETUP.POLICY.1:'.SecretsBackendNativeStore::canonical($plan));
    foreach($stores as$i=>$store){$worker=$peers[$i]->automaticSetup();$c=$store->read();$store->change($c['head'],SecretsBackendCodec::uuid(),hash('sha256','fixture-'.$i),function($s)use($worker,$plan,$token,$peers,$i){
        $s=$worker->enroll($s,$plan,$token,array_key_first($s['identity']['credentials']));
        $ensure=new ReflectionMethod($worker,'ensurePair');foreach($peers as$j=>$peer)if($i!==$j)$s=$ensure->invoke($worker,$s,$peer->descriptor()['vaultId']);
        $s['outbox']['jobs']=[];return $s;
    });}
    $initialHeads=array_map(static fn($s)=>$s->head(),$stores);
    $target=['descriptor'=>$peers[1]->descriptor(),'pairingId'=>$plan['id'],'epoch'=>'1'];
    $hello=$peers[0]->exchange($target,'SETUP_HELLO',['format'=>SecretsBackendAutomaticSetup::FORMAT],SecretsBackendCodec::uuid());
    secExpect($hello['authorized']&&count($hello['details']['links'])===3,'Status reply omitted authenticated authorization or full-mesh details.');
    $target=$stores[0]->read()['state']['pairing']['peers'][$peers[1]->descriptor()['vaultId']];
    foreach(['SETUP_INFO'=>SecretsBackendAutomaticSetup::FORMAT,'HEALTH'=>SecretsBackendNativeHealth::FORMAT,'MESH_STATUS'=>SecretsBackendMeshStatus::MAILBOX]as$kind=>$format){
        $reply=$peers[0]->exchange($target,$kind,['format'=>$format],SecretsBackendCodec::uuid());secExpect($reply['status']===($kind==='HEALTH'?'GLOBAL_HEALTH':$kind),'Incorrect status response.');
    }
    secExpect($initialHeads===array_map(static fn($s)=>$s->head(),$stores),'Status reads changed administrative state.');
    // The optimization must not cache approval across requests or accept forged envelopes.
    $receiver=$peers[1];$envelope=new ReflectionMethod($peers[0],'envelope');
    $wire=$envelope->invoke($peers[0],$receiver->descriptor(),'SETUP_HELLO',$plan['id'],'1',SecretsBackendCodec::uuid(),'0',['format'=>SecretsBackendAutomaticSetup::FORMAT]);
    $bad=$wire;$bad['id']=SecretsBackendCodec::uuid();secReject(fn()=>$receiver->receive(json_encode($bad)),'Forged signature accepted by snapshot receiver.');
    $rateKey='rate:'.hash('sha256','automatic-setup:'.$peers[0]->descriptor()['vaultId'].':'.intdiv(time(),60));
    $beforeRate=$stores[1]->get($rateKey,'rate')['count'];
    $invalid=$envelope->invoke($peers[0],$receiver->descriptor(),'SETUP_HELLO',$plan['id'],'1',SecretsBackendCodec::uuid(),'0',['format'=>'unsupported']);
    secReject(fn()=>$receiver->receive(json_encode($invalid)),'Invalid signed purpose accepted.');
    secExpect($stores[1]->get($rateKey,'rate')['count']===$beforeRate+1,'Rejected signed requests bypassed the rate limit.');
    $c=$stores[1]->read();$stores[1]->change($c['head'],SecretsBackendCodec::uuid(),hash('sha256','suspend'),static function($s){$s['native']['automaticSetup']['enabled']=false;return $s;});
    $target=['descriptor'=>$receiver->descriptor(),'pairingId'=>$plan['id'],'epoch'=>'1'];$reply=$peers[0]->exchange($target,'SETUP_HELLO',['format'=>SecretsBackendAutomaticSetup::FORMAT],SecretsBackendCodec::uuid());
    secExpect(!$reply['authorized']&&!isset($reply['token']),'Status reused authority from an older snapshot.');
    echo json_encode(['requests'=>$loads]).PHP_EOL;
}finally{
    $remove=static function($p)use(&$remove){if(is_dir($p)&&!is_link($p)){foreach(scandir($p)as$n)if($n!=='.'&&$n!=='..')$remove($p.'/'.$n);rmdir($p);}elseif(file_exists($p)||is_link($p))unlink($p);};
    foreach($roots as$root)$remove($root);
}
