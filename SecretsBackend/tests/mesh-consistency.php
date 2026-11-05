<?php
declare(strict_types=1);
require_once __DIR__.'/Fixture.php';
require_once __DIR__.'/../NativeOperations.php';
require_once __DIR__.'/../NativeRuntime.php';
require_once __DIR__.'/../LegacyAPI.php';

/** Executable boundary test: asynchronous sharing must never advertise strict emergency freshness. */
final class MeshConsistencyMachine {
    use SecretsBackendNativeRuntime;
    public function __construct(private SecretsBackendNativeStore $fixture) {}
    private function nativeStore(): SecretsBackendNativeStore { return $this->fixture; }
    private function nativeInitialized(): bool { return true; }
    private function nativeApplication(): void {}
    private function ReadPropertyBoolean(string $name): bool { return $name === 'Enabled'; }
}
$roots=[];$stores=[];$peers=[];$ops=[];$machines=[];$routes=[];$blocked=[];$checks=0;$messages=0;
$ok=static function(bool $condition,string $message)use(&$checks):void{secExpect($condition,$message);++$checks;};
$apply=static function(int $i,array $raw)use(&$stores,&$ops):array{
    $current=$stores[$i]->read();$op=$ops[$i]->normalize($raw,$current['state'],false);
    $stores[$i]->change($current['head'],SecretsBackendCodec::uuid(),SecretsBackendNativePeer::digest($op),static fn($s)=>$ops[$i]->apply($op,$s));return $op;
};
$pump=static function()use(&$peers,&$stores,$ok):void{
    for($round=0;$round<80;++$round){foreach($peers as$p)$p->dispatch(1,null,true);$pending=0;
        foreach($stores as$s){$state=$s->read()['state'];$pending+=count($state['outbox']['jobs']);foreach($state['pairing']['peers']as$p)if($p['active']&&($p['routeReceipt']??null)!==($state['native']['routeRevision']??'0'))++$pending;}
        if(!$pending)return;
    }$ok(false,'Fully connected mesh did not converge.');
};
$node=static fn($s)=>SecretsBackendTree::at($s->read()['state']['vault']['global'],['Account','Password'])['value'];
try {
    for($i=0;$i<4;++$i){
        $root=sys_get_temp_dir().'/sec-mesh-consistency-'.bin2hex(random_bytes(8));$roots[]=$root;$vault=SecretsBackendCodec::uuid();
        $binding=['origin'=>'https://mesh.example.test','frontend'=>1100+$i,'backend'=>9100+$i,'privateACLConfirmed'=>true];
        SecretsBackendNativeStore::initialize($root.'/data',$root.'/keys',$binding,[],$vault,secGenesis($binding,$vault));
        $store=new SecretsBackendNativeStore($root.'/data',$root.'/keys','mesh-'.$i);$store->recover();$stores[]=$store;
        $peer=new SecretsBackendNativePeer($store,'https://mesh.example.test/hook/secrets_peer_'.(9100+$i),static function($target,$body,$policy)use(&$routes,&$blocked,&$messages,$vault):string{
            ++$messages;if(isset($blocked[$vault])||isset($blocked[$target['vaultId']]))throw new SecretsBackendNativePeerDeliveryFailure('connect');
            return $routes[$target['endpoint']]->receive($body);
        });$peers[]=$peer;$ops[]=new SecretsBackendNativeOperations($store,$peer);$machines[]=new MeshConsistencyMachine($store);$routes[$peer->descriptor()['endpoint']]=$peer;
    }
    $current=$stores[0]->read();$stores[0]->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','initial-mesh-value'),static function($s){
        $s['vault']['global']=SecretsBackendTree::parse('{"Account":{"Password":"OLD-MESH-CANARY"}}');
        $s['vault']['local']=SecretsBackendTree::parse('{"Private":"LOCAL-MESH-CANARY"}');
        $s['vault']['revision']=SecretsBackendCodec::increment($s['vault']['revision']);$s['stream']['globalRevision']=SecretsBackendCodec::increment($s['stream']['globalRevision']);return SecretsBackendNativePeer::queueGlobal($s);
    });
    for($a=0;$a<4;++$a)for($b=$a+1;$b<4;++$b){
        $invite=$apply($a,['kind'=>'nativeInvite']);$apply($b,['kind'=>'nativePair','invitation'=>SecretsBackendNativePeer::invitationText($invite['invitation']),'name'=>'Mesh peer']);
        $peers[$b]->dispatch(1);$apply($a,['kind'=>'nativeAcceptPair','peerId'=>$peers[$b]->descriptor()['vaultId']]);$pump();
    }
    foreach($stores as$s){$ok(count(array_filter($s->read()['state']['pairing']['peers'],static fn($p)=>$p['active']))===3,'Fixture is not a full four-vault mesh.');$ok($node($s)==='OLD-MESH-CANARY','Initial mesh did not converge.');}
    $grants=[];for($i=0;$i<4;++$i)$grants[]=$apply($i,['kind'=>'nativeMachineGrant','name'=>'Fixture application','scope'=>'global','path'=>['Account'],'write'=>$i===0]);
    $health=new SecretsBackendNativeHealth($stores[1],$peers[1]);for($i=0;$i<3;++$i)$health->tick();
    $writerId=$peers[0]->descriptor()['vaultId'];
    $ok($health->statuses($stores[1]->read()['state'])[$writerId]['synchronization']==='verified','Initial health check did not match.');
    // Isolate one writer; use the actual public machine write API, not an invented acknowledgement.
    $blocked[$writerId]=true;$beforeMessages=$messages;$before=$stores[0]->read();$operation=SecretsBackendCodec::uuid();
    $ack=json_decode($machines[0]->WriteNativeSecret($grants[0]['token'],'global','["Account","Password"]','"NEW-MESH-CANARY"',$before['state']['stream']['globalRevision'],'1',$operation),true);
    $ok(($ack['committed']??false)===true,'Asynchronous write did not acknowledge its local commit.');
    $ok($messages===$beforeMessages,'Current local write unexpectedly obtained a remote certificate.');
    $ok($node($stores[0])==='NEW-MESH-CANARY'&&count($stores[0]->read()['state']['outbox']['jobs'])===3,'Local change did not leave three undelivered publications.');
    for($i=1;$i<4;++$i)$ok($node($stores[$i])==='OLD-MESH-CANARY','Isolated writer somehow published to another replica.');
    $ok($health->statuses($stores[1]->read()['state'])[$writerId]['synchronization']==='verified','Cached comparison did not reproduce the healthy-looking stale window.');
    // Reachable majority: fresh signed queries to three vaults agree on the OLD version.
    $majority=[SecretsBackendNativeHealth::stamp($stores[1]->read()['state'])['digest']];
    foreach([2,3]as$i){$p=$stores[1]->read()['state']['pairing']['peers'][$peers[$i]->descriptor()['vaultId']];$reply=$peers[1]->exchange($p,'HEALTH',['format'=>SecretsBackendNativeHealth::FORMAT],SecretsBackendCodec::uuid());$majority[]=$reply['digest'];}
    $ok(count(array_unique($majority))===1,'Reachable majority did not agree on its old state.');
    $ok($majority[0]!==SecretsBackendNativeHealth::stamp($stores[0]->read()['state'])['digest'],'Majority incorrectly included the unavailable new write.');
    $read=json_decode($machines[1]->ReadNativeSecret($grants[1]['token'],'global','["Account","Password"]'),true);
    $ok($read['value']==='OLD-MESH-CANARY','Existing machine API did not exhibit its local snapshot semantics.');
    $legacy=new SecretsBackendLegacyAPI($stores[1],9101,static function(array $permission):void{},9101);
    $ok(str_contains($legacy->GetSecret('Account'),'OLD-MESH-CANARY'),'Existing compatibility API did not exhibit its local snapshot semantics.');
    $g=SecretsBackendNativeHealth::guarantees();
    $ok(!$g['quorumCommit']&&!$g['linearizableRead']&&!$g['strictEmergencyReadSupported'],'Asynchronous mesh advertised a strict emergency guarantee.');
    echo "PASS four-vault partition: local write acknowledged; reachable majority and application reads can retain old value; cached health does not authorize emergency reads\n";
    // An authenticated response can also be outdated by the time it reaches its caller.
    unset($blocked[$writerId]);$pump();foreach($stores as$s)$ok($node($s)==='NEW-MESH-CANARY','Causal repair did not converge after reconnect.');
    $transport=(new ReflectionProperty($peers[1],'transport'))->getValue($peers[1]);$updated=false;
    $racingPeer=new SecretsBackendNativePeer($stores[1],$peers[1]->descriptor()['endpoint'],static function($target,$body,$policy)use($transport,&$updated,$stores,$machines,$grants,$writerId):string{
        $reply=$transport($target,$body,$policy);
        if($target['vaultId']===$writerId&&!$updated){$updated=true;$state=$stores[0]->read()['state'];$machines[0]->WriteNativeSecret($grants[0]['token'],'global','["Account","Password"]','"RACING-MESH-CANARY"',$state['stream']['globalRevision'],'2',SecretsBackendCodec::uuid());}
        return $reply;
    });
    $p=$stores[1]->read()['state']['pairing']['peers'][$writerId];$reply=$racingPeer->exchange($p,'HEALTH',['format'=>SecretsBackendNativeHealth::FORMAT],SecretsBackendCodec::uuid());
    $ok($updated&&$reply['digest']===SecretsBackendNativeHealth::stamp($stores[1]->read()['state'])['digest'],'Response race did not retain the matching pre-change observation.');
    $ok($reply['digest']!==SecretsBackendNativeHealth::stamp($stores[0]->read()['state'])['digest'],'Signed health response incorrectly proved current state after concurrent write.');
    echo "PASS signed-health race: the peer can change after forming its matching response; response authentication is not a linearizable read barrier\n";
    $pump();foreach($stores as$s)$ok($node($s)==='RACING-MESH-CANARY','Race fixture did not converge.');
    $ok(!str_contains(json_encode(SecretsBackendNativeHealth::guarantees()),'CANARY'),'Public consistency metadata exposed fixture data.');
    for($i=1;$i<4;++$i)$ok(!str_contains(json_encode($stores[$i]->read()['state']['vault']['local']),'LOCAL-MESH-CANARY'),'Consistency checks copied a Local secret.');
    echo "PASS $checks mesh consistency boundary checks: no production access, no network services, supplied crypto and encrypted stores\n";
} finally {
    $remove=static function($p)use(&$remove):void{if(is_dir($p)&&!is_link($p)){foreach(scandir($p)as$n)if($n!=='.'&&$n!=='..')$remove($p.'/'.$n);rmdir($p);}elseif(file_exists($p)||is_link($p))unlink($p);};
    foreach($roots as$r)if(is_dir($r))$remove($r);
}
