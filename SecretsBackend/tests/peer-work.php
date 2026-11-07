<?php
declare(strict_types=1);
require_once __DIR__.'/../NativeRuntime.php';
$assert=static function(bool $ok,string $why):void{if(!$ok)throw new RuntimeException($why);};
$primary='https://slow.example/hook/secrets_peer_123';$backup='https://'.str_repeat('a',32).'.ipmagic.de/hook/secrets_peer_123';
$assert(SecretsBackendNativeLegacyHTTPS::timeout($primary)===15.0,'Primary latency allowance was not increased.');
$assert(SecretsBackendNativeLegacyHTTPS::timeout($backup)===25.0,'Magic latency allowance was not increased.');
$assert(SecretsBackendPeerWork::phpBudget(30,2.0)===23.0&&SecretsBackendPeerWork::phpBudget(60)===45.0&&SecretsBackendPeerWork::phpBudget(0)===45.0&&SecretsBackendPeerWork::phpBudget(5)===0.0,'Worker ignored PHP execution limits or reserved cleanup time.');
$now=100.0;$clock=static function()use(&$now):float{return $now;};$work=new SecretsBackendPeerWork($clock);
$assert($work->attempt($primary)===15.0,'Wrong initial allowance.');$now+=15.0;
$assert($work->attempt($backup)===25.0,'Failover lost its full Magic allowance.');$now+=25.0;
$assert($work->attempt($backup)===5.0,'Failover exceeded the remaining worker budget.');$now+=5.0;
try{$work->attempt($primary);throw new RuntimeException('Expired budget issued another request.');}catch(SecretsBackendNativePeerDeliveryFailure $e){$assert($e->problem==='timeout','Expired budget had a wrong failure.');}
// A slow phase cannot occupy all ticks; other work starts first on later ticks.
$next=0;$called=[];
for($tick=0;$tick<count(SecretsBackendPeerWork::PHASES)*2;$tick++){
 $work=new SecretsBackendPeerWork($clock);$phases=[];
 foreach(SecretsBackendPeerWork::PHASES as$name)$phases[$name]=static function()use($name,&$called,$work,$primary,&$now):array{$called[]=$name;$work->attempt($primary);$now+=15;return [['status'=>$name]];};
 $result=$work->run($next,$phases,static function(int $n)use(&$next):void{$next=$n;});
 $assert(count($result)===1,'Worker stacked multiple outbound phases.');
}
$assert($called===array_merge(SecretsBackendPeerWork::PHASES,SecretsBackendPeerWork::PHASES),'Queued delivery starved health, mesh or provider work.');
$next=0;$called=[];
foreach(SecretsBackendPeerWork::SETUP_PHASES as$unused){
 $work=new SecretsBackendPeerWork($clock);$phases=[];
 foreach(SecretsBackendPeerWork::PHASES as$name)$phases[$name]=static function()use($name,&$called,$work,$primary):array{$called[]=$name;$work->attempt($primary,true);return [];};
 $work->run($next,$phases,static function($n)use(&$next){$next=$n;},true);
}
$assert($called===SecretsBackendPeerWork::SETUP_PHASES,'Active setup did not progress frequently while preserving health, mesh and provider fairness.');
$work=new SecretsBackendPeerWork($clock);$next=0;$called=[];
$work->run(0,['delivery'=>static fn():array=>[], 'health'=>static fn():array=>[['status'=>'HEALTH_IDLE']], 'mesh'=>static function()use($work,$backup,&$called):array{$called[]='mesh';$work->attempt($backup);return [['status'=>'MESH_CHECKED']];},'providers'=>static function()use(&$called):array{$called[]='providers';return [];}],static function(int $n)use(&$next):void{$next=$n;});
$assert($called===['mesh']&&$next===3,'Idle phases delayed useful work or outbound phases stacked.');
class PeerTimingProbe {
    use SecretsBackendNativeRuntime;
    public array $buffers=[];
    public float $timeout=0.0;
    public bool $fail=false;
    public function GetBuffer(string $name):string{return $this->buffers[$name]??'';}
    public function SetBuffer(string $name,string $value):void{$this->buffers[$name]=$value;}
    protected function peerHTTPSPost(string $endpoint,string $bytes,array $policy,float $timeout):string{$this->timeout=$timeout;if($this->fail)throw new SecretsBackendNativePeerDeliveryFailure('timeout');return 'RESPONSE-CANARY';}
}
$setupNow=0.0;$setupClock=static function()use(&$setupNow):float{return $setupNow;};$setupWork=new SecretsBackendPeerWork($setupClock,90,SecretsBackendPeerWork::SETUP_BUDGET);
$assert($setupWork->attempt($primary,true)===45.0,'Setup primary allowance is not generous.');$setupNow+=45;$assert($setupWork->attempt($backup,true)===45.0,'Setup failover ignored its remaining 90-second bound.');$setupNow+=45;try{$setupWork->attempt($backup,true);throw new RuntimeException('Setup exceeded its bound.');}catch(SecretsBackendNativePeerDeliveryFailure $expected){}
$setupWork=new SecretsBackendPeerWork($setupClock,90,SecretsBackendPeerWork::SETUP_BUDGET);$assert($setupWork->attempt($backup,true)===60.0,'Setup Magic allowance is too short.');
$assert(SecretsBackendPeerWork::phpBudget(100,0,90)===90.0&&SecretsBackendPeerWork::phpBudget(30,0,90)===25.0,'Setup ignored the PHP safety reserve.');
$probe=new PeerTimingProbe();$method=new ReflectionMethod(PeerTimingProbe::class,'timedPeerHTTPS');
$target=['vaultId'=>'11111111-1111-4111-8111-111111111111','endpoint'=>$primary];
$method->invoke($probe,$target,'{"kind":"HEALTH","payload":"REQUEST-CANARY"}',['mode'=>'strict']);
$assert($probe->timeout===15.0,'Real peer adapter ignored the larger primary allowance.');
$target['endpoint']=$backup;$probe->fail=true;
try{$method->invoke($probe,$target,'{"kind":"MESH_STATUS","payload":"REQUEST-CANARY"}',['mode'=>'strict']);}catch(SecretsBackendNativePeerDeliveryFailure $expected){}
$report=json_decode($probe->GetTransportDiagnostics(),true);$assert($report['requests'][1]['route']==='backup'&&$report['requests'][1]['timeoutMs']===25000&&$report['requests'][1]['outcome']==='timeout','Route timing omitted the attempted allowance or failure.');
$assert(!str_contains(json_encode($report),'CANARY')&&!str_contains(json_encode($report),'slow.example'),'Transport timing exposed request/response bytes or arbitrary hostnames.');
$probe->fail=false;$setupWork=new SecretsBackendPeerWork(null,90,SecretsBackendPeerWork::SETUP_BUDGET);$method->invoke($probe,$target,'{"kind":"SETUP_HELLO","payload":"SETUP-TOKEN-CANARY"}',['mode'=>'strict'],$setupWork);$assert($probe->timeout===60.0,'Native transport did not apply the generous setup Magic timeout.');$timings=json_decode($probe->GetTransportDiagnostics(),true);$last=end($timings['requests']);$assert($last['timeoutMs']===60000&&$last['kind']==='SETUP_HELLO'&&!str_contains(json_encode($timings),'CANARY'),'Setup timing was clipped, misclassified or leaked credentials.');
$probe->fail=false;for($i=0;$i<70;$i++){$target['vaultId']=sprintf('%08x-1111-4111-8111-111111111111',$i);$method->invoke($probe,$target,'{"kind":"HEALTH"}',['mode'=>'strict']);}
$assert(count(json_decode($probe->GetTransportDiagnostics(),true)['requests'])===64,'Route timing storage is unbounded.');
// Malformed/refused requests retain bounded timing without the request body.
for($i=0;$i<20;$i++){try{$probe->ReceiveNativePeer(json_encode(['sender'=>'INBOUND-SECRET-CANARY','kind'=>'CANARY','payload'=>'TOKEN-CANARY']));}catch(Throwable $expected){}}
$incoming=json_decode($probe->GetTransportDiagnostics(),true);
$assert(count($incoming['incoming'])===16&&$incoming['incomingActive']===null,'Incoming diagnostics are unbounded or retain completed work as active.');
$last=end($incoming['incoming']);$assert($last['kind']==='other'&&$last['claimedPeerId']===null&&$last['outcome']==='refused'&&is_int($last['elapsedMs']),'Refused incoming request timing is missing.');
$assert(!str_contains(json_encode($incoming),'CANARY'),'Incoming timing exposed untrusted envelope contents.');
echo "PASS peer latency: 15s primary, 25s Magic, shared 45s budget, exact remaining failover allowance, fair phases, idle skip and no stacked outbound work\n";
