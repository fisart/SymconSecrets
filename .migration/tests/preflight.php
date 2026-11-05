<?php
declare(strict_types=1);
// Separate PHP process per scenario so the public wrapper surface matches Symcon.
if(($argv[1]??'')==='fixture'){
    $scenario=$argv[2];$reads=0;
    function IPS_GetInstanceListByModuleID(string $id):array{global $scenario;return str_contains($id,'7C5A3841')?[49800,59597]:($scenario==='ambiguous'?[18262,18263]:[18262]);}
    function IPS_GetInstance(int $id):array{return ['InstanceStatus'=>102];}
    function IPS_HasChanges(int $id):bool{return false;}
    function IPS_GetObjectIDByIdent(string $ident,int $id):int{return $id;}
    function GetValueString(int $id):string{global $scenario;static $n=[];$n[$id]=($n[$id]??0)+1;return 'old-cipher-'.($scenario==='old-change'?$n[$id]:1);}
    function SECB_GetNativeInfo(int $id):string{global $scenario,$reads;return json_encode(['initialized'=>true,'ready'=>true,'vaultId'=>'native','head'=>['seq'=>$scenario==='native-change'?++$reads:1]]);}
    function SECB_GetLegacyAPIStatus(int $id):string{return '{"readAllowed":true}';}
    function SEC_GetKeys(int $id):string{global $scenario;return $scenario==='empty'?'[]':'["Application"]';}
    function SECB_GetKeys(int $id):string{return '["Application"]';}
    function SEC_GetSecret(int $id,string $key):string{global $scenario;if($scenario==='warning'){trigger_error('SECRET-CANARY hidden warning',E_USER_WARNING);return ''; }return $key==='__LOCAL__'?'{}':'{"Password":"SECRET-CANARY","List":[1,2]}';}
    function SECB_GetSecret(int $id,string $key):string{global $scenario;if($scenario==='warning')return '';return $key==='__LOCAL__'?'{}':($scenario==='mismatch'?'{}':'{"Password":"SECRET-CANARY","List":[1,2],"Added":"native-extra"}');}
    if($scenario==='replaced'){function SEC_GetReplacementInfo(int $id):string{return '{}';}}
    require __DIR__.'/../Preflight_Native_Replacement.php';exit;
}
$checks=0;foreach(['match','mismatch','empty','warning','old-change','native-change','ambiguous','replaced']as$scenario){
    $pipes=[];$process=proc_open([PHP_BINARY,__FILE__,'fixture',$scenario],[1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($process))throw new RuntimeException('Fixture process failed.');
    $out=stream_get_contents($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$code=proc_close($process);
    if($code!==0||$err!==''||str_contains($out,'SECRET-CANARY')||str_contains($out,'old-cipher'))throw new RuntimeException('Preflight fixture failed or disclosed material: '.$scenario);
    $report=json_decode($out,true,32,JSON_THROW_ON_ERROR);if(($report['dataVerified']??false)!==($scenario==='match')||$report['readyForBranchSwitch']!==false)throw new RuntimeException('Preflight accepted an incomplete baseline: '.$scenario);
    if($scenario==='match'&&(count($report['checks'])!==2||!$report['checks'][1]['pass']))throw new RuntimeException('Every old instance must be checked.');++$checks;
}
echo 'PASS '.$checks.' preflight scenarios: every instance, native supersets, differences, empty/unreadable/warning baselines, changed old/native state, ambiguity and already-replaced detection; no secret output'.PHP_EOL;
