<?php
declare(strict_types=1);
require_once __DIR__.'/NativeBackup.php';
require_once __DIR__.'/NativeHealth.php';
require_once __DIR__.'/MeshStatus.php';

/** Approved diagnostics: no live restore, authority changes, outbound requests or plaintext output. */
final class SecretsBackendProductionChecks
{
 public static function run(SecretsBackendNativeStore $store,SecretsBackendNativePeer $peer,array $validated):array
 {
  $checks=[];$add=static function(string $name,string $state,string $detail)use(&$checks):void{$checks[]=['name'=>$name,'state'=>$state,'detail'=>$detail];};
  $s=$validated['state'];$meta=$store->metadata();
  try{
   try{$budget=SecretsBackendNativePlatform::budget();}catch(Throwable $ignored){$budget=0;}
   if($meta['usedBytes']>$budget)$add('Backup recovery round trip','not-tested','Insufficient reserved memory for a safe in-memory test. Test a saved encrypted backup on a disposable installation.');
   else{
    $key=SecretsBackendCodec::b64(random_bytes(32));$bytes=SecretsBackendNativeBackup::encrypt($store,$key,$validated);$copy=SecretsBackendNativeBackup::decrypt($bytes,$key,$meta['capacityBytes']);
    foreach(['global','local']as$scope)if(SecretsBackendNativePeer::digest($copy['state']['vault'][$scope])!==SecretsBackendNativePeer::digest($s['vault'][$scope]))throw new RuntimeException('Mismatch');
    $recovery=SecretsBackendNativeBackup::localRecoveryNode($copy);
    if($recovery['type']!=='object'||SecretsBackendNativePeer::digest($copy['state']['identity'])!==SecretsBackendNativePeer::digest($s['identity']))throw new RuntimeException('Mismatch');
    $add('Backup recovery round trip','passed','Current state encrypted, authenticated, decrypted and prepared as an isolated in-memory recovery copy. No live values were restored; the separately saved backup has not been tested.');
    unset($key,$bytes,$copy,$recovery);
   }
  }catch(Throwable $ignored){$add('Backup recovery round trip','failed','The approved snapshot could not complete the bounded backup/recovery test. Check availability, capacity and retry with a fresh approval.');}
  $add('Storage headroom',!empty($meta['retentionWarning'])||$meta['usedBytes']>=$meta['capacityBytes']*.75?'attention':'passed','Retained operations: '.$meta['outcomes'].'. Capacity: '.$meta['usedBytes'].' of '.$meta['capacityBytes'].' bytes.');
  $health=(new SecretsBackendNativeHealth($store,$peer))->statuses($s);$mesh=new SecretsBackendMeshStatus($store,$peer);
  foreach($s['pairing']['peers']as$p){if(!($p['active']??false)||($p['state']??'')!=='ACTIVE')continue;$h=$health[$p['id']]??null;$ready=$h&&$h['synchronization']==='verified'&&$h['connection']==='reachable'&&empty($h['problem'])&&$h['pendingMessages']===0;
   $name=SecretsBackendPeerName::display($p);$add('Synchronization · '.$name,$ready?'passed':'attention','Saved authenticated background observation; no fresh network probe was sent.');
   foreach([false,true]as$backup){$route=$mesh->route($s,$p,$backup);$add(($backup?'Backup route · ':'Primary route · ').$name,$route['state']==='ok'?'passed':($route['state']==='none'?'not-tested':'attention'),'Symcon route observation: '.$route['state'].'.');}
  }
  $hardware=array_filter($s['identity']['credentials'],static fn($c)=>$c['active']&&($c['tested']??false)&&($c['hardware']??false)&&($c['trustVersion']??'')===($s['policy']['management']['settings']['HardwareTrustVersion']??null));
  $add('Hardware policy configuration',in_array(true,$s['policy']['hardware'],true)&&count($hardware)<2?'attention':'passed','Eligible tested hardware credentials: '.count($hardware).'. Configuration checks do not prove a fresh physical-key touch.');
  foreach(['Fresh Magic login with primary unavailable','Saved encrypted backup restored on a disposable installation','Physical-key/browser verification if hardware enforcement is used']as$name)$add($name,'not-tested','Requires a real user/device or isolated deployment. The automated check cannot certify this observation.');
  return ['format'=>'SECB.ProductionChecks.1','evaluatedAt'=>time(),'vaultId'=>$s['native']['vaultId'],'checks'=>$checks,'complete'=>false];
 }
}
