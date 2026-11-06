<?php
require_once __DIR__.'/../SupportReport.php';
$cfg=['ReadableSecretsDiagnostics'=>true,'GitHubOwner'=>'fisart','GitHubRepository'=>'private-backup','GitHubBranch'=>'main','Token'=>'PRIVATE-CANARY'];$changed=false;$calls=0;$mode='ok';
function IPS_GetInstanceListByModuleID($id){return $id==='{0E51F4D8-5A8C-46B3-8F77-610C3F9493AC}'?[123]:[];}
function IPS_GetConfiguration($id){return json_encode($GLOBALS['cfg']);}
function IPS_GetName($id){return 'Configuration Backup';}
function IPS_HasChanges($id){return $GLOBALS['changed'];}
function MCB_UploadSecretsDiagnostics($id){$GLOBALS['calls']++;if($GLOBALS['mode']==='throw')throw new RuntimeException('PRIVATE-CANARY');return json_encode($GLOBALS['mode']==='ok'?['ok'=>true,'commit'=>str_repeat('a',40),'warning'=>'']:['ok'=>false,'error'=>'PRIVATE-CANARY']);}
function check($yes,$why){if(!$yes)throw new RuntimeException($why);}
check(!str_contains(json_encode(SecretsBackendSupportReport::targets()),'PRIVATE-CANARY'),'Configuration values leaked.');
check(SecretsBackendSupportReport::upload(999)['ok']===false&&$calls===0,'Unrelated instance invoked.');
$cfg['ReadableSecretsDiagnostics']=false;check(!SecretsBackendSupportReport::upload(123)['ok']&&$calls===0,'Opt-in bypassed.');$cfg['ReadableSecretsDiagnostics']=true;$changed=true;check(!SecretsBackendSupportReport::upload(123)['ok']&&$calls===0,'Pending settings accepted.');$changed=false;
$r=SecretsBackendSupportReport::upload(123);check($r['ok']&&$r['commit']===str_repeat('a',40)&&$calls===1,'Confirmed commit missing.');
foreach(['throw','error']as$mode){$r=SecretsBackendSupportReport::upload(123);check(!$r['ok']&&!str_contains(json_encode($r),'PRIVATE-CANARY'),'Raw uploader error leaked.');}
echo "PASS support report: configured target, saved opt-in, exact backup API, confirmed commit and redacted failures\n";
