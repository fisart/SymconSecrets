<?php
declare(strict_types=1);
require_once __DIR__ . '/SymconHarness.php';
require_once __DIR__ . '/../../SecretsBackend/tests/Fixture.php';
require_once __DIR__ . '/../module.php';
require_once __DIR__ . '/../../SecretsBackend/module.php';
function SECB_GetInitialSetupInfo(int $id): string { return $GLOBALS['instances'][$id]->GetInitialSetupInfo(); }
function SECB_ConfigureInitialSetup(int $id, int $front, string $digest, string $json): bool { return $GLOBALS['instances'][$id]->ConfigureInitialSetup($front,$digest,$json); }
function SECB_ExportConfiguration(int $id): string { return $GLOBALS['instances'][$id]->ExportConfiguration(); }
function SECB_InitializeNativeStorage(int $id,int $front,string $digest,bool $acl,bool $persist,string $label): string { return $GLOBALS['instances'][$id]->InitializeNativeStorage($front,$digest,$acl,$persist,$label); }
function SECB_GetNativeInfo(int $id): string { return $GLOBALS['instances'][$id]->GetNativeInfo(); }
function SECB_HandleFrontendRequest(int $id,int $front,string $json): string { return $GLOBALS['instances'][$id]->HandleFrontendRequest($front,$json); }
function SECB_BeginAdminEnrollment(int $id,string $label,bool $hardware): string { return $GLOBALS['instances'][$id]->BeginAdminEnrollment($label,$hardware); }
$GLOBALS['moduleIDs'] = [5100 => SecretsBackend::FRONTEND, 5101 => '{52165EDD-B2C0-40EC-8A59-42A97319B6E2}', 700 => '{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}'];
$hooks = new IPSModule(700); $hooks->properties['Hooks'] = '[]';
$front = new SecretsFrontend(5100); $front->Create(); $back = new SecretsBackend(5101); $back->Create();
$root = sys_get_temp_dir() . '/sec-native-life-' . bin2hex(random_bytes(8));
$gateway = new ReflectionMethod(SecretsFrontend::class,'gateway');
$request = ['origin'=>'https://secrets.example.test','cookie'=>'','csrf'=>'','remote'=>'test'];
$invoke = static function (string $action,array $data=[]) use($gateway,$front,$back,&$request): array {
    $reply = $gateway->invoke($front,['action'=>$action,'data'=>$data]+$request);
    if ($reply['status']!==200) throw new RuntimeException($action.': '.json_encode($reply).' | '.($back->values['Status']??''));
    return $reply;
};
try {
    $code = $front->BeginGuidedSetup('https://secrets.example.test','');
    $found = $invoke('guidedDiscover',['code'=>$code])['data'];
    secExpect($found['defaults']['backend']===5101 && $found['defaults']['initialize']===true,'Native discovery/default selection failed.');
    $choice=['backend'=>5101,'portal'=>0,'documentation'=>0,'theme'=>'system','vaultDirectory'=>$root.'/data','keyDirectory'=>$root.'/keys','proxyIPs'=>[],'addPortalLink'=>false,'debugEnabled'=>false,'initialize'=>true,'privateACLConfirmed'=>true,'persistenceConfirmed'=>true,'administratorLabel'=>'Native owner'];
    $plan=$invoke('guidedPreview',['code'=>$code,'configuration'=>$choice])['data'];
    $done=$invoke('guidedApply',['code'=>$code,'planId'=>$plan['planId']])['data'];
    secExpect($done['vaultCreated'] && $done['native']['ready'] && $back->status===102,'Native wizard did not create/recover the real store.');
    secExpect(!file_exists($root.'/data/vault.sqlite') && is_file($root.'/data/native.json'),'Native setup entered SQLite.');
    $status=$invoke('status')['data'];secExpect($status['ready']&&$status['enrollmentNeeded'],'Native gateway remained in the old pending stub.');
    $key=secKey();$begin=$invoke('enrollmentOptions',['code'=>$done['native']['enrollmentCode']])['data'];
    $invoke('enrollmentVerify',['challengeId'=>$begin['challengeId'],'credential'=>secRegistration($key,$begin['options']->challenge ?? $begin['options']['challenge'])]);
    $begin=$invoke('authOptions')['data'];$args=json_decode(json_encode($begin),true);
    $login=$invoke('authVerify',['challengeId'=>$args['challengeId'],'credential'=>secAssertion($key,$args['options']['challenge'],1)]);
    $request['cookie']=explode(';',$login['cookie'])[0];$request['csrf']=$login['data']['csrf'];
    $listed=$invoke('session')['data'];secExpect($listed['revision']==='0','Fresh native session failed.');
    $write=['kind'=>'save','scope'=>'global','path'=>['ASK'],'revision'=>'0','mode'=>'create','json'=>'{"User":"native-user","Pass":"NATIVE-SECRET-CANARY"}'];
    $begin=json_decode(json_encode($invoke('prepare',['operation'=>$write])['data']),true);
    $invoke('approve',['challengeId'=>$begin['challengeId'],'credential'=>secAssertion($key,$begin['options']['challenge'],2)]);
    $listed=$invoke('session')['data'];secExpect($listed['revision']==='1'&&!str_contains(json_encode($listed),'NATIVE-SECRET-CANARY'),'Native list leaked or lost data.');
    $begin=json_decode(json_encode($invoke('prepare',['operation'=>['kind'=>'reveal','scope'=>'global','path'=>['ASK'],'revision'=>'1']])['data']),true);
    $reveal=$invoke('approve',['challengeId'=>$begin['challengeId'],'credential'=>secAssertion($key,$begin['options']['challenge'],3)])['data'];
    secExpect(str_contains(json_encode($reveal),'NATIVE-SECRET-CANARY'),'Native selected-record reveal failed.');
    $counter=3;
    $approved=static function(array $operation)use($invoke,$key,&$counter):array{
        $prepared=json_decode(json_encode($invoke('prepare',['operation'=>$operation])['data']),true);
        return $invoke('approve',['challengeId'=>$prepared['challengeId'],'credential'=>secAssertion($key,$prepared['options']['challenge'],++$counter)])['data'];
    };
    $readGrant=$approved(['kind'=>'nativeMachineGrant','name'=>'Read-only integration','scope'=>'global','path'=>['ASK'],'write'=>false]);
    secExpect(str_contains($back->ReadNativeSecret($readGrant['capabilityToken'],'global','["ASK","Pass"]'),'NATIVE-SECRET-CANARY'),'Scoped machine read failed.');
    secReject(static fn()=>$back->ReadNativeSecret($readGrant['capabilityToken'],'local','["ASK"]'),'Machine token crossed scope.');
    secReject(static fn()=>$back->WriteNativeSecret($readGrant['capabilityToken'],'global','["ASK","Pass"]','"NO"','1','1',SecretsBackendCodec::uuid()),'Read-only machine token wrote a secret.');
    $writeGrant=$approved(['kind'=>'nativeMachineGrant','name'=>'Scoped writer','scope'=>'global','path'=>['ASK'],'write'=>true]);
    $writeId=SecretsBackendCodec::uuid();
    $back->WriteNativeSecret($writeGrant['capabilityToken'],'global','["ASK","User"]','"MACHINE-UPDATED"','1','1',$writeId);
    $back->WriteNativeSecret($writeGrant['capabilityToken'],'global','["ASK","User"]','"MACHINE-UPDATED"','1','1',$writeId);
    secExpect($invoke('session')['data']['revision']==='2','Lost machine reply repeated its mutation.');
    secReject(static fn()=>$back->WriteNativeSecret($writeGrant['capabilityToken'],'global','["ASK","User"]','"CONFLICT"','1','1',$writeId),'Machine ID accepted different bytes.');
    $approved(['kind'=>'nativeMachineRevoke','id'=>$writeGrant['machineId']]);
    secReject(static fn()=>$back->ReadNativeSecret($writeGrant['capabilityToken'],'global','["ASK"]'),'Revoked machine token still reads.');
    $approved(['kind'=>'nativeRotateKey']);
    secExpect(count(glob($root.'/keys/data-*.key'))===2,'Key rotation lost the retained key generation.');
    $backup=$approved(['kind'=>'nativeBackup']);
    secExpect(!str_contains($backup['backup'],'NATIVE-SECRET-CANARY')&&!str_contains($backup['backup'],$backup['recoveryKey']),'Portable backup exposed a value or its wrapping key.');
    $material=SecretsBackendNativeBackup::decrypt($backup['backup'],$backup['recoveryKey'],4*1024*1024);
    secExpect(str_contains(json_encode($material['state']['vault']),'NATIVE-SECRET-CANARY')&&count($material['keys'])===5,'Complete backup omitted current values or retained keys.');
    secReject(static fn()=>SecretsBackendNativeBackup::decrypt($backup['backup'],SecretsBackendCodec::b64(random_bytes(32)),4*1024*1024),'Wrong recovery key opened backup.');
    $tampered=json_decode($backup['backup'],true);$tampered['vaultId']=SecretsBackendCodec::uuid();
    secReject(static fn()=>SecretsBackendNativeBackup::decrypt(json_encode($tampered),$backup['recoveryKey'],4*1024*1024),'Tampered backup identity was accepted.');
    $upload=static function(string $bytes)use($invoke):string{
        $begin=$invoke('nativeUploadBegin',['length'=>strlen($bytes),'digest'=>hash('sha256',$bytes)])['data'];
        for($at=0,$index=0;$at<strlen($bytes);$at+=$begin['chunkBytes'],++$index)$invoke('nativeUploadChunk',['uploadId'=>$begin['uploadId'],'index'=>$index,'chunk'=>SecretsBackendCodec::b64(substr($bytes,$at,$begin['chunkBytes']))]);
        return $invoke('nativeUploadFinish',['uploadId'=>$begin['uploadId']])['data']['uploadId'];
    };
    $compacted=$approved(['kind'=>'nativeCompact','uploadId'=>$upload($backup['backup']),'recoveryKey'=>$backup['recoveryKey']]);
    secExpect($compacted['compacted']&&$invoke('session')['data']['revision']==='2','Verified compaction damaged storage or secret revisions.');
    $restored=$approved(['kind'=>'nativeRestore','uploadId'=>$upload($backup['backup']),'recoveryKey'=>$backup['recoveryKey'],'mode'=>'local-copy']);
    secExpect($restored['restored']&&!$restored['authorityRestored'],'Restore replaced current authority.');
    $listed=$invoke('session')['data'];
    secExpect($listed['revision']==='3'&&count($listed['credentials'])===1&&str_contains(json_encode($listed['local']),'Recovered-'),'Local-copy recovery failed.');
    secExpect(!str_contains(json_encode($listed),$readGrant['capabilityToken'])&&!str_contains(json_encode($listed),'NATIVE-SECRET-CANARY'),'Native metadata exposed secrets or capability tokens.');
    $admission=$approved(['kind'=>'nativeEnrollment','label'=>'Second administrator key','hardware'=>false,'probe'=>false]);
    $secondKey=secKey();$registration=json_decode(json_encode($invoke('enrollmentOptions',['code'=>$admission['enrollmentCode']])['data']),true);
    $invoke('enrollmentVerify',['challengeId'=>$registration['challengeId'],'credential'=>secRegistration($secondKey,$registration['options']['challenge'])]);
    secReject(static fn()=>$invoke('session'),'New credential registration did not invalidate old sessions.');
    $loginOptions=json_decode(json_encode($invoke('authOptions')['data']),true);
    $login=$invoke('authVerify',['challengeId'=>$loginOptions['challengeId'],'credential'=>secAssertion($secondKey,$loginOptions['options']['challenge'],1)]);
    $request['cookie']=explode(';',$login['cookie'])[0];$request['csrf']=$login['data']['csrf'];
    $admission=$approved(['kind'=>'nativeEnrollment','label'=>'Stale admission','hardware'=>false,'probe'=>false]);
    $approved(['kind'=>'save','scope'=>'local','path'=>['NewerState'],'revision'=>'3','mode'=>'create','json'=>'true']);
    secReject(static fn()=>$invoke('enrollmentOptions',['code'=>$admission['enrollmentCode']]),'Web admission survived a change to its authorizing snapshot.');
    foreach(glob($root.'/data/*')?:[]as$file)if(is_file($file))secExpect(!str_contains(file_get_contents($file),'NATIVE-SECRET-CANARY'),'Native value was written in plaintext.');
    $front->properties['TrustedHTTPSProxyIPs']='["192.0.2.1"]';$back->ApplyChanges();
    secExpect(!$back->Recover(),'Changed protected frontend trust activated a native runtime.');
    secReject(static fn()=>$back->ReadNativeSecret($readGrant['capabilityToken'],'global','["ASK"]'),'Machine access survived failed security-profile recovery.');
    $front->properties['TrustedHTTPSProxyIPs']='[]';secExpect($back->Recover(),'Restored protected frontend trust did not permit recovery.');
    $back->ApplyChanges();$back->Recover();
    $rejected=$gateway->invoke($front,['action'=>'session','data'=>[]]+$request);secExpect($rejected['status']!==200,'Native restart retained a session.');
    echo "PASS native wizard, real WebAuthn, encrypted writes/reveal, scoped machine read/write/dedup/revocation, key rotation, authenticated backup/compaction/value recovery and restart fencing; no PDO/SQLite or external authority\n";
} finally {
    $remove=static function($path)use(&$remove){if(is_dir($path)&&!is_link($path)){foreach(scandir($path)as$n)if($n!=='.'&&$n!=='..')$remove($path.'/'.$n);rmdir($path);}elseif(file_exists($path)||is_link($path))unlink($path);};if(is_dir($root))$remove($root);
}
