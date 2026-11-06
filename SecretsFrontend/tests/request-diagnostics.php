<?php
declare(strict_types=1);
require_once __DIR__.'/BootstrapFixture.php';
$GLOBALS['moduleIDs']=[5100=>SecretsBackend::FRONTEND,5101=>'{52165EDD-B2C0-40EC-8A59-42A97319B6E2}',700=>'{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}'];
$hooks=new IPSModule(700);$hooks->properties['Hooks']='[]';
$front=new SecretsFrontend(5100);$front->Create();$back=new SecretsBackend(5101);$back->Create();
$root=sys_get_temp_dir().'/sec-request-diag-'.bin2hex(random_bytes(8));
$request=['origin'=>'https://secrets.example.test','cookie'=>'','csrf'=>'','remote'=>'test'];
$call=static fn(string $action,array $data=[],?array $r=null):array=>json_decode($back->HandleFrontendRequest(5100,json_encode(['action'=>$action,'data'=>$data]+($r??$request))),true);
try{
    $key=secKey();$choice=['backend'=>5101,'portal'=>0,'documentation'=>0,'theme'=>'system','vaultDirectory'=>$root.'/data','keyDirectory'=>$root.'/keys','addPortalLink'=>false,'debugEnabled'=>false,'privateACLConfirmed'=>true,'persistenceConfirmed'=>true];
    $login=secBootstrapInitialize($front,$request,$key,$choice);
    $request['cookie']=explode(';',$login['cookie'])[0];$request['csrf']=$login['data']['csrf'];
    $r=$call('session',[],$request);secExpect($r['status']===200,'Initial session failed.');
    $support=$call('nativeSupportStatus',[],$request);secExpect($support['status']===200&&$support['data']['targets']===[],'Authenticated support discovery failed.');
    foreach(['nativeSupportStatus','nativeSupportUpload','nativeSetupPreview','nativeSetupRun']as$action){
        $data=$action==='nativeSupportUpload'?['instance'=>123]:[];
        $anonymous=$request;$anonymous['cookie']='';$refused=$call($action,$data,$anonymous);secExpect($refused['data']['code']==='LOGIN_REQUIRED','Support API bypassed login.');
        $wrong=$request;$wrong['csrf']='INVALID-CSRF';$refused=$call($action,$data,$wrong);secExpect($refused['data']['code']==='CSRF_INVALID','Support API bypassed CSRF.');
    }
    $support=$call('nativeSupportUpload',['instance'=>0],$request);secExpect($support['status']===200&&$support['data']['state']==='queued','Upload was not queued directly.');
    $store=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);$job=$support['data']['job'];$head=$store->head();
    $second=$call('nativeSupportUpload',['instance'=>0],$request);secExpect($second['data']['job']===$job,'Repeated click queued a duplicate upload.');
    SecretsBackendSupportReport::tick($store);$status=$call('nativeSupportUploadStatus',['job'=>$job],$request);secExpect($status['data']['state']==='finished'&&!$status['data']['ok']&&str_contains($status['data']['error'],'no Configuration Backup instance'),'Background upload did not return the actual missing-instance failure.');secExpect($store->head()===$head,'Support queue invalidated a passkey approval.');
    $missing=$request;$missing['cookie']='';$r=$call('prepare',['operation'=>['kind'=>'nativeEmergencyAccept']],$missing);
    secExpect($r['data']['code']==='LOGIN_REQUIRED'&&$r['data']['requiresSignIn']===true,'Missing login was not distinguished.');
    $store=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);
    $hash=hash('sha256',explode('=',$request['cookie'],2)[1]);$session=$store->get($hash,'session');$old=$session;$old['last']=time()-901;$store->replace($hash,'session',$old,time()+3600);
    $r=$call('nativePairingStatus',[],$request);secExpect($r['data']['code']==='SESSION_INVALID'&&$r['data']['requiresSignIn'],'Idle session refusal did not instruct sign-in.');
    $store->replace($hash,'session',$session,time()+3600);
    $bad=$request;$bad['csrf']='CSRF-CANARY';$r=$call('prepare',['operation'=>['kind'=>'nativeInvite']],$bad);
    secExpect($r['data']['code']==='CSRF_INVALID','CSRF failure was hidden.');
    $r=$call('prepare',['operation'=>['kind'=>'nativeEmergencyAccept','peerId'=>SecretsBackendCodec::uuid(),'digest'=>str_repeat('a',64)]],$request);
    secExpect($r['data']['code']==='EMERGENCY_OFFER_CHANGED'&&!$r['data']['requiresSignIn'],'Missing/replaced emergency offer did not explain the refusal.');
    $begin=$call('prepare',['operation'=>['kind'=>'nativeInvite']],$request)['data'];
    $challenge=$store->get($begin['challengeId'],'approval');$store->replace($begin['challengeId'],'approval',$challenge,time()-1);
    $r=$call('approve',['challengeId'=>$begin['challengeId'],'credential'=>secAssertion($key,$begin['options']['challenge'],2)],$request);
    secExpect($r['data']['code']==='APPROVAL_EXPIRED','Expired approval was confused with an expired login.');
    $begin=$call('prepare',['operation'=>['kind'=>'nativeInvite']],$request)['data'];
    $current=$store->read();$store->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','intervening-change'),static function(array $s):array{$s['vault']['revision']=SecretsBackendCodec::increment($s['vault']['revision']);return $s;});
    $r=$call('approve',['challengeId'=>$begin['challengeId'],'credential'=>secAssertion($key,$begin['options']['challenge'],2)],$request);
    secExpect($r['data']['code']==='REVISION_CHANGED','Concurrent state change was not identified.');
    $report=json_decode($back->GetRequestDiagnostics(),true);$last=end($report['recentFailures']);
    secExpect($last['stage']==='commit'&&$last['operation']==='nativeInvite'&&$last['reference']===$r['data']['reference'],'Server/client refusal references or stages differ.');
    secExpect($last['authenticated']&&$last['csrfVerified'],'Verified authorization facts were lost.');
    $history=count($report['recentFailures']);$back->Recover();secExpect(count(json_decode($back->GetRequestDiagnostics(),true)['recentFailures'])===$history,'Recovery erased diagnostic history.');
    $mesh=json_decode($back->GetMeshHealth(),true);secExpect(isset($mesh['requestDiagnostics']['recentFailures']),'Mesh export omitted request failures.');
    $back->properties['Enabled']=false;secExpect(json_decode($back->GetRequestDiagnostics(),true)['recentFailures']!==[],'Diagnostics depended on enabled vault.');$back->properties['Enabled']=true;
    $unknown=SecretsBackendRequestDiagnostics::failure(new RuntimeException('PRIVATE-EXCEPTION-CANARY /private/path'),['stage'=>'prepare','authenticated'=>true,'csrfVerified'=>true,'operation'=>'OPERATION-CANARY'],['action'=>'ACTION-CANARY'],5101,5100);
    $public=SecretsBackendRequestDiagnostics::response($unknown);secExpect($unknown['operation']===null&&$unknown['action']==='other'&&$public['code']==='REQUEST_FAILED','Unknown input became a diagnostic identifier.');
    $hidden=SecretsBackendRequestDiagnostics::response(array_replace($unknown,['code'=>'EMERGENCY_OFFER_CHANGED','authenticated'=>false]));secExpect($hidden['code']==='REQUEST_FAILED','Unauthenticated client received operation details.');
    for($i=0;$i<25;$i++)$call('session',[],$missing);
    $report=$back->GetRequestDiagnostics();secExpect(count(json_decode($report,true)['recentFailures'])===20,'Diagnostic history is unbounded.');
    foreach(['CSRF-CANARY','PRIVATE-EXCEPTION-CANARY','OPERATION-CANARY','ACTION-CANARY',$request['cookie'],$request['csrf'],$root]as$canary)secExpect(!str_contains($report,$canary)&&!str_contains(json_encode($unknown),$canary),'Sensitive input leaked into diagnostics.');
    secExpect($back->properties['DebugEnabled']===false&&!empty($back->values['LastRequestFailure']),'Failures were lost with debug logging disabled.');
    // Another tab signs in: its shared cookie and this tab's old CSRF no longer match.
    $pending=$call('prepare',['operation'=>['kind'=>'nativeInvite']],$request)['data'];
    $auth=$call('authOptions',[],$request)['data'];
    $login=$call('authVerify',['challengeId'=>$auth['challengeId'],'credential'=>secAssertion($key,$auth['options']['challenge'],100)],$request);
    secExpect($login['status']===200,'Second-tab sign-in failed.');
    $next=$request;$next['cookie']=explode(';',$login['cookie'])[0];
    secExpect($next['cookie']!==$request['cookie']&&$login['data']['csrf']!==$request['csrf'],'Second sign-in did not create a distinct session.');
    $r=$call('approve',['challengeId'=>$pending['challengeId'],'credential'=>secAssertion($key,$pending['options']['challenge'],101)],$next);
    secExpect($r['data']['code']==='CSRF_INVALID','A changed cookie with old page token did not reproduce CSRF_INVALID.');
    $last=end(json_decode($back->GetRequestDiagnostics(),true)['recentFailures']);
    secExpect($last['authenticated']&&!$last['csrfVerified']&&$last['stage']==='csrf','CSRF diagnostics lost authenticated-session versus token-verification facts.');
    $refreshed=$call('session',[],$next);
    secExpect($refreshed['status']===200&&$refreshed['data']['csrf']===$login['data']['csrf'],'Authenticated session metadata could not refresh an old tab.');
    $next['csrf']=$refreshed['data']['csrf'];
    $r=$call('approve',['challengeId'=>$pending['challengeId'],'credential'=>secAssertion($key,$pending['options']['challenge'],101)],$next);
    secExpect($r['data']['code']==='APPROVAL_INVALID','Session refresh improperly made an old-session approval valid.');
    $fresh=$call('prepare',['operation'=>['kind'=>'nativeInvite']],$next)['data'];
    $r=$call('approve',['challengeId'=>$fresh['challengeId'],'credential'=>secAssertion($key,$fresh['options']['challenge'],101)],$next);
    secExpect($r['status']===200,'Freshly reviewed approval failed in the refreshed session.');
    echo "PASS request diagnostics: session expiry, CSRF, replaced offer, expired approval, revision race, safe correlation, recovery retention, locked-vault export, bounded redacted history and second-tab login recovery with old-session approval refusal\n";
}finally{
    $clean=static function(string $path)use(&$clean):void{if(is_dir($path)){foreach(scandir($path)as$n)if($n!=='.'&&$n!=='..')$clean($path.'/'.$n);rmdir($path);}elseif(file_exists($path))unlink($path);};$clean($root);
}
