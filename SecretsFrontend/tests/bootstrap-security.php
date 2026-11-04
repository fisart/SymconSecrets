<?php
declare(strict_types=1);
require_once __DIR__.'/BootstrapFixture.php';
$checks=0;
$ok=static function(bool $v,string $message)use(&$checks):void{secExpect($v,$message);$checks++;};
$no=static function(callable $fn,string $message)use(&$checks):void{secReject($fn,$message);$checks++;};
$GLOBALS['moduleIDs']=[700=>'{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}'];$hooks=new IPSModule(700);$hooks->properties['Hooks']='[]';
$next=6000;
$fixture=static function()use(&$next):array{
    $f=$next++;$b=$next++;$GLOBALS['moduleIDs'][$f]='{8D6AE8F7-EA3A-4513-AA14-C3F9613B0E83}';$GLOBALS['moduleIDs'][$b]='{52165EDD-B2C0-40EC-8A59-42A97319B6E2}';
    $front=new SecretsFrontend($f);$front->Create();$back=new SecretsBackend($b);$back->Create();
    $front->properties['BackendInstanceID']=$b;
    $root=rtrim(IPS_GetKernelDir(),'/');$choice=['backend'=>$b,'portal'=>0,'documentation'=>0,'theme'=>'system','vaultDirectory'=>$root.'/secrets-native-data/test-'.$b,'keyDirectory'=>$root.'/secrets-native-keys/test-'.$b,'addPortalLink'=>false,'debugEnabled'=>false,'privateACLConfirmed'=>true,'persistenceConfirmed'=>true];
    return [$front,$back,['origin'=>'https://secrets.example.test','cookie'=>'','csrf'=>'','remote'=>'test'],$choice];
};
$gateway=static fn($front,$request,$data,$action='bootstrapProof')=>(new ReflectionMethod(SecretsFrontend::class,'gateway'))->invoke($front,['action'=>$action,'data'=>$data]+$request);

[$front,$back,$request,$choice]=$fixture();
$configuration=json_decode($back->ExportConfiguration(),true,16,JSON_THROW_ON_ERROR);
$configuration['configuration']['Enabled']=true;
$ok($back->ImportConfiguration(SecretsBackendCodec::json($configuration)), 'Fresh native backend configuration import refused its default storage paths.');
$ok(!$back->properties['Enabled'] && !is_dir($back->properties['DataDirectory']), 'Native settings import enabled or initialized the vault.');
$invalid=$configuration;$invalid['configuration']['DataDirectory']=rtrim(IPS_GetKernelDir(),'/').'/webfront/unsafe';
$before=$back->properties;
$no(fn()=>$back->ImportConfiguration(SecretsBackendCodec::json($invalid)), 'Native settings import accepted a public storage folder.');
$ok($back->properties===$before, 'Rejected native import changed properties.');

$no(fn()=>$front->BeginGuidedSetup($request['origin'],''),'Old setup-code method remained active.');
$ok($gateway($front,$request,[],'bootstrapPrepare')['status']===403,'A public request opened a console intent.');
$url=$front->OpenBootstrap($request['origin'],'',false,true);$ok($url===$request['origin'].'/hook/secrets_frontend_'.$front->InstanceID&&!str_contains($url,'?')&&!str_contains($url,'#'),'Setup link contains authority.');
// A configured frontend/backend pair can still have no native storage (live console regression).
$action=static function(SecretsFrontend $front,string $name):array{foreach(json_decode($front->GetConfigurationForm(),true)['actions']as$a)if(($a['name']??'')===$name)return $a;throw new RuntimeException('Missing form action '.$name);};
$unboundProperties=$back->properties;$back->properties['FrontendInstanceID']=$front->InstanceID;$back->properties['AdminOrigin']=$request['origin'];
$ok($action($front,'OpenRecoveryBootstrap')['enabled']===false&&$action($front,'RecoveryAvailability')['visible']===true,'Empty backend exposed administrator recovery in the console.');
$beforeRecovery=[$back->attributes,$back->properties,$front->buffers];
try{$front->OpenRecoveryBootstrap();throw new LogicException('Empty backend entered recovery.');}catch(RuntimeException $e){$ok(str_contains($e->getMessage(),'Step 1: Open setup'),'Empty backend reached nativeStore instead of explaining initial setup.');}
$ok([$back->attributes,$back->properties,$front->buffers]===$beforeRecovery&&!is_dir($choice['vaultDirectory']),'Rejected recovery changed or initialized the empty backend.');
$back->properties=$unboundProperties;
$key=secKey();$ctx=secBootstrapCandidate($front,$request,$key);
$view=json_decode($front->GetBootstrapConsoleView(),true)[0];$ctx['operation']=secBootstrapProof($front,$request,$ctx,'candidateStatus')['data']['operation'];
$no(fn()=>secBootstrapProof($front,$request,$ctx,'planPreview',$choice),'Unapproved candidate discovered configuration.');
$requestB=$request;$ctxB=secBootstrapCandidate($front,$requestB,secKey());
$ok($view['candidate']===$ctx['candidate']&&$view['digest']===$ctx['candidateDigest'],'Console snapshot changed when B arrived.');
$no(fn()=>$front->ApproveBootstrapCandidate($ctxB['candidate'],$ctxB['candidateDigest'],$view['proof']),'View A authorized candidate B.');
$front->ApproveBootstrapCandidate($view['candidate'],$view['digest'],$view['proof']);
$ok(secBootstrapProof($front,$request,$ctx,'candidateStatus')['data']['approved']===true,'Exact console approval failed.');
$ok(secBootstrapProof($front,$requestB,$ctxB,'candidateStatus')['data']['approved']===false,'Another candidate was silently approved.');
$m=secBootstrapProof($front,$request,$ctx,'candidateStatus',[],false);$bad=$m;$bad['signature']=SecretsBackendCodec::b64(str_repeat("\0",64));
$ok($gateway($front,$request,$bad)['status']===403,'Invalid signature accepted.');
$r=$gateway($front,$request,$m);$ok($r['status']===200,'An invalid signature burned the valid nonce.');$ctx['nonce']=$r['data']['nonce'];
$ok($gateway($front,$request,$m)['status']===403,'A replay received a replacement nonce.');
$wrong=$m;$wrong['request']=SecretsBackendCodec::uuid();$wrong['origin']='https://evil.example.test';$wrong['signature']=secRawSign($ctx['browser'],SecretsBootstrapVerifier::signingBytes($wrong,'{}'));
$ok($gateway($front,$request,$wrong)['status']===403,'A valid signature escaped its origin binding.');
$cookie=$request;$cookie['cookie']='';$fresh=secBootstrapProof($front,$request,$ctx,'candidateStatus',[],false);$ok($gateway($front,$cookie,$fresh)['status']===403,'PoP without the bound cookie was accepted.');
$csrf=$request;$csrf['csrf']='wrong';$ok($gateway($front,$csrf,$fresh)['status']===403,'PoP without CSRF was accepted.');

// Resume challenges do not mutate active nonce/epoch. Exactly one proof wins.
$challenge=$gateway($front,$request,['candidate'=>$ctx['candidate']],'bootstrapResumeOptions')['data'];
$ok($gateway($front,$request,secBootstrapProof($front,$request,$ctx,'candidateStatus',[],false))['status']===200,'Resume options burned a live nonce.');
$raw=SecretsBackendCodec::json($challenge);$resume=$fresh;$resume['purpose']='resume';$resume['action']='resumeVerify';$resume['request']=SecretsBackendCodec::uuid();$resume['nonce']=$challenge['challenge'];$resume['body']=SecretsBackendCodec::b64($raw);$resume['operation']='-';$resume['signature']=secRawSign($ctx['browser'],SecretsBootstrapVerifier::signingBytes($resume,$raw));
$r=$gateway($front,$request,$resume);$ok($r['status']===200&&$r['data']['epoch']==='1','Valid resume proof did not advance exactly once.');
$ctx['epoch']=$r['data']['epoch'];$ctx['nonce']=$r['data']['nonce'];
$ok($gateway($front,$request,$resume)['status']===403,'Old resume proof advanced the epoch again.');
$ok($gateway($front,$request,$fresh)['status']===403,'Old-epoch request survived recovery.');
$plan=secBootstrapProof($front,$request,$ctx,'planPreview',$choice)['data'];
$options=json_decode(json_encode(secBootstrapProof($front,$request,$ctx,'applyOptions',['planDigest'=>$plan['planDigest']])['data']),true);
$cancel=secBootstrapProof($front,$request,$ctx,'cancel')['data'];$ok($cancel['status']==='CANCELLED','Cancellation was not durable.');
$no(fn()=>secBootstrapProof($front,$request,$ctx,'applyVerify',['planDigest'=>$plan['planDigest'],'credential'=>secAssertion($key,$options['options']['challenge'],1)]),'Cancelled setup created a vault.');
$ok(!is_dir($choice['vaultDirectory']),'Cancellation left a usable vault.');

// The unprivileged prepared-key record permits reuse after page loss, with new possession proof and console approval.
$front->ApplyChanges();$front->OpenBootstrap($request['origin'],'',false,true);$reused=secBootstrapCandidate($front,$request,$key,true);$status=secBootstrapProof($front,$request,$reused,'candidateStatus')['data'];$ok(!$status['approved'],'Reused key inherited a previous console approval.');
$view=json_decode($front->GetBootstrapConsoleView(),true)[0];$front->ApproveBootstrapCandidate($view['candidate'],$view['digest'],$view['proof']);$plan=secBootstrapProof($front,$request,$reused,'planPreview',$choice)['data'];$o=json_decode(json_encode(secBootstrapProof($front,$request,$reused,'applyOptions',['planDigest'=>$plan['planDigest']])['data']),true);
$done=secBootstrapProof($front,$request,$reused,'applyVerify',['planDigest'=>$plan['planDigest'],'credential'=>secAssertion($key,$o['options']['challenge'],2)]);$ok($done['data']['status']==='COMMITTED','Previously prepared key could not complete with fresh approval.');
$configuration=json_decode($back->ExportConfiguration(),true,16,JSON_THROW_ON_ERROR);
$changed=$configuration;$changed['configuration']['KeyDirectory'].='-changed';
$before=$back->properties;
$no(fn()=>$back->ImportConfiguration(SecretsBackendCodec::json($changed)), 'Native configuration import replaced initialized storage.');
$ok($back->properties===$before, 'Rejected native foundation import changed properties.');


// A lost acceptance response survives reload and uses the exact original administrator.
[$front,$back,$request,$choice]=$fixture();$key=secKey();$GLOBALS['pauseBootstrap']=true;
$r=secBootstrapInitialize($front,$request,$key,$choice);$ok($r['data']['status']==='RECOVERY_REQUIRED','Paused accepted operation was reported as success.');
$ok(str_contains($front->CancelBootstrap(),'No active')||str_contains($front->CancelBootstrap(),'already'),'Cancellation after acceptance promised a stop.');
$front->ApplyChanges();$GLOBALS['pauseBootstrap']=false;
$ok($front->RecoverBootstrap(),'Accepted operation did not recover after reload: '.($front->values['Status']??''));
$store=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);$state=$store->read()['state'];
$ok(count($state['identity']['credentials'])===1&&isset($state['identity']['credentials'][$key['id']]),'Restart substituted or omitted the approved administrator.');
$ok($state['native']['genesisFormat']==='SECF.Genesis.1','Genesis mode marker is missing.');
$ok($front->RecoverBootstrap(),'Repeated recovery was not idempotent.');
$no(fn()=>$back->InitializeNativeStorage($front->InstanceID,'old',true,true,'Old'),'Old empty-vault initializer remained active.');
$no(fn()=>$back->BeginAdminEnrollment('Old code',false),'Local native enrollment still issued a code.');

// Recovery adds exactly the console-approved key without changing secret values.
$ok($action($front,'OpenRecoveryBootstrap')['enabled']===true&&$action($front,'RecoveryAvailability')['visible']===false,'Initialized backend did not enable administrator recovery.');
$binding=$back->attributes['StorageBinding'];$back->attributes['StorageBinding']='';$lockedBefore=[$back->attributes,$front->buffers];
$no(fn()=>$front->OpenRecoveryBootstrap(),'Broken existing vault was downgraded to initial setup.');
$ok([$back->attributes,$front->buffers]===$lockedBefore,'Failed recovery reset an existing vault or its bootstrap intent.');$back->attributes['StorageBinding']=$binding;
$before=$store->read()['state']['vault'];$replacement=secKey();$front->OpenRecoveryBootstrap();$ctx=secBootstrapCandidate($front,$request,$replacement);$views=json_decode($front->GetBootstrapConsoleView(),true);$view=end($views);$front->ApproveBootstrapCandidate($view['candidate'],$view['digest'],$view['proof']);secBootstrapProof($front,$request,$ctx,'candidateStatus');
$recoveryChoice=array_replace($choice,['vaultDirectory'=>str_replace('/secrets-native-data/','//secrets-native-data///',$choice['vaultDirectory'])]);
$plan=secBootstrapProof($front,$request,$ctx,'planPreview',$recoveryChoice)['data'];$o=json_decode(json_encode(secBootstrapProof($front,$request,$ctx,'applyOptions',['planDigest'=>$plan['planDigest']])['data']),true);
$result=secBootstrapProof($front,$request,$ctx,'applyVerify',['planDigest'=>$plan['planDigest'],'credential'=>secAssertion($replacement,$o['options']['challenge'],1)]);
$ok($result['data']['status']==='COMMITTED','Console recovery failed.');$after=$store->read()['state'];$ok(isset($after['identity']['credentials'][$replacement['id']])&&$after['vault']===$before,'Recovery reset data or omitted the approved credential.');

// Journal publication uncertainty, authenticated encryption, immutable decisions and fencing.
foreach(['before_publish','after_publish','after_sync']as$point){
    $base=rtrim(IPS_GetKernelDir(),'/').'/fault-'.$point;$faulted=false;
    $j=new SecretsBootstrapJournal($base.'/data',$base.'/keys',true,static function($at)use($point,&$faulted){if(!$faulted&&$at===$point){$faulted=true;throw new RuntimeException('Injected I/O failure');}});
    $no(fn()=>$j->locked(fn()=>$j->write('decision-test',['status'=>'ACCEPTED','canary'=>'PRIVATE-REGISTRATION-CANARY'])),'Injected journal interruption did not propagate.');
    $clean=new SecretsBootstrapJournal($base.'/data',$base.'/keys');
    $record=$clean->locked(fn()=>$clean->read('decision-test'));$ok(($record!==null)===($point!=='before_publish'),'Journal misclassified publication uncertainty.');
    if($point==='before_publish')$no(fn()=>$clean->locked(fn()=>$clean->write('decision-test',['status'=>'CANCELLED'])),'Unknown publication permitted a competing decision.');
    else{$no(fn()=>$clean->locked(fn()=>$clean->write('decision-test',['status'=>'CANCELLED'])),'Immutable decision was overwritten.');
        $operation=SecretsBackendCodec::uuid();$one=$clean->locked(fn()=>$clean->fence($operation,'runtime-a'));$two=$clean->locked(fn()=>$clean->fence($operation,'runtime-b'));
        $no(fn()=>$clean->locked(fn()=>$clean->checkFence($operation,'runtime-a',$one)),'Superseded worker was not fenced.');$ok($two==='2','Worker generations did not advance.');}
    foreach(glob($base.'/data/*.sealed')?:[]as$file)$ok(!str_contains(file_get_contents($file),'PRIVATE-REGISTRATION-CANARY'),'Journal wrote registration context as plaintext.');
    unlink($base.'/keys/journal.key');$no(fn()=>new SecretsBootstrapJournal($base.'/data',$base.'/keys',true),'Missing journal key was regenerated.');
}

// No backend: exactly one disabled native instance is created for the planned UUID/paths.
$priorModules=$GLOBALS['moduleIDs'];$GLOBALS['moduleIDs']=[700=>'{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}',6300=>'{8D6AE8F7-EA3A-4513-AA14-C3F9613B0E83}'];
$auto=new SecretsFrontend(6300);$auto->Create();$request=['origin'=>'https://secrets.example.test','cookie'=>'','csrf'=>'','remote'=>'test'];$auto->OpenBootstrap($request['origin'],'',false,true);$key=secKey();$ctx=secBootstrapCandidate($auto,$request,$key);$view=json_decode($auto->GetBootstrapConsoleView(),true)[0];$auto->ApproveBootstrapCandidate($view['candidate'],$view['digest'],$view['proof']);$status=secBootstrapProof($auto,$request,$ctx,'candidateStatus')['data'];$defaults=$status['discovery']['backends'][0]['defaults'];
$choice=['backend'=>0,'portal'=>0,'documentation'=>0,'theme'=>'system','vaultDirectory'=>$defaults['vaultDirectory'],'keyDirectory'=>$defaults['keyDirectory'],'addPortalLink'=>false,'debugEnabled'=>false,'privateACLConfirmed'=>true,'persistenceConfirmed'=>true];
$plan=secBootstrapProof($auto,$request,$ctx,'planPreview',$choice)['data'];$o=json_decode(json_encode(secBootstrapProof($auto,$request,$ctx,'applyOptions',['planDigest'=>$plan['planDigest']])['data']),true);$result=secBootstrapProof($auto,$request,$ctx,'applyVerify',['planDigest'=>$plan['planDigest'],'credential'=>secAssertion($key,$o['options']['challenge'],1)]);
$ok($result['data']['status']==='COMMITTED'&&$result['data']['authenticated'],'Automatic backend creation failed: '.($auto->values['Status']??''));
$ok(count(IPS_GetInstanceListByModuleID('{52165EDD-B2C0-40EC-8A59-42A97319B6E2}'))===1,'Automatic setup created multiple backends.');$ok($auto->RecoverBootstrap(),'Automatic creation was not idempotent.');
// Lost object-creation acknowledgement remains UNKNOWN; no blind second object.
$GLOBALS['moduleIDs']=[700=>'{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}',6400=>'{8D6AE8F7-EA3A-4513-AA14-C3F9613B0E83}'];
$unknown=new SecretsFrontend(6400);$unknown->Create();$request=['origin'=>'https://secrets.example.test','cookie'=>'','csrf'=>'','remote'=>'test'];$unknown->OpenBootstrap($request['origin'],'',false,true);$key=secKey();$ctx=secBootstrapCandidate($unknown,$request,$key);$view=json_decode($unknown->GetBootstrapConsoleView(),true)[0];$unknown->ApproveBootstrapCandidate($view['candidate'],$view['digest'],$view['proof']);$status=secBootstrapProof($unknown,$request,$ctx,'candidateStatus')['data'];$defaults=$status['discovery']['backends'][0]['defaults'];$choice=array_replace($choice,['vaultDirectory'=>$defaults['vaultDirectory'],'keyDirectory'=>$defaults['keyDirectory']]);
$plan=secBootstrapProof($unknown,$request,$ctx,'planPreview',$choice)['data'];$o=json_decode(json_encode(secBootstrapProof($unknown,$request,$ctx,'applyOptions',['planDigest'=>$plan['planDigest']])['data']),true);$GLOBALS['loseBootstrapCreation']=true;
$result=secBootstrapProof($unknown,$request,$ctx,'applyVerify',['planDigest'=>$plan['planDigest'],'credential'=>secAssertion($key,$o['options']['challenge'],1)]);$GLOBALS['loseBootstrapCreation']=false;
$ok($result['data']['status']==='RECOVERY_REQUIRED','Unknown object-create result was claimed committed.');$unknownId=$GLOBALS['lastCreatedBackend'];$count=count(IPS_GetInstanceListByModuleID('{52165EDD-B2C0-40EC-8A59-42A97319B6E2}'));
$ok(!$unknown->RecoverBootstrap()&&count(IPS_GetInstanceListByModuleID('{52165EDD-B2C0-40EC-8A59-42A97319B6E2}'))===$count,'Unknown object create was blindly repeated.');
$ok(str_contains($unknown->GetConfigurationForm(),'Resolve uncertain backend creation'),'Missing targeted console resolution for ambiguous object creation.');
$ok($unknown->ResolveBootstrapBackend($ctx['operation'],$unknownId)&&$unknown->RecoverBootstrap(),'Explicit console resolution failed.');
$GLOBALS['moduleIDs']=$priorModules+$GLOBALS['moduleIDs'];

// Independent OS processes compete on the same journal decision name.
if(function_exists('pcntl_fork')){
    $base=rtrim(IPS_GetKernelDir(),'/').'/process-race';$race=new SecretsBootstrapJournal($base.'/data',$base.'/keys',true);
    $pid=pcntl_fork();if($pid===0){try{$race->locked(fn()=>$race->write('decision-race',['winner'=>'child']));exit(0);}catch(Throwable $e){exit(2);}}
    try{$race->locked(fn()=>$race->write('decision-race',['winner'=>'parent']));}catch(Throwable $e){}
    pcntl_waitpid($pid,$status);$winner=$race->locked(fn()=>$race->read('decision-race'));
    $ok(in_array($winner['winner'],['parent','child'],true),'Process race lost the immutable decision.');
}

// HTTP method/override gate happens before any dispatch, including Prepare/Resume.
$settings=array_replace(SecretsFrontendConfiguration::DEFAULTS,['Enabled'=>true,'AdminOrigin'=>'https://secrets.example.test']);$calls=0;
$server=['REQUEST_URI'=>'/hook/secrets_frontend_123','HTTP_HOST'=>'secrets.example.test','HTTP_ORIGIN'=>'https://secrets.example.test','CONTENT_TYPE'=>'application/json'];
foreach(['GET','HEAD','PUT','PATCH','DELETE','OPTIONS']as$method){$r=SecretsFrontendHttp::response($settings,123,$server+['REQUEST_METHOD'=>$method],'/hook/secrets_frontend_123','','','{"action":"bootstrapPrepare","data":{}}',static function()use(&$calls){$calls++;});$ok($calls===0,'Non-POST dispatched a bootstrap action.');}
$r=SecretsFrontendHttp::response($settings,123,$server+['REQUEST_METHOD'=>'POST','HTTP_X_HTTP_METHOD_OVERRIDE'=>'GET'],'/hook/secrets_frontend_123','','','{}',static function()use(&$calls){$calls++;});$ok($r['status']===405&&$calls===0,'Method override reached the dispatcher.');
$no(fn()=>SecretsFrontendConfiguration::decode('{"x":1,"x":2}'),'Duplicate keys accepted.');
$badKey=secJwk(secKey());$badKey['d']='private';$no(fn()=>SecretsBootstrapVerifier::publicKey($badKey),'Private/unknown JWK fields accepted.');
$no(fn()=>SecretsBootstrapVerifier::rawSignature(str_repeat("\0",64)),'Zero ECDSA scalars accepted.');
// WebAuthn authenticates the original clientDataJSON bytes, not a reserialized substitute.
$k=secKey();$challenge=SecretsBackendCodec::b64(random_bytes(32));$context=['challenge'=>$challenge,'origin'=>'https://secrets.example.test','owner'=>SecretsBackendCodec::b64(random_bytes(32)),'userHandle'=>SecretsBackendCodec::b64(random_bytes(32))];
$entry=SecretsBootstrapVerifier::registration(secRegistration($k,$challenge),$context);$get=SecretsBackendCodec::b64(random_bytes(32));$assertion=secAssertion($k,$get,1);
$ok(SecretsBootstrapVerifier::assertion($entry,$assertion,$get,$context['origin'])===1,'Original clientDataJSON bytes failed.');
$changed=$assertion;$object=json_decode(SecretsBackendCodec::unb64($assertion['response']['clientDataJSON']),true);$changed['response']['clientDataJSON']=SecretsBackendCodec::b64(json_encode($object));
$no(fn()=>SecretsBootstrapVerifier::assertion($entry,$changed,$get,$context['origin']),'Reserialized clientDataJSON substituted for signed bytes.');
foreach(['crossOrigin'=>true,'topOrigin'=>'https://secrets.example.test']as$field=>$value){
    $modified=$assertion;$obj=$object;$obj[$field]=$value;$raw=SecretsBackendCodec::json($obj);$modified['response']['clientDataJSON']=SecretsBackendCodec::b64($raw);openssl_sign(SecretsBackendCodec::unb64($modified['response']['authenticatorData']).hash('sha256',$raw,true),$sig,$k['private'],OPENSSL_ALGO_SHA256);$modified['response']['signature']=SecretsBackendCodec::b64($sig);
    $no(fn()=>SecretsBootstrapVerifier::assertion($entry,$modified,$get,$context['origin']),'Signed unexpected iframe/cross-origin context accepted.');
}
echo "PASS $checks code-free bootstrap approval, PoP, nonce/resume, cancellation, restart/genesis, recovery, journal I/O/fencing and HTTP-method checks\n";
