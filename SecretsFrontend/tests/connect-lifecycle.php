<?php
declare(strict_types=1);
require_once __DIR__.'/BootstrapFixture.php';
$GLOBALS['moduleIDs']=[5200=>SecretsBackend::FRONTEND,5201=>'{52165EDD-B2C0-40EC-8A59-42A97319B6E2}',700=>'{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}'];
$hooks=new IPSModule(700);$hooks->properties['Hooks']='[]';$front=new SecretsFrontend(5200);$front->Create();$back=new SecretsBackend(5201);$back->Create();
function CC_GetConnectURL(int $id): string { return $GLOBALS['connectTestUrl']??''; }
$root=sys_get_temp_dir().'/sec-connect-'.bin2hex(random_bytes(8));
$request=['origin'=>'https://secrets.example.test','cookie'=>'','csrf'=>'','remote'=>'connect-test'];
$invoke=static function(string $action,array $data=[])use($front,&$request):array{
 $reply=(new ReflectionMethod(SecretsFrontend::class,'gateway'))->invoke($front,['action'=>$action,'data'=>$data]+$request);
 if($reply['status']!==200)throw new RuntimeException($action.': '.json_encode($reply));return json_decode(json_encode($reply),true);
};
try{
 $key=secKey();$login=secBootstrapInitialize($front,$request,$key,['backend'=>5201,'portal'=>0,'documentation'=>0,'theme'=>'system','vaultDirectory'=>$root.'/data','keyDirectory'=>$root.'/keys','addPortalLink'=>false,'debugEnabled'=>false,'privateACLConfirmed'=>true,'persistenceConfirmed'=>true]);
 $request['cookie']=explode(';',$login['cookie'])[0];$request['csrf']=$login['data']['csrf'];$primary=$request;$counter=1;
 $approved=static function(array $op)use($invoke,$key,&$counter):array{$p=$invoke('prepare',['operation'=>$op])['data'];return $invoke('approve',['challengeId'=>$p['challengeId'],'credential'=>secAssertion($key,$p['options']['challenge'],++$counter)])['data'];};
 $approved(['kind'=>'save','scope'=>'local','path'=>['Connect-test'],'revision'=>'0','mode'=>'create','json'=>'"CONNECT-TEST-VALUE"']);
 $identityBefore=file_get_contents($root.'/data/native.json');
 $origin='https://'.str_repeat('a',32).'.ipmagic.de';
 $approved(['kind'=>'nativeConnectStage','origin'=>$origin]);
 if(!($GLOBALS['fullConnectTest']??false)){$legacyStore=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);$cur=$legacyStore->read();$legacyStore->change($cur['head'],SecretsBackendCodec::uuid(),hash('sha256','legacy-policy-fixture'),static function($s){$s['policy']['backupOrigin']['version']=1;unset($s['policy']['backupOrigin']['rights']);return $s;});}
 $p=$invoke('session')['data']['native']['backupOrigin'];secExpect($p['status']==='pending','Backup was activated without a candidate.');
 $settings=array_replace(SecretsFrontendConfiguration::DEFAULTS,['Enabled'=>true,'AdminOrigin'=>$primary['origin']]);$path='/hook/secrets_frontend_5200';$server=['REQUEST_METHOD'=>'GET','REQUEST_URI'=>$path,'HTTP_HOST'=>parse_url($origin,PHP_URL_HOST),'HTTP_COOKIE'=>'DIAG-COOKIE-CANARY','HTTP_AUTHORIZATION'=>'Bearer DIAG-AUTH-CANARY'];
 $http=SecretsFrontendHttp::response($settings,5200,$server,$path,'','', '',null,['backupOrigin'=>$p]);secExpect($http['status']===403,'Backup host was accepted without HTTPS evidence.');secExpect(str_contains($http['body'],'not supplied')&&str_contains($http['body'],'Check backup connection'),'Blocked Connect request omitted safe transport observations.');secExpect(!str_contains($http['body'],'DIAG-COOKIE-CANARY')&&!str_contains($http['body'],'DIAG-AUTH-CANARY'),'Transport diagnostic exposed request credentials.');
 $server['HTTPS']='on';$http=SecretsFrontendHttp::response($settings,5200,$server,$path,'','', '',null,['backupOrigin'=>$p]);secExpect($http['status']===200&&str_contains($http['body'],'"backupEnrollment":true'),'Pending HTTPS page was not served independently.');
 $server['HTTPS']='off';$server['HTTP_X_FORWARDED_PROTO']='https';$http=SecretsFrontendHttp::response($settings,5200,$server,$path,'','', '',null,['backupOrigin'=>$p]);secExpect($http['status']===403,'Untrusted forwarding headers established HTTPS.');
 $GLOBALS['moduleIDs'][800]=SecretsFrontendConnectDiscovery::MODULE;$connect=new IPSModule(800);$connect->status=102;$GLOBALS['connectTestUrl']=$origin;
 $savedServer=$_SERVER;$savedContext=$GLOBALS['_IPS']??null;$_SERVER=['REQUEST_METHOD'=>'GET','REQUEST_URI'=>$path,'HTTP_HOST'=>parse_url($origin,PHP_URL_HOST),'REMOTE_ADDR'=>'127.0.0.1'];$GLOBALS['_IPS']=['SENDER'=>'WebHook','INSTANCE'=>0];
 ob_start();$front->ProcessHookData();$html=ob_get_clean();secExpect(http_response_code()===200&&str_contains($html,'"backupEnrollment":true'),'Generated Symcon hook rejected the observed loopback Connect relay.');
 $_SERVER=$savedServer;if($savedContext===null)unset($GLOBALS['_IPS']);else $GLOBALS['_IPS']=$savedContext;
 $generation=$p['generation'];$request=['origin'=>$origin,'cookie'=>'','csrf'=>'','remote'=>'connect-test'];
 secReject(static fn()=>$invoke('authOptions'),'Pending origin admitted login.');
 secReject(static fn()=>$invoke('session'),'Pending origin admitted general access.');
 $browser=secKey();$jwk=secJwk($browser);$kd=SecretsBootstrapVerifier::publicKey($jwk)['digest'];$backupKey=secKey();
 $p=$invoke('connectOptions',['key'=>$jwk])['data'];$registration=secRegistration($backupKey,$p['options']['challenge'],$origin);
 $bytes=implode("\n",['SECF.CONNECT.REGISTER.1',$origin,$generation,$p['prepare'],$kd,SecretsBootstrapVerifier::digest($registration)])."\n";
 $test=$invoke('connectSubmit',['prepare'=>$p['prepare'],'credential'=>$registration,'signature'=>secRawSign($browser,$bytes)])['data'];
 $assertion=secAssertion($backupKey,$test['options']['challenge'],1,$origin);
 $bytes=implode("\n",['SECF.CONNECT.TEST.1',$origin,$generation,$test['test'],$kd,SecretsBootstrapVerifier::digest($assertion)])."\n";
 $candidate=$invoke('connectProof',['test'=>$test['test'],'credential'=>$assertion,'signature'=>secRawSign($browser,$bytes)])['data'];
 $statusBytes=implode("\n",['SECF.CONNECT.STATUS.1',$origin,$generation,$candidate['candidate'],$candidate['digest']])."\n";
 $statusRequest=['candidate'=>$candidate['candidate'],'digest'=>$candidate['digest'],'signature'=>secRawSign($browser,$statusBytes)];
 secExpect($invoke('connectStatus',$statusRequest)['data']['state']==='waiting','Passkey possession was treated as activation.');
 secReject(static fn()=>$invoke('connectStatus',array_replace($statusRequest,['signature'=>secRawSign(secKey(),$statusBytes)])),'Unsigned or wrong-browser status was admitted.');

 secReject(static fn()=>$invoke('session'),'Possession-tested candidate obtained general access.');
 secReject(static fn()=>$invoke('connectProof',['test'=>$test['test'],'credential'=>$assertion,'signature'=>secRawSign($browser,$bytes)]),'Possession proof was replayed.');
 $request=$primary;$review=$invoke('connectCandidateReview',['candidate'=>$candidate['candidate']])['data'];secExpect($review['digest']===$candidate['digest'],'Candidate digest differed across origins.');
 secReject(static fn()=>$approved(['kind'=>'nativeConnectActivate','candidate'=>$candidate['candidate'],'digest'=>str_repeat('0',64)]),'Changed candidate digest was admitted.');
 $approved(['kind'=>'nativeConnectActivate','candidate'=>$candidate['candidate'],'digest'=>$candidate['digest']]);
 $primarySession=$invoke('session')['data'];secExpect($primarySession['native']['backupOrigin']['status']==='active','Backup not activated.');
 if(!($GLOBALS['fullConnectTest']??false))secReject(static fn()=>$approved(['kind'=>'revoke','credentialId'=>$key['id']]),'Limited backup credential was counted as the last full route.');
 $request=['origin'=>$origin,'cookie'=>'','csrf'=>'','remote'=>'connect-test'];
 secExpect($invoke('connectStatus',$statusRequest)['data']['state']==='active','Exact candidate activation was not reported.');secReject(static fn()=>$invoke('session'),'Activation status granted a general session.');
 $options=$invoke('authOptions')['data'];$ids=array_column($options['options']['allowCredentials'],'id');secExpect($ids===[$backupKey['id']],'Backup login offered primary credentials.');
 secReject(static fn()=>$invoke('authVerify',['challengeId'=>$options['challengeId'],'credential'=>secAssertion($key,$options['options']['challenge'],10,$origin)]),'Primary credential logged in at backup.');
 $options=$invoke('authOptions')['data'];$logged=$invoke('authVerify',['challengeId'=>$options['challengeId'],'credential'=>secAssertion($backupKey,$options['options']['challenge'],2,$origin)]);
 $request['cookie']=explode(';',$logged['cookie'])[0];$request['csrf']=$logged['data']['csrf'];$backupSession=$request;$backupCounter=2;
 secExpect($invoke('session')['data']['native']['backupOrigin']['status']==='active','Backup session unavailable.');
 $revealed=$invoke('sessionReveal',['operation'=>['kind'=>'reveal','scope'=>'local','path'=>['Connect-test'],'revision'=>$invoke('session')['data']['revision']]])['data'];secExpect(str_contains(json_encode($revealed),'CONNECT-TEST-VALUE'),'Backup could not access the existing vault value.');
 if($GLOBALS['upgradeMagicTest']??false){require __DIR__.'/full-connect-upgrade-operations.php';}
 if($GLOBALS['fullConnectTest']??false){
  $peerTransport=new ReflectionMethod(SecretsBackend::class,'nativePeerTransportOrigin');$relay=['HTTP_HOST'=>parse_url($origin,PHP_URL_HOST),'REMOTE_ADDR'=>'127.0.0.1'];
  secExpect($peerTransport->invoke($back,$relay)===$origin,'Peer hook rejected the active exact Connect relay.');
  secExpect((new ReflectionMethod(SecretsBackend::class,'nativePairingPage'))->invoke($back,parse_url($origin,PHP_URL_HOST))===$origin.'/hook/secrets_frontend_5200','Magic peer landing redirected to primary.');
  foreach([['REMOTE_ADDR'=>'198.51.100.2'],['HTTP_X_FORWARDED_HOST'=>parse_url($origin,PHP_URL_HOST)],['HTTPS'=>'off']]as$override)secReject(static fn()=>$peerTransport->invoke($back,array_replace($relay,$override)),'Untrusted peer transport was admitted.');
  require __DIR__.'/full-connect-operations.php';$backupSession=$request;
 }
 $back->ApplyChanges();secExpect($back->Recover(),'Native restart recovery failed.');secReject(static fn()=>$invoke('session'),'Restart kept the backup session.');
 $options=$invoke('authOptions')['data'];$logged=$invoke('authVerify',['challengeId'=>$options['challengeId'],'credential'=>secAssertion($backupKey,$options['options']['challenge'],($GLOBALS['fullConnectTest']??false)?++$backupCounter:3,$origin)]);$request['cookie']=explode(';',$logged['cookie'])[0];$request['csrf']=$logged['data']['csrf'];$backupSession=$request;
 $revealed=$invoke('sessionReveal',['operation'=>['kind'=>'reveal','scope'=>'local','path'=>['Connect-test'],'revision'=>$invoke('session')['data']['revision']]])['data'];secExpect(str_contains(json_encode($revealed),'CONNECT-TEST-VALUE'),'Restart lost access to existing values.');secExpect(file_get_contents($root.'/data/native.json')===$identityBefore,'Connect setup changed the pinned vault identity.');
 $request=$primary;$options=$invoke('authOptions')['data'];$logged=$invoke('authVerify',['challengeId'=>$options['challengeId'],'credential'=>secAssertion($key,$options['options']['challenge'],++$counter)]);$request['cookie']=explode(';',$logged['cookie'])[0];$request['csrf']=$logged['data']['csrf'];$primary=$request;$request=$backupSession;

 if(!($GLOBALS['fullConnectTest']??false))secReject(static fn()=>$invoke('prepare',['operation'=>['kind'=>'nativeConnectRevoke','origin'=>$origin,'generation'=>$generation]]),'Limited backup session changed administrator routes.');
 $request['cookie']=$primary['cookie'];$request['csrf']=$primary['csrf'];secReject(static fn()=>$invoke('session'),'Primary cookie was accepted on backup.');$request=$backupSession;
 $staleLogin=$invoke('authOptions')['data'];
 $request=$primary;$primaryOptions=$invoke('authOptions')['data'];secExpect(!in_array($backupKey['id'],array_column($primaryOptions['options']['allowCredentials'],'id'),true),'Primary offered backup credential.');
 $approved(['kind'=>'nativeConnectRevoke','origin'=>$origin,'generation'=>$generation]);
 secExpect($invoke('session')['data']['native']['backupOrigin']['status']==='revoked','Primary session lost on backup revocation.');
 if($GLOBALS['fullConnectTest']??false)secReject(static fn()=>$peerTransport->invoke($back,$relay),'Revoked Magic peer route survived.');
 $request=$backupSession;secReject(static fn()=>$invoke('session'),'Revoked backup session survived.');secReject(static fn()=>$invoke('authVerify',['challengeId'=>$staleLogin['challengeId'],'credential'=>secAssertion($backupKey,$staleLogin['options']['challenge'],3,$origin)]),'Paused login survived revocation.');
 $request=$primary;$approved(['kind'=>'nativeConnectStage','origin'=>$origin]);$next=$invoke('session')['data']['native']['backupOrigin'];secExpect($next['generation']!==$generation,'Re-added URL reused its generation.');
 secReject(static fn()=>$invoke('connectCandidateReview',['candidate'=>$candidate['candidate']]),'Old candidate survived re-adding origin.');
 $request=$backupSession;secReject(static fn()=>$invoke('session'),'Re-added URL revived an old session.');
 echo "PASS Connect pending enrollment, browser PoP, separate RP/passkey login, exact primary activation, replay rejection and generation revocation\n";
}finally{$remove=static function($path)use(&$remove){if(is_dir($path)&&!is_link($path)){foreach(scandir($path)as$n)if($n!=='.'&&$n!=='..')$remove($path.'/'.$n);rmdir($path);}elseif(file_exists($path)||is_link($path))unlink($path);};if(is_dir($root))$remove($root);}
