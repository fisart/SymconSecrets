<?php
declare(strict_types=1);
require_once __DIR__.'/SymconHarness.php';
$GLOBALS['testKernel']=str_replace('\\','/',sys_get_temp_dir()).'/sec-bootstrap-kernel-'.bin2hex(random_bytes(8)).'/';
$bootstrapFixturePID=getmypid();
register_shutdown_function(static function()use($bootstrapFixturePID):void{if(getmypid()!==$bootstrapFixturePID)return;$remove=static function($p)use(&$remove){if(is_dir($p)&&!is_link($p)){foreach(scandir($p)as$n)if($n!=='.'&&$n!=='..')$remove($p.'/'.$n);rmdir($p);}elseif(file_exists($p)||is_link($p))unlink($p);};if(is_dir($GLOBALS['testKernel']))$remove(rtrim($GLOBALS['testKernel'],'/'));});
require_once __DIR__.'/../../SecretsBackend/tests/Fixture.php';
require_once __DIR__.'/../module.php';
require_once __DIR__.'/../../SecretsBackend/module.php';
function SECB_GetInitialSetupInfo(int $id): string { return $GLOBALS['instances'][$id]->GetInitialSetupInfo(); }
function SECB_ConfigureInitialSetup(int $id,int $front,string $digest,string $json): bool { return $GLOBALS['instances'][$id]->ConfigureInitialSetup($front,$digest,$json); }
function SECB_GetNativeInfo(int $id): string { return $GLOBALS['instances'][$id]->GetNativeInfo(); }
function SECB_HandleFrontendRequest(int $id,int $front,string $json): string { return $GLOBALS['instances'][$id]->HandleFrontendRequest($front,$json); }
function SECB_CompleteBootstrap(int $id,int $front,string $intent,string $runtime,string $worker): bool { if($GLOBALS['pauseBootstrap']??false)throw new RuntimeException('Injected worker interruption');return $GLOBALS['instances'][$id]->CompleteBootstrap($front,$intent,$runtime,$worker); }
function SECB_BootstrapLogin(int $id,int $front,string $intent,string $runtime): string { return $GLOBALS['instances'][$id]->BootstrapLogin($front,$intent,$runtime); }
function SECF_BootstrapRuntime(int $id): string { return $GLOBALS['instances'][$id]->BootstrapRuntime(); }
function SECB_GetBootstrapRecoveryInfo(int $id,int $front): string { return $GLOBALS['instances'][$id]->GetBootstrapRecoveryInfo($front); }
function SECB_CompleteBootstrapRecovery(int $id,int $front,string $json): string { return $GLOBALS['instances'][$id]->CompleteBootstrapRecovery($front,$json); }
function IPS_CreateInstance(string $module): int { $id=max(array_keys($GLOBALS['instances']))+1;$GLOBALS['moduleIDs'][$id]=$module;$instance=new SecretsBackend($id);$instance->Create();$GLOBALS['lastCreatedBackend']=$id;if($GLOBALS['loseBootstrapCreation']??false)throw new RuntimeException('Injected lost object creation acknowledgement');return $id; }
function secBootstrapCandidate(SecretsFrontend $front,array &$request,array $key,bool $reuse=false): array
{
    $gateway=new ReflectionMethod(SecretsFrontend::class,'gateway');
    $invoke=static function(string $action,array $data=[])use($gateway,$front,&$request):array{
        $r=$gateway->invoke($front,['action'=>$action,'data'=>$data]+$request);
        if($r['status']!==200)throw new RuntimeException($action.': '.json_encode($r));return $r;
    };
    $prepared=$gateway->invoke($front,['action'=>'bootstrapPrepare','data'=>$reuse?['reuse'=>true]:[]]+$request);
    // Use one prepare and its exact cookie; an earlier candidate cannot replace it.
    $p=json_decode(json_encode($prepared['data']),true);$request['cookie']=explode(';',$prepared['cookie'])[0];$request['csrf']=$p['csrf'];
    $browser=secKey();$jwk=secJwk($browser);$keyDigest=SecretsBootstrapVerifier::publicKey($jwk)['digest'];$credential=$reuse?secAssertion($key,$p['options']['challenge'],1):secRegistration($key,$p['options']['challenge']);
    $bytes=implode("\n",[$reuse?'SECF.BOOTSTRAP.REUSE.1':'SECF.BOOTSTRAP.SUBMIT.1',$request['origin'],'/hook/secrets_frontend_'.$front->InstanceID,$p['frontend'],$p['intent'],$p['prepare'],$p['options']['challenge'],$keyDigest,SecretsBootstrapVerifier::digest($credential)])."\n";
    $c=$invoke('bootstrapSubmit',['prepare'=>$p['prepare'],'key'=>$jwk,'credential'=>$credential,'signature'=>secRawSign($browser,$bytes)])['data'];
    return $c+['browser'=>$browser,'frontend'=>$p['frontend'],'intent'=>$p['intent'],'operation'=>'-'];
}
function secBootstrapProof(SecretsFrontend $front,array &$request,array &$ctx,string $action,array $body=[],bool $send=true): array
{
    $raw=$body?SecretsBackendCodec::json($body):'{}';
    $m=['version'=>'SECF.Bootstrap.PoP.1','purpose'=>'request','origin'=>$request['origin'],'path'=>'/hook/secrets_frontend_'.$front->InstanceID,'frontend'=>$ctx['frontend'],'intent'=>$ctx['intent'],'candidate'=>$ctx['candidate'],'candidateDigest'=>$ctx['candidateDigest'],'keyDigest'=>$ctx['keyDigest'],'epoch'=>$ctx['epoch'],'request'=>SecretsBackendCodec::uuid(),'nonce'=>$ctx['nonce'],
        'operation'=>in_array($action,['applyOptions','applyVerify','operationStatus','cancel'],true)?$ctx['operation']:'-','action'=>$action,'body'=>SecretsBackendCodec::b64($raw)];
    $m['signature']=secRawSign($ctx['browser'],SecretsBootstrapVerifier::signingBytes($m,$raw));if(!$send)return $m;
    $r=(new ReflectionMethod(SecretsFrontend::class,'gateway'))->invoke($front,['action'=>'bootstrapProof','data'=>$m]+$request);
    if($r['status']!==200)throw new RuntimeException($action.': '.json_encode($r));
    foreach(['epoch','nonce','operation']as$k)if(isset($r['data'][$k]))$ctx[$k]=$r['data'][$k];return $r;
}
function secBootstrapInitialize(SecretsFrontend $front,array &$request,array $key,array $choice): array
{
    $front->OpenBootstrap($request['origin'],'',false,true);$ctx=secBootstrapCandidate($front,$request,$key);
    $views=json_decode($front->GetBootstrapConsoleView(),true);$view=end($views);$front->ApproveBootstrapCandidate($view['candidate'],$view['digest'],$view['proof']);
    secBootstrapProof($front,$request,$ctx,'candidateStatus');
    $plan=secBootstrapProof($front,$request,$ctx,'planPreview',$choice)['data'];
    $begin=json_decode(json_encode(secBootstrapProof($front,$request,$ctx,'applyOptions',['planDigest'=>$plan['planDigest']])['data']),true);
    return secBootstrapProof($front,$request,$ctx,'applyVerify',['planDigest'=>$plan['planDigest'],'credential'=>secAssertion($key,$begin['options']['challenge'],1)]);
}
