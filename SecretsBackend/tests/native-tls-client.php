<?php
declare(strict_types=1);
require_once __DIR__.'/../NativeRuntime.php';
require_once __DIR__.'/../NativeTLSDiagnostics.php';
final class NativeTLSClientFixture { use SecretsBackendNativeRuntime; }
try{
 if(str_starts_with($argv[2]??'','issuers:')){ $file=substr($argv[2],8); echo json_encode(['ok'=>true,'body'=>SecretsBackendNativeIssuers::run(['verify_peer'=>true,'verify_peer_name'=>true,'allow_self_signed'=>false,'peer_name'=>parse_url($argv[1],PHP_URL_HOST)],static fn($ssl)=>(new ReflectionMethod(SecretsBackendNativeLegacyHTTPS::class,'send'))->invoke(null,$argv[1],'TLS-REQUEST-CANARY',['mode'=>'strict'],$ssl),$file,hash_file('sha256',$file))]);}
 elseif(($argv[2]??'')==='diagnose'){echo json_encode(SecretsBackendNativeTLSDiagnostics::inspect($argv[1],['mode'=>'strict']));}
 elseif(($argv[2]??'')==='baseline'){
  $h=curl_init($argv[1]);curl_setopt_array($h,[CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>'TLS-REQUEST-CANARY',CURLOPT_RETURNTRANSFER=>true,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_FOLLOWLOCATION=>false,CURLOPT_TIMEOUT=>5]);$body=curl_exec($h);echo json_encode(['ok'=>$body!==false,'body'=>$body,'curlCode'=>curl_errno($h)]);curl_close($h);
 }else echo json_encode(['ok'=>true,'body'=>NativeTLSClientFixture::nativeHTTPS($argv[1],'TLS-REQUEST-CANARY',str_starts_with($argv[2]??'','pin:')?['mode'=>'pinned','fingerprint'=>substr($argv[2],4)]:['mode'=>'strict'])]);
}catch(SecretsBackendNativePeerDeliveryFailure $e){echo json_encode(['ok'=>false,'problem'=>$e->problem,'curlCode'=>$e->curlCode,'reason'=>$e->certificateReason,'trust'=>SecretsBackendNativePeerDeliveryFailure::tlsDetails(['caTrust'=>$e->caTrust])['caTrust']]);}
