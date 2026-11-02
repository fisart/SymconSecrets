<?php
declare(strict_types=1);
require_once __DIR__.'/../NativeRuntime.php';
final class NativeTLSClientFixture { use SecretsBackendNativeRuntime; }
try{
 if(($argv[2]??'')==='baseline'){
  $h=curl_init($argv[1]);curl_setopt_array($h,[CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>'TLS-REQUEST-CANARY',CURLOPT_RETURNTRANSFER=>true,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_FOLLOWLOCATION=>false,CURLOPT_TIMEOUT=>5]);$body=curl_exec($h);echo json_encode(['ok'=>$body!==false,'body'=>$body,'curlCode'=>curl_errno($h)]);curl_close($h);
 }else echo json_encode(['ok'=>true,'body'=>NativeTLSClientFixture::nativeHTTPS($argv[1],'TLS-REQUEST-CANARY')]);
}catch(SecretsBackendNativePeerDeliveryFailure $e){echo json_encode(['ok'=>false,'problem'=>$e->problem,'curlCode'=>$e->curlCode,'reason'=>$e->certificateReason,'trust'=>SecretsBackendNativePeerDeliveryFailure::tlsDetails(['caTrust'=>$e->caTrust])['caTrust']]);}
