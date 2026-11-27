<?php
declare(strict_types=1);
require_once __DIR__.'/../NativeLegacyHTTPS.php';
$checks=0;
$ok=static function(bool $value,string $message)use(&$checks):void{if(!$value)throw new RuntimeException($message);++$checks;};
$no=static function(callable $call,string $message)use(&$checks):void{try{$call();}catch(RuntimeException $e){++$checks;return;}throw new RuntimeException($message);};
$strict=['mode'=>'strict'];$pin=['mode'=>'pinned','fingerprint'=>str_repeat('a',64)];
$ok(SecretsBackendNativeLegacyHTTPS::policy($strict)===$strict,'Strict policy changed.');
$no(fn()=>SecretsBackendNativeLegacyHTTPS::policy($pin),'A new pin exception was accepted.');
$ok(SecretsBackendNativeLegacyHTTPS::effectivePolicy($pin)===$strict,'An old saved exception was not upgraded to strict verification.');
foreach([['mode'=>'none'],['mode'=>'pinned'],['mode'=>'pinned','fingerprint'=>'bad'],['mode'=>'strict','verify_peer'=>false],$pin+['verify_peer'=>false]]as$invalid){
    $no(fn()=>SecretsBackendNativeLegacyHTTPS::effectivePolicy($invalid),'An invalid policy silently weakened verification.');
}
$url='https://peer.example:46901/hook/secrets_peer_123';
$old=[['descriptor'=>['endpoint'=>$url],'httpsPolicy'=>$pin],['descriptor'=>['endpoint'=>$url],'httpsPolicy'=>['mode'=>'pinned','fingerprint'=>str_repeat('b',64)]]];
$ok(SecretsBackendNativeLegacyHTTPS::proposal($url,$old)===['policy'=>$strict,'source'=>'saved connection'],'Re-pairing retained old certificate pins.');
$ok(SecretsBackendNativeLegacyHTTPS::proposal($url)['policy']===$strict,'New pairing did not require strict verification.');
echo "PASS $checks strict-only policy checks: reject new exceptions, upgrade saved pins, reject malformed policies and keep new/replacement pairing strict\n";
