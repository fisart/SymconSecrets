<?php
declare(strict_types=1);
require_once __DIR__.'/../QuorumIntent.php';
$c=new SecretsBackendQuorumIntent();$v=json_decode(file_get_contents(__DIR__.'/../quorum/core/intent-vector.json'),true,20,JSON_THROW_ON_ERROR);$a=$v['approved'];$n=0;
$ok=static function(bool $pass)use(&$n):void{if(!$pass)throw new RuntimeException('PHP/Go core contract differs.');++$n;};
$no=static function(callable $f)use(&$n):void{try{$f();}catch(Throwable $e){++$n;return;}throw new RuntimeException('Expected contract rejection.');};
$key=sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(hex2bin($v['publicTestSeedHex'])));
$ok($c->digest($a['intent'])===$v['intentDigest']);
$actual=$c->sign($a['intent'],$a['approvalRef'],$a['keyId'],$key);$ok(SecretsBackendCodec::same($actual,$a));
$ok(SecretsBackendCodec::same($c->verify(SecretsBackendCodec::json($a),$v['publicKey'],$a['keyId']),$a));
$no(fn()=>$c->verify(SecretsBackendCodec::json($a),$v['publicKey'],SecretsBackendCodec::b64(str_repeat('x',32))));
foreach(['userOperationId'=>SecretsBackendCodec::uuid(),'permittedDiffDigest'=>str_repeat('a',64),'newScopeDigest'=>str_repeat('c',64)] as $field=>$value){$bad=$a;$bad['intent'][$field]=$value;$no(fn()=>$c->verify(SecretsBackendCodec::json($bad),$v['publicKey'],$a['keyId']));}
$bad=$a['intent'];$bad['candidateHead']['incarnation']=SecretsBackendCodec::b64(str_repeat('z',32));$no(fn()=>$c->digest($bad));
$bad=$a['intent'];$bad['changeClass']='SECURITY';$no(fn()=>$c->digest($bad));
$bad=$a['intent'];$bad['changeClass']='LOCAL_EDIT';$no(fn()=>$c->digest($bad));
$bad=$a['intent'];$bad['bundle']['reservationId']=SecretsBackendCodec::uuid();$no(fn()=>$c->digest($bad));
$bad=$a['intent'];$bad['candidateHead']['index']=$bad['expectedHead']['index'];$no(fn()=>$c->digest($bad));
$bad=$a['intent'];$bad['outbox'][]=$bad['outbox'][0];$no(fn()=>$c->digest($bad));
$bad=$a['intent'];$bad['callerSaysApproved']=true;$no(fn()=>$c->digest($bad));
$raw=SecretsBackendCodec::json($a);$raw=preg_replace('/"version":"1"/','"version":"1","version":"1"',$raw,1);$no(fn()=>$c->verify($raw,$v['publicKey'],$a['keyId']));
echo "PASS $n PHP/Go/Python original intent digest/signature, binding, scope and closed-schema checks\n";
