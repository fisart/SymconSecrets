<?php
declare(strict_types=1);
require_once __DIR__.'/../QuorumBundle.php';
$b=new SecretsBackendQuorumBundle(); $n=0;
$ok=static function(bool $pass,string $why) use (&$n): void {if(!$pass)throw new RuntimeException($why);++$n;};
$no=static function(callable $f) use (&$n): void {try{$f();}catch(Throwable $e){++$n;return;}throw new RuntimeException('Expected rejection.');};
$uuid=static fn(int $n):string=>sprintf('00000000-0000-4000-8000-%012d',$n);
$base=static fn(string $s):string=>SecretsBackendCodec::b64(str_repeat($s,32));
$c=['version'=>'1','clusterId'=>$uuid(1),'realmId'=>$uuid(2),'incarnation'=>$base('i'),'scopeId'=>$uuid(3),'scopeKind'=>'GLOBAL','ownerNodeId'=>null,'generation'=>'1','keyId'=>$base('k'),'algorithm'=>'AES-128-GCM'];
$key=hex2bin('000102030405060708090a0b0c0d0e0f');$test=$b->keyTest($c,$key);
$pair=sodium_crypto_box_seed_keypair(str_repeat("\x42",32));$r=['id'=>$uuid(4),'kind'=>'PEER','publicKey'=>SecretsBackendCodec::b64(sodium_crypto_box_publickey($pair))];
$env=$b->wrapKey($c,$key,$test,$r);$ok($b->unwrapKey($c,$env['descriptor'],$env['bytes'],$pair,$test)===$key,'Envelope roundtrip.');
$recovery=sodium_crypto_box_seed_keypair(str_repeat("\x43",32));$rr=['id'=>$uuid(5),'kind'=>'RECOVERY','publicKey'=>SecretsBackendCodec::b64(sodium_crypto_box_publickey($recovery))];
$backup=$b->wrapKey($c,$key,$test,$rr);$ok($b->unwrapKey($c,$backup['descriptor'],$backup['bytes'],$recovery,$test)===$key,'Offline recovery independent of peer key.');
$no(fn()=>$b->unwrapKey($c,$env['descriptor'],$env['bytes'],$recovery,$test));
$no(fn()=>$b->unwrapKey($c,$env['descriptor'],$env['bytes'].'x',$pair,$test));
foreach(['clusterId'=>$uuid(6),'realmId'=>$uuid(7),'incarnation'=>$base('j'),'scopeId'=>$uuid(8),'generation'=>'2','keyId'=>$base('q')] as $field=>$value){$bad=$c;$bad[$field]=$value;$no(fn()=>$b->unwrapKey($bad,$env['descriptor'],$env['bytes'],$pair,$test));}
$bad=$env['descriptor'];$bad['recipient']['id']=$uuid(9);$no(fn()=>$b->unwrapKey($c,$bad,$env['bytes'],$pair,$test));
$bad=$env['descriptor'];$bad['extra']='unrecognized';$no(fn()=>$b->unwrapKey($c,$bad,$env['bytes'],$pair,$test));
$no(fn()=>$b->unwrapKey($c,$env['descriptor'],$env['bytes'],$pair,$b->keyTest($c,$key)));
// Even with a correctly wrapped key, a substituted test encrypted under another
// key cannot certify this data key.
$otherTest=$b->keyTest($c,str_repeat('z',16));$no(fn()=>$b->wrapKey($c,$key,$otherTest,$r));
$local=$c;$local['scopeKind']='LOCAL';$local['ownerNodeId']=$uuid(10);$localTest=$b->keyTest($local,$key);
$no(fn()=>$b->wrapKey($local,$key,$localTest,$r));
$localRecovery=$b->wrapKey($local,$key,$localTest,$rr);$ok($b->unwrapKey($local,$localRecovery['descriptor'],$localRecovery['bytes'],$recovery,$localTest)===$key,'Local offline recovery.');
$localPeer=$r;$localPeer['id']=$local['ownerNodeId'];$localEnv=$b->wrapKey($local,$key,$localTest,$localPeer);$ok($b->unwrapKey($local,$localEnv['descriptor'],$localEnv['bytes'],$pair,$localTest)===$key,'Local owner envelope.');
// Empty object/list, numeric object names, Unicode and fractional values remain
// plaintext bytes within the authenticated object; no metadata canonicalization
// can coerce their secret types or reveal their names to the archive.
$plain='{"ä":[{},[],1.5],"0":"sensitive-value"}';
$id=['id'=>$base('o'),'kind'=>'vault','schema'=>'1','keyId'=>$c['keyId'],'scopeId'=>$c['scopeId']];
$obj=$b->encryptObject($c,$key,$id,$plain);$ok($b->decryptObject($c,$key,$obj['reference'],$obj['bytes'])===$plain,'Typed JSON changed.');
$ok(!str_contains($obj['bytes'],'sensitive-value'),'Plaintext exposed.');
$bad=$obj['reference'];$bad['kind']='identity';$no(fn()=>$b->decryptObject($c,$key,$bad,$obj['bytes']));
$bad=$obj['reference'];$bad['id']=$base('p');$no(fn()=>$b->decryptObject($c,$key,$bad,$obj['bytes']));
$no(fn()=>$b->decryptObject($c,str_repeat('x',16),$obj['reference'],$obj['bytes']));
$no(fn()=>$b->encryptObject($c,$key,$id,str_repeat('x',1048577)));
$manifest=SecretsBackendCodec::seal('encrypted-manifest-placeholder',$key,'test-only-manifest-context');
$built=$b->build($uuid(11),$manifest,[$obj]);$read=$b->read($built['bytes'],$built['bundle']);$ok($read['manifest']===$manifest&&$read['objects'][0]['bytes']===$obj['bytes']&&SecretsBackendCodec::same($read['objects'][0]['reference'],$obj['reference']),'Bundle roundtrip.');
$again=$b->build($uuid(11),$manifest,[$obj]);$ok($built===$again,'Retry reframed unchanged encrypted bytes.');
$no(fn()=>$b->build($uuid(11),$manifest,[$obj,$obj]));
$bad=$obj;$bad['bytes'].='x';$no(fn()=>$b->build($uuid(11),$manifest,[$bad]));
$bad=$built['bundle'];$bad['ref']['id']=$uuid(12);$no(fn()=>$b->read($built['bytes'],$bad));
$bad=$built['bundle'];$bad['indexDigest']=str_repeat('0',64);$no(fn()=>$b->read($built['bytes'],$bad));
$no(fn()=>$b->read(substr($built['bytes'],0,-1),$built['bundle']));
$badBytes=$built['bytes'].'x';$bad=$built['bundle'];$bad['descriptor']['bundleLength']=(string)strlen($badBytes);$bad['descriptor']['bundleDigest']=hash('sha256',$badBytes);$bad['ref']['digest']=hash('sha256',SecretsBackendCodec::canonical($bad['descriptor']));$no(fn()=>$b->read($badBytes,$bad));
// Public interop fixture is deliberately synthetic; no fixture can authorize
// real host admission or replace an authority-approved manifest.
if(in_array('--write-vector',$argv,true)){
 $vector=['description'=>'PUBLIC SYNTHETIC TEST DATA ONLY','context'=>$c,'dataKeyHex'=>bin2hex($key),'scopeTest'=>$test,'recipient'=>$r,'recipientKeypairHex'=>bin2hex($pair),'envelopeDescriptor'=>$env['descriptor'],'envelope'=>SecretsBackendCodec::b64($env['bytes']),'manifest'=>$manifest,'objects'=>[['reference'=>$obj['reference'],'bytes'=>SecretsBackendCodec::b64($obj['bytes'])]],'bundle'=>$built['bundle'],'bytes'=>SecretsBackendCodec::b64($built['bytes'])];
 file_put_contents(__DIR__.'/../quorum/archive/php-bundle-vector.json',json_encode($vector,JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT|JSON_THROW_ON_ERROR)."\n");
}else{
 $v=json_decode(file_get_contents(__DIR__.'/../quorum/archive/php-bundle-vector.json'),true,16,JSON_THROW_ON_ERROR);
 $vb=$b->build($v['bundle']['descriptor']['commitId'],$v['manifest'],array_map(static fn($x)=>['reference'=>$x['reference'],'bytes'=>SecretsBackendCodec::unb64($x['bytes'])],$v['objects']));
 $ok($vb['bytes']===SecretsBackendCodec::unb64($v['bytes'])&&SecretsBackendCodec::same($vb['bundle'],$v['bundle']),'PHP/Go fixture changed.');
 $ok($b->unwrapKey($v['context'],$v['envelopeDescriptor'],SecretsBackendCodec::unb64($v['envelope']),hex2bin($v['recipientKeypairHex']),$v['scopeTest'])===hex2bin($v['dataKeyHex']),'Public key envelope vector changed.');
}
echo "PASS $n V2 key envelope, local-scope access, recovery, object AAD, bundle framing and rejection checks; no activation\n";
