<?php
declare(strict_types=1);
require_once __DIR__.'/../NativeTrust.php';
function trustExpect(bool $ok,string $message): void { if(!$ok)throw new RuntimeException($message); }
function trustReject(callable $f): void {try{$f();}catch(SecretsBackendNativePeerDeliveryFailure $e){trustExpect($e->certificateReason==='ca-store-unavailable','Invalid explicit trust did not fail closed.');return;}throw new RuntimeException('An invalid explicit trust setting was bypassed.');}
$dir=null;
$root=sys_get_temp_dir().'/sec-trust-'.bin2hex(random_bytes(8));mkdir($root,0700);
try{
 $bundle=getenv('SECB_TEST_CA_BUNDLE')?:__DIR__.'/../certificates/mozilla-ca.pem';$bytes=file_get_contents($bundle);trustExpect(hash('sha256',$bytes)===SecretsBackendNativeTrust::BUNDLE_SHA256&&substr_count($bytes,'-----BEGIN CERTIFICATE-----')===118,'Bundled roots differ from the checked official distribution.');
 preg_match('~-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----~',$bytes,$m);$file=$root.'/root.pem';file_put_contents($file,$m[0]);$bad=$root.'/not-a-ca.pem';file_put_contents($bad,'not a certificate');$dir=$root.'/hashed';mkdir($dir);if(getenv('SECB_TEST_TRUST_FAIL_AFTER_DIRECTORY'))throw new RuntimeException('Injected failure after directory creation.');$hash=openssl_x509_parse($m[0])['hash'];file_put_contents($dir.'/'.$hash.'.0',$m[0]);
 $p=SecretsBackendNativeTrust::resolve(['curlFile'=>$file,'openssl'=>['ini_cafile'=>$bad],'environment'=>['SSL_CERT_FILE'=>$bad]]);trustExpect($p['source']==='curl-configured'&&$p['file']===$file&&$p['directory']===null,'cURL explicit trust lost precedence.');
 $p=SecretsBackendNativeTrust::resolve(['openssl'=>['ini_cafile'=>$file,'ini_capath'=>$dir],'curlDefaultFile'=>$bad]);trustExpect($p['source']==='openssl-configured'&&$p['directory']===$dir,'PHP OpenSSL trust was not bridged to cURL.');
 $p=SecretsBackendNativeTrust::resolve(['environment'=>['SSL_CERT_FILE'=>$file]]);trustExpect($p['source']==='environment-configured','Explicit environment trust was ignored.');
 foreach([['curlFile'=>$root.'/missing'],['curlFile'=>$bad],['curlFile'=>'https://attacker.example/ca.pem'],['openssl'=>['ini_capath'=>$root]],['environment'=>['SSL_CERT_FILE'=>$bad]]]as$input)trustReject(static fn()=>SecretsBackendNativeTrust::resolve($input));
 trustExpect(SecretsBackendNativeTrust::resolve(['tlsBackend'=>'Schannel'])['source']==='native','Native Windows trust was replaced.');
 trustExpect(SecretsBackendNativeTrust::resolve(['curlDefaultFile'=>$file])['source']==='curl-default','Usable cURL default was ignored.');
 trustExpect(SecretsBackendNativeTrust::resolve(['curlDefaultFile'=>$bad,'openssl'=>['default_cert_file'=>$file]])['source']==='openssl-default','Missing embedded cURL roots did not use the host OpenSSL roots.');
 trustExpect(SecretsBackendNativeTrust::resolve(['systemFiles'=>[$bad,$file]])['source']==='system','System CA discovery failed.');
 trustExpect(SecretsBackendNativeTrust::resolve([])['source']==='bundled','No-store runtime did not use its verified module bundle.');
 echo "PASS native CA trust: explicit precedence/fail-closed overrides, PHP-to-cURL bridge, hashed stores, native Windows trust, system discovery and pinned Mozilla fallback\n";
}finally{
 // Cleanup owns only this freshly created tree, including on early failure.
 $clean=static function(string $path)use(&$clean):void{if(is_link($path)||!is_dir($path)){if(file_exists($path)||is_link($path))unlink($path);return;}foreach(scandir($path)as$name)if($name!=='.'&&$name!=='..')$clean($path.'/'.$name);rmdir($path);};
 if($root!==''&&dirname($root)===sys_get_temp_dir()&&str_starts_with(basename($root),'sec-trust-')&&is_dir($root)&&!is_link($root))$clean($root);
}
