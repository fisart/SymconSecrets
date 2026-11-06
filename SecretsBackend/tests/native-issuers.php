<?php
declare(strict_types=1);
require_once __DIR__.'/../NativeIssuers.php';
$file=__DIR__.'/../certificates/letsencrypt-issuers.pem';$pem=file_get_contents($file);
if(hash('sha256',$pem)!==SecretsBackendNativeIssuers::SHA256)throw new RuntimeException('Issuer bundle differs from reviewed bytes.');
preg_match_all('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s',$pem,$matches);
if(count($matches[0])!==3)throw new RuntimeException('Issuer bundle count differs.');
foreach($matches[0]as$c){
 if(openssl_x509_verify($c,openssl_pkey_get_public($c))===1)throw new RuntimeException('Unexpected self-signed trust anchor.');
 if(openssl_x509_checkpurpose($c,X509_PURPOSE_ANY,[__DIR__.'/../certificates/mozilla-ca.pem'],$file)!==true)throw new RuntimeException('Issuer cannot validate to deployment public roots.');
}
echo "PASS shipped YE2 issuer bytes and all three chains against the deployment CA bundle; no self-signed roots added\n";
