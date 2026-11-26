<?php
declare(strict_types=1);
/** Complete known public chains using only issuers that validate to the configured CA roots. */
final class SecretsBackendNativeIssuers
{
    public const SHA256='8f8f4ace3cef83be4bbd48e77f08959e4ec32aa6c70c5eb472f6dd6a4908d02b';
    public static function run(array $ssl,callable $request,?string $issuerFile=null,?string $expectedHash=null)
    {
        if(!($ssl['verify_peer']??false))return $request($ssl);
        $ca=(string)ini_get('openssl.cafile');
        if($ca===''||!is_file($ca)||!is_readable($ca))return $request($ssl);
        $roots=@file_get_contents($ca,false,null,0,2097153);
        $issuers=@file_get_contents($issuerFile??__DIR__.'/certificates/letsencrypt-issuers.pem',false,null,0,65537);
        if(!is_string($roots)||strlen($roots)>2097152||!is_string($issuers)||strlen($issuers)>65536||!hash_equals($expectedHash??self::SHA256,hash('sha256',$issuers)))return $request($ssl);
        $rootFile=@tempnam(sys_get_temp_dir(),'sec-roots-');$chainFile=@tempnam(sys_get_temp_dir(),'sec-chain-');
        if($rootFile===false||$chainFile===false){if(is_string($rootFile))@unlink($rootFile);if(is_string($chainFile))@unlink($chainFile);return $request($ssl);}
        try{
            if(file_put_contents($rootFile,$roots)!==strlen($roots)||file_put_contents($chainFile,$issuers)!==strlen($issuers))return $request($ssl);
            preg_match_all('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s',$issuers,$matches);$accepted='';
            foreach($matches[0]as$pem){
                $cert=@openssl_x509_read($pem);if($cert===false)continue;$details=@openssl_x509_parse($cert);
                if(!is_array($details)||!str_contains($details['extensions']['basicConstraints']??'','CA:TRUE'))continue;
                // No new trust anchor: each issuer must independently validate through the existing roots.
                if(@openssl_x509_checkpurpose($cert,X509_PURPOSE_ANY,[$rootFile],$chainFile)===true)$accepted.=$pem."\n";
            }
            if($accepted==='')return $request($ssl);
            $combined=$roots."\n".$accepted;if(file_put_contents($rootFile,$combined)!==strlen($combined))return $request($ssl);
            $ssl['cafile']=$rootFile;return $request($ssl);
        }finally{@unlink($rootFile);@unlink($chainFile);}
    }
}
