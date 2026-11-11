<?php
declare(strict_types=1);
require_once __DIR__ . '/NativeStore.php';

final class SecretsBackendNativeHardware
{
    public static function normalize(array $roots,array $aaguids): array
    {
        if(!$roots||count($roots)>16||!$aaguids||count($aaguids)>32)throw new RuntimeException('Select reviewed root certificates and exact hardware AAGUIDs.');
        $clean=[];$hashes=[];$total=0;
        foreach($roots as$i=>$pem){
            if(!is_string($pem)||strlen($pem)>65536||!preg_match('~^\s*-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*$~D',$pem))throw new RuntimeException('Upload public root certificates only, never a private key.');
            $pem=trim($pem)."\n";$total+=strlen($pem);if($total>262144)throw new RuntimeException('Hardware trust upload exceeds its bound.');
            $cert=openssl_x509_read($pem);$parsed=$cert===false?false:openssl_x509_parse($cert);
            if(!is_array($parsed)||!str_contains(strtoupper((string)($parsed['extensions']['basicConstraints']??'')),'CA:TRUE'))throw new RuntimeException('The selected certificate is not a CA trust anchor.');
            $name='root-'.$i.'.pem';$clean[$name]=$pem;$hashes[$name]=hash('sha256',$pem);
        }
        $ids=[];foreach($aaguids as$id){$id=strtolower(str_replace('-','',(string)$id));if(!preg_match('/^[a-f0-9]{32}$/D',$id)||$id===str_repeat('0',32))throw new RuntimeException('Use exact nonzero AAGUIDs from independently reviewed hardware.');$ids[]=$id;}
        return ['roots'=>$clean,'hashes'=>$hashes,'aaguids'=>array_values(array_unique($ids)),'version'=>'hw-'.SecretsBackendCodec::uuid()];
    }
}
