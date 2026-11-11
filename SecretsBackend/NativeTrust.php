<?php
declare(strict_types=1);
require_once __DIR__.'/NativePeer.php';

/** Resolve host trust explicitly for embedded PHP/cURL; never learns trust from a peer. */
final class SecretsBackendNativeTrust
{
    public const BUNDLE_DATE='2026-10-20';
    public const BUNDLE_SHA256='796f1389bfea13c0ed78f663b765baaff54a508e5483786bd6ece73c5e3e3cbe';
    public const SOURCES=['curl-configured','openssl-configured','environment-configured','curl-default','openssl-default','system','bundled','native','unavailable'];
    private static function pem(string $path): bool
    {
        if($path===''||str_contains($path,'://')||!is_file($path)||!is_readable($path))return false;
        $size=filesize($path);if(!is_int($size)||$size<64||$size>4194304)return false;
        $bytes=file_get_contents($path);return is_string($bytes)&&preg_match('~-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----~',$bytes,$m)===1&&@openssl_x509_read($m[0])!==false;
    }
    private static function directoryCertificate(string $path): ?string
    {
        if($path===''||str_contains($path,'://')||!is_dir($path)||!is_readable($path))return null;
        $h=opendir($path);if($h===false)return null;
        try{for($i=0;$i<8192&&($name=readdir($h))!==false;$i++)if(preg_match('/^[a-f0-9]{8}\.[0-9]+$/iD',$name)&&self::pem($path.DIRECTORY_SEPARATOR.$name))return $path.DIRECTORY_SEPARATOR.$name;}finally{closedir($h);}
        return null;
    }
    private static function plan(string $source,string $file,string $directory,bool $explicit=false): ?array
    {
        $fileOK=$file!==''&&self::pem($file);$directoryCert=self::directoryCertificate($directory);$dirOK=$directoryCert!==null;
        if($explicit&&(($file!==''&&!$fileOK)||($directory!==''&&!$dirOK))){
            throw new SecretsBackendNativePeerDeliveryFailure('certificate',0,77,-1,'ca-store-unavailable',[
                'source'=>$source,'fileSpecified'=>$file!=='','fileReadable'=>$file!==''?is_file($file)&&is_readable($file):null,
                'directorySpecified'=>$directory!=='','directoryReadable'=>$directory!==''?is_dir($directory)&&is_readable($directory):null]);
        }
        if(!$fileOK&&!$dirOK)return null;
        return ['source'=>$source,'file'=>$fileOK?$file:$directoryCert,'directory'=>$dirOK?$directory:null];
    }
    /** Pure input selection makes platform precedence and fail-closed overrides independently testable. */
    public static function resolve(array $input): array
    {
        $curl=trim((string)($input['curlFile']??''));$openssl=$input['openssl']??[];$env=$input['environment']??[];
        if($curl!=='')return self::plan('curl-configured',$curl,'',true);
        $file=trim((string)($openssl['ini_cafile']??''));$dir=trim((string)($openssl['ini_capath']??''));
        if($file!==''||$dir!=='')return self::plan('openssl-configured',$file,$dir,true);
        $file=trim((string)($env['CURL_CA_BUNDLE']??$env['SSL_CERT_FILE']??''));$dir=trim((string)($env['SSL_CERT_DIR']??''));
        if($file!==''||$dir!=='')return self::plan('environment-configured',$file,$dir,true);
        if(preg_match('/Schannel|SecureTransport|SecTrust/i',(string)($input['tlsBackend']??'')))return ['source'=>'native','file'=>null,'directory'=>null];
        foreach([
            ['curl-default',(string)($input['curlDefaultFile']??''),(string)($input['curlDefaultDirectory']??'')],
            ['openssl-default',(string)($openssl['default_cert_file']??''),(string)($openssl['default_cert_dir']??'')],
        ]as[$source,$f,$d]){if($plan=self::plan($source,$f,$d))return $plan;}
        foreach($input['systemFiles']??[]as$f)if($plan=self::plan('system',(string)$f,''))return $plan;
        $bundle=__DIR__.'/certificates/mozilla-ca.pem';
        if(!is_file($bundle)||!is_readable($bundle)||!hash_equals(self::BUNDLE_SHA256,(string)hash_file('sha256',$bundle))||!self::pem($bundle))throw new SecretsBackendNativePeerDeliveryFailure('certificate',0,77,-1,'ca-store-unavailable',['source'=>'unavailable']);
        return ['source'=>'bundled','file'=>$bundle,'directory'=>null];
    }
    public static function apply($handle): array
    {
        $env=[];foreach(['CURL_CA_BUNDLE','SSL_CERT_FILE','SSL_CERT_DIR']as$key){$v=getenv($key);if(is_string($v)&&trim($v)!=='')$env[$key]=$v;}
        $plan=self::resolve(['curlFile'=>ini_get('curl.cainfo'),'openssl'=>function_exists('openssl_get_cert_locations')?openssl_get_cert_locations():[],'environment'=>$env,'tlsBackend'=>curl_version()['ssl_version']??'',
            'curlDefaultFile'=>defined('CURLINFO_CAINFO')?(curl_getinfo($handle,constant('CURLINFO_CAINFO'))?:''):'',
            'curlDefaultDirectory'=>defined('CURLINFO_CAPATH')?(curl_getinfo($handle,constant('CURLINFO_CAPATH'))?:''):'',
            'systemFiles'=>['/etc/ssl/certs/ca-certificates.crt','/etc/pki/tls/certs/ca-bundle.crt','/etc/ssl/ca-bundle.pem','/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem','/etc/ssl/cert.pem']]);
        $options=[CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2];
        if($plan['source']!=='native'){
            $options[CURLOPT_CAINFO]=$plan['file'];
            if($plan['directory']!==null)$options[CURLOPT_CAPATH]=$plan['directory'];
            elseif(!preg_match('/Schannel|SecureTransport|SecTrust/i',curl_version()['ssl_version']??'')){$empty=__DIR__.'/certificates/empty';if(!is_dir($empty)||!is_readable($empty)||self::directoryCertificate($empty)!==null)throw new SecretsBackendNativePeerDeliveryFailure('certificate',0,77,-1,'ca-store-unavailable',['source'=>$plan['source']]);$options[CURLOPT_CAPATH]=$empty;}
        }
        if(!curl_setopt_array($handle,$options))throw new SecretsBackendNativePeerDeliveryFailure('certificate',0,77,-1,'ca-store-unavailable',['source'=>$plan['source']]);
        return ['source'=>$plan['source'],'fileSpecified'=>$plan['file']!==null,'fileReadable'=>$plan['file']!==null?true:null,
            'directorySpecified'=>$plan['directory']!==null,'directoryReadable'=>$plan['directory']!==null?true:null];
    }
}
