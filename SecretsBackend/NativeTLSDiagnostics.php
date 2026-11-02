<?php
declare(strict_types=1);
/** Explicit administrator retry only. TLS probes send no HTTP, credentials or vault messages. */
final class SecretsBackendNativeTLSDiagnostics
{
    public static function inspect(string $endpoint,array $policy): array
    {
        SecretsBackendNativePeer::endpoint($endpoint);$policy=SecretsBackendNativeLegacyHTTPS::policy($policy);
        $host=parse_url($endpoint,PHP_URL_HOST);$port=parse_url($endpoint,PHP_URL_PORT)??443;
        $out=['version'=>1,'checkedAt'=>time(),'php'=>PHP_VERSION,'openssl'=>OPENSSL_VERSION_TEXT,'targetHost'=>$host,'targetPort'=>$port,'httpDataSent'=>false,'configuredPolicy'=>$policy];
        try{$out['legacyProposal']=SecretsBackendNativeLegacyHTTPS::proposal($endpoint);}catch(Throwable $e){$out['legacyProposal']=['status'=>'conflicting-or-invalid-settings'];}
        $file=(string)ini_get('openssl.cafile');$dir=(string)ini_get('openssl.capath');$roots=[];
        $out['legacyRoutes']=self::legacyRoutes();
        $out['configuredCA']=['fileConfigured'=>$file!=='','directoryConfigured'=>$dir!=='','fileReadable'=>$file!==''&&is_readable($file),'sha256'=>null,'certificateCount'=>null,'parseFailures'=>0];
        if($file!==''&&is_file($file)&&is_readable($file)){
            $pem=@file_get_contents($file,false,null,0,2097153);
            if(is_string($pem)&&strlen($pem)<=2097152){
                $out['configuredCA']['sha256']=hash('sha256',$pem);preg_match_all('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s',$pem,$matches);
                $out['configuredCA']['certificateCount']=count($matches[0]);
                foreach(array_slice($matches[0],0,256)as$text){$c=@openssl_x509_read($text);if($c!==false)$roots[]=$c;else++$out['configuredCA']['parseFailures'];}
                $out['configuredCA']['inspectionComplete']=count($matches[0])<=256;
            }else $out['configuredCA']['inspectionComplete']=false;
        }
        // First probe uses the exact delivery authentication policy. Never send application bytes.
        foreach([true,false]as$verified){
            $ssl=['SNI_enabled'=>true,'peer_name'=>$host,'capture_peer_cert'=>true,'capture_peer_cert_chain'=>true,'verify_peer'=>$verified&&$policy['mode']==='strict','verify_peer_name'=>$verified&&$policy['mode']==='strict','allow_self_signed'=>!$verified||$policy['mode']==='pinned'];
            if($verified&&$policy['mode']==='pinned')$ssl['peer_fingerprint']=['sha256'=>$policy['fingerprint']];
            $context=stream_context_create(['ssl'=>$ssl]);$warnings='';$socket=false;
            for($i=0;$i<32&&openssl_error_string()!==false;++$i){}
            set_error_handler(static function(int $n,string $text)use(&$warnings):bool{$warnings=substr($warnings.' '.$text,0,8192);return true;});
            try{
                $socket=stream_socket_client('tls://'.$host.':'.$port,$errno,$errstr,2.5,STREAM_CLIENT_CONNECT,$context);
                $options=stream_context_get_options($context)['ssl'];$errors='';for($i=0;$i<16&&($error=openssl_error_string())!==false;++$i)$errors.=' '.$error;
                $evidence=self::errors($warnings.' '.$errors);
                if($verified){$out['authenticatedHandshake']=['ok'=>is_resource($socket),'errors'=>$evidence];if(is_resource($socket))$out['connectedAddress']=stream_socket_get_name($socket,true);}
                else{
                    $out['certificateObservation']=['authenticated'=>false,'handshakeSucceeded'=>is_resource($socket),'errors'=>$evidence,'certificates'=>[]];
                    if(is_resource($socket))$out['observedAddress']=stream_socket_get_name($socket,true);
                    $chain=$options['peer_certificate_chain']??[];if(!$chain&&isset($options['peer_certificate']))$chain=[$options['peer_certificate']];
                    $out['certificateObservation']['chainCount']=count($chain);
                    foreach(array_slice($chain,0,12)as$c){
                        $parsed=openssl_x509_parse($c);if(!is_array($parsed))continue;
                        $issuerFound=false;foreach(array_merge($chain,$roots)as$candidate){if(openssl_x509_fingerprint($c,'sha256')===openssl_x509_fingerprint($candidate,'sha256'))continue;if(@openssl_x509_verify($c,openssl_pkey_get_public($candidate))===1){$issuerFound=true;break;}}
                        $out['certificateObservation']['certificates'][]=['sha256'=>openssl_x509_fingerprint($c,'sha256'),'subject'=>self::name($parsed['subject']??[]),'issuer'=>self::name($parsed['issuer']??[]),'subjectAltName'=>substr((string)($parsed['extensions']['subjectAltName']??''),0,2048),'validFrom'=>$parsed['validFrom_time_t']??null,'validUntil'=>$parsed['validTo_time_t']??null,'selfSigned'=>@openssl_x509_verify($c,openssl_pkey_get_public($c))===1,'issuerSignatureFoundInPresentedChainOrConfiguredFile'=>$issuerFound];
                    }
                }
            }finally{if(is_resource($socket))fclose($socket);restore_error_handler();}
        }
        $out['interpretation']='Observed certificates are untrusted evidence, never adopted as trust. Issuer-signature checks are not full path validation. CA directories and implicit OS stores are not enumerated. The two handshakes can reach different load-balancer addresses.';
        return $out;
    }
    private static function legacyRoutes(): array
    {
        $out=[];if(!function_exists('IPS_GetInstanceListByModuleID')||!function_exists('IPS_GetConfiguration'))return $out;
        foreach(array_slice(IPS_GetInstanceListByModuleID('{7C5A3841-3F7B-4D2A-9E1C-5B6D8F9A0E12}'),0,32)as$id){
            try{
                $raw=IPS_GetConfiguration($id);if(strlen($raw)>65536)continue;$c=json_decode($raw,true,16,JSON_THROW_ON_ERROR);
                $entry=['instance'=>$id,'applied'=>!IPS_HasChanges($id),'status'=>IPS_GetInstance($id)['InstanceStatus']??null,'operationMode'=>$c['OperationMode']??null,'routes'=>[]];
                $rows=json_decode($c['SlaveURLs']??'[]',true,16,JSON_THROW_ON_ERROR);
                foreach(array_slice(is_array($rows)?$rows:[],0,64)as$row){
                    if(!is_array($row))continue;try{$origin=SecretsBackendNativeLegacyHTTPS::origin(trim($row['Url']??''));}catch(Throwable $e){$origin='not-usable-https';}
                    $entry['routes'][]=['origin'=>$origin,'tlsMode'=>in_array($row['TlsMode']??'strict',['strict','pinned','http'],true)?($row['TlsMode']??'strict'):'invalid','keyTransport'=>in_array($row['KeyTransport']??'manual',['sync','manual'],true)?($row['KeyTransport']??'manual'):'invalid','fingerprintConfigured'=>!empty($row['Fingerprint'])];
                }$out[]=$entry;
            }catch(Throwable $e){$out[]=['instance'=>$id,'status'=>'configuration-unreadable'];}
        }return $out;
    }
    private static function name(array $name): array
    {
        $out=[];foreach(['CN','O','OU','C']as$key)if(isset($name[$key])&&is_string($name[$key]))$out[$key]=substr($name[$key],0,160);return $out;
    }
    public static function errors(string $text): array
    {
        preg_match_all('/error:([0-9a-f]{8,16}):/i',$text,$m);$reasons=[];$lower=strtolower($text);
        foreach(['certificate verify failed','unable to get local issuer certificate','unable to verify the first certificate','certificate has expired','certificate is not yet valid','self-signed certificate','did not match expected','peer_fingerprint match failure','no suitable signature algorithm','ca md too weak','ee key too small','certificate chain too long','failed loading cafile','operation timed out','getaddrinfo failed']as$reason)if(str_contains($lower,$reason))$reasons[]=$reason;
        return ['opensslCodes'=>array_values(array_unique(array_slice($m[1],0,16))),'reasons'=>$reasons];
    }
}
