<?php
declare(strict_types=1);
require_once __DIR__.'/NativeIssuers.php';

/** Reuses SecretsManager's PHP-stream strict/pinned transport, without its legacy protocol or credentials. */
final class SecretsBackendNativeLegacyHTTPS
{
    private const MODULE='{7C5A3841-3F7B-4D2A-9E1C-5B6D8F9A0E12}';
    public static function available(): bool { return function_exists('openssl_x509_fingerprint')&&in_array('https',stream_get_wrappers(),true); }
    public static function origin(string $endpoint): string
    {
        $p=parse_url($endpoint);
        if(!is_array($p)||($p['scheme']??'')!=='https'||empty($p['host'])||isset($p['user'])||isset($p['pass']))throw new RuntimeException('Use an exact HTTPS platform address.');
        return 'https://'.strtolower($p['host']).':'.($p['port']??443);
    }
    public static function policy(array $policy): array
    {
        if(($policy['mode']??'strict')==='strict'&&array_diff(array_keys($policy),['mode'])===[])return ['mode'=>'strict'];
        $fingerprint=$policy['fingerprint']??'';
        if(($policy['mode']??'')!=='pinned'||!is_string($fingerprint)||array_diff(array_keys($policy),['mode','fingerprint'])||!preg_match('/^[a-f0-9]{64}$/D',$fingerprint))throw new RuntimeException('Invalid approved HTTPS certificate fingerprint.');
        return ['mode'=>'pinned','fingerprint'=>$fingerprint];
    }
    /** Public applied settings only: never read/decrypt a vault, token or password. */
    public static function proposal(string $endpoint,array $peers=[]): array
    {
        $origin=self::origin($endpoint);$matches=[];
        // Use native saved peer policy or strict PKI; never inspect old manager settings.
        $retained=[];foreach($peers as$peer){
            if(!isset($peer['httpsPolicy'],$peer['descriptor']['endpoint']))continue;
            if(self::origin($peer['descriptor']['endpoint'])!==$origin)continue;
            $policy=self::policy($peer['httpsPolicy']);$retained[json_encode($policy)]=$policy;
        }
        if(count($retained)>1)throw new RuntimeException('Saved connections have conflicting HTTPS settings for this platform.');
        return ['policy'=>$retained?array_values($retained)[0]:['mode'=>'strict'],'source'=>$retained?'saved connection':'PHP streams'];
    }
    public static function post(string $endpoint,string $bytes,array $policy=['mode'=>'strict'],float $timeout=4.5): string
    {
        SecretsBackendNativePeer::endpoint($endpoint);$policy=self::policy($policy);
        if($timeout<0.1||$timeout>4.5)throw new InvalidArgumentException('Invalid HTTPS timeout.');
        $deadline=microtime(true)+$timeout;
        if(!self::available())throw new SecretsBackendNativePeerDeliveryFailure('transport');
        $host=parse_url($endpoint,PHP_URL_HOST);$pinned=$policy['mode']==='pinned';
        // PHP verifies peer_fingerprint during TLS setup, before its HTTP wrapper sends request bytes.
        // Pinned mode authenticates the exact previously approved leaf certificate, as in SecretsManager.
        $ssl=['verify_peer'=>!$pinned,'verify_peer_name'=>!$pinned,'allow_self_signed'=>$pinned,'SNI_enabled'=>true,'peer_name'=>$host];
        if($pinned)$ssl['peer_fingerprint']=['sha256'=>$policy['fingerprint']];
        return SecretsBackendNativeIssuers::run($ssl,static fn(array $options):string=>self::send($endpoint,$bytes,$policy,$options,$deadline));
    }
    private static function send(string $endpoint,string $bytes,array $policy,array $ssl,float $deadline): string
    {
        $remaining=$deadline-microtime(true);if($remaining<0.1)throw new SecretsBackendNativePeerDeliveryFailure('timeout');
        $context=stream_context_create(['ssl'=>$ssl,'http'=>['method'=>'POST','header'=>"Content-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\n",'content'=>$bytes,'timeout'=>$remaining,'ignore_errors'=>true,'follow_location'=>0,'max_redirects'=>0,'protocol_version'=>1.1]]);
        $warning='';$stream=false;
        set_error_handler(static function(int $severity,string $message)use(&$warning):bool{$warning=substr($message,0,2048).' '.$warning;$warning=substr($warning,0,4096);return true;});
        try{
            $stream=fopen($endpoint,'rb',false,$context);
            if($stream===false)throw self::failure($warning,$policy);
            $meta=stream_get_meta_data($stream);$status=0;
            foreach($meta['wrapper_data']??[]as$line)if(preg_match('~^HTTP/\d(?:\.\d)? (\d{3})(?: |$)~D',$line,$m))$status=(int)$m[1];
            if($status!==200)throw new SecretsBackendNativePeerDeliveryFailure('http',$status);
            $body='';while(!feof($stream)){
                $left=$deadline-microtime(true);if($left<=0)throw new SecretsBackendNativePeerDeliveryFailure('timeout');
                stream_set_timeout($stream,(int)$left,(int)(($left-(int)$left)*1000000));
                $chunk=fread($stream,min(8192,65537-strlen($body)));
                if($chunk===false)throw self::failure($warning,$policy);
                $body.=$chunk;if(strlen($body)>65536)throw new SecretsBackendNativePeerDeliveryFailure('response-size');
                if(stream_get_meta_data($stream)['timed_out'])throw new SecretsBackendNativePeerDeliveryFailure('timeout');
                if($chunk===''&&!feof($stream))throw new SecretsBackendNativePeerDeliveryFailure('unconfirmed');
            }
            // A truncated Content-Length response must not be reported as delivered.
            $headers=$meta['wrapper_data']??[];$length=null;$chunked=false;
            foreach($headers as$line){if(preg_match('/^Content-Length:\s*(\d+)\s*$/iD',$line,$m))$length=(int)$m[1];if(preg_match('/^Transfer-Encoding:/i',$line))$chunked=true;}
            if(!$chunked&&$length!==null&&strlen($body)!==$length)throw new SecretsBackendNativePeerDeliveryFailure('unconfirmed');
            return $body;
        }finally{if(is_resource($stream))fclose($stream);restore_error_handler();}
    }
    private static function failure(string $warning,array $policy): SecretsBackendNativePeerDeliveryFailure
    {
        $w=strtolower($warning);$reason='unknown';$problem='connect';
        if(str_contains($w,'timed out'))$problem='timeout';
        elseif(str_contains($w,'getaddrinfo'))$problem='dns';
        elseif(str_contains($w,'certificate')||str_contains($w,'peer_fingerprint')||str_contains($w,'peer certificate')){
            $problem='certificate';
            if(str_contains($w,'did not match')||str_contains($w,'fingerprint'))$reason=$policy['mode']==='pinned'?'pin-mismatch':'hostname-mismatch';
        }elseif(str_contains($w,'crypto')||str_contains($w,'ssl'))$problem='tls';
        $file=(string)ini_get('openssl.cafile');$directory=(string)ini_get('openssl.capath');
        return new SecretsBackendNativePeerDeliveryFailure($problem,0,0,-1,$reason,['fileSpecified'=>$file!=='','fileReadable'=>$file!==''?is_readable($file):null,'directorySpecified'=>$directory!=='','directoryReadable'=>$directory!==''?is_readable($directory):null,'source'=>$policy['mode']==='pinned'?'certificate-pinned':($file!==''||$directory!==''?'openssl-configured':'openssl-default')]);
    }
}
