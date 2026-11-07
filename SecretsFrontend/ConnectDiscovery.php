<?php
declare(strict_types=1);
require_once __DIR__ . '/Configuration.php';
require_once __DIR__ . '/Transport.php';

/** Read-only suggestion; this never approves an origin or changes vault policy. */
final class SecretsFrontendConnectDiscovery
{
    public const MODULE = '{9486D575-BE8C-4ED8-B5B5-20930E26DE6F}';

    /** Read from the local Connect core, never from request headers. */
    public static function local(): array
    {
        return self::discover(
            static fn($module)=>IPS_GetInstanceListByModuleID($module),
            static fn($id)=>IPS_GetInstance($id)['InstanceStatus']??0,
            static function($id){
                if(function_exists('CC_GetConnectURL'))return CC_GetConnectURL($id);
                if(function_exists('CC_GetURL'))return CC_GetURL($id);
                throw new RuntimeException('Connect discovery is unavailable.');
            }
        );
    }

    /**
     * Explicit local relay profile: trust the host's loopback services and the
     * active Symcon Connect core. This does not prove TLS from PHP flags and is
     * never administrator authority. Local service/relay isolation is a stated
     * deployment requirement; untrusted local proxies must not expose this hop.
     */
    public static function secureRoute(array $server,string $origin,array $trusted,array $connect): bool
    {
        return in_array($server['HTTPS']??'', ['on','1'],true)||(in_array($server['REMOTE_ADDR']??'',$trusted,true)&&($server['HTTP_X_FORWARDED_PROTO']??'')==='https')||self::loopbackRelay($server,$origin,$connect)||SecretsFrontendTransport::nativeTLS($GLOBALS['_IPS']??[],$server);
    }
    public static function loopbackRelay(array $server,string $approvedOrigin,array $connect): bool
    {
        if(($connect['available']??false)!==true||($connect['origin']??null)!==$approvedOrigin
            ||!preg_match('~^https://[a-z0-9]{32}\.ipmagic\.de$~D',$approvedOrigin)
            ||!in_array($server['REMOTE_ADDR']??'', ['127.0.0.1','::1'],true))return false;
        if(isset($server['HTTP_FORWARDED'])||isset($server['HTTP_X_FORWARDED_HOST'])||isset($server['HTTP_X_FORWARDED_PROTO']))return false;
        if(!in_array($server['HTTPS']??'', ['', 'on', '1'],true)||!in_array($server['REQUEST_SCHEME']??'', ['', 'https'],true))return false;
        try{return SecretsFrontendConfiguration::origin('https://'.($server['HTTP_HOST']??''))===$approvedOrigin;}catch(Throwable $e){return false;}
    }

    public static function discover(callable $instances, callable $status, callable $url): array
    {
        try {
            $ids = $instances(self::MODULE);
            if (!is_array($ids) || count($ids) !== 1 || !is_int($ids[0]) || $ids[0] <= 0) {
                return ['available'=>false, 'message'=>'Connect Control was not found uniquely. Check Symcon Connect and try again.'];
            }
            if ($status($ids[0]) !== 102) return ['available'=>false, 'message'=>'Activate Symcon Connect and wait until it is connected.'];
            $value = $url($ids[0]);
            if (!is_string($value) || $value === '') return ['available'=>false, 'message'=>'Symcon Connect did not provide an address. Try again when it is connected.'];
            $origin = SecretsFrontendConfiguration::origin($value);
            $host = parse_url($origin, PHP_URL_HOST);
            if ($origin === '' || !is_string($host) || filter_var($host, FILTER_VALIDATE_IP) !== false || !str_contains($host, '.') || str_ends_with($host, '.')) throw new RuntimeException('Invalid Connect origin.');
            return ['available'=>true, 'origin'=>$origin];
        } catch (Throwable $e) {
            return ['available'=>false, 'message'=>'The Connect address is unavailable or is not an exact HTTPS address. Check Symcon Connect and try again.'];
        }
    }
}
