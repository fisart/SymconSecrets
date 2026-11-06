<?php
declare(strict_types=1);

/** Presentation only. Pairing authority continues to use the signed vault identity. */
final class SecretsBackendPeerName
{
    public static function address(string $url):string {
        $host=parse_url($url,PHP_URL_HOST);$port=parse_url($url,PHP_URL_PORT);
        return is_string($host)&&$host!==''?$host.($port!==null?':'.$port:''):'Unknown server';
    }
    public static function display(array $peer):string {
        $name=$peer['name']??'';
        if(is_string($name)&&trim($name)!==''&&!preg_match('/^Peer [a-f0-9]{8}$/Di',$name))return $name;
        $endpoint=$peer['descriptor']['endpoint']??'';
        foreach($peer['routes']['endpoints']??[]as$url)if(!preg_match('/^[a-z0-9]{32}\.ipmagic\.de$/Di',(string)parse_url($url,PHP_URL_HOST))){$endpoint=$url;break;}
        return self::address($endpoint);
    }
}
