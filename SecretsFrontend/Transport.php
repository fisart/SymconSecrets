<?php
declare(strict_types=1);

/** Local listener evidence. Never infer transport from Host, Origin or forwarded headers. */
final class SecretsFrontendTransport
{
    public const WEB_SERVER='{D83E9CCF-9869-420F-8306-2B043E9BA180}';
    private const TABLE_LIMIT=2097152;

    public static function nativeTLS(array $context,array $server):bool
    {
        $http=in_array(strtolower((string)($server['HTTPS']??'')),['off','0'],true)||($server['REQUEST_SCHEME']??'')==='http';
        try{
            // Available on some Symcon versions, and independent of an external NAT port.
            $caller=$context['INSTANCE']??null;
            if(!$http&&($context['SENDER']??'')==='WebHook'&&is_int($caller)&&$caller>0&&self::sslListener($caller))return true;
            // Module hooks may omit the caller and PHP HTTPS flag. Match the actual
            // accepted TCP connection in this Linux/container network namespace instead.
            if(PHP_OS_FAMILY!=='Linux')return false;
            $connections=self::connections($server,static function(string $name):?string{
                $p='/proc/net/'.$name;if($name==='tcp6'&&!file_exists($p))return '';if(!is_readable($p))return null;
                $text=@file_get_contents($p,false,null,0,self::TABLE_LIMIT+1);
                return is_string($text)&&strlen($text)<=self::TABLE_LIMIT?$text:null;
            });
            if(!$connections)return false;
            $remote=$server['REMOTE_PORT']??null;
            if($remote!==null&&$remote!==0&&$remote!=='0'){
                if((!is_int($remote)&&!is_string($remote))||!preg_match('/^[1-9][0-9]{0,4}$/D',(string)$remote)||(int)$remote>65535)return false;
                $exact=array_values(array_filter($connections,static fn($c)=>$c['remotePort']===(int)$remote));
                if($exact)return count($exact)===1&&self::connectionTLS($exact[0]);
            }
            // Some hook versions omit REMOTE_PORT or expose the destination port.
            // Without an exact tuple, EVERY possible connection from this peer
            // must be SSL. One plaintext/unknown socket makes the request unverified.
            foreach($connections as$connection)if(!self::connectionTLS($connection))return false;
            return true;
        }catch(Throwable $ignored){return false;}
    }

    private static function connectionTLS(array $connection):bool
    {
        $matches=[];
        foreach(IPS_GetInstanceListByModuleID(self::WEB_SERVER)as$id){
            $id=(int)$id;
            if(!self::sslListener($id)||IPS_GetProperty($id,'Port')!==$connection['port'])continue;
            $bind=self::address((string)IPS_GetProperty($id,'Server'));
            if($bind!==null&&($bind===$connection['address']||($bind===str_repeat("\0",strlen($bind))&&strlen($bind)===($connection['family']===6?16:4))))$matches[]=$id;
        }
        return count($matches)===1;
    }

    public static function diagnostic(array $context,array $server):array
    {
        $port=$server['REMOTE_PORT']??null;
        $ssl=null;$pending=null;
        try{$ssl=0;$pending=0;foreach(IPS_GetInstanceListByModuleID(self::WEB_SERVER)as$id){if(IPS_HasChanges((int)$id))$pending++;if(self::sslListener((int)$id))$ssl++;}}catch(Throwable $ignored){$ssl=null;$pending=null;}
        return ['caller'=>is_int($context['INSTANCE']??null)?$context['INSTANCE']:null,'remoteAddressSupplied'=>self::address((string)($server['REMOTE_ADDR']??''))!==null,
            'remoteLoopback'=>in_array($server['REMOTE_ADDR']??'', ['127.0.0.1','::1'],true),
            'remotePort'=>is_scalar($port)&&preg_match('/^[0-9]{1,5}$/D',(string)$port)?(int)$port:null,
            'httpsFlag'=>in_array($server['HTTPS']??'', ['on','off','1','0',''],true)?($server['HTTPS']??'missing'):'other',
            'scheme'=>in_array($server['REQUEST_SCHEME']??'', ['http','https',''],true)?($server['REQUEST_SCHEME']??'missing'):'other',
            'activeSSLListeners'=>$ssl,'listenersWithPendingChanges'=>$pending,
            'tcpTableReadable'=>PHP_OS_FAMILY==='Linux'&&is_readable('/proc/net/tcp'),'tcp6TableReadable'=>PHP_OS_FAMILY==='Linux'&&is_readable('/proc/net/tcp6')];
    }

    private static function sslListener(int $id):bool
    {
        if(!IPS_InstanceExists($id)||IPS_HasChanges($id))return false;
        $i=IPS_GetInstance($id);
        return strtoupper((string)($i['ModuleInfo']['ModuleID']??''))===self::WEB_SERVER&&($i['InstanceStatus']??0)===102
            &&IPS_GetProperty($id,'Active')===true&&IPS_GetProperty($id,'EnableSSL')===true;
    }

    /** Read only kernel-owned fields, not HTTP_* mirrors; ambiguous/missing tuples fail closed. */
    public static function connection(array $server,callable $read):?array
    {
        $remote=$server['REMOTE_PORT']??null;
        if((!is_int($remote)&&!is_string($remote))||!preg_match('/^[1-9][0-9]{0,4}$/D',(string)$remote)||(int)$remote>65535)return null;
        $rows=self::connections($server,$read);if($rows===null)return null;
        $matches=array_values(array_filter($rows,static fn($c)=>$c['remotePort']===(int)$remote));
        return count($matches)===1?$matches[0]:null;
    }

    private static function connections(array $server,callable $read):?array
    {
        $address=self::address((string)($server['REMOTE_ADDR']??''));if($address===null)return null;
        $local=isset($server['SERVER_ADDR'])?self::address((string)$server['SERVER_ADDR']):null;
        if(isset($server['SERVER_ADDR'])&&$local===null)return null;
        $matches=[];
        foreach(['tcp','tcp6']as$name){
            $table=$read($name);
            if($table===null)return null;
            if(!is_string($table)||strlen($table)>self::TABLE_LIMIT)return null;
            $lines=explode("\n",$table);if(count($lines)>16384)return null;
            foreach($lines as$line){
                $fields=preg_split('/\s+/',trim($line));
                // A client can half-close a plaintext request before PHP runs.
                // CLOSE_WAIT must participate, or a separate TLS socket could mask it.
                if(count($fields)<4||!in_array($fields[3],['01','08'],true))continue;
                $a=explode(':',$fields[1]);$b=explode(':',$fields[2]);
                if(count($a)!==2||count($b)!==2||!preg_match('/^[A-Fa-f0-9]{4}$/D',$a[1])||!preg_match('/^[A-Fa-f0-9]{4}$/D',$b[1]))continue;
                if(self::kernelAddress($b[0])!==$address||($local!==null&&self::kernelAddress($a[0])!==$local))continue;
                $port=(int)hexdec($a[1]);$addressLocal=self::kernelAddress($a[0]);if($port===0||$addressLocal===null)return null;$matches[]=['port'=>$port,'address'=>$addressLocal,'family'=>strlen($a[0])===32?6:4,'remotePort'=>(int)hexdec($b[1])];
            }
        }
        return $matches;
    }

    private static function address(string $text):?string
    {
        $bytes=@inet_pton($text);if($bytes===false)return null;
        return strlen($bytes)===16&&substr($bytes,0,12)===str_repeat("\0",10)."\xff\xff"?substr($bytes,12):$bytes;
    }
    private static function kernelAddress(string $hex):?string
    {
        if(!preg_match('/^(?:[A-Fa-f0-9]{8}|[A-Fa-f0-9]{32})$/D',$hex))return null;
        $bytes='';foreach(str_split($hex,8)as$word){$part=hex2bin($word);$bytes.=pack('S',1)==="\x01\x00"?strrev($part):$part;}
        return strlen($bytes)===16&&substr($bytes,0,12)===str_repeat("\0",10)."\xff\xff"?substr($bytes,12):$bytes;
    }
}
