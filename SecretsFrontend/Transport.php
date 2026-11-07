<?php
declare(strict_types=1);

/** Local listener evidence. Never infer transport from Host, Origin or forwarded headers. */
final class SecretsFrontendTransport
{
    public const WEB_SERVER='{D83E9CCF-9869-420F-8306-2B043E9BA180}';
    private const TABLE_LIMIT=2097152;

    public static function nativeTLS(array $context,array $server):bool
    {
        if(in_array(strtolower((string)($server['HTTPS']??'')),['off','0'],true)||($server['REQUEST_SCHEME']??'')==='http')return false;
        try{
            // Available on some Symcon versions, and independent of an external NAT port.
            $caller=$context['INSTANCE']??null;
            if(($context['SENDER']??'')==='WebHook'&&is_int($caller)&&$caller>0&&self::sslListener($caller))return true;
            // Module hooks may omit the caller and PHP HTTPS flag. Match the actual
            // accepted TCP connection in this Linux/container network namespace instead.
            if(PHP_OS_FAMILY!=='Linux')return false;
            $connection=self::connection($server,static function(string $name):?string{
                $p='/proc/net/'.$name;if($name==='tcp6'&&!file_exists($p))return '';if(!is_readable($p))return null;
                $text=@file_get_contents($p,false,null,0,self::TABLE_LIMIT+1);
                return is_string($text)&&strlen($text)<=self::TABLE_LIMIT?$text:null;
            });
            if($connection===null)return false;
            $matches=[];
            foreach(IPS_GetInstanceListByModuleID(self::WEB_SERVER)as$id){
                $id=(int)$id;
                if(!self::sslListener($id)||IPS_GetProperty($id,'Port')!==$connection['port'])continue;
                $bind=self::address((string)IPS_GetProperty($id,'Server'));
                if($bind!==null&&($bind===$connection['address']||($bind===str_repeat("\0",strlen($bind))&&strlen($bind)===($connection['family']===6?16:4))))$matches[]=$id;
            }
            return count($matches)===1;
        }catch(Throwable $ignored){return false;}
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
        $address=self::address((string)($server['REMOTE_ADDR']??''));$remote=$server['REMOTE_PORT']??null;
        if($address===null||(!is_int($remote)&&!is_string($remote))||!preg_match('/^[1-9][0-9]{0,4}$/D',(string)$remote)||(int)$remote>65535)return null;
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
                if(count($fields)<4||$fields[3]!=='01')continue;
                $a=explode(':',$fields[1]);$b=explode(':',$fields[2]);
                if(count($a)!==2||count($b)!==2||!preg_match('/^[A-Fa-f0-9]{4}$/D',$a[1])||!preg_match('/^[A-Fa-f0-9]{4}$/D',$b[1]))continue;
                if(hexdec($b[1])!==(int)$remote||self::kernelAddress($b[0])!==$address||($local!==null&&self::kernelAddress($a[0])!==$local))continue;
                $port=(int)hexdec($a[1]);$addressLocal=self::kernelAddress($a[0]);if($port===0||$addressLocal===null)return null;$matches[]=['port'=>$port,'address'=>$addressLocal,'family'=>strlen($a[0])===32?6:4];
            }
        }
        return count($matches)===1?$matches[0]:null;
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
