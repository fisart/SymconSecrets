<?php
declare(strict_types=1);
require_once __DIR__.'/BootstrapFixture.php';
require_once __DIR__.'/../Transport.php';
$checks=0;$ok=static function(bool $v,string $why)use(&$checks):void{secExpect($v,$why);$checks++;};
$hex=static function(string $ip):string{$p=inet_pton($ip);$out='';foreach(str_split($p,4)as$word)$out.=strtoupper(bin2hex(pack('S',1)==="\x01\x00"?strrev($word):$word));return $out;};
$line=static fn(string $local,int $lp,string $remote,int $rp,string $state='01')=>' 0: '.$hex($local).':'.sprintf('%04X',$lp).' '.$hex($remote).':'.sprintf('%04X',$rp).' '.$state.' 0 0 0 0 0 0';
$server=['REMOTE_ADDR'=>'198.51.100.8','REMOTE_PORT'=>'54321'];
$table=$line('172.18.0.2',8443,'198.51.100.8',54321);
$read=static fn($name)=>$name==='tcp'?$table:'';
$c=SecretsFrontendTransport::connection($server,$read);$ok($c!==null&&$c['port']===8443&&$c['address']===inet_pton('172.18.0.2'),'NAT listener tuple was not identified.');
foreach([['REMOTE_ADDR'=>'198.51.100.9'],['REMOTE_PORT'=>54322],['REMOTE_PORT'=>'bad'],['SERVER_ADDR'=>'172.18.0.3']]as$override)$ok(SecretsFrontendTransport::connection(array_replace($server,$override),$read)===null,'Different peer/local tuple was accepted.');
$ok(SecretsFrontendTransport::connection(['HTTP_REMOTE_ADDR'=>'198.51.100.8','HTTP_REMOTE_PORT'=>'54321'],$read)===null,'HTTP mirrors supplied a trusted connection tuple.');
$ok(SecretsFrontendTransport::connection($server,static fn($name)=>$name==='tcp'?$table."\n".$line('172.18.0.3',3777,'198.51.100.8',54321):'')===null,'Ambiguous kernel connections were trusted.');
$ok(SecretsFrontendTransport::connection($server,static fn($name)=>null)===null,'Missing kernel table was trusted.');
$ok(SecretsFrontendTransport::connection($server,static fn($name)=>$name==='tcp'?$line('172.18.0.2',8443,'198.51.100.8',54321,'06'):'')===null,'Closed connection was trusted.');
foreach(['::ffff:198.51.100.8','2001:db8::8']as$ip){$s=['REMOTE_ADDR'=>$ip,'REMOTE_PORT'=>54321];$row=$line('2001:db8::2',8443,$ip,54321);$c=SecretsFrontendTransport::connection($s,static fn($name)=>$name==='tcp6'?$row:'');$ok(($c['port']??null)===8443,'IPv6 or mapped IPv4 tuple failed.');}
// Trusted engine caller works without PHP HTTPS metadata, on every platform.
$core=new IPSModule(62000);$core->status=102;$core->properties=['Active'=>true,'EnableSSL'=>true,'Port'=>8443,'Server'=>'0.0.0.0'];$GLOBALS['moduleIDs'][62000]=SecretsFrontendTransport::WEB_SERVER;
$context=['SENDER'=>'WebHook','INSTANCE'=>62000];$ok(SecretsFrontendTransport::nativeTLS($context,[]),'Engine-identified SSL listener was rejected.');
foreach([['HTTPS'=>'off'],['REQUEST_SCHEME'=>'http']]as$s)$ok(!SecretsFrontendTransport::nativeTLS($context,$s),'Contradictory plaintext evidence was accepted.');
$core->properties['EnableSSL']=false;$ok(!SecretsFrontendTransport::nativeTLS($context,[]),'Plain engine caller was trusted.');$core->properties['EnableSSL']=true;
$GLOBALS['changed'][62000]=true;$ok(!SecretsFrontendTransport::nativeTLS($context,[]),'Pending listener edits were used as applied state.');$GLOBALS['changed'][62000]=false;
if(PHP_OS_FAMILY==='Linux'){
    $sockets=[];
    try{
        $listener=stream_socket_server('tcp://127.0.0.1:0',$errno,$error);if($listener===false)throw new RuntimeException('Loopback listener unavailable.');$sockets[]=$listener;
        $address=stream_socket_get_name($listener,false);$client=stream_socket_client('tcp://'.$address,$errno,$error,2);$sockets[]=$client;$accepted=stream_socket_accept($listener,2);$sockets[]=$accepted;
        $peer=stream_socket_get_name($accepted,true);$remotePort=(int)substr($peer,strrpos($peer,':')+1);$localPort=(int)substr($address,strrpos($address,':')+1);
        $core->properties['Port']=$localPort;$core->properties['Server']='127.0.0.1';
        $s=['REQUEST_METHOD'=>'POST','REQUEST_URI'=>'/hook/secrets_frontend_50365','REMOTE_ADDR'=>'127.0.0.1','REMOTE_PORT'=>$remotePort,'HTTP_HOST'=>'heartbeat.ap-fischer.de:46901','HTTP_ORIGIN'=>'https://heartbeat.ap-fischer.de:46901','CONTENT_TYPE'=>'application/json'];
        $GLOBALS['_IPS']=['SENDER'=>'WebHook','INSTANCE'=>0];$ok(SecretsFrontendTransport::nativeTLS($GLOBALS['_IPS'],$s),'Actual kernel connection did not match the configured SSL listener.');
        $settings=array_replace(SecretsFrontendConfiguration::DEFAULTS,['Enabled'=>true,'AdminOrigin'=>'https://heartbeat.ap-fischer.de:46901']);$calls=0;
        $gateway=static function($request)use(&$calls){$calls++;return ['status'=>401,'data'=>['error'=>'Administrator session required.']];};
        $r=SecretsFrontendHttp::response($settings,50365,$s,$s['REQUEST_URI'],'','','{"action":"session","data":{}}',$gateway);
        $ok($r['status']===401&&$calls===1,'Bound SSL transport did not reach the existing authentication boundary.');
        $core->properties['EnableSSL']=false;$s['HTTP_X_FORWARDED_PROTO']='https';$r=SecretsFrontendHttp::response($settings,50365,$s,$s['REQUEST_URI'],'','','{"action":"session","data":{}}',$gateway);
        $ok($r['status']===403&&$calls===1,'Forged HTTPS headers on a plain local listener reached authentication.');$core->properties['EnableSSL']=true;
        $core->properties['Server']='127.0.0.2';$ok(!SecretsFrontendTransport::nativeTLS($GLOBALS['_IPS'],$s),'An SSL listener bound to another local address vouched for this socket.');$core->properties['Server']='127.0.0.1';
        $core->properties['Port']=$localPort===65535?65534:$localPort+1;$ok(!SecretsFrontendTransport::nativeTLS($GLOBALS['_IPS'],$s),'The existence of a different SSL listener vouched for this socket.');
    }finally{foreach(array_reverse($sockets)as$socket)if(is_resource($socket))fclose($socket);}
}
echo "PASS $checks native transport checks: engine caller, kernel socket binding, NAT, IPv4/IPv6, plaintext/header spoof rejection, applied listener settings and unchanged authentication\n";
