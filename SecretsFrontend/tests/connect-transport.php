<?php
declare(strict_types=1);
require_once __DIR__.'/../Http.php';
function ctExpect(bool $value,string $message): void { if(!$value)throw new RuntimeException($message); }
$origin='https://'.str_repeat('a',32).'.ipmagic.de';$path='/hook/secrets_frontend_123';
$settings=array_replace(SecretsFrontendConfiguration::DEFAULTS,['Enabled'=>true,'AdminOrigin'=>'https://primary.example.test']);
$server=['REQUEST_METHOD'=>'GET','REQUEST_URI'=>$path,'HTTP_HOST'=>parse_url($origin,PHP_URL_HOST),'REMOTE_ADDR'=>'127.0.0.1'];
$backup=['version'=>1,'origin'=>$origin,'generation'=>str_repeat('1',64),'status'=>'pending'];
$ui=['backupOrigin'=>$backup,'connectDiscovery'=>['available'=>true,'origin'=>$origin]];
$reply=SecretsFrontendHttp::response($settings,123,$server,$path,'','', '',null,$ui);
ctExpect($reply['status']===200&&str_contains($reply['body'],'"backupEnrollment":true'),'Observed Connect loopback request was rejected.');
ctExpect(str_contains($reply['headers']['Content-Security-Policy'],'connect-src '.$origin.';'),'Backup CSP targeted the primary address.');
foreach ([['REMOTE_ADDR'=>'198.51.100.20'],['REMOTE_ADDR'=>'192.168.1.20'],['REMOTE_ADDR'=>'127.0.0.2'],['HTTP_X_FORWARDED_HOST'=>parse_url($origin,PHP_URL_HOST)],['HTTP_X_FORWARDED_PROTO'=>'https'],['HTTP_FORWARDED'=>'proto=https'],['HTTPS'=>'off'],['REQUEST_SCHEME'=>'http']] as $override) {
 $r=SecretsFrontendHttp::response($settings,123,array_replace($server,$override),$path,'','', '',null,$ui);
 ctExpect($r['status']===403,'Unqualified or contradictory relay evidence admitted: '.json_encode(array_keys($override)));
}
foreach ([[],['available'=>false,'origin'=>$origin],['available'=>true,'origin'=>'https://'.str_repeat('b',32).'.ipmagic.de']] as $discovery) {
 $r=SecretsFrontendHttp::response($settings,123,$server,$path,'','', '',null,array_replace($ui,['connectDiscovery'=>$discovery]));ctExpect($r['status']===403,'Missing, inactive or changed Connect address was trusted.');
}
$wrong=$server;$wrong['HTTP_HOST']=str_repeat('b',32).'.ipmagic.de';$wrong['REQUEST_METHOD']='POST';
$r=SecretsFrontendHttp::response($settings,123,$wrong,$path,'','', '',null,$ui);ctExpect($r['status']===403,'Wrong tenant host admitted.');
$revoked=$ui;$revoked['backupOrigin']['status']='revoked';$r=SecretsFrontendHttp::response($settings,123,$server,$path,'','', '',null,$revoked);ctExpect($r['status']!==200,'Revoked route served a page through loopback.');
$post=$server+['HTTP_ORIGIN'=>$origin,'CONTENT_TYPE'=>'application/json'];$post['REQUEST_METHOD']='POST';$calls=0;
$gateway=static function($request)use(&$calls){++$calls;return ['status'=>401,'data'=>['error'=>'Session required.']];};
$r=SecretsFrontendHttp::response($settings,123,$post,$path,'','', '{"action":"session","data":{}}',$gateway,$ui);ctExpect($calls===1&&$r['status']===401,'Relay profile bypassed backend authentication.');
$post['HTTP_ORIGIN']='https://evil.example';$r=SecretsFrontendHttp::response($settings,123,$post,$path,'','', '{"action":"session","data":{}}',$gateway,$ui);ctExpect($calls===1&&$r['status']===403,'Wrong Origin reached backend.');
echo "PASS exact active Connect loopback profile, missing PHP TLS flags, remote/header spoof rejection, changed tenant, revocation and backend authentication\n";
