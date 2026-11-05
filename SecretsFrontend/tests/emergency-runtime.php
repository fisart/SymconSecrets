<?php
declare(strict_types=1);
require_once __DIR__.'/BootstrapFixture.php';
class EmergencyBackendProbe extends SecretsBackend {
    protected function emergencyHTTPS(string $url,string $bytes,array $policy,float $timeout): string { return ($GLOBALS['emergencyTransport'])($url,$bytes,$policy,$timeout); }
}
$GLOBALS['emergencyRuntimeTest']=true;
$emergencyKernel=sys_get_temp_dir().'/sec-emergency-runtime-'.bin2hex(random_bytes(8));
$GLOBALS['testKernel']=$emergencyKernel.'/';
try{require __DIR__.'/native-lifecycle.php';}
finally{
    $clean=static function($p)use(&$clean):void{if(is_dir($p)&&!is_link($p)){foreach(scandir($p)as$n)if($n!=='.'&&$n!=='..')$clean($p.'/'.$n);rmdir($p);}elseif(file_exists($p)||is_link($p))unlink($p);};
    if(is_dir($emergencyKernel))$clean($emergencyKernel);
}
