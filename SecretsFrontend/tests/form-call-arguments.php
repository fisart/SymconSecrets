<?php
declare(strict_types=1);
require_once __DIR__.'/BootstrapFixture.php';

/** Symcon wrapper arguments do not inherit optional defaults from module methods. */
$checked=0;
$script=static function(string $source)use(&$checked):void{
    preg_match_all('/(SECF|SECB)_(\w+)\s*\(/',$source,$matches,PREG_SET_ORDER|PREG_OFFSET_CAPTURE);
    foreach($matches as$match){
        $depth=1;$args=0;$content=false;$quote='';$length=strlen($source);
        for($j=$match[0][1]+strlen($match[0][0]);$j<$length;$j++){
            $part=$source[$j];
            if($quote!==''){if($part==='\\'){$j++;continue;}if($part===$quote)$quote='';continue;}
            if($part==='\''||$part==='"'){$quote=$part;$content=true;continue;}
            if(in_array($part,['(','[','{'],true)){$depth++;$content=true;continue;}
            if(in_array($part,[')',']','}'],true)){$depth--;if($depth===0)break;continue;}
            if($part===','&&$depth===1)$args++;elseif(!preg_match('/\s/',$part))$content=true;
        }
        if($content)$args++;else $args=0;
        $method=new ReflectionMethod($match[1][0]==='SECF'?SecretsFrontend::class:SecretsBackend::class,$match[2][0]);
        $expected=1+$method->getNumberOfParameters();
        secExpect($args===$expected,$match[1][0].'_'.$match[2][0].' console call passes '.$args.' arguments; Symcon requires '.$expected.' including the instance ID.');$checked++;
    }

};
$walk=static function(array $items)use(&$walk,$script):void{
    foreach($items as$key=>$value){if(is_array($value)){$walk($value);continue;}if(is_string($key)&&is_string($value)&&(str_starts_with($key,'on')||$key==='validate'))$script($value);}
};
foreach(['SecretsFrontend','SecretsBackend']as$module)$walk(json_decode(file_get_contents(__DIR__.'/../../'.$module.'/form.json'),true,32,JSON_THROW_ON_ERROR));
secExpect($checked>15,'Console argument audit did not inspect the module form actions.');
echo 'PASS '.$checked." frontend/backend console calls supply every generated-wrapper argument\n";
