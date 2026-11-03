<?php
declare(strict_types=1);
/** Run as a NEW local PHP script BEFORE selecting the replacement branch.
 * Secret updates (including automated writers) must be frozen across all platforms.
 * This verifies existing application data through the current APIs. No data, settings,
 * keys, permissions or module code are changed. Values, hashes and raw errors stay hidden.
 */
(static function():void{
    $report=['test'=>'Native-only replacement preflight','checks'=>[],'readyForBranchSwitch'=>false];
    $finish=static function(string $result)use(&$report):void{$report['result']=$result;echo json_encode($report,JSON_PRETTY_PRINT|JSON_INVALID_UTF8_SUBSTITUTE|JSON_THROW_ON_ERROR).PHP_EOL;};
    $call=static function(string $function,array $args):array{$level=ob_get_level();ob_start();$warned=false;set_error_handler(static function()use(&$warned):bool{$warned=true;return true;});try{$value=$function(...$args);return ['ok'=>!$warned,'value'=>$value];}catch(Throwable $error){return ['ok'=>false,'value'=>null];}finally{restore_error_handler();while(ob_get_level()>$level)ob_end_clean();}};
    $decode=static function($json){if(!is_string($json))throw new RuntimeException('Unsupported API result.');return json_decode($json,false,32,JSON_THROW_ON_ERROR);};
    $subset=static function($expected,$actual)use(&$subset):bool{
        if(is_object($expected)){if(!is_object($actual))return false;foreach(get_object_vars($expected)as$key=>$value){if($key==='__folder')continue;if(!property_exists($actual,$key)||!$subset($value,$actual->{$key}))return false;}return true;}
        if(is_array($expected)){if(!is_array($actual)||count($expected)!==count($actual))return false;foreach($expected as$i=>$value)if(!$subset($value,$actual[$i]))return false;return true;}
        return gettype($expected)===gettype($actual)&&$expected===$actual;
    };
    $matches=static function(string $old,string $new)use($decode,$subset):bool{if($old===$new)return true;try{$a=$decode($old);$b=$decode($new);return (is_object($a)||is_array($a))&&$subset($a,$b);}catch(Throwable $error){return false;}};
    $keys=static function($json):array{if(!is_string($json))throw new RuntimeException('No key list.');$a=json_decode($json,true,16,JSON_THROW_ON_ERROR);if(!is_array($a)||!array_is_list($a))throw new RuntimeException('Invalid key list.');foreach($a as$key)if(!is_string($key)&&!is_int($key))throw new RuntimeException('Invalid key name.');return array_map('strval',$a);};
    try{
        foreach(['IPS_GetInstanceListByModuleID','IPS_GetInstance','IPS_HasChanges','IPS_GetObjectIDByIdent','GetValueString','SEC_GetKeys','SEC_GetSecret','SECB_GetNativeInfo','SECB_GetKeys','SECB_GetSecret','SECB_GetLegacyAPIStatus']as$fn)if(!function_exists($fn)){ $finish('UPDATE_REQUIRED: run in the test console with the normal Secrets development branch updated first.');return; }
        if(function_exists('SEC_GetReplacementInfo')){$finish('ALREADY_REPLACED: the SEC interface is native-only. It cannot provide an independent old-data baseline. Use the saved pre-switch report and offline backups.');return;}
        $oldIDs=IPS_GetInstanceListByModuleID('{7C5A3841-3F7B-4D2A-9E1C-5B6D8F9A0E12}');$newIDs=IPS_GetInstanceListByModuleID('{52165EDD-B2C0-40EC-8A59-42A97319B6E2}');
        if(!$oldIDs||!$newIDs){$finish('INCONCLUSIVE: no old instances or native backends were found.');return;}
        $ready=[];foreach($newIDs as$id){$id=(int)$id;$r=$call('SECB_GetNativeInfo',[$id]);$i=$r['ok']?$decode($r['value']):null;if($i&&($i->initialized??false)&&($i->ready??false)&&!IPS_HasChanges($id))$ready[]=$id;}
        if(count($ready)!==1){$report['readyBackendIDs']=$ready;$finish('INCONCLUSIVE: select the intended native backend by name when multiple are ready; this script does not guess or change bindings.');return;}
        $backend=$ready[0];$report['nativeBackend']=$backend;$r=$call('SECB_GetLegacyAPIStatus',[$backend]);$access=$r['ok']?$decode($r['value']):null;
        if(!$access||!($access->readAllowed??false)){$finish('BLOCKED: native application read access or backend readiness is unavailable.');return;}
        $newKeysCall=$call('SECB_GetKeys',[$backend]);if(!$newKeysCall['ok'])throw new RuntimeException('Native keys unavailable.');$newKeys=$keys($newKeysCall['value']);
        $all=true;foreach($oldIDs as$old){$old=(int)$old;$row=['oldInstance'=>$old,'globalCompared'=>0,'missingOrDifferent'=>0,'localCompared'=>false,'stable'=>false,'pass'=>false];
            try{
                if(IPS_HasChanges($old)||(IPS_GetInstance($old)['InstanceStatus']??0)!==102)throw new RuntimeException('Old instance unavailable.');
                $vaultID=IPS_GetObjectIDByIdent('Vault',$old);$before=hash('sha256',GetValueString($vaultID));
                $nativeBefore=$decode($call('SECB_GetNativeInfo',[$backend])['value']);
                $r=$call('SEC_GetKeys',[$old]);if(!$r['ok'])throw new RuntimeException('Old keys failed.');$oldKeys=$keys($r['value']);
                if(!$oldKeys)throw new RuntimeException('An empty old list cannot prove decryption/read success.');
                foreach($oldKeys as$key){
                    if(!in_array($key,$newKeys,true)){$row['missingOrDifferent']++;continue;}
                    $a=$call('SEC_GetSecret',[$old,$key]);$b=$call('SECB_GetSecret',[$backend,$key]);
                    if(!$a['ok']||!$b['ok']||!is_string($a['value'])||!is_string($b['value'])||!$matches($a['value'],$b['value']))$row['missingOrDifferent']++;
                    $row['globalCompared']++;unset($a,$b);
                }
                $a=$call('SEC_GetSecret',[$old,'__LOCAL__']);$b=$call('SECB_GetSecret',[$backend,'__LOCAL__']);
                $row['localCompared']=$a['ok']&&$b['ok']&&is_string($a['value'])&&is_string($b['value'])&&($a['value']===''||$matches($a['value'],$b['value']));unset($a,$b);
                $endKeys=$call('SEC_GetKeys',[$old]);$nativeAfter=$decode($call('SECB_GetNativeInfo',[$backend])['value']);$endAccess=$decode($call('SECB_GetLegacyAPIStatus',[$backend])['value']);
                $row['stable']=$endKeys['ok']&&$keys($endKeys['value'])===$oldKeys&&hash_equals($before,hash('sha256',GetValueString($vaultID)))&&json_encode($nativeBefore->head??null)===json_encode($nativeAfter->head??null)&&($endAccess->readAllowed??false);
                $row['pass']=$row['globalCompared']===count($oldKeys)&&$row['missingOrDifferent']===0&&$row['localCompared']&&$row['stable'];
                $row['meaning']=$row['pass']?'All old application values are present in the native vault. Native objects may contain additional fields/records; native administrator credentials are separate.':'Data missing/different, Local comparison failed, or a source changed during verification. Do not switch.';
            }catch(Throwable $error){$row['meaning']='Could not establish a readable, stable old baseline. No raw error or secret value is printed. Do not switch without resolving this instance.';}
            $report['checks'][]=$row;$all=$all&&$row['pass'];
        }
        $report['dataVerified']=$all;$report['readyForBranchSwitch']=false;
        $report['remaining']='A passing data check is not switch authorization: complete and restore-test backups, freeze all automated/manual writers, review unsupported legacy administration calls, and verify all consumers. The branch replaces every old module instance and has no old storage/auth/sync fallback.';
        $finish($all?'DATA_CHECK_PASS: deployment and rollback prerequisites still required.':'DO_NOT_SWITCH: at least one old instance is unverified.');
    }catch(Throwable $error){$finish('INCONCLUSIVE: a prerequisite or API read failed. Raw errors and secret values are concealed.');}
})();
