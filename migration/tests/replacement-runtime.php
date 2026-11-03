<?php
declare(strict_types=1);
require_once __DIR__.'/../../SecretsFrontend/tests/BootstrapFixture.php';
class IPSModuleStrict extends IPSModule
{
    protected function RegisterVariableString($k,$n,$p='',$position=0): void {if(!array_key_exists($k,$this->values))parent::RegisterVariableString($k,$n,$p,$position);}
    protected function RegisterPropertyInteger($k,$v): void {if(!array_key_exists($k,$this->properties))parent::RegisterPropertyInteger($k,$v);}
    protected function RegisterPropertyString($k,$v): void {if(!array_key_exists($k,$this->properties))parent::RegisterPropertyString($k,$v);}
    protected function RegisterPropertyBoolean($k,$v): void {if(!array_key_exists($k,$this->properties))parent::RegisterPropertyBoolean($k,$v);}
}
$entry=__DIR__.'/../../SecretsManager/module.php';$template=__DIR__.'/../templates/SecretsManager.php.txt';
if(file_get_contents($entry)===file_get_contents($template)){require $entry;$actualEntry=true;}
else{eval(substr(file_get_contents($template),5));$actualEntry=false;}
function SECB_CallLegacyAPI(int $id,int $source,string $method,string $args): string {return $GLOBALS['instances'][$id]->CallLegacyAPI($source,$method,$args);}
function SECB_IsNativePortalAuthenticated(int $id): bool {return $GLOBALS['instances'][$id]->IsNativePortalAuthenticated();}
function SECB_GetNativePortalLoginURL(int $id,string $path,string $server): string {return $GLOBALS['instances'][$id]->GetNativePortalLoginURL($path,$server);}
function SEC_GetKeys(int $id): string {return $GLOBALS['instances'][$id]->GetKeys();}
function SEC_GetSecret(int $id,string $ident): string {return $GLOBALS['instances'][$id]->GetSecret($ident);}
function SEC_SetRecordFields(int $id,string $path,array $fields,string $scope): bool {return $GLOBALS['instances'][$id]->SetRecordFields($path,$fields,$scope);}
function SEC_IsPortalAuthenticated(int $id): bool {return $GLOBALS['instances'][$id]->IsPortalAuthenticated();}
function IPS_GetConfiguration(int $id): string {throw new RuntimeException('A retired manager configuration must never be consulted.');}
class ReplacementReadyBackend extends IPSModule {public function GetNativeInfo():string{return json_encode(['initialized'=>true,'ready'=>true,'vaultId'=>'other-vault']);}}
$checks=0;$ok=static function(bool $value,string $message)use(&$checks):void{secExpect($value,$message);++$checks;};
$warnings=[];set_error_handler(static function(int $severity,string $message)use(&$warnings):bool{if($severity===E_USER_WARNING){$warnings[]=$message;return true;}return false;});
$root=sys_get_temp_dir().'/sec-native-replacement-'.bin2hex(random_bytes(8));
$GLOBALS['moduleIDs']=[5100=>SecretsBackend::FRONTEND,5101=>'{52165EDD-B2C0-40EC-8A59-42A97319B6E2}',49800=>SecretsBackendLegacyImport::MODULE,59597=>SecretsBackendLegacyImport::MODULE,700=>'{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}'];
$hooks=new IPSModule(700);$hooks->properties['Hooks']='[{"Hook":"/hook/secrets_49800","TargetID":49800}]';
$front=new SecretsFrontend(5100);$front->Create();$back=new SecretsBackend(5101);$back->Create();
$request=['origin'=>'https://secrets.example.test','cookie'=>'','csrf'=>'','remote'=>'test'];$gateway=new ReflectionMethod(SecretsFrontend::class,'gateway');
$invoke=static function(string $action,array $data=[])use($gateway,$front,&$request):array{$r=$gateway->invoke($front,['action'=>$action,'data'=>$data]+$request);if($r['status']!==200)throw new RuntimeException($action.': '.json_encode($r));return $r;};
try{
    $key=secKey();$choice=['backend'=>5101,'portal'=>0,'documentation'=>0,'theme'=>'system','vaultDirectory'=>$root.'/data','keyDirectory'=>$root.'/keys','addPortalLink'=>false,'debugEnabled'=>false,'privateACLConfirmed'=>true,'persistenceConfirmed'=>true];
    $login=secBootstrapInitialize($front,$request,$key,$choice);$request['cookie']=explode(';',$login['cookie'])[0];$request['csrf']=$login['data']['csrf'];$counter=1;
    $approve=static function(array $op)use($invoke,$key,&$counter):array{$p=json_decode(json_encode($invoke('prepare',['operation'=>$op])['data']),true);return $invoke('approve',['challengeId'=>$p['challengeId'],'credential'=>secAssertion($key,$p['options']['challenge'],++$counter)])['data'];};
    $approve(['kind'=>'save','scope'=>'global','path'=>['Hikvision'],'revision'=>$invoke('session')['data']['revision'],'mode'=>'create','json'=>'{"User":"native-user","PW":"NATIVE-ONLY-CANARY"}']);
    $approve(['kind'=>'save','scope'=>'local','path'=>['Private'],'revision'=>$invoke('session')['data']['revision'],'mode'=>'create','json'=>'{"token":"NATIVE-LOCAL-CANARY"}']);
    foreach([49800,59597]as$id){
        $m=new SecretsManager($id);$m->properties=['OperationMode'=>$id===49800?0:2,'KeyFolderPath'=>$root.'/retired-does-not-exist','PortalEnabled'=>false,'SlaveURLs'=>'[{"Url":"https://retired.invalid/hook/secrets_123"}]'];$m->values=['Vault'=>'RETIRED-CIPHERTEXT-MUST-NOT-BE-READ','PortalDebugMessage'=>'retained'];$before=$m->properties;$m->Create();$m->ApplyChanges();
        $ok($m->status===102,'Native replacement did not activate against the unique ready backend.');$ok($m->properties['NativeBackendInstanceID']===5101,'Backend was not detected automatically.');
        foreach($before as$property=>$value)$ok($m->properties[$property]===$value,'Retired configuration changed.');
        $ok($m->values['Vault']==='RETIRED-CIPHERTEXT-MUST-NOT-BE-READ','Saved old ciphertext was changed.');
        $ok(json_decode(SEC_GetKeys($id),true)===['Hikvision'],'Unchanged SEC call did not read the native vault.');
        $ok(str_contains(SEC_GetSecret($id,'Hikvision'),'NATIVE-ONLY-CANARY'),'SEC read depended on retired storage.');
        $ok(str_contains(SEC_GetSecret($id,'__LOCAL__'),'NATIVE-LOCAL-CANARY'),'SEC Local read did not use the native installation.');
        $info=json_decode($m->GetReplacementInfo(),true);$ok($info['engine']==='native-only'&&!$info['oldImplementationEnabled']&&!$info['oldStorageUsed']&&$info['ready'],'Replacement metadata suggested a legacy fallback.');
        $ok(!SEC_SetRecordFields($id,'blocked',['key'=>'value'],'global'),'Default replacement writes were not frozen.');
    }
    $a=$GLOBALS['instances'][49800];$b=$GLOBALS['instances'][59597];$ok($warnings===[],'Successful replacement reads produced warnings.');
    $hookRows=json_decode($hooks->properties['Hooks'],true);$ok(count(array_filter($hookRows,static fn($h)=>$h['Hook']==='/hook/secrets_49800'&&$h['TargetID']===49800))===1,'Existing hook was duplicated or reassigned.');
    $ok(!file_exists($root.'/retired-does-not-exist'),'Retired key directory was created or accessed.');
    $grant=['kind'=>'nativeLegacyAccess','instance'=>5101,'mode'=>2,'enabled'=>true,'read'=>true,'write'=>true,'portal'=>false,'frozen'=>false,'bulk'=>false];$approve($grant);
    foreach([0,1,2]as$oldRole){$a->properties['OperationMode']=$oldRole;$ok(SEC_SetRecordFields(49800,'Hikvision',['User'=>'native-role-independent'],'global'),'An old Master/Slave role controlled the new peer vault.');}
    $ok(str_contains(SEC_GetSecret(59597,'Hikvision'),'native-role-independent'),'Preserved SEC instances did not reach the same native backend.');
    $_SERVER=['HTTP_HOST'=>'secrets.example.test','HTTP_COOKIE'=>$request['cookie'],'REMOTE_ADDR'=>'test','REQUEST_URI'=>'/hook/secrets_49800','REQUEST_METHOD'=>'GET'];
    $ok(SEC_IsPortalAuthenticated(49800),'The replacement used old PortalEnabled/passkey state instead of the native session.');
    $_SERVER['HTTP_COOKIE']='';$ok(!SEC_IsPortalAuthenticated(49800),'Anonymous native session authenticated.');$_SERVER['HTTP_COOKIE']=$request['cookie'];
    $callHook=static function(array $get,string $method='GET')use($a):array{$_GET=$get;$_SERVER['REQUEST_METHOD']=$method;ob_start();(new ReflectionMethod(SecretsManager::class,'ProcessHookData'))->invoke($a);return [http_response_code(),ob_get_clean()];};
    [$status,$body]=$callHook(['portal'=>'1','return'=>'/hook/library']);$ok($status===303&&$body==='','Existing login hook did not use native authentication.');
    [$status]=$callHook([]);$ok($status===303,'Old base URL did not open the new administration page.');
    [$status]=$callHook(['portal'=>'1','return'=>'//evil.invalid']);$ok($status===403,'Replacement accepted an external return address.');
    [$status]=$callHook([],'POST');$ok($status===403,'Replacement accepted old synchronization traffic.');
    foreach(['SyncSlaves','SaveAuthToken','InitializeSlaveSecretStore']as$method){secReject(static function()use($a,$method):void{if($method==='SyncSlaves')$a->$method();else $a->$method('retired-token');},'A retired synchronization operation ran.');++$checks;}
    $ok(SecretsBackendLegacyImport::sources()===[],'Retired managers were discovered as import sources.');
    secReject(static fn()=>SecretsBackendLegacyImport::read(49800,65536),'Retired vault files were read.');++$checks;
    $policy=SecretsBackendNativeLegacyHTTPS::proposal('https://new-peer.example.test/hook/secrets_peer_99');$ok($policy['policy']===['mode'=>'strict'],'Peer transport depended on retired manager configuration.');
    $grant['enabled']=false;$approve($grant);$ok(SEC_GetKeys(49800)==='[]','Replacement bypassed an explicit native read revocation.');$grant['enabled']=true;$approve($grant);
    $back->properties['Enabled']=false;$ok(SEC_GetKeys(49800)==='[]'&&!json_decode($a->GetReplacementInfo(),true)['ready'],'Unavailable native backend fell back to old storage.');$back->properties['Enabled']=true;
    $other=new ReplacementReadyBackend(5102);$GLOBALS['moduleIDs'][5102]='{52165EDD-B2C0-40EC-8A59-42A97319B6E2}';
    $new=new SecretsManager(50000);$GLOBALS['moduleIDs'][50000]=SecretsBackendLegacyImport::MODULE;$new->Create();$new->ApplyChanges();$ok($new->status===200&&$new->properties['NativeBackendInstanceID']===0,'Ambiguous backend selection guessed a target.');
    $a->properties['NativeBackendInstanceID']=5102;$ok(SEC_GetKeys(49800)==='[]','Pinned vault identity silently changed.');$a->properties['NativeBackendInstanceID']=5101;
    unset($GLOBALS['instances'][5102],$GLOBALS['moduleIDs'][5102]);$back->ApplyChanges();$back->Recover();$a->ApplyChanges();$ok(str_contains(SEC_GetSecret(49800,'Hikvision'),'native-role-independent'),'Preserved native binding failed after restart.');$ok(!SEC_IsPortalAuthenticated(49800),'Restart retained the browser session.');
    echo 'PASS '.$checks.' native-only SEC replacement checks ('.($actualEntry?'actual registered module':'exact replacement template')."): unchanged IDs/calls, automatic/pinned backend, no old configuration/files/auth/sync/fallback, frozen/approved writes, native session/redirects, revocation, ambiguity and restart\n";
}finally{restore_error_handler();$remove=static function($p)use(&$remove){if(is_dir($p)&&!is_link($p)){foreach(scandir($p)as$n)if($n!=='.'&&$n!=='..')$remove($p.'/'.$n);rmdir($p);}elseif(file_exists($p))unlink($p);};if(is_dir($root))$remove($root);}
