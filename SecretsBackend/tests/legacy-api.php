<?php
declare(strict_types=1);
require_once __DIR__.'/../../SecretsFrontend/tests/BootstrapFixture.php';
if(!defined('KL_MESSAGE')){define('KL_MESSAGE',0);define('KL_WARNING',1);define('KL_ERROR',2);}
class IPSModuleStrict extends IPSModule
{
    protected function RegisterVariableString($k,$n,$p='',$position=0): void { if(!isset($this->values[$k]))parent::RegisterVariableString($k,$n,$p,$position); }
    protected function GetStatus(): int {return $this->status;}
    protected function LogMessage($message,$level): void {}
    protected function GetIDForIdent($ident): int {return 0;}
}
require_once __DIR__.'/../../SecretsManager/module.php';
$adapterSource=file_get_contents(__DIR__.'/../../.migration/templates/SecretsManager.php.txt');
eval(str_replace(['<?php','class SecretsManager extends'],['','class LegacyReplacementAdapter extends'],$adapterSource));
function SECB_CallLegacyAPI(int $id,int $source,string $method,string $arguments): string {return $GLOBALS['instances'][$id]->CallLegacyAPI($source,$method,$arguments);}
function SECB_CheckLegacyPortalSession(int $id,int $source,string $server): bool {return $GLOBALS['instances'][$id]->CheckLegacyPortalSession($source,$server);}
function SECB_GetLegacyLoginURL(int $id,int $source,string $path,string $server): string {return $GLOBALS['instances'][$id]->GetLegacyLoginURL($source,$path,$server);}
function SEC_GetSecret(int $id,string $ident): string {return $GLOBALS['instances'][$id]->GetSecret($ident);}
$readWarnings=[];set_error_handler(static function(int $severity,string $message)use(&$readWarnings):bool{if($severity===E_USER_WARNING&&(str_starts_with($message,'SecretsBackend:')||str_starts_with($message,'SecretsManager:'))){$readWarnings[]=$message;return true;}return false;});
$checks=0;$ok=static function(bool $v,string $message)use(&$checks):void{secExpect($v,$message);$checks++;};
$root=sys_get_temp_dir().'/sec-legacy-api-'.bin2hex(random_bytes(8));
$GLOBALS['moduleIDs']=[5100=>SecretsBackend::FRONTEND,5101=>'{52165EDD-B2C0-40EC-8A59-42A97319B6E2}',49800=>SecretsBackendLegacyImport::MODULE,700=>'{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}'];
$hooks=new IPSModule(700);$hooks->properties['Hooks']='[]';
$front=new SecretsFrontend(5100);$front->Create();$back=new SecretsBackend(5101);$back->Create();
$request=['origin'=>'https://secrets.example.test','cookie'=>'','csrf'=>'','remote'=>'test'];
$gateway=new ReflectionMethod(SecretsFrontend::class,'gateway');
$invoke=static function(string $action,array $data=[])use($gateway,$front,&$request):array{
    $r=$gateway->invoke($front,['action'=>$action,'data'=>$data]+$request);if($r['status']!==200)throw new RuntimeException($action.': '.json_encode($r));return $r;
};
try{
    $key=secKey();$choice=['backend'=>5101,'portal'=>0,'documentation'=>0,'theme'=>'system','vaultDirectory'=>$root.'/data','keyDirectory'=>$root.'/keys','addPortalLink'=>false,'debugEnabled'=>false,'privateACLConfirmed'=>true,'persistenceConfirmed'=>true];
    $login=secBootstrapInitialize($front,$request,$key,$choice);$request['cookie']=explode(';',$login['cookie'])[0];$request['csrf']=$login['data']['csrf'];$counter=1;
    $approve=static function(array $operation)use($invoke,$key,&$counter):array{$p=json_decode(json_encode($invoke('prepare',['operation'=>$operation])['data']),true);return $invoke('approve',['challengeId'=>$p['challengeId'],'credential'=>secAssertion($key,$p['options']['challenge'],++$counter)])['data'];};
    $legacy=new SecretsManager(49800);$legacy->Create();$legacy->status=102;$legacy->properties['OperationMode']=1;$legacy->properties['NativeBackendInstanceID']=5101;$legacy->properties['KeyFolderPath']=$root.'/old';mkdir($root.'/old',0700,true);file_put_contents($root.'/old/master.key',bin2hex(random_bytes(16)));
    $global=['Hikvision'=>['User'=>'camera-user','PW'=>'CANARY-LEGACY','Nested'=>['key'=>'nested']],'zero'=>0,'truth'=>true,'nothing'=>null,'false'=>false,'decimal'=>1.25,'empty'=>[],'slash/key'=>['field'=>'literal'],'unicode'=>'ä€','numeric'=>['0'=>'zero','1'=>'one']];$local=['OnlyHere'=>['token'=>'PRIVATE-CANARY']];
    $saved=(new ReflectionMethod(SecretsManager::class,'_encryptAndSave'))->invoke($legacy,$global+['__LOCAL__'=>$local]);$ok($saved,'Could not prepare actual old encrypted vault.');
    $store=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);$current=$store->read();
    $store->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','fixture-data'),static function(array $s)use($global,$local):array{$s['vault']['global']=SecretsBackendTree::parse(json_encode($global,JSON_THROW_ON_ERROR));$s['vault']['local']=SecretsBackendTree::parse(json_encode($local,JSON_THROW_ON_ERROR));return $s;});
    $compat=new LegacyReplacementAdapter(49800);$compat->Create();$compat->properties=$legacy->properties;$compat->values=$legacy->values;$compat->properties['PortalEnabled']=true;$compat->ApplyChanges();$ok($compat->status===102,'Replacement adapter did not register the existing hook.');
    $oldCipher=$legacy->values['Vault'];$oldKey=file_get_contents($root.'/old/master.key');
    $ok(SEC_GetSecret(49800,'Hikvision')==='','Unapproved SEC reader exposed a value.');
    $directStatus=json_decode($back->GetLegacyAPIStatus(),true);
    $ok($directStatus['code']==='READ_ALLOWED'&&$directStatus['readAllowed']&&$directStatus['defaultReadAccess']&&!$directStatus['grantPresent']&&$directStatus['writesFrozen'],'Direct local reads did not work with frozen defaults.');
    $warningCount=count($readWarnings);$ok($back->GetKeys()!=='[]'&&count($readWarnings)===$warningCount,'Default GetKeys required a separate grant.');
    $ok(str_contains($back->GetSecret('Hikvision'),'CANARY-LEGACY'),'Default direct record read failed.');
    $ok(!$back->SetRecordFields('Default blocked',['key'=>'value'],'local'),'Default local reads enabled writes.');
    $ok(!$back->SetRecordFields('Default blocked',['key'=>'value'],'global')&&!$back->ImportLocalSecrets('{"__LOCAL__":{}}'),'Default reads enabled Global writes or Local replacement.');
    $ok(str_contains($back->GetSecret('__LOCAL__'),'PRIVATE-CANARY')&&str_contains($back->ExportLocalSecrets(),'PRIVATE-CANARY'),'Default Local application reads failed.');
    $ok(!$back->IsPortalAuthenticated(),'Default local reads granted browser access.');
    $envelope=json_decode($back->CallLegacyAPI(5101,'GetKeys','[]'),true);$ok($envelope['error']===null&&$envelope['value']!=='[]','Default dispatcher read was refused.');
    $ok(!isset($store->read()['state']['native']['legacyAccess']['5101']),'Default read created a persistent grant or approval mutation.');
    $directGrant=['kind'=>'nativeLegacyAccess','instance'=>5101,'mode'=>2,'enabled'=>true,'read'=>true,'write'=>false,'portal'=>false,'frozen'=>true,'bulk'=>false];$approve($directGrant);
    $directStatus=json_decode($back->GetLegacyAPIStatus(),true);$ok($directStatus['code']==='READ_ALLOWED'&&$directStatus['readAllowed']&&$directStatus['writesFrozen'],'Read-only direct backend grant was not diagnosed.');
    $warningCount=count($readWarnings);$ok($back->GetKeys()!=='[]'&&count($readWarnings)===$warningCount,'Approved direct read failed or emitted a refusal warning.');
    $ok(!str_contains($back->GetLegacyAPIStatus(),'CANARY')&&!str_contains($back->GetLegacyAPIStatus(),'Hikvision'),'Diagnostic metadata leaked a value or record name.');
    foreach([['enabled',false,'READ_GRANT_DISABLED'],['read',false,'READ_NOT_APPROVED']]as[$field,$value,$code]){$candidate=$directGrant;$candidate[$field]=$value;$approve($candidate);$ok(json_decode($back->GetLegacyAPIStatus(),true)['code']===$code,'Wrong disabled/read-right diagnostic.');$warningCount=count($readWarnings);$ok($back->GetKeys()==='[]'&&count($readWarnings)===$warningCount+1,'Defaults bypassed explicit revocation or suppressed its warning.');$envelope=json_decode($back->CallLegacyAPI(5101,'GetKeys','[]'),true);$ok(($envelope['error']['code']??'')==='LEGACY_API_REFUSED','Dispatcher hid an explicit refusal.');}
    $approve($directGrant);
    $savedGlobal=$store->read()['state']['vault']['global'];$current=$store->read();
    $store->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','empty-read-fixture'),static function(array $s):array{$s['vault']['global']=SecretsBackendTree::parse('{}');return $s;});
    $warningCount=count($readWarnings);$ok($back->GetKeys()==='[]'&&count($readWarnings)===$warningCount&&json_decode($back->GetLegacyAPIStatus(),true)['readAllowed'],'A genuinely empty approved vault was diagnosed as a failure.');
    $current=$store->read();$store->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','restore-read-fixture'),static function(array $s)use($savedGlobal):array{$s['vault']['global']=$savedGlobal;return $s;});
    $GLOBALS['changed'][5101]=true;$ok(json_decode($back->GetLegacyAPIStatus(),true)['code']==='PENDING_SETTINGS','Pending backend settings were hidden.');$GLOBALS['changed'][5101]=false;
    $savedOrigin=$back->properties['AdminOrigin'];$back->properties['AdminOrigin']='https://drift.example.test';$status=$back->GetLegacyAPIStatus();$ok(json_decode($status,true)['code']==='BACKEND_UNAVAILABLE'&&!str_contains($status,'drift.example.test'),'Invalid native foundation was hidden or leaked raw configuration.');$back->properties['AdminOrigin']=$savedOrigin;
    $permission=['kind'=>'nativeLegacyAccess','instance'=>49800,'mode'=>1,'enabled'=>true,'read'=>true,'write'=>true,'portal'=>true,'frozen'=>true,'bulk'=>false];
    $approve($permission);
    $ok($compat->SetRecordFields('Hikvision',['User'=>'blocked'],'global')===false,'Frozen legacy write succeeded.');
    foreach(array_keys($global)as$name)$ok($legacy->GetSecret((string)$name)===SEC_GetSecret(49800,(string)$name),'GetSecret differs for '.$name);
    $ok($legacy->GetSecret('__LOCAL__')===$compat->GetSecret('__LOCAL__'),'Local read differs.');
    $ok($legacy->GetKeys()===$compat->GetKeys(),'GetKeys differs.');
    $ok($legacy->GetExplorerFields('Hikvision')===$compat->GetExplorerFields('Hikvision'),'Explorer fields differ.');
    $ok($legacy->ExportLocalSecrets()===$compat->ExportLocalSecrets(),'Local application export differs.');
    foreach(['','/Hikvision','Hikvision/','Hikvision//Nested','__LOCAL__/OnlyHere','missing']as$path)$ok($legacy->GetExplorerFields($path)===$compat->GetExplorerFields($path),'Explorer path semantics differ.');
    set_error_handler(static fn()=>true);$ok($legacy->GetSecret('missing')===$compat->GetSecret('missing'),'Missing key differs.');restore_error_handler();
    $permission['frozen']=false;$approve($permission);
    $typedBefore=SecretsBackendTree::at($store->read()['state']['vault']['global'],['empty']);
    foreach([['Hikvision',['User'=>'changed','number'=>12,'bool'=>false,'null'=>null],'global'],[' New / Nested ',[' field '=>'value'],'global'],['OnlyHere',['token'=>'LOCAL-UPDATED'],'local'],['bad//path',['a'=>'b'],'local'],['ok',['__reserved'=>'blocked'],'global'],['ok',['bad'=>['array']],'global'],['ok',['a'=>'b'],'unknown']]as$args){
        $expected=$legacy->SetRecordFields(...$args);$actual=$compat->SetRecordFields(...$args);$ok($expected===$actual,'Write result differs: '.json_encode($args));
    }
    $ok($legacy->GetSecret('Hikvision')===$compat->GetSecret('Hikvision'),'Field write lost nested folders or scalar replacement differs.');
    $ok($legacy->GetSecret('New')===$compat->GetSecret('New'),'Nested path creation differs.');
    $ok(SecretsBackendTree::at($store->read()['state']['vault']['global'],['empty'])===$typedBefore,'Legacy field write changed an unrelated typed subtree.');
    $ok($legacy->GetSecret('__LOCAL__')===$compat->GetSecret('__LOCAL__'),'Local write differs.');
    $replacement='{"__LOCAL__":{"Replaced":{"token":"NEW-LOCAL"}}}';$ok($legacy->ImportLocalSecrets($replacement)===$compat->ImportLocalSecrets($replacement),'Local import result differs.');$ok($legacy->ExportLocalSecrets()===$compat->ExportLocalSecrets(),'Local replacement differs.');
    foreach(['no JSON','{"__LOCAL__":"invalid"}','[]']as$json)$ok($legacy->ImportLocalSecrets($json)===$compat->ImportLocalSecrets($json),'Invalid/empty import differs.');
    $before=$compat->ExportLocalSecrets();$ok(!$compat->ImportLocalSecrets('{"__AUTH__":{},"__LOCAL__":{}}')&&$compat->ExportLocalSecrets()===$before,'Legacy auth import changed identity/data.');
    $ok($compat->GetSecret('__AUTH__')==='','Legacy identity area leaked.');
    $ok($compat->values['Vault']===$oldCipher&&file_get_contents($root.'/old/master.key')===$oldKey,'Adapter mutated old ciphertext or keys.');
    // The reference manager was intentionally written during comparisons; the adapter snapshot stays untouched.
    $server=['HTTP_HOST'=>'secrets.example.test','HTTP_COOKIE'=>$request['cookie'],'REMOTE_ADDR'=>'test'];
    $ok($back->CheckLegacyPortalSession(49800,json_encode($server)),'Valid native administrator did not authenticate the protected page.');
    $ok(!$back->CheckLegacyPortalSession(49800,json_encode(array_replace($server,['HTTP_COOKIE'=>'']))),'Anonymous browser authenticated.');
    $compat->properties['PortalEnabled']=false;$ok(!$back->CheckLegacyPortalSession(49800,json_encode($server)),'Disabled protected-page access authenticated.');$compat->properties['PortalEnabled']=true;
    $compat->status=200;$ok(SEC_GetSecret(49800,'Hikvision')==='','Inactive adapter exposed data.');$compat->status=102;
    $ok(!$back->CheckLegacyPortalSession(49800,json_encode(array_replace($server,['HTTP_HOST'=>'other.example.test']))),'Unknown origin authenticated.');
    $ok(!$back->CheckLegacyPortalSession(49800,json_encode(array_replace($server,['HTTP_COOKIE'=>$request['cookie'].'; '.$request['cookie']]))),'Duplicate cookies authenticated.');
    $ok(str_ends_with($back->GetLegacyLoginURL(49800,'/hook/library',json_encode($server)),'#legacy-return=%2Fhook%2Flibrary'),'Return address not preserved.');
    foreach(['//evil.test','https://evil.test','/hook/library?redirect=//evil','/hook/library%0d%0aLocation:x']as$path){secReject(static fn()=>$back->GetLegacyLoginURL(49800,$path,json_encode($server)),'Invalid return path accepted.');$checks++;}
    $savedServer=$_SERVER;$savedGet=$_GET;
    $_SERVER=$server+['REQUEST_METHOD'=>'GET','REQUEST_URI'=>'/hook/secrets_49800'];$_GET=['portal'=>'1','return'=>'/hook/library'];
    ob_start();(new ReflectionMethod(LegacyReplacementAdapter::class,'ProcessHookData'))->invoke($compat);$body=ob_get_clean();$ok(http_response_code()===303&&$body==='','Legacy hook login did not redirect without disclosing data.');
    $_GET=['portal'=>'1','return'=>'//evil.test'];ob_start();(new ReflectionMethod(LegacyReplacementAdapter::class,'ProcessHookData'))->invoke($compat);ob_end_clean();$ok(http_response_code()===403,'Legacy hook accepted an open redirect.');
    $_SERVER['REQUEST_METHOD']='POST';$_GET=[];ob_start();(new ReflectionMethod(LegacyReplacementAdapter::class,'ProcessHookData'))->invoke($compat);ob_end_clean();$ok(http_response_code()===403,'Legacy hook accepted old synchronization.');$_SERVER=$savedServer;$_GET=$savedGet;
    $GLOBALS['changed'][49800]=true;$ok(SEC_GetSecret(49800,'Hikvision')==='','Pending adapter settings retained access.');$GLOBALS['changed'][49800]=false;
    $compat->properties['OperationMode']=0;$ok(SEC_GetSecret(49800,'Hikvision')==='','Changed role retained access.');$compat->properties['OperationMode']=1;
    $compat->properties['NativeBackendInstanceID']=0;$ok(SEC_GetSecret(49800,'Hikvision')==='','Changed backend retained access.');$compat->properties['NativeBackendInstanceID']=5101;
    foreach([0,2]as$mode){$permission['mode']=$mode;$approve($permission);$compat->properties['OperationMode']=$mode;$ok(!$compat->SetRecordFields('test',['a'=>'b'],'global'),'Non-master Global write succeeded.');$ok($compat->SetRecordFields('test',['a'=>'b'],'local'),'Local write denied for old role.');}
    $permission['mode']=1;$compat->properties['OperationMode']=1;$permission['enabled']=false;$approve($permission);
    $ok(SEC_GetSecret(49800,'Hikvision')===''&&!$back->CheckLegacyPortalSession(49800,json_encode($server)),'Revoked legacy access survived.');
    $permission['enabled']=true;$approve($permission);
    $sessionHash=hash('sha256',explode('=',$request['cookie'],2)[1]);$session=$store->get($sessionHash,'session');$expired=$session;$expired['last']=time()-901;$store->replace($sessionHash,'session',$expired,time()+3600);
    $ok(!$back->CheckLegacyPortalSession(49800,json_encode($server)),'Idle expiry ignored.');$store->replace($sessionHash,'session',$session,time()+3600);
    $sessionBefore=$store->get($sessionHash,'session');$back->CheckLegacyPortalSession(49800,json_encode($server));$ok($store->get($sessionHash,'session')===$sessionBefore,'Portal predicate extended/refreshed administrator session.');
    foreach(['RemoveAllPasskeys','SyncSlaves','RevokePortalSessions','ResetPortalLoginPageRateLimit']as$method){secReject(static fn()=>$back->$method(),'Legacy administration bypassed native approval.');$checks++;}
    $permission['bulk']=true;$permission['frozen']=false;$approve($permission);
    foreach([1,2,0]as$mode){
        $compat->properties['OperationMode']=$mode;$legacy->properties['OperationMode']=$mode;$permission['mode']=$mode;$approve($permission);
        foreach(['', 'invalid', '{"Bulk":{"value":"BULK-CANARY"},"__LOCAL__":{"Keep":{"value":"LOCAL-BULK"}}}']as$json){
            ob_start();$legacy->EncryptAndSave($json);$expected=(string)ob_get_clean();ob_start();$compat->EncryptAndSave($json);$actual=(string)ob_get_clean();$ok($expected===$actual,'Bulk write output differs.');
        }
        $ok($legacy->GetSecret('Bulk')===$compat->GetSecret('Bulk'),'Bulk application write differs.');
        $ok($legacy->GetSecret('__LOCAL__')===$compat->GetSecret('__LOCAL__'),'Bulk Local write differs.');
    }
    $compat->properties['OperationMode']=1;$permission['mode']=1;$permission['frozen']=true;$approve($permission);
    $before=$compat->GetSecret('Bulk');ob_start();$compat->EncryptAndSave('{"other":"blocked"}');ob_end_clean();$ok($before===$compat->GetSecret('Bulk'),'Frozen bulk write changed data.');
    $compat->ClearVault();$ok($compat->GetSecret('Bulk')===$before,'ClearVault cleared application data instead of only editor state.');
    $native=new ReflectionClass(SecretsBackend::class);$adapter=new ReflectionClass(LegacyReplacementAdapter::class);$old=new ReflectionClass(SecretsManager::class);
    foreach($old->getMethods(ReflectionMethod::IS_PUBLIC)as$m){if($m->getDeclaringClass()->getName()!==SecretsManager::class)continue;foreach([$native,$adapter]as$target){$ok($target->hasMethod($m->name),'Missing API '.$m->name);if(in_array($m->name,['Create','ApplyChanges','RequestAction','GetConfigurationForm'],true))continue;$n=$target->getMethod($m->name);$ok((string)$m->getReturnType()===(string)$n->getReturnType()&&count($m->getParameters())===count($n->getParameters()),'Signature mismatch '.$m->name);foreach($m->getParameters()as$i=>$p)$ok((string)$p->getType()===(string)$n->getParameters()[$i]->getType()&&$p->getName()===$n->getParameters()[$i]->getName(),'Parameter mismatch '.$m->name);}}
    $directGrant['enabled']=false;$approve($directGrant);
    $back->ApplyChanges();$back->Recover();$ok(!$back->CheckLegacyPortalSession(49800,json_encode($server)),'Restart retained browser session.');
    $ok(json_decode($back->GetLegacyAPIStatus(),true)['code']==='READ_GRANT_DISABLED'&&$back->GetKeys()==='[]','Restart/upgrade restored explicitly revoked read access.');
    $currentStore=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);$cur=$currentStore->read();$currentStore->change($cur['head'],SecretsBackendCodec::uuid(),hash('sha256','fixture-no-override'),static function(array $s):array{unset($s['native']['legacyAccess']['5101']);return $s;});
    $back->ApplyChanges();$back->Recover();$ok(json_decode($back->GetLegacyAPIStatus(),true)['defaultReadAccess']&&$back->GetKeys()!=='[]','Default local reads required a grant after restart.');
    $back->properties['Enabled']=false;$ok(SEC_GetSecret(49800,'Hikvision')==='','Disabled backend exposed a secret.');$ok(json_decode($back->GetLegacyAPIStatus(),true)['code']==='BACKEND_DISABLED','Disabled backend status was obscured.');
    echo 'PASS '.$checks." legacy API signature, real old/new differential, unchanged SEC dispatch, freeze, roles, local isolation, approved binding, revocation, browser session, expiry and restart checks\n";
}finally{
    restore_error_handler();
    $remove=static function($path)use(&$remove){if(is_dir($path)&&!is_link($path)){foreach(scandir($path)as$n)if($n!=='.'&&$n!=='..')$remove($path.'/'.$n);rmdir($path);}elseif(file_exists($path))unlink($path);};if(is_dir($root))$remove($root);
}
