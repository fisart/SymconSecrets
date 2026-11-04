<?php
declare(strict_types=1);
require_once __DIR__.'/BootstrapFixture.php';
function IPS_GetName(int $id): string { return $GLOBALS['instances'][$id]->properties['Name']??('Instance '.$id); }
function IPS_GetConfiguration(int $id): string { return json_encode($GLOBALS['instances'][$id]->properties,JSON_THROW_ON_ERROR); }
function IPS_GetObjectIDByIdent(string $ident,int $id): int { if($ident!=='Vault'||$id!==6000)throw new RuntimeException('Unexpected legacy read.');return 6001; }
function GetValueString(int $id): string { if($id!==6001)throw new RuntimeException('Unexpected variable read.');$GLOBALS['legacyReadCount']++;return $GLOBALS['legacyCipher']; }
function legacyCipher($value,string $key): string {$iv=random_bytes(12);$tag='';$cipher=openssl_encrypt(json_encode($value,JSON_THROW_ON_ERROR|JSON_PRESERVE_ZERO_FRACTION),'aes-128-gcm',hex2bin($key),0,$iv,$tag);return json_encode(['cipher'=>'aes-128-gcm','iv'=>bin2hex($iv),'tag'=>bin2hex($tag),'data'=>$cipher],JSON_THROW_ON_ERROR);}
$GLOBALS['moduleIDs']=[5300=>SecretsBackend::FRONTEND,5301=>'{52165EDD-B2C0-40EC-8A59-42A97319B6E2}',700=>'{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}',6000=>SecretsBackendLegacyImport::MODULE];
$hooks=new IPSModule(700);$hooks->properties['Hooks']='[]';$front=new SecretsFrontend(5300);$front->Create();$back=new SecretsBackend(5301);$back->Create();$old=new IPSModule(6000);$old->status=102;
$root=str_replace('\\','/',sys_get_temp_dir()).'/sec-legacy-import-'.bin2hex(random_bytes(8));mkdir($root,0700);$root=SecretsBackendNativePlatform::directory($root);mkdir($root.'/old',0700);$keyHex=bin2hex(random_bytes(16));file_put_contents($root.'/old/master.key',$keyHex);file_put_contents($root.'/old/system.vault','SYSTEM-SECRET-CANARY');
$old->properties=['Name'=>'Old PasswordSafe','OperationMode'=>1,'KeyFolderPath'=>$root.'/old','SlaveURLs'=>json_encode([['Server'=>'Other vault','Url'=>'https://peer.example/hook/secrets_123?pass=QUERY-CANARY','TlsMode'=>'strict']])];
$source=(object)['ASK'=>(object)['Password'=>'IMPORT-VALUE-CANARY','Enabled'=>false,'Zero'=>0,'Number'=>1.0,'NumericObject'=>(object)['0'=>'string-key'],'EmptyObject'=>new stdClass(),'EmptyList'=>[],'Null'=>null], 'Existing'=>'OLD-VALUE', '__LOCAL__'=>(object)['LocalOnly'=>(object)['Token'=>'LOCAL-VALUE-CANARY']], '__AUTH__'=>(object)['Passkey'=>'DO-NOT-IMPORT-AUTH-CANARY']];
$GLOBALS['legacyCipher']=legacyCipher($source,$keyHex);$GLOBALS['legacyReadCount']=0;$before=$GLOBALS['legacyCipher'];$beforeConfig=IPS_GetConfiguration(6000);$beforeKey=file_get_contents($root.'/old/master.key');
$request=['origin'=>'https://secrets.example.test','cookie'=>'','csrf'=>'','remote'=>'legacy-test'];
$invoke=static function(string $action,array $data=[])use($front,&$request):array{$r=(new ReflectionMethod(SecretsFrontend::class,'gateway'))->invoke($front,['action'=>$action,'data'=>$data]+$request);if($r['status']!==200)throw new RuntimeException($action.': '.json_encode($r));return json_decode(json_encode($r),true);};
try{
 $key=secKey();$login=secBootstrapInitialize($front,$request,$key,['backend'=>5301,'portal'=>0,'documentation'=>0,'theme'=>'system','vaultDirectory'=>$root.'/data','keyDirectory'=>$root.'/keys','addPortalLink'=>false,'debugEnabled'=>false,'privateACLConfirmed'=>true,'persistenceConfirmed'=>true]);$request['cookie']=explode(';',$login['cookie'])[0];$request['csrf']=$login['data']['csrf'];$counter=1;
 $approved=static function(array $op)use($invoke,$key,&$counter,$back,&$request):array{
     $p=$invoke('prepare',['operation'=>$op])['data'];$data=['challengeId'=>$p['challengeId'],'credential'=>secAssertion($key,$p['options']['challenge'],++$counter)];
     // Keep backend exceptions visible in storage fault tests; the earlier imports
     // exercise the full gateway, including its deliberately masked error replies.
     if($GLOBALS['legacyDirectApproval']??false){
         $app=(new ReflectionMethod(SecretsBackend::class,'nativeApplication'))->invoke($back);
         set_error_handler(static function(int $severity,string $message,string $file,int $line):bool{if(!(error_reporting()&$severity))return false;throw new ErrorException($message,0,$severity,$file,$line);});
         try{return $app->handle('approve',$data,$request)['data'];}finally{restore_error_handler();}
     }
     return $invoke('approve',$data)['data'];
 };
 $approved(['kind'=>'save','scope'=>'global','path'=>['Existing'],'revision'=>'0','mode'=>'create','json'=>'"CURRENT-VALUE"']);
 $pathsBefore=((new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back))->read()['state']['policy']['management']['settings'];
 $sources=$invoke('legacySources')['data'];secExpect($sources['sources'][0]['id']===6000,'Old vault discovery failed.');
 $cookie=$request['cookie'];$request['cookie']='';$readCount=$GLOBALS['legacyReadCount'];secReject(static fn()=>$invoke('legacyPreview',['source'=>6000,'policy'=>'keep']),'Unauthenticated import preview was accepted.');secExpect($GLOBALS['legacyReadCount']===$readCount,'Unauthenticated preview read legacy bytes.');$request['cookie']=$cookie;
 // Local-only preparation on a system joining an existing Global vault.
 $store=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);
 $approved(['kind'=>'save','scope'=>'local','path'=>['LocalOnly'],'revision'=>$invoke('session')['data']['revision'],'mode'=>'create','json'=>'{"Token":"CURRENT-LOCAL"}']);
 $modelBeforeLocal=$store->read()['state']['native']['sharedGlobal']??null;
 $current=$store->read();$store->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','local-import-readonly-global'),static function($s){$s=SecretsBackendSharedGlobal::enable($s);$s['native']['globalWritable']=false;return $s;});
 $globalState=static fn($s)=>[$s['vault']['global'],$s['stream'],$s['native']['sharedGlobal'],$s['native']['globalTreeId'],$s['native']['globalWritable'],$s['pairing'],$s['outbox']];
 $globalBefore=$globalState($store->read()['state']);
 foreach(['global','invalid','',null,[]]as$invalid){$reads=$GLOBALS['legacyReadCount'];secReject(static fn()=>$invoke('legacyPreview',['source'=>6000,'policy'=>'keep','scope'=>$invalid]),'Invalid scope accepted.');secExpect($reads===$GLOBALS['legacyReadCount'],'Invalid scope read source bytes.');}
 foreach(['keep','replace']as$policy){
     $preview=$invoke('legacyPreview',['source'=>6000,'policy'=>$policy,'scope'=>'local'])['data'];$review=$preview['review'];
     secExpect($review['scope']==='local'&&$review['summary']['global']['skipped']&&$review['summary']['global']['conflicts']===[],'Local-only preview did not exclude Global.');
     secExpect($review['summary']['local'][$policy==='keep'?'kept':'replaced']===1,'Local-only conflict policy not reviewed.');
     secExpect(!str_contains(json_encode($review),'IMPORT-VALUE-CANARY')&&!str_contains(json_encode($review),'LOCAL-VALUE-CANARY')&&!str_contains(json_encode($review),'Existing'),'Local preview exposed secret values or Global conflict paths.');
     $op=['kind'=>'nativeLegacyImport','candidate'=>$preview['candidate'],'digest'=>$preview['digest']];
     secReject(static fn()=>$approved($op+['scope'=>'all']),'Approval allowed overriding the bound Local scope.');
     secReject(static fn()=>$approved(array_replace($op,['digest'=>str_repeat('0',64)])),'Local candidate digest tampering accepted.');
     $result=$approved($op);$state=$store->read()['state'];
     secExpect($result['scope']==='local'&&$result['verified'],'Import result lost its Local-only scope.');
     secExpect($globalState($state)===$globalBefore,'Local-only import changed Global tree, revision, versions, trust or queued sharing.');
     secExpect(SecretsBackendTree::value($state['vault']['local'])->LocalOnly->Token===($policy==='keep'?'CURRENT-LOCAL':'LOCAL-VALUE-CANARY'),'Local-only keep/replace failed.');
     secExpect($state['native']['legacyImports']['6000']['scope']==='local','Import history lost the selected scope.');
     $backup=SecretsBackendNativeBackup::decrypt($result['backup'],$result['recoveryKey'],4*1024*1024);
     secExpect(SecretsBackendTree::value($backup['state']['vault']['local'])->LocalOnly->Token==='CURRENT-LOCAL','Local import backup did not preserve the pre-import value.');
     secExpect(count($state['identity']['credentials'])===1&&!isset(SecretsBackendTree::value($state['vault']['local'])->__AUTH__),'Local import included old authentication.');
 }
 // An empty Local area is a no-op for application data, never a fallback to Global.
 $GLOBALS['legacyCipher']=legacyCipher((object)['UnrelatedGlobal'=>'GLOBAL-ONLY-CANARY'],$keyHex);
 $beforeNoLocal=$store->read()['state'];$preview=$invoke('legacyPreview',['source'=>6000,'policy'=>'replace','scope'=>'local'])['data'];
 secExpect($preview['review']['summary']['local']['added']===0,'Empty Local import claimed new values.');
 $approved(['kind'=>'nativeLegacyImport','candidate'=>$preview['candidate'],'digest'=>$preview['digest']]);
 $afterNoLocal=$store->read()['state'];secExpect($afterNoLocal['vault']===$beforeNoLocal['vault']&&$globalState($afterNoLocal)===$globalBefore,'Empty Local import erased data or imported Global.');$GLOBALS['legacyCipher']=$before;
 // The source fingerprint still guards the entire encrypted snapshot through approval.
 $preview=$invoke('legacyPreview',['source'=>6000,'policy'=>'keep','scope'=>'local'])['data'];
 $op=['kind'=>'nativeLegacyImport','candidate'=>$preview['candidate'],'digest'=>$preview['digest']];$prepared=$invoke('prepare',['operation'=>$op])['data'];
 $GLOBALS['legacyCipher']=legacyCipher((object)['__LOCAL__'=>(object)['Changed'=>'LATE-LOCAL']],$keyHex);
 secReject(static fn()=>$invoke('approve',['challengeId'=>$prepared['challengeId'],'credential'=>secAssertion($key,$prepared['options']['challenge'],++$counter)]),'Changed Local source committed after review.');$GLOBALS['legacyCipher']=$before;
 secExpect($globalState($store->read()['state'])===$globalBefore,'Rejected Local import changed Global.');
 // Full import remains explicit and cannot bypass non-writable Global restrictions.
 secReject(static fn()=>$invoke('legacyPreview',['source'=>6000,'policy'=>'keep','scope'=>'all']),'Full import bypassed non-writable Global.');
 $current=$store->read();$store->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','restore-global-writable'),static function($s)use($modelBeforeLocal){$s['native']['globalWritable']=true;if($modelBeforeLocal===null)unset($s['native']['sharedGlobal']);else $s['native']['sharedGlobal']=$modelBeforeLocal;return $s;});
 // Omitted scope preserves existing API callers' full-import behavior below.
 $preview=$invoke('legacyPreview',['source'=>6000,'policy'=>'keep'])['data'];$json=json_encode($preview);secExpect(!str_contains($json,'IMPORT-VALUE-CANARY')&&!str_contains($json,'LOCAL-VALUE-CANARY')&&!str_contains($json,'DO-NOT-IMPORT-AUTH-CANARY')&&!str_contains($json,'QUERY-CANARY'),'Import preview disclosed values or legacy credentials.');secExpect($preview['review']['summary']['global']['kept']===1,'Default conflict policy did not preserve the existing value.');secExpect($preview['review']['storage']['vaultDirectory']===$pathsBefore['DataDirectory']&&$preview['review']['storage']['keyDirectory']===$pathsBefore['KeyDirectory'],'Import proposed silently changing active storage.');
 $op=['kind'=>'nativeLegacyImport','candidate'=>$preview['candidate'],'digest'=>$preview['digest']];
 secReject(static fn()=>$approved(array_replace($op,['digest'=>str_repeat('0',64)])),'Changed import digest accepted.');
 $result=$approved($op);secExpect($result['verified']&&$result['legacyImported']&&isset($result['backup'],$result['recoveryKey']),'Import verification or pre-import backup missing.');
 $backup=SecretsBackendNativeBackup::decrypt($result['backup'],$result['recoveryKey'],4*1024*1024);secExpect(count($backup['state']['vault']['global']['entries'])===1,'Backup did not capture the pre-import destination.');
 $store=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);$state=$store->read()['state'];secExpect($state['policy']['management']['settings']===$pathsBefore,'Import changed pinned storage settings.');$values=SecretsBackendTree::value($state['vault']['global']);$locals=SecretsBackendTree::value($state['vault']['local']);
 secExpect($values->Existing==='CURRENT-VALUE'&&$values->ASK->Password==='IMPORT-VALUE-CANARY'&&$values->ASK->Enabled===false&&$values->ASK->Zero===0&&$values->ASK->Number===1.0&&is_object($values->ASK->NumericObject)&&$values->ASK->NumericObject->{'0'}==='string-key'&&$values->ASK->Null===null&&is_object($values->ASK->EmptyObject)&&is_array($values->ASK->EmptyList),'Imported values or types changed.');secExpect($locals->LocalOnly->Token==='LOCAL-VALUE-CANARY'&&!isset($values->__AUTH__),'Local scope or authentication exclusion failed.');secExpect(count($state['identity']['credentials'])===1&&$state['pairing']['peers']===[],'Legacy import changed authority or activated a connection.');
 secExpect($GLOBALS['legacyCipher']===$before&&IPS_GetConfiguration(6000)===$beforeConfig&&file_get_contents($root.'/old/master.key')===$beforeKey&&file_get_contents($root.'/old/system.vault')==='SYSTEM-SECRET-CANARY','Import modified old vault data, configuration or keys.');
 $preview=$invoke('legacyPreview',['source'=>6000,'policy'=>'replace'])['data'];$op=['kind'=>'nativeLegacyImport','candidate'=>$preview['candidate'],'digest'=>$preview['digest']];$prepared=$invoke('prepare',['operation'=>$op])['data'];$GLOBALS['legacyCipher']=legacyCipher((object)['Changed'=>'LATE-CHANGE'],$keyHex);secReject(static fn()=>$invoke('approve',['challengeId'=>$prepared['challengeId'],'credential'=>secAssertion($key,$prepared['options']['challenge'],++$counter)]),'Changed old vault committed after approval review.');secExpect(SecretsBackendTree::value($store->read()['state']['vault']['global'])->Existing==='CURRENT-VALUE','Failed import partially replaced current values.');$GLOBALS['legacyCipher']=$before;
 $preview=$invoke('legacyPreview',['source'=>6000,'policy'=>'replace'])['data'];$result=$approved(['kind'=>'nativeLegacyImport','candidate'=>$preview['candidate'],'digest'=>$preview['digest']]);secExpect(SecretsBackendTree::value($store->read()['state']['vault']['global'])->Existing==='OLD-VALUE','Explicit conflict replacement failed.');
 $current=$store->read();$store->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','legacy-import-hardware-on'),static function($s){$s['policy']['hardware']['write']=true;return $s;});$preview=$invoke('legacyPreview',['source'=>6000,'policy'=>'keep'])['data'];secReject(static fn()=>$approved(['kind'=>'nativeLegacyImport','candidate'=>$preview['candidate'],'digest'=>$preview['digest']]),'Import bypassed the existing hardware policy.');$current=$store->read();$store->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','legacy-import-hardware-off'),static function($s){$s['policy']['hardware']['write']=false;return $s;});
 $old->status=104;$readCount=$GLOBALS['legacyReadCount'];secReject(static fn()=>$invoke('legacyPreview',['source'=>6000,'policy'=>'keep']),'Inactive source was read.');secExpect($GLOBALS['legacyReadCount']===$readCount,'Inactive source bytes were read.');$old->status=102;
 $preview=$invoke('legacyPreview',['source'=>6000,'policy'=>'keep'])['data'];$approved(['kind'=>'save','scope'=>'local','path'=>['Destination-change'],'revision'=>$invoke('session')['data']['revision'],'mode'=>'create','json'=>'"LATE-DESTINATION"']);secReject(static fn()=>$approved(['kind'=>'nativeLegacyImport','candidate'=>$preview['candidate'],'digest'=>$preview['digest']]),'Destination change did not invalidate import review.');
 $keyCopy=$beforeKey;unlink($root.'/old/master.key');secReject(static fn()=>$invoke('legacyPreview',['source'=>6000,'policy'=>'keep']),'Missing legacy key was accepted.');secExpect(!file_exists($root.'/old/master.key'),'A missing legacy key was generated.');file_put_contents($root.'/old/master.key',$keyCopy);
 // Trust roots stored inside the key folder follow a key-only move without changing their fingerprints.
 $store=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);$hardwareVersion='hw-'.SecretsBackendCodec::uuid();$hardwareRoot=$store->installHardwareRoots($hardwareVersion,['root-0.pem'=>'REVIEWED-ROOT-FIXTURE']);$current=$store->read();
 $store->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','relocation-root-fixture'),static function(array $s)use($hardwareRoot):array{$s['policy']['management']['settings']['HardwareRootsDirectory']=$hardwareRoot;$s['policy']['management']['files']['HardwareRoots']=['root-0.pem'=>hash('sha256','REVIEWED-ROOT-FIXTURE')];return $s;});$back->properties['HardwareRootsDirectory']=$hardwareRoot;
 $kernel=SecretsBackendNativePlatform::directory(IPS_GetKernelDir());$legacyParent=$kernel.'/legacy-private';
 SecretsBackendNativePlatform::paths($legacyParent.'/secrets-native-data-6000',$legacyParent.'/secrets-native-keys-6000',$kernel,false,$legacyParent);
 SecretsBackendNativePlatform::paths($kernel.'/legacy-second/secrets-native-data-6002',$legacyParent.'/secrets-native-keys-6000',$kernel,false,['vaultDirectory'=>$kernel.'/legacy-second','keyDirectory'=>$legacyParent]);
 secReject(static fn()=>SecretsBackendNativePlatform::paths($kernel.'/webfront/secrets-native-data-6000',$kernel.'/webfront/secrets-native-keys-6000',$kernel,false,$kernel.'/webfront'),'Public imported storage accepted.');
 $GLOBALS['legacyDirectApproval']=true;
 // Windows mandatory locks deny byte reads of an already-held lock file.
 $lockPath=$pathsBefore['DataDirectory'].'/native.lock';$held=fopen($lockPath,'r+b');flock($held,LOCK_EX);try{secExpect(SecretsBackendNativePlatform::readPrivate($lockPath,0)==='','Empty lock validation attempted a byte read.');}finally{flock($held,LOCK_UN);fclose($held);}
 // Each path can be selected independently; the first move changes only keys.
 $preview=$invoke('legacyPreview',['source'=>6000,'policy'=>'keep','vaultLocation'=>'current','keyLocation'=>'imported','privateACLConfirmed'=>true,'persistenceConfirmed'=>true])['data'];
 secExpect($preview['review']['storage']['vaultDirectory']===$pathsBefore['DataDirectory']&&$preview['review']['storage']['keyDirectory']===$root.'/old/secrets-native-keys-6000','Independent key-folder choice was not reviewed.');
 $result=$approved(['kind'=>'nativeLegacyImport','candidate'=>$preview['candidate'],'digest'=>$preview['digest']]);$invoke('session');
 secExpect($back->properties['DataDirectory']===$pathsBefore['DataDirectory']&&$back->properties['KeyDirectory']===$root.'/old/secrets-native-keys-6000','Key-only move did not update the console configuration.');
 secExpect($back->properties['HardwareRootsDirectory']===$root.'/old/secrets-native-keys-6000/'.$hardwareVersion,'Approved hardware roots did not follow the key folder.');
 secExpect($store->storagePaths()['keyDirectory']===$root.'/old/secrets-native-keys-6000','Existing store handle continued using the old key folder.');
 $preview=$invoke('legacyPreview',['source'=>6000,'policy'=>'keep','vaultLocation'=>'imported','keyLocation'=>'current','privateACLConfirmed'=>true,'persistenceConfirmed'=>true])['data'];
 $selected=$preview['review']['storage'];secExpect($selected['keyDirectory']===$root.'/old/secrets-native-keys-6000','Vault-only choice changed the current key folder.');
 // A destination populated after preview is rejected before committing the import.
 mkdir($selected['vaultDirectory'],0700);file_put_contents($selected['vaultDirectory'].'/unrelated','KEEP');
 secReject(static fn()=>$approved(['kind'=>'nativeLegacyImport','candidate'=>$preview['candidate'],'digest'=>$preview['digest']]),'Populated storage destination accepted.');
 secExpect(file_get_contents($selected['vaultDirectory'].'/unrelated')==='KEEP','Existing destination file was replaced.');unlink($selected['vaultDirectory'].'/unrelated');rmdir($selected['vaultDirectory']);
 $preview=$invoke('legacyPreview',['source'=>6000,'policy'=>'keep','vaultLocation'=>'imported','keyLocation'=>'current','privateACLConfirmed'=>true,'persistenceConfirmed'=>true])['data'];
 $result=$approved(['kind'=>'nativeLegacyImport','candidate'=>$preview['candidate'],'digest'=>$preview['digest']]);$invoke('session');
 secExpect($back->properties['DataDirectory']===$root.'/old/secrets-native-data-6000'&&$back->properties['KeyDirectory']===$root.'/old/secrets-native-keys-6000','Vault-only move failed to preserve selected key location.');
 secExpect($GLOBALS['legacyCipher']===$before&&IPS_GetConfiguration(6000)===$beforeConfig&&file_get_contents($root.'/old/master.key')===$beforeKey&&file_get_contents($root.'/old/system.vault')==='SYSTEM-SECRET-CANARY','Storage choices modified legacy data or keys.');
 // Simulate a process stopping after the authenticated intent and during copying.
 $store=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);$from=$store->storagePaths();
 $extraKey=SecretsBackendCodec::uuid();$store->prepareDataKey($extraKey);$runtime=(new ReflectionProperty(SecretsBackendNativeStore::class,'runtime'))->getValue($store);
 $copyKey=file_get_contents($from['keyDirectory'].'/data-'.$extraKey.'.key');
 $store->installHardwareRoots('hw-'.SecretsBackendCodec::uuid(),['root-0.pem'=>'TEST-ROOT-MATERIAL']);
 $effectId=hash('sha256','relocation-completion');$effectDigest=hash('sha256','relocation-request');$current=$store->read();$store->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','retain-relocation-capture'),static function(array $s)use($effectId,$effectDigest):array{$s['native']['effects'][$effectId]=['state'=>'ABANDONED','requestDigest'=>$effectDigest];return $s;});$store->captureEffect($effectId,$effectDigest,['status'=>'saved-before-move']);
 foreach(['after_marker','relocation_after_intent','relocation_copy','relocation_before_receipt'] as $index=>$point){
     $from=$store->storagePaths();$to=['vaultDirectory'=>$root.'/moved-data-'.$index,'keyDirectory'=>$root.'/moved-keys-'.$index];$current=$store->read();$once=true;
     $fault=new SecretsBackendNativeStore($from['vaultDirectory'],$from['keyDirectory'],$runtime,null,static function(string $p)use($point,&$once):void{if($once&&$p===$point){$once=false;throw new RuntimeException('Injected move interruption');}});
     secReject(static fn()=>$fault->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256',$point),static function(array $s)use($from,$to):array{
         $s['native']['storageMove']=['id'=>SecretsBackendCodec::uuid(),'from'=>$from,'to'=>$to,'kernel'=>IPS_GetKernelDir(),'legacyParent'=>null];
         $s['policy']['management']['settings']['DataDirectory']=$to['vaultDirectory'];$s['policy']['management']['settings']['KeyDirectory']=$to['keyDirectory'];$s['policy']['management']['settings']['HardwareRootsDirectory']=$to['keyDirectory'].substr($s['policy']['management']['settings']['HardwareRootsDirectory'],strlen($from['keyDirectory']));return $s;
     }),'Injected storage interruption did not stop the worker.');
     secExpect($store->storagePaths()===$to,'Storage did not resume the exact interrupted move.');
     secExpect(file_get_contents($to['keyDirectory'].'/data-'.$extraKey.'.key')===$copyKey,'Retired data key was lost in the move.');
     secExpect($store->readCapturedEffect($effectId,$effectDigest)['status']==='saved-before-move','Captured provider result was lost in the move.');
     $invoke('session'); // Also repairs the durable backend binding after a lost reply.
 }
 $current=$store->read();$store->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','after-relocation'),static function(array $s):array{$s['native']['relocationTest']='new-location-only';return $s;});
 $original=new SecretsBackendNativeStore($pathsBefore['DataDirectory'],$pathsBefore['KeyDirectory'],$runtime);
 secExpect($original->read()['state']['native']['relocationTest']==='new-location-only','A stale source handle revived an old state after relocation.');
 // Simulate a restart with the last durable binding/configuration handoff unacknowledged.
 $lastMove=$store->read()['state']['native']['storageMove'];$binding=json_decode($back->attributes['StorageBinding'],true);$binding['paths']=['vault'=>$lastMove['from']['vaultDirectory'],'keys'=>$lastMove['from']['keyDirectory']];$back->attributes['StorageBinding']=SecretsBackendCodec::json($binding);$back->properties['DataDirectory']=$lastMove['from']['vaultDirectory'];$back->properties['KeyDirectory']=$lastMove['from']['keyDirectory'];$back->properties['HardwareRootsDirectory']=$lastMove['from']['keyDirectory'].'/'.$hardwareVersion;
 $back->ApplyChanges();secExpect($back->Recover(),'Restart after import failed: '.($back->values['Status']??''));secExpect(SecretsBackendTree::value(((new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back))->read()['state']['vault']['global'])->ASK->Password==='IMPORT-VALUE-CANARY','Restart lost imported secrets.');
 echo "PASS legacy import: Local-only keep/replace, immutable Global/revisions/versions/sharing, bound scope, empty Local, invalid scope rejection, full-import compatibility, real encrypted source, typed scopes, masked preview, conflicts, source-change rejection, preserved old files, pre-import backup, independent storage choices, interrupted moves, stale-worker routing, current authority and restart\n";
}finally{$remove=static function($p)use(&$remove){if(is_dir($p)&&!is_link($p)){foreach(scandir($p)as$n)if($n!=='.'&&$n!=='..')$remove($p.'/'.$n);rmdir($p);}elseif(file_exists($p)||is_link($p))unlink($p);};if(is_dir($root))$remove($root);}
