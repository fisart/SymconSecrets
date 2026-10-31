<?php
declare(strict_types=1);
require_once __DIR__ . '/modules.php';
function SECB_GetInitialSetupInfo(int $id): string { return $GLOBALS['instances'][$id]->GetInitialSetupInfo(); }
function SECB_ConfigureInitialSetup(int $id, int $frontend, string $digest, string $settings): bool { return $GLOBALS['instances'][$id]->ConfigureInitialSetup($frontend, $digest, $settings); }
function SECB_ExportConfiguration(int $id): string { return $GLOBALS['instances'][$id]->ExportConfiguration(); }
$GLOBALS['moduleIDs'][124] = '{8D6AE8F7-EA3A-4513-AA14-C3F9613B0E83}';
$guided = new SecretsFrontend(124); $guided->Create();
foreach ([789,790] as $id) { $GLOBALS['moduleIDs'][$id] = '{52165EDD-B2C0-40EC-8A59-42A97319B6E2}'; $new = new SecretsBackendTestModule($id); $new->Create(); }
$apiMethod = new ReflectionMethod(SecretsFrontend::class, 'gateway');
$invoke = static function (string $action, array $data, ?string $origin = null) use ($guided, $apiMethod): array {
    $settings = json_decode($guided->ExportConfiguration(), true)['configuration'];
    $server = ['REQUEST_METHOD'=>'POST','REQUEST_URI'=>'/hook/secrets_frontend_124','QUERY_STRING'=>'','HTTPS'=>'on','HTTP_HOST'=>'wizard.example.test','HTTP_ORIGIN'=>$origin ?? 'https://wizard.example.test','CONTENT_TYPE'=>'application/json'];
    return SecretsFrontendHttp::response($settings,124,$server,'/hook/secrets_frontend_124','','',json_encode(['action'=>$action,'data'=>$data]),static fn($r)=>$apiMethod->invoke($guided,$r));
};
$code = $guided->BeginGuidedSetup('https://wizard.example.test/console/?view=123', '');
secExpect($guided->values['FrontendURL'] === 'https://wizard.example.test/hook/secrets_frontend_124', 'Wizard URL not registered.');
secExpect(!str_contains(json_encode($guided->properties),$code) && !str_contains(json_encode($guided->buffers),$code) && !str_contains($guided->ExportConfiguration(),$code),'Bootstrap credential persisted.');
secExpect($invoke('guidedDiscover',['code'=>$code],'https://evil.test')['status']===403,'Foreign origin reached commissioning.');
secExpect($invoke('guidedDiscover',['code'=>'wrong'])['status']===403,'Missing console authority accepted.');
$found = $invoke('guidedDiscover',['code'=>$code]);secExpect($found['status']===200,'Discovery failed.');$discovery=json_decode($found['body'],true);
secExpect(array_column($discovery['backends'],'id')===[789,790],'Sealed/existing backend included or candidates lost.');
$choice=['backend'=>789,'portal'=>800,'documentation'=>0,'theme'=>'dark','vaultDirectory'=>$directory.'/new-data','keyDirectory'=>$directory.'/new-keys','proxyIPs'=>[],'addPortalLink'=>true,'debugEnabled'=>false];
$bad=$choice;$bad['backend']=456;secExpect($invoke('guidedPreview',['code'=>$code,'configuration'=>$bad])['status']===403,'Existing vault selected.');
$bad=$choice;$bad['keyDirectory']=$choice['vaultDirectory'].'/nested';secExpect($invoke('guidedPreview',['code'=>$code,'configuration'=>$bad])['status']===403,'Nested directories accepted.');
$preview=json_decode($invoke('guidedPreview',['code'=>$code,'configuration'=>$choice])['body'],true);secExpect(isset($preview['planId']),'Review failed.');
$target=$GLOBALS['instances'][789];$target->properties['DebugEnabled']=true;
secExpect($invoke('guidedApply',['code'=>$code,'planId'=>$preview['planId']])['status']===403,'Changed backend applied after review.');
$code=$guided->BeginGuidedSetup('https://wizard.example.test','');
$preview=json_decode($invoke('guidedPreview',['code'=>$code,'configuration'=>$choice])['body'],true);
$before=count(json_decode($portal->properties['AdditionalPages'],true));
$applied=$invoke('guidedApply',['code'=>$code,'planId'=>$preview['planId']]);secExpect($applied['status']===200,'Reviewed application failed: '.$applied['body']);$result=json_decode($applied['body'],true);
secExpect($result['configured']&&!$result['vaultCreated']&&!$result['quorumConnected'],'Settings reported as a working vault.');
secExpect($guided->properties['BackendInstanceID']===789&&$target->properties['FrontendInstanceID']===124&&$target->properties['AdminOrigin']===$guided->properties['AdminOrigin'],'Reciprocal pairing not automated.');
secExpect(!$target->properties['Enabled']&&!file_exists($choice['vaultDirectory'])&&!file_exists($choice['keyDirectory']),'Setup enabled or created a vault.');
secExpect(count(json_decode($portal->properties['AdditionalPages'],true))===$before+1,'Portal link not registered preserving earlier rows.');
secExpect(!str_contains($applied['body'],$code)&&!str_contains(json_encode($result['configurationExport']),$code),'Code leaked to result/export.');
secExpect($invoke('guidedApply',['code'=>$code,'planId'=>$preview['planId']])['status']===403,'Consumed authorization replayed.');
secExpect(json_decode($invoke('status',[])['body'],true)['configured']===true,'Saved configuration progress was lost.');
secExpect($invoke('authOptions',[])['status']===503,'Guided V2 mode fell back to the old anchor application.');
secRejectReason(static fn()=>$target->BeginStorageSetup(),'Quorum runtime connection pending');
$code=$guided->BeginGuidedSetup('https://wizard.example.test','');
secExpect($invoke('guidedCancel',['code'=>$code])['status']===200&&$invoke('guidedDiscover',['code'=>$code])['status']===403,'Server cancellation failed.');
$code=$guided->BeginGuidedSetup('https://wizard.example.test','');for($i=0;$i<5;$i++)$invoke('guidedDiscover',['code'=>'invalid']);secExpect($invoke('guidedDiscover',['code'=>$code])['status']===403,'Failed-attempt limit ignored.');
$code=$guided->BeginGuidedSetup('https://wizard.example.test','');$grant=json_decode($guided->buffers['GuidedSetup'],true);$grant['expires']=time()-1;$guided->buffers['GuidedSetup']=json_encode($grant);secExpect($invoke('guidedDiscover',['code'=>$code])['status']===403,'Expired authority accepted.');
secExpect(SecretsFrontendCommissioning::address('https://Example.Test:443/path?q=1')==='https://example.test','Address normalization failed.');
secRejectReason(static fn()=>SecretsFrontendCommissioning::address('http://example.test'),'trusted HTTPS');
secRejectReason(static fn()=>SecretsFrontendCommissioning::paths('/var/lib/symcon/modules/data','/tmp/keys','/var/lib/symcon/'),'outside the Symcon');
$code=$guided->BeginGuidedSetup('https://wizard.example.test','');$guided->ApplyChanges();secExpect($invoke('guidedDiscover',['code'=>$code])['status']===403,'Reload retained setup authority.');
echo "PASS HTML commissioning discovery, console-only authority, binding, exact review, expiry/replay/cancel/reload, Portal preservation, configuration-only apply and V2 fallback refusal\n";

// A failed multi-instance apply is never replayed or reported as fully configured.
class FailingGuidedBackend extends SecretsBackendTestModule {
    public function ApplyChanges(): void { parent::ApplyChanges(); throw new RuntimeException('Synthetic apply interruption'); }
}
$GLOBALS['moduleIDs'][126] = '{8D6AE8F7-EA3A-4513-AA14-C3F9613B0E83}';$interrupted=new SecretsFrontend(126);$interrupted->Create();
$GLOBALS['moduleIDs'][791] = '{52165EDD-B2C0-40EC-8A59-42A97319B6E2}';$failedBackend=new FailingGuidedBackend(791);$failedBackend->Create();$failedBackend->properties['Enabled']=true;
$code2=$interrupted->BeginGuidedSetup('https://wizard.example.test','');
$direct=static fn($action,$data)=>$apiMethod->invoke($interrupted,['action'=>$action,'data'=>$data,'origin'=>'https://wizard.example.test','remote'=>'test','cookie'=>'','csrf'=>'']);
$choice2=$choice;$choice2['backend']=791;$choice2['addPortalLink']=false;$choice2['vaultDirectory']=$directory.'/interrupted-data';$choice2['keyDirectory']=$directory.'/interrupted-keys';
$plan=$direct('guidedPreview',['code'=>$code2,'configuration'=>$choice2])['data'];secExpect(isset($plan['planId']),'Interrupted plan failed.');
$result=$direct('guidedApply',['code'=>$code2,'planId'=>$plan['planId']]);
secExpect($result['status']===403&&!$failedBackend->properties['Enabled']&&$interrupted->attributes['GuidedV2Only']&&$failedBackend->attributes['GuidedV2Only'],'Partial apply escaped disabled quorum mode.');
secExpect($direct('guidedApply',['code'=>$code2,'planId'=>$plan['planId']])['status']===403,'Uncertain apply was replayed.');
secExpect(!file_exists($choice2['vaultDirectory'])&&!file_exists($choice2['keyDirectory']),'Partial apply created storage.');
$form=json_decode($interrupted->GetConfigurationForm(),true);secExpect($form['elements'][1]['value']==='https://wizard.example.test','Saved origin was not offered as the default.');
$target->attributes['ProvisioningSealed']=true;$form=json_decode($target->GetConfigurationForm(),true);$fields=[];$walk=static function($items)use(&$walk,&$fields){foreach($items as $item){if(isset($item['name']))$fields[$item['name']]=$item;if(isset($item['items']))$walk($item['items']);}};$walk($form['elements']);secExpect(($fields['DataDirectory']['enabled']??true)===false,'Collapsed form lost pinned-field protection.');
echo "PASS partial-apply one-use recovery, disabled V2-only state, saved defaults and nested pinned-field protection\n";

$GLOBALS['locks']['SECF.GuidedSetup.124']=true;
secRejectReason(static fn()=>$guided->CancelGuidedSetup(),'cancellation has not completed');
secRejectReason(static fn()=>$guided->BeginGuidedSetup('https://wizard.example.test',''),'wait before issuing');
unset($GLOBALS['locks']['SECF.GuidedSetup.124']);
$GLOBALS['moduleIDs'][792]='{52165EDD-B2C0-40EC-8A59-42A97319B6E2}';$lockedBackend=new SecretsBackendTestModule(792);$lockedBackend->Create();$lockedInfo=json_decode($lockedBackend->GetInitialSetupInfo(),true);
$GLOBALS['locks']['SECB.Setup.792']=true;
secRejectReason(static fn()=>$lockedBackend->ConfigureInitialSetup(124,$lockedInfo['digest'],json_encode(['origin'=>'https://wizard.example.test','vaultDirectory'=>$directory.'/locked-data','keyDirectory'=>$directory.'/locked-keys','debugEnabled'=>false])),'storage operation is busy');
secExpect(!$lockedBackend->attributes['GuidedV2Only']&&$lockedBackend->properties['FrontendInstanceID']===0,'Busy legacy creation was reconfigured.');
unset($GLOBALS['locks']['SECB.Setup.792']);
echo "PASS commissioning serialization against issuance/cancellation and in-flight legacy storage creation\n";
