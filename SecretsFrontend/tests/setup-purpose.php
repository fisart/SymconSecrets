<?php
declare(strict_types=1);
require_once __DIR__.'/BootstrapFixture.php';
$GLOBALS['moduleIDs']=[8850=>SecretsBackend::FRONTEND,8851=>'{52165EDD-B2C0-40EC-8A59-42A97319B6E2}',700=>'{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}'];
$hooks=new IPSModule(700);$hooks->properties['Hooks']='[]';$front=new SecretsFrontend(8850);$front->Create();$back=new SecretsBackend(8851);$back->Create();
$origin='https://secrets.example.test';$request=['origin'=>$origin,'cookie'=>'','csrf'=>'','remote'=>'setup-purpose'];$key=secKey();
secBootstrapInitialize($front,$request,$key,['backend'=>8851,'portal'=>0,'documentation'=>0,'theme'=>'system','vaultDirectory'=>IPS_GetKernelDir().'secrets-native-data/purpose','keyDirectory'=>IPS_GetKernelDir().'secrets-native-keys/purpose','addPortalLink'=>false,'debugEnabled'=>false,'privateACLConfirmed'=>true,'persistenceConfirmed'=>true]);
$store=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);$identity=$store->identity();$vault=$store->read()['state']['vault'];
$render=static function()use($front):array{$saved=$_SERVER;$_SERVER=['REQUEST_METHOD'=>'GET','REQUEST_URI'=>'/hook/secrets_frontend_8850','HTTP_HOST'=>'secrets.example.test','REMOTE_ADDR'=>'127.0.0.1'];ob_start();try{$front->ProcessHookData();$html=ob_get_contents();}finally{ob_end_clean();$_SERVER=$saved;}secExpect(http_response_code()===200&&preg_match('/const boot=(.*?);/',$html,$m)===1,'Setup presentation did not render.');return json_decode($m[1],true,32,JSON_THROW_ON_ERROR);};
$boot=$render();secExpect($boot['vaultInitialized']===true&&$boot['setupMode']==='initial','Initialized vault was presented as unfinished setup.');
$front->OpenBootstrap($origin,'',true,true);$boot=$render();secExpect($boot['vaultInitialized']===true&&$boot['setupMode']==='recovery','Console recovery did not identify its purpose before passkey preparation.');
$front->CancelBootstrap();$boot=$render();secExpect($boot['setupMode']==='initial','Cancelled console recovery stayed active.');secExpect($store->identity()===$identity&&$store->read()['state']['vault']===$vault,'Presentation or cancelled recovery altered vault contents or identity.');
echo "PASS setup presentation: initialized vault, console-authorized recovery mode, cancellation, preserved identity and values\n";
