<?php
declare(strict_types=1);
require_once __DIR__.'/BootstrapFixture.php';
$GLOBALS['moduleIDs']=[8500=>SecretsBackend::FRONTEND,8501=>'{52165EDD-B2C0-40EC-8A59-42A97319B6E2}',700=>'{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}'];
$hooks=new IPSModule(700);$hooks->properties['Hooks']='[]';$front=new SecretsFrontend(8500);$front->Create();$back=new SecretsBackend(8501);$back->Create();
$root=IPS_GetKernelDir().'secrets-native-data/magic-first';$origin='https://'.str_repeat('d',32).'.ipmagic.de';$request=['origin'=>$origin,'cookie'=>'','csrf'=>'','remote'=>'magic-initial'];$key=secKey();
$login=secBootstrapInitialize($front,$request,$key,['backend'=>8501,'portal'=>0,'documentation'=>0,'theme'=>'system','vaultDirectory'=>$root,'keyDirectory'=>IPS_GetKernelDir().'secrets-native-keys/magic-first','addPortalLink'=>false,'debugEnabled'=>false,'privateACLConfirmed'=>true,'persistenceConfirmed'=>true]);
secExpect($login['data']['authenticated']===true&&$front->properties['AdminOrigin']===$origin,'Initial Magic setup required another hostname.');
$request['cookie']=explode(';',$login['cookie'])[0];$request['csrf']=$login['data']['csrf'];$response=(new ReflectionMethod(SecretsFrontend::class,'gateway'))->invoke($front,['action'=>'session','data'=>[]]+$request);secExpect($response['status']===200&&$response['data']['native']['fullAdministrator'],'Initial Magic administrator was not eligible.');
echo "PASS initial installation through Magic: console-approved genesis, actual passkey registration/login and full administration without another hostname\n";
