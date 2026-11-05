<?php
// The ordinary lifecycle created a real, protected backend and exercised passkeys.
$back->CheckAvailability();
$sourceStore=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);
$remoteRoot=$root.'/remote-emergency';$remoteId=SecretsBackendCodec::uuid();$binding=['origin'=>'https://remote.example.test','frontend'=>8100,'backend'=>8101,'privateACLConfirmed'=>true];
SecretsBackendNativeStore::initialize($remoteRoot.'/data',$remoteRoot.'/keys',$binding,[],$remoteId,secGenesis($binding,$remoteId));
$remoteStore=new SecretsBackendNativeStore($remoteRoot.'/data',$remoteRoot.'/keys','remote-emergency');$remoteStore->recover();
$routes=[];$transport=static function($target,$bytes,$policy)use(&$routes):string{return $routes[$target['endpoint']]->receive($bytes);};
$sourcePeer=new SecretsBackendNativePeer($sourceStore,$request['origin'].'/hook/secrets_peer_5101',$transport);
$remotePeer=new SecretsBackendNativePeer($remoteStore,'https://remote.example.test/hook/secrets_peer_8101',$transport);
$routes[$sourcePeer->descriptor()['endpoint']]=$sourcePeer;$routes[$remotePeer->descriptor()['endpoint']]=$remotePeer;
$sourceOps=new SecretsBackendNativeOperations($sourceStore,$sourcePeer);$remoteOps=new SecretsBackendNativeOperations($remoteStore,$remotePeer);
$operate=static function($store,$ops,array $raw):array{$cur=$store->read();$op=$ops->normalize($raw,$cur['state'],false);$store->change($cur['head'],SecretsBackendCodec::uuid(),SecretsBackendNativePeer::digest($op),static fn($s)=>$ops->apply($op,$s));return $op;};
$pump=static function()use($sourcePeer,$remotePeer,$sourceStore,$remoteStore):void{for($i=0;$i<30;++$i){$sourcePeer->dispatch(1,null,true);$remotePeer->dispatch(1,null,true);if(!$sourceStore->read()['state']['outbox']['jobs']&&!$remoteStore->read()['state']['outbox']['jobs'])return;}throw new RuntimeException('Runtime emergency fixture did not settle.');};
$inv=$operate($sourceStore,$sourceOps,['kind'=>'nativeInvite']);$operate($remoteStore,$remoteOps,['kind'=>'nativePair','invitation'=>SecretsBackendNativePeer::invitationText($inv['invitation']),'name'=>'Production source']);$remotePeer->dispatch(1);$operate($sourceStore,$sourceOps,['kind'=>'nativeAcceptPair','peerId'=>$remoteId]);$pump();
$grant=$operate($remoteStore,$remoteOps,['kind'=>'nativeEmergencyGrant','peerId'=>$sourceStore->identity()['deploymentId']]);$pump();
secExpect(empty($sourceStore->read()['state']['native']['emergencyClients']),'Received offer activated emergency access before local approval.');
$offers=SecretsBackendEmergency::publicMetadata($sourceStore->read()['state'])['offers'];secExpect(count($offers)===1,'Encrypted offer did not arrive.');
$loginOptions=json_decode(json_encode($invoke('authOptions')['data']),true);
$login=$invoke('authVerify',['challengeId'=>$loginOptions['challengeId'],'credential'=>secAssertion($key,$loginOptions['options']['challenge'],++$counter)]);
$request['cookie']=explode(';',$login['cookie'])[0];$request['csrf']=$login['data']['csrf'];
$configured=$approved(['kind'=>'nativeEmergencyAccept','peerId'=>$remoteId,'digest'=>$offers[0]['digest']]);
secExpect($configured['emergencyConfigured']===true,'Passkey-approved offer did not provision independent credentials.');
$capsule=(new ReflectionMethod(SecretsBackend::class,'emergencyCapsule'))->invoke($back);
secExpect($capsule->exists(),'Approved emergency capsule was not persisted.');
$sourceVault=$sourceStore->identity()['deploymentId'];$remoteCalls=0;
$GLOBALS['emergencyTransport']=static function($url,$bytes,$policy,$timeout)use($remotePeer,$remoteStore,&$remoteCalls):string{
    ++$remoteCalls;if($url!==$remotePeer->descriptor()['endpoint'])throw new RuntimeException('Unapproved runtime target.');return SecretsBackendEmergency::serve($remoteStore,$bytes);
};
$local=json_decode($back->CallBoundLegacyAPI($sourceVault,'GetSecret','["ASK"]'),true);secExpect($local['error']===null&&$remoteCalls===0,'Healthy local API unnecessarily called a peer.');
// Source is unavailable; the same pinned compatibility call now obtains the Global record remotely.
rename($root.'/keys/master.key',$root.'/keys/master.saved');
try{
    $result=json_decode($back->CallBoundLegacyAPI($sourceVault,'GetSecret','["ASK"]'),true);
    secExpect($result['error']===null&&$result['source']==='emergency-peer'&&$result['value']===$local['value'],'Pinned application read did not fall back after local key loss.');
    secExpect($back->values['FallbackActive']===true&&$back->values['SecretsUnavailable']===false&&$back->values['SynchronizationProblem']===true,'Fallback alarm indicators were incorrect.');
    $before=$remoteCalls;$private=json_decode($back->CallBoundLegacyAPI($sourceVault,'GetSecret','["__LOCAL__"]'),true);secExpect($private['error']!==null&&$remoteCalls===$before,'Local read reached emergency peer.');
    $wrong=json_decode($back->CallBoundLegacyAPI(SecretsBackendCodec::uuid(),'GetSecret','["ASK"]'),true);secExpect($wrong['error']!==null&&$remoteCalls===$before,'Wrong pinned vault reached emergency peer.');
    $back->properties['Enabled']=false;$disabled=json_decode($back->CallBoundLegacyAPI($sourceVault,'GetSecret','["ASK"]'),true);secExpect($disabled['error']!==null&&$remoteCalls===$before,'Disabled backend used emergency access.');$back->properties['Enabled']=true;
    $front->properties['TrustedHTTPSProxyIPs']='["192.0.2.5"]';$changed=json_decode($back->CallBoundLegacyAPI($sourceVault,'GetSecret','["ASK"]'),true);secExpect($changed['error']!==null&&$remoteCalls===$before,'Changed source foundation used emergency access.');$front->properties['TrustedHTTPSProxyIPs']='[]';
    $back->CheckAvailability();secExpect($back->values['VaultError']===true&&$back->values['FallbackActive']===true&&!$back->values['SecretsUnavailable'],'Watchdog did not preserve remote availability while local recovery failed.');
}finally{rename($root.'/keys/master.saved',$root.'/keys/master.key');}
secExpect($back->Recover(),'Local vault did not recover after the test key was restored.');
$back->CheckAvailability();$back->CheckAvailability();
secExpect(!$back->values['FallbackActive']&&!$back->values['SecretsUnavailable']&&!json_decode($back->GetEmergencyStatus(),true)['freshnessUncertain']&&$back->values['ActiveSource']==='Local vault','Stable healthy recovery did not return to local source.');
$before=$remoteCalls;$back->CallBoundLegacyAPI($sourceVault,'GetSecret','["ASK"]');secExpect($remoteCalls===$before,'Recovered local reads still contacted remote vault.');
// A local permission change blocks the external credential copy before the durable change.
$access=['kind'=>'nativeLegacyAccess','instance'=>5101,'mode'=>2,'enabled'=>false,'read'=>false,'write'=>false,'portal'=>false,'frozen'=>true,'bulk'=>false];
$operate($sourceStore,$sourceOps,$access);
$bindingHash=(new ReflectionMethod(SecretsBackend::class,'emergencyBinding'))->invoke($back);
secReject(fn()=>$capsule->load($bindingHash),'Local access revocation left emergency authority live.');
$denied=json_decode($back->CallBoundLegacyAPI($sourceVault,'GetSecret','["ASK"]'),true);secExpect($denied['error']!==null&&$remoteCalls===$before,'Local permission denial fell through to emergency access.');
// Restore fixture permissions through the normal approved-operation normalization.
$access['enabled']=true;$access['read']=true;$operate($sourceStore,$sourceOps,$access);$back->CheckAvailability();
$back->StopEmergencyAccess();$back->CheckAvailability();secReject(fn()=>$capsule->load($bindingHash),'Watchdog re-enabled manually stopped fallback.');
secExpect(!$back->values['SecretsUnavailable'],'Stopping emergency fallback disabled healthy local access.');
// Manual fallback stop must not allow data older than a previously observed checkpoint.
$floor=$capsule->checkpoint($sourceVault);$future=['clock'=>$floor['clock'],'digest'=>$floor['digest'],'conflicts'=>0];$future['clock'][$remoteId]=SecretsBackendCodec::increment($future['clock'][$remoteId]??'0');
(new ReflectionMethod(SecretsBackend::class,'syncEmergencyAccess'))->invoke($back,true);$a=$capsule->load($bindingHash);$capsule->observe($bindingHash,$a['authorization'],$future);$back->StopEmergencyAccess();
$before=$remoteCalls;$behind=json_decode($back->CallBoundLegacyAPI($sourceVault,'GetSecret','["ASK"]'),true);secExpect($behind['error']!==null&&$remoteCalls===$before,'Manual stop discarded the known newer checkpoint.');
echo "PASS real backend emergency runtime: passkey offer acceptance, pinned SEC fallback, Local exclusion, disabled/configuration fencing, independent watchdog, local failback and immediate local permission revocation\n";
