<?php
$limited=$request;$oldLogin=$invoke('authOptions')['data'];
secExpect(!$invoke('session')['data']['native']['fullAdministrator'],'Limited credentials silently gained administrator authority.');
secReject(fn()=>$invoke('prepare',['operation'=>['kind'=>'nativeConnectUpgrade']]),'Limited Magic session upgraded itself.');
secReject(fn()=>$invoke('nativePairingStatus'),'Limited Magic session obtained full integration access.');
// Even already-tested hardware credentials cannot skip the fresh hardware approval.
$upgradeStore=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);$beforeHardware=$upgradeStore->read()['state'];$cur=$upgradeStore->read();
$upgradeStore->change($cur['head'],SecretsBackendCodec::uuid(),hash('sha256','enforced-upgrade-fixture'),static function($s)use($backupKey){$s['policy']['hardware']['identity']=true;$s['identity']['credentials'][$backupKey['id']]['hardware']=true;$s['identity']['credentials'][$backupKey['id']]['trustVersion']=$s['policy']['management']['settings']['HardwareTrustVersion'];return $s;});
$hardwareReview=json_decode($back->GetConnectUpgradeReview(5200),true);secExpect($hardwareReview['consoleApprovalAllowed']===false,'Console exposed a hardware approval bypass.');
secReject(fn()=>$back->ApproveConnectUpgradeFromConsole(5200,$hardwareReview['digest']),'Console upgraded hardware-enforced authority without a fresh hardware assertion.');
$cur=$upgradeStore->read();$upgradeStore->change($cur['head'],SecretsBackendCodec::uuid(),hash('sha256','restore-upgrade-fixture'),static function($s)use($beforeHardware){$s['policy']=$beforeHardware['policy'];$s['identity']=$beforeHardware['identity'];return $s;});
$review=json_decode($back->GetConnectUpgradeReview(5200),true);secExpect($review['review']['rights']===SecretsBackendBackupOriginPolicy::FULL_RIGHTS&&$review['review']['credentials'][0]['credential']===$backupKey['id'],'Upgrade approval omitted exact credential/rights.');
secReject(fn()=>$back->ApproveConnectUpgradeFromConsole(5200,str_repeat('0',64)),'Changed console approval was accepted.');
if($GLOBALS['upgradeMagicTest']==='console')$back->ApproveConnectUpgradeFromConsole(5200,$review['digest']);else{$request=$primary;$approved(['kind'=>'nativeConnectUpgrade']);}
$request=$limited;secReject(fn()=>$invoke('session'),'Old limited session survived privilege/generation change.');secReject(fn()=>$invoke('authVerify',['challengeId'=>$oldLogin['challengeId'],'credential'=>secAssertion($backupKey,$oldLogin['options']['challenge'],3,$origin)]),'Old login challenge survived privilege upgrade.');
$o=$invoke('authOptions')['data'];$backupCounter=3;$r=$invoke('authVerify',['challengeId'=>$o['challengeId'],'credential'=>secAssertion($backupKey,$o['options']['challenge'],$backupCounter,$origin)]);$request['cookie']=explode(';',$r['cookie'])[0];$request['csrf']=$r['data']['csrf'];$backupSession=$request;
$generation=$invoke('session')['data']['native']['backupOrigin']['generation'];secExpect($generation!==$review['review']['generation']&&$invoke('session')['data']['native']['fullAdministrator'],'Approved upgrade did not establish a fresh full-access generation.');$GLOBALS['fullConnectTest']=true;
echo 'PASS explicit '.$GLOBALS['upgradeMagicTest']." upgrade: exact rights/credential approval, no self-elevation, stale challenge/session invalidation and fresh Magic login\n";
