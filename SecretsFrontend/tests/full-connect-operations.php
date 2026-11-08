<?php
// Included by the actual WebAuthn lifecycle fixture, after full Magic login.
$magicApproved=static function(array $op)use($invoke,$backupKey,$origin,&$backupCounter):array{$p=$invoke('prepare',['operation'=>$op])['data'];return $invoke('approve',['challengeId'=>$p['challengeId'],'credential'=>secAssertion($backupKey,$p['options']['challenge'],++$backupCounter,$origin)])['data'];};
$magicLogin=static function(array $which,int &$n)use($invoke,&$request,$origin):void{$request=['origin'=>$origin,'cookie'=>'','csrf'=>'','remote'=>'connect-test'];$o=$invoke('authOptions')['data'];$login=$invoke('authVerify',['challengeId'=>$o['challengeId'],'credential'=>secAssertion($which,$o['options']['challenge'],++$n,$origin)]);$request['cookie']=explode(';',$login['cookie'])[0];$request['csrf']=$login['data']['csrf'];};
secExpect($invoke('session')['data']['native']['fullAdministrator']===true,'Magic did not receive the explicitly approved full rights.');
secExpect($invoke('portalAuthOptions')['data']===['authenticated'=>true],'Full Magic session did not use compact authorization locally.');
secExpect($invoke('session')['data']['native']['peerDescriptor']['endpoint']===$origin.'/hook/secrets_peer_5201','Magic presentation endpoint contacts primary.');
$magicApproved(['kind'=>'save','scope'=>'global','path'=>['Magic folder'],'mode'=>'create','json'=>'{}','revision'=>$invoke('session')['data']['revision']]);
$magicApproved(['kind'=>'rename','scope'=>'global','path'=>['Magic folder'],'newName'=>'Renamed folder','revision'=>$invoke('session')['data']['revision']]);
$magicApproved(['kind'=>'save','scope'=>'global','path'=>['Renamed folder','Password'],'mode'=>'create','json'=>'"FULL-MAGIC-VALUE"','revision'=>$invoke('session')['data']['revision']]);
$cap=$magicApproved(['kind'=>'nativeMachineGrant','name'=>'Magic app','scope'=>'global','path'=>['Renamed folder'],'write'=>true]);secExpect(isset($cap['capabilityToken']),'Magic cannot issue application capabilities.');
$magicApproved(['kind'=>'nativeMachineRevoke','id'=>$cap['machineId']]);
// The SEC replacement uses only native browser authentication, without old portal grants.
$nativeServer=['HTTP_HOST'=>parse_url($origin,PHP_URL_HOST),'HTTP_COOKIE'=>$request['cookie'],'REMOTE_ADDR'=>'127.0.0.1'];
$savedServer=$_SERVER;$_SERVER=$nativeServer;
secExpect($back->IsNativePortalAuthenticated(),'Native-only protected page did not accept the current full Magic session.');
$_SERVER=$savedServer;
secExpect(str_starts_with($back->GetNativePortalLoginURL('/hook/library',json_encode($nativeServer)),$origin.'/'),'Native-only Magic login contacted the primary origin.');
secExpect($back->GetNativePortalLoginURL('',json_encode($nativeServer))===$origin.'/hook/secrets_frontend_5200','Old base hook did not open the native Magic administration page.');
// Legacy protected pages must validate the Magic cookie locally; no primary contact is needed.
$magicApproved(['kind'=>'nativeLegacyAccess','instance'=>$back->InstanceID,'mode'=>1,'enabled'=>true,'read'=>true,'write'=>false,'portal'=>true,'frozen'=>true,'bulk'=>false]);
secExpect(str_contains($back->GetSecret('Renamed folder'),'FULL-MAGIC-VALUE'),'Direct native legacy signature did not read application data.');
$legacyServer=['HTTP_HOST'=>parse_url($origin,PHP_URL_HOST),'HTTP_COOKIE'=>$request['cookie'],'REMOTE_ADDR'=>'127.0.0.1'];
secExpect($back->CheckLegacyPortalSession($back->InstanceID,json_encode($legacyServer)),'Approved Magic legacy page access failed.');
secExpect(str_starts_with($back->GetLegacyLoginURL($back->InstanceID,'/hook/library',json_encode($legacyServer)),$origin.'/'),'Legacy Magic login redirected to primary.');
$invoke('legacySources');$invoke('connectDiscovery');$invoke('nativePairingStatus');$invoke('nativeGlobalStatus');
$invitation=$magicApproved(['kind'=>'nativeInvite']);$decoded=SecretsBackendNativePeer::readInvitation($invitation['invitation']);secExpect(str_starts_with($decoded['issuer']['endpoint'],$origin.'/'),'Magic invitation points to primary.');
$export=$magicApproved(['kind'=>'nativeBackup']);secExpect(isset($export['backup'],$export['recoveryKey']),'Magic cannot export an encrypted backup.');
$bytes=$export['backup'];$u=$invoke('nativeUploadBegin',['length'=>strlen($bytes),'digest'=>hash('sha256',$bytes)])['data'];
for($offset=0,$index=0;$offset<strlen($bytes);$offset+=$u['chunkBytes'],$index++)$invoke('nativeUploadChunk',['uploadId'=>$u['uploadId'],'index'=>$index,'chunk'=>SecretsBackendCodec::b64(substr($bytes,$offset,$u['chunkBytes']))]);
$done=$invoke('nativeUploadFinish',['uploadId'=>$u['uploadId']])['data'];$magicApproved(['kind'=>'nativeRestore','uploadId'=>$done['uploadId'],'recoveryKey'=>$export['recoveryKey'],'mode'=>'replace-values']);
secExpect($request['origin']===$origin,'Full access required the primary request origin.');
// Register another device using only this origin; existing hardware policy still governs approval.
$device=secKey();$browserKey=secKey();$public=secJwk($browserKey);$prepare=$invoke('nativeCandidateOptions',['label'=>'Magic new device','hardware'=>false,'probe'=>false])['data'];$reg=secRegistration($device,$prepare['options']['challenge'],$origin);
$sign=implode("\n",['SECF.ADDKEY.SUBMIT.1',$origin,$prepare['prepare'],$prepare['options']['challenge'],SecretsBootstrapVerifier::publicKey($public)['digest'],SecretsBootstrapVerifier::digest($reg)])."\n";
$c=$invoke('nativeCandidateSubmit',['prepare'=>$prepare['prepare'],'key'=>$public,'credential'=>$reg,'signature'=>secRawSign($browserKey,$sign)])['data'];$magicApproved(['kind'=>'nativeEnrollment','candidate'=>$c['candidate'],'digest'=>$c['digest']]);
$deviceCounter=0;$magicLogin($device,$deviceCounter);secExpect($invoke('session')['data']['native']['fullAdministrator'],'A device approved on Magic cannot administer there.');$magicLogin($backupKey,$backupCounter);
// Console recovery uses Magic while keeping the pinned primary origin and stored values.
$oldConfig=$front->properties['AdminOrigin'];$store=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);$before=$store->read()['state']['vault'];
$replacement=secKey();$url=$front->OpenBootstrap($origin,'',true,true);secExpect($url===$origin.'/hook/secrets_frontend_5200'&&$front->properties['AdminOrigin']===$oldConfig,'Magic recovery rewrote primary storage binding.');
$ctx=secBootstrapCandidate($front,$request,$replacement);$views=json_decode($front->GetBootstrapConsoleView(),true);$v=end($views);$front->ApproveBootstrapCandidate($v['candidate'],$v['digest'],$v['proof']);secBootstrapProof($front,$request,$ctx,'candidateStatus');
$choice=['backend'=>5201,'portal'=>0,'documentation'=>0,'theme'=>'system','vaultDirectory'=>$root.'/data','keyDirectory'=>$root.'/keys','addPortalLink'=>false,'debugEnabled'=>false,'privateACLConfirmed'=>true,'persistenceConfirmed'=>true];
$plan=secBootstrapProof($front,$request,$ctx,'planPreview',$choice)['data'];$o=json_decode(json_encode(secBootstrapProof($front,$request,$ctx,'applyOptions',['planDigest'=>$plan['planDigest']])['data']),true);
$r=secBootstrapProof($front,$request,$ctx,'applyVerify',['planDigest'=>$plan['planDigest'],'credential'=>secAssertion($replacement,$o['options']['challenge'],1,$origin)]);secExpect($r['data']['status']==='COMMITTED'&&$store->read()['state']['vault']===$before,'Magic recovery changed the vault or failed.');$recoveredCounter=1;$magicLogin($replacement,$recoveredCounter);secExpect($invoke('session')['data']['native']['fullAdministrator'],'Recovered Magic administrator is not eligible.');$magicLogin($backupKey,$backupCounter);
echo "PASS full Magic: same vault, CRUD, machine grants, import listing, invitation, backup/restore, device enrollment, console recovery and origin-bound authentication without primary API calls\n";
