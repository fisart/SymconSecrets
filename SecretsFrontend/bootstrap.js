// Private keys exist only in this closure. No storage, URL, clipboard or cache.
let bootstrapContext=null, bootstrapQueue=Promise.resolve(), bootstrapPoll=null;
function bootstrapPause(){clearTimeout(bootstrapPoll);bootstrapPoll=null;}
function bootstrapClear(){bootstrapPause();bootstrapContext=null;$('bsComparison').textContent='';$('bsCancel').hidden=true;$('bsSecrets').hidden=true;$('bsLogin').hidden=true;}
const bootstrapHex=bytes=>Array.from(new Uint8Array(bytes),x=>x.toString(16).padStart(2,'0')).join('');
async function bootstrapHash(value){return bootstrapHex(await crypto.subtle.digest('SHA-256',typeof value==='string'?new TextEncoder().encode(value):value));}
function bootstrapCanonical(v){if(Array.isArray(v))return v.map(bootstrapCanonical);if(v&&typeof v==='object')return Object.fromEntries(Object.keys(v).sort().map(k=>[k,bootstrapCanonical(v[k])]));return v;}
async function bootstrapKey(){const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);const jwk=await crypto.subtle.exportKey('jwk',pair.publicKey);const key={kty:jwk.kty,crv:jwk.crv,x:jwk.x,y:jwk.y};const prefix=new TextEncoder().encode('SECF.BOOTSTRAP.KEY.1\0');const all=new Uint8Array(prefix.length+64);all.set(prefix);all.set(binary(key.x),prefix.length);all.set(binary(key.y),prefix.length+32);return{pair,key,keyDigest:await bootstrapHash(all)};}
async function bootstrapSign(ctx,text){return encoded(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},ctx.pair.privateKey,new TextEncoder().encode(text)));}
async function bootstrapFetch(action,data,ctx,ticket=generation){
 ensure(ticket);if(!secureOrigin())throw Error('Use the trusted HTTPS address.');
 const response=await fetch(boot.path,{method:'POST',credentials:'same-origin',cache:'no-store',redirect:'error',headers:{'Content-Type':'application/json','X-CSRF-Token':ctx?.csrf||''},body:JSON.stringify({action,data})});
 const result=await response.json();ensure(ticket);if(!response.ok)throw Error(result.error||'Setup request refused.');return result;
}
function bootstrapShow(id){for(const name of ['bsStart','bsWaiting','bsConfiguration','bsPlan','bsDone'])$(name).hidden=name!==id;}
async function bootstrapResume(ctx,ticket){
 const challenge=await bootstrapFetch('bootstrapResumeOptions',{candidate:ctx.candidate},ctx,ticket);
 const result=await bootstrapWire(ctx,'resumeVerify',challenge,'resume','-',challenge.challenge,ticket);
 ctx.epoch=result.epoch;ctx.nonce=result.nonce;
}
async function bootstrapWire(ctx,action,body,purpose='request',operation='-',nonce=ctx.nonce,ticket=generation){
 const raw=JSON.stringify(body), m={version:'SECF.Bootstrap.PoP.1',purpose,origin:boot.origin,path:boot.path,frontend:ctx.frontend,intent:ctx.intent,candidate:ctx.candidate,candidateDigest:ctx.candidateDigest,keyDigest:ctx.keyDigest,epoch:ctx.epoch,request:crypto.randomUUID(),nonce,operation,action,body:encoded(new TextEncoder().encode(raw))};
 const bytes=['SECF.BOOTSTRAP.POP.1',...['purpose','origin','path','frontend','intent','candidate','candidateDigest','keyDigest','epoch','request','nonce','operation','action'].map(k=>m[k]),await bootstrapHash(raw)].join('\n')+'\n';m.signature=await bootstrapSign(ctx,bytes);
 return bootstrapFetch('bootstrapProof',m,ctx,ticket);
}
function bootstrapRequest(action,body={},ticket=generation){
 const ctx=bootstrapContext;if(!ctx) return Promise.reject(Error('Prepare a passkey first.'));
 bootstrapPause();const job=async()=>{ensure(ticket);if(ctx!==bootstrapContext)throw Error('Setup context changed.');if(ctx.uncertain){await bootstrapResume(ctx,ticket);ctx.uncertain=false;}
   const operation=['applyOptions','applyVerify','operationStatus','cancel'].includes(action)?ctx.operation:'-';
   try{const result=await bootstrapWire(ctx,action,body,'request',operation,ctx.nonce,ticket);if(result.nonce){ctx.nonce=result.nonce;ctx.epoch=result.epoch;}return result;}catch(error){ctx.uncertain=true;throw error;}
 };const promise=bootstrapQueue.then(job);bootstrapQueue=promise.catch(()=>{});return promise;
}
let installationReady=boot.vaultInitialized===true,setupRecovery=boot.setupMode==='recovery',setupFinished=false;
function renderSetupPurpose(){
 const ready=installationReady||!!snapshot,nav=$('setupNav');nav.hidden=ready&&(!setupRecovery||setupFinished);nav.textContent=setupRecovery?'Administrator recovery':'Setup assistant';$('firstTimeSetup').hidden=ready||setupRecovery;
 $('setupPurposeLabel').textContent=setupRecovery?'Administrator access recovery':'First-time setup';$('setupTitle').textContent=setupRecovery?'Administrator recovery':'Setup assistant';
 $('setupPurpose').textContent=setupRecovery?'Restore administrator access to this existing vault with a replacement passkey approved in the Symcon console. Your secrets stay in the same vault. This does not restore values from a backup.':'Create this platform’s encrypted secrets vault, choose where its vault and keys are stored, and approve its first administrator passkey. Use this assistant once for a new installation; follow the numbered steps.';
 $('bsStartTitle').textContent=setupRecovery?'Step 2 of 5: Prepare replacement passkey':'Step 2 of 5: Prepare first passkey';$('bsPrepare').textContent=setupRecovery?'Prepare replacement passkey':'Prepare first passkey';
 $('bsStartHelp').textContent=setupRecovery?'In the Symcon console, open Secrets Frontend and select Recover administrator access. Then prepare a replacement passkey here and compare its request with the console. Hardware requirements remain enforced.':'In the Symcon console, open Secrets Frontend and select Step 1: Open setup. Then prepare the passkey below and keep this page open.';
 $('bsPlanTitle').textContent=setupRecovery?'Step 5 of 5: Restore administrator access':'Step 5 of 5: Create vault';$('bsApply').textContent=setupRecovery?'Recover administrator access':'Set up and sign in';
 $('bsPlanHelp').textContent=setupRecovery?'Check the existing vault and replacement passkey in the summary, then confirm Recover administrator access with that passkey.':'Check the summary, then click Set up and sign in. Your device will ask you to confirm with your passkey.';
 $('bsPlanEffect').textContent=setupRecovery?'Adds the approved replacement administrator passkey. The existing vault and secret values are preserved.':'Your approved passkey becomes the first administrator of this new vault. Connect other platforms later in Connections.';
 if(ready&&!setupRecovery&&!bootstrapContext&&$('bsDone').hidden){bootstrapShow('bsDone');$('bsDoneTitle').textContent='First-time setup complete';$('bsResult').textContent='This platform already has an encrypted vault and an approved administrator. Use Key enrollment for additional passkeys, Connections for sharing, or Recover administrator access if access is lost.';$('bsLogin').hidden=!!snapshot;$('bsSecrets').hidden=!snapshot;}
}
function showAdministratorRecovery(){setupRecovery=true;setupFinished=false;tab('setup');renderSetupPurpose();bootstrapShow('bsStart');message('In the trusted Symcon console, open Recover administrator access. Then prepare and compare your replacement passkey here. Hardware policies remain enforced.');}
async function bootstrapBegin(ticket,reuse=false){
 if(installationReady&&!setupRecovery)throw Error('First-time setup is complete. Use Key enrollment to add a passkey, or Recover administrator access.');
 bootstrapClear();if(window.top!==window.self)throw Error('Open setup in its own browser tab.');
 const ctx=await bootstrapKey();const prepare=await bootstrapFetch('bootstrapPrepare',reuse?{reuse:true}:{},null,ticket);Object.assign(ctx,prepare);
 const cred=await ceremony(reuse?'get':'create',options(prepare.options,!reuse),ticket);
 const credential=reuse?assertion(cred):{type:cred.type,rawId:encoded(cred.rawId),response:{clientDataJSON:encoded(cred.response.clientDataJSON),attestationObject:encoded(cred.response.attestationObject)}};
 const transcript=await bootstrapHash(JSON.stringify(bootstrapCanonical(credential)));
 const challenge=prepare.options.challenge;
 const input=[reuse?'SECF.BOOTSTRAP.REUSE.1':'SECF.BOOTSTRAP.SUBMIT.1',boot.origin,boot.path,ctx.frontend,ctx.intent,prepare.prepare,challenge,ctx.keyDigest,transcript].join('\n')+'\n';
 const result=await bootstrapFetch('bootstrapSubmit',{prepare:prepare.prepare,key:ctx.key,credential,signature:await bootstrapSign(ctx,input)},ctx,ticket);
 Object.assign(ctx,result);bootstrapContext=ctx;$('bsComparison').textContent=result.comparison;$('bsCancel').hidden=false;bootstrapShow('bsWaiting');bootstrapSchedule();message('Compare the full identifier and approve this request in the Symcon console.');
}
run($('bsPrepare'),ticket=>bootstrapBegin(ticket));
run($('bsReuse'),ticket=>bootstrapBegin(ticket,true));
function bootstrapSelect(id,items,current,optional=true){const select=$(id);select.replaceChildren();if(optional){const o=document.createElement('option');o.value='0';o.textContent='No connection';select.append(o);}for(const item of items){const o=document.createElement('option');o.value=String(item.id);o.textContent=item.name;select.append(o);}select.value=String(current);}
function bootstrapPaths(){const ctx=bootstrapContext;const selected=ctx?.discovery?.backends.find(x=>x.id===Number($('bsBackend').value));if(selected){$('bsVault').value=selected.defaults.vaultDirectory;$('bsKeys').value=selected.defaults.keyDirectory;}}
async function bootstrapCheck(ticket=generation){const status=await bootstrapRequest('candidateStatus',{},ticket);bootstrapContext.operation=status.operation;if(!status.approved){message('Waiting for deliberate console approval.');return;}const d=status.discovery;bootstrapContext.discovery=d;setupRecovery=d.mode==='recovery';renderSetupPurpose();bootstrapSelect('bsBackend',d.backends,d.defaults.backend,false);bootstrapSelect('bsPortal',d.portals,d.defaults.portal);bootstrapSelect('bsDocs',d.documentation,d.defaults.documentation);$('bsBackendRow').hidden=d.backends.length===1;$('bsPortalLink').checked=d.defaults.portal>0;$('bsTheme').value=d.defaults.theme;$('bsDebug').checked=d.defaults.debugEnabled;$('bsOrigin').textContent=d.origin;$('bsACLRow').hidden=!d.requirements.native.windowsACLConfirmationRequired;bootstrapPaths();bootstrapShow('bsConfiguration');message('Your request is approved. Review the suggested settings.');}
function bootstrapSchedule(){bootstrapPause();if(bootstrapContext&&!document.hidden&&!$('bsWaiting').hidden)bootstrapPoll=setTimeout(async()=>{try{await bootstrapCheck();}catch(error){if(bootstrapContext)message(error.message,true);}bootstrapSchedule();},3000);}
run($('bsCheck'),async ticket=>{await bootstrapCheck(ticket);bootstrapSchedule();});
document.addEventListener('visibilitychange',()=>{if(!document.hidden)bootstrapSchedule();});
function bootstrapChoice(){return{backend:Number($('bsBackend').value),portal:Number($('bsPortal').value),documentation:Number($('bsDocs').value),theme:$('bsTheme').value,vaultDirectory:$('bsVault').value,keyDirectory:$('bsKeys').value,addPortalLink:$('bsPortalLink').checked,debugEnabled:$('bsDebug').checked,privateACLConfirmed:$('bsACL').checked,persistenceConfirmed:$('bsPersistence').checked};}
run($('bsReview'),async ticket=>{const result=await bootstrapRequest('planPreview',bootstrapChoice(),ticket);bootstrapContext.planDigest=result.planDigest;const p=result.configuration;const persistent=p.persistence.vault.confirmationRequired||p.persistence.keys.confirmationRequired;$('bsPersistenceRow').hidden=!persistent;if(persistent&&!p.persistenceConfirmed){message('Verify that the selected folders persist across container replacement.');return;}if(!p.privateACLConfirmed&&!$('bsACLRow').hidden){message('Verify the private Windows ACLs for the selected folders.');return;}const summary=$('bsSummary');summary.replaceChildren();for(const[label,value]of[['HTTPS address',p.origin],['Backend',p.backend||'Create new native backend'],['Encrypted vault',p.vaultDirectory],['Separate keys',p.keyDirectory],['Administrator','The passkey you prepared and approved'],['Portal link',p.addPortalLink?'Add link':'No change']]){const dt=document.createElement('dt');dt.textContent=label;const dd=document.createElement('dd');dd.textContent=String(value);summary.append(dt,dd);}bootstrapShow('bsPlan');});
run($('bsApply'),async ticket=>{
 const ctx=bootstrapContext;if(!ctx?.planDigest)throw Error('Review the current setup plan first.');const begin=await bootstrapRequest('applyOptions',{planDigest:ctx.planDigest},ticket);const cred=await ceremony('get',options(begin.options),ticket);
 $('bsCancel').hidden=true;let result;try{result=await bootstrapRequest('applyVerify',{planDigest:ctx.planDigest,credential:assertion(cred)},ticket);}catch(error){bootstrapShow('bsDone');$('bsResult').textContent='The setup response was lost. Check the accepted operation in the Symcon console. If the vault committed, use normal passkey sign-in. Do not start a second setup.';throw error;}
 bootstrapShow('bsDone');$('bsResult').textContent=result.status==='COMMITTED'?'Your vault contains the approved administrator.':result.message||'Setup is accepted. Resolve this operation in the console.';
 if(result.authenticated){csrf=result.csrf;await load(ticket);$('bsDoneTitle').textContent=setupRecovery?'Administrator access recovered':'Setup complete';$('bsResult').textContent=setupRecovery?'Your replacement passkey is approved and you are signed in. Continue to Secrets.':'Your vault is ready and you are signed in. Continue to Secrets to create a test entry.';$('bsSecrets').hidden=false;$('bsLogin').hidden=true;message(setupRecovery?'Administrator access recovered. You are signed in.':'Setup complete. You are signed in.');}else if(result.status==='COMMITTED'){csrf='';revision='';snapshot=null;selected=null;clearSecrets();$('login').hidden=false;$('logout').hidden=true;$('sessionTimeout').disabled=true;$('credentials').textContent='Sign in to view administrator credentials.';$('bsDoneTitle').textContent=setupRecovery?'Administrator access recovered':'Setup complete';$('bsResult').textContent=setupRecovery?'Your replacement passkey is approved. Sign in with it to open your existing vault.':'Your vault is ready. Sign in with your passkey to continue.';$('bsLogin').hidden=false;message(setupRecovery?'Administrator access recovered. Sign in with your replacement passkey.':'Vault created. Sign in with your passkey.');}if(result.status==='COMMITTED'){installationReady=true;setupFinished=true;}bootstrapContext=null;renderSetupPurpose();
});
$('bsEdit').addEventListener('click',()=>{if(bootstrapContext)bootstrapContext.planDigest=null;bootstrapShow('bsConfiguration');});
$('bsBackend').addEventListener('change',bootstrapPaths);
run($('bsCancel'),async ticket=>{const status=await bootstrapRequest('cancel',{},ticket);if(status.status==='CANCELLED'){bootstrapClear();if(installationReady){setupRecovery=false;setupFinished=true;renderSetupPurpose();tab('overview');}else bootstrapShow('bsStart');message('Cancelled; no setup operation was authorized.');}else{bootstrapShow('bsDone');$('bsResult').textContent=status.message;$('bsCancel').hidden=true;}});
$('bsSecrets').addEventListener('click',()=>tab('secrets'));
run($('bsLogin'),async()=>{$('signin').click();});
for(const id of ['bsBackend','bsPortal','bsDocs','bsTheme','bsVault','bsKeys','bsPortalLink','bsDebug','bsACL','bsPersistence'])$(id).addEventListener('change',()=>{if(bootstrapContext)bootstrapContext.planDigest=null;});
