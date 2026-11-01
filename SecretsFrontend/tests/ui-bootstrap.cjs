'use strict';
const assert=require('node:assert/strict');
const {webcrypto,randomUUID,createHash}=require('node:crypto');
const {TextEncoder}=require('node:util');
const {spawnSync}=require('node:child_process');
const {JSDOM,VirtualConsole}=require('jsdom');
const origin='https://secrets.example.test',path='/hook/secrets_frontend_123';
const source=require('./page-source.cjs')().replaceAll('%%NONCE%%','test').replace('%%BOOT%%',JSON.stringify({origin,path,theme:'system',guidedV2Only:true})).replace('%%NAVIGATION%%','');
const tick=()=>new Promise(r=>setImmediate(r));
const wait=async(fn)=>{for(let i=0;i<150;i++){if(fn())return;await new Promise(r=>setTimeout(r,5));}throw Error('Timed out waiting for UI: '+fn);};
const b64=x=>Buffer.from(x).toString('base64url');
const nonce=()=>b64(webcrypto.getRandomValues(new Uint8Array(32)));
const canonical=x=>x&&typeof x==='object'&&!Array.isArray(x)?Object.fromEntries(Object.keys(x).sort().map(k=>[k,canonical(x[k])])):x;
async function fixture({delayCreate=false}={}){
 const calls=[],errors=[],cryptoChecks=[];let pairKey,ctx,expectedNonce,approved=false,creationResolve;
 const delayed=new Promise(r=>{creationResolve=r;});
 const ids={frontend:randomUUID(),intent:nonce(),candidate:nonce(),candidateDigest:'a'.repeat(64),operation:randomUUID()};
 const v=new VirtualConsole();v.on('jsdomError',e=>errors.push(e));
 const snapshot={csrf:'normal-csrf',revision:'0',hardware:{write:false,identity:false,export:false,reveal:false},global:[],local:[],credentials:[]};
 const discovery={mode:'initial',origin,requirements:{native:{windowsACLConfirmationRequired:false}},backends:[{id:456,name:'Native backend',defaults:{vaultDirectory:'/private/vault',keyDirectory:'/private/keys'}}],portals:[],documentation:[],defaults:{backend:456,portal:0,documentation:0,theme:'system',debugEnabled:false}};
 const dom=new JSDOM(source,{url:origin+path,runScripts:'dangerously',pretendToBeVisual:true,virtualConsole:v,beforeParse(w){
  Object.defineProperty(w,'crypto',{value:webcrypto});w.TextEncoder=TextEncoder;Object.defineProperty(w,'isSecureContext',{value:true});
  w.HTMLDialogElement.prototype.showModal=function(){this.open=true;};w.HTMLDialogElement.prototype.close=function(){this.open=false;};
  const credential={type:'public-key',rawId:Uint8Array.of(1).buffer,response:{clientDataJSON:Uint8Array.of(2).buffer,attestationObject:Uint8Array.of(3).buffer,authenticatorData:Uint8Array.of(4).buffer,signature:Uint8Array.of(5).buffer,userHandle:null}};
  Object.defineProperty(w.navigator,'credentials',{value:{create:async()=>delayCreate?delayed:credential,get:async()=>credential}});
  w.fetch=async(url,options)=>{
   assert.equal(url,path);assert.equal(options.method,'POST');assert.equal(options.redirect,'error');assert.equal(options.credentials,'same-origin');
   const r=JSON.parse(options.body);calls.push(r);let data={};
   if(r.action==='status')data={ready:false,message:'Open setup from the console.'};
   if(r.action==='session')data=snapshot;
   if(r.action==='bootstrapPrepare'){ctx={...ids,prepare:nonce(),challenge:nonce()};data={prepare:ctx.prepare,options:{challenge:ctx.challenge,user:{id:nonce()}},csrf:'bootstrap-csrf',intent:ids.intent,frontend:ids.frontend};}
   if(r.action==='bootstrapSubmit'){
    assert.equal(options.headers['X-CSRF-Token'],'bootstrap-csrf');pairKey=await webcrypto.subtle.importKey('jwk',r.data.key,{name:'ECDSA',namedCurve:'P-256'},true,['verify']);
    const prefix=Buffer.from('SECF.BOOTSTRAP.KEY.1\0'),kd=createHash('sha256').update(Buffer.concat([prefix,Buffer.from(r.data.key.x,'base64url'),Buffer.from(r.data.key.y,'base64url')])).digest('hex');
    const digest=createHash('sha256').update(JSON.stringify(canonical(r.data.credential))).digest('hex');
    const signed=['SECF.BOOTSTRAP.SUBMIT.1',origin,path,ids.frontend,ids.intent,ctx.prepare,ctx.challenge,kd,digest].join('\n')+'\n';
    assert(await webcrypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},pairKey,Buffer.from(r.data.signature,'base64url'),Buffer.from(signed)),'Actual browser submit signature failed independent verification.');
    expectedNonce=nonce();data={candidate:ids.candidate,candidateDigest:ids.candidateDigest,keyDigest:kd,comparison:'1234–5678–9ABC–DEF0',epoch:'0',nonce:expectedNonce};
   }
   if(r.action==='bootstrapProof'){
    assert.equal(r.data.nonce,expectedNonce,'Browser sent concurrent/stale transport requests.');assert.equal(r.data.origin,origin);assert.equal(r.data.path,path);assert.equal(r.data.frontend,ids.frontend);assert.equal(options.headers['X-CSRF-Token'],'bootstrap-csrf');
    const m=r.data,raw=Buffer.from(m.body,'base64url'),digest=createHash('sha256').update(raw).digest('hex');
    const signed=['SECF.BOOTSTRAP.POP.1',...['purpose','origin','path','frontend','intent','candidate','candidateDigest','keyDigest','epoch','request','nonce','operation','action'].map(k=>m[k]),digest].join('\n')+'\n';
    assert.equal(Buffer.from(m.signature,'base64url').length,64);assert(await webcrypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},pairKey,Buffer.from(m.signature,'base64url'),Buffer.from(signed)));
    cryptoChecks.push({message:m,key:calls.find(x=>x.action==='bootstrapSubmit').data.key});
    const body=JSON.parse(raw);expectedNonce=nonce();data={epoch:'0',nonce:expectedNonce};
    if(m.action==='candidateStatus')Object.assign(data,{approved,operation:ids.operation,...(approved?{discovery}:{})});
    if(m.action==='planPreview')Object.assign(data,{planDigest:'b'.repeat(64),configuration:{...body,origin,persistence:{vault:{confirmationRequired:false},keys:{confirmationRequired:false}}}});
    if(m.action==='applyOptions')Object.assign(data,{options:{challenge:nonce(),allowCredentials:[]}});
    if(m.action==='applyVerify')Object.assign(data,{status:'COMMITTED',authenticated:true,csrf:'normal-csrf'});
   }
   return{ok:true,json:async()=>data};
  };
 }});await tick();return{dom,$:id=>dom.window.document.getElementById(id),calls,errors,cryptoChecks,approve:()=>{approved=true;},resolve:()=>creationResolve({type:'public-key',rawId:Uint8Array.of(1).buffer,response:{clientDataJSON:Uint8Array.of(2).buffer,attestationObject:Uint8Array.of(3).buffer}})};
}
(async()=>{
 const f=await fixture();f.$('bsPrepare').click();await wait(()=>!f.$('bsWaiting').hidden);assert.equal(f.$('bsComparison').textContent,'1234–5678–9ABC–DEF0');
 f.$('bsCheck').click();await wait(()=>f.calls.some(r=>r.data.action==='candidateStatus'));assert.equal(f.$('bsConfiguration').hidden,true,'Pending candidate received configuration.');
 await wait(()=>!f.$('bsCheck').disabled);f.approve();f.$('bsCheck').click();await wait(()=>!f.$('bsConfiguration').hidden);assert.equal(f.$('bsBackendRow').hidden,true);assert.equal(f.$('bsVault').value,'/private/vault');assert.equal(f.$('bsPortal').value,'0');
 f.$('bsReview').click();await wait(()=>!f.$('bsPlan').hidden);assert.match(f.$('bsSummary').textContent,/passkey you prepared/);f.$('bsApply').click();await wait(()=>f.calls.some(r=>r.action==='session'));assert.equal(f.$('login').hidden,true);assert.match(f.$('message').textContent,/You are signed in|you are signed in/);assert.equal(f.$('bsSecrets').hidden,false);assert.equal(f.$('bsLogin').hidden,true);assert.match(f.$('bsResult').textContent,/you are signed in/);f.$('bsSecrets').click();assert.equal(f.$('secrets').hidden,false,'Completion did not open Secrets.');
 const vector=f.cryptoChecks[0];const verifier=spawnSync(process.env.PHP_BINARY||'php',['-n','-r',"require 'SecretsBackend/BootstrapVerifier.php'; $v=json_decode(stream_get_contents(STDIN),true); SecretsBootstrapVerifier::message($v['message'],$v['key']); echo 'OK';"],{cwd:require('node:path').join(__dirname,'../..'),input:JSON.stringify(vector),encoding:'utf8'});
 assert.equal(verifier.status,0,verifier.stdout+verifier.stderr);assert.equal(verifier.stdout,'OK','Actual WebCrypto signature did not interoperate with PHP/OpenSSL.');
 assert.equal(f.calls.some(r=>/guided|enrollmentOptions|setupCreate/.test(r.action)),false);assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));assert.equal(f.dom.window.localStorage.length,0);assert.equal(f.dom.window.sessionStorage.length,0);f.dom.window.close();
 const automatic=await fixture();automatic.$('bsPrepare').click();await wait(()=>!automatic.$('bsWaiting').hidden);automatic.approve();
 for(let i=0;i<100&&automatic.$('bsConfiguration').hidden;i++)await new Promise(r=>setTimeout(r,50));
 assert.equal(automatic.$('bsConfiguration').hidden,false,'Approved setup did not automatically advance.');
 assert.match(automatic.dom.window.document.querySelector('#guide').textContent,/Step 3: Refresh approval requests/);
 assert.doesNotMatch(automatic.dom.window.document.querySelector('#guide').textContent,/ten-minute setup code/);automatic.dom.window.close();
 const late=await fixture({delayCreate:true});late.$('bsPrepare').click();await wait(()=>late.calls.some(r=>r.action==='bootstrapPrepare'));late.dom.window.dispatchEvent(new late.dom.window.Event('pagehide'));late.resolve();await tick();await tick();assert.equal(late.calls.some(r=>r.action==='bootstrapSubmit'),false,'Navigated page submitted a late passkey.');late.dom.window.close();
 console.log('PASS code-free rendered setup, actual WebCrypto/PHP interoperability, serial signed transport, approved defaults, atomic completion/login and late-candidate cleanup');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exit(1);});
