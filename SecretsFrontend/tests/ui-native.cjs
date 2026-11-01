'use strict';
const assert=require('node:assert/strict');
const {webcrypto}=require('node:crypto');
const {TextEncoder}=require('node:util');
const {JSDOM,VirtualConsole}=require('jsdom');
const source=require('./page-source.cjs')().replaceAll('%%NONCE%%','test').replace('%%BOOT%%',JSON.stringify({origin:'https://secrets.example.test',path:'/hook/secrets_frontend_123',theme:'system',guidedV2Only:true})).replace('%%NAVIGATION%%','');
const tick=()=>new Promise(r=>setImmediate(r));
const credential=()=>({type:'public-key',rawId:new Uint8Array([1]).buffer,response:{clientDataJSON:new Uint8Array([1]).buffer,authenticatorData:new Uint8Array([1]).buffer,signature:new Uint8Array([1]).buffer,attestationObject:new Uint8Array([1]).buffer,userHandle:null}});
async function fixture(){
 const calls=[],errors=[];let output={nativeChanged:true},lose=false;
 const v=new VirtualConsole();v.on('jsdomError',e=>errors.push(e));
 const descriptor={backend:'456',endpoint:'https://secrets.example.test/hook/secrets_peer_456',vaultId:'vault-a',treeId:'tree-a'};
 const n={info:{vaultId:'vault-a',usedBytes:4096,capacityBytes:524288,directorySync:true},peerEndpoint:descriptor.endpoint,peerDescriptor:descriptor,globalTreeId:'tree-a',globalWritable:true,queuedJobs:0,peers:[],ownedTrees:[],received:[{id:'tree-b',owner:'vault-b',at:'2026-11-01T01:00:00Z',revision:'7',entries:[{path:[],type:'object',children:1},{path:['Shared <safe>'],type:'string'}]}],transfers:{},machines:[],hardwareProfile:{version:'none',fingerprints:{},aaguids:[]},providers:[],effects:{}};
 const snapshot={csrf:'csrf',revision:'3',hardware:{write:false,identity:false,export:false,reveal:false},global:[{path:[],type:'object',children:1},{path:['ASK'],type:'object',children:2}],local:[{path:[],type:'object',children:0}],credentials:[{id:'key-a',label:'Key <safe>',active:true,hardware:false}],native:n};
 const dom=new JSDOM(source,{url:'https://secrets.example.test/hook/secrets_frontend_123',runScripts:'dangerously',pretendToBeVisual:true,virtualConsole:v,beforeParse(w){
  Object.defineProperty(w,'crypto',{value:webcrypto});w.TextEncoder=TextEncoder;
  Object.defineProperty(w,'isSecureContext',{value:true});w.HTMLDialogElement.prototype.showModal=function(){this.open=true};w.HTMLDialogElement.prototype.close=function(){this.open=false};
  Object.defineProperty(w.navigator,'credentials',{value:{get:async()=>credential(),create:async()=>credential()}});
  w.URL.createObjectURL=()=> 'blob:test';w.URL.revokeObjectURL=()=>{};w.HTMLAnchorElement.prototype.click=function(){};
  w.fetch=async(url,options)=>{const r=JSON.parse(options.body);calls.push(r);let data={};
   if(r.action==='status')data={ready:true,enrollmentNeeded:false};if(r.action==='session')data=snapshot;
   if(r.action==='prepare')data={operationId:'operation-a',challengeId:'challenge-a',options:{challenge:'AQ',allowCredentials:[]},reviewSummary:{kind:r.data.operation.kind},requiresHardware:false};
   if(r.action==='approve'){if(lose){lose=false;return{ok:false,json:async()=>({error:'Reply lost'})};}data=output;}
   if(r.action==='nativeOperationStatus')data={result:'COMMITTED'};
   if(r.action==='nativeCandidateOptions')data={prepare:'candidate-prepare',options:{challenge:'AQ',user:{id:'AQ'},excludeCredentials:[]}};
   if(r.action==='nativeCandidateSubmit')data={candidate:'candidate-id',digest:'exact-digest',keyDigest:'browser-digest',label:'Second key'};
   return{ok:true,json:async()=>data};
  };
 }});
 await tick();await tick();return{dom,$:id=>dom.window.document.getElementById(id),calls,errors,setOutput:x=>{output=x},lose:()=>{lose=true}};
}
async function approve(f,id,output){f.setOutput(output);f.$(id).click();await tick();assert.equal(f.$('review').open,true);f.$('approve').click();await tick();await tick();}
(async()=>{
 const f=await fixture(),$=f.$;
 assert.equal($('nativeRecoveryEnrollment').hidden,false);$('nativeRecoveryEnrollment').click();assert.match($('message').textContent,/trusted Symcon console/);f.dom.window.document.querySelector('[data-tab="overview"]').click();assert.equal($('nativePeersNav').hidden,false);assert.match($('nativeStorageInfo').textContent,/512 KiB/);assert.equal($('nativePeerURL').value,'https://secrets.example.test/hook/secrets_peer_456');
 f.dom.window.document.querySelector('[data-tab="secrets"]').click();$('tree').querySelectorAll('button')[1].click();assert.equal($('nativeMachineScope').value,'global');assert.equal($('nativeMachinePath').value,'["ASK"]');
 $('scope').value='received:tree-b';$('scope').dispatchEvent(new f.dom.window.Event('change'));assert.equal($('save').disabled,true);assert.equal($('delete').disabled,true);assert.equal($('tree').querySelector('safe'),null);
 $('tree').querySelectorAll('button')[1].click();$('reveal').click();await tick();const op=f.calls.at(-1).data.operation;assert.equal(op.kind,'nativeReveal');assert.equal(op.revision,'7');assert.equal(op.treeId,'tree-b');$('cancelReview').click();
 f.dom.window.document.querySelector('[data-tab="nativePeers"]').click();await approve(f,'nativeInvite',{invitation:'PAIR-ONE-USE'});assert.equal($('nativeSensitiveValue').value,'PAIR-ONE-USE');assert.equal($('nativeSensitiveDialog').open,true);
 f.dom.window.document.querySelector('[data-tab="overview"]').click();assert.equal($('nativeSensitiveValue').value,'');assert.equal($('nativeSensitiveDialog').open,false);
 f.dom.window.document.querySelector('[data-tab="nativeRecovery"]').click();await approve(f,'nativeBackup',{backup:'{"encrypted":true}',recoveryKey:'BACKUP-RECOVERY-KEY'});assert.equal($('nativeSensitiveValue').value,'BACKUP-RECOVERY-KEY');$('nativeSensitiveClose').click();assert.equal($('nativeSensitiveValue').value,'');
 f.dom.window.document.querySelector('[data-tab="nativePeers"]').click();f.lose();await approve(f,'nativeInvite',{invitation:'NEVER-REPLAY-OUTPUT'});assert.equal(f.calls.filter(r=>r.action==='nativeOperationStatus').length,1);assert.equal($('nativeSensitiveValue').value,'');assert.match($('message').textContent,/response was lost/);
 f.dom.window.document.querySelector('[data-tab="nativeKeys"]').click();f.setOutput({committed:true,reloginRequired:true});$('nativeNewAdmin').click();
 for(let i=0;i<100&&!$('review').open;i++)await new Promise(r=>setTimeout(r,5));
 assert.equal($('review').open,true);const candidateOp=f.calls.filter(r=>r.action==='prepare').at(-1).data.operation;assert.equal(candidateOp.candidate,'candidate-id');assert.equal(candidateOp.digest,'exact-digest');assert.equal(f.calls.some(r=>r.action==='enrollmentOptions'),false);
 const sessionsBefore=f.calls.filter(r=>r.action==='session').length;$('approve').click();await tick();await tick();assert.equal(f.calls.filter(r=>r.action==='session').length,sessionsBefore);assert.equal($('login').hidden,false);assert.equal($('logout').hidden,true);assert.match($('message').textContent,/Sign in again/);
 $('nativeInvitation').value='SHOULD-CLEAR';$('nativeRecoveryKey').value='SHOULD-CLEAR';f.dom.window.dispatchEvent(new f.dom.window.Event('pagehide'));assert.equal($('nativeInvitation').value,'');assert.equal($('nativeRecoveryKey').value,'');assert.equal(f.dom.window.localStorage.length,0);assert.equal(f.dom.window.sessionStorage.length,0);assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));f.dom.window.close();
 process.stdout.write('PASS integrated native HTML: masked shared trees, scope defaults, exact approval, one-use outputs, backup download, lost-result lookup, re-login after enrollment and navigation cleanup\n');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exit(1);});
