'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {JSDOM}=require('jsdom');
const source=require('./page-source.cjs')().replaceAll('%%NONCE%%','test').replace('%%BOOT%%',JSON.stringify({origin:'https://secrets.example.test',path:'/hook/secrets_frontend_123',theme:'system'})).replace('%%NAVIGATION%%','');
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r});return{promise,resolve};};
const credential=()=>({type:'public-key',rawId:new Uint8Array([1]).buffer,response:{clientDataJSON:new Uint8Array([1]).buffer,authenticatorData:new Uint8Array([1]).buffer,signature:new Uint8Array([1]).buffer,userHandle:null}});
async function fixture(mode='approve'){
 const pending=deferred(),calls=[],timers=[];
 const dom=new JSDOM(source,{url:'https://secrets.example.test/hook/secrets_frontend_123',runScripts:'dangerously',pretendToBeVisual:true,beforeParse(w){Object.defineProperty(w,'isSecureContext',{value:true,configurable:true});
  const timeout=w.setTimeout.bind(w);w.setTimeout=(fn,ms,...args)=>{if(ms===600000)timers.push(fn);return timeout(fn,ms,...args)};
  w.HTMLDialogElement.prototype.showModal=function(){this.open=true};w.HTMLDialogElement.prototype.close=function(){this.open=false};
  Object.defineProperty(w.navigator,'credentials',{value:{get:async()=>mode==='credential'?pending.promise:credential(),create:async()=>mode==='enrollment'?pending.promise:credential()}});
  w.fetch=async(url,options)=>{
   const request=JSON.parse(options.body);calls.push(request.action);
   let data=request.action==='status'?{ready:true}:request.action==='session'?{csrf:'test',revision:'1',hardware:{write:false,identity:false,export:false,reveal:false},global:[{path:['Service'],type:'object',children:1},{path:['Other'],type:'object',children:1}],local:[],credentials:[]}:['prepare','enrollmentOptions'].includes(request.action)?{challengeId:'test',options:{challenge:'AQ',allowCredentials:[],user:{id:'AQ'}}}:{};
   if((mode==='approve'&&request.action==='approve')||(mode==='preview'&&request.action==='setupPreview'))data=await pending.promise; // Deliberately ignore AbortSignal.
   return{ok:true,json:async()=>data};
  };
 }});
 await tick();await tick();const $=id=>dom.window.document.getElementById(id);
 return{dom,$,pending,calls,timers};
}
async function pendingReveal(f){
 f.dom.window.document.querySelector('[data-tab="secrets"]').click();f.$('tree').querySelector('button').click();f.$('reveal').click();await tick();f.$('approve').click();await tick();
}
(async()=>{
 for(const event of ['pagehide','hidden','navigation','selection','scope','cancel','clear','logout']){
  const f=await fixture();await pendingReveal(f);assert(f.calls.includes('approve'));
  if(event==='pagehide')f.dom.window.dispatchEvent(new f.dom.window.Event('pagehide'));
  if(event==='hidden'){Object.defineProperty(f.dom.window.document,'hidden',{value:true,configurable:true});f.dom.window.document.dispatchEvent(new f.dom.window.Event('visibilitychange'));}
  if(event==='navigation')f.dom.window.document.querySelector('[data-tab="overview"]').click();
  if(event==='selection')f.$('tree').querySelectorAll('button')[1].click();
  if(event==='scope'){f.$('scope').value='local';f.$('scope').dispatchEvent(new f.dom.window.Event('change'));}
  if(event==='cancel')f.$('cancelReview').click();
  if(event==='clear')f.$('clearReveal').click();
  if(event==='logout')f.$('logout').click();
  f.pending.resolve({fields:[{field:'Password',value:'LATE_CANARY'}]});await tick();await tick();
  assert.equal(f.$('revealed').textContent,'',event+' restored cleared plaintext');assert.equal(f.$('revealed').hidden,true);
  if(event==='pagehide')assert.equal(f.$('readiness').textContent.includes('LATE_CANARY'),false);
  f.dom.window.close();process.stdout.write('PASS A07 discard delayed reveal after '+event+'\n');
 }
 const credentialRace=await fixture('credential');await pendingReveal(credentialRace);credentialRace.$('cancelReview').click();credentialRace.pending.resolve(credential());await tick();await tick();assert(!credentialRace.calls.includes('approve'));credentialRace.dom.window.close();
 assert.equal(credentialRace.dom.window?.document?.getElementById?.('guidedCode')??null,null);
 process.stdout.write('PASS A07 cancelled WebAuthn and delayed sensitive-response cleanup\n');
})().catch(error=>{process.stderr.write(error.stack+'\n');process.exitCode=1;});
