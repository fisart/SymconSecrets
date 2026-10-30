'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {JSDOM,VirtualConsole}=require('jsdom');
const original=fs.readFileSync(path.join(__dirname,'../page.html'),'utf8');
const html=original.replaceAll('%%NONCE%%','test-nonce').replace('%%BOOT%%',JSON.stringify({path:'/hook/secrets_frontend_123',theme:'system'})).replace('%%NAVIGATION%%','');
const calls=[];let failPreview=false;let createWasVolatile=false;
const errors=[];const console=new VirtualConsole();console.on('jsdomError',error=>errors.push(error));
const dom=new JSDOM(html,{url:'https://secrets.example.test/hook/secrets_frontend_123',runScripts:'dangerously',virtualConsole:console,beforeParse(window){
 window.fetch=async(url,options)=>{
  const data=JSON.parse(options.body);calls.push({url,options,request:data});
  let result={};let ok=true;
  if(data.action==='status')result={ready:false,message:'Storage setup required.'};
  if(data.action==='setupPreview'){if(failPreview){ok=false;result={error:'Invalid setup credential.'};}else result={planId:'reviewed-plan',vaultDirectory:'/private/vault',keyDirectory:'/private/keys',permissions:'0700 / 0600'};}
  if(data.action==='setupCreate'){createWasVolatile=window.document.getElementById('setupCode').value===''&&window.document.getElementById('storagePlan').hidden;result={created:true,provisioning:{deploymentId:'public-id'}};}
  return{ok,json:async()=>result};
 };
 window.HTMLDialogElement.prototype.showModal=function(){this.open=true;};window.HTMLDialogElement.prototype.close=function(){this.open=false;};
}});
const $=id=>dom.window.document.getElementById(id);
const tick=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
 await tick();assert.match($('readiness').textContent,/Storage setup/);
 const tab=dom.window.document.querySelector('[data-tab="setup"]');tab.click();assert.equal($('setup').hidden,false);
 $('setupCode').value='TEST_ONE_USE_CREDENTIAL';$('setupForm').dispatchEvent(new dom.window.Event('submit',{bubbles:true,cancelable:true}));await tick();
 assert.equal($('setupCode').value,'');assert.equal($('storagePlan').hidden,false);assert.match($('vaultLocation').textContent,/\/private\/vault/);
 $('createStorage').click();await tick();assert.equal(createWasVolatile,true);assert.equal($('storageDone').hidden,false);
 const create=calls.find(call=>call.request.action==='setupCreate');assert.equal(create.request.data.code,'TEST_ONE_USE_CREDENTIAL');assert.equal(create.request.data.planId,'reviewed-plan');
 assert(calls.every(call=>call.url==='/hook/secrets_frontend_123'&&call.options.method==='POST'&&call.options.redirect==='error'));
 assert.equal(dom.window.localStorage.length,0);assert.equal(dom.window.sessionStorage.length,0);
 failPreview=true;$('setupCode').value='BAD_CODE';$('setupForm').dispatchEvent(new dom.window.Event('submit',{bubbles:true,cancelable:true}));await tick();assert.equal($('setupCode').value,'');assert.equal($('storagePlan').hidden,true);assert.match($('message').textContent,/Invalid setup/);
 $('newValue').value='SHOULD_CLEAR';$('enrollmentCode').value='SHOULD_CLEAR';dom.window.dispatchEvent(new dom.window.Event('pagehide'));assert.equal($('newValue').value,'');assert.equal($('enrollmentCode').value,'');
 assert.equal(errors.length,0,errors.map(error=>error.message).join('\n'));
 dom.window.close();process.stdout.write('PASS DOM wizard preview/create, volatile entry clearing, failure/cancel cleanup, no browser storage and fixed POST endpoint\n');
})().catch(error=>{process.stderr.write(error.stack+'\n');process.exitCode=1;dom.window.close();});
