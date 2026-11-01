'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {JSDOM,VirtualConsole}=require('jsdom');
const origin='https://test.hermitage.ap-fischer.de:46910';
const hook='/hook/secrets_frontend_50365';
const canonical=origin+hook;
const html=require('./page-source.cjs')().replaceAll('%%NONCE%%','test').replace('%%BOOT%%',JSON.stringify({origin,path:hook,theme:'system'})).replace('%%NAVIGATION%%','');
const tick=()=>new Promise(resolve=>setImmediate(resolve));
async function fixture(url,secure){
 const calls=[],errors=[],console=new VirtualConsole();console.on('jsdomError',e=>errors.push(e));
 const dom=new JSDOM(html,{url,runScripts:'dangerously',pretendToBeVisual:true,virtualConsole:console,beforeParse(w){
  if(secure!==undefined)Object.defineProperty(w,'isSecureContext',{value:secure,configurable:true});
  w.HTMLDialogElement.prototype.showModal=function(){this.open=true;};w.HTMLDialogElement.prototype.close=function(){this.open=false;};
  w.fetch=async(url,options)=>{calls.push({url,options});return{ok:true,json:async()=>({ready:false,message:'Setup required.'})};};
 }});await tick();return{dom,calls,errors};
}
(async()=>{
 for(const [url,secure] of [['http://test.hermitage.ap-fischer.de:46910'+hook,true],['https://evil.example.test'+hook,true],['https://test.hermitage.ap-fischer.de'+hook,true],[canonical,false],[canonical,undefined]]){
  const f=await fixture(url,secure);
  assert.equal(f.calls.length,0,'Unsafe browser context sent an API request.');
  assert.equal(f.dom.window.document.querySelectorAll('input,textarea,button,form').length,0,'Unsafe browser context retained credential controls.');
  assert.equal(f.dom.window.document.getElementById('secureWizardLink').href,canonical);
  assert.match(f.dom.window.document.querySelector('[role=alert]').textContent,/No credentials or requests have been sent/);
  assert(f.errors.every(e=>e.message.startsWith('Not implemented: navigation')),'Unexpected script failure.');
  f.dom.window.close();
 }
 const f=await fixture(canonical,true);
 assert.equal(f.errors.length,0);assert.equal(f.calls.length,1);assert.equal(JSON.parse(f.calls[0].options.body).action,'status');
 assert.equal(new URL(f.calls[0].url,canonical).href,canonical);
 assert.equal(f.calls[0].options.redirect,'error');assert.equal(f.calls[0].options.credentials,'same-origin');
 // Recheck on every API operation, not just the first page load.
 Object.defineProperty(f.dom.window,'isSecureContext',{value:false,configurable:true});
 f.dom.window.document.getElementById('setupCode').value='MUST_NOT_SEND';
 f.dom.window.document.getElementById('setupForm').dispatchEvent(new f.dom.window.Event('submit',{bubbles:true,cancelable:true}));await tick();
 assert.equal(f.calls.length,1,'A later insecure-context request sent credentials.');
 assert.equal(f.dom.window.document.getElementById('setupCode').value,'');
 f.dom.window.close();
 process.stdout.write('PASS browser HTTPS/exact-origin/secure-context gate, fixed canonical navigation, zero unsafe requests or credential controls and per-request recheck\n');
})().catch(error=>{process.stderr.write(error.stack+'\n');process.exitCode=1;});
