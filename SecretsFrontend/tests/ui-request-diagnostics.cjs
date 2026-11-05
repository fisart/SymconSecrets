'use strict';
const assert=require('node:assert/strict');
const {fixture,tick}=require('./ui-native.cjs');
(async()=>{
 for(const action of ['prepare','nativeOverviewStatus']){
  const f=await fixture(),$=f.$,original=f.dom.window.fetch;
  let failures=0;
  f.dom.window.fetch=async(url,options)=>{
   if(JSON.parse(options.body).action!==action)return original(url,options);
   failures++;return {ok:false,json:async()=>({error:'Your administrator session expired. Sign in again. [SESSION_EXPIRED · 0123456789abcdef]',code:'SESSION_EXPIRED',reference:'0123456789abcdef',requiresSignIn:true})};
  };
  $('nativeRecoveryKey').value='RECOVERY-CANARY';$('browserValue').value='UNSAVED-CANARY';
  $(action==='prepare'?'nativeInvite':'overviewRefresh').click();await tick();await tick();
  assert.equal($('login').hidden,false);assert.equal($('logout').hidden,true);assert.equal($('review').open,false);
  assert.match($('message').textContent,/SESSION_EXPIRED.*0123456789abcdef/);assert.match($('readiness').textContent,/session expired/);
  assert.equal($('browserValue').value,'');assert.equal($('nativeRecoveryKey').value,'');
  assert.equal(failures,1,'Refused request was automatically retried.');
  assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));f.dom.window.close();
 }
 const f=await fixture(),$=f.$,original=f.dom.window.fetch;let failures=0;
 f.dom.window.fetch=async(url,options)=>{
  if(JSON.parse(options.body).action!=='prepare')return original(url,options);
  failures++;return {ok:false,json:async()=>({error:'The emergency offer changed. Refresh Connections. [EMERGENCY_OFFER_CHANGED · fedcba9876543210]',code:'EMERGENCY_OFFER_CHANGED',reference:'fedcba9876543210',requiresSignIn:false})};
 };
 $('nativeInvite').click();await tick();await tick();assert.equal($('login').hidden,true);assert.equal($('review').open,false);assert.match($('message').textContent,/EMERGENCY_OFFER_CHANGED.*fedcba9876543210/);assert.equal(failures,1);
 assert.equal(f.errors.length,0);f.dom.window.close();
 console.log('PASS refused-request UI: clear session-expiry recovery, cleared sensitive controls, safe reference, retained valid session and no automatic mutation retries');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exitCode=1;});
