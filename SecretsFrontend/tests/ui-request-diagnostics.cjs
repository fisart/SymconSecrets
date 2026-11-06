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
 // A second tab's sign-in replaces the cookie while this tab retains its CSRF.
 for(const action of ['prepare','approve','nativeOverviewStatus']){
  const f=await fixture(),$=f.$,original=f.dom.window.fetch;let refused=false,approved=0,sessions=0;
  f.dom.window.fetch=async(url,options)=>{
   const r=JSON.parse(options.body);if(r.action==='session')sessions++;
   if(r.action==='approve')approved++;
   if(r.action===action&&!refused){refused=true;f.state.csrf='new-session-csrf';return {ok:false,json:async()=>({error:'Session verification failed. [CSRF_INVALID · 24074380ac5f01ca]',code:'CSRF_INVALID',reference:'24074380ac5f01ca',requiresSignIn:true})};}
   return original(url,options);
  };
  $('browserValue').value='UNSAVED-CANARY';$('nativeRecoveryKey').value='RECOVERY-CANARY';
  $(action==='nativeOverviewStatus'?'overviewRefresh':'nativeInvite').click();await tick();await tick();
  if(action==='approve'){assert.equal($('review').open,true);$('approve').click();await tick();await tick();}
  assert.equal(refused,true);assert.equal(sessions,1,'CSRF recovery did not do exactly one session refresh.');
  assert.equal($('login').hidden,true);assert.equal($('review').open,false);assert.match($('message').textContent,/Session refreshed.*confirm again.*24074380ac5f01ca/);
  assert.equal($('browserValue').value,'');assert.equal($('nativeRecoveryKey').value,'');assert.equal(approved,action==='approve'?1:0,'CSRF recovery replayed approval.');
  assert.equal(f.calls.filter(c=>c.action==='nativeOperationStatus').length,0,'CSRF refusal queried an old-session approval.');
  // Only a fresh user action prepares a new approval with the new token.
  let token;const recovered=f.dom.window.fetch;f.dom.window.fetch=async(url,options)=>{if(JSON.parse(options.body).action==='prepare')token=options.headers['X-CSRF-Token'];return recovered(url,options);};
  $('nativeInvite').click();await tick();assert.equal($('review').open,true);assert.equal(token,'new-session-csrf');$('cancelReview').click();
  assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));f.dom.window.close();
 }
 // Safe discovery/status recovery retries once; it never asks for approval itself.
 for(const action of ['nativeSupportUploadStatus']){
  const f=await fixture(),w=f.dom.window,original=w.fetch;let attempts=0;const timers=[];const timeout=w.setTimeout.bind(w);w.setTimeout=(fn,ms,...args)=>ms===5000||ms===10000?(timers.push(fn),-ms):timeout(fn,ms,...args);
  w.fetch=async(url,options)=>{const q=JSON.parse(options.body);
   if(q.action==='nativeSupportUpload')return {ok:true,json:async()=>({job:'test-job',state:'queued'})};
   if(q.action===action){attempts++;if(attempts===1){f.state.csrf='fresh-token';return {ok:false,json:async()=>({error:'Token changed',code:'CSRF_INVALID',reference:'csrf-test'})};}assert.equal(options.headers['X-CSRF-Token'],'fresh-token');return {ok:true,json:async()=>action==='nativeSetupPreview'?{complete:false,found:4,checked:2}:{state:'finished',ok:false,error:'Known failure after authenticated recovery'}};}
   return original(url,options);
  };
  w.document.querySelector('[data-tab=nativeMailbox]').click();await tick();
  f.$('supportUpload').click();
  await tick();await tick();await tick();assert.equal(attempts,2);assert.equal(f.calls.filter(q=>q.action==='approve').length,0);assert.equal(f.errors.length,0);w.close();
 }
 // A failed refresh cannot turn an expired session into an authenticated page.
 for(const code of ['SESSION_EXPIRED','CSRF_INVALID']){
  const expired=await fixture(),e=expired.$,fetch=expired.dom.window.fetch;let refreshes=0;
  expired.dom.window.fetch=async(url,options)=>{const action=JSON.parse(options.body).action;if(action==='prepare')return {ok:false,json:async()=>({error:'CSRF refusal [24074380ac5f01ca]',code:'CSRF_INVALID',reference:'24074380ac5f01ca'})};if(action==='session'){refreshes++;return {ok:false,json:async()=>({error:'Session expired',code,requiresSignIn:true})};}return fetch(url,options);};
  e('nativeInvite').click();await tick();await tick();assert.equal(refreshes,1,'Failed session refresh recursed.');assert.equal(e('login').hidden,false);assert.equal(e('review').open,false);assert.match(e('message').textContent,/Sign in again.*24074380ac5f01ca/);expired.dom.window.close();
 }
 // Restoring a browser history page must not retain its old token or session view.
 const restored=await fixture(),r=restored.$;restored.dom.window.dispatchEvent(new restored.dom.window.Event('pagehide'));restored.state.csrf='restored-session';const shown=new restored.dom.window.Event('pageshow');Object.defineProperty(shown,'persisted',{value:true});restored.dom.window.dispatchEvent(shown);await tick();await tick();assert.equal(r('login').hidden,true);r('nativeInvite').click();await tick();assert.equal(r('review').open,true);restored.dom.window.close();
 console.log('PASS refused-request UI: clear session-expiry recovery, cleared sensitive controls, safe reference, retained valid session and no automatic mutation retries');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exitCode=1;});
