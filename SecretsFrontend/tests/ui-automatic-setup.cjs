'use strict';
const assert=require('node:assert/strict');
const {fixture,tick}=require('./ui-native.cjs');
(async()=>{
 const f=await fixture(),$=f.$,n=f.state.native,base=f.dom.window.fetch;
 const policy={id:'plan-one',members:[0,1,2,3].map(i=>({descriptor:{vaultId:'node-'+i,endpoint:'https://server-'+i+'.example/hook/secrets_peer_'+(100+i)},routes:['https://server-'+i+'.example/hook/secrets_peer_'+(100+i)],frontend:200+i}))};
 const status=(authorized,running,ready=false)=>({authorized,running,policy,completedAt:ready?1793790000:null,members:policy.members.map((m,i)=>({id:m.descriptor.vaultId,name:'server-'+i+'.example',local:i===0,url:'https://server-'+i+'.example/hook/secrets_frontend_'+(200+i),authorized:authorized||i===0?authorized:null,fresh:true,backupStatus:ready?'active':'pending',backupReady:ready,ready}))});
 let previews=0,runs=0;const polls=[];const timeout=f.dom.window.setTimeout.bind(f.dom.window);f.dom.window.setTimeout=(fn,ms,...args)=>ms===5000?(polls.push(fn),-5000):timeout(fn,ms,...args);
 f.dom.window.fetch=async(url,options)=>{const r=JSON.parse(options.body);
  if(r.action==='nativeSetupPreview')return {ok:true,json:async()=>++previews===1?{complete:false,found:3,checked:1}:{complete:true,policy}};
  if(r.action==='approve'){
   const operation=f.calls.filter(c=>c.action==='prepare').at(-1)?.data.operation;
   n.automaticSetup=operation?.kind==='nativeSetupStop'?{authorized:false,policy:null,members:[]}:status(true,true);
  }
  if(r.action==='nativeSetupRun'){runs++;n.automaticSetup=status(true,false,true);return {ok:true,json:async()=>({automaticSetup:n.automaticSetup})};}
  return base(url,options);
 };
 f.dom.window.document.querySelector('[data-tab=nativeMailbox]').click();await tick();await tick();
 $('setupFinish').click();await tick();await tick();assert.equal(previews,1);assert.match($('setupProgress').textContent,/background|Waiting/);polls.shift()();await tick();await tick();assert.equal(previews,2);assert.match($('setupFinish').textContent,/Authorize automatic setup/);assert.match($('setupMembers').textContent,/4 explicitly reviewed server/);assert.match($('setupMembers').textContent,/Local values, secret edits, administrator creation/);
 $('setupFinish').click();await tick();await tick();await tick();
 assert.equal(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation.kind,'nativeSetupAuthorize');assert.equal(f.calls.filter(c=>c.action==='approve').length,1);assert.equal($('review').open,false);assert.equal($('nativeMailbox').hidden,false);assert.match($('setupProgress').textContent,/0 of 4 servers ready/);assert.match($('setupMembers').textContent,/device step/);
 $('setupFinish').click();await tick();await tick();assert.equal(runs,1);assert.match($('setupProgress').textContent,/4 of 4 servers ready.*complete/);
 $('setupStop').click();await tick();await tick();assert.equal(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation.kind,'nativeSetupStop');assert.equal($('setupStop').hidden,true);
 assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));f.dom.window.close();
 console.log('PASS automatic setup UI: bounded discovery, explicit roster, one-time local passkey authorization, one-button run, remote/device progress, in-place approval and stop');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exitCode=1;});
