'use strict';
const assert=require('node:assert/strict');
const {fixture,tick}=require('./ui-native.cjs');
(async()=>{
 const f=await fixture(),$=f.$,n=f.state.native,base=f.dom.window.fetch;
 const policy={id:'plan-one',members:[0,1,2,3].map(i=>({descriptor:{vaultId:'node-'+i,endpoint:'https://server-'+i+'.example/hook/secrets_peer_'+(100+i)},routes:['https://server-'+i+'.example/hook/secrets_peer_'+(100+i)],frontend:200+i}))};
 const status=(ready=false)=>({authorized:true,running:!ready,policy,completedAt:ready?1793790000:null,report:{state:ready?'complete':'running'},members:policy.members.map((m,i)=>({id:m.descriptor.vaultId,name:'server-'+i+'.example',local:i===0,authorized:true,fresh:true,backupReady:false,ready,details:{links:[],queuedMessages:0,conflicts:0,errors:[]}}))});
 let runs=0;
 f.dom.window.fetch=async(url,options)=>{
  const r=JSON.parse(options.body);
  if(r.action==='nativeSetupRun'){runs++;n.automaticSetup=status();return {ok:true,json:async()=>({automaticSetup:n.automaticSetup})};}
  return base(url,options);
 };
 f.dom.window.document.querySelector('[data-tab=nativeMailbox]').click();await tick();await tick();
 $('setupFinish').click();await tick();await tick();
 assert.equal(runs,1);assert.equal(f.calls.filter(c=>['prepare','approve','nativeSetupPreview'].includes(c.action)).length,0,'One click requested another approval or preview');
 assert.match($('setupProgress').textContent,/running.*0 of 4/);assert.doesNotMatch($('setupMembers').textContent,/Authorize on this server|device step/);
 n.automaticSetup=status(true);f.dom.window.document.querySelector('[data-tab=nativeMailbox]').click();await tick();await tick();
 assert.match($('setupProgress').textContent,/OK.*all 4 servers/,'Browser backup keys blocked mesh completion');
 n.automaticSetup.members[2].fresh=false;f.dom.window.document.querySelector('[data-tab=nativeMailbox]').click();await tick();await tick();assert.doesNotMatch($('setupProgress').textContent,/^OK/,'Stale peer result displayed OK');assert.match($('setupProgress').textContent,/setup completed.*checks need refreshing/,'A completed run was mislabeled as unfinished setup');
 n.automaticSetup.report={errors:[{server:'server-2.example',direction:'node-0 → node-2',step:'SETUP_ADVANCE',code:'timeout',attempts:[{route:'https://server-2.example/hook/secrets_peer_102',elapsedMs:45000,httpStatus:0}]}]};
 f.dom.window.document.querySelector('[data-tab=nativeMailbox]').click();await tick();await tick();assert.match($('setupMembers').textContent,/SETUP_ADVANCE/);assert.match($('setupMembers').textContent,/45000/);assert.ok($('setupReport'));
 // Download must read the latest backend state, not relabel the cached UI with a new time.
 let downloaded=null;f.dom.window.Blob=class{constructor(parts){downloaded=JSON.parse(parts[0]);}};
 n.automaticSetup=status(true);n.automaticSetup.observedAt=1794007400;
 const reads=f.calls.filter(c=>c.action==='nativeOverviewStatus').length;
 $('setupReport').click();await tick();await tick();
 assert.equal(f.calls.filter(c=>c.action==='nativeOverviewStatus').length,reads+1);
 assert.equal(downloaded.setup.observedAt,1794007400);assert.equal(downloaded.setup.running,false);
 downloaded=null;const fetchWorking=f.dom.window.fetch;
 f.dom.window.fetch=async(url,options)=>JSON.parse(options.body).action==='nativeOverviewStatus'?Promise.reject(Error('Offline')):fetchWorking(url,options);
 $('setupReport').click();await tick();await tick();assert.equal(downloaded,null,'Failed refresh downloaded stale status');assert.equal($('setupReport').disabled,false);
 assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));f.dom.window.close();
 const refused=await fixture(),original=refused.dom.window.fetch;let starts=0;
 refused.dom.window.fetch=async(url,options)=>{const r=JSON.parse(options.body);if(r.action==='nativeSetupRun'){starts++;return {ok:false,json:async()=>({error:'Session token changed',code:'CSRF_INVALID'})};}return original(url,options);};
 refused.$('setupFinish').click();await tick();await tick();await tick();assert.equal(starts,1,'A setup mutation was replayed after CSRF recovery');assert.match(refused.$('setupProgress').textContent,/not confirmed/);refused.dom.window.close();
 console.log('PASS automatic mesh UI: one click, no node approvals, progress, verified OK without browser keys, stale status rejection and detailed errors');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exitCode=1;});
