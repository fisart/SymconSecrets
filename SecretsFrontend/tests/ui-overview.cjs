'use strict';
const assert=require('node:assert/strict');
const {fixture,tick}=require('./ui-native.cjs');
(async()=>{
 const f=await fixture(),$=f.$,n=f.state.native;
 n.overview={globalValues:12,localValues:3,credentials:4,hardwareCredentials:2,magicCredentials:1,machines:2,providers:1,pendingEffects:0,storage:{usedBytes:1000,capacityBytes:10000}};
 n.globalRevision='7';n.routeRevision='2';n.globalConflictCount=0;
 const peer=(id,extra={})=>({id,name:id,active:true,state:'ACTIVE',globalMode:'shared-global-v1',pairingId:'pair-'+id,descriptor:{treeId:'tree-'+id,endpoint:'https://'+id+'.example/hook/secrets_peer_22'},routeReceipt:'2',lastSync:'2026-11-03T08:00:00Z',delivery:null,...extra});
 n.peers=[peer('ready'),peer('blocked',{delivery:{problem:'certificate'}}),peer('pending',{active:false,state:'PENDING_APPROVAL'}),peer('removed',{active:false,state:'REVOKED'})];
 n.pairingReceived=[{id:'tree-ready',owner:'ready',pairingId:'pair-ready'}];n.pairingSent=[{peerId:'ready',pairingId:'pair-ready',status:'APPLIED',treeId:n.globalTreeId,revision:'7'}];n.outbox=[];
 n.backupOrigin={version:2,status:'active',origin:'https://'+'a'.repeat(32)+'.ipmagic.de'};
 $('overviewRefresh').click();await tick();await tick();
 assert.equal($('nativeOverview').hidden,false);assert.match($('meshConsistencyNotice').textContent,/saved here first.*synchronized afterward/);assert.match($('meshConsistencyNotice').textContent,/remote vaults are not enabled/);assert.equal($('overviewConnections').textContent,'2');assert.match($('overviewConnectionDetail').textContent,/1 synchronized.*1 awaiting approval.*1 delivery blocked/);assert.equal($('overviewPeerList').children.length,3);assert.match($('readiness').textContent,/Needs attention.*delivery blocked/);
 assert.equal($('globalCount').textContent,'12');assert.equal($('localCount').textContent,'3');assert.equal($('overviewMagic').textContent,'Full access active');assert.match($('overviewAccess').textContent,/4 tested.*2 hardware.*2 automation.*1 OAuth/);assert.equal($('overviewStorage').textContent,'10% used');
 // No vault revision changes: connection and Magic status must still refresh.
 const oldRevision=f.state.revision;n.peers=[peer('ready')];n.backupOrigin.version=1;n.globalConflictCount=2;n.overview.providerIssues=1;
 $('overviewRefresh').click();await tick();await tick();assert.equal(f.state.revision,oldRevision);assert.equal($('overviewConnections').textContent,'1');assert.equal($('overviewMagic').textContent,'Limited access active');assert.match($('overviewMagicDetail').textContent,/Approve full Magic access/);assert.equal($('overviewConflicts').textContent,'2');assert.match($('readiness').textContent,/secret conflicts.*OAuth/);
 n.backupOrigin.version=2;n.peers[0].routeReceipt='1';n.globalConflictCount=0;n.overview.providerIssues=0;await f.globalTimers.at(-1)();assert.match($('overviewMagicDetail').textContent,/Address delivery: 0 of 1/);assert.equal($('readiness').textContent,'Setup or synchronization in progress.');
 n.peers[0].routeReceipt='2';await f.globalTimers.at(-1)();assert.equal($('readiness').textContent,'Vault ready.');assert.equal($('readiness').classList.contains('success'),true);
 f.failOverview(true);await f.globalTimers.at(-1)();assert.match($('readiness').textContent,/out of date/);assert.equal($('readiness').classList.contains('success'),false);assert.equal($('overviewConnections').textContent,'1');f.failOverview(false);
 n.connectDiscovery={available:false};await f.globalTimers.at(-1)();assert.equal($('overviewMagic').textContent,'Connect unavailable');assert.match($('readiness').textContent,/Magic connection unavailable/);n.connectDiscovery={available:true,origin:'https://'+'b'.repeat(32)+'.ipmagic.de'};await f.globalTimers.at(-1)();assert.equal($('overviewMagic').textContent,'Address changed');n.connectDiscovery.origin=n.backupOrigin.origin;
 n.overview.magicCredentials=0;await f.globalTimers.at(-1)();assert.equal($('overviewMagic').textContent,'No usable passkey');assert.match($('readiness').textContent,/Magic passkey unavailable/);
 for(const [policy,label]of [[{status:'pending'},'Setup incomplete'],[{status:'revoked'},'Removed'],[null,'Not configured']]){n.backupOrigin=policy;await f.globalTimers.at(-1)();assert.equal($('overviewMagic').textContent,label);assert.equal($('overviewMagicURL').textContent,'');}
 n.peers=[];await f.globalTimers.at(-1)();assert.match($('overviewConnectionDetail').textContent,/Standalone/);assert.equal($('overviewPeerList').children.length,0);
 // Peer names are data, never markup. Status links open the existing wizard.
 n.peers=[peer('safe',{name:'<img src=x onerror=alert(1)>'})];await f.globalTimers.at(-1)();assert.equal($('overviewPeerList').querySelector('img'),null);$('overviewPeerList').querySelector('button').click();await tick();assert.equal($('nativePeers').hidden,false);
 $('logout').click();await tick();await tick();assert.equal($('nativeOverview').hidden,true);assert.equal($('overviewMagicURL').textContent,'');assert.equal($('overviewPeerList').children.length,0);assert.equal($('globalCount').textContent,'');
 assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));f.dom.window.close();
 console.log('PASS overview: live connection readiness/counts, Magic lifecycle and route delivery, conflicts, storage/access, unchanged-revision refresh, stale failures, safe text/navigation and logout cleanup');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exitCode=1;});
