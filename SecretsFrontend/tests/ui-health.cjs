'use strict';
const assert=require('node:assert/strict');
const {fixture,tick}=require('./ui-native.cjs');
(async()=>{
 const f=await fixture(),$=f.$,n=f.state.native;n.globalConflictCount=0;n.outbox=[];
 const health={connection:'reachable',synchronization:'verified',lastAttemptAt:1793656600,lastSuccessAt:1793656600,lastVerifiedAt:1793656600,pendingMessages:0,problem:null,failedChecks:0,intervalSeconds:60,staleAfterSeconds:180,remoteConflicts:0};
 const p={id:'vault-b',name:'Other platform',state:'ACTIVE',active:true,globalMode:'shared-global-v1',pairingId:'pair-b',descriptor:{treeId:'tree-b',endpoint:'https://peer.example/hook/secrets_peer_22'},health};n.peers=[p];
 const update=async()=>{await f.globalTimers.at(-1)();await tick();};await update();
 assert.equal($('readiness').textContent,'Vault ready.');assert.match($('overviewPeerList').textContent,/Verified in sync.*Connection: Reachable.*Last check:.*Last successful check:.*Last verified in sync:.*Pending messages: 0/);assert.match($('overviewChecked').textContent,/background every 60 seconds.*page closed/);
 health.synchronization='synchronizing';health.pendingMessages=2;await update();assert.equal($('readiness').textContent,'Setup or synchronization in progress.');assert.equal($('readiness').classList.contains('success'),false);assert.match($('overviewPeerList').textContent,/Synchronizing.*Pending messages: 2/);
 health.synchronization='mismatch';await update();assert.match($('readiness').textContent,/Needs attention.*1 platform.*synchronization attention/);assert.match($('overviewPeerList').textContent,/Not synchronized/);assert.equal($('overviewPeerList').querySelector('.healthStatus').dataset.state,'mismatch');
 health.connection='unreachable';health.synchronization='unknown';health.problem='certificate';health.failedChecks=3;await update();assert.match($('readiness').textContent,/Needs attention/);assert.match($('overviewPeerList').textContent,/Status unknown · unreachable.*HTTPS verification failed/);assert.equal($('overviewPeerList').querySelector('.healthStatus').dataset.state,'unknown');
 health.connection='unknown';health.problem='check-overdue';await update();assert.match($('overviewPeerList').textContent,/verification is overdue/);assert.match($('readiness').textContent,/Needs attention/);
 health.connection='reachable';health.synchronization='mismatch';health.problem='inconsistent-state';await update();assert.match($('overviewPeerList').textContent,/history differs; investigation required/);
 health.synchronization='verified';health.problem=null;health.pendingMessages=0;health.failedChecks=0;n.globalConflictCount=2;await update();assert.match($('overviewPeerList').textContent,/Verified in sync · resolve conflicts/);assert.equal($('overviewConflicts').textContent,'2');assert.match($('readiness').textContent,/secret conflicts/);assert.doesNotMatch($('readiness').textContent,/platform\(s\) need synchronization/);n.globalConflictCount=0;
 f.dom.window.document.querySelector('[data-tab=nativePeers]').click();await update();assert.match($('nativePeerList').textContent,/Verified in sync.*Last verified in sync/);assert.equal(f.calls.at(-1).action,'nativeOverviewStatus','Completed Connections tab stopped refreshing health.');
 f.failOverview(true);await update();assert.match($('nativeDeliveryInfo').textContent,/out of date/);assert.match($('nativePeerList').textContent,/Status unknown · refresh required/);f.failOverview(false);await update();assert.match($('nativePeerList').textContent,/Verified in sync/);
 // Freshness is background metadata, never a login or passkey ceremony.
 assert.equal(f.calls.filter(r=>['authOptions','prepare','approve'].includes(r.action)).length,0);assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));f.dom.window.close();
 console.log('PASS health UI: Overview alerts for mismatch/unreachable/overdue/inconsistent state, fresh timestamps, separate conflicts, live Connections refresh and stale-page refusal');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exitCode=1;});
