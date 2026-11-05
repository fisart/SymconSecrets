'use strict';
const assert=require('node:assert/strict');
const {fixture,tick}=require('./ui-native.cjs');
(async()=>{
 const f=await fixture(),$=f.$,n=f.state.native;
 n.peers=[{id:'peer-a',name:'Remote A',active:true,state:'ACTIVE',globalMode:'shared-global-v1',pairingId:'pair-a',descriptor:{treeId:'tree-a',endpoint:'https://remote.example/hook/secrets_peer_11'},lastSync:null,delivery:null}];
 n.emergency={runtime:{mode:'REMOTE',ready:true,activeSource:'Remote A'},clients:[{peerId:'peer-a',name:'Remote A',grantId:'g1'}],grants:[{id:'g2',name:'Source B',active:true}],offers:[{peerId:'peer-a',name:'Remote A',grantId:'g3',digest:'d3'}]};
 $('overviewRefresh').click();await tick();await tick();
 assert.equal($('nativeEmergencyPeer').options.length,1);assert.equal($('nativeEmergencyGrant').disabled,false);
 assert.match($('nativeEmergencyRuntime').textContent,/Remote A.*Freshness is uncertain/);
 assert.match($('nativeEmergencyOffers').textContent,/Enable this emergency source/);
 assert.match($('nativeEmergencyClients').textContent,/Remove source/);
 assert.match($('nativeEmergencyGrants').textContent,/Revoke emergency access/);
 $('nativeEmergencyGrant').click();await tick();assert.equal($('review').open,true);assert.deepEqual(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation,{kind:'nativeEmergencyGrant',peerId:'peer-a'});$('cancelReview').click();await tick();
 $('nativeEmergencyOffers').querySelector('button').click();await tick();assert.equal($('review').open,true);assert.deepEqual(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation,{kind:'nativeEmergencyAccept',peerId:'peer-a',digest:'d3'});$('cancelReview').click();await tick();
 $('nativeEmergencyGrants').querySelector('button').click();await tick();assert.deepEqual(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation,{kind:'nativeEmergencyRevoke',id:'g2'});$('cancelReview').click();await tick();

 n.emergency.offers[0].name='<img src=x onerror=alert(1)>';
 $('overviewRefresh').click();await tick();await tick();assert.equal($('nativeEmergencyOffers').querySelector('img'),null);
 n.peers=[];n.emergency={clients:[],grants:[],offers:[],runtime:{mode:'LOCAL',ready:true}};
 $('overviewRefresh').click();await tick();await tick();
 assert.equal($('nativeEmergencyGrant').disabled,true);assert.match($('nativeEmergencyRuntime').textContent,/Local secrets source/);assert.match($('nativeEmergencyClients').textContent,/No emergency sources/);
 assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));f.dom.window.close();
 console.log('PASS emergency controls: explicit offers/grants, source status, uncertain freshness, standalone state and safe text');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exitCode=1;});
