'use strict';
const assert=require('node:assert/strict');
const {fixture,tick}=require('./ui-native.cjs');
(async()=>{
 const f=await fixture(),$=f.$,n=f.state.native;
 n.peers=[{id:'peer-a',name:'Remote A',active:true,state:'ACTIVE',globalMode:'shared-global-v1',pairingId:'pair-a',descriptor:{treeId:'tree-a',endpoint:'https://remote.example/hook/secrets_peer_11'},lastSync:null,delivery:null}];
 n.emergency={runtime:{mode:'REMOTE',ready:true,activeSource:'Remote A'},clients:[{peerId:'peer-a',name:'Remote A',grantId:'g1'}],grants:[{id:'g2',source:'peer-b',name:'Source B',active:true}],offers:[{peerId:'peer-a',name:'Remote A',grantId:'g3',digest:'d3'}]};
 $('overviewRefresh').click();await tick();await tick();
 assert.equal($('nativeEmergencyPeer').options.length,1);assert.equal($('nativeEmergencyGrant').disabled,false);
 assert.match($('nativeEmergencyRuntime').textContent,/Remote A.*Freshness is uncertain/);
 assert.match($('nativeEmergencyOffers').textContent,/Enable this emergency source/);
 assert.match($('nativeEmergencyClients').textContent,/Remove source/);
 assert.match($('nativeEmergencyGrants').textContent,/Revoke emergency access/);
 $('nativeEmergencyGrant').click();await tick();assert.equal($('review').open,true);assert.deepEqual(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation,{kind:'nativeEmergencyGrant',peerId:'peer-a'});$('cancelReview').click();await tick();
 $('nativeEmergencyOffers').querySelector('button').click();await tick();assert.equal($('review').open,true);assert.deepEqual(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation,{kind:'nativeEmergencyAccept',peerId:'peer-a',digest:'d3'});$('cancelReview').click();await tick();
 $('nativeEmergencyGrants').querySelector('button').click();await tick();assert.deepEqual(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation,{kind:'nativeEmergencyRevoke',id:'g2'});$('cancelReview').click();await tick();

 // Provider permissions filter the grant dropdown independently of incoming offers and sources.
 const update=async()=>{$('overviewRefresh').click();await tick();await tick();};
 n.peers.push({...n.peers[0],id:'peer-b',name:'Remote B'},{...n.peers[0],id:'peer-c',name:'Remote C'});
 n.emergency.grants.push({id:'g4',source:'peer-c',name:'Remote C',active:false});
 await update();
 assert.deepEqual([...$('nativeEmergencyPeer').options].map(option=>option.value),['peer-a','peer-c']);
 $('nativeEmergencyPeer').value='peer-c';await update();
 assert.equal($('nativeEmergencyPeer').value,'peer-c','Keep an eligible selected connection across refresh');
 n.emergency.grants.push({id:'g5',source:'peer-c',name:'Remote C',active:true});
 await update();assert.equal($('nativeEmergencyPeer').value,'peer-a','Remove a selection as soon as permission is granted');
 n.emergency.grants.push({id:'g6',source:'peer-a',name:'Remote A',active:true});
 await update();
 assert.equal($('nativeEmergencyPeer').disabled,true);
 assert.equal($('nativeEmergencyPeer').value,'');
 assert.equal($('nativeEmergencyGrant').disabled,true);
 assert.match($('nativeEmergencyPeer').textContent,/No connections awaiting permission/);
 n.emergency.grants.find(grant=>grant.id==='g6').active=false;
 await update();
 assert.deepEqual([...$('nativeEmergencyPeer').options].map(option=>option.value),['peer-a']);
 assert.equal($('nativeEmergencyPeer').disabled,false);
 assert.equal($('nativeEmergencyGrant').disabled,false);

 n.emergency.offers[0].name='<img src=x onerror=alert(1)>';
 $('overviewRefresh').click();await tick();await tick();assert.equal($('nativeEmergencyOffers').querySelector('img'),null);
 n.peers=[];n.emergency={clients:[],grants:[],offers:[],runtime:{mode:'LOCAL',ready:true}};
 $('overviewRefresh').click();await tick();await tick();
 assert.equal($('nativeEmergencyGrant').disabled,true);assert.match($('nativeEmergencyRuntime').textContent,/Local secrets source/);assert.match($('nativeEmergencyClients').textContent,/No emergency sources/);
 assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));f.dom.window.close();
 console.log('PASS emergency controls: explicit offers/grants, source status, uncertain freshness, standalone state and safe text');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exitCode=1;});
