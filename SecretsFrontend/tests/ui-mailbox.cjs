'use strict';
const assert=require('node:assert/strict');
const {fixture,tick}=require('./ui-native.cjs');
(async()=>{
 const f=await fixture(),$=f.$,n=f.state.native;
 const row=(state,direction='provider')=>({id:'grant:g',type:'emergency',state,peerId:'remote',direction,action:'nativePeers',requestedAt:null});
 n.mailbox={approvals:{'grant:h':[{label:'Approve with passkey',operation:{kind:'nativeEmergencyAccept',peerId:'remote',digest:'exact-offer'},summary:'Allow Global emergency reads from Heartbeat.'}]},nodes:[{id:'local',name:'Test',local:true,fresh:true,available:true,checkedAt:1793656603,rows:[row('SENDING'),{...row('APPROVAL_REQUIRED','consumer'),id:'grant:h'}]},{id:'remote',name:'Heartbeat <img src=x>',local:false,fresh:false,available:false,checkedAt:null,rows:[]}]};
 const original=f.dom.window.fetch;let uploads=0,resolve,statusCalls=0,preflight=0,targets=[{id:123,name:'Backup',repository:'fisart/Module-Configuration-Backup',branch:'main',enabled:true}];
 f.dom.window.fetch=async(url,options)=>{const r=JSON.parse(options.body);if(r.action==='nativeSupportStatus'){preflight++;throw Error('No preflight allowed');}if(r.action==='nativeSupportUpload'){uploads++;assert.equal(r.data.instance,0);return {ok:true,json:async()=>({job:'test-job',state:'queued'})};}if(r.action==='nativeSupportUploadStatus'){statusCalls++;return new Promise(done=>{resolve=done;});}return original(url,options);};
 f.dom.window.document.querySelector('[data-tab=nativeMailbox]').click();await tick();await tick();
 assert.match($('nativeMailboxNav').textContent,/1 to approve.*1 waiting/);assert.match($('mailboxRows').textContent,/Sending \/ retrying.*RequestedTime not recorded/);assert.match($('mailboxRows').textContent,/Your approval required/);assert.match($('mailboxRows').textContent,/Mailbox unavailable/);assert.equal($('mailboxRows').querySelector('img'),null);
 const approve=$('mailboxRows').querySelectorAll('button')[1];assert.equal(approve.textContent,'Approve with passkey');assert.match($('mailboxRows').textContent,/Allow Global emergency reads from Heartbeat/);approve.click();await tick();await tick();assert.equal($('review').open,false,'Direct approval opened another workflow.');assert.deepEqual(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation,{kind:'nativeEmergencyAccept',peerId:'remote',digest:'exact-offer'});assert.equal(f.calls.filter(c=>c.action==='approve').length,1,'Direct approval did not submit the passkey.');assert.equal($('nativeMailbox').hidden,false,'Approval left the Mailbox.');

 $('mailboxServer').value='local';$('mailboxServer').dispatchEvent(new f.dom.window.Event('change'));assert.doesNotMatch($('mailboxRows').textContent,/Mailbox unavailable/);
 n.mailbox.nodes[0].rows=[row('COMPLETED')];$('mailboxRefresh').click();await tick();await tick();assert.match($('mailboxRows').textContent,/No matching/);
 $('mailboxState').value='all';$('mailboxState').dispatchEvent(new f.dom.window.Event('change'));assert.match($('mailboxRows').textContent,/Completed/);
 assert.equal($('supportUpload').disabled,false);
 $('supportUpload').click();await tick();$('supportUpload').click();assert.equal(uploads,1);assert.equal(statusCalls,1);assert.equal(preflight,0);
 resolve({ok:true,json:async()=>({ok:true,repository:targets[0].repository,branch:'main',commit:'a'.repeat(40)})});await tick();await tick();assert.match($('supportResult').textContent,/Saved to.*commit a{40}/);assert.equal($('supportUpload').disabled,false);
 assert.equal(preflight,0,'Mailbox still performs an advance Configuration Backup lookup.');
 assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));f.dom.window.close();
 // A cancelled passkey must never submit approval or leave the Mailbox.
 const cancelled=await fixture(),c=cancelled.$;
 cancelled.state.native.mailbox={approvals:{'pair:p':[{operation:{kind:'nativeAcceptPair',peerId:'p'},summary:'Connect this exact server and share Global secrets.'}]},nodes:[{id:'local',name:'Test',local:true,fresh:true,available:true,checkedAt:1,rows:[{id:'pair:p',type:'pairing',state:'APPROVAL_REQUIRED',peerId:'p',action:'nativePeers'}]}]};
 cancelled.dom.window.navigator.credentials.get=async()=>{throw new cancelled.dom.window.DOMException('Passkey cancelled','NotAllowedError');};
 c('overviewRefresh').click();await tick();await tick();cancelled.dom.window.document.querySelector('[data-tab=nativeMailbox]').click();await tick();await tick();
 c('mailboxRows').querySelector('button').click();await tick();await tick();assert.equal(cancelled.calls.filter(x=>x.action==='approve').length,0);assert.equal(c('review').open,false);assert.equal(c('nativeMailbox').hidden,false);assert.match(c('mailboxRows').textContent,/Your approval required/);assert.equal(c('mailboxRows').querySelector('button').disabled,false);cancelled.dom.window.close();
 const stale=await fixture(),t=stale.$;stale.state.native.mailbox={approvals:{'grant:x':[{operation:{kind:'nativeEmergencyAccept',peerId:'remote',digest:'old-offer'},summary:'Read Global from the exact provider.'}]},nodes:[{id:'local',name:'Test',local:true,fresh:true,available:true,checkedAt:1,rows:[{id:'grant:x',type:'emergency',state:'APPROVAL_REQUIRED',peerId:'remote',action:'nativePeers',direction:'consumer'}]}]};
 const fetch=stale.dom.window.fetch;stale.dom.window.fetch=async(url,options)=>JSON.parse(options.body).action==='prepare'?{ok:false,json:async()=>({error:'The offer changed. Refresh this page.',code:'REVISION_CHANGED'})}:fetch(url,options);
 t('overviewRefresh').click();await tick();await tick();stale.dom.window.document.querySelector('[data-tab=nativeMailbox]').click();await tick();await tick();t('mailboxRows').querySelector('button').click();await tick();await tick();assert.equal(stale.calls.filter(x=>x.action==='approve').length,0);assert.match(t('message').textContent,/offer changed/);assert.equal(t('nativeMailbox').hidden,false);stale.dom.window.close();
 console.log('PASS Mailbox and support upload: direction, waiting, missing remote coverage, filters, safe text, explicit destination consent, single flight and confirmed commit');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exitCode=1;});
