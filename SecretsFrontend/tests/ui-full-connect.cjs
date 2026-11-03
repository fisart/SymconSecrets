'use strict';
const assert=require('node:assert/strict');
const {fixture,tick,approve}=require('./ui-native.cjs');
(async()=>{
 const origin='https://'+'a'.repeat(32)+'.ipmagic.de',f=await fixture({origin,full:true}),$=f.$;
 assert.equal($('connectWizard').hidden,false,'Full Magic administration is hidden.');assert.equal($('nativeImportNav').hidden,false);assert.equal($('connectAdminURL').value,origin+'/hook/secrets_frontend_123');
 f.dom.window.document.querySelector('[data-tab=nativeImport]').click();await tick();assert(f.calls.some(c=>c.action==='legacySources'));
 f.dom.window.document.querySelector('[data-tab=nativeKeys]').click();$('nativeNewAdmin').click();for(let n=0;n<100&&!$('review').open;n++)await new Promise(r=>setTimeout(r,5));assert.equal(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation.kind,'nativeEnrollment');$('cancelReview').click();await tick();
 f.dom.window.document.querySelector('[data-tab=nativeRecovery]').click();await approve(f,'nativeBackup',{backup:'{"encrypted":true}',recoveryKey:'MAGIC-RECOVERY-KEY'});assert.equal($('nativeSensitiveValue').value,'MAGIC-RECOVERY-KEY');$('nativeSensitiveClose').click();
 f.dom.window.document.querySelector('[data-tab=nativePeers]').click();$('peerConnectTarget').value='https://'+'b'.repeat(32)+'.ipmagic.de/hook/secrets_peer_202';$('peerConnectHere').click();await tick();assert.equal($('peerCoordinatorPanel').hidden,false);assert.doesNotMatch($('peerCoordinatorStatus').textContent,/primary administration address/);
 assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));f.dom.window.close();
 console.log('PASS full Magic browser: current-origin APIs, import, key enrollment, encrypted backup and connection wizard while primary host contact is blocked');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exitCode=1;});
