'use strict';
const assert=require('node:assert/strict');
const {fixture,tick}=require('./ui-native.cjs');
(async()=>{
 const f=await fixture(),$=f.$,d=f.dom.window.document;
 for(const nav of d.querySelectorAll('[data-tab]')){const panel=$(nav.dataset.tab),intro=panel.querySelector('.panelPurpose');assert(intro&&intro.textContent.trim().length>35,'Missing tab purpose: '+nav.textContent);}
 assert.equal($('setupNav').hidden,true,'First-time setup stayed in navigation for an initialized vault.');assert.equal($('firstTimeSetup').hidden,true);assert.equal($('bsStart').hidden,true);assert.match($('bsDoneTitle').textContent,/setup complete/);
 assert.equal($('nativeKeys').querySelector('h2').textContent,'Key enrollment');assert.equal($('nativeRecovery').querySelector('h2').textContent,'Encrypted backup');assert.match($('backup').querySelector('.panelPurpose').textContent,/settings.*Encrypted backup/);
 const before=f.calls.filter(c=>c.action==='bootstrapPrepare').length;$('accessRecoveryEnrollment').click();await tick();assert.equal($('setup').hidden,false);assert.equal($('setupTitle').textContent,'Administrator recovery');assert.match($('setupPurpose').textContent,/existing vault.*replacement passkey/);assert.match($('bsStartHelp').textContent,/Symcon console.*Hardware/);assert.equal(f.calls.filter(c=>c.action==='bootstrapPrepare').length,before,'Opening recovery created a passkey without console review.');
 $('logout').click();await tick();await tick();assert.equal($('firstTimeSetup').hidden,true,'Sign-out revived initial setup.');assert.equal($('nativeRecoveryEnrollment').hidden,false);$('nativeRecoveryEnrollment').click();await tick();assert.equal($('setupTitle').textContent,'Administrator recovery');assert.equal($('bsStart').hidden,false);assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));f.dom.window.close();
 console.log('PASS tab purpose and lifecycle: all tab introductions, first-time setup hidden after initialization/sign-out, existing-vault recovery accessible without automatic enrollment');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exitCode=1;});
