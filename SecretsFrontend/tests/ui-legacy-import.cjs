const assert=require('node:assert/strict');
const {fixture,tick}=require('./ui-native.cjs');
(async()=>{
 const f=await fixture();const $=f.$;
 try {
  $('login').click();await tick();await tick();
  f.dom.window.document.querySelector('[data-tab="nativeImport"]').click();await tick();
  assert.equal($('legacySource').value,'6000','Single ready source should be discovered automatically');
  assert.equal($('legacyScope').value,'local','Local-only must be the safe UI default');
  $('legacyPreview').click();await tick();
  assert.equal(f.calls.filter(r=>r.action==='legacyPreview').at(-1).data.scope,'local');
  assert.match($('legacyReview').textContent,/Local secrets only/);
  assert.match($('legacyReview').textContent,/Not imported · left unchanged/);
  assert.doesNotMatch($('legacyReview').textContent,/Conflicting paths: Existing/);
  assert.match($('legacyReview').textContent,/Global secrets and Global sharing state stay unchanged/);
  // Changing scope invalidates the reviewed candidate; it cannot silently broaden an approval.
  $('legacyScope').value='all';$('legacyScope').dispatchEvent(new f.dom.window.Event('change'));
  assert.equal($('legacyStep1').hidden,false);
  const prepared=f.calls.filter(r=>r.action==='prepare').length;
  $('legacyApprove').click();await tick();
  assert.equal(f.calls.filter(r=>r.action==='prepare').length,prepared);
  $('legacyPreview').click();await tick();
  assert.equal(f.calls.filter(r=>r.action==='legacyPreview').at(-1).data.scope,'all');
  assert.match($('legacyReview').textContent,/Global and Local secrets/);
  assert.match($('legacyReview').textContent,/Conflicting paths: Existing/);
  // Complete a freshly reviewed Local-only import and check accurate result text.
  $('legacyScope').value='local';$('legacyScope').dispatchEvent(new f.dom.window.Event('change'));
  $('legacyPreview').click();await tick();$('legacyApprove').click();await tick();
  assert.equal($('review').open,true);
  assert.deepEqual(f.calls.filter(r=>r.action==='prepare').at(-1).data.operation,{kind:'nativeLegacyImport',candidate:'legacy-candidate',digest:'legacy-digest'});
  f.setOutput({legacyImported:true,scope:'local',verified:true,backup:'{"encrypted":true}',recoveryKey:'LOCAL-IMPORT-RECOVERY'});
  $('approve').click();await tick();await tick();
  assert.equal($('legacyStep4').hidden,false);
  assert.match($('legacyResult').textContent,/Local secrets match the approved import\. Global secrets were left unchanged\./);
  assert.doesNotMatch($('legacyResult').textContent,/Global and local trees match/);
  assert.equal($('nativeSensitiveValue').value,'LOCAL-IMPORT-RECOVERY');
  $('nativeSensitiveClose').click();assert.equal($('nativeSensitiveValue').value,'');
  assert.equal(f.errors.length,0);
  console.log('PASS Local-only import UI: default, discovery, scoped preview, scope-change invalidation, full-import option, bound approval and result');
 } finally { f.dom.window.close(); }
})().catch(error=>{console.error(error);process.exitCode=1;});
