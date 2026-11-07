'use strict';
const assert=require('node:assert/strict');
const {fixture,tick}=require('./ui-native.cjs');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
(async()=>{
 const f=await fixture(),$=f.$;
 const ids=[...f.dom.window.document.querySelectorAll('[id]')].map(n=>n.id);assert.equal(new Set(ids).size,ids.length,'Duplicate control IDs interfere with existing workflows.');
 assert.equal($('compatFrozen').checked,true);assert.equal($('compatEnabled').checked,true);assert.equal($('compatRead').checked,true);assert.equal($('compatInstance'),null);assert.equal($('compatMode'),null);assert.equal($('compatTarget').value,'456');assert.equal($('compatWrite').checked,false);assert.equal($('compatBulk').checked,false);
 $('productionWrites').click();await tick();assert.equal($('review').open,true);
 assert.deepEqual(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation,{kind:'nativeLegacyAccess',instance:456,mode:2,enabled:true,read:true,write:true,portal:false,frozen:false,bulk:false});
 $('cancelReview').click();await tick();assert.equal($('compatFrozen').checked,true,'A production preview silently changed permissions.');
 $('compatPortal').checked=true;
 $('compatApprove').click();await tick();
 assert.deepEqual(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation,{kind:'nativeLegacyAccess',instance:456,mode:2,enabled:true,read:true,write:false,portal:true,frozen:true,bulk:false});
 assert.equal($('review').open,true);$('cancelReview').click();await tick();
 f.state.native.legacyDirectAccess={enabled:true,read:true,write:true,portal:false,frozen:false,bulk:false};$('refresh').click();await tick();await tick();assert.equal($('deploymentState').textContent,'Production system');assert.equal($('productionWrites').disabled,true);
 f.state.native.legacyAccess=[{instance:456,mode:1,enabled:false,read:false,write:false,portal:false,frozen:true,bulk:false}];f.state.native.legacyTargets=[{instance:456,mode:1,name:'This backend (local scripts)'},{instance:49800,mode:1,name:'Old <safe> manager'}];$('refresh').click();await tick();await tick();
 assert.equal($('compatEnabled').checked,false,'Rendering defaults restored an explicit revocation.');assert.equal($('compatRead').checked,false);assert.equal($('deploymentState').textContent,'Secrets system','Explicit revocation was hidden by a production label.');
 $('compatApprove').click();await tick();assert.equal(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation.mode,1,'Existing explicit role was changed.');$('cancelReview').click();await tick();
 $('compatTarget').value='49800';$('compatTarget').dispatchEvent(new f.dom.window.Event('change'));assert.equal($('compatEnabled').checked,false);assert.equal($('compatTarget').querySelector('safe'),null);
 $('compatEnabled').checked=true;$('compatApprove').click();await tick();assert.equal(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation.instance,49800);assert.equal(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation.mode,1);$('cancelReview').click();await tick();
 f.state.native.nativeOnlyReplacement=true;$('refresh').click();await tick();await tick();assert.equal($('nativeImportNav').hidden,false);assert.doesNotMatch($('legacyHistory').textContent,/disabled/);
 assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));f.dom.window.close();
 const page=fs.readFileSync(path.join(__dirname,'../page.html'),'utf8');const start=page.indexOf("let legacyReturn='';"),end=page.indexOf('\n',page.indexOf('function returnToLegacyPage'));const script=page.slice(start,end);
 for(const hash of ['#legacy-return=%2Fhook%2Flibrary','#legacy-return=https%3A%2F%2Fevil.test','#legacy-return=%2F%2Fevil.test','#legacy-return=%2Fhook%2Fsecrets_49800','#legacy-return=%2Fhook%2Flibrary%3Fx%3D1']){let target='';const ctx={URLSearchParams,location:{hash,replace:p=>{target=p;}},snapshot:{native:{fullAdministrator:true}}};vm.createContext(ctx);vm.runInContext(script+';returnToLegacyPage();',ctx);assert.equal(target,hash==='#legacy-return=%2Fhook%2Flibrary'?'/hook/library':'');}
 console.log('PASS legacy application browser controls: automatic backend selection, default reads, frozen writes, exact detected-instance approval and independent import wizard');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exitCode=1;});
