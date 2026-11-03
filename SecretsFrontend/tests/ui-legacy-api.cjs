'use strict';
const assert=require('node:assert/strict');
const {fixture,tick}=require('./ui-native.cjs');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
(async()=>{
 const f=await fixture(),$=f.$;
 const ids=[...f.dom.window.document.querySelectorAll('[id]')].map(n=>n.id);assert.equal(new Set(ids).size,ids.length,'Duplicate control IDs interfere with existing workflows.');
 assert.equal($('compatFrozen').checked,true);assert.equal($('compatEnabled').checked,false);assert.equal($('compatWrite').checked,false);assert.equal($('compatBulk').checked,false);
 $('compatInstance').value='49800';$('compatMode').value='1';$('compatEnabled').checked=true;$('compatPortal').checked=true;
 $('compatApprove').click();await tick();
 assert.deepEqual(f.calls.filter(c=>c.action==='prepare').at(-1).data.operation,{kind:'nativeLegacyAccess',instance:49800,mode:1,enabled:true,read:true,write:false,portal:true,frozen:true,bulk:false});
 assert.equal($('review').open,true);$('cancelReview').click();await tick();
 assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));f.dom.window.close();
 const page=fs.readFileSync(path.join(__dirname,'../page.html'),'utf8');const start=page.indexOf("let legacyReturn='';"),end=page.indexOf('\n',page.indexOf('function returnToLegacyPage'));const script=page.slice(start,end);
 for(const hash of ['#legacy-return=%2Fhook%2Flibrary','#legacy-return=https%3A%2F%2Fevil.test','#legacy-return=%2F%2Fevil.test','#legacy-return=%2Fhook%2Fsecrets_49800','#legacy-return=%2Fhook%2Flibrary%3Fx%3D1']){let target='';const ctx={URLSearchParams,location:{hash,replace:p=>{target=p;}},snapshot:{native:{fullAdministrator:true}}};vm.createContext(ctx);vm.runInContext(script+';returnToLegacyPage();',ctx);assert.equal(target,hash==='#legacy-return=%2Fhook%2Flibrary'?'/hook/library':'');}
 console.log('PASS legacy application browser controls: disabled default, frozen writes, exact instance/role/rights approval and independent import wizard');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exitCode=1;});
