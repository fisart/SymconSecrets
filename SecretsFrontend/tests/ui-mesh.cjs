'use strict';
const assert=require('node:assert/strict');
const {fixture,tick}=require('./ui-native.cjs');
(async()=>{
 const f=await fixture(),$=f.$,n=f.state.native;
 const names=['Production 121','Heartbeat','Test Hermitage','Hermitage','Standby'];
 const ids=names.map((_,i)=>'node-'+i),ok={state:'ok',age:0};
 const report=i=>({format:'SECB.MeshStatus.1',id:ids[i],name:names[i],components:{frontend:{...ok},backend:{...ok},vault:{...ok}},source:{...ok},fallback:false,activeSource:null,backupService:{...ok},conflicts:0,storagePercent:35,ttl:180,truncated:false,links:ids.filter(id=>id!==ids[i]).map(id=>({id,name:names[ids.indexOf(id)],paired:true,connection:'reachable',sync:'verified',age:0,ttl:180,primary:{...ok},backup:{...ok},consumes:true,grants:true,clientGrant:ids[i]+'-reads-'+id,grantIds:[id+'-reads-'+ids[i]]}))});
 n.mesh={localId:ids[0],observedAt:Math.floor(Date.now()/1000),reports:ids.map((_,i)=>({report:report(i),age:0,direct:true}))};
 n.peers=ids.slice(1).map((id,i)=>({id,name:names[i+1],active:true,state:'ACTIVE',globalMode:'shared-global-v1',pairingId:'pair-'+id,descriptor:{treeId:'tree-'+id,endpoint:'https://node'+i+'.example/hook/secrets_peer_22'}}));
 const update=async()=>{$('overviewRefresh').click();await tick();await tick();};await update();
 // Completed setup plus current green links must survive setup-contact expiry.
 n.globalConflictCount=0;n.outbox=[];
 for(const peer of n.peers)peer.health={connection:'reachable',synchronization:'verified',pendingMessages:0,problem:null,intervalSeconds:60};
 n.automaticSetup={policy:{id:'completed-plan'},running:false,completedAt:1794013666,report:{state:'complete'},members:[{ready:false,fresh:false,authorized:null}]};await update();
 assert.equal($('readiness').textContent,'Mesh setup completed. Vault ready.');
 n.automaticSetup.report={state:'idle',steps:[],errors:[]};await update();assert.equal($('readiness').textContent,'Mesh setup completed. Vault ready.');
 n.mesh.reports[1].age=181;await update();
 assert.match($('readiness').textContent,/^Mesh setup completed\. .*mesh check\(s\) unknown or stale/);
 assert.doesNotMatch($('readiness').textContent,/setup is running|synchronization in progress|setup is incomplete/i);
 assert.equal($('readiness').classList.contains('success'),false);
 n.mesh.reports[1].age=0;n.automaticSetup.running=true;await update();
 assert.match($('readiness').textContent,/Mesh setup is running/);assert.doesNotMatch($('readiness').textContent,/Mesh setup completed/);
 n.automaticSetup.running=false;n.automaticSetup.completedAt=null;n.automaticSetup.report.state='incomplete';await update();
 assert.match($('readiness').textContent,/Mesh setup is incomplete/);
 n.automaticSetup.completedAt=1794013666;n.automaticSetup.report.state='complete';await update();
 // Remote component age must include latency without reapplying a 90-second
 // local watchdog to a healthy cached report. Actual source faults stay visible.
 const oldReports=n.mesh.reports;
 n.mesh.reports=ids.map((_,i)=>{const r=report(i);r.ttl=900;for(const l of r.links){l.ttl=900;l.age=395;l.primary.age=395;l.backup.age=395;}for(const h of Object.values(r.components))h.age=20;return {report:r,age:395,direct:true};});await update();
 assert.equal($('meshMatrix').querySelectorAll('[data-state="unknown"]').length,0,'Normal remote sampling plus transit age raised yellow indicators.');
 assert.equal($('readiness').textContent,'Mesh setup completed. Vault ready.');
 assert.match($('meshMatrix').querySelector('.meshCell').title,/age warning after 15 min/);
 n.mesh.reports[1].report.components.frontend.state='error';await update();assert.match($('readiness').textContent,/Needs attention/,'Generous age window hid a component failure.');
 n.mesh.reports[1].report.components.frontend.state='unknown';await update();assert.match($('readiness').textContent,/unknown or stale/,'A source-reported local watchdog problem was turned green.');
 n.mesh.reports[1].report.components.frontend.state='ok';n.mesh.reports[1].age=901;await update();assert.equal($('readiness').classList.contains('success'),false,'Stopped remote reporting never expired.');
 for(const x of n.mesh.reports){x.report.ttl=1800;x.age=1300;for(const l of x.report.links){l.ttl=1800;l.age=10;l.primary.age=10;l.backup.age=10;}}await update();
 assert.equal($('readiness').classList.contains('success'),true,'Browser ignored the learned generous limit.');
 n.mesh.reports=oldReports;await update();
 assert.equal($('meshGraph').querySelectorAll('svg .meshNode').length,5);assert.equal($('meshGraph').querySelectorAll('.meshEdge').length,20);assert.equal($('meshMatrix').querySelectorAll('table').length,2);assert.equal($('meshMatrix').querySelectorAll('.meshCell').length,20);
 assert.match($('meshMatrixInfo').textContent,/5 known node/);assert.equal($('meshGraph').querySelectorAll('line[stroke-dasharray="7 5"]').length,20);
 const node=$('meshGraph').querySelector('.meshNode');
 const click=element=>element.dispatchEvent(new f.dom.window.MouseEvent('click',{bubbles:true}));
 click(node.querySelector('rect'));
 assert.equal($('meshDetailsDialog').open,true,'A node tap must open its populated details window');
 assert.equal($('meshDetailsTitle').textContent,'Connectivity details');
 assert.match($('meshDetailsText').textContent,/Production 121.*Frontend: ok.*Backend: ok.*Vault: ok/);
 assert.equal($('meshDetailsText').textContent,node.getAttribute('aria-label'));
 assert.equal(node.getAttribute('aria-haspopup'),'dialog');
 assert.equal(node.querySelector('title'),null,'Details must not depend on the SVG browser tooltip');
 $('meshDetailsClose').click();assert.equal($('meshDetailsDialog').open,false);
 for(const key of ['Enter',' ']){
  node.dispatchEvent(new f.dom.window.KeyboardEvent('keydown',{key,bubbles:true,cancelable:true}));
  assert.equal($('meshDetailsDialog').open,true,'Keyboard activation must show the same node details');
  $('meshDetailsClose').click();
 }
 click($('meshGraph').querySelector('.meshEdge').lastElementChild);
 assert.equal($('meshDetailsDialog').open,true);
 assert.match($('meshDetailsText').textContent,/Production 121 → Heartbeat/);
 const first=$('meshMatrix').querySelector('.meshCell');assert.equal(first.querySelector('[aria-label^="Exact emergency"]').dataset.state,'ok');first.click();assert.match($('meshCellDetail').textContent,/Production 121 → Heartbeat/);
 n.mesh.reports[1].report.components.frontend.state='error';n.mesh.reports[0].report.links[0].primary={state:'error',age:0,problem:'timeout',httpStatus:0,failedChecks:3};n.mesh.reports[0].report.fallback=true;n.mesh.reports[0].report.activeSource=ids[1];await update();
 assert.equal($('meshMatrix').querySelector('.meshCell .meshIndicator').dataset.state,'error');assert.equal($('meshMatrix').querySelectorAll('.meshCell .meshIndicator')[1].dataset.state,'ok');assert.match($('meshCellDetail').textContent,/Primary route: Error/);assert.match($('meshWarnings').textContent,/Production 121 → Heartbeat.*timed out.*3 consecutive/);assert.match($('meshMatrix').textContent,/Remote fallback/);assert.match($('readiness').textContent,/Needs attention.*mesh health/);
 assert.equal($('meshDetailsDialog').open,true,'Refreshing the chart must preserve the open details');
 assert.match($('meshDetailsText').textContent,/Primary route: Error.*timed out/);
 $('meshDetailsClose').click();
 n.mesh.reports[1].report.links.find(l=>l.id===ids[0]).grantIds=['different-grant'];await update();assert.equal($('meshMatrix').querySelector('.meshCell').lastElementChild.dataset.state,'error','A different active grant incorrectly approved this consumer.');
 $('meshFocus').value=ids[0];$('meshFocus').dispatchEvent(new f.dom.window.Event('change'));assert.equal($('meshGraph').querySelectorAll('.meshEdge').length,8);
 n.mesh.reports[0].report.links[1].backup={state:'none',age:null};await update();assert.equal([...$('meshMatrix').querySelectorAll('.meshCell')].find(b=>b.getAttribute('aria-label').startsWith('Production 121 → Test Hermitage.')).children[1].dataset.state,'none','Unconfigured backup was confused with failed or stale health.');
 // Every cached green ages out, including an open details panel.
 for(const r of n.mesh.reports)r.age=181;await update();assert.equal($('meshMatrix').querySelectorAll('[data-state="ok"]').length,0);assert.match($('meshCellDetail').textContent,/Unknown/);
 for(const r of n.mesh.reports)r.age=0;f.failOverview(true);await update();assert.equal($('meshMatrix').querySelectorAll('[data-state="ok"]').length,0);assert.match($('meshMatrixInfo').textContent,/stale/);f.failOverview(false);
 // Partial reports do not claim an absent edge or authorization is unconfigured.
 n.mesh.reports[0].report.truncated=true;n.mesh.reports[0].report.links=[];await update();assert.equal($('meshMatrix').querySelector('.meshCell').firstElementChild.dataset.state,'unknown');assert.match($('meshMatrixInfo').textContent,/omitted/);
 n.mesh.reports[1].report.name='<img src=x onerror=alert(1)>';await update();assert.equal($('meshGraph').querySelector('img'),null);assert.equal($('meshMatrix').querySelector('img'),null);
 click([...$('meshGraph').querySelectorAll('.meshNode')].find(node=>node.getAttribute('aria-label').startsWith('<img')));
 assert.equal($('meshDetailsDialog').querySelector('img'),null);
 assert.match($('meshDetailsText').textContent,/<img src=x onerror=alert\(1\)>/);
 // Keep a representative graphical fixture for optional local visual inspection.
 if(process.env.MESH_PREVIEW){n.mesh.reports=ids.map((_,i)=>({report:report(i),age:0,direct:true}));n.mesh.reports[1].report.components.frontend.state='error';n.mesh.reports[0].report.links[0].primary.state='error';n.mesh.reports[0].report.fallback=true;$('meshFocus').value='all';await update();const copy=f.dom.window.document.documentElement.cloneNode(true);for(const script of copy.querySelectorAll('script'))script.remove();require('node:fs').writeFileSync(process.env.MESH_PREVIEW,'<!doctype html>'+copy.outerHTML);}
 n.mesh.reports=[{report:report(0),age:0,direct:true}];n.mesh.reports[0].report.links=[];n.peers=[];await update();assert.equal($('meshGraph').querySelectorAll('.meshNode').length,1);assert.equal($('meshGraph').querySelectorAll('.meshEdge').length,0);assert.match($('meshMatrixInfo').textContent,/1 known node/);
 assert.equal($('meshDetailsDialog').open,false,'Removing a selected node must close its details');
 click($('meshGraph').querySelector('.meshNode'));
 assert.match($('meshDetailsText').textContent,/Production 121/);
 delete n.mesh;await update();
 assert.equal($('meshDetailsDialog').open,false,'Unavailable mesh data must close the details window');
 assert.equal($('meshDetailsText').textContent,'');
 assert.equal(f.calls.filter(c=>['prepare','approve','authOptions'].includes(c.action)).length,0);assert.equal(f.errors.length,0,f.errors.map(e=>e.message).join('\n'));f.dom.window.close();
 // Larger meshes automatically focus one installation instead of drawing every edge.
 for(let i=5;i<9;i++){ids.push('node-'+i);names.push('Installation '+i);}
 const large=await fixture();large.state.native.mesh={localId:ids[0],reports:ids.map((_,i)=>({report:report(i),age:0,direct:true}))};large.$('overviewRefresh').click();await tick();await tick();assert.equal(large.$('meshFocus').value,ids[0]);assert.equal(large.$('meshGraph').querySelectorAll('.meshNode').length,9);assert.equal(large.$('meshGraph').querySelectorAll('.meshEdge').length,16);assert.equal(large.errors.length,0);large.dom.window.close();
 console.log('PASS graphical mesh: five nodes, primary/backup separation, exact directional grants, focus, live detail, stale failure, partial reports, safe labels and standalone');
})().catch(e=>{process.stderr.write(e.stack+'\n');process.exitCode=1;});
