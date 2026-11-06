function fullAdministration(){return snapshot?.native?.fullAdministrator===true||boot.origin===(snapshot?.native?.primaryOrigin||boot.origin);}
'use strict';
let nativeSensitiveTimer=null,nativeProviderId='';
function nativeClearSecrets(){clearTimeout(nativeSensitiveTimer);for(const id of ['nativeSensitiveValue','nativeInvitation','nativeRecoveryKey'])if($(id))$(id).value='';for(const id of ['nativeSensitiveDialog'])if($(id)?.open)$(id).close();}
function nativeRelogin(text){invalidate();csrf='';snapshot=null;selected=null;clearSecrets();$('login').hidden=false;$('logout').hidden=true;$('signin').disabled=false;tab('overview');message(text);}
function nativeShowSecret(title,help,value,seconds=60){nativeClearSecrets();$('nativeSensitiveTitle').textContent=title;$('nativeSensitiveHelp').textContent=help;$('nativeSensitiveValue').value=value;$('nativeSensitiveDialog').showModal();nativeSensitiveTimer=setTimeout(nativeClearSecrets,seconds*1000);}
async function nativeCopy(id){const node=$(id);if(navigator.clipboard?.writeText)await navigator.clipboard.writeText(node.value);else{node.focus();node.select();message('Text selected. Use your browser’s Copy command.');}}
function nativeRow(parent,title,detail,actions=[]){const card=document.createElement('div');card.className='card';const h=document.createElement('h4');h.textContent=title;const p=document.createElement('p');p.className='muted break';p.textContent=detail;card.append(h,p);const row=document.createElement('div');row.className='row';for(const [label,callback]of actions){const button=document.createElement('button');button.type='button';button.textContent=label;run(button,callback);row.append(button);}card.append(row);parent.append(card);}
function nativeSelect(id,items){const select=$(id),old=select.value;select.replaceChildren();for(const [value,label]of items){const option=document.createElement('option');option.value=value;option.textContent=label;select.append(option);}if(items.some(x=>x[0]===old))select.value=old;}
function nativeEntries(){const scope=$('scope').value;if(scope.startsWith('owned:'))return snapshot?.native?.ownedTrees.find(t=>t.id===scope.slice(6))?.entries||[];if(scope.startsWith('received:'))return snapshot?.native?.received.find(t=>t.id===scope.slice(9))?.entries||[];return snapshot?.[scope]||[];}
function nativeOperationForSelection(kind,extra={}){const scope=$('scope').value,path=JSON.parse($('path').value);if(!Array.isArray(path)||(!path.length&&kind!=='reveal'))throw Error('Choose an exact non-root JSON path.');if(scope.startsWith('received:')||scope.startsWith('owned:')){const owned=scope.startsWith('owned:'),treeId=scope.slice(owned?6:9),tree=(owned?snapshot.native.ownedTrees:snapshot.native.received).find(t=>t.id===treeId);if(!tree)throw Error('The selected shared tree is unavailable.');if(kind==='reveal')return{kind:'nativeReveal',treeId,path,revision:tree.revision};if(!owned||tree.frozen)throw Error('This is a read-only or frozen received tree.');return{kind:kind==='save'?'nativeSharedSave':kind==='rename'?'nativeSharedRename':'nativeSharedDelete',treeId,path,revision:tree.revision,...extra};}return{kind,...target(kind==='reveal'),...extra};}
function nativeSelectionChanged(){if($('globalScopeStatus'))$('globalScopeStatus').hidden=$('scope').value!=='global';const scope=$('scope').value,n=snapshot?.native;const readonly=scope.startsWith('received:')||(scope==='global'&&n&&!n.globalWritable)||(scope.startsWith('owned:')&&n?.ownedTrees.find(t=>t.id===scope.slice(6))?.frozen);$('save').disabled=!!readonly;$('delete').disabled=!!readonly||!selected?.path?.length;if(n){$('nativeMachineScope').value=scope;$('nativeMachinePath').value=$('path').value;}}
function nativeSuggestProvider(){if(!$('nativeProviderURL').value&&!nativeProviderId){const entries=[];for(const scope of ['local','global'])for(const entry of snapshot[scope]||[])entries.push({scope,path:entry.path,type:entry.type});const find=names=>entries.filter(x=>x.type==='string'&&names.includes(String(x.path.at(-1)).replace(/[^a-z]/gi,'').toLowerCase()));const refresh=find(['refreshtoken']),secret=find(['clientsecret']);if(refresh.length===1){$('nativeProviderRefreshScope').value=refresh[0].scope;$('nativeProviderRefreshPath').value=JSON.stringify(refresh[0].path);$('nativeProviderResultScope').value=refresh[0].scope;$('nativeProviderResultPath').value=JSON.stringify(refresh[0].path.slice(0,-1));}if(secret.length===1){$('nativeProviderSecretScope').value=secret[0].scope;$('nativeProviderSecretPath').value=JSON.stringify(secret[0].path);}}}
let overviewBusy=false,overviewStale=false;
let meshAttention=0,meshPending=0,meshFallback=0,meshReceivedAt=0,meshSelected=null,meshFocusSelected=false,meshDescriptions=new Map();
function renderMeshDetails(){
 const description=meshDescriptions.get(meshSelected)||'',detail=$('meshCellDetail'),dialog=$('meshDetailsDialog');
 detail.hidden=!description;
 detail.textContent=description;
 $('meshDetailsText').textContent=description;
 if(!description&&dialog.open)dialog.close();
}
function showMeshDetails(selection){
 meshSelected=selection;
 renderMeshDetails();
 const dialog=$('meshDetailsDialog');
 if($('meshDetailsText').textContent&&!dialog.open)dialog.showModal();
}
$('meshDetailsClose').addEventListener('click',()=>$('meshDetailsDialog').close());
function renderMeshGraph(nodes,reports,item,fresh,cells,localId){
 const host=$('meshGraph');host.replaceChildren();const selector=$('meshFocus'),previous=selector.value;selector.replaceChildren();
 for(const [value,label]of [['all','All connections'],...nodes.map(n=>[n.id,n.name])]){const o=document.createElement('option');o.value=value;o.textContent=label;selector.append(o);}selector.value=!meshFocusSelected&&nodes.length>8?localId:[...selector.options].some(o=>o.value===previous)?previous:(nodes.length>8?localId:'all');
 const focus=selector.value,ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg');
 const cols=Math.min(4,nodes.length),width=nodes.length<=8?900:Math.max(700,cols*230),height=nodes.length<=1?230:nodes.length<=8?760:Math.ceil(nodes.length/cols)*170+70;
 svg.setAttribute('viewBox',`0 0 ${width} ${height}`);svg.setAttribute('role','group');svg.setAttribute('aria-label','Interactive secrets mesh health diagram');svg.style.minWidth=nodes.length===1?'280px':'700px';
 const make=(tag,attrs={},text)=>{const e=document.createElementNS(ns,tag);for(const [k,v]of Object.entries(attrs))e.setAttribute(k,String(v));if(text!==undefined)e.textContent=text;return e;};
 const colors={ok:'#18864b',error:'#d44035',unknown:'#d99500',none:'#8b929c'},positions=new Map();
 nodes.forEach((n,i)=>{const angle=-Math.PI/2+2*Math.PI*i/nodes.length;positions.set(n.id,nodes.length===1?[width/2,110]:nodes.length<=8?[width/2+300*Math.cos(angle),height/2+275*Math.sin(angle)]:[120+(i%cols)*230,100+Math.floor(i/cols)*170]);});
 const interactive=(element,label,selection)=>{
  element.setAttribute('tabindex','0');element.setAttribute('role','button');element.setAttribute('aria-label',label);
  element.setAttribute('aria-haspopup','dialog');element.setAttribute('aria-controls','meshDetailsDialog');
  meshDescriptions.set(selection,label);
  element.addEventListener('click',()=>showMeshDetails(selection));
  element.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();showMeshDetails(selection);}});
 };
 for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){
  const a=nodes[i],b=nodes[j];if(focus!=='all'&&a.id!==focus&&b.id!==focus)continue;
  const ab=cells.get(a.id+'|'+b.id),ba=cells.get(b.id+'|'+a.id);if(!ab?.paired&&!ba?.paired)continue;
  const [x1,y1]=positions.get(a.id),[x2,y2]=positions.get(b.id),dx=x2-x1,dy=y2-y1,len=Math.hypot(dx,dy),ux=dx/len,uy=dy/len;
  for(const [cell,reverse]of [[ab,false],[ba,true]]){if(!cell)continue;const g=make('g',{'class':'meshEdge'});interactive(g,cell.description,'cell|'+cell.key);
   for(const [index,offset,dashed]of [[0,-5,false],[1,5,true]]){const state=cell.observations[index][1];if(state==='none')continue;const start=reverse?0.5:0,end=reverse?1:0.5;const line=make('line',{x1:x1+dx*start-uy*offset,y1:y1+dy*start+ux*offset,x2:x1+dx*end-uy*offset,y2:y1+dy*end+ux*offset,stroke:colors[state],'stroke-width':3,'stroke-dasharray':dashed?'7 5':'none'});g.append(line);}
   // Directional authorization badge: the arrow names the consuming row's target.
   const t=reverse?.64:.36,cx=x1+dx*t,cy=y1+dy*t,sign=reverse?-1:1,state=cell.observations[3][1];g.append(make('circle',{cx,cy,r:12,fill:colors[state],stroke:'white','stroke-width':2}),make('text',{x:cx,y:cy+4,'text-anchor':'middle',fill:'white','font-size':11,'font-weight':700},'A'));
   const ax=cx+ux*sign*18,ay=cy+uy*sign*18;g.append(make('path',{d:`M ${ax-ux*sign*6-uy*4} ${ay-uy*sign*6+ux*4} L ${ax} ${ay} L ${ax-ux*sign*6+uy*4} ${ay-uy*sign*6-ux*4}`,fill:'none',stroke:colors[state],'stroke-width':2}));svg.append(g);
  }
 }
 for(const n of nodes){const [x,y]=positions.get(n.id),r=reports.get(n.id),g=make('g',{'class':'meshNode'}),current=fresh(r);const summary=[];
  g.append(make('rect',{x:x-100,y:y-67,width:200,height:134,rx:13,'class':'meshNodeBox',stroke:n.id===localId?'#1d6490':'#a8b4c2','stroke-width':n.id===localId?3:1.5}));
  const name=n.name.length>26?n.name.slice(0,24)+'…':n.name;g.append(make('text',{x,y:y-43,'text-anchor':'middle','class':'meshNodeName'},name),make('text',{x,y:y-26,'text-anchor':'middle','class':'meshNodeMeta'},current&&r.report.fallback?'Remote fallback active':n.id===localId?'This installation':!n.direct?'Indirect · status unknown':current?'Authenticated peer report':r?'Report stale':'No report yet'));
  const values=[['Frontend','frontend'],['Backend','backend'],['Vault','vault'],['Source','source'],['Backup','backupService'],['Sync','sync']];
  const syncState=!current?'unknown':r.report.links.some(l=>l.sync==='mismatch')?'error':r.report.truncated||r.report.links.some(l=>l.sync!=='verified'||l.connection!=='reachable'||!Number.isFinite(l.age)||l.age+r.age+(meshReceivedAt?(Date.now()-meshReceivedAt)/1000:0)>=l.ttl)?'unknown':'ok';
  values.forEach(([label,key],i)=>{const v=['source','backupService'].includes(key)?r?.report[key]:r?.report.components?.[key],h=key==='sync'?{state:syncState}:item(r,v),cx=x-82+(i%3)*65,cy=y-5+Math.floor(i/3)*24;g.append(make('circle',{cx,cy,r:5,fill:colors[h.state]}),make('text',{x:cx+9,y:cy+4,'class':'meshNodeLabel'},label));summary.push(label+': '+h.state+(key==='source'&&current&&r.report.fallback?' (remote fallback from '+(nodes.find(n=>n.id===r.report.activeSource)?.name||'approved peer')+')':''));});
  const extra=current?`${r.report.conflicts} conflict(s) · ${r.report.storagePercent===null?'?':r.report.storagePercent}% storage`:'Waiting for a fresh report';g.append(make('text',{x,y:y+49,'text-anchor':'middle','class':'meshNodeMeta'+(current&&(r.report.conflicts>0||r.report.storagePercent>=90)?' meshNodeFault':current&&r.report.storagePercent>=75?' meshNodeWarning':'')},extra));
  interactive(g,n.name+'. '+summary.join('. ')+'. '+extra+'. '+(r&&Number.isFinite(r.age)?'Report '+Math.floor(r.age+(meshReceivedAt?(Date.now()-meshReceivedAt)/1000:0))+'s old.':'No authenticated report.'),'node|'+n.id);svg.append(g);
 }
 host.append(svg);
}

function renderMeshMatrix(){
 const host=$('meshMatrix');if(!host)return;host.replaceChildren();$('meshWarnings').replaceChildren();$('meshWarnings').hidden=true;meshDescriptions=new Map();meshAttention=0;meshPending=0;meshFallback=0;const n=snapshot?.native,m=n?.mesh;
 const info=$('meshMatrixInfo');if(!m){$('meshGraph').replaceChildren();meshSelected=null;renderMeshDetails();meshFocusSelected=false;info.textContent='Mesh reports are not available yet. Update each installation; unknown health is never treated as healthy.';return;}
 const elapsed=meshReceivedAt?Math.max(0,(Date.now()-meshReceivedAt)/1000):0,invalid=overviewStale||!meshReceivedAt||Date.now()<meshReceivedAt;
 const rows=new Map([[m.localId,{id:m.localId,name:'This installation',direct:true}]]),reports=new Map();
 for(const x of m.reports||[]){reports.set(x.report.id,x);rows.set(x.report.id,{id:x.report.id,name:x.report.name,direct:true});}
 for(const p of n.peers||[])if(p.state!=='REVOKED')rows.set(p.id,{id:p.id,name:reports.get(p.id)?.report.name||p.name,direct:true});
 for(const x of m.reports||[])for(const l of x.report.links||[])if(!rows.has(l.id)&&rows.size<64)rows.set(l.id,{id:l.id,name:l.name,direct:false});
 const nodes=[...rows.values()].sort((a,b)=>a.id===m.localId?-1:b.id===m.localId?1:a.name.localeCompare(b.name));
 const fresh=x=>!!x&&!invalid&&Number.isFinite(x.age)&&x.age>=0&&x.age+elapsed<x.report.ttl;
 const age=(x,v)=>x&&Number.isFinite(x.age)&&Number.isFinite(v?.age)?Math.floor(x.age+elapsed+v.age):null;
 const item=(x,v,ttl=90)=>{const a=age(x,v);return {state:!fresh(x)?'unknown':v?.state==='none'?'none':a===null||a>=ttl?'unknown':v?.state||'unknown',age:a};};
 const words={ok:'Healthy',error:'Error',unknown:'Unknown / stale',none:'Not configured'};
 const dot=(state,label,detail='')=>{const span=document.createElement('span');span.className='meshIndicator';span.dataset.state=state;const ball=document.createElement('span');ball.className='meshDot';ball.setAttribute('aria-hidden','true');const text=document.createElement('span');text.textContent=label;span.append(ball,text);span.title=(detail||label+': '+words[state]);span.setAttribute('aria-label',span.title);return span;};
 const checked=a=>a===null?'No current check':a+'s since check';
 const routeReason=v=>{if(!v?.problem)return v?.state==='error'?' Detailed reason unavailable; update the reporting installation.':'';const labels={dns:'DNS lookup failed',connect:'Connection failed',timeout:'Request timed out',certificate:'HTTPS certificate verification failed',tls:'TLS handshake failed',http:'HTTP request refused', 'response-size':'Response exceeded its size limit','invalid-reply':'Reply could not be authenticated or validated',transport:'HTTPS transport unavailable',unconfirmed:'Delivery unconfirmed'};return ' '+(labels[v.problem]||'Check failed')+(v.httpStatus?' (HTTP '+v.httpStatus+')':'')+(v.certificateReason&&v.certificateReason!=='unknown'?' · '+v.certificateReason:'')+(v.failedChecks?' · '+v.failedChecks+' consecutive failure(s)':'')+'.';};

 const table=(caption,heads)=>{const wrap=document.createElement('div');wrap.className='meshScroll';wrap.tabIndex=0;wrap.setAttribute('aria-label',caption+'; scroll horizontally for more nodes');const t=document.createElement('table');t.className='meshTable';const c=document.createElement('caption');c.textContent=caption;t.append(c);const head=document.createElement('thead'),tr=document.createElement('tr');for(const h of heads){const th=document.createElement('th');th.scope='col';th.textContent=h;th.title=h;tr.append(th);}head.append(tr);const body=document.createElement('tbody');t.append(head,body);wrap.append(t);host.append(wrap);return body;};
 const rowName=(tr,node)=>{const th=document.createElement('th');th.scope='row';th.textContent=node.name+(node.id===m.localId?' (here)':'');th.title=node.name+' · '+node.id+(node.direct?'':' · reported node; no direct pairing');tr.append(th);};
 const health=table('Node health',['Installation','Frontend','Backend','Vault','Secret source','Backup service','Conflicts','Storage','Report age']);let problems=0;
 for(const node of nodes){const x=reports.get(node.id),tr=document.createElement('tr');rowName(tr,node);
  for(const key of ['frontend','backend','vault','source','backupService']){const v=key==='source'?x?.report.source:key==='backupService'?x?.report.backupService:x?.report.components?.[key],h=item(x,v),td=document.createElement('td');if(h.state==='error')problems++;if(h.state==='unknown')meshPending++;const label=key==='source'&&fresh(x)&&x.report.fallback?'Remote fallback':words[h.state];td.append(dot(h.state,label,node.name+' · '+key+': '+label+'. '+checked(h.age)+(node.id!==m.localId?'. Reported by this node.':'')));tr.append(td);}
  if(fresh(x)&&x.report.fallback)meshFallback++;
  const current=fresh(x),conflicts=current?x.report.conflicts:null,storage=current?x.report.storagePercent:null;
  for(const [state,label]of [[conflicts===null?'unknown':conflicts?'error':'ok',conflicts===null?'Unknown':String(conflicts)],[storage===null?'unknown':storage>=90?'error':storage>=75?'unknown':'ok',storage===null?'Unknown':storage+'%']]){const td=document.createElement('td');td.append(dot(state,label));tr.append(td);if(state==='error')problems++;}
  const last=document.createElement('td');last.textContent=x&&Number.isFinite(x.age)?Math.floor(x.age+elapsed)+'s'+(current?'':' · stale'):'No report';tr.append(last);health.append(tr);
 }
 const cells=new Map();
 const body=table('Connections and emergency read authorizations',['From ↓ / To →',...nodes.map(n=>n.name)]);
 const detail=$('meshCellDetail');
 for(const from of nodes){const tr=document.createElement('tr');rowName(tr,from);const x=reports.get(from.id);
  for(const to of nodes){const td=document.createElement('td');if(from.id===to.id){td.textContent='—';td.className='meshSelf';tr.append(td);continue;}
   const y=reports.get(to.id),l=x?.report.links?.find(l=>l.id===to.id),reverse=y?.report.links?.find(l=>l.id===from.id),live=fresh(x),other=fresh(y);
   const primary=item(x,l?.primary,x?.report.ttl||180),backup=item(x,l?.backup,x?.report.ttl||180);
   if(live&&!l&&!x.report.truncated){primary.state='none';backup.state='none';}
   const a=age(x,l);const sync=live&&!l&&!x.report.truncated?'none':!live||!l||a===null||a>=l.ttl?'unknown':l.sync==='mismatch'||l.connection==='unreachable'?'error':l.sync==='verified'&&l.connection==='reachable'?'ok':'unknown';
   let auth='unknown',authText='Authorization cannot be confirmed from fresh reports.';
   if(live&&other&&(!x.report.truncated||l)&&(!y.report.truncated||reverse)){const enabled=l?.consumes&&l.clientGrant;const granted=enabled&&reverse?.grants&&reverse.grantIds?.includes(l.clientGrant);auth=enabled&&granted?'ok':enabled?'error':!reverse?.grants?'none':'unknown';authText=auth==='ok'?'Exact emergency read grant approved on both installations.':auth==='none'?'Emergency reads are not configured in this direction.':auth==='error'?'The consuming installation’s exact grant is no longer approved by the provider.':'Only the provider is configured. Accept its offer on the consuming installation.';}
   const observations=[['P',primary.state,'Primary route: '+words[primary.state]+'. '+checked(primary.age)+routeReason(l?.primary)],['B',backup.state,'Backup route: '+words[backup.state]+'. '+checked(backup.age)+routeReason(l?.backup)],['S',sync,'Global synchronization: '+(live&&l?l.sync:'unknown')+'. '+checked(a)],['A',auth,authText]];
   for(const o of observations){if(o[1]==='error'){const li=document.createElement('li');li.textContent=from.name+' → '+to.name+': '+o[2];$('meshWarnings').append(li);$('meshWarnings').hidden=false;}if(o[1]==='error')problems++;if(o[1]==='unknown')meshPending++;}
   const button=document.createElement('button');button.type='button';button.className='meshCell';const description=from.name+' → '+to.name+'. '+observations.map(o=>o[2]).join(' ')+(from.id!==m.localId?' Observations reported by '+from.name+'.':' Observed on this installation.');cells.set(from.id+'|'+to.id,{key:from.id+'|'+to.id,observations,description,paired:!!l?.paired});button.title=description;button.setAttribute('aria-label',description);
   for(const [label,state,text]of observations)button.append(dot(state,label,text));meshDescriptions.set('cell|'+from.id+'|'+to.id,description);button.addEventListener('click',()=>{meshSelected='cell|'+from.id+'|'+to.id;detail.hidden=false;detail.textContent=description;});td.append(button);tr.append(td);
  }body.append(tr);
 }
 renderMeshGraph(nodes,reports,item,fresh,cells,m.localId);
 renderMeshDetails();
 meshAttention=problems;
 info.textContent=(m.unavailable?'Mesh diagnostics are temporarily unavailable. ':'')+(invalid?'Refresh failed or page data is stale. ':'')+nodes.length+' known node(s). '+(problems?problems+' health warning(s). ':'')+'Rows show the observing installation; A means the row may read Global secrets from the column. Reports are authenticated observations, not proof of current availability. '+(nodes.some(n=>!n.direct)?'Indirect nodes remain unknown until directly paired. ':'')+([...reports.values()].some(x=>x.report.truncated)?'Some remote detail is omitted to protect journal capacity; missing details remain unknown. ':'')+(rows.size>=64?'Display limited to 64 known nodes. ':'');
}

function renderNativeOverview(){
 renderMailbox();
 if(snapshot?.native&&$('nativeEmergencyPanel'))renderEmergencyAccess();
 renderMeshMatrix();
 const n=snapshot?.native,show=!!n;$('nativeOverview').hidden=!show;$('overviewRefresh').hidden=!show;
 if(!show){$('readiness').classList.remove('success');for(const id of ['globalCount','localCount','overviewConnections','overviewConnectionDetail','overviewMagic','overviewMagicDetail','overviewMagicURL','overviewConflicts','overviewConflictDetail','overviewStorage','overviewStorageDetail','overviewAccess','overviewEffects','overviewChecked'])$(id).textContent='';$('overviewPeerList').replaceChildren();return;}
 const o=n.overview||{},peers=(n.peers||[]).filter(p=>p.state!=='REVOKED'),active=peers.filter(p=>p.active&&p.state==='ACTIVE'),pending=peers.filter(p=>!p.active||p.state!=='ACTIVE');
 const blocked=peers.filter(peerDeliveryBlocked),expired=pending.filter(peerExpired),ready=active.filter(p=>p.health?p.health.synchronization==='verified':peerSharingProgress(p).ready),conflicts=Number(n.globalConflictCount??n.sharedGlobal?.conflicts?.length??0);
 const count=entries=>(entries||[]).filter(e=>!['object','array'].includes(e.type)).length;
 $('globalCount').textContent=o.globalValues??count(snapshot.global);$('localCount').textContent=o.localValues??count(snapshot.local);
 $('overviewConnections').textContent=String(active.length);
 $('overviewConnectionDetail').textContent=peers.length?[ready.length+' synchronized',...(active.length>ready.length?[active.length-ready.length+' awaiting data or delivery']:[]),...(pending.length?[pending.length+' awaiting approval']:[]),...(blocked.length?[blocked.length+' delivery blocked']:[]),...(expired.length?[expired.length+' expired']:[])].join(' · '):'Standalone · no connected platforms.';
 const p=n.backupOrigin,magicActive=p?.status==='active',magicMissing=magicActive&&o.magicCredentials===0,relayProblem=magicActive&&/^https:\/\/[a-z0-9]{32}\.ipmagic\.de$/.test(p.origin)&&n.connectDiscovery&&(n.connectDiscovery.available!==true||n.connectDiscovery.origin!==p.origin),routePending=magicActive&&p.version===2?active.filter(peer=>peer.routeReceipt!==(n.routeRevision||'0')).length:0;
 $('overviewMagic').textContent=relayProblem?(n.connectDiscovery.available?'Address changed':'Connect unavailable'):magicMissing?'No usable passkey':magicActive?p.version===2?'Full access active':'Limited access active':p?.status==='pending'?'Setup incomplete':p?.status==='revoked'?'Removed':'Not configured';
 $('overviewMagicDetail').textContent=relayProblem?'Access is configured, but the local Connect service does not report this address as active. Check Symcon Connect and review the address in Key enrollment.':magicMissing?'Enroll and test an eligible Magic passkey in Key enrollment.':magicActive?(p.version===2?'Same vault and administration functions.':'Approve full Magic access in Key enrollment or the Symcon console.')+(active.length&&p.version===2?' Address delivery: '+(active.length-routePending)+' of '+active.length+' platforms.':''):(p?.status==='pending'?'Finish the numbered setup in Key enrollment.':'Set up a second HTTPS address in Key enrollment.');
 $('overviewMagicURL').textContent=magicActive?new URL(boot.path,p.origin).href:'';
 $('overviewConflicts').textContent=String(conflicts);$('overviewConflictDetail').textContent=conflicts?'Resolve these secrets in Conflicts. Other secrets remain available.':'No unresolved conflicts.';
 const storage=o.storage||n.info,percent=storage.capacityBytes>0?Math.ceil(storage.usedBytes/storage.capacityBytes*100):null;
 $('overviewStorage').textContent=percent===null?'Unavailable':percent+'% used';$('overviewStorageDetail').textContent=percent===null?'Refresh to check storage.':Math.ceil(storage.usedBytes/1024)+' of '+Math.floor(storage.capacityBytes/1024)+' KiB'+(percent>=75?' · Export and verify an encrypted backup, then review storage.':'.');
 $('overviewAccess').textContent=(o.credentials??snapshot.credentials.filter(c=>c.active).length)+' tested passkey(s) · '+(o.hardwareCredentials??snapshot.credentials.filter(c=>c.active&&c.hardware).length)+' hardware · '+(o.machines??n.machines?.filter(m=>m.active).length??0)+' automation grant(s) · '+(o.providers??n.providers?.filter(p=>p.active).length??0)+' OAuth provider(s).';
 $('overviewEffects').textContent=o.providerIssues?o.providerIssues+' OAuth provider(s) need review in OAuth providers.':o.pendingEffects?o.pendingEffects+' OAuth operation(s) in progress.':'';
 const healthProblems=active.filter(p=>p.health&&(p.health.problem||['unreachable','retrying'].includes(p.health.connection)||p.health.synchronization==='mismatch'));
 const issues=[...(meshAttention?[meshAttention+' mesh health issue(s)']:[]),...(meshFallback?[meshFallback+' installation(s) using emergency fallback']:[]),...(healthProblems.length?[healthProblems.length+' platform(s) need synchronization attention — see Connection status below']:[]),...(blocked.length?['delivery blocked']:[]),...(expired.length?['expired connection approval']:[]),...(conflicts?['secret conflicts']:[]),...(relayProblem?['Magic connection unavailable']:[]),...(magicMissing?['Magic passkey unavailable']:[]),...(percent>=75?['storage nearing capacity']:[]),...(n.globalWritable===false?['Global changes paused']:[]),...(o.providerIssues?['OAuth providers need review']:[]),...(active.length&&n.remoteHttpsAvailable===false?['connection transport unavailable']:[])];
 const inProgress=meshPending||o.pendingEffects||pending.length||active.length>ready.length||p?.status==='pending'||routePending;
 $('readiness').textContent=overviewStale?'Status could not be refreshed. These figures may be out of date. Sign in again or select Refresh status.':issues.length?'Needs attention · '+issues.join(' · ')+'.':inProgress?'Setup or synchronization in progress.':'Vault ready.';
 $('readiness').classList.toggle('success',!overviewStale&&!issues.length&&!inProgress);
 $('overviewChecked').textContent=(n.serverTime?'Last checked '+new Date(n.serverTime*1000).toLocaleString()+'. ':'')+'Updates every 10 seconds while this tab is open. Synchronization is checked in the background every '+(active.find(p=>p.health)?.health.intervalSeconds||60)+' seconds, even with this page closed.';
 const list=$('overviewPeerList');list.replaceChildren();if(!peers.length)list.textContent='No connections yet. This vault works independently.';
 for(const peer of peers){const row=document.createElement('div');row.className='overviewPeer';const name=document.createElement('strong');name.textContent=peer.name;const status=document.createElement('p');status.textContent=peerConnectionLabel(peer);if(peer.health){status.className='healthStatus';status.dataset.state=overviewStale?'unknown':peer.health.synchronization;}if(peerDeliveryBlocked(peer)||peerExpired(peer)||healthProblems.includes(peer))status.classList.add('overviewWarning');const last=document.createElement('p');last.className='muted';last.textContent=peer.health?peerHealthDetail(peer):'Last received: '+(peer.lastSync||'not yet');const button=document.createElement('button');button.type='button';button.textContent='Connection status';run(button,()=>{tab('nativePeers');peerWizardResume(peer.id);});row.append(name,status,last,button);list.append(row);}
}
async function refreshNativeOverview(ticket=generation){
 if(overviewBusy||mailboxApprovalBusy||automaticSetupBusy||supportBusy||!snapshot?.native||document.hidden||!pageActive||$('review').open||ceremonyActive)return;overviewBusy=true;
 try{const r=await api('nativeOverviewStatus',{},ticket);if(!r.overview||!Array.isArray(r.peers))throw Error('Update this module and refresh.');Object.assign(snapshot.native,r);meshReceivedAt=Date.now();overviewStale=false;renderNativeOverview();if(!$('nativePeers').hidden){renderPeerConnections();renderPeerWizard();}}
 catch(error){if(ticket===generation&&snapshot?.native&&error.name!=='AbortError'){overviewStale=true;renderNativeOverview();$('readiness').textContent+=' '+error.message;if(!$('nativePeers').hidden){renderPeerConnections();$('nativeDeliveryInfo').textContent='Status could not be refreshed. Last shown checks may be out of date. '+error.message;}}}
 finally{overviewBusy=false;}
}
$('meshFocus').addEventListener('change',()=>{meshFocusSelected=true;renderMeshMatrix();});
run($('overviewRefresh'),ticket=>refreshNativeOverview(ticket));
let compatViewKey='';
function legacyAccessTargets(){
 const n=snapshot?.native,backend=Number(n?.peerDescriptor?.backend);if(!Number.isSafeInteger(backend)||backend<=0)return [];
 const mode=(n.legacyAccess??[]).find(p=>p.instance===backend)?.mode??2;
 const out=new Map([[backend,{instance:backend,mode,name:'This backend (local scripts)'}]]);
 for(const target of n.legacyTargets??[])if(Number.isSafeInteger(target.instance)&&target.instance>0&&[0,1,2].includes(target.mode))out.set(target.instance,target);
 for(const p of n.legacyAccess??[])if(!out.has(p.instance))out.set(p.instance,{instance:p.instance,mode:p.mode,name:'Existing approved manager '+p.instance});
 return [...out.values()];
}
function renderLegacyAccess(){
 const n=snapshot?.native;if(!n)return;const backend=Number(n.peerDescriptor?.backend),targets=legacyAccessTargets();
 nativeSelect('compatTarget',targets.map(t=>[String(t.instance),t.name]));
 const target=targets.find(t=>t.instance===Number($('compatTarget').value));$('compatApprove').disabled=!target;
 if(!target){$('compatTargetInfo').textContent='The backend could not be identified. Refresh the signed-in page.';return;}
 const explicit=(n.legacyAccess??[]).find(p=>p.instance===target.instance);
 const p=explicit||(target.instance===backend?(n.legacyDirectAccess??{enabled:true,read:true,write:false,bulk:false,portal:false,frozen:true}):{enabled:false,read:true,write:false,bulk:false,portal:false,frozen:true});
 const key=JSON.stringify([target,p]);if(compatViewKey!==key){for(const k of ['enabled','read','write','portal','frozen','bulk'])$('compat'+k[0].toUpperCase()+k.slice(1)).checked=p[k]===true;compatViewKey=key;}
 $('compatTargetInfo').textContent='Detected instance '+target.instance+' · '+(target.instance===backend?'local script access':({0:'receiver',1:'sender',2:'standalone'}[target.mode]||'existing role'))+' · '+(explicit?'existing explicit settings':target.instance===backend?'reads enabled by default; writes frozen':'not yet approved');
 const list=$('compatAccessList');list.replaceChildren();for(const grant of n.legacyAccess??[])nativeRow(list,'Instance '+grant.instance+' · '+(grant.enabled?'allowed':'disabled'),(grant.read?'read ':'')+(grant.write?'write ':'')+(grant.frozen?'· writes frozen':''),[['Change / revoke',()=>{$('compatTarget').value=String(grant.instance);compatViewKey='';renderLegacyAccess();}]]);
}
function renderEmergencyAccess(){
 const e=snapshot?.native?.emergency||{},peers=(snapshot?.native?.peers||[]).filter(p=>p.active&&p.state==='ACTIVE'&&peerShared(p));
 const granted=new Set((e.grants||[]).filter(grant=>grant.active).map(grant=>grant.source));
 const awaitingPermission=peers.filter(peer=>!granted.has(peer.id));
 const options=awaitingPermission.map(peer=>[peer.id,peer.name+' · '+new URL(peer.descriptor.endpoint).origin]);
 nativeSelect('nativeEmergencyPeer',options.length?options:[['','No connections awaiting permission']]);
 $('nativeEmergencyPeer').disabled=!options.length;
 $('nativeEmergencyGrant').disabled=!options.length;
 const r=e.runtime;$('nativeEmergencyRuntime').textContent=r?(r.ready?(r.mode==='REMOTE'?'Using remote source: '+r.activeSource+'. Freshness is uncertain.':'Local secrets source is available.'):'Availability check: '+(r.reason||r.mode||'pending')+'.'):'No emergency availability check recorded yet.';
 const offers=$('nativeEmergencyOffers');offers.replaceChildren();for(const o of e.offers||[])nativeRow(offers,o.name,'Approve this source for Global SEC application reads. No Local values or writes.',[['Enable this emergency source',()=>review({kind:'nativeEmergencyAccept',peerId:o.peerId,digest:o.digest},'Approve availability-first emergency reads from '+o.name+'. The separate encrypted credentials remain usable when this vault cannot open. A remote copy is not guaranteed to include an unreachable writer’s latest change.')]]);if(!offers.children.length)offers.textContent='No offers awaiting approval.';
 const clients=$('nativeEmergencyClients');clients.replaceChildren();for(const c of e.clients||[])nativeRow(clients,c.name,'Approved Global read source.',[['Remove source',()=>review({kind:'nativeEmergencyRemove',peerId:c.peerId},'Stop using this vault for emergency reads.')]]);if(!clients.children.length)clients.textContent='No emergency sources configured.';
 const grants=$('nativeEmergencyGrants');grants.replaceChildren();for(const g of e.grants||[])nativeRow(grants,g.name+(g.active?' · enabled':' · revoked'),'Read-only Global access from this vault.',g.active?[['Revoke emergency access',()=>review({kind:'nativeEmergencyRevoke',id:g.id},'Revoke this exact emergency credential immediately on this vault.')]]:[]);if(!grants.children.length)grants.textContent='No emergency access granted.';
}
function renderNative(){meshReceivedAt=Date.now();overviewStale=false;renderNativeOverview();scheduleGlobalRefresh();const n=snapshot?.native;for(const id of ['nativeMailboxNav','nativePeersNav','nativeRecoveryNav','nativeMachinesNav','nativeKeysNav','nativeProvidersNav'])$(id).hidden=!n;if(!n)return;renderEmergencyAccess();
 renderConnect();renderLegacyImports();
 $('nativePeerURL').value=n.peerEndpoint;$('nativeStorageInfo').textContent='Vault '+n.info.vaultId+' · '+Math.ceil(n.info.usedBytes/1024)+' / '+Math.floor(n.info.capacityBytes/1024)+' KiB · '+(n.info.directorySync?'file and directory synchronization':'file synchronization; platform qualification required')+' · standalone full-state rollback detection unavailable.'+(n.storage?' Vault folder: '+n.storage.vaultDirectory+'. Key folder: '+n.storage.keyDirectory+'.':'');
 const scopes=[['global','Global'],['local','Local']];nativeSelect('scope',scopes);nativeSelect('nativeMachineScope',scopes);nativeSelectionChanged();renderTree();renderGlobalConflicts();
 renderPeerConnections();renderPeerWizard();if(typeof pairCoordinatorRender==='function')pairCoordinatorRender();
 nativeSelect('nativeTransferPeer',n.peers.filter(p=>p.active).map(p=>[p.id,p.name+' · '+p.id.slice(0,8)]));nativeSelect('nativeTransferTree',[...(n.globalWritable&&!n.sharedGlobal?[[n.globalTreeId,'This vault’s global tree']]:[]),...n.ownedTrees.filter(t=>!t.frozen).map(t=>[t.id,'Owned tree '+t.id.slice(0,8)])]);$('nativeFork').hidden=n.globalWritable;
 const transfers=$('nativeTransferList');transfers.replaceChildren();for(const [id,t]of Object.entries(n.transfers)){const actions=t.direction==='incoming'&&t.state==='PENDING_APPROVAL'?[['Review and accept ownership',()=>review({kind:'nativeTransferAccept',transferId:id},'Accept this exact frozen tree and its listed subscribers. Other local/global trees remain independent.')]]:[];nativeRow(transfers,t.direction+' · '+t.state,'Tree '+t.certificate.treeId+' · new owner '+t.certificate.newOwner.vaultId+' · epoch '+t.certificate.newEpoch,actions);}
 renderLegacyAccess();
 const machines=$('nativeMachineList');machines.replaceChildren();for(const m of n.machines)nativeRow(machines,m.name+' · '+(m.active?'active':'revoked'),m.scope+' '+JSON.stringify(m.path)+' · '+(m.write?'read/write':'read-only'),m.active?[['Revoke capability',()=>review({kind:'nativeMachineRevoke',id:m.id},'Revoke this exact integration token.')]]:[]);
 $('nativeMachineExample').textContent='SECB_ReadNativeSecret('+n.peerDescriptor.backend+', "YOUR_CAPABILITY_TOKEN", "local", \'["ASK"]\');';
 $('nativeNewAdminLabel').value='Administrator '+(snapshot.credentials.length+1);$('nativeHardwareInfo').textContent='Trust generation '+n.hardwareProfile.version+' · '+Object.keys(n.hardwareProfile.fingerprints).length+' reviewed root certificate(s).';if(!$('nativeHardwareAAGUIDs').value){const candidates=[...new Set(snapshot.credentials.map(c=>c.aaguid).filter(x=>x&&x!=='0'.repeat(32)))];$('nativeHardwareAAGUIDs').value=(n.hardwareProfile.aaguids.length?n.hardwareProfile.aaguids:candidates).join('\n');}
 const providers=$('nativeProviderList');providers.replaceChildren();for(const p of n.providers)nativeRow(providers,p.name+' · '+p.status,p.endpoint+' · '+(p.automatic?'automatic with declared idempotency':'manual approved refresh'),[['Refresh once',()=>review({kind:'nativeRefresh',id:p.id},'Authorize one exact OAuth refresh. Uncertain outcomes are quarantined.')],['Edit settings',()=>nativeEditProvider(p)],...(p.active?[['Disable provider',()=>review({kind:'nativeProviderDisable',id:p.id},'Disable this provider and automatic refresh. Captured uncertain effects stay retained.')]]:[])]);
 const effects=$('nativeEffectList');effects.replaceChildren();for(const [id,e]of Object.entries(n.effects))if(!['COMPLETE','ERROR'].includes(e.state))nativeRow(effects,e.state,'Effect '+id+' · '+(e.reason||'awaiting exact completion'),[['Apply captured result',()=>review({kind:'nativeEffectApply',id},'Apply only an authenticated captured response whose current provider policy and predecessor still match. No external request is sent.')],['Abandon and require reauthorization',()=>review({kind:'nativeEffectAbandon',id},'Keep the uncertainty tombstone and require a newly authorized refresh token. This never retries the uncertain request.')]]);nativeSuggestProvider();
}
function nativeEditProvider(p){nativeProviderId=p.id;const fields={Name:'name',URL:'endpoint',Client:'clientId',Auth:'authentication',SecretScope:'secretScope',RefreshScope:'refreshScope',ResultScope:'resultScope',AccessField:'accessField',IdempotencyHeader:'idempotencyHeader'};for(const [id,key]of Object.entries(fields))$('nativeProvider'+id).value=p[key];for(const kind of ['Secret','Refresh','Result'])$('nativeProvider'+kind+'Path').value=JSON.stringify(p[kind.toLowerCase()+'Path']);$('nativeProviderAutomatic').checked=p.automatic;$('nativeProviderIdempotent').checked=p.idempotencySupported;message('Editing '+p.name+'. Review the exact settings before approval.');}
async function nativeUpload(ticket){const file=$('nativeBackupFile').files[0];if(!file)throw Error('Choose the encrypted native backup file.');const bytes=new Uint8Array(await file.arrayBuffer());ensure(ticket);const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))).map(x=>x.toString(16).padStart(2,'0')).join('');const begin=await api('nativeUploadBegin',{length:bytes.length,digest},ticket);for(let offset=0,index=0;offset<bytes.length;offset+=begin.chunkBytes,index++){ensure(ticket);const chunk=bytes.slice(offset,offset+begin.chunkBytes);await api('nativeUploadChunk',{uploadId:begin.uploadId,index,chunk:encoded(chunk)},ticket);}return(await api('nativeUploadFinish',{uploadId:begin.uploadId},ticket)).uploadId;}
async function nativeResult(result,ticket){if(result.conflictValues){nativeShowSecret('Compare Global versions','Values hide after 30 seconds. Close this window, then choose the versions to keep.',result.fields.map(f=>f.field+'\n'+f.value).join('\n\n'),30);return true;}if(result.fields)return false;if(!snapshot?.native)return false;if(result.reloginRequired){nativeRelogin('Credential or hardware profile updated. Sign in again and test the new key.');return true;}if(result.pairingSetup)peerWizardCommitted(result.pairingSetup);await load(ticket);
 if(typeof pairCoordinatorResult==='function'&&pairCoordinatorResult(result))return true;
 if(result.invitation){if(!result.pairingSetup){peerWizardCommitted({kind:'invitation'});peerWizardSetStep(3);}nativeShowSecret('Step 2 of 6 · Copy the invitation','Copy the complete text now, then switch to Connections on the second platform and choose I have an invitation. The invitation expires after 15 minutes. This popup clears after 60 seconds.',result.invitation);return true;}
 if(result.capabilityToken){nativeShowSecret('Integration capability token','Shown once. Store it in the intended integration; use the exact granted scope/path.',result.capabilityToken);return true;}
 if(result.legacyImported){legacySetStep(4);legacyReviewContext=null;$('legacyResult').textContent=(result.scope==='local'?'Local secrets match the approved import. Global secrets were left unchanged.':'Global and local trees match the approved import.')+' Source settings and inactive connection proposals were saved. The old vault was not changed.'+(result.storage?' Vault folder: '+result.storage.vaultDirectory+'. Key folder: '+result.storage.keyDirectory+'.':'');}
 if(result.backup){download('native-secrets-backup-'+snapshot.native.info.vaultId+'.json',result.backup);nativeShowSecret('Separate backup recovery key','Keep this key separately from the encrypted backup file. It is required for recovery.',result.recoveryKey);return true;}

 message(result.emergencyOffered?'Emergency offer approved. Wait for encrypted delivery, then approve it under Connections on the receiving installation.':result.emergencyConfigured?'Emergency source configuration saved. Check backend availability after the next watchdog tick.':result.restored?'Reviewed secret values recovered; current authority retained.':result.compacted?'Verified backup accepted; retained outcomes compacted.':'Change committed.');return true;
}
run($('nativeCopyPeerURL'),()=>nativeCopy('nativePeerURL'));run($('nativeSensitiveCopy'),()=>nativeCopy('nativeSensitiveValue'));$('nativeSensitiveClose').addEventListener('click',nativeClearSecrets);$('nativeSensitiveDialog').addEventListener('cancel',nativeClearSecrets);

run($('nativeInvite'),()=>peerReview({kind:'nativeInvite'},'Step 2 of 6: create one invitation for the second platform. Its request must be approved here in Step 4.'));
run($('nativeJoin'),()=>{const invitation=$('nativeInvitation').value.trim();if(!invitation){peerWizardSetStep(2);throw Error('Return to Step 2 and paste the invitation again.');}try{if(JSON.parse(new TextDecoder().decode(binary(invitation.slice(10)))).scope!=='shared-global-v1')throw Error();}catch{throw Error('Update both modules and create a new shared Global invitation.');}$('nativeInvitation').value='';return peerReview({kind:'nativePair',invitation,name:$('nativePeerName').value},'Step 3 of 6: check the first platform’s address and approve this request. Then return to Step 4 on the first platform.');});
run($('nativeTransfer'),()=>{if(!$('nativeTransferTree').value||!$('nativeTransferPeer').value)throw Error('Choose an owned tree and an active paired new owner.');return review({kind:'nativeTransferOffer',treeId:$('nativeTransferTree').value,peerId:$('nativeTransferPeer').value},'Freeze this writer and offer ownership. It never resumes automatically after a timeout.');});
run($('nativeFork'),()=>review({kind:'nativeFork',treeId:snapshot.native.globalTreeId},'Create a NEW independent global tree identity. The old writer is not fenced by this fork. Global machine grants and ordinary pairings are revoked; select and pair recipients again.'));
run($('nativeBackup'),()=>review({kind:'nativeBackup'},'Export the complete native state and recovery keys inside an encrypted backup. A separate generated recovery key is shown once.'));
run($('nativeRotateKey'),()=>review({kind:'nativeRotateKey'},'Generate a new data encryption key for future complete snapshots. Current and predecessor snapshots retain their required generations.'));
for(const [id,kind]of [['nativeRestore','nativeRestore'],['nativeCompact','nativeCompact']])run($(id),async ticket=>{const recoveryKey=$('nativeRecoveryKey').value;$('nativeRecoveryKey').value='';if(!recoveryKey)throw Error('Enter the separate recovery key.');const uploadId=await nativeUpload(ticket);await review({kind,uploadId,recoveryKey,...(kind==='nativeRestore'?{mode:$('nativeRecoveryMode').value}:{})},kind==='nativeRestore'?'Recover the reviewed values from this exact encrypted backup. Current credentials, rights, peers and uncertain effects are retained.':'Verify this current complete backup, then retain the latest 512 outcomes/audit entries. Pending effects and cursors are kept.',ticket);});
run($('nativeEmergencyGrant'),()=>{const peerId=$('nativeEmergencyPeer').value;if(!peerId)throw Error('Choose an active shared Global peer.');return review({kind:'nativeEmergencyGrant',peerId},'Grant trusted local SEC applications on this installation read-only access to all replicated Global secrets here during an emergency. Local secrets, writes and administrator actions are excluded. The receiving installation must also approve the offer.');});
run($('nativeMachineCreate'),()=>review({kind:'nativeMachineGrant',name:$('nativeMachineName').value,scope:$('nativeMachineScope').value,path:JSON.parse($('nativeMachinePath').value),write:$('nativeMachineWrite').checked},'Grant only this exact path and its descendants. Read-only is the default.'));
run($('nativeNewAdmin'),async ticket=>{
 const mode=$('nativeNewAdminMode').value,ctx=await bootstrapKey();const p=await api('nativeCandidateOptions',{label:$('nativeNewAdminLabel').value,hardware:mode==='hardware',probe:mode==='probe'},ticket);
 const c=await ceremony('create',options(p.options,true),ticket);const credential={type:c.type,rawId:encoded(c.rawId),response:{clientDataJSON:encoded(c.response.clientDataJSON),attestationObject:encoded(c.response.attestationObject)}};
 const bytes=['SECF.ADDKEY.SUBMIT.1',boot.origin,p.prepare,p.options.challenge,ctx.keyDigest,await bootstrapHash(JSON.stringify(bootstrapCanonical(credential)))].join('\n')+'\n';
 const candidate=await api('nativeCandidateSubmit',{prepare:p.prepare,key:ctx.key,credential,signature:await bootstrapSign(ctx,bytes)},ticket);
 await review({kind:'nativeEnrollment',candidate:candidate.candidate,digest:candidate.digest},'Approve exactly this prepared credential: '+candidate.label+' · candidate digest '+candidate.digest+' · browser key '+candidate.keyDigest+'. Use an already authorized passkey; the new candidate cannot approve itself.',ticket);
});
run($('nativeHardwareReview'),async ticket=>{const roots=[];for(const file of $('nativeHardwareFiles').files){const text=await file.text();ensure(ticket);const certificates=text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)||[];if(!certificates.length)throw Error('Select public CA certificates in PEM format.');roots.push(...certificates);}const aaguids=$('nativeHardwareAAGUIDs').value.split(/[\s,;]+/).filter(Boolean);await review({kind:'nativeHardwareProfile',roots,aaguids,allowReenrollmentLock:$('nativeHardwareLockAck').checked},'Approve the independently reviewed certificate fingerprints and exact hardware AAGUIDs. Existing hardware credentials need re-enrollment against the new generation.',ticket);});
run($('nativeProviderCreate'),()=>{const op={kind:'nativeProvider',id:nativeProviderId,name:$('nativeProviderName').value,endpoint:$('nativeProviderURL').value,clientId:$('nativeProviderClient').value,authentication:$('nativeProviderAuth').value,accessField:$('nativeProviderAccessField').value,automatic:$('nativeProviderAutomatic').checked,idempotencySupported:$('nativeProviderIdempotent').checked,idempotencyHeader:$('nativeProviderIdempotencyHeader').value};for(const kind of ['Secret','Refresh','Result']){op[kind.toLowerCase()+'Scope']=$('nativeProvider'+kind+'Scope').value;op[kind.toLowerCase()+'Path']=JSON.parse($('nativeProvider'+kind+'Path').value);}return review(op,'Approve this exact HTTPS provider endpoint, credential references, result path and automatic-refresh contract.');});
run($('nativeRefreshPeers'),load);run($('nativeRefreshProviders'),load);$('scope').addEventListener('change',nativeSelectionChanged);

$('nativeMachineScope').addEventListener('change',()=>{const scope=$('nativeMachineScope').value;const readOnly=scope.startsWith('received:')||(scope==='global'&&snapshot?.native&&!snapshot.native.globalWritable);$('nativeMachineWrite').disabled=readOnly;if(readOnly)$('nativeMachineWrite').checked=false;});

run($('nativeRecoveryEnrollment'),showAdministratorRecovery);run($('accessRecoveryEnrollment'),showAdministratorRecovery);

let connectPopup=null,connectCandidate=null,connectPendingMessage=null,connectEnrollmentStatus=null,connectStatusTimer=null,connectRouteTimer=null;
function renderConnect(){
 const p=snapshot?.native?.backupOrigin,primary=fullAdministration();
 clearTimeout(connectRouteTimer);$('connectWizard').hidden=!primary;
 if(!primary)return;
 if(p&&p.status!=='revoked')$('connectOrigin').value=p.origin;
 const pending=p?.status==='pending',active=p?.status==='active';const routePending=(snapshot.native.peers||[]).filter(peer=>peer.active&&peer.routeReceipt!==(snapshot.native.routeRevision||'0')).length;$('connectUpgrade').hidden=!(active&&p.version===1);$('connectAdminURL').value=p?.origin?new URL(boot.path,p.origin).href:'';
 $('connectAllow').disabled=pending||active||!$('connectOrigin').value;
 $('connectOpen').disabled=!pending;$('connectApprove').disabled=!pending||!connectCandidate;
 $('connectRevoke').hidden=!pending&&!active;
 $('connectState').textContent=active?p.version===2?routePending?'Full Magic access is active. Publishing its address to '+routePending+' connected platform(s)…':'Full Magic access is active. Both addresses provide the same functions.':'Limited Magic access is active. Approve full access below.':pending?'Step 3 of 4 · Create the backup passkey, then approve it here.':'Step 1 of 4 · Find your Connect address.';
 if(active&&p.version===2&&routePending)connectRouteTimer=setTimeout(async()=>{if(!pageActive||document.hidden||!snapshot?.native)return;try{const progress=await api('nativePairingStatus');Object.assign(snapshot.native,progress);renderConnect();}catch{message('Refresh connection status to check Magic address delivery.',true);}},5000);
 for(let i=1;i<=4;i++)$('connectStep'+i).classList.toggle('active',i===(active?4:pending?connectCandidate?4:3:$('connectOrigin').value?2:1));
}
run($('nativeDiscoverConnect'),async ticket=>{const result=await api('connectDiscovery',{},ticket);if(result.available){$('connectOrigin').value=result.origin;$('nativeConnectDiscovery').textContent='Address found. Continue with 2 · Allow backup setup.';renderConnect();}else $('nativeConnectDiscovery').textContent=result.message;});
run($('connectAllow'),ticket=>review({kind:'nativeConnectStage',origin:$('connectOrigin').value},'Allow restricted backup passkey setup at this exact address. Backup access stays closed until Step 4.',ticket));
run($('connectOpen'),()=>{connectCandidate=null;connectPopup=window.open(snapshot.native.backupOrigin.origin+boot.path,'secrets-connect-setup','popup,width=760,height=850');if(!connectPopup)throw Error('Allow this setup popup, then select Step 3 again.');});
async function connectReviewIncoming(){
 if(document.hidden||!connectPendingMessage||!snapshot)return;
 const incoming=connectPendingMessage;connectPendingMessage=null;const ticket=generation;
 try{const candidate=await api('connectCandidateReview',{candidate:incoming.candidate},ticket);if(candidate.digest!==incoming.digest)throw Error('Backup candidate changed. Repeat Step 3.');connectCandidate=candidate;renderConnect();$('nativeConnectDiscovery').textContent='Passkey tested. Compare fingerprint '+candidate.fingerprint+' with the backup window, then continue with Step 4.';}catch(e){if(ticket===generation)message(e.message,true);}
}
window.addEventListener('message',event=>{
 const p=snapshot?.native?.backupOrigin;
 if(!p||p.status!=='pending'||event.origin!==p.origin||event.source!==connectPopup||event.data?.type!=='SECF.ConnectCandidate.1'||typeof event.data.candidate!=='string'||typeof event.data.digest!=='string')return;
 connectPendingMessage={candidate:event.data.candidate,digest:event.data.digest};connectReviewIncoming();
});
window.addEventListener('focus',connectReviewIncoming);document.addEventListener('visibilitychange',connectReviewIncoming);
run($('connectApprove'),ticket=>{if(!connectCandidate)throw Error('Complete Step 3 first.');return review({kind:'nativeConnectActivate',candidate:connectCandidate.candidate,digest:connectCandidate.digest},'Compare this exact credential fingerprint with the backup window: '+connectCandidate.fingerprint+'. Grant the displayed administrator access at '+connectCandidate.origin+'.',ticket);});
run($('connectRevoke'),ticket=>{const p=snapshot.native.backupOrigin;connectCandidate=null;return review({kind:'nativeConnectRevoke',origin:p.origin,generation:p.generation},'Remove this backup route and invalidate all its sessions, challenges and pending setup. Your primary address remains available.',ticket);});
run($('connectCreate'),async ticket=>{
 clearTimeout(connectStatusTimer);clearTimeout(connectRouteTimer);connectEnrollmentStatus=null;$('connectEnrollmentStep').textContent='Backup access · Step 3 of 4';$('connectFinish').hidden=true;$('connectFinish').disabled=true;$('connectReturnPrimary').hidden=true;
 const ctx=await bootstrapKey(),p=await api('connectOptions',{key:ctx.key},ticket);
 const cred=await ceremony('create',options(p.options,true),ticket);
 const credential={type:cred.type,rawId:encoded(cred.rawId),response:{clientDataJSON:encoded(cred.response.clientDataJSON),attestationObject:encoded(cred.response.attestationObject)}};
 const digest=await bootstrapHash(JSON.stringify(bootstrapCanonical(credential)));
 const bytes=['SECF.CONNECT.REGISTER.1',boot.origin,boot.originGeneration,p.prepare,ctx.keyDigest,digest].join('\n')+'\n';
 const test=await api('connectSubmit',{prepare:p.prepare,credential,signature:await bootstrapSign(ctx,bytes)},ticket);
 const proof=assertion(await ceremony('get',options(test.options),ticket));
 const proofDigest=await bootstrapHash(JSON.stringify(bootstrapCanonical(proof)));
 const proofBytes=['SECF.CONNECT.TEST.1',boot.origin,boot.originGeneration,test.test,ctx.keyDigest,proofDigest].join('\n')+'\n';
 const result=await api('connectProof',{test:test.test,credential:proof,signature:await bootstrapSign(ctx,proofBytes)},ticket);
 $('connectEnrollmentResult').textContent='Passkey tested. Compare fingerprint '+result.fingerprint+' in the primary window and approve Step 4 there.';
 if(window.opener)window.opener.postMessage({type:'SECF.ConnectCandidate.1',candidate:result.candidate,digest:result.digest},boot.primaryOrigin);
 const statusBytes=['SECF.CONNECT.STATUS.1',boot.origin,boot.originGeneration,result.candidate,result.digest].join('\n')+'\n';
 connectEnrollmentStatus={candidate:result.candidate,digest:result.digest,signature:await bootstrapSign(ctx,statusBytes)};
 $('connectCreate').hidden=true;$('connectEnrollmentStep').textContent='Backup access · Step 4 of 4';$('connectReturnPrimary').hidden=false;$('connectFinish').hidden=false;$('connectFinish').disabled=true;
 connectScheduleStatus();
});
function connectScheduleStatus(){clearTimeout(connectStatusTimer);if(connectEnrollmentStatus&&!document.hidden&&pageActive)connectStatusTimer=setTimeout(()=>connectCheckStatus(),2000);}
async function connectCheckStatus(ticket=generation){
 if(!connectEnrollmentStatus||document.hidden||!pageActive)return false;
 const context=connectEnrollmentStatus;
 try{
  const result=await api('connectStatus',context,ticket);if(context!==connectEnrollmentStatus)return false;
  if(result.state==='active'){$('connectFinish').disabled=false;$('connectReturnPrimary').hidden=true;$('connectEnrollmentResult').textContent='Backup approved. Select Continue to sign in.';clearTimeout(connectStatusTimer);return true;}
  if(result.state!=='waiting')throw Error('This passkey was not approved. Return to the primary window and repeat Step 3.');
  $('connectFinish').disabled=true;connectScheduleStatus();return false;
 }catch(error){if(ticket===generation&&error.name!=='AbortError'){$('connectFinish').disabled=true;$('connectEnrollmentResult').textContent=error.message;connectEnrollmentStatus=null;$('connectCreate').hidden=false;}return false;}
}
run($('connectReturnPrimary'),()=>{if(window.opener&&!window.opener.closed)window.opener.focus();else message('Return to your usual Secrets address and approve Step 4. Keep this backup window open.');});
$('connectFinish').addEventListener('click',async()=>{
 $('connectFinish').disabled=true;const ticket=generation;if(!await connectCheckStatus(ticket))return;
 clearTimeout(connectStatusTimer);clearTimeout(connectRouteTimer);connectEnrollmentStatus=null;boot.backupEnrollment=false;document.body.classList.remove('connectPending');tab('overview');
 $('login').hidden=false;$('signin').disabled=false;$('readiness').textContent='Backup access is approved. Sign in with your backup passkey.';
});
window.addEventListener('pagehide',()=>{clearTimeout(connectStatusTimer);clearTimeout(connectRouteTimer);connectEnrollmentStatus=null;});
document.addEventListener('visibilitychange',()=>{if(document.hidden)clearTimeout(connectStatusTimer);else connectScheduleStatus();});

let legacyReviewContext=null,legacyReviewGeneration=0;
function legacySetStep(step){for(let n=1;n<=4;n++)$('legacyStep'+n).hidden=n!==step;[...$('legacySteps').children].forEach((node,i)=>{node.classList.toggle('active',i+1===step);node.classList.toggle('complete',i+1<step);});}
function renderLegacyImports(){const n=snapshot?.native;if(!n)return;$('nativeImportNav').hidden=!fullAdministration();const holder=$('legacyHistory');holder.replaceChildren();for(const record of n.legacyImports||[]){nativeRow(holder,record.source.name+' · imported '+record.at,(record.scope==='local'?'Local secrets only':'Global and Local secrets')+' · Old key folder: '+record.source.legacyKeyFolder+' · vault folder: '+(record.storage?.vaultDirectory||'kept current')+' · key folder: '+(record.storage?.keyDirectory||'kept current')+' · connections inactive.');for(const proposal of record.source.connections||[])nativeRow(holder,proposal.name,proposal.legacyEndpoint+' · needs new pairing');}if(!holder.childNodes.length)holder.textContent='No source settings imported yet.';}
run($('legacyDiscover'),async ticket=>{legacyReviewGeneration++;legacyReviewContext=null;const result=await api('legacySources',{},ticket);const select=$('legacySource');select.replaceChildren();const placeholder=document.createElement('option');placeholder.value='';placeholder.textContent=result.sources.length?'Choose the old vault…':'No retained vault instances found';select.append(placeholder);for(const source of result.sources){const option=document.createElement('option');option.value=String(source.id);option.disabled=!source.ready;option.textContent=source.name+' · '+source.id+(source.ready?'':' · inactive or unapplied settings');select.append(option);}const ready=result.sources.filter(s=>s.ready);if(ready.length===1)select.value=String(ready[0].id);legacyReviewContext=null;legacySetStep(1);});
function legacyParagraph(parent,label,value){const p=document.createElement('p'),strong=document.createElement('strong');strong.textContent=label+': ';p.append(strong,document.createTextNode(String(value)));parent.append(p);}
run($('legacyPreview'),async ticket=>{const source=Number($('legacySource').value);if(!Number.isInteger(source)||source<=0)throw Error('Choose a ready retained vault.');const generation=++legacyReviewGeneration;legacyReviewContext=null;const result=await api('legacyPreview',{source,scope:$('legacyScope').value,policy:$('legacyPolicy').value,vaultLocation:$('legacyVaultLocation').value,keyLocation:$('legacyKeyLocation').value,persistenceConfirmed:$('legacyPersistence').checked,privateACLConfirmed:$('legacyACL').checked},ticket);if(generation!==legacyReviewGeneration)return;legacyReviewContext=result;const r=result.review,holder=$('legacyReview');holder.replaceChildren();legacyParagraph(holder,'Source',r.source.name+' · '+r.source.id+' · '+r.source.role);legacyParagraph(holder,'Import scope',r.scope==='local'?'Local secrets only':'Global and Local secrets');for(const scope of ['global','local']){const stats=r.summary[scope];if(stats.skipped){legacyParagraph(holder,'Global secrets','Not imported · left unchanged');continue;}legacyParagraph(holder,scope==='global'?'Global secrets':'Local secrets',stats.added+' new entries, '+stats.unchanged+' unchanged, '+stats.kept+' conflicting values kept, '+stats.replaced+' conflicting values replaced');if(stats.conflicts.length)legacyParagraph(holder,'Conflicting paths',stats.conflicts.map(p=>p.join(' / ')).join('; '));}legacyParagraph(holder,'Old vault location',r.source.legacyVaultLocation);legacyParagraph(holder,'Old key folder',r.source.legacyKeyFolder);legacyParagraph(holder,'Existing new-vault peers',String(r.activeRecipients??0)+(r.scope==='local'?' active recipients; Global secrets and Global sharing state stay unchanged. Local secrets remain local.':' active recipients; global imports follow current sharing. Local secrets remain local.'));legacyParagraph(holder,'Current vault folder',r.storage.current?.vaultDirectory||r.storage.vaultDirectory);legacyParagraph(holder,'Current key folder',r.storage.current?.keyDirectory||r.storage.keyDirectory);legacyParagraph(holder,'Selected vault folder',r.storage.vaultDirectory);legacyParagraph(holder,'Selected key folder',r.storage.keyDirectory);legacyParagraph(holder,'Storage choice',r.storage.action==='use-selected'?'Move the new vault to the selected folders. The old PasswordSafe files stay in place. Retained copies of the new vault are fenced against further writes.':'Keep current locations.');legacyParagraph(holder,'Excluded internal areas',r.excluded.join(', ')||'None');for(const warning of r.source.warnings)legacyParagraph(holder,'Review note',warning);for(const connection of r.source.connections)legacyParagraph(holder,'Inactive connection proposal',connection.name+' · '+connection.legacyEndpoint);legacySetStep(2);});
run($('legacyApprove'),async ticket=>{if(!legacyReviewContext)throw Error('Review the import first.');await review({kind:'nativeLegacyImport',candidate:legacyReviewContext.candidate,digest:legacyReviewContext.digest},(legacyReviewContext.review.scope==='local'?'Import only the reviewed Local secrets and source settings. Global secrets and Global sharing state stay unchanged.':'Import the exact reviewed Global and Local secrets and source settings.')+' Conflict policy: '+legacyReviewContext.review.conflictPolicy+'. Existing administrators and active peer trust are retained. Vault folder: '+legacyReviewContext.review.storage.vaultDirectory+'. Key folder: '+legacyReviewContext.review.storage.keyDirectory+'.',ticket);legacySetStep(3);});
for(const id of ['legacyBack','legacyAnother'])run($(id),()=>{legacyReviewGeneration++;legacyReviewContext=null;legacySetStep(1);});
run($('legacyBackToReview'),()=>{if($('review').open)$('review').close();legacySetStep(2);});
function legacyStorageChoiceChanged(){legacyReviewGeneration++;legacyReviewContext=null;legacySetStep(1);$('legacyStorageConfirmations').hidden=$('legacyVaultLocation').value==='current'&&$('legacyKeyLocation').value==='current';}
for(const id of ['legacySource','legacyScope','legacyPolicy','legacyVaultLocation','legacyKeyLocation','legacyPersistence','legacyACL'])$(id).addEventListener('change',legacyStorageChoiceChanged);
legacySetStep(1);

$('nativeImportNav').addEventListener('click',()=>{if(snapshot?.native)$('legacyDiscover').click();});

function globalHasConflict(path){return $('scope').value==='global'&&(snapshot?.native?.sharedGlobal?.conflicts||[]).some(c=>samePath(c.path.slice(0,path.length),path)||samePath(path.slice(0,c.path.length),c.path));}
function globalPlatform(id){if(id===snapshot?.native?.info.vaultId)return 'this platform';const p=snapshot?.native?.peers.find(p=>p.id===id);return p?new URL(p.descriptor.endpoint).host:id.slice(0,8);}
function renderGlobalConflicts(){
 const list=$('globalConflictList'),conflicts=snapshot?.native?.sharedGlobal?.conflicts||[];list.replaceChildren();$('globalConflicts').hidden=!conflicts.length;$('globalNoConflicts').hidden=!!conflicts.length;$('nativeConflictsNav').hidden=!snapshot?.native;$('nativeConflictsNav').textContent=conflicts.length?'Conflicts ('+conflicts.length+')':'Conflicts';
 $('globalScopeStatus').textContent=conflicts.length?'Conflicted secrets are in the Conflicts tab.':'';
 for(const c of conflicts){const card=document.createElement('div');card.className='card';const title=document.createElement('h4');title.textContent=c.path.join(' / ');card.append(title);
  const show=document.createElement('button');show.type='button';show.textContent='1 · Show versions';run(show,async ticket=>{const op={kind:'nativeGlobalReveal',path:c.path,digest:c.digest,versionId:chosen?.id||''};if(snapshot.hardware.reveal)return review(op,'Show the conflicting Global versions with the required hardware key.',ticket);const r=await api('sessionReveal',{operation:op},ticket);if(r.requiresHardware)return review(op,'Show the conflicting Global versions with the required hardware key.',ticket);await nativeResult(r,ticket);});card.append(show);
  const keep=document.createElement('button');keep.type='button';keep.textContent='2 · Keep selected version';keep.disabled=true;let chosen=null;const inputs=[];
  for(const [i,v]of c.versions.entries()){const row=document.createElement('div'),label=document.createElement('label'),radio=document.createElement('input');radio.type='radio';radio.name='global-conflict-'+c.digest;radio.addEventListener('change',()=>{chosen=v;keep.disabled=false;});label.append(radio,document.createTextNode(' Version '+v.id.slice(0,8)+' · '+(v.platforms.map(globalPlatform).join(', ')||'concurrent folder changes')+' · '+v.type));row.append(label);
   if(v.type!=='deleted'){const name=document.createElement('input');name.type='text';name.maxLength=160;name.setAttribute('aria-label','Name when keeping version '+v.id.slice(0,8));name.value=i===0?String(c.path.at(-1)):String(c.path.at(-1)).slice(0,130)+' (version '+(i+1)+')';row.append(name);inputs.push({v,input:name});}card.append(row);
  }
  run(keep,ticket=>{if(!chosen)throw Error('Select a version first.');return review({kind:'nativeGlobalResolve',path:c.path,digest:c.digest,choices:[{id:chosen.id,name:String(c.path.at(-1))}]},'3 · Confirm conflict resolution. Keep this version at '+c.path.join(' / ')+'. The other live versions will be removed. This choice synchronizes to every connected platform.',ticket);});card.append(keep);
  if(inputs.length>1){const all=document.createElement('button');all.type='button';all.textContent='2 · Keep all versions with these names';run(all,ticket=>review({kind:'nativeGlobalResolve',path:c.path,digest:c.digest,choices:inputs.map(x=>({id:x.v.id,name:x.input.value.trim()}))},'3 · Confirm conflict resolution. Keep every value under the displayed different names. This choice synchronizes to every connected platform.',ticket));card.append(all);}
  list.append(card);
 }
}

let globalRefreshTimer=null;
function scheduleGlobalRefresh(){clearTimeout(globalRefreshTimer);if(!snapshot?.native||!pageActive||!window.document)return;globalRefreshTimer=setTimeout(async()=>{
 renderMeshMatrix();
 try{if(!document.hidden&&(!$('overview').hidden||!$('nativePeers').hidden||!$('nativeMailbox').hidden)){await refreshNativeOverview(generation);return;}if(document.hidden||!fullAdministration()||($('secrets').hidden&&$('conflicts').hidden)||$('review').open||!$('browserForm').hidden||!$('revealed').hidden||$('nativeSensitiveDialog').open)return;
 const ticket=generation,r=await api('nativeGlobalStatus',{},ticket);if(r.revision===snapshot.revision)return;
 snapshot.revision=r.revision;revision=r.revision;snapshot.global=r.global;snapshot.local=r.local;snapshot.native.sharedGlobal=r.sharedGlobal;clearSecrets();renderTree();renderGlobalConflicts();
 }catch(error){if(error.name!=='AbortError')message('Sign in or refresh to update secrets.',true);}finally{scheduleGlobalRefresh();}
 },10000);}

window.addEventListener('pagehide',()=>clearTimeout(globalRefreshTimer));

run($('connectUpgrade'),ticket=>review({kind:'nativeConnectUpgrade'},'Grant full administration to the displayed tested Magic credentials. Existing Magic sessions will expire. Sign in again afterwards.',ticket));

$('compatTarget').addEventListener('change',()=>{compatViewKey='';renderLegacyAccess();});
run($('compatApprove'),()=>{
 const target=legacyAccessTargets().find(t=>t.instance===Number($('compatTarget').value));if(!target)throw Error('The selected backend/manager is unavailable. Refresh the page.');
 return review({kind:'nativeLegacyAccess',instance:target.instance,mode:target.mode,enabled:$('compatEnabled').checked,read:$('compatRead').checked,write:$('compatWrite').checked,portal:$('compatPortal').checked,frozen:$('compatFrozen').checked,bulk:$('compatBulk').checked},'Change application access for the automatically detected instance. Local scripts may read application Global and Local secrets. This does not switch existing applications.');
});

let mailboxApprovalBusy=false;
const mailboxLabels={APPROVAL_REQUIRED:'Your approval required',WAITING_REMOTE:'Waiting for the other server',SENDING:'Sending / retrying delivery',CONFIRMATION_PENDING:'Approval sent — confirmation pending',COMPLETED:'Completed',EXPIRED:'Expired',REVOKED:'Revoked',UNKNOWN:'Status unknown — confirmation outstanding'};
function renderMailbox(){
 if(mailboxApprovalBusy)return;
 renderAutomaticSetup();
 const m=snapshot?.native?.mailbox,nodes=m?.nodes||[],local=nodes.find(n=>n.local),localActions=(local?.rows||[]).filter(r=>r.state==='APPROVAL_REQUIRED'&&!(r.type==='emergency'&&snapshot?.native?.automaticSetup?.authorized&&(snapshot.native.automaticSetup.policy?.members||[]).some(m=>m.descriptor.vaultId===r.peerId))).length+(snapshot?.native?.automaticSetup?.policy&&!snapshot.native.automaticSetup.authorized?1:0);
 const pending=nodes.reduce((sum,n)=>sum+(n.rows||[]).filter(r=>['WAITING_REMOTE','SENDING','CONFIRMATION_PENDING','UNKNOWN'].includes(r.state)).length,0);
 $('nativeMailboxNav').textContent='Mailbox'+(localActions?' · '+localActions+' to approve':'')+(pending?' · '+pending+' waiting':'');
 const selected=$('mailboxServer').value;nativeSelect('mailboxServer',[['all','All servers'],['local','This server'],...nodes.filter(n=>!n.local).map(n=>[n.id,n.name])]);if(selected==='local')$('mailboxServer').value='local';
 $('mailboxSummary').textContent=localActions+' approval(s) need your action on this server · '+pending+' waiting for delivery, another server or confirmation.';
 $('mailboxCoverage').textContent=(!m?'Update this backend to load the Mailbox. ':overviewStale?'Refresh failed. Last shown states are unconfirmed. ':'')+'Remote summaries arrive with existing background checks. Unavailable, stale or older servers remain unknown. Request times are shown only when recorded; existing workflows may have no saved timestamp. Completed entries are retained while their workflow records exist.';
 const list=$('mailboxRows');list.replaceChildren();let count=0;
 for(const node of nodes){if($('mailboxServer').value==='local'&&!node.local||!['all','local'].includes($('mailboxServer').value)&&$('mailboxServer').value!==node.id)continue;
  const heading=document.createElement('h3');heading.textContent=node.name+(node.local?' · this server':'');list.append(heading);
  const stamp=node.checkedAt?new Date(node.checkedAt*1000).toLocaleString():'not confirmed';
  if(!node.available||!node.fresh||node.partial){const note=document.createElement('p');note.className='muted';note.textContent=(!node.available?'Mailbox unavailable; update or open this server.':!node.fresh?'Status unknown; showing last known requests.':'Summary is incomplete; open this server for the full list.')+' Last confirmed update: '+stamp;list.append(note);}
  for(const row of node.rows||[]){if($('mailboxState').value==='outstanding'&&['COMPLETED','REVOKED','EXPIRED'].includes(row.state))continue;count++;
   const peer=nodes.find(n=>n.id===row.peerId),peerName=peer?.name||row.peerId||'';
   const title=row.type==='emergency'?((row.direction==='provider'?peerName:node.name)+' may read Global from '+(row.direction==='provider'?node.name:peerName)):({'pairing':'Connect platforms','ownership':'Transfer ownership','backup-access':'Magic backup access','provider-operation':'OAuth operation'}[row.type]||row.type)+(peerName?' · '+peerName:'');
   let state=overviewStale?'UNKNOWN':row.state;const status=row.type==='backup-access'&&state==='CONFIRMATION_PENDING'?'Waiting for a tested backup passkey':state==='APPROVAL_REQUIRED'&&!node.local?'Approval required on '+node.name:mailboxLabels[state]||'Status unknown';
   const managed=row.type==='emergency'&&snapshot?.native?.automaticSetup?.authorized&&(snapshot.native.automaticSetup.policy?.members||[]).some(m=>m.descriptor.vaultId===row.peerId);
   const approvals=node.local&&!overviewStale&&!managed?(m.approvals?.[row.id]||[]):[];
   const actions=approvals.map(a=>[a.label||'Approve with passkey',()=>approveMailboxEntry(a)]);
   if(node.local&&!actions.length&&!managed)actions.push([row.type==='backup-access'&&row.state==='CONFIRMATION_PENDING'?'Continue backup setup':row.state==='APPROVAL_REQUIRED'?'Refresh approval details':'Open workflow',()=>row.state==='APPROVAL_REQUIRED'?refreshNativeOverview(generation):tab(row.action)]);
   nativeRow(list,title,status+(row.lastKnownState?' · last known: '+(mailboxLabels[row.lastKnownState]||row.lastKnownState):''),actions);
   const card=list.lastElementChild,detail=card.querySelector('p');
   for(const a of approvals){const instructions=document.createElement('p');instructions.className='break';instructions.textContent=a.summary+' Select “'+(a.label||'Approve with passkey')+'”, then confirm with your passkey or the required hardware key. The result will appear here.';card.insertBefore(instructions,card.lastElementChild);}
   if(managed){const note=document.createElement('p');note.className='muted';note.textContent='Handled by Finish setup on all servers. No individual approval is needed for this request.';card.insertBefore(note,card.lastElementChild);}
   detail.classList.add('mailboxStatus');const facts=document.createElement('dl');facts.className='mailboxFacts';
   const fields=[];
   if(row.type==='emergency')fields.push(['Provider approval',row.state==='REVOKED'?'Revoked or pairing retired':row.direction==='provider'?'Granted on this server':'Signed offer received'],['Consumer acceptance',row.state==='COMPLETED'?'Confirmed':row.state==='REVOKED'?'Inactive':row.direction==='consumer'&&row.state!=='APPROVAL_REQUIRED'?'Approved locally; confirmation pending':'Awaiting confirmation']);
   if(row.type==='backup-access'&&row.state==='CONFIRMATION_PENDING')fields.push(['Next step','Create and test the backup passkey before activation can be approved.']);
   fields.push(['Responsible server',state==='WAITING_REMOTE'?peerName:node.name],['Requested',row.requestedAt?new Date(row.requestedAt*1000).toLocaleString():'Time not recorded'],['Last confirmed update',stamp]);
   if(row.expiresAt)fields.push(['Expires',new Date(row.expiresAt*1000).toLocaleString()]);
   for(const [label,value]of fields){const field=document.createElement('div'),term=document.createElement('dt'),definition=document.createElement('dd');term.textContent=label;definition.textContent=value;field.append(term,definition);facts.append(field);}detail.after(facts);

  }
 }
 if(!count){const empty=document.createElement('p');empty.textContent='No matching requests in the available summaries. Unknown or incomplete servers may still have outstanding approvals.';list.append(empty);}
}
async function approveMailboxEntry(action){
 if(mailboxApprovalBusy||!fullAdministration())return;
 mailboxApprovalBusy=true;const ticket=generation;
 for(const button of $('mailboxRows').querySelectorAll('button'))button.disabled=true;
 try{
  message('Preparing this exact approval…');
  const prepared=await api('prepare',{operation:action.operation},ticket);
  message((prepared.reviewSummary?(peerWizardApprovalText(prepared.reviewSummary)||JSON.stringify(prepared.reviewSummary,null,2))+'\n\n':'')+action.summary+'\nConfirm with your passkey'+(prepared.requiresHardware?' using an approved hardware key':'')+'.');
  await finishApproval({...prepared,uiOperation:action.operation},ticket);
 }finally{mailboxApprovalBusy=false;renderMailbox();}
}
for(const id of ['mailboxServer','mailboxState'])$(id).addEventListener('change',renderMailbox);
run($('mailboxRefresh'),ticket=>refreshNativeOverview(ticket));
let supportBusy=false,supportJob=null,supportPollTimer=null,supportPollBusy=false;
function renderSupportUpload(){ $('supportUpload').disabled=supportBusy||!snapshot?.native||!fullAdministration(); }
async function pollSupportUpload(ticket){
 if(!supportJob||supportPollBusy||ticket!==generation||document.hidden)return;
 clearTimeout(supportPollTimer);supportPollBusy=true;
 try{
  const r=await api('nativeSupportUploadStatus',{job:supportJob},ticket);ticket=generation;
  if(r.state==='queued'||r.state==='running'){
   $('supportResult').textContent=r.state==='queued'?'Report queued on this server; waiting for its background worker. You can leave this page and return.':'Sending report in the background; waiting for GitHub confirmation. Slow requests can take several minutes.';
   supportPollTimer=setTimeout(()=>pollSupportUpload(ticket),10000);return;
  }
  $('supportResult').textContent=r.ok?'Saved to '+r.repository+' · '+r.branch+' · commit '+r.commit+(r.incomplete?' · Some backend reports are incomplete; review the uploaded status.':''):r.error||'Upload was not confirmed. Check the repository before starting a new upload.';
  supportJob=null;supportBusy=false;renderSupportUpload();
 }catch(e){if(ticket===generation){$('supportResult').textContent='Could not read upload progress: '+e.message+' The upload may still be running. Progress will be checked again; no duplicate upload is started.';supportPollTimer=setTimeout(()=>pollSupportUpload(ticket),15000);}}
 finally{supportPollBusy=false;}
}
function resumeSupportUpload(){ renderSupportUpload();if(supportJob)pollSupportUpload(generation); }
$('supportUpload').addEventListener('click',async()=>{
 const ticket=generation;
 if(supportBusy)return;
 supportBusy=true;renderSupportUpload();$('supportResult').textContent='Requesting report upload on this server…';
 try{
  const r=await api('nativeSupportUpload',{instance:0},ticket);
  if(r.job){supportJob=r.job;await pollSupportUpload(ticket);}
  else{supportBusy=false;$('supportResult').textContent=r.error||'The upload could not be started.';}
 }catch(e){supportBusy=false;$('supportResult').textContent='Upload request was not confirmed: '+e.message+' Check the saved report before retrying.';}
 finally{renderSupportUpload();}
});
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&supportJob)pollSupportUpload(generation);});

let automaticSetupBusy=false,automaticSetupPreview=null,automaticSetupNotice="",automaticSetupTimer=null;
function renderAutomaticSetup(){
 if(automaticSetupBusy)return;
 const n=snapshot?.native,a=n?.automaticSetup||{},policy=a.policy||automaticSetupPreview;
 $('setupFinish').disabled=!fullAdministration();$('setupStop').hidden=!a.policy;
 $('setupFinish').textContent=!a.authorized&&policy?'Authorize automatic setup on this server':'Finish setup on all servers';
 $('setupProgress').textContent=!policy&&automaticSetupNotice?automaticSetupNotice:!policy?'First, this button finds the servers reached through your existing approved connections. You then review the server list and authorize this installation once.':!a.authorized?'One-time authorization required on this server. Review the exact servers below, then authorize with your passkey.':a.running?'Setup is running in the background. Replies still outstanding remain waiting; unreachable servers are retried.':a.completedAt?'This server’s setup completed at '+new Date(a.completedAt*1000).toLocaleString()+'. Select Finish setup to refresh and verify all servers.':'Automatic setup is authorized. Select Finish setup to continue.';
 const holder=$('setupMembers');holder.replaceChildren();
 const members=a.members?.length?a.members:(policy?.members||[]).map(m=>({id:m.descriptor.vaultId,name:new URL(m.descriptor.endpoint).host,local:m.descriptor.vaultId===n?.peerDescriptor?.vaultId,url:m.frontend?new URL('/hook/secrets_frontend_'+m.frontend,m.descriptor.endpoint).href:null,authorized:null,backupStatus:'unknown',fresh:false}));
 for(const m of members){
  const actions=[];if(!m.local&&m.url)actions.push([m.authorized?'Open server / complete device steps':'Authorize on this server',()=>window.open(m.url+'#automatic-setup','_blank','noopener')]);
  if(m.local&&a.authorized&&!m.backupReady){
   const choices=n?.mailbox?.approvals?.['magic:'+m.id]||[];
   for(const choice of choices)actions.push([choice.label,()=>approveMailboxEntry(choice)]);
   if(!choices.length)actions.push(['Continue backup passkey setup',()=>{tab('nativeKeys');if(n.backupOrigin?.status==='pending')$('connectOpen').click();else $('nativeDiscoverConnect').click();}]);
  }
  const description=!a.authorized?'Review this server’s HTTPS address and identity before authorizing the plan.':m.deliveryPending?'A confirmation request is still in progress; waiting for this server’s reply.':!m.fresh&&!m.local?(m.deliveryProblem?'Delivery is being retried ('+m.deliveryProblem+'); approval status is unconfirmed. ':'Waiting for a current authenticated reply; the approval status is unconfirmed.'):m.authorized===false?'Waiting for one-time authorization on this server.':m.authorized===null?'Waiting for the server’s first authenticated reply.':!m.backupReady?'Authorization received. Backup access needs a device step on this server.':m.ready?'This server completed its setup.':'Authorized; connections, emergency approvals or background verification are still in progress.';
  nativeRow(holder,m.name+(m.local?' · this server':''),description+(!m.local&&m.checkedAt?' Last confirmed reply: '+new Date(m.checkedAt*1000).toLocaleString()+'.':''),actions);
 }
 if(a.authorized){const ready=members.filter(m=>m.authorized&&m.ready&&(m.local||m.fresh)).length;$('setupProgress').textContent=ready+' of '+members.length+' servers ready. '+(ready===members.length?'Setup is complete.':a.running?'Setup is running; waiting for the steps listed below.':'Select Finish setup to refresh outstanding replies and verification.');}
 if(policy){const p=document.createElement('p');p.className='muted break';p.textContent='Plan '+policy.id+' · '+policy.members.length+' explicitly reviewed server(s). Permissions: connections, signed primary/Magic routes, Global-only emergency reads and confirmed duplicate cleanup. Local values, secret edits, administrator creation, hardware policy and OAuth operations are outside this authorization.';holder.append(p);}
}
async function continueSetupDiscovery(ticket){
 if(automaticSetupBusy||ticket!==generation)return;
 clearTimeout(automaticSetupTimer);automaticSetupBusy=true;
 try{
  const r=await api('nativeSetupPreview',{},ticket);ticket=generation;
  if(r.complete){automaticSetupPreview=r.policy;automaticSetupNotice='';}
  else{
   automaticSetupNotice='Found '+(r.found??'?')+' servers; confirmed '+(r.checked??0)+' connections. '+(r.message||'Waiting for background discovery.');
   for(const w of r.waiting||[])automaticSetupNotice+=' '+w.server+' · '+w.step+': '+w.message+(w.retryAt?' Next retry after '+new Date(w.retryAt*1000).toLocaleTimeString()+'.':'');
   if(!r.blocked)automaticSetupTimer=setTimeout(()=>continueSetupDiscovery(ticket),5000);
  }
 }catch(e){if(ticket===generation){automaticSetupNotice='Discovery progress could not be read: '+e.message+' Confirmed work is retained. Retrying automatically.';automaticSetupTimer=setTimeout(()=>continueSetupDiscovery(ticket),15000);}}
 finally{automaticSetupBusy=false;renderAutomaticSetup();}
}
run($('setupFinish'),async ticket=>{
 if(automaticSetupBusy)return;
 const a=snapshot?.native?.automaticSetup||{};
 if(a.authorized){automaticSetupBusy=true;try{const r=await api('nativeSetupRun',{},ticket);snapshot.native.automaticSetup=r.automaticSetup;message('Setup requested across the approved servers. Progress will update here.');}finally{automaticSetupBusy=false;renderAutomaticSetup();}return;}
 const p=a.policy||automaticSetupPreview;
 if(p){await approveMailboxEntry({operation:{kind:'nativeSetupAuthorize',policy:p},summary:'Authorize only the displayed '+p.members.length+' server(s) for full-mesh connections, approved routes, reciprocal Global-only emergency reads and confirmed obsolete-grant cleanup. Credentials stay private. Browser passkey steps remain on their own installation.'});automaticSetupPreview=null;renderAutomaticSetup();return;}
 await continueSetupDiscovery(ticket);

});
run($('setupStop'),()=>{const a=snapshot?.native?.automaticSetup;if(!a?.policy)return;return approveMailboxEntry({operation:{kind:'nativeSetupStop',id:a.policy.id},summary:'Stop this server’s automatic setup and invalidate its private setup capabilities. Existing connections and emergency approvals are retained.'});});
