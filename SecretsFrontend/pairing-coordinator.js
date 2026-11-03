'use strict';
// Browser coordination only. Every vault mutation retains its own exact passkey approval.
let pairCoordinator=null,pairCoordinatorTimer=null;
function pairCoordinatorURL(raw){if(typeof raw!=='string'||raw.length>512)throw Error('Use the complete Secrets URL, up to 512 characters.');const u=new URL(raw);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||!/^\/hook\/secrets_(?:frontend|peer)_[1-9][0-9]*$/.test(u.pathname))throw Error('Choose the complete HTTPS Secrets administration or peer URL of the other platform.');return u;}
function pairCoordinatorDescriptor(d){if(!d||typeof d!=='object')throw Error('The popup did not identify its vault.');const u=pairCoordinatorURL(d.endpoint);for(const k of ['vaultId','treeId'])if(!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(d[k]))throw Error('Invalid vault identity.');if(!/^[1-9][0-9]{0,8}$/.test(d.backend)||u.pathname!=='/hook/secrets_peer_'+d.backend)throw Error('Invalid backend identity.');for(const k of ['signKey','boxKey'])if(typeof d[k]!=='string'||!/^[-_A-Za-z0-9]{43}$/.test(d[k]))throw Error('Invalid public vault key.');return d;}
function pairCoordinatorSame(a,b){return ['vaultId','treeId','backend','signKey','boxKey'].every(k=>a?.[k]===b?.[k]);}
function pairCoordinatorHideManual(){if(!pairCoordinator)return;for(let i=1;i<=4;i++)$('peerStep'+i).hidden=true;$('peerExpired').hidden=true;$('peerResend').hidden=true;$('peerLeaveWizard').hidden=true;for(const button of $('nativePeerList').querySelectorAll('button'))button.disabled=true;}
function pairCoordinatorLostResult(){if(pairCoordinator)pairCoordinatorStop('An approved change committed but its response was lost. Coordination stopped safely. Saved requests remain available; start Connect from here again to review the current connection.');}
function pairCoordinatorApprovalFailed(){if(pairCoordinator?.waiting)pairCoordinatorStop('Approval did not finish. Coordination stopped; check the saved connection before starting again.');}
function pairCoordinatorNavigation(name){if(pairCoordinator&&name!=='nativePeers')pairCoordinatorStop('Guided connection stopped when you left this page. Saved requests remain available under Your connections.');}
function pairCoordinatorStatus(text){$('peerCoordinatorPanel').hidden=false;if(pairCoordinator)$('peerCoordinatorTitle').textContent=(pairCoordinator.mode==='local'?'Connect to ':'Approve connection from ')+pairCoordinator.origin;$('peerCoordinatorStatus').textContent=text;peerFeedback(text);}
function pairCoordinatorSend(action,data={}){const c=pairCoordinator;if(!c||!c.window||c.window.closed)return;c.window.postMessage({type:'SECF.PairCoordinator.1',channel:c.channel,action,data},c.origin);}
function pairCoordinatorStop(text,notify=true){const c=pairCoordinator;if(notify)pairCoordinatorSend('CANCEL');clearTimeout(pairCoordinatorTimer);pairCoordinatorTimer=null;if(c)c.invitation='';pairCoordinator=null;$('peerCoordinatorCancel').hidden=true;$('peerCoordinatorAgain').hidden=false;$('peerCoordinatorOpen').hidden=true;$('peerCoordinatorRetry').hidden=true;$('peerCoordinatorRemoteError').textContent='';pairCoordinatorStatus(text);if(c?.waiting)invalidate();if(snapshot?.native){renderPeerConnections();renderPeerWizard();}}
function pairCoordinatorSchedule(){clearTimeout(pairCoordinatorTimer);if(pairCoordinator)pairCoordinatorTimer=setTimeout(()=>pairCoordinatorPump(),5000);}
function pairCoordinatorRender(){const n=snapshot?.native;if(n){const list=$('peerKnownPlatforms');list.replaceChildren();for(const p of n.peers){const o=document.createElement('option');o.value=p.routes?.endpoints?.[0]||p.descriptor.endpoint;o.label=p.name;list.append(o);}if(!$('peerConnectTarget').value&&n.peers.filter(p=>p.state!=='REVOKED').length===1)$('peerConnectTarget').value=n.peers.find(p=>p.state!=='REVOKED').routes?.endpoints?.[0]||n.peers.find(p=>p.state!=='REVOKED').descriptor.endpoint;}if(pairCoordinator)queueMicrotask(()=>pairCoordinatorPump());}
function pairCoordinatorOpen(){const c=pairCoordinator;if(!c||c.mode!=='local')return;if(c.window&&!c.window.closed&&c.stage!=='opening'){c.window.focus?.();pairCoordinatorStatus('Complete the displayed approval in the popup; this wizard will continue automatically.');return;}const fragment=encoded(new TextEncoder().encode(JSON.stringify({origin:boot.origin,channel:c.channel,issuerEndpoint:snapshot.native.peerEndpoint})));c.openedAt=Date.now();c.window=window.open(c.target+'#secrets-pair='+fragment,'secrets-pair-'+c.channel,'popup,width=640,height=760');$('peerCoordinatorOpen').hidden=!!c.window;pairCoordinatorStatus(c.window?'Opening the other platform’s approval popup. Sign in there if asked.':'Your browser blocked the approval popup. Select Open approval popup to continue.');pairCoordinatorSchedule();}
async function pairCoordinatorBegin(){if(!snapshot?.native)throw Error('Sign in first.');if(!snapshot.native.globalWritable||snapshot.native.remoteHttpsAvailable===false)throw Error('Resolve this platform’s sharing/HTTPS readiness before connecting.');if(pairCoordinator)throw Error('Finish or cancel the current guided connection first.');const u=pairCoordinatorURL($('peerConnectTarget').value.trim());if(u.href===boot.origin+boot.path||u.href===snapshot.native.peerEndpoint)throw Error('Choose another vault, not this one.');
 pairCoordinator={mode:'local',channel:encoded(crypto.getRandomValues(new Uint8Array(32))),origin:u.origin,target:u.href,window:null,stage:'opening',deadline:Date.now()+10*60*1000,waiting:false,busy:false,remote:null,invitation:''};$('peerCoordinatorCancel').hidden=false;$('peerCoordinatorAgain').hidden=true;pairCoordinatorHideManual();pairCoordinatorOpen();
}
function pairCoordinatorSummary(p){return p?{pairingId:p.pairingId,comparison:p.comparison,state:p.state,expired:peerExpired(p)}:null;}
function pairCoordinatorPeer(c){const p=snapshot?.native?.peers.find(p=>p.id===c.remote?.vaultId&&p.state!=='REVOKED')||null;if(p&&!pairCoordinatorSame(p.descriptor,c.remote))throw Error('The other vault’s identity changed. No connection will be removed or approved automatically.');return p;}
async function pairCoordinatorReview(op,text,next){const c=pairCoordinator;if(!c||c.waiting||$('review').open||document.hidden)return;try{window.focus();}catch{}c.waiting=true;c.operation=op.kind;c.after=next;try{await peerReview(op,text);}catch(e){c.waiting=false;throw e;}}
// Called after an already-approved operation finishes. Invitations never enter the clipboard or a URL.
function pairCoordinatorResult(result){const c=pairCoordinator;if(!c||!c.waiting)return false;const invitation=result.invitation;if(c.operation==='nativeInvite'&&!invitation)return false;c.waiting=false;c.stage=c.after;c.operation='';
 if(invitation){c.invitation=invitation;pairCoordinatorSend('INVITATION',{invitation});c.invitation='';$('peerCoordinatorOpen').hidden=false;$('peerCoordinatorOpen').textContent='Show approval popup';c.window.focus?.();pairCoordinatorStatus('Invitation transferred automatically. Confirm the connection in the other platform’s popup.');}
 if(result.pairingSetup?.kind==='request'){c.requested=true;c.invitation='';}
 queueMicrotask(()=>pairCoordinatorPump());return !!invitation;
}
async function pairCoordinatorRefresh(){const c=pairCoordinator;if(!c)return;const progress=await api('nativePairingStatus');if(c!==pairCoordinator)return;Object.assign(snapshot.native,progress);renderPeerConnections();renderPeerWizard();}
async function pairCoordinatorPump(){const c=pairCoordinator;if(!c||c.busy||c.waiting||c.failed)return;
 if(Date.now()>c.deadline){pairCoordinatorStop('Guided connection paused after 10 minutes. Saved server-side requests remain available under Your connections.');return;}
 if(!snapshot?.native){pairCoordinatorStatus('Sign in on this platform to continue the guided connection.');pairCoordinatorSchedule();return;}
 if(!fullAdministration()){pairCoordinatorStop('Use this platform’s usual primary administration address for pairing.');return;}
 if(c.window?.closed&&c.stage!=='sent'&&!(c.mode==='local'&&(c.requested||c.stage==='sharing'))){if(!c.closedAt)c.closedAt=Date.now();if(Date.now()-c.closedAt<5000){pairCoordinatorSchedule();return;}pairCoordinatorStop('The approval popup was closed before its part completed. Saved requests remain available; reopen the guided connection to continue.');return;}
 if(document.hidden){pairCoordinatorSchedule();return;}
 if($('nativePeers').hidden)tab('nativePeers');
 c.busy=true;
 try{
  if(c.mode==='local'&&c.stage==='opening'&&Date.now()-(c.openedAt||Date.now())>15000){pairCoordinatorStatus('Waiting for sign-in in the approval popup. If you are already signed in there, check that this module is updated on both platforms and read any popup message.');$('peerCoordinatorOpen').hidden=false;}
  if(c.mode==='remote'&&c.stage==='hello'){
   if(!document.hidden){pairCoordinatorSend('READY',{descriptor:snapshot.native.peerDescriptor,sharedGlobalSupported:snapshot.native.sharedGlobalSupported===true});try{window.opener?.focus();}catch{}}
   const existing=snapshot.native.peers.find(p=>p.active&&p.state==='ACTIVE'&&p.descriptor.endpoint===c.issuerEndpoint);
   if(existing){if(peerWizardState.peerId!==existing.id)peerWizardResume(existing.id);pairCoordinatorStatus(peerConnectionLabel(existing)+'. Continue in the initiating wizard. Global sharing permissions may need a new approval.');}
   else pairCoordinatorStatus('Waiting for the initiating wizard to send the invitation. No connection has been completed yet.');
  }else if(c.remote){
   await pairCoordinatorRefresh();if(c!==pairCoordinator)return;const p=pairCoordinatorPeer(c);
   if(c.mode==='local'){
    if(c.stage==='prepare'){
     if(p?.active){peerWizardResume(p.id);c.stage='sharing';pairCoordinatorSend('FINISHED');pairCoordinatorStatus('This connection is already approved. Checking sharing automatically.');}
     else if(p){pairCoordinatorStatus('Approve replacing the previous connection with one shared Global vault. The other platform’s popup will handle its matching approval too.');await pairCoordinatorReview({kind:'nativeRevokePeer',peerId:p.id},'Replace this exact connection with shared Global editing. Existing secrets are retained. Conflicting values will need your choice.','invite');}
     else c.stage='invite';
    }
    if(c.stage==='invite'){pairCoordinatorStatus('Confirm creation of the invitation here. The wizard sends it directly to the other platform.');await pairCoordinatorReview({kind:'nativeInvite'},'Create a one-use invitation for '+c.origin+'. It will be sent only to the selected approval popup. Both vaults must still approve the exact pairing.','request');}
    if(c.stage==='request'&&c.requested&&p){
     if(p.pairingId!==c.requested.pairingId||p.comparison!==c.requested.comparison||p.invitationId!==peerWizardState.invitationId)throw Error('The two platforms did not confirm the same invitation and connection code. Cancel and start again.');
     if(p.state==='PENDING_APPROVAL'){peerWizardState.peerId=p.id;peerWizardState.pairingId=p.pairingId;peerWizardState.comparison=p.comparison;pairCoordinatorStatus('The other platform approved its request. Confirm the final connection here; the wizard has matched both connection codes.');await pairCoordinatorReview({kind:'nativeAcceptPair',peerId:p.id},'The selected HTTPS approval popup and this vault report the same connection code: '+p.comparison+'. Approve this exact platform and sharing scope.','sharing');}
    }
    if(c.stage==='sharing'){
     if(p&&!peerWizardState.role)peerWizardResume(p.id);
     pairCoordinatorStatus(peerWizardStep===6?'Complete. Global is shared across both platforms. Local secrets remain private.':peerDeliveryBlocked(p)?'Pairing approved · delivery blocked. The connection is not ready. Use Connection check below.':'Pairing approved. Waiting for verified data exchange before this connection is Ready.');
     if(peerWizardStep===6){pairCoordinatorSend('FINISHED');clearTimeout(pairCoordinatorTimer);pairCoordinator=null;$('peerCoordinatorCancel').hidden=true;$('peerCoordinatorAgain').hidden=false;$('peerCoordinatorRetry').hidden=true;renderPeerConnections();return;}
    }
   }else{
    if(c.stage==='prepare'){
     if(p){pairCoordinatorStatus('Confirm removal of this platform’s previous connection to '+c.origin+' before starting the replacement.');await pairCoordinatorReview({kind:'nativeRevokePeer',peerId:p.id},'Replace this exact previous connection with the one requested by '+c.origin+'. Received copies are retained; your own secrets stay unchanged.','pair');}
     else c.stage='pair';
    }
    if(c.stage==='pair'&&c.invitation&&!document.hidden){const invitation=c.invitation;pairCoordinatorStatus('Confirm connection to '+c.origin+'. The initiating wizard will finish the remaining steps automatically.');await pairCoordinatorReview({kind:'nativePair',invitation,name:('Platform '+c.origin).slice(0,80)},'Request sharing with the initiating vault at '+c.origin+'. Both platforms may edit one shared Global vault. Conflicting versions are retained; Local secrets remain private.','delivery');}
    if(c.stage==='delivery'&&p){
     if(!c.attempted){c.attempted=true;const progress=await api('nativeRetryPeerDelivery',{peerId:p.id,pairingId:p.pairingId});if(c!==pairCoordinator)return;Object.assign(snapshot.native,progress);}
     const current=pairCoordinatorPeer(c),queued=snapshot.native.outbox.some(j=>j.receiverId===p.id&&j.kind==='PAIR_REQUEST');
     if(queued){pairCoordinatorSend('PROGRESS',{delivery:current.delivery,expired:peerExpired(current)});pairCoordinatorStatus('Your approval is saved. Delivering the request to the initiating platform.');renderPeerWizard();}
     else{pairCoordinatorSend('REQUESTED',{pairingId:current.pairingId,comparison:current.comparison});c.stage='sent';pairCoordinatorStatus('This platform’s part is complete. Returning to the initiating wizard.');try{window.opener?.focus();}catch{}window.close();}
    }
   }
  }
 }catch(error){if(error.name==='AbortError')return;if(c===pairCoordinator){pairCoordinatorStatus('Guided connection paused: '+error.message);if(c.mode==='remote')pairCoordinatorSend('ERROR',{message:String(error.message).slice(0,240)});c.failed=true;}}
 finally{c.busy=false;if(c===pairCoordinator&&!c.failed)pairCoordinatorSchedule();}
}
window.addEventListener('message',event=>{const c=pairCoordinator,m=event.data;if(!c||event.origin!==c.origin||event.source!==c.window||!m||m.type!=='SECF.PairCoordinator.1'||m.channel!==c.channel||typeof m.action!=='string'||!m.data||typeof m.data!=='object')return;
 try{if(JSON.stringify(m).length>24000)return;
  if(m.action==='CANCEL'){pairCoordinatorStop('The guided connection was cancelled. Saved requests remain available.',false);return;}
  if(c.mode==='local'&&m.action==='ERROR'){pairCoordinatorStatus('The other platform paused: '+String(m.data.message||'Approval could not finish.').slice(0,240)+' Cancel this guided connection and start again when corrected. Saved requests remain available.');c.failed=true;return;}
  if(c.mode==='local'&&m.action==='READY'&&c.stage==='opening'){
   if(m.data.sharedGlobalSupported!==true)throw Error('Update the Secrets module on both platforms before merging Global secrets.');
   const d=pairCoordinatorDescriptor(m.data.descriptor),u=pairCoordinatorURL(d.endpoint);if(u.origin!==c.origin||d.vaultId===snapshot.native.info.vaultId)throw Error('The popup did not identify the selected platform.');
   if(c.target.includes('/hook/secrets_peer_')&&d.endpoint!==c.target)throw Error('The popup returned a different backend.');
   c.remote=d;c.stage='prepare';pairCoordinatorSend('HELLO',{descriptor:snapshot.native.peerDescriptor,sharedGlobalSupported:snapshot.native.sharedGlobalSupported===true});
  }else if(c.mode==='remote'&&m.action==='HELLO'&&c.stage==='hello'){
   if(m.data.sharedGlobalSupported!==true)throw Error('Update the Secrets module on both platforms before merging Global secrets.');
   const d=pairCoordinatorDescriptor(m.data.descriptor);if(d.endpoint!==c.issuerEndpoint||new URL(d.endpoint).origin!==c.origin||d.vaultId===snapshot.native.info.vaultId)throw Error('The initiating vault address changed.');c.remote=d;c.stage='waiting-invitation';
  }else if(c.mode==='remote'&&m.action==='INVITATION'&&c.stage==='waiting-invitation'){
   if(typeof m.data.invitation!=='string'||!m.data.invitation.startsWith('SECBPAIR1.')||m.data.invitation.length>16384)throw Error('Invalid invitation handoff.');
   // Decode only to check browser handoff identity; the backend verifies the signature and proof.
   const invitation=JSON.parse(new TextDecoder().decode(binary(m.data.invitation.slice(10))));if(invitation.scope!=='shared-global-v1')throw Error('Use a new shared Global invitation from the updated module.');if(!pairCoordinatorSame(invitation.issuer,c.remote))throw Error('The invitation belongs to another vault.');
   c.invitation=m.data.invitation;c.stage='prepare';
  }else if(c.mode==='local'&&m.action==='REQUESTED'&&c.stage==='request'){
   if(!/^[a-f0-9-]{36}$/.test(m.data.pairingId)||!/^([A-F0-9]{5} ){3}[A-F0-9]{5}$/.test(m.data.comparison))return;c.requested={pairingId:m.data.pairingId,comparison:m.data.comparison};$('peerCoordinatorOpen').hidden=true;$('peerCoordinatorRemoteError').textContent='';$('peerCoordinatorRetry').hidden=true;
  }else if(c.mode==='local'&&m.action==='PROGRESS'&&c.stage==='request'){
   const d=m.data.delivery;$('peerCoordinatorRemoteError').textContent=d?.problem==='certificate'?'The other Symcon client could not verify HTTPS while delivering its approved request. '+peerCertificateHelp(d):d?.problem?'The other platform reports a delivery problem: '+String(d.problem).slice(0,40)+'. Its approval has not arrived here yet.':'The other platform is delivering its approved request.';$('peerCoordinatorRetry').hidden=false;
  }else if(c.mode==='remote'&&m.action==='RETRY'&&c.stage==='delivery'){c.attempted=false;c.failed=false;}
  else if(c.mode==='remote'&&m.action==='FINISHED'){pairCoordinatorStop('Connection already established. Continue in the initiating wizard.',false);window.close();return;}
  else return;
  queueMicrotask(()=>pairCoordinatorPump());
 }catch{pairCoordinatorStatus('Guided connection paused: the handoff did not match the selected vault. Cancel and start again.');if(c.mode==='remote')pairCoordinatorSend('ERROR',{message:'The handoff did not match the selected vault.'});c.failed=true;}
});
run($('peerConnectHere'),pairCoordinatorBegin);run($('peerCoordinatorOpen'),pairCoordinatorOpen);run($('peerCoordinatorRetry'),()=>{if(pairCoordinator)pairCoordinator.failed=false;pairCoordinatorSend('RETRY');pairCoordinatorStatus('Retry requested on the other platform. Waiting for its delivery result.');});
run($('peerCoordinatorAgain'),()=>{$('peerCoordinatorPanel').hidden=true;$('peerConnectTarget').value='';peerWizardStart('');});
run($('peerCoordinatorCancel'),()=>pairCoordinatorStop('Guided connection cancelled. Saved requests remain available under Your connections.'));
for(const event of ['click','cancel'])$(event==='click'?'cancelReview':'review').addEventListener(event,()=>{if(pairCoordinator?.waiting)pairCoordinatorStop('Approval cancelled. No automatic replacement or pairing will continue.');},{capture:true});
document.addEventListener('visibilitychange',()=>{if(document.hidden&&pairCoordinator?.waiting&&!ceremonyActive)pairCoordinatorStop('An approval was interrupted when the window was hidden. Coordination stopped safely; saved requests remain available.');else if(!document.hidden&&pairCoordinator)pairCoordinatorPump();});
window.addEventListener('pagehide',()=>{const c=pairCoordinator;if(c&&c.stage!=='sent')pairCoordinatorSend('CANCEL');if(c)c.invitation='';clearTimeout(pairCoordinatorTimer);pairCoordinator=null;});
// The fragment carries public routing information and a random channel, never an invitation or token.
if(location.hash.startsWith('#secrets-pair=')){
 try{if(location.hash.length>2048)throw Error('Oversized guided connection launch.');const launch=JSON.parse(new TextDecoder().decode(binary(location.hash.slice(14))));const origin=new URL(launch.origin);if(origin.protocol!=='https:'||origin.origin!==launch.origin||!/^[-_A-Za-z0-9]{43}$/.test(launch.channel)||!window.opener||pairCoordinatorURL(launch.issuerEndpoint).origin!==launch.origin)throw Error('Invalid guided connection launch.');
  pairCoordinator={mode:'remote',origin:launch.origin,channel:launch.channel,issuerEndpoint:launch.issuerEndpoint,window:window.opener,stage:'hello',deadline:Date.now()+10*60*1000,waiting:false,busy:false,remote:null,invitation:''};
  history.replaceState(null,'',boot.path);pairCoordinatorSchedule();
 }catch{history.replaceState(null,'',boot.path);message('The guided connection link is invalid. Start again from the initiating platform.',true);}
}
