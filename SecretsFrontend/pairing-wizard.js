'use strict';
// Only public progress is kept here. Invitations stay in the existing cleared, timed controls.
let peerWizardState={role:'',peerId:'',pairingId:'',invitationId:'',expires:0,requested:false},peerWizardStep=1,peerWizardTimer=null,peerWizardEpoch=0,peerWizardDeadline=0,peerWizardBusy=false;
function peerWizardPause(){clearTimeout(peerWizardTimer);peerWizardTimer=null;}
function peerWizardVisible(){return pageActive&&!document.hidden&&!$('nativePeers').hidden&&!!snapshot?.native;}
function peerStateLabel(state){return ({PENDING_REMOTE:'Waiting for the first platform',PENDING_APPROVAL:'Waiting for your approval',ACTIVE:'Connected',REVOKED:'Removed'})[state]||'Check connection';}
function peerWizardPeer(){const n=snapshot?.native;if(!n)return null;return n.peers.find(p=>peerWizardState.peerId?p.id===peerWizardState.peerId:peerWizardState.invitationId&&p.invitationId===peerWizardState.invitationId)||null;}
function peerWizardSetStep(step){peerWizardStep=step;for(let i=1;i<=6;i++)$('peerStep'+i).hidden=i!==step;[...$('peerSteps').children].forEach((node,i)=>{node.classList.toggle('active',i+1===step);node.classList.toggle('complete',i+1<step);node.setAttribute('aria-current',i+1===step?'step':'false');});$('peerCheckProgress').hidden=step<3;$('peerLeaveWizard').hidden=step===1;}
function peerWizardSchedule(){peerWizardPause();if(!peerWizardVisible()||peerWizardStep<3||peerWizardStep>5||Date.now()>peerWizardDeadline)return;const epoch=peerWizardEpoch;peerWizardTimer=setTimeout(async()=>{if(!peerWizardVisible()||epoch!==peerWizardEpoch||peerWizardStep<3||peerWizardStep>5||Date.now()>peerWizardDeadline)return;if($('review').open||ceremonyActive){peerWizardSchedule();return;}await peerWizardCheck(false);},5000);}
async function peerWizardCheck(manual){if(!peerWizardVisible()||peerWizardBusy)return;const ticket=generation,epoch=peerWizardEpoch;peerWizardBusy=true;peerWizardPause();
 try{const progress=await api('nativePairingStatus',{},ticket);if(epoch!==peerWizardEpoch||!peerWizardVisible()||$('review').open)return;if(!Array.isArray(progress.peers)||!Array.isArray(progress.pairingReceived)||!Array.isArray(progress.outbox)||!Array.isArray(progress.pairingSent))throw Error('Update this module on both platforms before continuing.');Object.assign(snapshot.native,progress);if(manual)peerWizardDeadline=Date.now()+15*60*1000;$('peerProgressMessage').textContent='';$('peerSignInAgain').hidden=true;renderPeerConnections();renderPeerWizard();}
 catch(error){if(ticket===generation&&epoch===peerWizardEpoch&&peerWizardVisible()){$('peerSignInAgain').hidden=false;$('peerProgressMessage').textContent='Automatic checking paused. Select Check progress to retry. Sign in again if your session expired. '+(error.name==='AbortError'?'':error.message);}}
 finally{peerWizardBusy=false;}
}
function peerWizardCommitted(result){peerWizardPause();peerWizardEpoch++;$('peerCompared').checked=false;
 if(result.kind==='invitation')peerWizardState={role:'first',peerId:'',pairingId:'',invitationId:result.invitationId||'',expires:Number(result.expires)||0,requested:false};
 else if(result.kind==='request')peerWizardState={role:'second',peerId:result.peerId,pairingId:result.pairingId,invitationId:'',expires:Number(result.expires)||0,requested:true};
 else if(result.kind==='accepted')peerWizardState={...peerWizardState,role:'first',peerId:result.peerId,pairingId:result.pairingId};
 peerWizardDeadline=Date.now()+15*60*1000;
}
function peerWizardResume(id){const p=snapshot?.native?.peers.find(p=>p.id===id);if(!p)throw Error('Select an existing connection.');invalidate();peerWizardEpoch++;peerWizardState={role:p.pair?.a?.vaultId===snapshot.native.info.vaultId?'first':'second',peerId:p.id,pairingId:p.pairingId,comparison:p.comparison,invitationId:p.invitationId||'',expires:Number(p.expires)||0,requested:true};peerWizardDeadline=Date.now()+15*60*1000;$('peerCompared').checked=false;$('peerProgressMessage').textContent='';renderPeerWizard();}
function peerWizardStart(role){invalidate();peerWizardEpoch++;peerWizardState={role,peerId:'',pairingId:'',invitationId:'',expires:0,requested:false};peerWizardDeadline=Date.now()+15*60*1000;$('peerCompared').checked=false;$('peerProgressMessage').textContent='';peerWizardSetStep(role?2:1);renderPeerWizard();}
function renderPeerWizard(){const n=snapshot?.native;if(!n){peerWizardPause();return;}const primary=boot.origin===(n.primaryOrigin||boot.origin);$('peerWizard').hidden=!primary;$('peerRouteNotice').hidden=primary;if(!primary){peerWizardPause();return;}
 $('peerThisPlatform').textContent='This platform: '+boot.origin+boot.path;
 const canStart=n.globalWritable&&n.remoteHttpsAvailable!==false;$('peerStartFirst').disabled=!canStart;$('peerStartSecond').disabled=!canStart;$('nativeInvite').disabled=!canStart;
 const previous=$('peerResumeSelect').value;nativeSelect('peerResumeSelect',[['','Choose a connection…'],...n.peers.filter(p=>p.state!=='REVOKED').map(p=>[p.id,p.name+' · '+peerStateLabel(p.state)])]);if(previous&&n.peers.some(p=>p.id===previous))$('peerResumeSelect').value=previous;$('peerResume').disabled=!$('peerResumeSelect').value;
 const first=peerWizardState.role==='first';$('peerCreateInvitation').hidden=!first;$('peerUseInvitation').hidden=first;$('peerWaitRequest').hidden=!first;$('peerSendRequest').hidden=first;
 let p=peerWizardPeer(),step=peerWizardStep;
 if(!peerWizardState.role)step=1;
 else if(p){
  if((peerWizardState.pairingId&&p.pairingId!==peerWizardState.pairingId)||(peerWizardState.comparison&&p.comparison!==peerWizardState.comparison)){peerWizardPause();$('peerCompared').checked=false;$('peerAccept').disabled=true;peerWizardSetStep(1);$('peerWizardStatus').textContent='This connection changed. Go back to Step 1 and select the current connection.';return;}
  peerWizardState.comparison=p.comparison;
  if(!peerWizardState.peerId){peerWizardState.peerId=p.id;peerWizardState.pairingId=p.pairingId;$('peerCompared').checked=false;}
  if(p.state==='REVOKED'){peerWizardPause();peerWizardSetStep(1);$('peerWizardStatus').textContent='This connection was removed. Start a new setup or select another connection.';return;}
  if(p.active&&p.state==='ACTIVE'){
   const received=(n.pairingReceived||[]).find(r=>r.id===p.descriptor.treeId&&r.owner===p.id&&r.pairingId===p.pairingId);
   const queued=(n.outbox||[]).filter(j=>j.receiverId===p.id&&['PAIR_REQUEST','PAIR_ACCEPT','SYNC','RESYNC'].includes(j.kind));
   const sent=(n.pairingSent||[]).find(r=>r.peerId===p.id&&r.pairingId===p.pairingId&&r.status==='APPLIED'&&r.treeId===n.globalTreeId&&r.revision===n.globalRevision);
   $('peerIncomingCheck').textContent=received?'✓ Received the other platform’s Global section for this connection.':'Waiting to receive the other platform’s Global section.';
   $('peerOutgoingCheck').textContent=sent&&!queued.length?'✓ The other platform acknowledged this platform’s current Global section.':'Waiting for acknowledgement of this platform’s current Global section.';
   step=received&&sent&&!queued.length&&n.globalWritable?6:5;
   $('peerReadySummary').textContent='The new connection exchanged Global sections successfully with '+new URL(p.descriptor.endpoint).origin+'. Local secrets remain private.';
  }else if(p.state==='PENDING_APPROVAL')step=4;
  else if(p.state==='PENDING_REMOTE')step=(n.outbox||[]).some(j=>j.receiverId===p.id&&j.kind==='PAIR_REQUEST')?3:4;
 }else if(first&&peerWizardState.invitationId)step=3;
 else if(!first&&peerWizardState.requested)step=3;
 else if(step!==3||first)step=2;
 peerWizardSetStep(step);
 $('peerWizardStatus').textContent='Step '+step+' of 6 · '+(first?'First platform':'Second platform')+(p?' · '+peerStateLabel(p.state):'')+(n.globalWritable?'':' · This platform’s Global section is frozen; resolve ownership before starting a new connection.')+(n.remoteHttpsAvailable===false?' · This Symcon PHP runtime has no cURL HTTPS transport. Remote platform sharing is unavailable; check your Symcon PHP configuration.':'');
 $('nativeJoin').disabled=!!p||!n.globalWritable;$('peerRequestNote').textContent=p?'Your request is being delivered automatically. If waiting continues, check that both platforms are online and their HTTPS addresses and certificates work from the other platform. Check the module versions and HTTPS transport on both platforms before creating another request.':'The next popup asks for this platform’s existing passkey.';
 if(step===4&&p){
  if(first&&peerWizardState.invitationId&&p.invitationId===peerWizardState.invitationId&&$('nativeSensitiveDialog').open&&$('nativeSensitiveTitle').textContent==='Step 2 of 6 · Copy the invitation')nativeClearSecrets();
  $('peerApprovalTitle').textContent=first?'First platform: approve this exact second platform':'Return to the first platform to approve';
  $('peerApprovalHelp').textContent=first?'Compare the code below with Step 4 on the second platform. Check its address, tick the box, then select 4 · Review and accept.':'Keep this code visible. Switch to the first platform’s Connections wizard, compare the same code and address there, and select 4 · Review and accept. This window checks automatically when you return.';
  $('peerApprovalIdentity').textContent='Other platform: '+new URL(p.descriptor.endpoint).origin+' · vault '+p.id;
  $('peerComparison').textContent=p.comparison||'Update both platforms to display the connection check code.';$('peerAcceptControls').hidden=!first;$('peerAccept').disabled=!first||!p.comparison||!$('peerCompared').checked;
 }
 if(step>=3&&step<=4&&peerWizardState.expires&&peerWizardState.expires*1000<Date.now()){$('peerProgressMessage').textContent='The invitation or pending request expired. Go back to Step 1 and create a new invitation.';peerWizardPause();return;}
 if(Date.now()>peerWizardDeadline&&step>=3&&step<=5)$('peerProgressMessage').textContent='Automatic checking paused after 15 minutes. Select Check progress to continue.';
 peerWizardSchedule();
}
function renderPeerConnections(){const n=snapshot?.native;if(!n)return;$('nativeDeliveryInfo').textContent=n.queuedJobs+' sharing or background message(s) waiting for delivery.';const holder=$('nativePeerList');holder.replaceChildren();for(const p of n.peers){const actions=[];if(p.state!=='REVOKED'){actions.push(['Open connection wizard',()=>peerWizardResume(p.id)]);if(p.active)actions.push(['Resynchronize global snapshot',()=>review({kind:'nativeResync',peerId:p.id},'Send this platform’s current Global section after checking the receiver’s signed progress.')]);actions.push(['Remove connection',()=>review({kind:'nativeRevokePeer',peerId:p.id},'Stop this exact connection. Received copies already held by the other platform remain there.')]);}nativeRow(holder,p.name+' · '+peerStateLabel(p.state),p.descriptor.endpoint+' · last received '+(p.lastSync||'not yet'),actions);}if(!n.peers.length)holder.textContent='No connections yet. Start with Step 1 above.';}
function peerWizardApprovalText(summary){if(!['nativeInvite','nativePair','nativeAcceptPair'].includes(summary?.kind))return '';const lines=[summary.kind==='nativeInvite'?'Step 2 of 6 · Create the invitation':summary.kind==='nativePair'?'Step 3 of 6 · Request connection':'Step 4 of 6 · Approve connection','Share: each platform’s complete Global section. Local secrets remain private.'];if(summary.peerURL)lines.push('Other platform: '+summary.peerURL);if(summary.peerVault)lines.push('Other vault: '+summary.peerVault);if(summary.comparison)lines.push('Connection check code: '+summary.comparison);return lines.join('\n');}
run($('peerStartFirst'),()=>peerWizardStart('first'));run($('peerStartSecond'),()=>peerWizardStart('second'));run($('peerLeaveWizard'),()=>peerWizardStart(''));run($('peerNewInvitation'),()=>peerWizardStart('first'));
$('peerResumeSelect').addEventListener('change',()=>{$('peerResume').disabled=!$('peerResumeSelect').value;});run($('peerResume'),()=>peerWizardResume($('peerResumeSelect').value));
run($('peerInvitationNext'),()=>{if(!$('nativeInvitation').value.trim().startsWith('SECBPAIR1.'))throw Error('Paste the complete one-use invitation from Step 2 on the first platform.');peerWizardSetStep(3);renderPeerWizard();});
$('peerCompared').addEventListener('change',renderPeerWizard);
run($('peerAccept'),ticket=>{const p=peerWizardPeer();if(!p||peerWizardState.role!=='first'||p.pairingId!==peerWizardState.pairingId||p.comparison!==peerWizardState.comparison||p.state!=='PENDING_APPROVAL'||!p.comparison||!$('peerCompared').checked)throw Error('Compare the code on both platforms and tick the confirmation box first.');return review({kind:'nativeAcceptPair',peerId:p.id},'Step 4 of 6: approve the exact platform and matching connection check code.',ticket);});
run($('peerCheckProgress'),()=>peerWizardCheck(true));
run($('peerSignInAgain'),()=>nativeRelogin('Sign in again, then open Connections and choose Continue an existing connection. Your server-side pairing request remains available.'));
run($('peerResend'),ticket=>{const p=peerWizardPeer();if(!p?.active)throw Error('Wait until both platforms approve the connection.');return review({kind:'nativeResync',peerId:p.id},'Step 5 of 6: verify the receiver’s signed progress and resend this platform’s current Global section.',ticket);});
async function peerWizardOpenSecrets(received,ticket){await load(ticket);const p=peerWizardPeer();if(received&&!p)throw Error('Select a connected platform.');const scope=received?'received:'+p.descriptor.treeId:'global';tab('secrets');if(![...$('scope').options].some(o=>o.value===scope)){message('Refresh Secrets, then select the other platform’s Received section.');return;}$('scope').value=scope;$('scope').dispatchEvent(new Event('change'));}
run($('peerOpenGlobal'),ticket=>peerWizardOpenSecrets(false,ticket));run($('peerOpenReceived'),ticket=>peerWizardOpenSecrets(true,ticket));
$('nativePeersNav').addEventListener('click',()=>{renderPeerWizard();if(peerWizardStep>=3)peerWizardCheck(false);});
document.addEventListener('visibilitychange',()=>{peerWizardPause();if(!document.hidden&&peerWizardVisible())renderPeerWizard();});window.addEventListener('pagehide',peerWizardPause);
peerWizardSetStep(1);
