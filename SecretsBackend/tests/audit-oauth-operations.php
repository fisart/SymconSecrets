<?php
// Real encrypted peers: sharing an access-token result must not share its refresh authority.
$edit(0,['Audit shared refresh'],'"SHARED-ROTATING-CANARY"','create');$edit(0,['Audit OAuth'],'{"access_token":"old"}','create');$pump();
$configuration=['kind'=>'nativeProvider','id'=>'','name'=>'Audit executor','endpoint'=>'https://oauth.example.test/token','clientId'=>'client','authentication'=>'none','secretScope'=>'local','secretPath'=>[],'refreshScope'=>'global','refreshPath'=>['Audit shared refresh'],'resultScope'=>'global','resultPath'=>['Audit OAuth'],'accessField'=>'access_token','automatic'=>false,'idempotencySupported'=>true,'idempotencyHeader'=>'Idempotency-Key'];
foreach([0,1]as$i)$no(static fn()=>$operation($i,$configuration),'A replicated refresh predecessor was accepted on a paired executor.');
$s=$stores[0];$s->change($s->head(),SecretsBackendCodec::uuid(),hash('sha256','local-oauth-executor'),static function($x){SecretsBackendTree::edit($x['vault']['local'],['Executor token'],SecretsBackendTree::parse('"LOCAL-ROTATING-CANARY"'),'create');return $x;});
$configuration['refreshScope']='local';$configuration['refreshPath']=['Executor token'];$provider=$operation(0,$configuration);$operation(0,['kind'=>'nativeRefresh','id'=>$provider['id']]);
// A pre-update unsafe provider must stop, rather than dispatch during a partition.
$old=$stores[0]->read()['state']['native']['providers'][$provider['id']];$old['refreshScope']='global';$old['refreshPath']=['Audit shared refresh'];$old['activeEffect']=null;$old['automatic']=true;$old['nextAt']=1;$old['targetGlobalTreeId']=$stores[1]->read()['state']['native']['globalTreeId'];
$stores[1]->change($stores[1]->head(),SecretsBackendCodec::uuid(),hash('sha256','old-global-oauth'),static function($x)use($old){$x['native']['providers'][$old['id']]=$old;return $x;});
$calls=0;$transport=static function($effect)use(&$calls){$calls++;return ['status'=>200,'body'=>'{"access_token":"SHARED-ACCESS-NEW","refresh_token":"LOCAL-ROTATED-NEW"}'];};
$blockedBefore=$blockPrimary;$blockPrimary=true;
$ok((new SecretsBackendNativeEffects($stores[1],$transport))->tick()['status']==='IDLE','Unsafe old provider ran during partition.');
$ok((new SecretsBackendNativeEffects($stores[0],$transport))->tick()['status']==='COMPLETE'&&$calls===1,'Local refresh executor did not perform exactly one effect.');$blockPrimary=$blockedBefore;$pump();
foreach($stores as$i=>$store){$state=$store->read()['state'];$global=SecretsBackendCodec::json($state['vault']['global']);$ok(str_contains($global,'SHARED-ACCESS-NEW')&&!str_contains($global,'LOCAL-ROTATING-CANARY')&&!str_contains($global,'LOCAL-ROTATED-NEW'),'Refresh credential entered shared Global history.');if($i!==0)$no(static fn()=>SecretsBackendTree::at($state['vault']['local'],['Executor token']),'A peer acquired the executor Local credential.');}
echo "PASS OAuth encrypted-peer partition: shared predecessor refused, old unsafe executor paused, one Local rotation, shared access result and private refresh credentials\n";
