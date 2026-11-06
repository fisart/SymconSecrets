<?php
declare(strict_types=1);
require_once __DIR__.'/BootstrapFixture.php';
$GLOBALS['moduleIDs']=[5500=>SecretsBackend::FRONTEND,5501=>'{52165EDD-B2C0-40EC-8A59-42A97319B6E2}',700=>'{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}'];
$hooks=new IPSModule(700);$hooks->properties['Hooks']='[]';$front=new SecretsFrontend(5500);$front->Create();$back=new SecretsBackend(5501);$back->Create();
$root=str_replace('\\','/',sys_get_temp_dir()).'/sec-folder-editor-'.bin2hex(random_bytes(8));
$request=['origin'=>'https://secrets.example.test','cookie'=>'','csrf'=>'','remote'=>'folder-test'];
$invoke=static function(string $action,array $data=[])use($front,&$request):array{
    $r=(new ReflectionMethod(SecretsFrontend::class,'gateway'))->invoke($front,['action'=>$action,'data'=>$data]+$request);
    if($r['status']!==200)throw new RuntimeException($action.': '.json_encode($r));return json_decode(json_encode($r),true)['data'];
};
try{
    $key=secKey();$login=secBootstrapInitialize($front,$request,$key,['backend'=>5501,'portal'=>0,'documentation'=>0,'theme'=>'system','vaultDirectory'=>$root.'/data','keyDirectory'=>$root.'/keys','addPortalLink'=>false,'debugEnabled'=>false,'privateACLConfirmed'=>true,'persistenceConfirmed'=>true]);
    $request['cookie']=explode(';',$login['cookie'])[0];$request['csrf']=$login['data']['csrf'];$counter=1;
    $approved=static function(array $op)use($invoke,$key,&$counter):array{$p=$invoke('prepare',['operation'=>$op]);return $invoke('approve',['challengeId'=>$p['challengeId'],'credential'=>secAssertion($key,$p['options']['challenge'],++$counter)]);};
    $revision=static fn():string=>$invoke('session')['revision'];
    $approved(['kind'=>'save','scope'=>'global','path'=>['Parent'],'revision'=>$revision(),'mode'=>'create','json'=>'{"Empty":{},"Taken":{},"Full":{"Password":"FOLDER-SECRET-CANARY","EmptyObject":{},"EmptyList":[],"Number":1.0,"False":false}}']);
    $store=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);
    $rename=['kind'=>'rename','scope'=>'global','path'=>['Parent','Empty'],'revision'=>$revision(),'newName'=>'Renamed'];
    $cookie=$request['cookie'];$request['cookie']='';secReject(static fn()=>$invoke('prepare',['operation'=>$rename]),'Unauthenticated folder rename accepted.');$request['cookie']=$cookie;
    $csrf=$request['csrf'];$request['csrf']='wrong';secReject(static fn()=>$invoke('prepare',['operation'=>$rename]),'Folder rename accepted invalid CSRF.');$request['csrf']=$csrf;
    $before=$store->read()['state'];$approved($rename);$after=$store->read()['state'];
    secExpect(SecretsBackendTree::at($after['vault']['global'],['Parent','Renamed'])===['type'=>'object','entries'=>[]],'Empty folder rename did not preserve its type.');
    secReject(static fn()=>SecretsBackendTree::at($after['vault']['global'],['Parent','Empty']),'Rename retained the old folder.');
    secExpect($after['stream']['globalRevision']===SecretsBackendCodec::increment($before['stream']['globalRevision']),'Folder rename did not advance global replication.');
    foreach([['path'=>[],'newName'=>'Root'],['path'=>['Parent','Renamed'],'newName'=>'Taken'],['path'=>['Parent','Renamed'],'newName'=>'__reserved'],['path'=>['Parent','Full','Password'],'newName'=>'Scalar'],['path'=>['Parent','Renamed'],'revision'=>'0']] as $bad){secReject(static fn()=>$approved(array_replace($rename,['revision'=>$revision()],$bad)),'Invalid folder rename accepted.');}
    $original=SecretsBackendTree::at($after['vault']['global'],['Parent','Full']);
    $p=$invoke('prepare',['operation'=>array_replace($rename,['path'=>['Parent','Full'],'revision'=>$revision(),'newName'=>'Preserved'])]);
    secExpect(!str_contains(json_encode($p),'FOLDER-SECRET-CANARY'),'Rename preview exposed folder values.');
    $invoke('approve',['challengeId'=>$p['challengeId'],'credential'=>secAssertion($key,$p['options']['challenge'],++$counter)]);
    secExpect(SecretsBackendTree::at($store->read()['state']['vault']['global'],['Parent','Preserved'])===$original,'Folder rename changed typed contents.');
    $approved(['kind'=>'delete','scope'=>'global','path'=>['Parent','Renamed'],'revision'=>$revision()]);
    secReject(static fn()=>SecretsBackendTree::at($store->read()['state']['vault']['global'],['Parent','Renamed']),'Empty folder deletion failed.');
    // An approval cannot rename a newer version of either the folder or its siblings.
    $p=$invoke('prepare',['operation'=>array_replace($rename,['path'=>['Parent','Preserved'],'revision'=>$revision(),'newName'=>'Stale'])]);
    $approved(['kind'=>'save','scope'=>'local','path'=>['LocalEmpty'],'revision'=>$revision(),'mode'=>'create','json'=>'{}']);
    secReject(static fn()=>$invoke('approve',['challengeId'=>$p['challengeId'],'credential'=>secAssertion($key,$p['options']['challenge'],++$counter)]),'Stale folder rename approval committed.');
    $current=$store->read();$store->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','folder-hardware-on'),static function($s){$s['policy']['hardware']['write']=true;return $s;});
    secReject(static fn()=>$approved(array_replace($rename,['path'=>['Parent','Preserved'],'revision'=>$revision(),'newName'=>'HardwareBypass'])),'Rename bypassed hardware write policy.');
    $current=$store->read();$treeId=SecretsBackendCodec::uuid();$store->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','folder-owned-fixture'),static function($s)use($treeId){$s['policy']['hardware']['write']=false;$s['native']['globalWritable']=false;$s['native']['trees'][$treeId]=['owner'=>$s['native']['vaultId'],'frozen'=>false,'revision'=>'0','epoch'=>'1','node'=>SecretsBackendTree::parse('{"Empty":{}}'),'subscribers'=>[]];return $s;});
    secReject(static fn()=>$approved(array_replace($rename,['path'=>['Parent','Preserved'],'revision'=>$revision(),'newName'=>'FrozenBypass'])),'Frozen global tree was renamed.');
    $approved(['kind'=>'rename','scope'=>'local','path'=>['LocalEmpty'],'revision'=>$revision(),'newName'=>'LocalRenamed']);
    $approved(['kind'=>'delete','scope'=>'local','path'=>['LocalRenamed'],'revision'=>$revision()]);
    $shared=['kind'=>'nativeSharedRename','treeId'=>$treeId,'path'=>['Empty'],'revision'=>'0','newName'=>'OwnedRenamed'];
    $approved($shared);secExpect(SecretsBackendTree::at($store->read()['state']['native']['trees'][$treeId]['node'],['OwnedRenamed'])['type']==='object','Owned shared folder rename failed.');
    secReject(static fn()=>$approved($shared),'Owned folder rename accepted a stale revision.');
    $current=$store->read();$store->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256','folder-freeze-owned'),static function($s)use($treeId){$s['native']['trees'][$treeId]['frozen']=true;return $s;});
    secReject(static fn()=>$approved(array_replace($shared,['path'=>['OwnedRenamed'],'revision'=>'1','newName'=>'Frozen'])),'Frozen owned folder renamed.');
    $list=SecretsBackendTree::parse('[{}]');secReject(static function()use(&$list){SecretsBackendTree::rename($list,[0],'Name');},'List positions were converted into folder names.');
    $back->ApplyChanges();secExpect($back->Recover(),'Restart after folder edits failed.');
    $restarted=(new ReflectionMethod(SecretsBackend::class,'nativeStore'))->invoke($back);secExpect(SecretsBackendTree::at($restarted->read()['state']['vault']['global'],['Parent','Preserved'])===$original,'Restart changed the renamed subtree.');
    echo "PASS empty-folder rename/delete, atomic typed subtree preservation, collision/root/stale rejection, session/CSRF/hardware policy, frozen/owned scopes and restart\n";
}finally{
    $remove=static function($p)use(&$remove){if(is_dir($p)&&!is_link($p)){foreach(scandir($p)as$n)if($n!=='.'&&$n!=='..')$remove($p.'/'.$n);rmdir($p);}elseif(file_exists($p)||is_link($p))unlink($p);};if(is_dir($root))$remove($root);
}
