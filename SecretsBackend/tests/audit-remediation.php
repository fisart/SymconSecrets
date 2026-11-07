<?php
declare(strict_types=1);
require_once __DIR__.'/Fixture.php';
require_once __DIR__.'/../NativeOperations.php';
$roots=[];$checks=0;
$ok=static function(bool $v,string $m)use(&$checks){secExpect($v,$m);$checks++;};
$fixture=static function()use(&$roots):array{
 $root=sys_get_temp_dir().'/sec-audit-'.bin2hex(random_bytes(8));$roots[]=$root;$binding=['origin'=>'https://audit.example.test','frontend'=>1,'backend'=>2,'privateACLConfirmed'=>true];$uuid=SecretsBackendCodec::uuid();SecretsBackendNativeStore::initialize($root.'/data',$root.'/keys',$binding,[],$uuid,secGenesis($binding,$uuid));$s=new SecretsBackendNativeStore($root.'/data',$root.'/keys','audit');$s->recover();$ops=new SecretsBackendNativeOperations($s,new SecretsBackendNativePeer($s,'https://audit.example.test/hook/secrets_peer_2'));$ops->bindSession('session');return [$root,$s,$ops];
};
try{
 [$root,$s,$ops]=$fixture();$state=$s->read()['state'];preg_match('~-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----~',file_get_contents(__DIR__.'/../certificates/mozilla-ca.pem'),$pem);
 $proposal=['kind'=>'nativeHardwareProfile','roots'=>[$pem[0]],'aaguids'=>[str_repeat('1',32)],'allowReenrollmentLock'=>true];$review=$ops->normalize($proposal,$state,false);$head=$s->head();
 foreach(['write','identity','export','reveal']as$key){$enforced=$state;$enforced['policy']['hardware'][$key]=true;secRejectReason(static fn()=>$ops->normalize($proposal,$enforced,false),'enforcement');secRejectReason(static fn()=>$ops->apply($review,$enforced),'enforcement');}
 $enforced=$state;$enforced['policy']['hardware']['identity']=true;
 $app=new SecretsBackendApplication($s,['candidateProfile'=>static fn()=>['changed'=>true]]);
 secRejectReason(static fn()=>(new ReflectionMethod($app,'candidateProfile'))->invoke($app,$enforced),'enforcement');
 secRejectReason(static fn()=>(new ReflectionMethod($app,'apply'))->invoke($app,['kind'=>'configuration','profile'=>['changed'=>true]],$enforced),'enforcement');
 $ok($s->head()===$head,'Rejected hardware replacement changed authority.');
 // Saturate outcome history in one isolated fixture mutation, not 4,112 fsyncs.
 $seed=static function(array $x,int $count):array{$x['operations']['outcomes']=[];for($i=0;$i<$count-1;$i++)$x['operations']['outcomes'][SecretsBackendCodec::uuid()]=['requestDigest'=>hash('sha256',(string)$i),'index'=>'0','result'=>'committed'];$x['operations']['audit']=[];return $x;};
 $s->change($s->head(),SecretsBackendCodec::uuid(),hash('sha256','seed3499'),static fn($x)=>$seed($x,3499));
 $s->change($s->head(),SecretsBackendCodec::uuid(),hash('sha256','ordinary'),static fn($x)=>$x);secRejectReason(static fn()=>$s->change($s->head(),SecretsBackendCodec::uuid(),hash('sha256','refused'),static fn($x)=>$x),'retention');
 $s->change($s->head(),SecretsBackendCodec::uuid(),hash('sha256','seed4112'),static fn($x)=>$seed($x,4112),['action'=>'nativeRotateKey']);
 $before=$s->read()['state'];$first=null;
 for($i=0;$i<40;$i++){$id=SecretsBackendCodec::uuid();$first??=$id;$s->change($s->head(),$id,hash('sha256','recovery'.$i),static fn($x)=>$x,['action'=>$i%2?'nativeBackup':'login']);}
 $ok(count($s->read()['state']['operations']['outcomes'])===4144,'Recovery maintenance was unbounded or unavailable.');$ok(count($s->read()['state']['operations']['recoveryIds'])===32,'Recovery ring exceeded its bound.');$ok($s->operationStatus($first)['result']==='UNKNOWN','Retired recovery outcome was claimed committed.');$ok(SecretsBackendNativeStore::stateDigest($before)===SecretsBackendNativeStore::stateDigest($s->read()['state']),'Recovery bookkeeping changed authority or values.');
 // Verify a real encrypted backup and execute the actual approved compact callback at the ceiling.
 $material=$s->backupMaterial();$key=SecretsBackendCodec::b64(random_bytes(32));$bytes=SecretsBackendNativeBackup::encrypt($s,$key);$uploads=$ops->uploads();$u=$uploads->begin(strlen($bytes),hash('sha256',$bytes));$id=$u['uploadId'];foreach(str_split($bytes,$u['chunkBytes'])as$i=>$chunk)$uploads->chunk($id,$i,SecretsBackendCodec::b64($chunk));$uploads->finish($id);
 $op=$ops->normalize(['kind'=>'nativeCompact','uploadId'=>$id,'recoveryKey'=>$key],$s->read()['state'],false);
 $fault=new ReflectionProperty(SecretsBackendNativeStore::class,'fault');
 $fault->setValue($s,static function($at){if($at==='before_marker')throw new RuntimeException('Interrupted before compaction publication.');});
 secReject(static fn()=>$s->change($s->head(),SecretsBackendCodec::uuid(),hash('sha256','compact-before'),static fn($x)=>$ops->apply($op,$x),['action'=>'nativeCompact']),'Compaction interruption was ignored.');$fault->setValue($s,null);
 $ok(count($s->read()['state']['operations']['outcomes'])===4144,'Unpublished compaction pruned outcomes.');
 $compactId=SecretsBackendCodec::uuid();$fault->setValue($s,static function($at){if($at==='after_marker')throw new RuntimeException('Lost compaction response after publication.');});
 secReject(static fn()=>$s->change($s->head(),$compactId,hash('sha256','compact'),static fn($x)=>$ops->apply($op,$x),['action'=>'nativeCompact']),'Lost-result injection was ignored.');$fault->setValue($s,null);
 $ok($s->operationStatus($compactId)['result']==='COMMITTED','Published compaction lost its exact committed outcome.');
 $ok(count($s->read()['state']['operations']['outcomes'])===512,'Approved compaction did not publish pruning atomically.');
 unset($before,$material,$bytes,$op,$uploads,$u,$review);gc_collect_cycles();
 // Repeated rejections must stop publishing encrypted snapshots after one sample.
 $writes=0;$probe=$s;(new ReflectionProperty(SecretsBackendNativeStore::class,'fault'))->setValue($probe,static function($at)use(&$writes){if($at==='before_marker')$writes++;});$window=intdiv(time(),60);
 $probe->rate('flood',1);$base=$writes;for($i=0;$i<100;$i++){try{$probe->rate('flood',1);}catch(Throwable $e){}$probe->auditRejected(['action'=>'denied']);}
 $ok($writes-$base<=(intdiv(time(),60)===$window?1:3),'Rate-limited rejection flood kept publishing the vault.');
 // Recover Local values and all concurrent variants without a source server.
 $a=SecretsBackendCodec::uuid();$b=SecretsBackendCodec::uuid();$model=['format'=>'SECB.SharedGlobal.1','clock'=>[$a=>'1',$b=>'1'],'records'=>[SecretsBackendCodec::b64('["Token"]')=>['path'=>['Token'],'versions'=>[$a=>['counter'=>'1','node'=>['type'=>'string','value'=>'LEFT-CANARY']],$b=>['counter'=>'1','node'=>['type'=>'string','value'=>'RIGHT-CANARY']]]]]];SecretsBackendSharedGlobal::validate($model);
 $backup=['state'=>['native'=>['sharedGlobal'=>$model],'vault'=>['global'=>SecretsBackendSharedGlobal::view($model)['node'],'local'=>SecretsBackendTree::parse('{"Local":"LOCAL-CANARY"}')]]];$recovered=SecretsBackendNativeBackup::localRecoveryNode($backup);$encoded=SecretsBackendCodec::json(SecretsBackendTree::value($recovered));
 $ok(str_contains($encoded,'LEFT-CANARY')&&str_contains($encoded,'RIGHT-CANARY')&&str_contains($encoded,'LOCAL-CANARY')&&str_contains($encoded,'Global causal history'),'Conflict-preserving recovery omitted values or provenance.');
 // Exercise the encrypted upload/review/apply path with the source unavailable.
 $s->change($s->head(),SecretsBackendCodec::uuid(),hash('sha256','conflict-source'),static function($x)use($backup,$model){$x['native']['sharedGlobal']=$model;$x['vault']=$backup['state']['vault']+['revision'=>$x['vault']['revision']];return $x;});
 $source=$s->read()['state'];$bytes=SecretsBackendNativeBackup::encrypt($s,$key);$uploads=$ops->uploads();$u=$uploads->begin(strlen($bytes),hash('sha256',$bytes));foreach(str_split($bytes,$u['chunkBytes'])as$i=>$chunk)$uploads->chunk($u['uploadId'],$i,SecretsBackendCodec::b64($chunk));$uploads->finish($u['uploadId']);
 $restore=['kind'=>'nativeRestore','uploadId'=>$u['uploadId'],'recoveryKey'=>$key,'mode'=>'local-copy'];
 secRejectReason(static fn()=>$ops->normalize(array_replace($restore,['mode'=>'replace-values']),$source,false),'unresolved');
 $op=$ops->normalize($restore,$source,false);$s->change($s->head(),SecretsBackendCodec::uuid(),hash('sha256','recover-conflicts'),static fn($x)=>$ops->apply($op,$x));$after=$s->read()['state'];
 $ok($after['vault']['global']===$source['vault']['global']&&$after['identity']===$source['identity']&&$after['pairing']===$source['pairing'],'Local recovery changed shared winners or current authority.');
 $local=SecretsBackendCodec::json($after['vault']['local']);$ok(str_contains($local,'LEFT-CANARY')&&str_contains($local,'RIGHT-CANARY')&&str_contains($local,'LOCAL-CANARY'),'Encrypted conflict backup did not recover all Local variants.');
 echo "PASS audit fixes: enforced hardware profile refusal at review/commit, retention boundaries and bounded recovery, actual encrypted-backup compaction at ceiling, measured bounded rejection writes, complete local conflict variants\n";
}finally{
 $rm=static function($path)use(&$rm){if(is_link($path)||!is_dir($path)){if(file_exists($path)||is_link($path))unlink($path);return;}foreach(scandir($path)as$n)if($n!=='.'&&$n!=='..')$rm($path.'/'.$n);rmdir($path);};foreach($roots as$r)$rm($r);
}
