<?php
declare(strict_types=1);
require_once __DIR__ . '/../NativeStore.php';
require_once __DIR__ . '/Fixture.php';
require_once __DIR__ . '/../Tree.php';
$checks = 0;
$ok = static function (bool $v, string $why) use (&$checks): void { if (!$v) throw new RuntimeException($why); ++$checks; };
$no = static function (callable $fn, string $why) use (&$checks): void { try { $fn(); } catch (Throwable $e) { ++$checks; return; } throw new RuntimeException($why); };
$roots = [];
$fixture = static function () use (&$roots): array {
    $root = sys_get_temp_dir() . '/sec-native-' . bin2hex(random_bytes(8)); $roots[] = $root;
    $paths = ['vaultDirectory' => $root . '/data', 'keyDirectory' => $root . '/keys'];
    $binding = ['origin' => 'https://native.example.test', 'frontend' => 1, 'backend' => 2, 'privateACLConfirmed' => true];
    $id = SecretsBackendCodec::uuid(); SecretsBackendNativeStore::initialize($paths['vaultDirectory'], $paths['keyDirectory'], $binding, [], $id, secGenesis($binding,$id));
    $store = new SecretsBackendNativeStore($paths['vaultDirectory'], $paths['keyDirectory'], 'runtime-a'); $store->recover();
    return [$root, $paths, $store, $binding, $id];
};
try {
    [$root,$paths,$store,$binding,$id] = $fixture(); $initial = $store->read();
    $ok($initial['state']['vault']['revision'] === '0', 'Native genesis incorrect.');
    $operation = SecretsBackendCodec::uuid(); $digest = hash('sha256','request'); $runs = 0;
    $mutate = static function (array $s) use (&$runs): array { ++$runs; $s['vault']['local'] = SecretsBackendTree::parse('{"ASK":{"Pass":"CANARY-NATIVE"}}'); $s['vault']['revision'] = '1'; return $s; };
    $head = $store->change($initial['head'], $operation, $digest, $mutate);
    $ok($store->read()['head'] === $head && $runs === 1, 'Native mutation not committed.');
    $ok($store->change($initial['head'],$operation,$digest,$mutate) === $head && $runs === 1, 'Lost acknowledgement replayed mutation.');
    $no(static fn()=>$store->change($head,$operation,hash('sha256','different'),$mutate),'Changed duplicate operation accepted.');
    $no(static fn()=>$store->change($initial['head'],SecretsBackendCodec::uuid(),$digest,$mutate),'Stale head accepted.');
    foreach (glob($paths['vaultDirectory'].'/*') ?: [] as $file) if (is_file($file)) $ok(!str_contains(file_get_contents($file),'CANARY-NATIVE'),'Plaintext secret on disk.');
    $store->put('challenge','test',['x'=>1],time()+120); $ok($store->get('challenge','test',true)['x']===1,'One-use state missing.');
    $no(static fn()=>$store->get('challenge','test',true),'Consumed state replayed.');
    $store->put('session','session',[],time()+120);
    $new = new SecretsBackendNativeStore($paths['vaultDirectory'],$paths['keyDirectory'],'runtime-b'); $new->recover();
    $no(static fn()=>$store->read(),'Old runtime remained active after restart.');
    $no(static fn()=>$new->get('session','session'),'Restart preserved a session.');
    $before = $new->read();
    $no(static fn()=>$new->authorize('reveal',$digest,$initial,static fn($x)=>null),'Stale exact-snapshot grant accepted.');
    $ok($new->authorize('metadata',$digest,$before,static fn($x)=>null)['result']['status']==='AUTHORIZED','Current exact grant refused.');
    foreach (['after_frame','before_marker','after_marker','after_directory_sync'] as $point) {
        [$r,$p,$s] = $fixture(); $base = $s->read(); $op=SecretsBackendCodec::uuid();
        $fault = new SecretsBackendNativeStore($p['vaultDirectory'],$p['keyDirectory'],'runtime-a',null,static function($where)use($point){if($where===$point)throw new RuntimeException('Injected interruption');});
        $no(static fn()=>$fault->change($base['head'],$op,$digest,$mutate),'Fault did not interrupt.');
        $recovered = new SecretsBackendNativeStore($p['vaultDirectory'],$p['keyDirectory'],'runtime-recovered'); $recovered->recover();
        $current = $recovered->read(); $published = in_array($point,['after_marker','after_directory_sync'],true);
        $ok(($current['state']['vault']['revision']==='1')===$published,'Wrong interruption recovery at '.$point);
        $ok(isset($current['state']['operations']['outcomes'][$op])===$published,'Values/outcome recovery split at '.$point);
    }
    [$r,$p,$s] = $fixture(); $markers=glob($p['vaultDirectory'].'/commit-*.json');sort($markers);file_put_contents(end($markers),'corrupt');
    $no(static fn()=>$s->read(),'Corrupt highest state fell back to old permissions.');
    [$r,$p,$s] = $fixture();unlink($p['keyDirectory'].'/master.key');
    $no(static fn()=>new SecretsBackendNativeStore($p['vaultDirectory'],$p['keyDirectory'],'x'),'Missing master key accepted.');
    $no(static fn()=>SecretsBackendNativeStore::initialize($p['vaultDirectory'],$p['keyDirectory'],$binding,[],$id,secGenesis($binding,$id),true),'Missing key for ciphertext was regenerated.');
    $ok(!file_exists($p['keyDirectory'].'/master.key'),'Missing key was replaced.');
    [$r,$p,$s] = $fixture();$s->invalidate();$candidate=new SecretsBackendNativeStore($p['vaultDirectory'],$p['keyDirectory'],'rejected-runtime');
    $no(static fn()=>$candidate->recover(static function(array $state):void{throw new RuntimeException('Security profile drift');}),'Recovery ignored the pinned-profile validator.');
    $no(static fn()=>$candidate->read(),'Failed recovery nevertheless activated peer/machine access.');
    $ok($candidate->recover() === $candidate->head(),'Corrected explicit recovery could not resume.');
    foreach(['after_frame','before_marker','after_marker','after_directory_sync']as$point){
        $r=sys_get_temp_dir().'/sec-genesis-'.bin2hex(random_bytes(8));$roots[]=$r;$uuid=SecretsBackendCodec::uuid();$admission=secGenesis($binding,$uuid);
        $no(static fn()=>SecretsBackendNativeStore::initialize($r.'/data',$r.'/keys',$binding,[],$uuid,$admission,false,static function($at)use($point){if($at===$point)throw new RuntimeException('Injected genesis interruption');}),'Genesis interruption did not propagate.');
        SecretsBackendNativeStore::initialize($r.'/data',$r.'/keys',$binding,[],$uuid,$admission,true);
        $recovered=new SecretsBackendNativeStore($r.'/data',$r.'/keys','genesis-recovery');$recovered->recover();$state=$recovered->read()['state'];
        $ok(count($state['identity']['credentials'])===1&&isset($state['identity']['credentials'][$admission['registration']['rawId']]),'First usable recovered genesis omitted or changed its administrator.');
        $ok(isset($state['operations']['outcomes'][$admission['operation']])&&$state['operations']['audit'][0]['action']==='bootstrap-genesis','Genesis omitted its correlated audit/outcome.');
    }
    $ok(SecretsBackendNativePlatform::normalize('C:\\Symcon\\data',true)==='C:/Symcon/data','Windows normalization failed.');
    $no(static fn()=>SecretsBackendNativePlatform::normalize('C:/Symcon/../keys',true),'Windows traversal accepted.');
    $no(static fn()=>SecretsBackendNativePlatform::normalize('C:/Symcon/CON',true),'Windows device path accepted.');
    $no(static fn()=>SecretsBackendNativePlatform::paths($root.'/same',$root.'//same/',$root.'/different-kernel'),'Native aliases accepted.');
    echo 'PASS ' . $checks . " native encrypted-journal, injected filesystem-publication interruption, idempotence, fencing, grant, missing-key, corruption and portable-path checks; PHP peak " . memory_get_peak_usage(true) . " bytes\n";
} finally {
    $remove = static function (string $p) use (&$remove): void { if (is_dir($p) && !is_link($p)) { foreach (scandir($p) as $name) if ($name!=='.'&&$name!=='..') $remove($p.'/'.$name); rmdir($p); } elseif (file_exists($p)||is_link($p)) unlink($p); };
    foreach ($roots as $root) $remove($root);
}
