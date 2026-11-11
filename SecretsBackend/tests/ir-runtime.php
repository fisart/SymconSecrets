<?php
declare(strict_types=1);
require_once __DIR__ . '/Fixture.php';
function irBridge(array $args, string $input = ''): string {
    $p = proc_open(array_merge(['python3', __DIR__ . '/anchor_bridge.py'], $args), [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']], $pipes);
    fwrite($pipes[0], $input); fclose($pipes[0]); $out = stream_get_contents($pipes[1]); fclose($pipes[1]); $error = stream_get_contents($pipes[2]); fclose($pipes[2]);
    if (proc_close($p) !== 0) throw new RuntimeException($error); return $out;
}
function irFixture(): array {
    $dir = sys_get_temp_dir() . '/ir-runtime-' . bin2hex(random_bytes(8)); mkdir($dir, 0700);
    $info = SecretsBackendStore::initialize($dir . '/data', $dir . '/keys', 'https://secrets.example.test', 123, 'DELETE');
    file_put_contents($dir . '/provision.json', SecretsBackendCodec::json($info));
    $witness = json_decode(irBridge([$dir . '/anchor', $dir . '/provision.json']), true);
    $settings = $info + $witness + ['signingKeyFile'=>$dir . '/keys/anchor-sign.key'];
    $client = new SecretsBackendAnchorClient($settings, static fn($wire) => irBridge([$dir . '/anchor'], $wire));
    $runtime = SecretsBackendCodec::b64(random_bytes(32));
    $base = new SecretsBackendStore($dir . '/data', $dir . '/keys', $runtime, $client, 'DELETE'); $base->recover();
    $new = new SecretsBackendStore($dir . '/data', $dir . '/keys', SecretsBackendCodec::b64(random_bytes(32)), $client, 'DELETE');
    return [$base,$new,$client,$settings,$runtime,$dir];
}
$mutate = static function ($state) { $state['vault']['global'] = SecretsBackendTree::parse('{"Audit":"PREPARED_CANARY"}'); return $state; };
// The auditor's exact invalidation-first trace must stop before any new advance.
[$base,$new,$client,$settings,$runtime,$dir] = irFixture(); $advances = 0;
$observed = new SecretsBackendAnchorClient($settings, static function ($wire) use ($dir,&$advances) { if (json_decode($wire,true)['request']['operation'] === 'advance') ++$advances; return irBridge([$dir . '/anchor'],$wire); });
$old = new SecretsBackendStore($dir . '/data',$dir . '/keys',$runtime,$observed,'DELETE',static function ($point) use ($new) { if ($point === 'after_prepare') $new->invalidate(); });
$before = $base->head(); secRejectReason(fn() => $old->change($before,SecretsBackendCodec::uuid(),hash('sha256','invalidation-first'),$mutate), 'Runtime is fenced');
secExpect($advances === 0 && SecretsBackendCodec::same($client->call('read',[])['head'],$before), 'Invalidated writer obtained a new external commit.');
$new->recover(); secExpect(SecretsBackendCodec::same($new->head(),$before) && !str_contains(SecretsBackendCodec::json($new->read()['state']['vault']), 'PREPARED_CANARY'), 'Recovery published an uncommitted prepare.');
echo "PASS IR-01 successful invalidation prevents any later fresh witness advance\n";
// The protected advance wins first: invalidation cannot report success inside it.
[$base,$new,$client,$settings,$runtime,$dir] = irFixture(); $busy = false; $externalLock = false;
$old = new SecretsBackendStore($dir . '/data',$dir . '/keys',$runtime,$client,'DELETE',static function ($point) use ($new,$dir,&$busy,&$externalLock) {
    if ($point === 'before_advance') {
        secRejectReason(fn() => $new->invalidate(), 'Runtime transition is busy'); $busy = true;
        $python = "import fcntl,sys\nf=open(sys.argv[1],'rb')\ntry:\n fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\n sys.exit(2)\nexcept BlockingIOError:\n sys.exit(0)\n";
        $p = proc_open(['python3','-c',$python,$dir . '/keys/runtime.lock'], [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']], $pipes);
        foreach ($pipes as $pipe) fclose($pipe); secExpect(proc_close($p) === 0, 'Second process bypassed final advance lock.'); $externalLock = true;
    }
    if ($point === 'after_anchor') $new->invalidate();
});
$before = $base->head(); secRejectReason(fn() => $old->change($before,SecretsBackendCodec::uuid(),hash('sha256','advance-first'),$mutate), 'Runtime is fenced');
secExpect($busy && $externalLock && $client->call('read',[])['head']['index'] === SecretsBackendCodec::increment($before['index']), 'Protected external commit did not establish the expected outcome.');
$new->recover(); secExpect(str_contains(SecretsBackendCodec::json($new->read()['state']['vault']), 'PREPARED_CANARY'), 'Current owner could not recover exact committed data.');
echo "PASS IR-01 protected advance excludes invalidation; only current owner recovers publication\n";
// A lost acknowledgement stays ambiguous and recoverable under the same prepare.
[$base,$new,$client,$settings,$runtime,$dir] = irFixture(); $advances = 0;
$lost = new SecretsBackendAnchorClient($settings, static function ($wire) use ($dir,&$advances) { $reply = irBridge([$dir . '/anchor'],$wire); if (json_decode($wire,true)['request']['operation'] === 'advance') { ++$advances; throw new RuntimeException('lost advance acknowledgement'); } return $reply; });
$old = new SecretsBackendStore($dir . '/data',$dir . '/keys',$runtime,$lost,'DELETE');
secRejectReason(fn() => $old->change($old->head(),SecretsBackendCodec::uuid(),hash('sha256','uncertain-advance'),$mutate), 'lost advance acknowledgement');
$new->invalidate(); $new->recover(); secExpect($advances === 1 && $new->head()['index'] === '1', 'Uncertain commit was replayed or discarded.');
echo "PASS IR-01 lost external acknowledgement recovers without replay or invented cancellation\n";
