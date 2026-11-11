<?php
declare(strict_types=1);
require_once __DIR__ . '/Fixture.php';
[$store, $witness, $client, $directory, $info, $runtime] = secFixture();
$checked = false;
$settings = $info + ['signingKeyFile' => $directory . '/keys/anchor-sign.key', 'anchorPublicKey' => SecretsBackendCodec::b64($witness->public), 'anchorKeyId' => $witness->keyId];
$lockedClient = new SecretsBackendAnchorClient($settings, static function ($wire) use ($witness, $directory, &$checked) {
    if (json_decode($wire, true)['request']['operation'] === 'authorize') {
        $python = "import fcntl,sys\nf=open(sys.argv[1],'rb')\ntry:\n fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\n print('INCORRECTLY_ACQUIRED')\nexcept BlockingIOError:\n print('BLOCKED')\n";
        $process = proc_open(['python3', '-c', $python, $directory . '/keys/runtime.lock'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        fclose($pipes[0]); $result = stream_get_contents($pipes[1]); fclose($pipes[1]); $error = stream_get_contents($pipes[2]); fclose($pipes[2]);
        secExpect(proc_close($process) === 0 && trim($result) === 'BLOCKED', 'Competing OS process bypassed grant/transition lock: ' . $error); $checked = true;
    }
    return $witness->transport($wire);
});
$old = new SecretsBackendStore($directory . '/data', $directory . '/keys', $runtime, $lockedClient, 'DELETE');
$validated = $old->read(); $old->authorize('metadata', hash('sha256', 'locked-grant'), $validated, static function ($s): void {});
secExpect($checked, 'OS lock test did not reach final grant.');
$new = new SecretsBackendStore($directory . '/data', $directory . '/keys', SecretsBackendCodec::b64(random_bytes(32)), $client, 'DELETE');
$new->invalidate();
secRejectReason(static fn() => $old->authorize('metadata', hash('sha256', 'old-grant'), $validated, static function ($s): void {}), 'Runtime is fenced');
$new->recover(); secExpect($new->read()['head']['index'] === $validated['head']['index'], 'Runtime transition changed vault state.');
echo "PASS R68 real second-process OS lock excludes runtime transition during final authorization; old worker refused after invalidation\n";
