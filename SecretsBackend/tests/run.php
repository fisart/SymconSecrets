<?php
declare(strict_types=1);
require_once __DIR__ . '/Fixture.php';
set_error_handler(static function (int $level, string $message, string $file, int $line): bool { if (!(error_reporting() & $level)) return false; throw new ErrorException($message, 0, $level, $file, $line); });
$tests = 0;
function check(string $name, callable $test): void { $test(); ++$GLOBALS['tests']; echo 'PASS ' . $name . "\n"; }

check('typed values preserve empty objects, arrays and numeric object keys', static function (): void {
    $json = '{"emptyObject":{},"emptyList":[],"0":[false,null,1,1.5,"x"]}'; $tree = SecretsBackendTree::parse($json);
    secExpect(SecretsBackendCodec::json(SecretsBackendTree::value($tree)) === $json, 'Typed roundtrip changed JSON.');
    secReject(static fn() => SecretsBackendTree::parse('{"x":1,"x":2}'), 'Duplicate secret keys accepted.');
    secReject(static fn() => SecretsBackendTree::parse('{"__AUTH__":"bad"}'), 'Reserved field accepted.');
    secReject(static fn() => SecretsBackendTree::at($tree, [0]), 'Numeric object key confused with array index.');
});
check('isolated encrypted storage, signed reads and stale update rejection', static function (): void {
    [$store, $witness, $client, $directory] = secFixture(); $before = $store->read();
    $store->change($before['head'], SecretsBackendCodec::uuid(), hash('sha256', 'write'), static function ($state) { $state['vault']['local'] = SecretsBackendTree::parse('{"Password":"UNIQUE_SECRET_CANARY"}'); return $state; });
    secExpect(!str_contains(file_get_contents($directory . '/data/vault.sqlite'), 'UNIQUE_SECRET_CANARY'), 'Plaintext secret found in SQLite file.');
    secReject(static fn() => $store->change($before['head'], SecretsBackendCodec::uuid(), hash('sha256', 'stale'), static fn($s) => $s), 'Stale write accepted.');
    $witness->offline = true; secReject(static fn() => $store->read(), 'Offline authoritative read accepted.'); $witness->offline = false;
    $witness->tamper = true; secReject(static fn() => $store->read(), 'Tampered signed reply accepted.');
});
check('pending prepare discarded when unanchored; old worker fenced', static function (): void {
    $fail = false; [$store, $witness, $client, $directory] = secFixture(static function ($point) use (&$fail): void { if ($fail && $point === 'after_prepare') throw new RuntimeException('Crash'); });
    $before = $store->read(); $fail = true;
    secReject(static fn() => $store->change($before['head'], SecretsBackendCodec::uuid(), hash('sha256', 'prepare'), static fn($s) => $s), 'Fault injection did not run.');
    $new = new SecretsBackendStore($directory . '/data', $directory . '/keys', SecretsBackendCodec::b64(random_bytes(32)), $client, 'DELETE'); $new->recover();
    secExpect(SecretsBackendCodec::same($new->read()['head'], $before['head']), 'Unanchored state published.');
    secRejectReason(static fn() => $store->authorize('metadata', hash('sha256', 'old'), $before, static function ($current): void {}), 'Runtime is fenced');
});
check('anchored prepare recovered after crash before publication', static function (): void {
    $fail = false; [$store, $witness, $client, $directory] = secFixture(static function ($point) use (&$fail): void { if ($fail && $point === 'after_anchor') throw new RuntimeException('Crash'); });
    $before = $store->read(); $fail = true;
    secReject(static fn() => $store->change($before['head'], SecretsBackendCodec::uuid(), hash('sha256', 'committed'), static fn($s) => $s), 'Fault injection did not run.');
    $new = new SecretsBackendStore($directory . '/data', $directory . '/keys', SecretsBackendCodec::b64(random_bytes(32)), $client, 'DELETE'); $new->recover();
    secExpect($new->read()['head']['index'] === '1', 'Irrevocable decision was lost.');
});
check('lost acquire acknowledgement retries same durable operation', static function (): void {
    [$store, $witness, $client, $directory] = secFixture();
    $new = new SecretsBackendStore($directory . '/data', $directory . '/keys', SecretsBackendCodec::b64(random_bytes(32)), $client, 'DELETE');
    $witness->loseReply = true; secReject(static fn() => $new->recover(), 'Lost reply injection missing.');
    $fence = json_decode(file_get_contents($directory . '/witness.json'), true)['owner']['fence']; $new->recover();
    secExpect(json_decode(file_get_contents($directory . '/witness.json'), true)['owner']['fence'] === $fence, 'Acquire retry advanced fence twice.');
});
check('old complete database backup is rejected by independent witness', static function (): void {
    [$store, $witness, $client, $directory] = secFixture(); copy($directory . '/data/vault.sqlite', $directory . '/old.sqlite');
    $store->change($store->head(), SecretsBackendCodec::uuid(), hash('sha256', 'new'), static fn($s) => $s);
    mkdir($directory . '/restored', 0700); copy($directory . '/old.sqlite', $directory . '/restored/vault.sqlite'); chmod($directory . '/restored/vault.sqlite', 0600);
    $restored = new SecretsBackendStore($directory . '/restored', $directory . '/keys', SecretsBackendCodec::b64(random_bytes(32)), $client, 'DELETE');
    secReject(static fn() => $restored->recover(), 'Stale backup reactivated administrator state.');
});
check('paused old publisher cannot overwrite a newer runtime and commit', static function (): void {
    $next = null; $run = false; $client = null; $directory = '';
    [$store, $witness, $client, $directory] = secFixture(static function ($point) use (&$run, &$next, &$client, &$directory): void {
        if (!$run || $point !== 'after_anchor') return;
        $run = false;
        $next = new SecretsBackendStore($directory . '/data', $directory . '/keys', SecretsBackendCodec::b64(random_bytes(32)), $client, 'DELETE');
        $next->recover();
        $next->change($next->head(), SecretsBackendCodec::uuid(), hash('sha256', 'new-runtime-write'), static fn($s) => $s);
    });
    $run = true;
    secReject(static fn() => $store->change($store->head(), SecretsBackendCodec::uuid(), hash('sha256', 'paused-old-write'), static fn($s) => $s), 'Old publisher overwrote a newer runtime.');
    secExpect($next instanceof SecretsBackendStore && $next->read()['head']['index'] === '2', 'New runtime state was not retained.');
});
check('WebAuthn registration, login, bound change, masked list and record reveal', static function (): void {
    [$store] = secFixture(); $app = new SecretsBackendApplication($store, ['origin' => 'https://secrets.example.test', 'frontend' => 123, 'backend' => 456, 'hardwareRoots' => '', 'hardwareAAGUIDs' => []]);
    $request = ['origin' => 'https://secrets.example.test', 'cookie' => '', 'csrf' => '', 'remote' => '127.0.0.1']; $key = secKey();
    $code = $app->beginEnrollment('Test owner', false); $begin = secOptions($app->handle('enrollmentOptions', ['code' => $code], $request));
    $app->handle('enrollmentVerify', ['challengeId' => $begin['challengeId'], 'credential' => secRegistration($key, $begin['options']['challenge'])], $request);
    secReject(static fn() => $app->handle('enrollmentOptions', ['code' => $code], $request), 'Enrollment credential reused.');
    $begin = secOptions($app->handle('authOptions', [], $request));
    secReject(static fn() => $app->handle('authVerify', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($key, $begin['options']['challenge'], 1, 'https://evil.example.test')], $request), 'Wrong origin assertion accepted.');
    $begin = secOptions($app->handle('authOptions', [], $request)); $login = $app->handle('authVerify', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($key, $begin['options']['challenge'], 1)], $request);
    $request['cookie'] = explode(';', $login['cookie'])[0]; $request['csrf'] = $login['data']['csrf'];
    $write = ['kind' => 'save', 'scope' => 'global', 'path' => ['Service'], 'revision' => '0', 'mode' => 'create', 'json' => '{"User":"alice","Pass":"SECRET_REVEAL_CANARY","Nested":{"Child":"hidden"}}'];
    $begin = secOptions($app->handle('prepare', ['operation' => $write], $request));
    $app->handle('approve', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($key, $begin['options']['challenge'], 2)], $request);
    secReject(static fn() => $app->handle('approve', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($key, $begin['options']['challenge'], 3)], $request), 'Consumed approval reused.');
    $list = $app->handle('list', [], $request); secExpect(!str_contains(SecretsBackendCodec::json($list), 'SECRET_REVEAL_CANARY'), 'List disclosed a secret.');
    secReject(static fn() => $app->handle('prepare', ['operation' => $write], $request), 'Stale vault revision accepted.');
    $read = ['kind' => 'reveal', 'scope' => 'global', 'path' => ['Service'], 'revision' => '1']; $begin = secOptions($app->handle('prepare', ['operation' => $read], $request));
    $reveal = $app->handle('approve', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($key, $begin['options']['challenge'], 3)], $request);
    secExpect(str_contains(SecretsBackendCodec::json($reveal), 'SECRET_REVEAL_CANARY') && !str_contains(SecretsBackendCodec::json($reveal), 'hidden'), 'Reveal crossed into nested record.');
    $bad = $request; $bad['csrf'] = 'wrong'; secReject(static fn() => $app->handle('list', [], $bad), 'CSRF accepted.');
    secReject(static fn() => $app->handle('enrollmentOptions', ['code' => 'ordinary-passkey-is-not-a-console-recovery-code'], $request), 'Ordinary session created an eligible approver.');
});
echo 'Completed ' . $tests . " implementation checks. Production acceptance suite is NOT claimed passed.\n";
