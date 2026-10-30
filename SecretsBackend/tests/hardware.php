<?php
declare(strict_types=1);
require_once __DIR__ . '/Fixture.php';
$directory = sys_get_temp_dir() . '/secb-hardware-' . bin2hex(random_bytes(8));
$process = proc_open(['python3', __DIR__ . '/hardware_certificates.py', $directory], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
fclose($pipes[0]); stream_get_contents($pipes[1]); fclose($pipes[1]); $error = stream_get_contents($pipes[2]); fclose($pipes[2]);
secExpect(proc_close($process) === 0, 'Cannot generate synthetic attestation fixtures: ' . $error);
function hwLength(int $type, int $length): string { return $length < 24 ? chr(($type << 5) | $length) : ($length < 256 ? chr(($type << 5) | 24) . chr($length) : chr(($type << 5) | 25) . pack('n', $length)); }
function hwText(string $value): string { return hwLength(3, strlen($value)) . $value; }
function hwBytes(string $value): string { return hwLength(2, strlen($value)) . $value; }
function hwRegistration(array $key, string $challenge, string $label, array $chain): array
{
    global $directory;
    $base = secRegistration($key, $challenge);
    $decoded = new \lbuchs\WebAuthn\Attestation\AttestationObject(SecretsBackendCodec::unb64($base['response']['attestationObject']), ['none']);
    $auth = substr_replace($decoded->getAuthenticatorData()->getBinary(), str_repeat("\x42", 16), 37, 16);
    $client = SecretsBackendCodec::unb64($base['response']['clientDataJSON']);
    openssl_sign($auth . hash('sha256', $client, true), $signature, file_get_contents($directory . '/' . $label . '.key'), OPENSSL_ALGO_SHA256);
    $certificates = hwLength(4, count($chain));
    foreach ($chain as $certificate) $certificates .= hwBytes(file_get_contents($directory . '/' . $certificate . '.der'));
    $object = "\xa3" . hwText('fmt') . hwText('packed') . hwText('authData') . hwBytes($auth) . hwText('attStmt') . "\xa3" . hwText('alg') . "\x26" . hwText('sig') . hwBytes($signature) . hwText('x5c') . $certificates;
    $base['response']['attestationObject'] = SecretsBackendCodec::b64($object); return $base;
}
[$store] = secFixture();
$app = new SecretsBackendApplication($store, ['origin' => 'https://secrets.example.test', 'frontend' => 123, 'backend' => 456,
    'hardwareRoots' => $directory . '/roots', 'hardwareAAGUIDs' => [str_repeat('42', 16)], 'hardwareTrustVersion' => 'synthetic-test-v1']);
$request = ['origin' => 'https://secrets.example.test', 'cookie' => '', 'csrf' => '', 'remote' => '127.0.0.1'];
$attempt = static function (string $label, array $chain) use ($app, $request): array {
    $key = secKey(); $code = $app->beginEnrollment('Synthetic attester', true);
    $begin = secOptions($app->handle('enrollmentOptions', ['code' => $code], $request));
    $app->handle('enrollmentVerify', ['challengeId' => $begin['challengeId'], 'credential' => hwRegistration($key, $begin['options']['challenge'], $label, $chain)], $request);
    return $key;
};
foreach ([['rogue-leaf', ['rogue-leaf']], ['rogue-leaf', ['rogue-leaf', 'rogue']], ['expired', ['expired']],
    ['wrong-model', ['wrong-model']], ['missing-model', ['missing-model']], ['wrong-subject', ['wrong-subject']], ['ca-leaf', ['ca-leaf']]] as [$label, $chain]) {
    // Different test remote buckets avoid rate-limit rejection masquerading as trust rejection.
    $request['remote'] = 'fixture-' . $label . count($chain);
    $code = $app->beginEnrollment('Rejected synthetic attester', true); $key = secKey();
    $begin = secOptions($app->handle('enrollmentOptions', ['code' => $code], $request));
    try { $app->handle('enrollmentVerify', ['challengeId' => $begin['challengeId'], 'credential' => hwRegistration($key, $begin['options']['challenge'], $label, $chain)], $request); throw new LogicException('Invalid hardware accepted.'); }
    catch (RuntimeException $exception) {
        $reason = in_array($label, ['rogue-leaf', 'expired'], true) ? 'not rooted' : (in_array($label, ['wrong-model', 'missing-model'], true) ? 'model binding' : 'certificate profile');
        secExpect(str_contains($exception->getMessage(), $reason), 'Wrong hardware rejection reason: ' . $exception->getMessage());
    }
    secExpect(!isset($store->read()['state']['identity']['credentials'][$key['id']]), 'Rejected attester became eligible hardware.');
    echo 'PASS A01 reject ' . $label . ' chain=' . count($chain) . "\n";
}
$first = $attempt('valid', ['valid']); $second = $attempt('valid-intermediate', ['valid-intermediate', 'intermediate', 'approved']);
secExpect($store->read()['state']['identity']['credentials'][$first['id']]['hardware'] && $store->read()['state']['identity']['credentials'][$second['id']]['hardware'], 'Valid configured chains did not enroll.');
$begin = secOptions($app->handle('authOptions', [], $request));
$login = $app->handle('authVerify', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($first, $begin['options']['challenge'], 1)], $request);
$request['cookie'] = explode(';', $login['cookie'])[0]; $request['csrf'] = $login['data']['csrf'];
$operation = ['kind' => 'policy', 'hardware' => ['write' => true, 'identity' => false, 'export' => false, 'reveal' => false]];
$begin = secOptions($app->handle('prepare', ['operation' => $operation], $request));
secExpect($begin['requiresHardware'] === true, 'Enabling hardware policy did not require hardware.');
$app->handle('approve', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($first, $begin['options']['challenge'], 2)], $request);
$begin = secOptions($app->handle('prepare', ['operation' => ['kind' => 'save', 'scope' => 'local', 'path' => ['Test'], 'revision' => '0', 'mode' => 'create', 'json' => '"synthetic"']], $request));
secExpect($begin['requiresHardware'] === true, 'Protected write lacked hardware requirement.');
$app->handle('approve', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($first, $begin['options']['challenge'], 3)], $request);
$ordinary = secKey(); $code = $app->beginEnrollment('Independent recovery ordinary passkey', false);
$begin = secOptions($app->handle('enrollmentOptions', ['code' => $code], $request));
$app->handle('enrollmentVerify', ['challengeId' => $begin['challengeId'], 'credential' => secRegistration($ordinary, $begin['options']['challenge'])], $request);
$begin = secOptions($app->handle('authOptions', [], $request)); $login = $app->handle('authVerify', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($ordinary, $begin['options']['challenge'], 1)], $request);
$request['cookie'] = explode(';', $login['cookie'])[0]; $request['csrf'] = $login['data']['csrf'];
$begin = secOptions($app->handle('prepare', ['operation' => ['kind' => 'revoke', 'credentialId' => $second['id']]], $request));
secExpect($begin['requiresHardware'] === true, 'Mixed policy let an ordinary approver manage eligible credentials.');
secRejectReason(static fn() => $app->handle('approve', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($ordinary, $begin['options']['challenge'], 2)], $request), 'Wrong approval credential');
echo "PASS A01 configured root/intermediate/model-bound positive crypto path and mixed-policy bypass refusal (synthetic devices only)\n";

// A mixed policy must also protect trust-profile changes, not just credential revocation.
$profile = ['version' => '1', 'settings' => ['HardwareTrustVersion' => 'synthetic-test-v1', 'HardwareRootsDirectory' => $directory . '/roots', 'HardwareAAGUIDs' => json_encode([str_repeat('42', 16)])], 'frontendSecurity' => [], 'files' => []];
$candidate = $profile; $candidate['settings']['HardwareTrustVersion'] = 'synthetic-test-v2';
$store->change($store->head(), SecretsBackendCodec::uuid(), hash('sha256', 'fixture-profile'), static function ($s) use ($profile) { $s['policy']['management'] = $profile; return $s; });
$settings = ['origin' => 'https://secrets.example.test', 'frontend' => 123, 'backend' => 456, 'hardwareRoots' => $directory . '/roots',
    'hardwareAAGUIDs' => [str_repeat('42', 16)], 'hardwareTrustVersion' => 'synthetic-test-v1', 'managementProfile' => $profile, 'candidateProfile' => static fn() => $candidate];
$protectedApp = new SecretsBackendApplication($store, $settings);
$operation = ['kind' => 'configuration', 'profile' => $candidate];
$begin = secOptions($protectedApp->handle('prepare', ['operation' => $operation], $request));
secExpect($begin['requiresHardware'] === true, 'Mixed write-only policy let ordinary passkey change hardware trust.');
secRejectReason(static fn() => $protectedApp->handle('approve', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($ordinary, $begin['options']['challenge'], 2)], $request), 'Wrong approval credential');
$begin = secOptions($protectedApp->handle('prepare', ['operation' => $operation], $request));
$protectedApp->handle('approve', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($first, $begin['options']['challenge'], 4)], $request);
secRejectReason(static fn() => $protectedApp->handle('list', [], $request), 'Security profile changed');
echo "PASS A05 mixed-policy trust-profile change requires an existing eligible hardware approver; stale profile worker rejected\n";
