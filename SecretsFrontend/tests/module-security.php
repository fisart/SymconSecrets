<?php
declare(strict_types=1);
require_once __DIR__ . '/modules.php';
foreach (['ClientCertificatePath' => 'tls-client.pem', 'ClientKeyPath' => 'tls-client.key', 'AnchorCAFile' => 'tls-ca.pem'] as $field => $name) {
    $file = $directory . '/' . $name; SecretsBackendCodec::writeNew($file, 'SYNTHETIC TLS MATERIAL FOR IN-PROCESS TRANSPORT ONLY'); $backend->properties[$field] = $file;
}
$backend->properties['AnchorURL'] = 'https://witness.example.test/v1/anchor';
$backend->properties['AnchorPublicKey'] = SecretsBackendCodec::b64($backend->witness->public); $backend->properties['AnchorKeyID'] = $backend->witness->keyId;
$backend->properties['Enabled'] = true; $backend->ApplyChanges(); secExpect($backend->Recover(), 'Module recovery did not activate.');
secRejectReason(static fn() => $backend->BeginAdminEnrollment('Before seal', false), 'Seal initial security configuration');
$digest = $backend->SecurityConfigurationDigest();
secRejectReason(static fn() => $backend->SealInitialSecurityConfiguration(str_repeat('0', 64)), 'Review the exact current provisioning digest');
secExpect($backend->SealInitialSecurityConfiguration($digest), 'Initial explicit provisioning did not seal.');
secRejectReason(static fn() => $backend->SealInitialSecurityConfiguration($digest), 'Initial provisioning is closed');
secRejectReason(static fn() => $backend->BeginStorageSetup(), 'already bound');
$changed = json_decode($backend->ExportConfiguration(), true); $changed['configuration']['AnchorPublicKey'] = SecretsBackendCodec::b64(random_bytes(32));
secRejectReason(static fn() => $backend->ImportConfiguration(json_encode($changed)), 'Import cannot replace provisioned anchor trust');
secExpect($backend->properties['Enabled'] === true, 'Rejected foundation import partially changed configuration.');
$invoke = static function (string $action, array $data, string $cookie = '', string $csrf = '') use ($backend): array {
    return json_decode($backend->HandleFrontendRequest(123, SecretsBackendCodec::json(['action' => $action, 'data' => $data, 'origin' => 'https://secrets.example.test', 'cookie' => $cookie, 'csrf' => $csrf, 'remote' => 'module-security-test'])), true);
};
$key = secKey(); $code = $backend->BeginAdminEnrollment('Synthetic owner', false); $begin = $invoke('enrollmentOptions', ['code' => $code])['data'];
secExpect($invoke('enrollmentVerify', ['challengeId' => $begin['challengeId'], 'credential' => secRegistration($key, $begin['options']['challenge'])])['status'] === 200, 'Module registration failed.');
$login = static function (int $counter) use ($invoke, $key): array {
    $begin = $invoke('authOptions', [])['data']; $response = $invoke('authVerify', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($key, $begin['options']['challenge'], $counter)]);
    secExpect($response['status'] === 200, 'Module login failed.'); return [explode(';', $response['cookie'])[0], $response['data']['csrf']];
};
[$cookie, $csrf] = $login(1);
$backend->properties['HardwareTrustVersion'] = 'staged-profile-v2'; $backend->ApplyChanges(); secExpect($backend->Recover(), 'Recovery failed for staged trust profile.');
[$cookie, $csrf] = $login(2);
$storeMethod = new ReflectionMethod(SecretsBackend::class, 'store'); $store = $storeMethod->invoke($backend);
secExpect($store->read()['state']['policy']['management']['settings']['HardwareTrustVersion'] === 'none', 'Normal form apply activated unapproved hardware trust.');
$preview = $invoke('configurationPreview', [], $cookie, $csrf); secExpect($preview['status'] === 200, 'Staged configuration could not be reviewed.');
$operation = ['kind' => 'configuration', 'profile' => $preview['data']['profile']];
$begin = $invoke('prepare', ['operation' => $operation], $cookie, $csrf)['data'];
secExpect($invoke('approve', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($key, $begin['options']['challenge'], 3)], $cookie, $csrf)['status'] === 200, 'Exact configuration approval failed.');
secExpect($store->read()['state']['policy']['management']['settings']['HardwareTrustVersion'] === 'staged-profile-v2', 'Approved hardware profile was not anchored.');
file_put_contents($backend->properties['AnchorCAFile'], 'DRIFTED CA CONTENT');
secExpect($invoke('session', [], $cookie, $csrf)['status'] === 403, 'Unapproved trust-file drift was accepted.');
file_put_contents($backend->properties['AnchorCAFile'], 'SYNTHETIC TLS MATERIAL FOR IN-PROCESS TRANSPORT ONLY');
secExpect($invoke('session', [], $cookie, $csrf)['status'] === 200, 'Restoring exact approved trust file did not recover.');
echo "PASS A05 explicit one-time provisioning, pinned foundation/import, staged profile approval and trust-file drift lock\n";

// Uncertainty BEFORE witness persistence: the mutation is not automatically replayed.
$operation = ['kind' => 'save', 'scope' => 'local', 'path' => ['Test'], 'revision' => '0', 'mode' => 'create', 'json' => '"SAFE_CANARY"'];
$begin = $invoke('prepare', ['operation' => $operation], $cookie, $csrf)['data'];
$inject = true; $backend->fault = static function ($point) use (&$inject, $backend): void { if ($inject && $point === 'after_prepare') { $inject = false; $backend->witness->offline = true; } };
$response = $invoke('approve', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($key, $begin['options']['challenge'], 4)], $cookie, $csrf);
secExpect($response['status'] === 403 && $backend->timers['Recovery'] > 0 && $backend->status === 200, 'Ambiguous request did not schedule recovery.');
$delay = $backend->timers['Recovery']; secExpect(!$backend->Recover() && $backend->timers['Recovery'] >= $delay, 'Outage recovery did not back off.');
$backend->witness->offline = false; $backend->fault = null; secExpect($backend->Recover() && $backend->timers['Recovery'] === 0, 'Automatic recovery invocation did not resume after outage.');
$store = $storeMethod->invoke($backend); secExpect($store->read()['state']['vault']['revision'] === '0', 'Browser mutation was replayed after uncertain unanchored prepare.');

// Uncertainty AFTER witness persistence: publish the exact already committed mutation.
[$cookie, $csrf] = $login(4); $begin = $invoke('prepare', ['operation' => $operation], $cookie, $csrf)['data']; $backend->witness->loseReply = true;
$response = $invoke('approve', ['challengeId' => $begin['challengeId'], 'credential' => secAssertion($key, $begin['options']['challenge'], 5)], $cookie, $csrf);
secExpect($response['status'] === 403 && $backend->timers['Recovery'] > 0, 'Lost commit acknowledgement did not schedule recovery.');
secExpect($backend->Recover(), 'Lost acknowledgement did not recover.');
$store = $storeMethod->invoke($backend); secExpect($store->read()['state']['vault']['revision'] === '1', 'Exact anchored pending state was lost.');
secExpect(!str_contains($backend->values['Debug'], 'SAFE_CANARY') && !str_contains(file_get_contents($directory . '/data/vault.sqlite'), 'SAFE_CANARY'), 'Canary leaked into Debug or SQLite.');
echo "PASS A04 module timer/backoff and request-time recovery before/after witness persistence; no browser mutation replay\n";

// Immediate local invalidation, even before the next remote recovery.
$old = $store->read(); $backend->ApplyChanges();
secRejectReason(static fn() => $store->authorize('metadata', hash('sha256', 'paused-old-grant'), $old, static function ($s): void {}), 'Runtime is fenced');
secRejectReason(static fn() => $store->change($old['head'], SecretsBackendCodec::uuid(), hash('sha256', 'paused-old-change'), static fn($s) => $s), 'Runtime is fenced');
secExpect($backend->Recover(), 'Reload recovery failed.');
$duplicate = new SecretsBackendTestModule(457); $duplicate->Create(); $duplicate->properties = $backend->properties; $duplicate->witness = $backend->witness;
$GLOBALS['moduleIDs'][457] = '{52165EDD-B2C0-40EC-8A59-42A97319B6E2}';
secExpect(!$duplicate->Recover() && str_contains($duplicate->values['Status'], 'binding'), 'Duplicate backend identity was accepted.');
secExpect(!$backend->Recover() && str_contains($backend->values['Status'], 'Another backend'), 'Competing backend storage claim was not detected.');
unset($GLOBALS['moduleIDs'][457], $GLOBALS['instances'][457]); secExpect($backend->Recover(), 'Removing duplicate did not permit recovery.');
echo "PASS R68 reload invalidates paused old grants/writes before remote recovery; duplicate storage/instance binding rejected\n";

// Durable secret-free operation semantics and bounded rejection telemetry.
$store = $storeMethod->invoke($backend); $state = $store->read()['state']; $last = end($state['operations']['audit']);
foreach (['actor', 'action', 'target', 'backend', 'frontend', 'deployment', 'beforeRevision', 'revision', 'result', 'anchorOperationId', 'operationId'] as $field) secExpect(array_key_exists($field, $last), 'Missing structured audit field: ' . $field);
secExpect($last['action'] === 'save' && $last['result'] === 'committed' && !str_contains(SecretsBackendCodec::json($state['operations']['audit']), 'SAFE_CANARY'), 'Durable audit lacks safe action semantics.');
for ($i = 0; $i < 30; $i++) $store->auditRejected();
$db = new PDO('sqlite:' . $directory . '/data/vault.sqlite'); $count = (int)$db->query("SELECT MAX(n) FROM (SELECT COUNT(*) AS n FROM audit_events WHERE bucket LIKE 'rejected:%' GROUP BY bucket)")->fetchColumn();
secExpect($count <= 20, 'Rejected-request telemetry is not bounded per minute.');
echo "PASS A06 structured anchored mutation audit, correlated local grant events and bounded secret-free rejection telemetry\n";
$claims = []; $receipts = []; $consoleEvents = 0;
foreach ($db->query('SELECT bucket,sealed FROM audit_events') as $row) {
    $event = json_decode(SecretsBackendCodec::open($row['sealed'], SecretsBackendCodec::privateFile($directory . '/keys/master.key'), 'audit:' . $store->identity()['deploymentId']), true);
    secExpect(!str_contains(SecretsBackendCodec::json($event), 'SAFE_CANARY'), 'Audit logged a raw value.');
    if ($row['bucket'] === 'console') { secExpect($event['action'] === 'enroll-recovery' && $event['result'] === 'issued', 'Console recovery issuance is not distinguishable.'); $consoleEvents++; }
    if ($event['result'] === 'claimed') $claims[$event['operationId']] = $event;
    if (isset($event['signedReceipt'])) $receipts[$event['operationId']] = $event;
}
secExpect(count($claims) > 0 && count($receipts) > 0 && $consoleEvents > 0, 'Missing durable grant/console audit events.');
foreach ($receipts as $id => $event) {
    $claim = $claims[$id]; $baseEvent = array_diff_key($claim, array_flip(['actionDigest', 'operationDigest', 'requestBody', 'anchorOperationDigest']));
    secExpect(hash('sha256', SecretsBackendCodec::json(['operationDigest' => $claim['operationDigest'], 'audit' => $baseEvent])) === $claim['actionDigest'], 'Audit claim does not bind actor/action/target to the grant digest.');
    $receipt = $event['signedReceipt'];
    secExpect(sodium_crypto_sign_verify_detached(SecretsBackendCodec::unb64($receipt['signature'], 64), "SYMCON-ANCHOR-RESPONSE-V1\0" . SecretsBackendCodec::canonical($receipt['response']), $backend->witness->public), 'Stored witness receipt signature is invalid.');
    secExpect($receipt['response']['result']['operationDigest'] === $claim['anchorOperationDigest'] && $receipt['response']['result']['actionDigest'] === $claim['actionDigest'], 'Grant receipt is not correlated to its exact audited request.');
}
$pin = $directory . '/keys/management-bootstrap.json'; rename($pin, $pin . '.saved');
secExpect(!$backend->Recover() && str_contains($backend->values['Status'], 'Pinned provisioning file is missing'), 'Missing bootstrap pin silently fell back to editable settings.');
rename($pin . '.saved', $pin); secExpect($backend->Recover(), 'Restoring exact provisioning file did not recover.');
echo "PASS A06 encrypted grant claims bind audit context to verified signed receipts; explicit console issuance is distinguishable; missing pin locks management\n";
