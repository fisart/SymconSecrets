<?php
declare(strict_types=1);
require_once __DIR__ . '/Fixture.php';
[$store, $witness, $client, $directory, $info] = secFixture(); $current = $store->read();
$body = ['operationId' => SecretsBackendCodec::uuid(), 'expectedHead' => $current['head'], 'expectedOwner' => $current['owner'], 'kind' => 'metadata', 'actionDigest' => hash('sha256', 'test'), 'audience' => null];
$settings = $info + ['signingKeyFile' => $directory . '/keys/anchor-sign.key', 'anchorPublicKey' => SecretsBackendCodec::b64($witness->public), 'anchorKeyId' => $witness->keyId];
$cases = [
 ['read unknown field', 'read', static function (&$r) { $r['extra'] = true; }, 'closed anchor schema'],
 ['head unknown field', 'read', static function (&$r) { $r['head']['extra'] = true; }, 'closed anchor schema'],
 ['malformed owner', 'read', static function (&$r) { $r['owner']['fence'] = '-1'; }, 'anchor counter'],
 ['noncanonical revision', 'read', static function (&$r) { $r['credentialRevision'] = '01'; }, 'anchor counter'],
 ['unexpected read result', 'read', static function (&$r) { $r['result'] = ['status' => 'AUTHORIZED']; }, 'Unexpected read decision'],
 ['decision unknown field', 'authorize', static function (&$r) { $r['result']['extra'] = true; }, 'closed anchor schema'],
 ['wrong operation id', 'authorize', static function (&$r) { $r['result']['operationId'] = SecretsBackendCodec::uuid(); }, 'decision binding'],
 ['wrong digest', 'authorize', static function (&$r) { $r['result']['operationDigest'] = str_repeat('0', 64); }, 'decision binding'],
 ['wrong operation', 'authorize', static function (&$r) { $r['result']['operation'] = 'advance'; }, 'operation decision'],
 ['wrong success status', 'authorize', static function (&$r) { $r['result']['status'] = 'APPLIED'; }, 'successful anchor decision'],
 ['wrong head', 'authorize', static function (&$r) { $r['result']['head']['digest'] = str_repeat('0', 64); }, 'contradicts its durable decision'],
 ['wrong owner', 'authorize', static function (&$r) { $r['result']['owner']['fence'] = '99'; }, 'contradicts its durable decision'],
 ['wrong action digest', 'authorize', static function (&$r) { $r['result']['actionDigest'] = str_repeat('0', 64); }, 'successful anchor decision'],
 ['rejected without reason', 'authorize', static function (&$r) { $r['result']['status'] = 'REJECTED'; }, 'lacks a reason'],
 ['success with rejection reason', 'authorize', static function (&$r) { $r['result']['reason'] = 'OWNER'; }, 'successful anchor decision'],
];
foreach ($cases as [$name, $operation, $mutation, $reason]) {
 $bad = new SecretsBackendAnchorClient($settings, static function ($wire) use ($witness, $mutation) {
    $data = json_decode($witness->transport($wire), true); $mutation($data['response']);
    $data['signature'] = SecretsBackendCodec::b64(sodium_crypto_sign_detached("SYMCON-ANCHOR-RESPONSE-V1\0" . SecretsBackendCodec::canonical($data['response']), $witness->private));
    return SecretsBackendCodec::json($data);
 });
 $body['operationId'] = SecretsBackendCodec::uuid();
 secRejectReason(static fn() => $bad->call($operation, $operation === 'read' ? [] : $body), $reason);
 echo 'PASS R71 signed negative response: ' . $name . "\n";
}
echo "PASS R71 closed response/head/owner/decision schemas and exact successful operation bindings\n";
$body['operationId'] = SecretsBackendCodec::uuid(); $client->call('authorize', $body);
$operationDigest = SecretsBackendAnchorClient::operationDigest($info['deploymentId'], $info['clientId'], 'authorize', $body);
$store->change($store->head(), SecretsBackendCodec::uuid(), hash('sha256', 'later'), static fn($s) => $s);
$statusBody = ['operationId' => $body['operationId'], 'operationDigest' => $operationDigest];
$status = $client->call('status', $statusBody);
secExpect($status['result']['status'] === 'AUTHORIZED' && $status['head']['index'] !== $status['result']['head']['index'], 'Historical status decision did not survive a newer head.');
$unknown = $client->call('status', ['operationId' => SecretsBackendCodec::uuid(), 'operationDigest' => hash('sha256', 'unknown')]);
secExpect($unknown['result']['status'] === 'NOT_FOUND', 'Unknown status did not have a complete missing decision.');
$badStatus = new SecretsBackendAnchorClient($settings, static function ($wire) use ($witness) {
    $data = json_decode($witness->transport($wire), true); $data['response']['result']['status'] = 'APPLIED';
    $data['signature'] = SecretsBackendCodec::b64(sodium_crypto_sign_detached("SYMCON-ANCHOR-RESPONSE-V1\0" . SecretsBackendCodec::canonical($data['response']), $witness->private)); return SecretsBackendCodec::json($data);
});
secRejectReason(static fn() => $badStatus->call('status', $statusBody), 'Invalid successful status decision');
echo "PASS R71 historical/missing status decisions and signed inconsistent status refusal\n";
