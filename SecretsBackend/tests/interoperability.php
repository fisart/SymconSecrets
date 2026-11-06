<?php
declare(strict_types=1);
require_once __DIR__ . '/Fixture.php';
function bridge(array $args, string $input = ''): string
{
    $pipes = []; $process = proc_open(array_merge(['python3', __DIR__ . '/anchor_bridge.py'], $args), [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($process)) throw new RuntimeException('Cannot start witness interoperability test.');
    fwrite($pipes[0], $input); fclose($pipes[0]); $output = stream_get_contents($pipes[1]); fclose($pipes[1]); $error = stream_get_contents($pipes[2]); fclose($pipes[2]);
    if (proc_close($process) !== 0) throw new RuntimeException('Witness interoperability failure: ' . $error);
    return $output;
}
$directory = sys_get_temp_dir() . '/symcon-witness-cross-test-' . bin2hex(random_bytes(8)); mkdir($directory, 0700);
$info = SecretsBackendStore::initialize($directory . '/data', $directory . '/keys', 'https://secrets.example.test', 123, 'DELETE');
file_put_contents($directory . '/provision.json', SecretsBackendCodec::json($info));
$witness = json_decode(bridge([$directory . '/anchor', $directory . '/provision.json']), true, 8, JSON_THROW_ON_ERROR);
$lost = false;
$transport = static function (string $wire) use ($directory, &$lost): string {
    $response = bridge([$directory . '/anchor'], $wire);
    if ($lost && json_decode($wire, true)['request']['operation'] === 'acquire') { $lost = false; throw new RuntimeException('Lost reply after real witness persisted.'); }
    return $response;
};
$client = new SecretsBackendAnchorClient($info + $witness + ['signingKeyFile' => $directory . '/keys/anchor-sign.key'], $transport);
$store = new SecretsBackendStore($directory . '/data', $directory . '/keys', SecretsBackendCodec::b64(random_bytes(32)), $client, 'DELETE');
$lost = true; secReject(static fn() => $store->recover(), 'Lost acknowledgement not injected.'); $store->recover();
$head = $store->read()['head'];
$store->change($head, SecretsBackendCodec::uuid(), hash('sha256', 'cross-language'), static fn($s) => $s);
secExpect($store->read()['head']['index'] === '1', 'Real witness did not persist exact PHP target.');
secReject(static fn() => $client->call('advance', ['operationId' => SecretsBackendCodec::uuid()]), 'Witness accepted an incomplete schema.');
echo "PASS PHP/Python signatures, canonical metadata, durable acquire retry and commit interoperability\n";
