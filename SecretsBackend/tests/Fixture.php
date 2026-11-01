<?php
declare(strict_types=1);
require_once __DIR__ . '/../Application.php';
require_once __DIR__ . '/../Store.php';

function secExpect(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
function secRejectReason(callable $callback, string $reason): void { try { $callback(); } catch (Throwable $exception) { secExpect(str_contains($exception->getMessage(), $reason), 'Wrong rejection: ' . $exception->getMessage()); return; } throw new RuntimeException('Expected rejection: ' . $reason); }
function secReject(callable $callback, string $message): void { try { $callback(); } catch (Throwable $exception) { return; } throw new RuntimeException($message); }

/** Signed test witness with a separate durable decision file; never available as a runtime mode. */
final class SecretsTestWitness
{
    public string $directory;
    public string $private;
    public string $public;
    public string $keyId;
    public array $initial;
    public bool $offline = false;
    public bool $loseReply = false;
    public bool $tamper = false;
    public function __construct(string $directory, array $initial)
    {
        $this->directory = $directory; $this->initial = $initial;
        $pair = sodium_crypto_sign_keypair(); $this->private = sodium_crypto_sign_secretkey($pair); $this->public = sodium_crypto_sign_publickey($pair); $this->keyId = SecretsBackendCodec::b64(random_bytes(32));
        file_put_contents($directory . '/witness.json', SecretsBackendCodec::json(['head' => $initial['head'], 'owner' => ['fence' => '0', 'bootId' => SecretsBackendCodec::b64(str_repeat("\0", 32)), 'clientId' => $initial['clientId']], 'decisions' => []]));
    }
    public function transport(string $wire): string
    {
        if ($this->offline) throw new RuntimeException('Injected witness outage.');
        $data = json_decode($wire, true, 16, JSON_THROW_ON_ERROR); $request = $data['request'];
        if ($request['operation'] === 'read') $request['body'] = (object)[];
        secExpect(sodium_crypto_sign_verify_detached(SecretsBackendCodec::unb64($data['signature'], 64), "SYMCON-ANCHOR-REQUEST-V1\0" . SecretsBackendCodec::canonical($request), SecretsBackendCodec::unb64($this->initial['clientPublicKey'], 32)), 'Client signature failed in fixture.');
        $state = json_decode(file_get_contents($this->directory . '/witness.json'), true, 16, JSON_THROW_ON_ERROR); $operation = $request['operation']; $body = $request['body']; $result = null;
        if ($operation !== 'read') {
            $id = $body['operationId']; $digest = $operation === 'status' ? $body['operationDigest'] : SecretsBackendAnchorClient::operationDigest($request['deploymentId'], $request['clientId'], $operation, $body);
            if (isset($state['decisions'][$id])) {
                $result = $state['decisions'][$id];
                if ($result['operationDigest'] !== $digest) $result['status'] = 'REJECTED';
            } elseif ($operation === 'status') $result = ['operationId' => $id, 'operationDigest' => $digest, 'operation' => null, 'status' => 'NOT_FOUND', 'head' => $state['head'], 'owner' => $state['owner'], 'actionDigest' => null, 'reason' => 'NOT_FOUND'];
            else {
                $ok = SecretsBackendCodec::same($body['expectedHead'], $state['head']) && SecretsBackendCodec::same($body['expectedOwner'], $state['owner']);
                if ($ok && $operation === 'advance') $state['head'] = $body['target'];
                if ($ok && $operation === 'acquire') $state['owner'] = ['fence' => SecretsBackendCodec::increment($state['owner']['fence']), 'bootId' => $body['newBootId'], 'clientId' => $request['clientId']];
                $result = ['operationId' => $id, 'operationDigest' => $digest, 'operation' => $operation, 'status' => $ok ? ($operation === 'authorize' ? 'AUTHORIZED' : 'APPLIED') : 'REJECTED', 'head' => $state['head'], 'owner' => $state['owner'], 'actionDigest' => $body['actionDigest'] ?? null, 'reason' => $ok ? 'NONE' : 'OWNER'];
                $state['decisions'][$id] = $result;
            }
        }
        file_put_contents($this->directory . '/witness.json', SecretsBackendCodec::json($state));
        if ($this->loseReply && $operation !== 'read') { $this->loseReply = false; throw new RuntimeException('Injected lost acknowledgement after persistence.'); }
        $response = ['version' => '1', 'deploymentId' => $request['deploymentId'], 'requestId' => $request['requestId'], 'nonce' => $request['nonce'], 'requestDigest' => hash('sha256', SecretsBackendCodec::canonical($request)), 'anchorKeyId' => $this->keyId,
            'head' => $state['head'], 'owner' => $state['owner'], 'credentialRevision' => '0', 'result' => $result];
        $signature = sodium_crypto_sign_detached("SYMCON-ANCHOR-RESPONSE-V1\0" . SecretsBackendCodec::canonical($response), $this->private);
        if ($this->tamper) $response['nonce'] = SecretsBackendCodec::b64(random_bytes(32));
        return SecretsBackendCodec::json(['response' => $response, 'signature' => SecretsBackendCodec::b64($signature)]);
    }
}

function secFixture(?callable $fault = null): array
{
    $directory = sys_get_temp_dir() . '/symcon-secrets-test-' . bin2hex(random_bytes(8)); mkdir($directory, 0700);
    $info = SecretsBackendStore::initialize($directory . '/data', $directory . '/keys', 'https://secrets.example.test', 123, 'DELETE');
    $witness = new SecretsTestWitness($directory, $info);
    $client = new SecretsBackendAnchorClient($info + ['signingKeyFile' => $directory . '/keys/anchor-sign.key', 'anchorPublicKey' => SecretsBackendCodec::b64($witness->public), 'anchorKeyId' => $witness->keyId], [$witness, 'transport']);
    $runtime = SecretsBackendCodec::b64(random_bytes(32));
    $store = new SecretsBackendStore($directory . '/data', $directory . '/keys', $runtime, $client, 'DELETE', $fault); $store->recover();
    return [$store, $witness, $client, $directory, $info, $runtime];
}

function secOptions(array $response): array { return json_decode(SecretsBackendCodec::json($response['data']), true, 16, JSON_THROW_ON_ERROR); }
function secKey(): array
{
    $private = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    $details = openssl_pkey_get_details($private);
    foreach (['x', 'y'] as $coordinate) $details['ec'][$coordinate] = str_pad($details['ec'][$coordinate], 32, "\0", STR_PAD_LEFT);
    return ['private' => $private, 'details' => $details, 'id' => SecretsBackendCodec::b64(random_bytes(32))];
}
function secAssertion(array $key, string $challenge, int $counter, string $origin = 'https://secrets.example.test', int $flags = 5): array
{
    $client = SecretsBackendCodec::json(['type' => 'webauthn.get', 'origin' => $origin, 'challenge' => $challenge, 'crossOrigin' => false]);
    $auth = hash('sha256', 'secrets.example.test', true) . chr($flags) . pack('N', $counter); $signature = '';
    openssl_sign($auth . hash('sha256', $client, true), $signature, $key['private'], OPENSSL_ALGO_SHA256);
    return ['type' => 'public-key', 'rawId' => $key['id'], 'response' => ['clientDataJSON' => SecretsBackendCodec::b64($client), 'authenticatorData' => SecretsBackendCodec::b64($auth), 'signature' => SecretsBackendCodec::b64($signature), 'userHandle' => null]];
}
function secRegistration(array $key, string $challenge): array
{
    $bytes = static fn(string $value) => chr(0x58) . chr(strlen($value)) . $value;
    $cose = "\xa5\x01\x02\x03\x26\x20\x01\x21" . $bytes($key['details']['ec']['x']) . "\x22" . $bytes($key['details']['ec']['y']);
    $id = SecretsBackendCodec::unb64($key['id']);
    $auth = hash('sha256', 'secrets.example.test', true) . chr(0x45) . pack('N', 0) . str_repeat("\0", 16) . pack('n', strlen($id)) . $id . $cose;
    $byteString = strlen($auth) < 256 ? chr(0x58) . chr(strlen($auth)) . $auth : chr(0x59) . pack('n', strlen($auth)) . $auth;
    $attestation = "\xa3\x63fmt\x64none\x68authData" . $byteString . "\x67attStmt\xa0";
    $client = SecretsBackendCodec::json(['type' => 'webauthn.create', 'origin' => 'https://secrets.example.test', 'challenge' => $challenge, 'crossOrigin' => false]);
    return ['type' => 'public-key', 'rawId' => $key['id'], 'response' => ['clientDataJSON' => SecretsBackendCodec::b64($client), 'attestationObject' => SecretsBackendCodec::b64($attestation)]];
}
