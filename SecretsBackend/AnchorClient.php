<?php
declare(strict_types=1);
require_once __DIR__ . '/Codec.php';
require_once __DIR__ . '/../SecretsFrontend/Configuration.php';

final class SecretsBackendAnchorClient
{
    private array $settings;
    private $transport;
    private array $lastEvidence = [];
    public function __construct(array $settings, ?callable $transport = null) { $this->settings = $settings; $this->transport = $transport; }
    public function call(string $operation, array $body): array
    {
        $request = ['version' => '1', 'deploymentId' => $this->settings['deploymentId'], 'clientId' => $this->settings['clientId'],
            'keyId' => $this->settings['keyId'], 'requestId' => SecretsBackendCodec::uuid(), 'nonce' => SecretsBackendCodec::b64(random_bytes(32)),
            'operation' => $operation, 'body' => $body ?: (object)[]];
        $canonical = SecretsBackendCodec::canonical($request);
        $key = SecretsBackendCodec::privateFile($this->settings['signingKeyFile']);
        if (strlen($key) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) throw new RuntimeException('Invalid anchor signing key.');
        $wire = SecretsBackendCodec::json(['request' => $request, 'signature' => SecretsBackendCodec::b64(sodium_crypto_sign_detached("SYMCON-ANCHOR-REQUEST-V1\0" . $canonical, $key))]);
        $raw = $this->transport !== null ? ($this->transport)($wire) : $this->https($wire);
        $data = SecretsFrontendConfiguration::decode($raw);
        if (count($data) !== 2 || !isset($data['response'], $data['signature']) || !is_array($data['response'])) throw new RuntimeException('Invalid anchor response.');
        $response = $data['response'];
        $public = SecretsBackendCodec::unb64($this->settings['anchorPublicKey'], 32);
        if (!sodium_crypto_sign_verify_detached(SecretsBackendCodec::unb64($data['signature'], 64), "SYMCON-ANCHOR-RESPONSE-V1\0" . SecretsBackendCodec::canonical($response), $public)) throw new RuntimeException('Anchor signature verification failed.');
        if (($response['version'] ?? '') !== '1' || ($response['deploymentId'] ?? '') !== $request['deploymentId']
            || ($response['requestId'] ?? '') !== $request['requestId'] || ($response['nonce'] ?? '') !== $request['nonce']
            || ($response['requestDigest'] ?? '') !== hash('sha256', $canonical) || ($response['anchorKeyId'] ?? '') !== $this->settings['anchorKeyId']) throw new RuntimeException('Stale or foreign anchor response.');
        self::validateResponse($response, $request);
        $this->lastEvidence = $data;
        return $response;
    }
    public function evidence(): array { return $this->lastEvidence; }
    private static function fields($value, array $fields): void
    {
        if (!is_array($value) || array_diff(array_keys($value), $fields) || array_diff($fields, array_keys($value))) throw new RuntimeException('Invalid closed anchor schema.');
    }
    private static function number($value): void
    {
        if (!is_string($value) || !preg_match('/^(0|[1-9][0-9]{0,18})$/D', $value)
            || (strlen($value) === 19 && strcmp($value, '9223372036854775807') > 0)) throw new RuntimeException('Invalid anchor counter.');
    }
    private static function uuid($value): void
    {
        if (!is_string($value) || !preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/D', $value)) throw new RuntimeException('Invalid anchor operation identity.');
    }
    private static function digest($value): void
    {
        if (!is_string($value) || !preg_match('/^[a-f0-9]{64}$/D', $value)) throw new RuntimeException('Invalid anchor digest.');
    }
    private static function head($head): void
    {
        self::fields($head, ['generation', 'index', 'digest', 'commitId']);
        SecretsBackendCodec::unb64($head['generation'], 32); self::number($head['index']); self::digest($head['digest']); self::uuid($head['commitId']);
    }
    private static function owner($owner): void
    {
        self::fields($owner, ['fence', 'bootId', 'clientId']); self::number($owner['fence']);
        SecretsBackendCodec::unb64($owner['bootId'], 32); self::uuid($owner['clientId']);
    }
    private static function validateResponse(array $response, array $request): void
    {
        self::fields($response, ['version', 'deploymentId', 'requestId', 'nonce', 'requestDigest', 'anchorKeyId', 'head', 'owner', 'credentialRevision', 'result']);
        self::head($response['head']); self::owner($response['owner']); self::number($response['credentialRevision']);
        $operation = $request['operation']; $body = $request['body']; $decision = $response['result'];
        if ($operation === 'read') { if ($decision !== null) throw new RuntimeException('Unexpected read decision.'); return; }
        self::fields($decision, ['operationId', 'operationDigest', 'operation', 'status', 'head', 'owner', 'actionDigest', 'reason']);
        self::head($decision['head']); self::owner($decision['owner']);
        $expectedDigest = $operation === 'status' ? $body['operationDigest'] : self::operationDigest($request['deploymentId'], $request['clientId'], $operation, $body);
        if ($decision['operationId'] !== $body['operationId'] || $decision['operationDigest'] !== $expectedDigest
            || !in_array($decision['status'], ['APPLIED', 'AUTHORIZED', 'REJECTED', 'NOT_FOUND'], true)
            || !in_array($decision['reason'], ['NONE', 'HEAD', 'OWNER', 'LIMIT', 'ID_REUSE', 'NOT_FOUND'], true)) throw new RuntimeException('Anchor decision binding mismatch.');
        if ($response['head']['generation'] !== $decision['head']['generation'] || (int)$response['head']['index'] < (int)$decision['head']['index']
            || (int)$response['owner']['fence'] < (int)$decision['owner']['fence']
            || ($response['head']['index'] === $decision['head']['index'] && !SecretsBackendCodec::same($response['head'], $decision['head']))
            || ($response['owner']['fence'] === $decision['owner']['fence'] && !SecretsBackendCodec::same($response['owner'], $decision['owner']))) throw new RuntimeException('Anchor envelope precedes or contradicts its durable decision.');
        if ($operation === 'status') {
            if (!in_array($decision['operation'], ['acquire', 'advance', 'authorize', null], true)) throw new RuntimeException('Invalid status operation.');
            if ($decision['status'] === 'NOT_FOUND') {
                if ($decision['operation'] !== null || $decision['reason'] !== 'NOT_FOUND' || $decision['actionDigest'] !== null) throw new RuntimeException('Invalid missing decision.');
                return;
            }
            if ($decision['actionDigest'] !== null) self::digest($decision['actionDigest']);
            if ($decision['status'] === 'REJECTED') {
                if (!in_array($decision['reason'], ['HEAD', 'OWNER', 'LIMIT', 'ID_REUSE'], true)) throw new RuntimeException('Invalid rejected status decision.');
                if ($decision['operation'] === null && $decision['reason'] !== 'ID_REUSE') throw new RuntimeException('Rejected status decision lacks its operation.');
                if ($decision['operation'] !== 'authorize' && $decision['actionDigest'] !== null) throw new RuntimeException('Unexpected status action digest.');
                return;
            }
            if ($decision['reason'] !== 'NONE' || !in_array($decision['operation'], ['acquire', 'advance', 'authorize'], true)
                || $decision['status'] !== ($decision['operation'] === 'authorize' ? 'AUTHORIZED' : 'APPLIED')
                || ($decision['operation'] === 'authorize' ? $decision['actionDigest'] === null : $decision['actionDigest'] !== null)) throw new RuntimeException('Invalid successful status decision.');
            return;
        }
        if ($decision['operation'] !== $operation || $decision['status'] === 'NOT_FOUND') throw new RuntimeException('Unexpected anchor operation decision.');
        if ($decision['status'] === 'REJECTED') {
            if (!in_array($decision['reason'], ['HEAD', 'OWNER', 'LIMIT', 'ID_REUSE'], true)) throw new RuntimeException('Rejected decision lacks a reason.');
            if ($decision['actionDigest'] !== ($body['actionDigest'] ?? null) && !($decision['reason'] === 'ID_REUSE' && $decision['actionDigest'] === null)) throw new RuntimeException('Rejected action digest mismatch.');
            return;
        }
        if ($decision['reason'] !== 'NONE' || $decision['status'] !== ($operation === 'authorize' ? 'AUTHORIZED' : 'APPLIED')
            || $decision['actionDigest'] !== ($body['actionDigest'] ?? null)) throw new RuntimeException('Invalid successful anchor decision.');
        $expectedHead = $operation === 'advance' ? $body['target'] : $body['expectedHead'];
        $expectedOwner = $operation === 'acquire' ? ['fence' => SecretsBackendCodec::increment($body['expectedOwner']['fence']), 'bootId' => $body['newBootId'], 'clientId' => $request['clientId']] : $body['expectedOwner'];
        if (!SecretsBackendCodec::same($decision['head'], $expectedHead) || !SecretsBackendCodec::same($decision['owner'], $expectedOwner)) throw new RuntimeException('Successful anchor decision describes a different state.');
        // Envelope head/owner describe NOW; an idempotent historical decision may describe an older state.
    }
    private function https(string $wire): string
    {
        if (!function_exists('curl_init')) throw new RuntimeException('PHP curl is required.');
        $url = $this->settings['url']; $parts = parse_url($url);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || ($parts['path'] ?? '') !== '/v1/anchor'
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) throw new RuntimeException('Configure an exact HTTPS /v1/anchor URL.');
        foreach (['clientCertificate', 'clientKey', 'caFile'] as $field) if (!is_file($this->settings[$field])) throw new RuntimeException('Anchor TLS material is missing.');
        $body = ''; $curl = curl_init($url);
        curl_setopt_array($curl, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $wire, CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_RETURNTRANSFER => false, CURLOPT_FOLLOWLOCATION => false, CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_TIMEOUT => 10,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_SSLCERT => $this->settings['clientCertificate'], CURLOPT_SSLKEY => $this->settings['clientKey'], CURLOPT_CAINFO => $this->settings['caFile'],
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body): int { if (strlen($body) + strlen($chunk) > 65536) return 0; $body .= $chunk; return strlen($chunk); }]);
        try { if (curl_exec($curl) === false || curl_getinfo($curl, CURLINFO_RESPONSE_CODE) !== 200) throw new RuntimeException('Anchor unavailable; no offline authorization.'); }
        finally { curl_close($curl); }
        return $body;
    }
    public static function operationDigest(string $deployment, string $client, string $operation, array $body): string
    {
        return hash('sha256', SecretsBackendCodec::canonical(['deploymentId' => $deployment, 'clientId' => $client, 'operation' => $operation, 'body' => $body]));
    }
}
