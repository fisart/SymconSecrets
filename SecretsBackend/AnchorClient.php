<?php
declare(strict_types=1);
require_once __DIR__ . '/Codec.php';
require_once __DIR__ . '/../SecretsFrontend/Configuration.php';

final class SecretsBackendAnchorClient
{
    private array $settings;
    private $transport;
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
        return $response;
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
