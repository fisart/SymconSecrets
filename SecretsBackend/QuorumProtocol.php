<?php
declare(strict_types=1);
require_once __DIR__ . '/Codec.php';
require_once __DIR__ . '/../SecretsFrontend/Configuration.php';

/** DC-01 V2 codec. This is deliberately not an adapter for the V1 witness/store. */
final class SecretsBackendQuorumProtocol
{
    public const PROFILE_SHA256 = 'd406bb26320866f390b4d2222f6307516ff0edadcdd2ef166277f9ec739176fc';
    private array $profile;
    public function __construct()
    {
        $raw = file_get_contents(__DIR__ . '/quorum/protocol/profile.json');
        if (!is_string($raw) || !hash_equals(self::PROFILE_SHA256, hash('sha256', $raw))) throw new RuntimeException('Quorum protocol profile integrity failure.');
        $this->profile = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    }
    public function decode(string $raw): array
    {
        // The existing strict scanner rejects duplicate keys after unescaping.
        SecretsFrontendConfiguration::decode($raw);
        $object = json_decode($raw, false, 10, JSON_THROW_ON_ERROR);
        if (!$object instanceof stdClass) throw new InvalidArgumentException('Quorum wire root must be an object.');
        $walk = static function ($node, int $depth) use (&$walk): void {
            if (is_int($node) || is_float($node)) throw new InvalidArgumentException('Quorum numbers must be strings.');
            if (is_string($node) && preg_match('/[^\x20-\x7e]/', $node)) throw new InvalidArgumentException('Non-ASCII quorum metadata.');
            if (is_object($node) || is_array($node)) {
                if ($depth > 8 || (is_array($node) && count($node) > 100)) throw new InvalidArgumentException('Quorum depth/array limit.');
                foreach ($node as $key => $value) {
                    if (is_string($key) && preg_match('/[^\x20-\x7e]/', $key)) throw new InvalidArgumentException('Non-ASCII quorum key.');
                    $walk($value, $depth + 1);
                }
            }
        };
        $walk($object, 1);
        // Preserve empty objects so a network edit from [] to {} cannot survive
        // associative-array decoding and retain the same verified signature.
        $convert = static function ($node) use (&$convert) {
            if ($node instanceof stdClass) {
                $fields = get_object_vars($node);
                if ($fields === []) return new stdClass();
                return array_map($convert, $fields);
            }
            return is_array($node) ? array_map($convert, $node) : $node;
        };
        $result = [];
        foreach (get_object_vars($object) as $key => $value) $result[$key] = $convert($value);
        return $result;
    }
    private function fields($value, array $fields, string $operation): void
    {
        if (!is_array($value) || array_diff(array_keys($value), array_keys($fields)) || array_diff(array_keys($fields), array_keys($value))) throw new InvalidArgumentException('Invalid closed quorum field set.');
        foreach ($fields as $key => $type) $this->validate($value[$key], $type, $operation);
    }
    public function validate($value, string $type, string $operation = ''): void
    {
        if (str_ends_with($type, '?')) { if ($value === null) return; $type = substr($type, 0, -1); }
        if (str_ends_with($type, '[]')) {
            if (!is_array($value) || !array_is_list($value) || count($value) > 100) throw new InvalidArgumentException('Invalid quorum array.');
            foreach ($value as $item) $this->validate($item, substr($type, 0, -2), $operation);
            return;
        }
        if (isset($this->profile['records'][$type])) { $this->fields($value, $this->profile['records'][$type]['fields'], $operation); return; }
        if (isset($this->profile['enums'][$type])) {
            if (!is_string($value) || !in_array($value, $this->profile['enums'][$type], true)) throw new InvalidArgumentException('Invalid quorum enum.');
            return;
        }
        if ($type === 'Operation') { if (!is_string($value) || !isset($this->profile['operations'][$value])) throw new InvalidArgumentException('Unknown quorum operation.'); return; }
        if (in_array($type, ['OperationBody', 'OperationResult'], true)) {
            if (!isset($this->profile['operations'][$operation])) throw new InvalidArgumentException('Missing quorum dispatch context.');
            $this->fields($value, $this->profile['operations'][$operation][$type === 'OperationBody' ? 'body' : 'result']['fields'], $operation); return;
        }
        if (in_array($type, ['Actor', 'AuthorizationEvidence'], true)) {
            if (!is_array($value)) throw new InvalidArgumentException('Invalid quorum union.');
            foreach ($this->profile['unions'][$type] as $choice) {
                $enum = $this->profile['records'][$choice]['fields']['kind'];
                if (in_array($value['kind'] ?? null, $this->profile['enums'][$enum], true)) { $this->validate($value, $choice, $operation); return; }
            }
            throw new InvalidArgumentException('Unknown quorum union tag.');
        }
        if (!is_string($value)) throw new InvalidArgumentException('Invalid quorum primitive.');
        $valid = false;
        switch ($type) {
            case 'UUID': $valid = (bool)preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/D', $value); break;
            case 'DIGEST': $valid = (bool)preg_match('/^[a-f0-9]{64}$/D', $value); break;
            case 'NATIVE_ID': $valid = (bool)preg_match('/^[a-f0-9]{16}$/D', $value) && $value !== '0000000000000000'; break;
            case 'Q': case 'Q_POS': $valid = preg_match('/^(0|[1-9][0-9]*)$/D', $value) && (strlen($value) < 19 || (strlen($value) === 19 && strcmp($value, '9223372036854775807') <= 0)) && ($type !== 'Q_POS' || $value !== '0'); break;
            case 'B64_16': case 'B64_32': case 'B64_64': SecretsBackendCodec::unb64($value, (int)substr($type, 4)); return;
            case 'B64_VAR': SecretsBackendCodec::unb64($value); $valid = strlen($value) <= 16384; break;
            case 'ASCII_2048': case 'ASCII_253': $valid = strlen($value) > 0 && strlen($value) <= (int)substr($type, 6) && !preg_match('/[^\x20-\x7e]/', $value); break;
        }
        if (!$valid) throw new InvalidArgumentException('Invalid quorum type: ' . $type);
    }
    public function actionDigest(array $request): string
    {
        $logical = []; foreach ($this->profile['signingRules']['actionDigestFields'] as $key) $logical[$key] = $request[$key];
        return hash('sha256', $this->profile['domains']['action'] . SecretsBackendCodec::canonical($logical));
    }
    public function verify(string $domain, array $record, string $signature, string $publicKey): void
    {
        if (!isset($this->profile['domains'][$domain]) || strlen($publicKey) !== 32 || !sodium_crypto_sign_verify_detached(SecretsBackendCodec::unb64($signature, 64), $this->profile['domains'][$domain] . SecretsBackendCodec::canonical($record), $publicKey)) throw new RuntimeException('Quorum signature verification failed.');
    }
    public function signRequest(array $request, string $privateKey): string
    {
        $this->validate($request, 'Request', $request['action']['operation'] ?? '');
        if (strlen($privateKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) throw new InvalidArgumentException('Invalid quorum signing key.');
        $signature = SecretsBackendCodec::b64(sodium_crypto_sign_detached($this->profile['domains']['request'] . SecretsBackendCodec::canonical($request), $privateKey));
        $wire = SecretsBackendCodec::json(['request' => $request, 'signature' => $signature]);
        $this->decode($wire); // Enforce wire size/depth, not just individual field types.
        return $wire;
    }
    /** TrustPack and gateway map must come from independently pinned current trust. */
    public function verifyResponse(string $raw, array $request, array $trustPack, array $gateways): array
    {
        $wire = $this->decode($raw); $operation = $request['action']['operation'] ?? '';
        $this->validate($request, 'Request', $operation);
        $this->validate($wire, 'WireResponse', $operation); $this->validate($trustPack, 'TrustPack');
        $response = $wire['response']; $server = $gateways[$response['serverId']] ?? null;
        if (!is_array($server) || ($server['keyId'] ?? '') !== $wire['keyId']) throw new RuntimeException('Unpinned quorum gateway.');
        $this->verify('response', $response, $wire['signature'], SecretsBackendCodec::unb64($server['publicKey'], 32));
        foreach (['clusterId', 'realmId', 'incarnation', 'trustRevision', 'nativeClusterId'] as $key) if ($response[$key] !== $trustPack[$key]) throw new RuntimeException('Quorum response lineage mismatch.');
        foreach (['version', 'clusterId', 'realmId', 'incarnation', 'trustRevision', 'requestId', 'nonce'] as $key) if ($response[$key] !== $request[$key]) throw new RuntimeException('Quorum request/response binding mismatch.');
        if ($response['operation'] !== $operation || !hash_equals($this->actionDigest($request), $response['actionDigest'])) throw new RuntimeException('Quorum action binding mismatch.');
        foreach (['clusterId', 'realmId', 'incarnation'] as $key) if ($response['currentHead'][$key] !== $request[$key]) throw new RuntimeException('Quorum head lineage mismatch.');
        $decision = $response['decision']; $action = $request['action'];
        if ($decision !== null) {
            if ($decision['operationId'] !== $action['operationId'] || $decision['operation'] !== $operation || $decision['actionDigest'] !== $response['actionDigest'] || $decision['incarnation'] !== $request['incarnation'] || $decision['actorDigest'] !== hash('sha256', SecretsBackendCodec::canonical($request['actor']))) throw new RuntimeException('Quorum decision binding mismatch.');
        }
        if ($response['outcome'] === 'REJECTED') {
            if ($response['result'] !== null || $decision === null || $decision['result'] !== 'REJECTED' || $decision['reason'] === 'NONE' || $decision['resultHeadDigest'] !== null) throw new RuntimeException('Inconsistent quorum rejection.');
            return $response;
        }
        if (!is_array($response['result'])) throw new RuntimeException('Missing quorum success result.');
        if (in_array($operation, ['readHead', 'status'], true)) { if ($decision !== null) throw new RuntimeException('Unexpected quorum read decision.'); }
        elseif ($decision === null || !in_array($decision['result'], $this->profile['responseDecisionContract']['successResultsByOperation'][$operation], true) || $decision['reason'] !== 'NONE') throw new RuntimeException('Inconsistent quorum success.');
        if ($operation === 'status') {
            $result = $response['result']; $target = $result['targetDecision'];
            if ($result['resolution'] === 'UNKNOWN') { if ($target !== null) throw new RuntimeException('UNKNOWN is not a decision.'); }
            elseif ($target === null || $target['operationId'] !== $action['body']['targetOperationId'] || $target['actionDigest'] !== $action['body']['targetActionDigest']) throw new RuntimeException('Historical quorum decision mismatch.');
        }
        return $response;
    }
}
