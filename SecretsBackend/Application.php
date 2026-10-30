<?php
declare(strict_types=1);
require_once __DIR__ . '/Store.php';
require_once __DIR__ . '/Tree.php';
require_once __DIR__ . '/../SecretsManager/libs/PortalSecurity.php';
require_once __DIR__ . '/../SecretsManager/libs/WebAuthn/src/WebAuthn.php';

/** Dedicated administrator API. It never accepts a legacy portal session or admin password. */
final class SecretsBackendApplication
{
    private SecretsBackendStore $store;
    private array $settings;
    public function __construct(SecretsBackendStore $store, array $settings) { $this->store = $store; $this->settings = $settings; }
    private function webauthn(bool $hardware = false): \lbuchs\WebAuthn\WebAuthn
    {
        $rp = (string)parse_url($this->settings['origin'], PHP_URL_HOST);
        $auth = new \lbuchs\WebAuthn\WebAuthn('Secrets administration', $rp, $hardware ? ['packed', 'fido-u2f'] : ['none', 'packed', 'fido-u2f', 'apple', 'tpm', 'android-key'], true);
        if ($hardware) {
            $roots = $this->settings['hardwareRoots'] ?? '';
            if (!is_dir($roots) || count(glob($roots . '/*.pem') ?: []) === 0 || empty($this->settings['hardwareAAGUIDs'])) throw new RuntimeException('No reviewed hardware trust profile is installed.');
            $auth->addRootCertificates($roots, ['pem']);
        }
        return $auth;
    }
    private static function exact(array $data, array $fields): void
    {
        if (array_diff(array_keys($data), $fields) || array_diff($fields, array_keys($data))) throw new InvalidArgumentException('Unexpected request fields.');
    }
    private function cookieName(): string { return '__Host-SECB_' . $this->settings['backend']; }
    private function session(array $request, array $current): array
    {
        $cookies = []; preg_match_all('/(?:^|;\s*)' . preg_quote($this->cookieName(), '/') . '=([A-Za-z0-9_-]{43})(?:;|$)/', $request['cookie'] ?? '', $matches);
        if (count($matches[1]) !== 1) throw new RuntimeException('Administrator login is required.');
        $hash = hash('sha256', $matches[1][0]); $session = $this->store->get($hash, 'session');
        $credential = $current['state']['identity']['credentials'][$session['credential']] ?? null;
        if (!is_array($credential) || !$credential['active'] || $session['revocation'] !== $current['state']['identity']['revocation']
            || $session['administrator'] !== $credential['administrator']
            || $session['origin'] !== $this->settings['origin'] || $session['created'] + 3600 < time() || $session['last'] + 900 < time()) throw new RuntimeException('Administrator session expired or revoked.');
        $session['hash'] = $hash; return $session;
    }
    private function requireCsrf(array $request, array $session): void
    {
        if (!is_string($request['csrf'] ?? null) || !hash_equals($session['csrf'], $request['csrf'])) throw new RuntimeException('CSRF verification failed.');
    }
    private function credential(array $credential, array $challenge, array $assertion): int
    {
        self::exact($assertion, ['type', 'rawId', 'response']);
        $response = $assertion['response']; self::exact($response, ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle']);
        if ($assertion['type'] !== 'public-key' || !in_array($assertion['rawId'], $challenge['allowed'], true) || $assertion['rawId'] !== $credential['id']) throw new RuntimeException('Wrong approval credential.');
        $client = SecretsBackendCodec::unb64($response['clientDataJSON']); $authData = SecretsBackendCodec::unb64($response['authenticatorData']);
        $clientObject = SecretsFrontendConfiguration::decode($client);
        if (($clientObject['type'] ?? '') !== 'webauthn.get' || ($clientObject['challenge'] ?? '') !== $challenge['challenge']
            || ($clientObject['origin'] ?? '') !== $this->settings['origin'] || ($clientObject['crossOrigin'] ?? false) !== false) throw new RuntimeException('Invalid WebAuthn client data.');
        if ($response['userHandle'] !== null && (!is_string($response['userHandle']) || $response['userHandle'] !== $credential['userHandle'])) throw new RuntimeException('User handle mismatch.');
        $verifier = $this->webauthn();
        $verifier->processGet($client, $authData, SecretsBackendCodec::unb64($response['signature']), $credential['publicKey'], SecretsBackendCodec::unb64($challenge['challenge'], 32), $credential['counter'], true, true);
        $data = new \lbuchs\WebAuthn\Attestation\AuthenticatorData($authData);
        if (!SecretsPortalSecurity::validateBackupFlags($data->getIsBackupEligible(), $data->getIsBackup(), $credential['backupEligible'])) throw new RuntimeException('Credential backup flags changed.');
        if ($challenge['hardware'] && (!$credential['hardware'] || $data->getIsBackupEligible())) throw new RuntimeException('Hardware approval is required.');
        return (int)($verifier->getSignatureCounter() ?? 0);
    }
    private function challenge(array $current, array $credentials, bool $hardware, string $kind, array $context): array
    {
        $ids = []; foreach ($credentials as $credential) if ($credential['active'] && (!$hardware || $credential['hardware'])) $ids[] = $credential['id'];
        if (!$ids) throw new RuntimeException('No eligible administrator key. Use independent recovery if all keys are lost.');
        $verifier = $this->webauthn(); $args = $verifier->getGetArgs(array_map([SecretsBackendCodec::class, 'unb64'], $ids), 120, true, true, true, true, true, true);
        $id = SecretsBackendCodec::b64(random_bytes(32));
        $this->store->put($id, $kind, ['challenge' => SecretsBackendCodec::b64($verifier->getChallenge()->getBinaryString()), 'allowed' => $ids,
            'head' => $current['head'], 'hardware' => $hardware, 'context' => $context], time() + 120);
        return ['challengeId' => $id, 'options' => $args->publicKey];
    }
    public function beginEnrollment(string $label, bool $hardware): string
    {
        if ($label === '' || strlen($label) > 80 || preg_match('/[\x00-\x1f]/', $label)) throw new InvalidArgumentException('Invalid administrator label.');
        $this->store->read(); $token = SecretsBackendCodec::b64(random_bytes(32));
        $this->store->put(hash('sha256', $token), 'enrollment', ['label' => $label, 'hardware' => $hardware, 'independentRecovery' => true], time() + 600);
        return $token;
    }
    private function enrollmentOptions(array $data): array
    {
        self::exact($data, ['code']); $token = $this->store->get(hash('sha256', $data['code']), 'enrollment');
        $current = $this->store->read(); $auth = $this->webauthn($token['hardware']); $user = random_bytes(32);
        $args = $auth->getCreateArgs($user, $token['label'], $token['label'], 120, 'preferred', true, $token['hardware'] ? true : null,
            array_map(static fn($c) => SecretsBackendCodec::unb64($c['id']), array_values($current['state']['identity']['credentials'])));
        if ($token['hardware']) $args->publicKey->attestation = 'direct';
        $id = SecretsBackendCodec::b64(random_bytes(32));
        $this->store->put($id, 'registration', ['tokenHash' => hash('sha256', $data['code']), 'challenge' => SecretsBackendCodec::b64($auth->getChallenge()->getBinaryString()),
            'head' => $current['head'], 'userHandle' => SecretsBackendCodec::b64($user), 'label' => $token['label'], 'hardware' => $token['hardware']], time() + 120);
        return ['challengeId' => $id, 'options' => $args->publicKey];
    }
    private function enrollmentVerify(array $data): array
    {
        self::exact($data, ['challengeId', 'credential']);
        $registration = $this->store->get($data['challengeId'], 'registration', true);
        $this->store->get($registration['tokenHash'], 'enrollment', true); // Independent console approval consumed once.
        $credential = $data['credential']; self::exact($credential, ['type', 'rawId', 'response']); self::exact($credential['response'], ['clientDataJSON', 'attestationObject']);
        $client = SecretsBackendCodec::unb64($credential['response']['clientDataJSON']); $object = SecretsFrontendConfiguration::decode($client);
        if ($credential['type'] !== 'public-key' || ($object['type'] ?? '') !== 'webauthn.create' || ($object['challenge'] ?? '') !== $registration['challenge']
            || ($object['origin'] ?? '') !== $this->settings['origin'] || ($object['crossOrigin'] ?? false) !== false) throw new RuntimeException('Registration context mismatch.');
        $verifier = $this->webauthn($registration['hardware']);
        $created = $verifier->processCreate($client, SecretsBackendCodec::unb64($credential['response']['attestationObject']), SecretsBackendCodec::unb64($registration['challenge'], 32), true, true, true);
        $id = SecretsBackendCodec::b64($created->credentialId);
        if ($id !== $credential['rawId'] || !SecretsPortalSecurity::validateBackupFlags($created->isBackupEligible, $created->isBackedUp)) throw new RuntimeException('Registration credential mismatch.');
        $aaguid = bin2hex($created->AAGUID);
        if ($registration['hardware'] && ($created->rootValid !== true || $created->isBackupEligible || !in_array($aaguid, $this->settings['hardwareAAGUIDs'], true))) throw new RuntimeException('Hardware attestation does not satisfy the reviewed trust profile.');
        $current = $this->store->read();
        $entry = ['id' => $id, 'publicKey' => $created->credentialPublicKey, 'label' => $registration['label'], 'active' => true, 'administrator' => $current['state']['identity']['ownerId'],
            'hardware' => $registration['hardware'], 'aaguid' => $aaguid, 'attestationFormat' => $created->attestationFormat,
            'attestationEvidence' => $credential['response']['attestationObject'], 'trustVersion' => $this->settings['hardwareTrustVersion'] ?? 'none',
            'counter' => (int)($created->signatureCounter ?? 0), 'backupEligible' => $created->isBackupEligible, 'userHandle' => $registration['userHandle']];
        $this->store->change($registration['head'], SecretsBackendCodec::uuid(), hash('sha256', SecretsBackendCodec::json($entry)), static function (array $state) use ($id, $entry): array {
            if (isset($state['identity']['credentials'][$id])) throw new RuntimeException('Credential already exists.');
            $state['identity']['credentials'][$id] = $entry; $state['identity']['revocation'] = SecretsBackendCodec::increment($state['identity']['revocation']); return $state;
        });
        return ['registered' => true];
    }
    public function handle(string $action, array $data, array $request): array
    {
        if (($request['origin'] ?? '') !== $this->settings['origin']) throw new RuntimeException('Origin mismatch.');
        $this->store->rate(hash('sha256', ($request['remote'] ?? '') . ':' . $action), in_array($action, ['authOptions', 'authVerify', 'enrollmentOptions', 'enrollmentVerify'], true) ? 10 : 120);
        $current = $this->store->read();
        if ($current['state']['policy']['origin'] !== $this->settings['origin'] || $current['state']['policy']['frontend'] !== (string)$this->settings['frontend']) throw new RuntimeException('Protected origin or frontend binding differs; use independent recovery.');
        if ($action === 'status') { self::exact($data, []); return ['data' => ['ready' => true, 'enrollmentNeeded' => count($current['state']['identity']['credentials']) === 0]]; }
        if ($action === 'enrollmentOptions') return ['data' => $this->enrollmentOptions($data)];
        if ($action === 'enrollmentVerify') return ['data' => $this->enrollmentVerify($data)];
        if ($action === 'authOptions') { self::exact($data, []); return ['data' => $this->challenge($current, $current['state']['identity']['credentials'], false, 'login', [])]; }
        if ($action === 'authVerify') {
            self::exact($data, ['challengeId', 'credential']); $challenge = $this->store->get($data['challengeId'], 'login', true);
            $id = $data['credential']['rawId'] ?? ''; $entry = $current['state']['identity']['credentials'][$id] ?? null;
            if (!is_array($entry) || !$entry['active']) throw new RuntimeException('Credential is not an administrator.');
            $counter = $this->credential($entry, $challenge, $data['credential']);
            $this->store->change($challenge['head'], SecretsBackendCodec::uuid(), hash('sha256', $data['challengeId']), static function (array $state) use ($id, $counter): array { $state['identity']['credentials'][$id]['counter'] = $counter; return $state; });
            $this->store->authorize('login', hash('sha256', $id . ':' . $data['challengeId']));
            $current = $this->store->read(); $raw = SecretsBackendCodec::b64(random_bytes(32)); $csrf = SecretsBackendCodec::b64(random_bytes(32));
            $this->store->put(hash('sha256', $raw), 'session', ['credential' => $id, 'administrator' => $entry['administrator'], 'revocation' => $current['state']['identity']['revocation'], 'csrf' => $csrf,
                'origin' => $this->settings['origin'], 'created' => time(), 'last' => time()], time() + 3600);
            return ['data' => ['authenticated' => true, 'csrf' => $csrf], 'cookie' => $this->cookieName() . '=' . $raw . '; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600'];
        }
        $session = $this->session($request, $current);
        if ($action !== 'session') $this->requireCsrf($request, $session);
        if ($action === 'logout') { self::exact($data, []); $this->store->delete($session['hash']); return ['data' => ['loggedOut' => true], 'cookie' => $this->cookieName() . '=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0']; }
        if ($action === 'session' || $action === 'list') {
            self::exact($data, []); $this->store->authorize('metadata', hash('sha256', $session['hash'] . ':' . $current['head']['digest']));
            $session['last'] = time(); $this->store->replace($session['hash'], 'session', array_diff_key($session, ['hash' => true]), $session['created'] + 3600);
            return ['data' => ['authenticated' => true, 'csrf' => $session['csrf'], 'revision' => $current['state']['vault']['revision'], 'hardware' => $current['state']['policy']['hardware'],
                'global' => SecretsBackendTree::listing($current['state']['vault']['global']), 'local' => SecretsBackendTree::listing($current['state']['vault']['local']),
                'credentials' => array_map(static fn($c) => array_intersect_key($c, array_flip(['id', 'label', 'active', 'hardware'])), array_values($current['state']['identity']['credentials']))]];
        }
        if ($action === 'prepare') {
            self::exact($data, ['operation']); $operation = $this->operation($data['operation'], $current['state']);
            $class = in_array($operation['kind'], ['save', 'delete'], true) ? 'write' : ($operation['kind'] === 'reveal' ? 'reveal' : 'identity');
            $hardware = $class === 'identity' ? in_array(true, $current['state']['policy']['hardware'], true) : $current['state']['policy']['hardware'][$class];
            if ($operation['kind'] === 'policy' && in_array(true, $operation['hardware'], true)) $hardware = true;
            $eligible = array_filter($current['state']['identity']['credentials'], static fn($credential) => $credential['administrator'] === $session['administrator']);
            $args = $this->challenge($current, $eligible, $hardware, 'approval',
                ['session' => $session['hash'], 'operation' => $operation, 'operationId' => SecretsBackendCodec::uuid()]);
            return ['data' => $args + ['requiresHardware' => $hardware]];
        }
        if ($action === 'approve') {
            self::exact($data, ['challengeId', 'credential']); $challenge = $this->store->get($data['challengeId'], 'approval', true);
            if ($challenge['context']['session'] !== $session['hash']) throw new RuntimeException('Approval belongs to a different session.');
            $approvalCredential = $data['credential']['rawId'] ?? '';
            $entry = $current['state']['identity']['credentials'][$approvalCredential] ?? null;
            if (!is_array($entry) || !$entry['active'] || $entry['administrator'] !== $session['administrator']) throw new RuntimeException('Approval administrator mismatch.');
            $counter = $this->credential($entry, $challenge, $data['credential']); $operation = $this->operation($challenge['context']['operation'], $current['state']);
            $id = $approvalCredential; $operationId = $challenge['context']['operationId'];
            $digest = hash('sha256', SecretsBackendCodec::json(['operation' => $operation, 'session' => $session['hash'], 'credential' => $id, 'approval' => $data['challengeId']]));
            $this->store->change($challenge['head'], $operationId, $digest, function (array $state) use ($operation, $id, $counter): array {
                $state = $this->apply($operation, $state); $state['identity']['credentials'][$id]['counter'] = $counter; return $state;
            });
            if ($operation['kind'] === 'reveal') {
                $this->store->authorize('reveal', $digest); $latest = $this->store->read();
                // The protected counter commit is not permission to read a different record revision.
                if ($latest['state']['vault']['revision'] !== $operation['revision']) throw new RuntimeException('Record changed before reveal.');
                return ['data' => ['fields' => SecretsBackendTree::reveal(SecretsBackendTree::at($latest['state']['vault'][$operation['scope']], $operation['path'])), 'clearAfterSeconds' => 30]];
            }
            return ['data' => ['committed' => true, 'operationId' => $operationId]];
        }
        throw new InvalidArgumentException('Unknown frontend action.');
    }
    private function operation(array $operation, array $state): array
    {
        $kind = $operation['kind'] ?? '';
        if (in_array($kind, ['save', 'delete', 'reveal'], true)) {
            self::exact($operation, $kind === 'save' ? ['kind', 'scope', 'path', 'revision', 'mode', 'json'] : ['kind', 'scope', 'path', 'revision']);
            if (!in_array($operation['scope'], ['global', 'local'], true) || !is_array($operation['path']) || !$operation['path'] || !is_string($operation['revision']) || $operation['revision'] !== $state['vault']['revision']) throw new RuntimeException('Invalid scope or stale revision.');
            SecretsBackendTree::path($operation['path']);
            if ($kind === 'save') { if (!is_string($operation['json']) || !in_array($operation['mode'], ['create', 'replace'], true)) throw new InvalidArgumentException('Invalid save.'); SecretsBackendTree::parse($operation['json']); }
            else SecretsBackendTree::at($state['vault'][$operation['scope']], $operation['path']);
        } elseif ($kind === 'revoke') {
            self::exact($operation, ['kind', 'credentialId']);
            if (!isset($state['identity']['credentials'][$operation['credentialId']])) throw new RuntimeException('Unknown credential.');
        } elseif ($kind === 'policy') {
            self::exact($operation, ['kind', 'hardware']); self::exact($operation['hardware'], ['write', 'identity', 'export', 'reveal']);
            foreach ($operation['hardware'] as $required) if (!is_bool($required)) throw new InvalidArgumentException('Invalid hardware policy.');
        } else throw new InvalidArgumentException('Unknown operation.');
        return $operation;
    }
    private function apply(array $operation, array $state): array
    {
        if (in_array($operation['kind'], ['save', 'delete'], true)) {
            SecretsBackendTree::edit($state['vault'][$operation['scope']], $operation['path'], $operation['kind'] === 'save' ? SecretsBackendTree::parse($operation['json']) : null, $operation['kind'] === 'save' ? $operation['mode'] : 'delete');
            $state['vault']['revision'] = SecretsBackendCodec::increment($state['vault']['revision']);
            if ($operation['scope'] === 'global') {
                $state['stream']['globalRevision'] = SecretsBackendCodec::increment($state['stream']['globalRevision']);
                // Every configured peer receives an immutable complete snapshot in this SAME core.
                foreach ($state['pairing']['peers'] as $peer) {
                    if (!$peer['active']) continue;
                    $sequence = $state['stream']['next'][$peer['id']] ?? '0'; $sequence = SecretsBackendCodec::increment($sequence); $state['stream']['next'][$peer['id']] = $sequence;
                    $snapshot = SecretsBackendCodec::json($state['vault']['global']);
                    $state['outbox']['jobs'][] = ['operationId' => SecretsBackendCodec::uuid(), 'receiverId' => $peer['id'], 'pairingId' => $peer['pairingId'], 'epoch' => $peer['epoch'],
                        'sourceRevision' => $state['stream']['globalRevision'], 'sequence' => $sequence, 'payloadDigest' => hash('sha256', $snapshot), 'snapshot' => $snapshot, 'status' => 'queued'];
                }
            }
        } elseif ($operation['kind'] === 'revoke') {
            $state['identity']['credentials'][$operation['credentialId']]['active'] = false;
            $active = array_filter($state['identity']['credentials'], static fn($credential) => $credential['active']);
            if (!$active || (in_array(true, $state['policy']['hardware'], true) && !array_filter($active, static fn($credential) => $credential['hardware']))) throw new RuntimeException('Cannot revoke the last eligible administrator.');
            $state['identity']['revocation'] = SecretsBackendCodec::increment($state['identity']['revocation']);
        } elseif ($operation['kind'] === 'policy') {
            $eligible = array_filter($state['identity']['credentials'], static fn($credential) => $credential['active'] && $credential['hardware']);
            if (in_array(true, $operation['hardware'], true) && count($eligible) < 2) throw new RuntimeException('Enroll and test two separate approved hardware credentials before enforcement.');
            $state['policy']['hardware'] = $operation['hardware']; $state['policy']['version'] = SecretsBackendCodec::increment($state['policy']['version']);
        }
        return $state;
    }
}
