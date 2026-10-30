<?php
declare(strict_types=1);
require_once __DIR__ . '/Codec.php';
require_once __DIR__ . '/AnchorClient.php';

/** Separate encrypted vault. SQLite prepares durably; the external anchor decides; SQLite publishes. */
final class SecretsBackendStore
{
    private const KINDS = ['vault', 'identity', 'policy', 'pairing', 'stream', 'operations', 'outbox'];
    private PDO $db;
    private string $key;
    private array $identity;
    private string $runtime;
    private SecretsBackendAnchorClient $anchor;
    private $fault;
    private string $directory;
    private string $keyDirectory;
    private bool $inTransaction = false;

    public function __construct(string $directory, string $keyDirectory, string $runtime, SecretsBackendAnchorClient $anchor, string $journal = 'WAL', ?callable $fault = null)
    {
        SecretsBackendCodec::privateDirectory($directory); SecretsBackendCodec::privateDirectory($keyDirectory);
        if (!is_file($directory . '/vault.sqlite') || is_link($directory . '/vault.sqlite') || (fileperms($directory . '/vault.sqlite') & 0077) !== 0 || !is_file($keyDirectory . '/master.key')) throw new RuntimeException('Initialize a private new development vault from the backend console first.');
        $this->key = SecretsBackendCodec::privateFile($keyDirectory . '/master.key');
        if (strlen($this->key) !== 16) throw new RuntimeException('Invalid master key; no replacement key is generated.');
        $this->db = new PDO('sqlite:' . $directory . '/vault.sqlite', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
        self::pragmas($this->db, $journal);
        $this->identity = json_decode($this->meta('identity'), true, 8, JSON_THROW_ON_ERROR);
        $this->runtime = $runtime; $this->anchor = $anchor; $this->fault = $fault;
        $this->directory = $directory; $this->keyDirectory = $keyDirectory;
        $this->db->exec('CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY, bucket TEXT NOT NULL, sealed TEXT NOT NULL);');
    }

    private static function pragmas(PDO $db, string $journal): void
    {
        // DELETE is accepted only by direct test harnesses. The Symcon module always requests WAL.
        if (!in_array($journal, ['WAL', 'DELETE'], true)) throw new RuntimeException('Unsupported journal.');
        $version = $db->query('SELECT sqlite_version()')->fetchColumn();
        if ($journal === 'WAL' && version_compare($version, '3.51.3', '<')) throw new RuntimeException('WAL requires SQLite 3.51.3 or later in this build; reviewed backports are not yet enabled.');
        $actual = strtoupper($db->query('PRAGMA journal_mode=' . $journal)->fetchColumn());
        if ($actual !== $journal) throw new RuntimeException('Cannot activate the required SQLite journal.');
        $db->exec('PRAGMA synchronous=FULL'); $db->exec('PRAGMA foreign_keys=ON'); $db->exec('PRAGMA busy_timeout=2000');
        if ((int)$db->query('PRAGMA synchronous')->fetchColumn() !== 2 || (int)$db->query('PRAGMA foreign_keys')->fetchColumn() !== 1) throw new RuntimeException('SQLite durability settings were not applied.');
    }

    public static function initialize(string $directory, string $keyDirectory, string $origin, int $frontend, string $journal = 'WAL'): array
    {
        $probe = new PDO('sqlite::memory:');
        if ($journal === 'WAL' && version_compare($probe->query('SELECT sqlite_version()')->fetchColumn(), '3.51.3', '<')) throw new RuntimeException('WAL requires SQLite 3.51.3 or later; initialization made no security files.');
        SecretsBackendCodec::privateDirectory($directory); SecretsBackendCodec::privateDirectory($keyDirectory);
        $dataPath = realpath($directory); $keysPath = realpath($keyDirectory);
        if ($dataPath === $keysPath || str_starts_with($dataPath . '/', $keysPath . '/') || str_starts_with($keysPath . '/', $dataPath . '/')) throw new RuntimeException('Use separate, non-nested data and key directories.');
        foreach ([$directory, $keyDirectory] as $newDirectory) if (count(array_diff(scandir($newDirectory), ['.', '..'])) !== 0) throw new RuntimeException('Storage setup requires new or empty directories; old module storage is never adopted.');
        foreach ([$directory . '/vault.sqlite', $keyDirectory . '/master.key', $keyDirectory . '/anchor-sign.key', $keyDirectory . '/sync-sign.key'] as $file) if (file_exists($file) || is_link($file)) throw new RuntimeException('Security storage already exists; initialize never overwrites it.');
        $identity = ['deploymentId' => SecretsBackendCodec::uuid(), 'clientId' => SecretsBackendCodec::uuid(), 'generation' => SecretsBackendCodec::b64(random_bytes(32)), 'keyId' => SecretsBackendCodec::b64(random_bytes(32))];
        $key = random_bytes(16); $anchorKey = sodium_crypto_sign_keypair(); $syncKey = sodium_crypto_sign_keypair();
        SecretsBackendCodec::writeNew($keyDirectory . '/master.key', $key);
        SecretsBackendCodec::writeNew($keyDirectory . '/anchor-sign.key', sodium_crypto_sign_secretkey($anchorKey));
        SecretsBackendCodec::writeNew($keyDirectory . '/sync-sign.key', sodium_crypto_sign_secretkey($syncKey));
        $oldMask = umask(0077);
        try { $db = new PDO('sqlite:' . $directory . '/vault.sqlite', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]); }
        finally { umask($oldMask); }
        chmod($directory . '/vault.sqlite', 0600); self::pragmas($db, $journal);
        $db->exec('CREATE TABLE metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE cores (id TEXT PRIMARY KEY, head TEXT NOT NULL, manifest TEXT NOT NULL, payloads TEXT NOT NULL); CREATE TABLE ephemeral (id TEXT PRIMARY KEY, kind TEXT NOT NULL, boot TEXT NOT NULL, expires INTEGER NOT NULL, payload TEXT NOT NULL);');
        $state = [
            'vault' => ['global' => ['type' => 'object', 'entries' => []], 'local' => ['type' => 'object', 'entries' => []], 'revision' => '0'],
            'identity' => ['credentials' => [], 'revocation' => '0', 'ownerId' => SecretsBackendCodec::b64(random_bytes(32))],
            'policy' => ['origin' => $origin, 'frontend' => (string)$frontend, 'version' => '1', 'management' => null, 'hardware' => ['write' => false, 'identity' => false, 'export' => false, 'reveal' => false]],
            'pairing' => ['peers' => []], 'stream' => ['globalRevision' => '0', 'next' => [], 'received' => []],
            'operations' => ['outcomes' => [], 'audit' => []], 'outbox' => ['jobs' => []],
        ];
        $core = self::pack($state, $key, $identity, null);
        $db->beginTransaction();
        try {
            $statement = $db->prepare('INSERT INTO cores VALUES (?, ?, ?, ?)'); $statement->execute([$core['head']['commitId'], SecretsBackendCodec::json($core['head']), $core['manifest'], $core['payloads']]);
            foreach (['identity' => SecretsBackendCodec::json($identity), 'active' => $core['head']['commitId'], 'pending' => '', 'runtime' => '', 'status' => 'RECOVERY_CHECK', 'owner' => '', 'acquire' => ''] as $name => $value) $db->prepare('INSERT INTO metadata VALUES (?, ?)')->execute([$name, $value]);
            $db->commit();
        } catch (Throwable $exception) { if ($db->inTransaction()) $db->rollBack(); throw $exception; }
        $db = null;
        SecretsBackendCodec::syncDirectory($keyDirectory); SecretsBackendCodec::syncDirectory($directory);
        return $identity + ['head' => $core['head'], 'clientPublicKey' => SecretsBackendCodec::b64(sodium_crypto_sign_publickey($anchorKey)), 'syncPublicKey' => SecretsBackendCodec::b64(sodium_crypto_sign_publickey($syncKey))];
    }

    public function identity(): array { return $this->identity; }
    private function meta(string $name): string { $s = $this->db->prepare('SELECT value FROM metadata WHERE name=?'); $s->execute([$name]); $v = $s->fetchColumn(); if (!is_string($v)) throw new RuntimeException('Missing database metadata.'); return $v; }
    private function set(string $name, string $value): void { $this->db->prepare('INSERT INTO metadata(name,value) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value')->execute([$name, $value]); }
    private function transaction(callable $callback)
    {
        if ($this->inTransaction) return $callback();
        $this->db->exec('BEGIN IMMEDIATE');
        $this->inTransaction = true;
        try { $result = $callback(); $this->db->exec('COMMIT'); return $result; }
        catch (Throwable $exception) { try { $this->db->exec('ROLLBACK'); } catch (Throwable $ignored) {} throw $exception; }
        finally { $this->inTransaction = false; }
    }
    private function current(string $which = 'active'): array
    {
        $s = $this->db->prepare('SELECT * FROM cores WHERE id=?'); $s->execute([$this->meta($which)]); $core = $s->fetch();
        if (!is_array($core)) throw new RuntimeException('Required core is missing.');
        $core['head'] = json_decode($core['head'], true, 8, JSON_THROW_ON_ERROR); return $core;
    }
    private function ownerCheck(): array
    {
        if ($this->runtime === '' || !hash_equals($this->meta('runtime'), $this->runtime) || $this->meta('status') !== 'ACTIVE') throw new RuntimeException('Runtime is fenced or recovery is pending.');
        return json_decode($this->meta('owner'), true, 8, JSON_THROW_ON_ERROR);
    }
    private function trip(string $point): void { if ($this->fault !== null) ($this->fault)($point); }
    private static function pack(array $state, string $key, array $identity, ?array $parent, ?string $commitId = null): array
    {
        $index = $parent === null ? '0' : SecretsBackendCodec::increment($parent['index']); $id = $commitId ?? SecretsBackendCodec::uuid(); $roots = []; $payloads = [];
        foreach (self::KINDS as $kind) {
            $objectId = SecretsBackendCodec::b64(random_bytes(32));
            $context = $identity['deploymentId'] . ':' . $identity['generation'] . ':' . $kind . ':' . $objectId;
            $bytes = SecretsBackendCodec::seal(SecretsBackendCodec::json($state[$kind]), $key, $context);
            $payloads[$objectId] = $bytes;
            $roots[] = ['kind' => $kind, 'objects' => [['id' => $objectId, 'schema' => '1', 'length' => (string)strlen($bytes), 'digest' => hash('sha256', "SYMCON-SECRETS-OBJECT-V1\0" . $bytes)]]];
        }
        $manifest = SecretsBackendCodec::canonical(['version' => '1', 'deploymentId' => $identity['deploymentId'], 'generation' => $identity['generation'], 'index' => $index, 'parent' => $parent, 'roots' => $roots]);
        return ['head' => ['generation' => $identity['generation'], 'index' => $index, 'digest' => hash('sha256', "SYMCON-SECRETS-CORE-V1\0" . $manifest), 'commitId' => $id], 'manifest' => $manifest, 'payloads' => SecretsBackendCodec::json($payloads)];
    }
    private function unpack(array $core): array
    {
        $manifest = json_decode($core['manifest'], true, 12, JSON_THROW_ON_ERROR); $payloads = json_decode($core['payloads'], true, 8, JSON_THROW_ON_ERROR); $state = [];
        if (!hash_equals($core['head']['digest'], hash('sha256', "SYMCON-SECRETS-CORE-V1\0" . $core['manifest'])) || ($manifest['deploymentId'] ?? '') !== $this->identity['deploymentId'] || ($manifest['generation'] ?? '') !== $this->identity['generation'] || ($manifest['index'] ?? '') !== $core['head']['index'] || count($manifest['roots'] ?? []) !== 7) throw new RuntimeException('Core manifest mismatch.');
        foreach ($manifest['roots'] as $i => $root) {
            if (($root['kind'] ?? '') !== self::KINDS[$i] || count($root['objects'] ?? []) !== 1) throw new RuntimeException('Unexpected core object.');
            $object = $root['objects'][0]; $bytes = $payloads[$object['id']] ?? '';
            if ((string)strlen($bytes) !== $object['length'] || !hash_equals($object['digest'], hash('sha256', "SYMCON-SECRETS-OBJECT-V1\0" . $bytes))) throw new RuntimeException('Missing or modified payload.');
            $context = $this->identity['deploymentId'] . ':' . $this->identity['generation'] . ':' . $root['kind'] . ':' . $object['id'];
            $state[$root['kind']] = json_decode(SecretsBackendCodec::open($bytes, $this->key, $context), true, 64, JSON_THROW_ON_ERROR);
        }
        return $state;
    }

    /** Stable OS lock shared by final grants/advances and exclusive runtime transitions. */
    private function transition(int $mode, callable $callback)
    {
        $path = $this->keyDirectory . '/runtime.lock';
        if (is_link($path)) throw new RuntimeException('Unsafe runtime lock.');
        $mask = umask(0077);
        try { $handle = fopen($path, 'c+b'); } finally { umask($mask); }
        if ($handle === false || (fileperms($path) & 0077) !== 0) throw new RuntimeException('Private runtime lock is required.');
        try {
            if (!flock($handle, $mode | LOCK_NB)) throw new RuntimeException('Runtime transition is busy; retry later.');
            return $callback();
        } finally { flock($handle, LOCK_UN); fclose($handle); }
    }
    /** Called synchronously at reload/disable, before scheduling any remote recovery. */
    public function invalidate(): void
    {
        $this->transition(LOCK_EX, function (): void {
            $this->transaction(function (): void {
                $this->set('runtime', $this->runtime); $this->set('status', 'INSTALLING');
                $this->set('acquire', ''); $this->db->exec('DELETE FROM ephemeral');
            });
        });
    }
    public function recoveryRequired(): bool
    {
        return $this->meta('runtime') === $this->runtime && ($this->meta('status') !== 'ACTIVE' || $this->meta('pending') !== '');
    }
    public function recover(): array
    {
        return $this->transition(LOCK_EX, fn() => $this->recoverLocked());
    }
    private function recoverLocked(): array
    {
        $retry = $this->transaction(function (): ?array {
            if ($this->meta('runtime') === $this->runtime && $this->meta('status') === 'INSTALLING' && $this->meta('acquire') !== '') return json_decode($this->meta('acquire'), true, 12, JSON_THROW_ON_ERROR);
            $this->set('status', 'INSTALLING'); $this->set('runtime', $this->runtime); $this->set('acquire', ''); $this->db->exec('DELETE FROM ephemeral'); return null;
        });
        $fresh = $this->anchor->call('read', []); $active = $this->current(); $this->unpack($active);
        $pending = $this->meta('pending') !== '' ? $this->current('pending') : null;
        if ($pending !== null) $this->unpack($pending);
        if (!SecretsBackendCodec::same($fresh['head'], $active['head']) && ($pending === null || !SecretsBackendCodec::same($fresh['head'], $pending['head']))) throw new RuntimeException('Anchor mismatch: restore an exact current core; automatic rebase is forbidden.');
        $acquire = $retry ?? ['operationId' => SecretsBackendCodec::uuid(), 'expectedHead' => $fresh['head'], 'expectedOwner' => $fresh['owner'], 'newBootId' => SecretsBackendCodec::b64(random_bytes(32))];
        // One stable acquire operation survives a lost transport response in this start attempt.
        $this->transaction(function () use ($acquire): void { if ($this->meta('runtime') !== $this->runtime) throw new RuntimeException('Superseded recovery.'); $this->set('acquire', SecretsBackendCodec::json($acquire)); });
        $reply = $this->anchor->call('acquire', $acquire);
        if (($reply['result']['status'] ?? '') === 'REJECTED') {
            // A signed durable rejection is final. A timeout is NOT: leave that ID intact.
            $this->transaction(function () use ($acquire): void {
                if ($this->meta('runtime') !== $this->runtime || $this->meta('acquire') !== SecretsBackendCodec::json($acquire)) throw new RuntimeException('Superseded recovery.');
                $this->set('acquire', '');
            });
            throw new RuntimeException('Acquisition definitively rejected; automatic recovery will recheck the new head.');
        }
        if (($reply['result']['status'] ?? '') !== 'APPLIED' || !SecretsBackendCodec::same($reply['owner'], $reply['result']['owner'])) throw new RuntimeException('Runtime acquisition was superseded; independent recovery is required.');
        $this->transaction(function () use ($reply, $active, $pending): void {
            if ($this->meta('runtime') !== $this->runtime || $this->meta('status') !== 'INSTALLING' || $this->meta('active') !== $active['head']['commitId']) throw new RuntimeException('Superseded recovery publication.');
            if ($pending !== null && SecretsBackendCodec::same($reply['head'], $pending['head'])) $this->set('active', $pending['head']['commitId']);
            elseif (!SecretsBackendCodec::same($reply['head'], $active['head'])) throw new RuntimeException('Recovery head changed.');
            $this->set('pending', ''); $this->set('owner', SecretsBackendCodec::json($reply['owner'])); $this->set('status', 'ACTIVE');
        });
        return $reply['head'];
    }

    public function read(bool $fresh = true): array
    {
        [$owner, $core] = $this->transaction(function (): array {
            $owner = $this->ownerCheck(); $core = $this->current();
            if ($this->meta('pending') !== '') throw new RuntimeException('A commit outcome requires recovery.');
            return [$owner, $core];
        });
        if ($fresh) {
            $reply = $this->anchor->call('read', []);
            if (!SecretsBackendCodec::same($reply['head'], $core['head']) || !SecretsBackendCodec::same($reply['owner'], $owner)) throw new RuntimeException('Anchor mismatch or superseded runtime.');
        }
        return ['head' => $core['head'], 'state' => $this->unpack($core), 'owner' => $owner];
    }

    public function change(array $expectedHead, string $operationId, string $requestDigest, callable $mutate, array $audit = []): array
    {
        $prepared = $this->transaction(function () use ($expectedHead, $operationId, $requestDigest, $mutate, $audit): array {
            $owner = $this->ownerCheck(); $active = $this->current();
            if ($this->meta('pending') !== '' || !SecretsBackendCodec::same($active['head'], $expectedHead)) throw new RuntimeException('Revision conflict; reload before saving.');
            $state = $this->unpack($active);
            if (isset($state['operations']['outcomes'][$operationId])) {
                if ($state['operations']['outcomes'][$operationId]['requestDigest'] !== $requestDigest) throw new RuntimeException('Operation ID reused with different data.');
                throw new RuntimeException('Operation already committed; use a status query.');
            }
            $beforeRevision = $state['vault']['revision'];
            $state = $mutate($state);
            $commitId = SecretsBackendCodec::uuid();
            $state['operations']['outcomes'][$operationId] = ['requestDigest' => $requestDigest, 'index' => SecretsBackendCodec::increment($expectedHead['index']), 'result' => 'committed'];
            $state['operations']['audit'][] = $this->auditEvent($audit, $operationId, 'committed', $expectedHead, $state['vault']['revision'])
                + ['anchorOperationId' => $commitId, 'beforeRevision' => $beforeRevision, 'afterRevision' => $state['vault']['revision'], 'afterIndex' => SecretsBackendCodec::increment($expectedHead['index'])];
            $core = self::pack($state, $this->key, $this->identity, $expectedHead, $commitId);
            if (strlen($core['payloads']) > 32 * 1024 * 1024) throw new RuntimeException('Vault size limit exceeded.');
            $body = ['operationId' => $core['head']['commitId'], 'expectedHead' => $expectedHead, 'expectedOwner' => $owner, 'target' => $core['head']];
            $this->db->prepare('INSERT INTO cores VALUES (?, ?, ?, ?)')->execute([$core['head']['commitId'], SecretsBackendCodec::json($core['head']), $core['manifest'], $core['payloads']]);
            $this->set('pending', $core['head']['commitId']); $this->set('advance', SecretsBackendCodec::json($body));
            return ['body' => $body, 'core' => $core];
        });
        $this->trip('after_prepare');
        $reply = $this->transition(LOCK_SH, function () use ($expectedHead, $prepared): array {
            // Preparation is not irrevocable authorization. Invalidation may have
            // won since SQLite prepared the successor. Claim the exact pending
            // operation again while excluding reload/disable through advance.
            $this->transaction(function () use ($expectedHead, $prepared): void {
                $owner = $this->ownerCheck();
                if (!SecretsBackendCodec::same($owner, $prepared['body']['expectedOwner'])
                    || !SecretsBackendCodec::same($this->current()['head'], $expectedHead)
                    || $this->meta('pending') !== $prepared['core']['head']['commitId']
                    || $this->meta('advance') !== SecretsBackendCodec::json($prepared['body'])) {
                    throw new RuntimeException('Prepared ownership claim changed; recovery is required.');
                }
            });
            $this->trip('before_advance');
            // HTTPS transport is bounded. An uncertain result keeps the exact
            // pending identity for recovery; no cancellation is invented.
            return $this->anchor->call('advance', $prepared['body']);
        });
        if (($reply['result']['status'] ?? '') !== 'APPLIED' || !SecretsBackendCodec::same($reply['result']['head'], $prepared['core']['head'])) throw new RuntimeException('Commit was not authorized; recovery is required.');
        $this->trip('after_anchor');
        $this->transaction(function () use ($expectedHead, $prepared): void {
            $owner = $this->ownerCheck();
            if (!SecretsBackendCodec::same($owner, $prepared['body']['expectedOwner']) || !SecretsBackendCodec::same($this->current()['head'], $expectedHead) || $this->meta('pending') !== $prepared['core']['head']['commitId']) throw new RuntimeException('Old runtime cannot publish this commit.');
            $this->set('active', $prepared['core']['head']['commitId']); $this->set('pending', '');
        });
        return $prepared['core']['head'];
    }

    /** Never substitute a newer head for the snapshot whose permissions the caller checked. */
    public function authorize(string $kind, string $actionDigest, array $validated, callable $validate, array $audit = []): array
    {
        return $this->transition(LOCK_SH, function () use ($kind, $actionDigest, $validated, $validate, $audit): array {
            $body = $this->transaction(function () use ($kind, $actionDigest, $validated, $validate, $audit): array {
                $owner = $this->ownerCheck(); $core = $this->current();
                if ($this->meta('pending') !== '' || !SecretsBackendCodec::same($core['head'], $validated['head'])
                    || !SecretsBackendCodec::same($owner, $validated['owner'])) throw new RuntimeException('Authorization state changed; repeat complete validation.');
                $current = ['head' => $core['head'], 'owner' => $owner, 'state' => $this->unpack($core)];
                $validate($current); // Revalidate session, credential and policy in the claim transaction.
                $body = ['operationId' => SecretsBackendCodec::uuid(), 'expectedHead' => $current['head'], 'expectedOwner' => $owner,
                    'kind' => $kind, 'actionDigest' => $actionDigest, 'audience' => null];
                $event = $this->auditEvent($audit + ['action' => $kind], $body['operationId'], 'claimed', $current['head'], $current['state']['vault']['revision']);
                $body['actionDigest'] = hash('sha256', SecretsBackendCodec::json(['operationDigest' => $actionDigest, 'audit' => $event]));
                $this->insertEphemeral($body['operationId'], 'authorization', $body, time() + 3600, $owner);
                $this->appendAudit($event + ['actionDigest' => $body['actionDigest'], 'operationDigest' => $actionDigest, 'requestBody' => $body,
                    'anchorOperationDigest' => SecretsBackendAnchorClient::operationDigest($this->identity['deploymentId'], $this->identity['clientId'], 'authorize', $body)], 'grant');
                return $body;
            });
            $reply = $this->anchor->call('authorize', $body);
            $evidence = $this->anchor->evidence();
            $this->transaction(function () use ($body, $reply, $audit, $evidence): void {
                $this->appendAudit($this->auditEvent($audit + ['action' => $body['kind']], $body['operationId'],
                    $reply['result']['status'] === 'AUTHORIZED' ? 'authorized' : 'rejected', $body['expectedHead'], null)
                    + ['actionDigest' => $body['actionDigest'], 'anchorDecision' => $reply['result'], 'signedReceipt' => $evidence], 'grant');
            });
            if (($reply['result']['status'] ?? '') !== 'AUTHORIZED') throw new RuntimeException('Action authorization was rejected.');
            return $reply; // Only the exact validated snapshot may supply the response bytes.
        });
    }
    private function insertEphemeral(string $id, string $kind, array $body, int $expires, array $owner): void
    {
        $sealed = SecretsBackendCodec::seal(SecretsBackendCodec::json($body), $this->key, $kind . ':' . $id . ':' . $owner['bootId']);
        $this->db->prepare('INSERT INTO ephemeral VALUES (?, ?, ?, ?, ?)')->execute([$id, $kind, $owner['bootId'], $expires, $sealed]);
    }
    public function opaque(string $value): string { return hash_hmac('sha256', $value, $this->key); }
    private function auditEvent(array $context, string $operationId, string $result, array $head, ?string $revision): array
    {
        $allowed = ['system', 'enroll-recovery', 'login', 'metadata', 'reveal', 'save', 'delete', 'revoke', 'policy', 'configuration', 'provisioning', 'request'];
        $action = $context['action'] ?? 'system';
        if (!in_array($action, $allowed, true)) throw new InvalidArgumentException('Invalid audit action.');
        return ['operationId' => $operationId, 'at' => gmdate('c'), 'deployment' => $this->identity['deploymentId'],
            'backend' => (string)($context['backend'] ?? '0'), 'frontend' => (string)($context['frontend'] ?? '0'),
            'actor' => $this->opaque((string)($context['actor'] ?? 'system')), 'action' => $action,
            'target' => $this->opaque((string)($context['target'] ?? 'none')), 'beforeIndex' => $head['index'],
            'revision' => $revision, 'result' => $result];
    }
    private function appendAudit(array $event, string $bucket): void
    {
        $this->db->prepare('INSERT INTO audit_events(bucket,sealed) VALUES (?,?)')->execute([$bucket,
            SecretsBackendCodec::seal(SecretsBackendCodec::json($event), $this->key, 'audit:' . $this->identity['deploymentId'])]);
    }
    /** Bounded rejected-request telemetry; no request body, code, secret, signature or error text. */
    public function auditRejected(array $context = []): void
    {
        $this->transaction(function () use ($context): void {
            $bucket = 'rejected:' . intdiv(time(), 60);
            $s = $this->db->prepare('SELECT COUNT(*) FROM audit_events WHERE bucket=?'); $s->execute([$bucket]);
            if ((int)$s->fetchColumn() >= 20) return;
            $this->db->exec("DELETE FROM audit_events WHERE bucket LIKE 'rejected:%' AND id NOT IN (SELECT id FROM audit_events WHERE bucket LIKE 'rejected:%' ORDER BY id DESC LIMIT 999)");
            $this->appendAudit($this->auditEvent($context + ['action' => 'request', 'actor' => 'unverified-request', 'target' => 'undetermined'], SecretsBackendCodec::uuid(), 'rejected', $this->head(), null), $bucket);
        });
    }

    public function put(string $id, string $kind, array $body, int $expires, ?array $audit = null): void
    {
        $this->transaction(function () use ($id, $kind, $body, $expires, $audit): void {
            $owner = $this->ownerCheck();
            $this->insertEphemeral($id, $kind, $body, $expires, $owner);
            if ($audit !== null) {
                $core = $this->current(); $state = $this->unpack($core);
                $this->appendAudit($this->auditEvent($audit, SecretsBackendCodec::uuid(), 'issued', $core['head'], $state['vault']['revision']), 'console');
            }
        });
    }
    public function get(string $id, string $kind, bool $consume = false): array
    {
        return $this->transaction(function () use ($id, $kind, $consume): array {
            $owner = $this->ownerCheck(); $statement = $this->db->prepare('SELECT * FROM ephemeral WHERE id=? AND kind=?'); $statement->execute([$id, $kind]); $row = $statement->fetch();
            if (!is_array($row) || $row['boot'] !== $owner['bootId'] || $row['expires'] < time()) throw new RuntimeException('Session or approval expired.');
            if ($consume) $this->db->prepare('DELETE FROM ephemeral WHERE id=?')->execute([$id]);
            return json_decode(SecretsBackendCodec::open($row['payload'], $this->key, $kind . ':' . $id . ':' . $owner['bootId']), true, 64, JSON_THROW_ON_ERROR);
        });
    }
    public function delete(string $id): void { $this->transaction(function () use ($id): void { $this->ownerCheck(); $this->db->prepare('DELETE FROM ephemeral WHERE id=?')->execute([$id]); }); }
    public function replace(string $id, string $kind, array $body, int $expires): void
    {
        $this->transaction(function () use ($id, $kind, $body, $expires): void {
            $owner = $this->ownerCheck(); $sealed = SecretsBackendCodec::seal(SecretsBackendCodec::json($body), $this->key, $kind . ':' . $id . ':' . $owner['bootId']);
            $this->db->prepare('UPDATE ephemeral SET payload=?,expires=? WHERE id=? AND kind=? AND boot=?')->execute([$sealed, $expires, $id, $kind, $owner['bootId']]);
        });
    }
    public function rate(string $key, int $limit): void
    {
        $this->transaction(function () use ($key, $limit): void {
            $owner = $this->ownerCheck(); $id = hash('sha256', 'rate:' . $key . ':' . intdiv(time(), 60));
            $s = $this->db->prepare('SELECT payload FROM ephemeral WHERE id=?'); $s->execute([$id]); $row = $s->fetchColumn();
            $count = is_string($row) ? (int)SecretsBackendCodec::open($row, $this->key, 'rate:' . $id . ':' . $owner['bootId']) : 0;
            if ($count >= $limit) throw new RuntimeException('Request limit reached.');
            $sealed = SecretsBackendCodec::seal((string)($count + 1), $this->key, 'rate:' . $id . ':' . $owner['bootId']);
            $this->db->prepare('INSERT INTO ephemeral VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload')->execute([$id, 'rate', $owner['bootId'], time() + 120, $sealed]);
            $this->db->prepare('DELETE FROM ephemeral WHERE expires<?')->execute([time()]);
        });
    }
    public function head(): array { return $this->current()['head']; }
}
