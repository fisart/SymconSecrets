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
            'policy' => ['origin' => $origin, 'frontend' => (string)$frontend, 'version' => '1', 'hardware' => ['write' => false, 'identity' => false, 'export' => false, 'reveal' => false]],
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
        return $identity + ['head' => $core['head'], 'clientPublicKey' => SecretsBackendCodec::b64(sodium_crypto_sign_publickey($anchorKey)), 'syncPublicKey' => SecretsBackendCodec::b64(sodium_crypto_sign_publickey($syncKey))];
    }

    public function identity(): array { return $this->identity; }
    private function meta(string $name): string { $s = $this->db->prepare('SELECT value FROM metadata WHERE name=?'); $s->execute([$name]); $v = $s->fetchColumn(); if (!is_string($v)) throw new RuntimeException('Missing database metadata.'); return $v; }
    private function set(string $name, string $value): void { $this->db->prepare('INSERT INTO metadata(name,value) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value')->execute([$name, $value]); }
    private function transaction(callable $callback)
    {
        $this->db->exec('BEGIN IMMEDIATE');
        try { $result = $callback(); $this->db->exec('COMMIT'); return $result; }
        catch (Throwable $exception) { $this->db->exec('ROLLBACK'); throw $exception; }
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
    private static function pack(array $state, string $key, array $identity, ?array $parent): array
    {
        $index = $parent === null ? '0' : SecretsBackendCodec::increment($parent['index']); $id = SecretsBackendCodec::uuid(); $roots = []; $payloads = [];
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

    public function recover(): array
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
        if (($reply['result']['status'] ?? '') !== 'APPLIED' || !SecretsBackendCodec::same($reply['owner'], $reply['result']['owner'])) throw new RuntimeException('Runtime acquisition was rejected or superseded.');
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
        $owner = $this->ownerCheck(); $core = $this->current();
        if ($this->meta('pending') !== '') throw new RuntimeException('A commit outcome requires recovery.');
        if ($fresh) {
            $reply = $this->anchor->call('read', []);
            if (!SecretsBackendCodec::same($reply['head'], $core['head']) || !SecretsBackendCodec::same($reply['owner'], $owner)) throw new RuntimeException('Anchor mismatch or superseded runtime.');
        }
        return ['head' => $core['head'], 'state' => $this->unpack($core), 'owner' => $owner];
    }

    public function change(array $expectedHead, string $operationId, string $requestDigest, callable $mutate): array
    {
        $prepared = $this->transaction(function () use ($expectedHead, $operationId, $requestDigest, $mutate): array {
            $owner = $this->ownerCheck(); $active = $this->current();
            if ($this->meta('pending') !== '' || !SecretsBackendCodec::same($active['head'], $expectedHead)) throw new RuntimeException('Revision conflict; reload before saving.');
            $state = $this->unpack($active);
            if (isset($state['operations']['outcomes'][$operationId])) {
                if ($state['operations']['outcomes'][$operationId]['requestDigest'] !== $requestDigest) throw new RuntimeException('Operation ID reused with different data.');
                throw new RuntimeException('Operation already committed; use a status query.');
            }
            $state = $mutate($state);
            $state['operations']['outcomes'][$operationId] = ['requestDigest' => $requestDigest, 'index' => SecretsBackendCodec::increment($expectedHead['index']), 'result' => 'committed'];
            $state['operations']['audit'][] = ['operationId' => $operationId, 'index' => SecretsBackendCodec::increment($expectedHead['index']), 'at' => gmdate('c')];
            $core = self::pack($state, $this->key, $this->identity, $expectedHead);
            if (strlen($core['payloads']) > 32 * 1024 * 1024) throw new RuntimeException('Vault size limit exceeded.');
            $body = ['operationId' => $core['head']['commitId'], 'expectedHead' => $expectedHead, 'expectedOwner' => $owner, 'target' => $core['head']];
            $this->db->prepare('INSERT INTO cores VALUES (?, ?, ?, ?)')->execute([$core['head']['commitId'], SecretsBackendCodec::json($core['head']), $core['manifest'], $core['payloads']]);
            $this->set('pending', $core['head']['commitId']); $this->set('advance', SecretsBackendCodec::json($body));
            return ['body' => $body, 'core' => $core];
        });
        $this->trip('after_prepare');
        $reply = $this->anchor->call('advance', $prepared['body']);
        if (($reply['result']['status'] ?? '') !== 'APPLIED' || !SecretsBackendCodec::same($reply['result']['head'], $prepared['core']['head'])) throw new RuntimeException('Commit was not authorized; recovery is required.');
        $this->trip('after_anchor');
        $this->transaction(function () use ($expectedHead, $prepared): void {
            $owner = $this->ownerCheck();
            if (!SecretsBackendCodec::same($owner, $prepared['body']['expectedOwner']) || !SecretsBackendCodec::same($this->current()['head'], $expectedHead) || $this->meta('pending') !== $prepared['core']['head']['commitId']) throw new RuntimeException('Old runtime cannot publish this commit.');
            $this->set('active', $prepared['core']['head']['commitId']); $this->set('pending', '');
        });
        return $prepared['core']['head'];
    }

    public function authorize(string $kind, string $actionDigest): array
    {
        $current = $this->read();
        $body = ['operationId' => SecretsBackendCodec::uuid(), 'expectedHead' => $current['head'], 'expectedOwner' => $current['owner'], 'kind' => $kind, 'actionDigest' => $actionDigest, 'audience' => null];
        $id = $body['operationId']; $this->put($id, 'authorization', $body, time() + 3600);
        $reply = $this->anchor->call('authorize', $body);
        if (($reply['result']['status'] ?? '') !== 'AUTHORIZED') throw new RuntimeException('Action authorization was rejected.');
        return $reply;
    }

    public function put(string $id, string $kind, array $body, int $expires): void
    {
        $this->transaction(function () use ($id, $kind, $body, $expires): void {
            $owner = $this->ownerCheck();
            $sealed = SecretsBackendCodec::seal(SecretsBackendCodec::json($body), $this->key, $kind . ':' . $id . ':' . $owner['bootId']);
            $this->db->prepare('INSERT INTO ephemeral VALUES (?, ?, ?, ?, ?)')->execute([$id, $kind, $owner['bootId'], $expires, $sealed]);
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
