<?php
declare(strict_types=1);
require_once __DIR__ . '/BackendStorage.php';
require_once __DIR__ . '/NativePlatform.php';
require_once __DIR__ . '/Codec.php';
require_once __DIR__ . '/BootstrapVerifier.php';
require_once __DIR__ . '/NativeRelocation.php';
require_once __DIR__ . '/SharedGlobal.php';

/** One encrypted complete-state journal, implemented solely with supplied PHP. */
final class SecretsBackendNativeStore implements SecretsBackendStorage
{
    private string $key;
    private array $identity;
    private ?array $frame = null;
    private bool $dirty = false;
    private int $depth = 0;
    private $currentRuntime;
    private $fault;
    private string $markerDigest = '';
    private int $effectiveLimit;
    private bool $ordinaryChange = false;
    public function __construct(private string $directory, private string $keyDirectory, private string $runtime, ?callable $currentRuntime = null, ?callable $fault = null)
    {
        $this->directory = SecretsBackendNativePlatform::directory($directory);
        $this->keyDirectory = SecretsBackendNativePlatform::directory($keyDirectory);
        $this->currentRuntime = $currentRuntime; $this->fault = $fault;
        $this->key = SecretsBackendNativePlatform::readPrivate($this->keyDirectory . '/master.key', 32);
        if (strlen($this->key) !== 32) throw new RuntimeException('The native master key is missing or invalid; it is never replaced automatically.');
        $id = json_decode(SecretsBackendNativePlatform::readPrivate($this->directory . '/native.json', 8192), true, 16, JSON_THROW_ON_ERROR);
        $mac = $id['mac'] ?? ''; unset($id['mac']);
        if (!is_string($mac) || !hash_equals($this->mac('identity', $id), $mac) || ($id['format'] ?? '') !== 'SECB.Native.1'
            || !preg_match('/^[a-f0-9-]{36}$/D', $id['deploymentId'] ?? '') || !is_int($id['maxPlainBytes'] ?? null)
            || $id['maxPlainBytes'] < 65536 || $id['maxPlainBytes'] > 4 * 1024 * 1024) throw new RuntimeException('Native identity authentication failed.');
        $this->effectiveLimit = min($id['maxPlainBytes'], SecretsBackendNativePlatform::budget());
        $this->identity = $id;
    }
    public static function canonical($value): string
    {
        $sort = static function ($x) use (&$sort) { if (!is_array($x)) return $x; if (!array_is_list($x)) ksort($x, SORT_STRING); return array_map($sort, $x); };
        return SecretsBackendCodec::json($sort($value));
    }
    private function mac(string $kind, array $value): string { return hash_hmac('sha256', 'SECB.NATIVE.' . $kind . "\0" . self::canonical($value), $this->key); }
    public function identity(): array { return $this->identity; }
    public function sign(string $bytes): string
    {
        $key = SecretsBackendNativePlatform::readPrivate($this->keyDirectory . '/sign.key', SODIUM_CRYPTO_SIGN_SECRETKEYBYTES);
        if (SecretsBackendCodec::b64(sodium_crypto_sign_publickey_from_secretkey($key)) !== $this->identity['signPublicKey']) throw new RuntimeException('Native signing key does not match its pinned identity.');
        return SecretsBackendCodec::b64(sodium_crypto_sign_detached($bytes, $key));
    }
    public function openPeer(string $sealed): string
    {
        $key = SecretsBackendNativePlatform::readPrivate($this->keyDirectory . '/box.key', SODIUM_CRYPTO_BOX_KEYPAIRBYTES);
        if (SecretsBackendCodec::b64(sodium_crypto_box_publickey($key)) !== $this->identity['boxPublicKey']) throw new RuntimeException('Native wrapping key does not match its identity.');
        $plain = sodium_crypto_box_seal_open(SecretsBackendCodec::unb64($sealed), $key);
        if (!is_string($plain)) throw new RuntimeException('Peer payload authentication failed.'); return $plain;
    }
    public static function initialize(string $directory, string $keys, array $binding, array $profile, string $initializationId, array $admission, bool $resume = false, ?callable $publicationGuard = null): array
    {
        $first = SecretsBootstrapVerifier::genesis($admission, $binding, $initializationId);
        $genesisDigest = SecretsBootstrapVerifier::digest($admission);
        $cap = SecretsBackendNativePlatform::capabilities();
        if ($cap['missing']) throw new RuntimeException('The supplied Symcon PHP lacks: ' . implode(', ', $cap['missing']));
        if (PHP_OS_FAMILY === 'Windows' && ($binding['privateACLConfirmed'] ?? false) !== true) throw new RuntimeException('Confirm private Windows folder ACLs in the wizard before initialization.');
        if (!preg_match('/^[a-f0-9-]{36}$/D', $initializationId)) throw new RuntimeException('Invalid native initialization identity.');
        if (is_dir($directory) && !$resume && count(scandir($directory) ?: []) !== 2) throw new RuntimeException('Native initialization never adopts existing data.');
        if (is_dir($keys) && !$resume && count(scandir($keys) ?: []) !== 2) throw new RuntimeException('Native initialization never adopts existing keys.');
        SecretsBackendNativePlatform::makePrivate($directory); SecretsBackendNativePlatform::makePrivate($keys);
        $frames = glob($directory . '/frame-*.sealed') ?: [];
        $create = static function (string $path, callable $generator) use ($frames): string {
            if (is_file($path)) return SecretsBackendNativePlatform::readPrivate($path, 4096);
            if ($frames) throw new RuntimeException('A key is missing for existing ciphertext; recovery is required.');
            $value = $generator(); self::publishFile($path, $value); return $value;
        };
        // Probe the real target filesystem before making any identity/key material.
        $probe = $directory . '/probe-' . SecretsBackendCodec::uuid();
        try { SecretsBackendNativePlatform::writeNew($probe, 'native-storage-probe'); SecretsBackendNativePlatform::syncDirectory($directory); }
        finally { if (is_file($probe) && !is_link($probe)) { unlink($probe); SecretsBackendNativePlatform::syncDirectory($directory); } }
        $master = $create($keys . '/master.key', static fn() => random_bytes(32));
        $sign = $create($keys . '/sign.key', static fn() => sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair()));
        $box = $create($keys . '/box.key', static fn() => sodium_crypto_box_keypair());
        if (strlen($master) !== 32 || strlen($sign) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES || strlen($box) !== SODIUM_CRYPTO_BOX_KEYPAIRBYTES) throw new RuntimeException('Incomplete native key material requires explicit recovery.');
        if (!is_file($directory . '/native.json')) {
            if ($frames) throw new RuntimeException('Missing native identity for existing encrypted state.');
            $id = ['format' => 'SECB.Native.1', 'deploymentId' => $initializationId, 'clientId' => $initializationId,
                'generation' => SecretsBackendCodec::b64(random_bytes(32)), 'keyId' => SecretsBackendCodec::uuid(), 'globalTreeId' => SecretsBackendCodec::uuid(), 'maxPlainBytes' => $cap['maxPlainBytes'],
                'signPublicKey' => SecretsBackendCodec::b64(sodium_crypto_sign_publickey_from_secretkey($sign)),
                'boxPublicKey' => SecretsBackendCodec::b64(sodium_crypto_box_publickey($box)),
                'binding' => $binding, 'directorySync' => PHP_OS_FAMILY !== 'Windows'];
            $create($keys . '/data-' . $id['keyId'] . '.key', static fn() => random_bytes(32));
            $id['mac'] = hash_hmac('sha256', "SECB.NATIVE.identity\0" . self::canonical($id), $master);
            self::publishFile($directory . '/native.json', SecretsBackendCodec::json($id));
        }
        if (!is_file($directory . '/native.lock')) self::publishFile($directory . '/native.lock', '');
        $store = new self($directory, $keys, '', null, $publicationGuard);
        $create($keys . '/data-' . $store->identity['keyId'] . '.key', static fn() => random_bytes(32));
        if ($store->identity['deploymentId'] !== $initializationId || self::canonical($store->identity['binding']) !== self::canonical($binding)) throw new RuntimeException('Native initialization binding changed.');
        $store->locked(function () use ($store, $profile, $binding, $first, $admission, $genesisDigest): void {
            if ($store->frame !== null) { if (($store->frame['state']['native']['genesisDigest'] ?? '') !== $genesisDigest || !isset($store->frame['state']['identity']['credentials'][$first['id']])) throw new RuntimeException('A different or legacy genesis requires recovery.'); return; } // Exact interrupted initialization only.
            $empty = ['type' => 'object', 'entries' => []];
            $state = ['vault' => ['global' => $empty, 'local' => $empty, 'revision' => '0'],
                'identity' => ['credentials' => [$first['id'] => $first], 'revocation' => '0', 'ownerId' => $first['administrator']],
                'policy' => ['origin' => $binding['origin'], 'frontend' => (string)$binding['frontend'], 'version' => '1', 'management' => $profile,
                    'hardware' => ['write' => false, 'identity' => false, 'export' => false, 'reveal' => false]],
                'pairing' => ['peers' => []], 'stream' => ['globalRevision' => '0', 'next' => [], 'received' => []],
                'operations' => ['outcomes' => [], 'audit' => []], 'outbox' => ['jobs' => []],
                'native' => ['genesisFormat' => 'SECF.Genesis.1', 'genesisDigest' => $genesisDigest, 'initializationOperation' => $admission['operation'], 'candidateDigest' => $admission['candidateDigest'], 'planDigest' => $admission['planDigest'], 'genesisAdmission' => $admission, 'activeDataKeyId' => $store->identity['keyId'], 'vaultId' => $store->identity['deploymentId'], 'globalTreeId' => $store->identity['globalTreeId'], 'ownershipEpoch' => '1', 'globalWritable' => true,
                    'trees' => [], 'received' => [], 'machines' => [], 'providers' => [], 'effects' => [], 'externalPredecessors' => [], 'transfers' => [], 'invites' => [], 'deliveryReceipts' => []]];
            $state['operations']['audit'][] = ['operationId'=>$admission['operation'],'at'=>gmdate('c'),'deployment'=>$store->identity['deploymentId'],'backend'=>(string)$binding['backend'],'frontend'=>(string)$binding['frontend'],
                'actor'=>$store->opaque($first['id']),'action'=>'bootstrap-genesis','target'=>$store->opaque($admission['candidateDigest']),'beforeIndex'=>'0','afterIndex'=>'0','revision'=>'0','afterRevision'=>'0','result'=>'committed'];
            $state['operations']['outcomes'][$admission['operation']] = ['requestDigest'=>$genesisDigest,'index'=>'0','result'=>'committed'];
            $head=$store->newHead($state,'0');
            $store->frame = ['sequence' => '0', 'previous' => str_repeat('0', 64), 'head' => $head,
                'state' => $state, 'runtime' => '', 'active' => false, 'ephemeral' => [], 'telemetry' => [], 'outcomeHeads' => [$admission['operation']=>$head]];
            $store->dirty = true;
        }, true);
        return $store->identity;
    }
    private static function publishFile(string $path, string $bytes): void
    {
        if (file_exists($path) || is_link($path)) throw new RuntimeException('Security file already exists.');
        $temp = dirname($path) . '/tmp-' . SecretsBackendCodec::uuid();
        SecretsBackendNativePlatform::writeNew($temp, $bytes);
        if (file_exists($path) || !rename($temp, $path)) throw new RuntimeException('Cannot publish the new security file.');
        SecretsBackendNativePlatform::syncDirectory(dirname($path));
    }
    private function trip(string $point): void { if ($this->fault !== null) ($this->fault)($point); }
    private function load(bool $allowEmpty): void
    {
        $markers = glob($this->directory . '/commit-*.json') ?: [];
        if (count($markers) > 64) throw new RuntimeException('Native journal requires bounded recovery cleanup.');
        sort($markers, SORT_STRING);
        if (!$markers) { if ($allowEmpty) { $this->frame = null; return; } throw new RuntimeException('No committed native snapshot; incomplete initialization requires the wizard.'); }
        $last = end($markers);
        if (!preg_match('/^commit-([0-9]{20})\.json$/D', basename($last), $matches)) throw new RuntimeException('Invalid native commit marker.');
        $marker = json_decode(SecretsBackendNativePlatform::readPrivate($last, 4096), true, 8, JSON_THROW_ON_ERROR);
        if (count($markers) > 1 && !hash_equals((string)($marker['previous'] ?? ''), hash('sha256', SecretsBackendNativePlatform::readPrivate($markers[count($markers) - 2], 4096)))) throw new RuntimeException('Native predecessor marker is missing or inconsistent.');
        $mac = $marker['mac'] ?? ''; unset($marker['mac']);
        if (!is_string($mac) || !hash_equals($this->mac('commit', $marker), $mac) || ($marker['vault'] ?? '') !== $this->identity['deploymentId']
            || str_pad($marker['sequence'] ?? '', 20, '0', STR_PAD_LEFT) !== $matches[1]
            || !preg_match('/^frame-[0-9]{20}-[a-f0-9]{64}\.sealed$/D', $marker['frame'] ?? '')
            || !is_int($marker['length'] ?? null) || $marker['length'] > $this->effectiveLimit * 2 + 8192) throw new RuntimeException('Highest native commit marker is corrupt; older permissions are not substituted.');
        $sealed = SecretsBackendNativePlatform::readPrivate($this->directory . '/' . $marker['frame'], $this->effectiveLimit * 2 + 8192);
        if (strlen($sealed) !== $marker['length'] || !hash_equals($marker['digest'], hash('sha256', $sealed))) throw new RuntimeException('The highest committed native snapshot is missing or damaged.');
        $body = json_decode($sealed, true, 8, JSON_THROW_ON_ERROR);
        if (array_keys($body) !== ['iv','tag','data']) throw new RuntimeException('Invalid native ciphertext envelope.');
        $iv = SecretsBackendCodec::unb64($body['iv'], 12); $tag = SecretsBackendCodec::unb64($body['tag'], 16);
        $cipher = SecretsBackendCodec::unb64($body['data']);
        $keyId = $marker['keyId'] ?? ''; if (!preg_match('/^[a-f0-9-]{36}$/D', $keyId)) throw new RuntimeException('Invalid native encryption-key reference.');
        $dataKey = SecretsBackendNativePlatform::readPrivate($this->keyDirectory . '/data-' . $keyId . '.key', 32);
        if (strlen($dataKey) !== 32) throw new RuntimeException('Missing native data encryption key; recovery is required.');
        $context = 'SECB.Native.1:' . $this->identity['deploymentId'] . ':' . $marker['sequence'] . ':' . $marker['previous'] . ':' . $keyId;
        $plain = openssl_decrypt($cipher, 'aes-256-gcm', $dataKey, OPENSSL_RAW_DATA, $iv, $tag, $context);
        if (!is_string($plain) || strlen($plain) > $this->effectiveLimit) throw new RuntimeException('Native snapshot authentication failed.');
        $frame = json_decode($plain, true, 96, JSON_THROW_ON_ERROR);
        if (($frame['state']['native']['activeDataKeyId'] ?? '') !== $keyId || ($frame['sequence'] ?? '') !== $marker['sequence'] || ($frame['previous'] ?? '') !== $marker['previous']
            || !hash_equals($frame['head']['digest'] ?? '', self::stateDigest($frame['state']))) throw new RuntimeException('Native state/commit binding failed.');
        $genesis=$frame['state']['native']??[];
        if(($genesis['genesisFormat']??'')!=='SECF.Genesis.1'||!is_array($genesis['genesisAdmission']??null)||!hash_equals($genesis['genesisDigest']??'',SecretsBootstrapVerifier::digest($genesis['genesisAdmission']))
            ||($genesis['genesisAdmission']['vault']??'')!==$this->identity['deploymentId']||($genesis['genesisAdmission']['operation']??'')!==($genesis['initializationOperation']??'')||!$frame['state']['identity']['credentials'])throw new RuntimeException('Legacy or incomplete native genesis is locked for explicit recovery.');
        $this->frame = $frame; $this->markerDigest = hash('sha256', SecretsBackendCodec::json($marker + ['mac' => $mac]));
    }
    private function save(): void
    {
        $this->assertRuntimeSource();
        $this->frame['sequence'] = SecretsBackendCodec::increment($this->frame['sequence']);
        $this->frame['previous'] = $this->markerDigest !== '' ? $this->markerDigest : str_repeat('0', 64);
        $plain = SecretsBackendCodec::json($this->frame);
        if ($this->ordinaryChange && strlen($plain) > (int)($this->effectiveLimit * 0.75)) throw new RuntimeException('Native capacity reserve is kept for backup, revocation and recovery. Verify a backup and compact retention before adding more data.');
        if (strlen($plain) > $this->effectiveLimit) throw new RuntimeException('Native vault capacity reached. Export a backup and review retention; no partial change was saved.');
        $sequence = $this->frame['sequence']; $iv = random_bytes(12); $tag = '';
        $keyId = $this->frame['state']['native']['activeDataKeyId'];
        $dataKey = SecretsBackendNativePlatform::readPrivate($this->keyDirectory . '/data-' . $keyId . '.key', 32);
        if (strlen($dataKey) !== 32) throw new RuntimeException('Missing native data encryption key.');
        $context = 'SECB.Native.1:' . $this->identity['deploymentId'] . ':' . $sequence . ':' . $this->frame['previous'] . ':' . $keyId;
        $cipher = openssl_encrypt($plain, 'aes-256-gcm', $dataKey, OPENSSL_RAW_DATA, $iv, $tag, $context, 16);
        if (!is_string($cipher) || strlen($tag) !== 16) throw new RuntimeException('Native snapshot encryption failed.');
        $sealed = SecretsBackendCodec::json(['iv' => SecretsBackendCodec::b64($iv), 'tag' => SecretsBackendCodec::b64($tag), 'data' => SecretsBackendCodec::b64($cipher)]);
        $digest = hash('sha256', $sealed); $padded = str_pad($sequence, 20, '0', STR_PAD_LEFT);
        $file = 'frame-' . $padded . '-' . $digest . '.sealed';
        self::publishFile($this->directory . '/' . $file, $sealed); $this->trip('after_frame');
        $marker = ['vault' => $this->identity['deploymentId'], 'keyId' => $keyId, 'sequence' => $sequence, 'previous' => $this->frame['previous'], 'frame' => $file, 'length' => strlen($sealed), 'digest' => $digest];
        $marker['mac'] = $this->mac('commit', $marker); $bytes = SecretsBackendCodec::json($marker);
        $temp = $this->directory . '/tmp-' . SecretsBackendCodec::uuid();
        SecretsBackendNativePlatform::writeNew($temp, $bytes); $this->trip('before_marker'); $this->assertRuntimeSource();
        $target = $this->directory . '/commit-' . $padded . '.json';
        if (file_exists($target) || !rename($temp, $target)) throw new RuntimeException('Native commit publication failed; query the operation outcome before retrying.');
        $this->trip('after_marker');
        SecretsBackendNativePlatform::syncDirectory($this->directory); $this->trip('after_directory_sync');
        $this->markerDigest = hash('sha256', $bytes); $this->dirty = false;
        // Committed marker is the publication point. Keep its predecessor for recovery.
        // Cleanup failure never turns an already committed operation into a rejection.
        try { $this->cleanup(); } catch (Throwable $ignored) { }
    }
    private function cleanup(): void
    {
        $markers = glob($this->directory . '/commit-*.json') ?: []; sort($markers, SORT_STRING); $keep = array_slice($markers, -2); $frames = [];
        foreach ($keep as $path) { $m = json_decode(SecretsBackendNativePlatform::readPrivate($path, 4096), true); $frames[] = $m['frame']; }
        foreach (array_diff($markers, $keep) as $path) if (!is_link($path)) unlink($path);
        foreach (glob($this->directory . '/frame-*.sealed') ?: [] as $path) if (!in_array(basename($path), $frames, true) && !is_link($path)) unlink($path);
        foreach (glob($this->directory . '/tmp-*') ?: [] as $path) if (preg_match('/^tmp-[a-f0-9-]{36}$/D', basename($path)) && is_file($path) && !is_link($path)) unlink($path);
        foreach(glob($this->directory.'/completion-*.json')?:[]as$path){
            if(preg_match('/^completion-([a-f0-9]{64})\.json$/D',basename($path),$m)){
                $effect=$this->frame['state']['native']['effects'][$m[1]]??null;
                if(($effect===null||in_array($effect['state'],['COMPLETE','ERROR'],true))&&!is_link($path))unlink($path);
            }
        }
        foreach(glob($this->directory.'/uploads/up-*')?:[]as$path){
            if(preg_match('/^up-([a-f0-9-]{36})-(?:[0-9]+|final)$/D',basename($path),$m)){
                $entry=$this->frame['ephemeral']['upload:'.$m[1]]??null;
                if(($entry===null||$entry['expires']<time())&&is_file($path)&&!is_link($path))unlink($path);
            }
        }
        SecretsBackendNativePlatform::syncDirectory($this->directory);
    }
    private function locked(callable $callback, bool $allowEmpty = false)
    {
        if ($this->depth > 0) return $callback();
        $locks=[];
        $route=function()use(&$locks,$allowEmpty):void{
            for($hop=0;$hop<16;$hop++){
                if(!isset($locks[$this->directory])){
                    $path=$this->directory.'/native.lock';SecretsBackendNativePlatform::readPrivate($path,0);
                    $h=fopen($path,'r+b');if($h===false||!flock($h,LOCK_EX))throw new RuntimeException('Native storage is busy.');$locks[$this->directory]=$h;
                }
                $paths=$this->physicalPaths();$sign=fn(string $bytes):string=>$this->opaque($bytes);
                $redirect=SecretsBackendNativeRelocation::read($paths,$this->identity['deploymentId'],$sign);
                if($redirect===null){
                    $this->load($allowEmpty);$move=$this->frame['state']['native']['storageMove']??null;
                    if(is_array($move)&&$move['from']===$paths&&$move['to']!==$paths){
                        $this->assertRuntimeSource();$redirect=SecretsBackendNativeRelocation::prepare($move,$this->identity['deploymentId'],$sign);$this->trip('relocation_after_intent');
                    }else return;
                }
                $target=SecretsBackendNativeRelocation::resume($redirect,$sign,fn(string $point)=>$this->trip($point));
                $key=SecretsBackendNativePlatform::readPrivate($target['keyDirectory'].'/master.key',32);
                if(!hash_equals($this->key,$key))throw new RuntimeException('Relocated master key differs from the vault identity.');
                $this->directory=$target['vaultDirectory'];$this->keyDirectory=$target['keyDirectory'];
            }
            throw new RuntimeException('Storage handoff chain exceeds its bound.');
        };
        try {
            $this->depth=1;$this->dirty=false;$this->ordinaryChange=false;$route();
            $result=$callback();if($this->dirty)$this->save();$route();return $result;
        } finally { $this->depth=0;$this->frame=null;$this->dirty=false;foreach(array_reverse($locks)as$h){flock($h,LOCK_UN);fclose($h);} }
    }
    private function physicalPaths(): array { return ['vaultDirectory'=>$this->directory,'keyDirectory'=>$this->keyDirectory]; }
    public function storageHandoff(): array { return $this->locked(fn():array=>['paths'=>$this->physicalPaths(),'move'=>$this->frame['state']['native']['storageMove']??null,'profile'=>$this->frame['state']['policy']['management']]); }
    public function storagePaths(): array { return $this->locked(fn():array=>$this->physicalPaths()); }
    public function reviewStorageMove(array $target,string $kernel,string|array|null $legacyParent=null): array
    {
        return $this->locked(function()use($target,$kernel,$legacyParent):array{
            $this->active();$from=$this->physicalPaths();$to=SecretsBackendNativeRelocation::validate($from,$target,$kernel,true,$legacyParent);
            if($from!==$to){
                foreach($from as $kind=>$root)if($root!==$to[$kind])SecretsBackendNativeRelocation::inventory($root);
                foreach($this->frame['ephemeral'] as $entry)if($entry['kind']==='upload'&&$entry['expires']>=time())throw new RuntimeException('Finish or expire the active backup upload before moving storage.');
                foreach($this->frame['state']['native']['effects'] as $effect)if(!in_array($effect['state'],['COMPLETE','ERROR','ABANDONED'],true))throw new RuntimeException('Resolve pending OAuth refresh results before moving storage.');
            }
            return ['from'=>$from,'to'=>$to];
        });
    }

    private function assertRuntimeSource(): void
    {
        if ($this->currentRuntime !== null && !hash_equals((string)($this->currentRuntime)(), $this->runtime)) throw new RuntimeException('This native worker was superseded by a settings change or restart.');
    }
    private function active(): void
    {
        $this->assertRuntimeSource();
        if ($this->runtime === '' || !$this->frame['active'] || !hash_equals($this->frame['runtime'], hash('sha256', $this->runtime))) throw new RuntimeException('Native runtime is fenced or recovery is pending.');
    }
    private function owner(): array { return ['bootId' => $this->frame['runtime'], 'runtime' => $this->frame['runtime'], 'vault' => $this->identity['deploymentId']]; }
    private function current(): array { return ['head' => $this->frame['head'], 'state' => $this->frame['state'], 'owner' => $this->owner()]; }
    public static function stateDigest(array $state): string
    {
        // Transport bookkeeping never changes the facts a person reviewed. The
        // entire frame, including these fields, remains AEAD-authenticated.
        unset($state['operations'], $state['outbox']);
        unset($state['native']['deliveryReceipts'], $state['stream']['next'], $state['stream']['queuedDigest']);
        foreach ($state['pairing']['peers'] as &$peer) unset($peer['lastSync'],$peer['routeReceipt']);
        unset($peer);
        return hash('sha256', 'SECB.Native.State:' . self::canonical($state));
    }
    private function newHead(array $state, string $index): array { return ['generation' => $this->identity['generation'], 'index' => $index, 'digest' => self::stateDigest($state), 'commitId' => SecretsBackendCodec::uuid()]; }
    public function invalidate(): void
    {
        $this->locked(function (): void { $this->assertRuntimeSource(); $this->frame['active'] = false; $this->frame['runtime'] = ''; $this->frame['ephemeral'] = []; $this->dirty = true; });
    }
    public function recover(?callable $validate = null): array
    {
        return $this->locked(function () use ($validate): array {
            $this->assertRuntimeSource(); if ($this->runtime === '') throw new RuntimeException('Native recovery needs a fresh runtime nonce.');
            if($validate!==null)$validate($this->frame['state']);
            $hash = hash('sha256', $this->runtime);
            if (!$this->frame['active'] || $this->frame['runtime'] !== $hash) { $this->frame['runtime'] = $hash; $this->frame['active'] = true; $this->frame['ephemeral'] = []; $this->dirty = true; }
            return $this->frame['head'];
        });
    }
    public function recoveryRequired(): bool { try { $this->read(); return false; } catch (Throwable $e) { return true; } }
    public function read(bool $fresh = true): array { return $this->locked(function (): array { $this->active(); return $this->current(); }); }
    /** One local operation, with fresh state and nested authorization under the same lock.
     * Never retain this snapshot between calls or perform network I/O in the callback.
     */
    public function withActiveSnapshot(callable $operation)
    {
        return $this->locked(function () use ($operation) { $this->active(); return $operation($this->current()); });
    }
    public function head(): array { return $this->read()['head']; }
    private function event(array $context, string $id, string $result): array
    {
        return ['operationId' => $id, 'at' => gmdate('c'), 'deployment' => $this->identity['deploymentId'], 'backend' => (string)($context['backend'] ?? '0'),
            'frontend' => (string)($context['frontend'] ?? '0'), 'actor' => $this->opaque((string)($context['actor'] ?? 'system')),
            'action' => substr((string)($context['action'] ?? 'system'), 0, 40), 'target' => $this->opaque((string)($context['target'] ?? 'none')),
            'beforeIndex' => $this->frame['head']['index'], 'revision' => $this->frame['state']['vault']['revision'], 'result' => $result];
    }
    public function change(array $expectedHead, string $operationId, string $requestDigest, callable $mutate, array $audit = []): array
    {
        return $this->locked(function () use ($expectedHead, $operationId, $requestDigest, $mutate, $audit): array {
            $this->active(); if (!preg_match('/^[a-f0-9-]{36}$/D', $operationId) || !preg_match('/^[a-f0-9]{64}$/D', $requestDigest)) throw new RuntimeException('Invalid mutation identity.');
            $old = $this->frame['state']['operations']['outcomes'][$operationId] ?? null;
            if ($old !== null) { if ($old['requestDigest'] !== $requestDigest) throw new RuntimeException('Operation ID reused with different data.'); return $this->frame['outcomeHeads'][$operationId]; }
            if (!SecretsBackendCodec::same($this->frame['head'], $expectedHead)) throw new RuntimeException('Revision conflict; reload and approve the current change.');
            $maintenance = in_array($audit['action'] ?? '', ['nativeConnectRevoke','login','reveal','nativeReveal','nativeBackup','nativeCompact','revoke','nativeMachineRevoke','nativeRevokePeer','nativeRotateKey','enroll-recovery','policy'], true);
            if (count($this->frame['state']['operations']['outcomes']) >= ($maintenance ? 4112 : 3500)) throw new RuntimeException('Operation retention is full; create and verify a backup, then compact explicitly.');
            $state = $mutate($this->frame['state']);
            if(isset($state['native']['sharedGlobal'])&&self::canonical($state['native']['sharedGlobal'])===self::canonical($this->frame['state']['native']['sharedGlobal']??null)&&self::canonical($state['vault']['global'])!==self::canonical($this->frame['state']['vault']['global'])){
                $state=SecretsBackendSharedGlobal::capture($state);
                if(class_exists(SecretsBackendNativePeer::class))$state=SecretsBackendNativePeer::queueGlobal($state);
            }
            $changed = self::stateDigest($state) !== $expectedHead['digest']; $index = $changed ? SecretsBackendCodec::increment($expectedHead['index']) : $expectedHead['index'];
            $event = $this->event($audit, $operationId, 'committed');
            $state['operations']['audit'][] = $event + ['afterIndex' => $index, 'afterRevision' => $state['vault']['revision']];
            // Outcome omits its own digest to avoid a circular state hash.
            $state['operations']['outcomes'][$operationId] = ['requestDigest' => $requestDigest, 'index' => $index, 'result' => 'committed'];
            $head = $changed ? $this->newHead($state, $index) : $expectedHead;
            $this->frame['outcomeHeads'][$operationId] = $head;
            $this->frame['state'] = $state; $this->frame['head'] = $head; $this->ordinaryChange = $changed && !$maintenance; $this->dirty = true; return $head;
        });
    }
    /** Trusted local application read: fresh authorization without persistent read telemetry.
     * Mutations, browser reveals and administrative approvals retain authorize()/change().
     */
    public function authorizeApplicationRead(array $validated, callable $validate): array
    {
        return $this->locked(function () use ($validated, $validate): array {
            $this->active(); $current = $this->current();
            if (!SecretsBackendCodec::same($current['head'], $validated['head']) || !SecretsBackendCodec::same($current['owner'], $validated['owner'])) throw new RuntimeException('Authorization state changed; repeat full verification.');
            $validate($current); $this->trip('before_authorize'); $this->active();
            return ['result' => ['status' => 'AUTHORIZED', 'head' => $current['head']], 'head' => $current['head'], 'owner' => $current['owner']];
        });
    }
    public function authorize(string $kind, string $actionDigest, array $validated, callable $validate, array $audit = []): array
    {
        return $this->locked(function () use ($kind, $actionDigest, $validated, $validate, $audit): array {
            $this->active(); $current = $this->current();
            if (!SecretsBackendCodec::same($current['head'], $validated['head']) || !SecretsBackendCodec::same($current['owner'], $validated['owner'])) throw new RuntimeException('Authorization state changed; repeat full verification.');
            $validate($current); $this->trip('before_authorize'); $this->active();
            $id = SecretsBackendCodec::uuid(); $this->frame['telemetry'][] = $this->event($audit + ['action' => $kind], $id, 'authorized');
            $this->frame['telemetry'] = array_slice($this->frame['telemetry'], -128); $this->dirty = true;
            return ['result' => ['status' => 'AUTHORIZED', 'head' => $current['head']], 'head' => $current['head'], 'owner' => $current['owner']];
        });
    }
    public function opaque(string $value): string { return hash_hmac('sha256', $value, $this->key); }
    private function expire(): void { foreach ($this->frame['ephemeral'] as $id => $entry) if ($entry['expires'] < time()) { unset($this->frame['ephemeral'][$id]); $this->dirty = true; } }
    public function put(string $id, string $kind, array $body, int $expires, ?array $audit = null): void
    {
        $this->locked(function () use ($id, $kind, $body, $expires, $audit): void {
            $this->active(); $this->expire();
            if($kind==='upload'&&count(array_filter($this->frame['ephemeral'],static fn($e)=>$e['kind']==='upload'))>=4)throw new RuntimeException('Finish or expire an existing backup upload before starting another.');
            if (isset($this->frame['ephemeral'][$id]) || count($this->frame['ephemeral']) >= 512 || $expires > time() + 86400) throw new RuntimeException('Transient state capacity or identity conflict.');
            $this->frame['ephemeral'][$id] = ['kind' => $kind, 'expires' => $expires, 'body' => $body]; $this->dirty = true;
            if ($audit !== null) { $this->frame['telemetry'][] = $this->event($audit, SecretsBackendCodec::uuid(), 'issued'); $this->frame['telemetry'] = array_slice($this->frame['telemetry'], -128); }
        });
    }
    public function get(string $id, string $kind, bool $consume = false): array
    {
        return $this->locked(function () use ($id, $kind, $consume): array {
            $this->active(); $entry = $this->frame['ephemeral'][$id] ?? null;
            if (!is_array($entry) || $entry['kind'] !== $kind || $entry['expires'] < time()) throw new RuntimeException('Session or one-use authorization expired.');
            if ($consume) { unset($this->frame['ephemeral'][$id]); $this->dirty = true; } return $entry['body'];
        });
    }
    public function delete(string $id): void { $this->locked(function () use ($id): void { $this->active(); unset($this->frame['ephemeral'][$id]); $this->dirty = true; }); }
    public function replace(string $id, string $kind, array $body, int $expires): void
    {
        $this->locked(function () use ($id, $kind, $body, $expires): void { $this->get($id, $kind); $this->frame['ephemeral'][$id] = ['kind' => $kind, 'expires' => $expires, 'body' => $body]; $this->dirty = true; });
    }
    /** Preserve concurrent timeout changes and never revive a logged-out or expired session. */
    public function refreshAdministratorSession(string $id, ?int $idleLimit = null): array
    {
        return $this->locked(function () use ($id, $idleLimit): array {
            $session = $this->get($id, 'session'); $now = time();
            $limit = min(900, max(60, (int)($session['idleLimit'] ?? 900)));
            if ($session['created'] + 3600 < $now || $session['last'] + $limit < $now) throw new RuntimeException('Administrator session expired.');
            if ($idleLimit !== null) {
                if (!in_array($idleLimit, [60, 300, 900], true)) throw new InvalidArgumentException('Invalid session timeout.');
                $session['idleLimit'] = $idleLimit;
            }
            $session['last'] = $now;
            $this->frame['ephemeral'][$id] = ['kind' => 'session', 'expires' => $session['created'] + 3600, 'body' => $session]; $this->dirty = true;
            return $session;
        });
    }
    public function rate(string $key, int $limit): void
    {
        $this->locked(function () use ($key, $limit): void {
            $this->active(); $this->expire(); $id = 'rate:' . hash('sha256', $key . ':' . intdiv(time(), 60));
            $count = $this->frame['ephemeral'][$id]['body']['count'] ?? 0;
            if ($count >= $limit || count($this->frame['ephemeral']) >= 512) throw new RuntimeException('Request limit reached.');
            $this->frame['ephemeral'][$id] = ['kind' => 'rate', 'expires' => time() + 120, 'body' => ['count' => $count + 1]]; $this->dirty = true;
        });
    }
    public function auditRejected(array $context = []): void
    {
        $this->locked(function () use ($context): void { $this->active(); $this->frame['telemetry'][] = $this->event($context, SecretsBackendCodec::uuid(), 'rejected'); $this->frame['telemetry'] = array_slice($this->frame['telemetry'], -128); $this->dirty = true; });
    }
    public function metadata(): array
    {
        return $this->locked(function (): array { $this->active(); return ['vaultId' => $this->identity['deploymentId'], 'head' => $this->frame['head'],
            'usedBytes' => strlen(SecretsBackendCodec::json($this->frame)), 'capacityBytes' => $this->effectiveLimit,
            'directorySync' => $this->identity['directorySync'], 'independentRollbackDetection' => false,
            'outcomes' => count($this->frame['state']['operations']['outcomes'])]; });
    }
    public function operationStatus(string $id): array { return $this->locked(function()use($id):array{$this->active();$o=$this->frame['state']['operations']['outcomes'][$id]??null;return $o===null?['operationId'=>$id,'result'=>'UNKNOWN']:['operationId'=>$id,'result'=>'COMMITTED','head'=>$this->frame['outcomeHeads'][$id]];}); }
    public function captureEffect(string $id,string $requestDigest,array $result): void
    {
        $this->locked(function()use($id,$requestDigest,$result):void{
        if(!preg_match('/^[a-f0-9]{64}$/D',$id)||!preg_match('/^[a-f0-9]{64}$/D',$requestDigest))throw new RuntimeException('Invalid effect capture identity.');
        $plain=SecretsBackendCodec::json($result);if(strlen($plain)>131072)throw new RuntimeException('Effect response exceeds capture bound.');
        $path=$this->directory.'/completion-'.$id.'.json';if(is_file($path)){if(self::canonical($this->readCapturedEffect($id,$requestDigest))!==self::canonical($result))throw new RuntimeException('Conflicting captured provider response.');return;}
        $iv=random_bytes(12);$tag='';$context='SECB.Native.Effect:'.$this->identity['deploymentId'].':'.$id.':'.$requestDigest;
        $cipher=openssl_encrypt($plain,'aes-256-gcm',$this->key,OPENSSL_RAW_DATA,$iv,$tag,$context,16);if(!is_string($cipher))throw new RuntimeException('Provider response capture encryption failed.');
        self::publishFile($path,SecretsBackendCodec::json(['requestDigest'=>$requestDigest,'iv'=>SecretsBackendCodec::b64($iv),'tag'=>SecretsBackendCodec::b64($tag),'data'=>SecretsBackendCodec::b64($cipher)]));
        });
    }
    public function readCapturedEffect(string $id,string $requestDigest): ?array
    {
        return $this->locked(function()use($id,$requestDigest): ?array{
        if(!preg_match('/^[a-f0-9]{64}$/D',$id)||!preg_match('/^[a-f0-9]{64}$/D',$requestDigest))throw new RuntimeException('Invalid effect capture reference.');$path=$this->directory.'/completion-'.$id.'.json';if(!is_file($path))return null;
        $b=json_decode(SecretsBackendNativePlatform::readPrivate($path,196608),true,8,JSON_THROW_ON_ERROR);if(($b['requestDigest']??'')!==$requestDigest)throw new RuntimeException('Captured provider predecessor changed.');
        $plain=openssl_decrypt(SecretsBackendCodec::unb64($b['data']),'aes-256-gcm',$this->key,OPENSSL_RAW_DATA,SecretsBackendCodec::unb64($b['iv'],12),SecretsBackendCodec::unb64($b['tag'],16),'SECB.Native.Effect:'.$this->identity['deploymentId'].':'.$id.':'.$requestDigest);
        if(!is_string($plain))throw new RuntimeException('Captured provider response authentication failed.');return json_decode($plain,true,32,JSON_THROW_ON_ERROR);
        });
    }
    public function prepareDataKey(string $id): void
    {
        $this->locked(function()use($id):void{
        if(!preg_match('/^[a-f0-9-]{36}$/D',$id))throw new RuntimeException('Invalid encryption key generation.');
        if(count(glob($this->keyDirectory.'/data-*.key')?:[])>=32)throw new RuntimeException('Verify a complete backup and compact retired encryption keys before rotating again.');
        $path=$this->keyDirectory.'/data-'.$id.'.key';if(is_file($path))throw new RuntimeException('Encryption key generation already exists.');self::publishFile($path,random_bytes(32));
        });
    }
    public function compactKeys(): void
    {
        $this->locked(function():void{$this->active();$keep=[];foreach(glob($this->directory.'/commit-*.json')?:[]as$file){$m=json_decode(SecretsBackendNativePlatform::readPrivate($file,4096),true);$keep[$m['keyId']]=true;}
            foreach(glob($this->keyDirectory.'/data-*.key')?:[]as$file){$name=basename($file);if(preg_match('/^data-([a-f0-9-]{36})\.key$/D',$name,$m)&&!isset($keep[$m[1]])&&!is_link($file))unlink($file);}SecretsBackendNativePlatform::syncDirectory($this->keyDirectory);});
    }
    public function installHardwareRoots(string $version,array $roots): string
    {
        return $this->locked(function()use($version,$roots): string{
        if(!preg_match('/^hw-[a-f0-9-]{36}$/D',$version))throw new RuntimeException('Invalid native hardware generation.');
        $path=$this->keyDirectory.'/'.$version;SecretsBackendNativePlatform::makePrivate($path);
        foreach($roots as$name=>$pem){if(!preg_match('/^root-[0-9]{1,2}\.pem$/D',$name))throw new RuntimeException('Invalid hardware certificate name.');$file=$path.'/'.$name;
            if(is_file($file)){if(!hash_equals(hash('sha256',SecretsBackendNativePlatform::readPrivate($file,65536)),hash('sha256',$pem)))throw new RuntimeException('Existing hardware root generation changed.');}else self::publishFile($file,$pem);}
        return $path;
        });
    }
    public function verifyOwnBackup(array $material,array $current): void
    {
        if(($material['identity']['deploymentId']??'')!==$this->identity['deploymentId']||!isset($material['keys']['master.key'])||!hash_equals($this->key,SecretsBackendCodec::unb64($material['keys']['master.key'],32)))throw new RuntimeException('Verify a backup of this exact native vault before compaction.');
        $before=$material['state'];$after=$current;foreach($before['identity']['credentials']as&$c)unset($c['counter'],$c['tested']);unset($c);foreach($after['identity']['credentials']as&$c)unset($c['counter'],$c['tested']);unset($c);
        if(self::stateDigest($before)!==self::stateDigest($after))throw new RuntimeException('The backup predates current secrets or permissions. Create and verify a current backup first.');
    }
    public function stagingDirectory(): string { return $this->locked(function():string{$path=$this->directory.'/uploads';SecretsBackendNativePlatform::makePrivate($path);return $path;}); }
    /** Called only after an administrator's exact export approval. Never used in settings exports. */
    public function backupMaterial(?array $validated = null): array
    {
        return $this->locked(function()use($validated):array{$this->active();if($validated!==null&&(!SecretsBackendCodec::same($this->frame['head'],$validated['head'])||!SecretsBackendCodec::same($this->owner(),$validated['owner'])))throw new RuntimeException('Export snapshot changed after approval.');$keys=[];$names=['master.key','sign.key','box.key'];foreach(glob($this->keyDirectory.'/data-*.key')?:[]as$file)$names[]=basename($file);foreach($names as$name)$keys[$name]=SecretsBackendCodec::b64(SecretsBackendNativePlatform::readPrivate($this->keyDirectory.'/'.$name,4096));
            $captures=[];$roots=[];$extra=0;$extraLimit=intdiv($this->effectiveLimit,2);
            $profile=$this->frame['state']['policy']['management'];
            foreach($profile['files']['HardwareRoots']??[]as$name=>$hash){
                $path=$profile['settings']['HardwareRootsDirectory'].'/'.$name;
                if(is_link($path)||!is_file($path)||filesize($path)>131072||$extra+filesize($path)>$extraLimit)throw new RuntimeException('Hardware backup material exceeds its private bounded capacity.');
                $pem=file_get_contents($path);if(!is_string($pem)||!hash_equals($hash,hash('sha256',$pem)))throw new RuntimeException('Reviewed hardware trust changed before backup.');$roots[$name]=$pem;$extra+=strlen($pem);
            }
            foreach($this->frame['state']['native']['effects']as$id=>$effect){
                if(in_array($effect['state'],['COMPLETE','ERROR'],true))continue;
                $path=$this->directory.'/completion-'.$id.'.json';
                if(is_file($path)){if($extra+filesize($path)>$extraLimit)throw new RuntimeException('Resolve captured uncertain effects before exporting a bounded complete backup.');$captures[$id]=SecretsBackendNativePlatform::readPrivate($path,196608);$extra+=strlen($captures[$id]);}
            }
            return ['identity'=>$this->identity,'state'=>$this->frame['state'],'head'=>$this->frame['head'],'keys'=>$keys,'hardwareRoots'=>$roots,'completions'=>$captures,'at'=>gmdate('c')];});
    }
    public function compactOutcomes(int $keep=512): void
    {
        // Explicit maintenance only. Pending effects/cursors/outbox are never pruned.
        $this->locked(function()use($keep):void{$this->active();$all=$this->frame['state']['operations']['outcomes'];$retained=array_slice($all,-$keep,null,true);
            $this->frame['state']['operations']['outcomes']=$retained;$this->frame['outcomeHeads']=array_intersect_key($this->frame['outcomeHeads'],$retained);
            $this->frame['state']['operations']['audit']=array_slice($this->frame['state']['operations']['audit'],-$keep);$this->dirty=true;});
    }
}
