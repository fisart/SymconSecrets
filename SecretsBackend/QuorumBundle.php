<?php
declare(strict_types=1);
require_once __DIR__ . '/QuorumProtocol.php';

/** V2 framing and key envelopes. Callers must first authenticate the current
 * quorum-approved descriptor/context. A matching digest is not authorization.
 * No browser route, trust issuance or V1 storage adoption is provided here. */
final class SecretsBackendQuorumBundle
{
    public const MAX_BYTES = 67108864;
    private const MAGIC = "SYMCB2\0\0";
    private const TEST = "SymconSecrets/DC01/ScopeKeyTest/v1";
    private SecretsBackendQuorumProtocol $codec;
    public function __construct() { $this->codec = new SecretsBackendQuorumProtocol(); }
    private static function fields(array $record, array $fields): void
    {
        if (array_diff(array_keys($record), $fields) || array_diff($fields, array_keys($record))) throw new InvalidArgumentException('Unexpected V2 record fields.');
    }
    /** Stable key context: object revisions are deliberately not key generations. */
    public function context(array $context): void
    {
        self::fields($context, ['version','clusterId','realmId','incarnation','scopeId','scopeKind','ownerNodeId','generation','keyId','algorithm']);
        if ($context['version'] !== '1' || $context['algorithm'] !== 'AES-128-GCM' || !in_array($context['scopeKind'], ['GLOBAL','LOCAL'], true)) throw new InvalidArgumentException('Unsupported V2 key context.');
        foreach (['clusterId','realmId','scopeId'] as $field) $this->codec->validate($context[$field], 'UUID');
        foreach (['incarnation','keyId'] as $field) $this->codec->validate($context[$field], 'B64_32');
        $this->codec->validate($context['generation'], 'Q_POS');
        if ($context['scopeKind'] === 'GLOBAL') { if ($context['ownerNodeId'] !== null) throw new InvalidArgumentException('Global key cannot have a local owner.'); }
        else $this->codec->validate($context['ownerNodeId'], 'UUID');
    }
    private function recipient(array $recipient, array $context): void
    {
        self::fields($recipient, ['id','kind','publicKey']);
        $this->codec->validate($recipient['id'], 'UUID');
        $this->codec->validate($recipient['publicKey'], 'B64_32');
        if (!in_array($recipient['kind'], ['PEER','RECOVERY'], true) || ($context['scopeKind'] === 'LOCAL' && $recipient['kind'] === 'PEER' && $recipient['id'] !== $context['ownerNodeId'])) throw new InvalidArgumentException('Recipient has no local-scope key access.');
    }
    private static function key(string $key): void { if (strlen($key) !== 16) throw new InvalidArgumentException('Expected a 128-bit data key.'); }
    private static function aad(string $kind, array $context): string { return "SymconSecrets/DC01/" . $kind . "/v1\0" . SecretsBackendCodec::canonical($context); }
    public function keyTest(array $context, string $key): string
    {
        $this->context($context); self::key($key);
        return SecretsBackendCodec::seal(self::TEST, $key, self::aad('ScopeKeyTest', $context));
    }
    public function verifyKey(array $context, string $key, string $test): void
    {
        $this->context($context); self::key($key);
        if (strlen($test) > 2048 || SecretsBackendCodec::open($test, $key, self::aad('ScopeKeyTest', $context)) !== self::TEST) throw new RuntimeException('Scope key test failed.');
    }
    /** Recipient list must come from approved policy, never an untrusted request.
     * The ciphertext is placed in the bundle. Only its descriptor enters the
     * authenticated manifest; neither the descriptor nor archive contains a key. */
    public function wrapKey(array $context, string $key, string $test, array $recipient): array
    {
        $this->verifyKey($context, $key, $test); $this->recipient($recipient, $context);
        $record = ['version'=>'1','context'=>$context,'recipient'=>$recipient,'keyTestDigest'=>hash('sha256',$test),'key'=>SecretsBackendCodec::b64($key)];
        $plain = SecretsBackendCodec::canonical($record);
        try { $bytes = sodium_crypto_box_seal($plain, SecretsBackendCodec::unb64($recipient['publicKey'],32)); }
        finally { sodium_memzero($plain); sodium_memzero($record['key']); }
        return ['descriptor'=>['version'=>'1','context'=>$context,'recipient'=>$recipient,'keyTestDigest'=>hash('sha256',$test),'digest'=>hash('sha256',$bytes),'length'=>(string)strlen($bytes)],'bytes'=>$bytes];
    }
    public function unwrapKey(array $expectedContext, array $approvedDescriptor, string $bytes, string $recipientKeypair, string $approvedTest): string
    {
        $this->context($expectedContext);
        self::fields($approvedDescriptor, ['version','context','recipient','keyTestDigest','digest','length']);
        if ($approvedDescriptor['version'] !== '1' || !is_array($approvedDescriptor['context']) || !SecretsBackendCodec::same($approvedDescriptor['context'],$expectedContext) || !is_array($approvedDescriptor['recipient'])) throw new RuntimeException('Envelope context mismatch.');
        $this->recipient($approvedDescriptor['recipient'],$expectedContext);
        $this->codec->validate($approvedDescriptor['keyTestDigest'],'DIGEST'); $this->codec->validate($approvedDescriptor['digest'],'DIGEST'); $this->codec->validate($approvedDescriptor['length'],'Q');
        if (strlen($bytes)>16384 || $approvedDescriptor['length'] !== (string)strlen($bytes) || !hash_equals($approvedDescriptor['digest'],hash('sha256',$bytes)) || !hash_equals($approvedDescriptor['keyTestDigest'],hash('sha256',$approvedTest)) || strlen($recipientKeypair)!==SODIUM_CRYPTO_BOX_KEYPAIRBYTES || !hash_equals($approvedDescriptor['recipient']['publicKey'],SecretsBackendCodec::b64(sodium_crypto_box_publickey($recipientKeypair)))) throw new RuntimeException('Envelope recipient/digest mismatch.');
        $plain = sodium_crypto_box_seal_open($bytes,$recipientKeypair);
        if ($plain === false) throw new RuntimeException('Key envelope authentication failed.');
        try {
            $record=$this->codec->decode($plain); self::fields($record,['version','context','recipient','keyTestDigest','key']);
            if ($record['version']!=='1' || !SecretsBackendCodec::same($record['context'],$expectedContext) || !SecretsBackendCodec::same($record['recipient'],$approvedDescriptor['recipient']) || $record['keyTestDigest']!==$approvedDescriptor['keyTestDigest'] || !is_string($record['key'])) throw new RuntimeException('Sealed key record mismatch.');
            $key=SecretsBackendCodec::unb64($record['key'],16);
            try { $this->verifyKey($expectedContext,$key,$approvedTest); } catch (Throwable $error) { sodium_memzero($key); throw $error; }
            return $key;
        } finally { sodium_memzero($plain); if (isset($record['key']) && is_string($record['key'])) sodium_memzero($record['key']); }
    }
    private function objectIdentity(array $identity, array $context): void
    {
        self::fields($identity,['id','kind','schema','keyId','scopeId']);
        $this->codec->validate($identity+['length'=>'0','digest'=>str_repeat('0',64)],'ObjectRef');
        if ($identity['keyId']!==$context['keyId'] || $identity['scopeId']!==$context['scopeId']) throw new InvalidArgumentException('Object scope/key mismatch.');
    }
    public function encryptObject(array $context, string $key, array $identity, string $plain): array
    {
        $this->context($context); self::key($key); $this->objectIdentity($identity,$context);
        if (strlen($plain)>1048576) throw new InvalidArgumentException('Object plaintext exceeds 1 MiB.');
        $bytes=SecretsBackendCodec::seal($plain,$key,self::aad('Object',['context'=>$context,'object'=>$identity]));
        return ['reference'=>$identity+['length'=>(string)strlen($bytes),'digest'=>hash('sha256',$bytes)],'bytes'=>$bytes];
    }
    public function decryptObject(array $context, string $key, array $approvedReference, string $bytes): string
    {
        $this->context($context); self::key($key); $this->codec->validate($approvedReference,'ObjectRef');
        $identity=array_diff_key($approvedReference,array_flip(['length','digest'])); $this->objectIdentity($identity,$context);
        if (strlen($bytes)>1500000 || $approvedReference['length']!==(string)strlen($bytes) || !hash_equals($approvedReference['digest'],hash('sha256',$bytes))) throw new RuntimeException('Object ciphertext mismatch.');
        $plain=SecretsBackendCodec::open($bytes,$key,self::aad('Object',['context'=>$context,'object'=>$identity]));
        if (strlen($plain)>1048576) { sodium_memzero($plain); throw new RuntimeException('Object plaintext exceeds 1 MiB.'); }
        return $plain;
    }
    /** Frame exactly the encrypted manifest/objects already reviewed by the
     * packer. This method neither authorizes a diff nor changes foreign scopes. */
    public function build(string $commitId, string $encryptedManifest, array $objects): array
    {
        $this->codec->validate($commitId,'UUID');
        if (!array_is_list($objects) || count($objects)>100 || $encryptedManifest==='' || strlen($encryptedManifest)>1048576) throw new InvalidArgumentException('Bundle manifest/object limits.');
        $refs=[]; $payload=''; $seen=[];
        foreach ($objects as $object) {
            if (!is_array($object)) throw new InvalidArgumentException('Expected a bundle object.');
            self::fields($object,['reference','bytes']);
            if (!is_array($object['reference']) || !is_string($object['bytes'])) throw new InvalidArgumentException('Invalid bundle object.');
            $ref=$object['reference']; $this->codec->validate($ref,'ObjectRef');
            if (isset($seen[$ref['id']]) || strlen($object['bytes'])>1500000 || $ref['length']!==(string)strlen($object['bytes']) || !hash_equals($ref['digest'],hash('sha256',$object['bytes']))) throw new InvalidArgumentException('Bundle object coverage mismatch.');
            $seen[$ref['id']]=true; $refs[]=$ref; $payload.=$object['bytes'];
            if (strlen($payload)>self::MAX_BYTES) throw new InvalidArgumentException('Bundle exceeds 64 MiB.');
        }
        $index=SecretsBackendCodec::canonical(['version'=>'2','manifestLength'=>(string)strlen($encryptedManifest),'manifestDigest'=>hash('sha256',$encryptedManifest),'objects'=>$refs]);
        if (strlen($index)>65536) throw new InvalidArgumentException('Bundle index exceeds 64 KiB.');
        $bytes=self::MAGIC.pack('N',strlen($index)).$index.$encryptedManifest.$payload;
        if (strlen($bytes)>self::MAX_BYTES) throw new InvalidArgumentException('Bundle exceeds 64 MiB.');
        $descriptor=['commitId'=>$commitId,'bundleDigest'=>hash('sha256',$bytes),'manifestDigest'=>hash('sha256',$encryptedManifest),'bundleLength'=>(string)strlen($bytes)];
        return ['bytes'=>$bytes,'bundle'=>['ref'=>['id'=>$commitId,'version'=>'1','digest'=>hash('sha256',SecretsBackendCodec::canonical($descriptor))],'descriptor'=>$descriptor,'indexDigest'=>hash('sha256',$index),'protected'=>false]];
    }
    public function read(string $bytes, array $approvedBundle): array
    {
        self::fields(array_diff_key($approvedBundle,['reservationId'=>true]),['ref','descriptor','indexDigest','protected']);
        if (!is_array($approvedBundle['descriptor']) || !is_array($approvedBundle['ref']) || !is_bool($approvedBundle['protected']) || !is_string($approvedBundle['reservationId'] ?? '')) throw new InvalidArgumentException('Invalid bundle record.');
        $d=$approvedBundle['descriptor']; $this->codec->validate($d,'BundleDescriptor'); $this->codec->validate($approvedBundle['ref'],'RecordRef'); $this->codec->validate($approvedBundle['indexDigest'],'DIGEST');
        if (($approvedBundle['reservationId'] ?? '')!=='') $this->codec->validate($approvedBundle['reservationId'],'UUID');
        if ($approvedBundle['ref']['id']!==$d['commitId'] || $approvedBundle['ref']['version']!=='1' || !hash_equals($approvedBundle['ref']['digest'],hash('sha256',SecretsBackendCodec::canonical($d))) || strlen($bytes)>self::MAX_BYTES || strlen($bytes)<12 || substr($bytes,0,8)!==self::MAGIC || $d['bundleLength']!==(string)strlen($bytes) || !hash_equals($d['bundleDigest'],hash('sha256',$bytes))) throw new RuntimeException('Bundle descriptor mismatch.');
        $n=unpack('Nlength',substr($bytes,8,4))['length'];
        if ($n<1 || $n>65536 || 12+$n>strlen($bytes)) throw new RuntimeException('Bundle index length.');
        $meta=substr($bytes,12,$n); $index=$this->codec->decode($meta); self::fields($index,['version','manifestLength','manifestDigest','objects']);
        if (!hash_equals($approvedBundle['indexDigest'],hash('sha256',$meta)) || $index['version']!=='2' || SecretsBackendCodec::canonical($index)!==$meta || !is_array($index['objects']) || !array_is_list($index['objects']) || count($index['objects'])>100) throw new RuntimeException('Bundle index mismatch.');
        $this->codec->validate($index['manifestLength'],'Q'); $this->codec->validate($index['manifestDigest'],'DIGEST');
        $offset=12+$n; $length=(int)$index['manifestLength'];
        if ($length<1 || $length>1048576 || $length>strlen($bytes)-$offset) throw new RuntimeException('Manifest length.');
        $manifest=substr($bytes,$offset,$length); $offset+=$length;
        if ($index['manifestDigest']!==$d['manifestDigest'] || !hash_equals($index['manifestDigest'],hash('sha256',$manifest))) throw new RuntimeException('Manifest digest.');
        $objects=[]; $seen=[];
        foreach ($index['objects'] as $ref) {
            $this->codec->validate($ref,'ObjectRef'); $length=(int)$ref['length'];
            if (isset($seen[$ref['id']]) || $length>1500000 || $length>strlen($bytes)-$offset) throw new RuntimeException('Object length/coverage.');
            $seen[$ref['id']]=true; $payload=substr($bytes,$offset,$length); $offset+=$length;
            if (!hash_equals($ref['digest'],hash('sha256',$payload))) throw new RuntimeException('Object digest.');
            $objects[]=['reference'=>$ref,'bytes'=>$payload];
        }
        if ($offset!==strlen($bytes)) throw new RuntimeException('Trailing bundle bytes.');
        return ['manifest'=>$manifest,'objects'=>$objects];
    }
}
