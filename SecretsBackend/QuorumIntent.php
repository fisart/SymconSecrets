<?php
declare(strict_types=1);
require_once __DIR__.'/QuorumBundle.php';

/** Internal PHP/Go CoreUserIntent/v1 contract, independent of the frozen wire
 * Request/Decision codec. This signature is not a WebAuthn approval. */
final class SecretsBackendQuorumIntent
{
    private SecretsBackendQuorumProtocol $codec;
    public function __construct() { $this->codec=new SecretsBackendQuorumProtocol(); }
    private static function fields(array $v,array $keys): void
    {
        if(array_diff(array_keys($v),$keys)||array_diff($keys,array_keys($v)))throw new InvalidArgumentException('Unexpected core intent fields.');
    }
    public function validate(array $intent): void
    {
        $fields=['newScopeDigest','version','userOperationId','expectedHead','owner','policyRef','membershipRef','permissionRef','sessionRef','credentialRef','scope','newRevision','changeClass','permittedDiffDigest','candidateHead','bundle','outbox'];
        self::fields($intent,$fields);
        if($intent['version']!=='1'||!in_array($intent['changeClass'],['GLOBAL_EDIT','LOCAL_EDIT'],true)||!is_array($intent['outbox'])||!array_is_list($intent['outbox'])||count($intent['outbox'])>4)throw new InvalidArgumentException('Unsupported core change class.');
        foreach(['userOperationId'=>'UUID','expectedHead'=>'Head','owner'=>'NodeBinding','scope'=>'ScopeBinding','newRevision'=>'Q_POS','permittedDiffDigest'=>'DIGEST','newScopeDigest'=>'DIGEST','candidateHead'=>'Head','policyRef'=>'RecordRef','membershipRef'=>'RecordRef','permissionRef'=>'RecordRef','sessionRef'=>'RecordRef','credentialRef'=>'RecordRef'] as $field=>$type)$this->codec->validate($intent[$field],$type);
        $b=$intent['bundle'];if(!is_array($b))throw new InvalidArgumentException('Expected a candidate bundle.');
        self::fields($b,['ref','descriptor','indexDigest','protected']);
        foreach(['ref'=>'RecordRef','descriptor'=>'BundleDescriptor','indexDigest'=>'DIGEST'] as $field=>$type)$this->codec->validate($b[$field],$type);
        if($b['protected']!==false)throw new InvalidArgumentException('Candidate cannot be a protected historical bundle.');
        $old=$intent['expectedHead'];$new=$intent['candidateHead'];
        foreach(['clusterId','realmId','incarnation','keyEpoch'] as $field)if($old[$field]!==$new[$field])throw new InvalidArgumentException('Human edit cannot change authority/key lineage.');
        if($new['index']!==SecretsBackendCodec::increment($old['index'])||$new['commitId']===$old['commitId']||$intent['newRevision']!==SecretsBackendCodec::increment($intent['scope']['revision'])||$b['ref']['id']!==$new['commitId']||$b['ref']['version']!=='1'||$b['ref']['digest']!==hash('sha256',SecretsBackendCodec::canonical($b['descriptor']))||$b['descriptor']['commitId']!==$new['commitId']||$b['descriptor']['manifestDigest']!==$new['manifestDigest'])throw new InvalidArgumentException('Candidate predecessor/descriptor mismatch.');
        if($intent['changeClass']==='LOCAL_EDIT'){
            if($intent['scope']['kind']!=='LOCAL'||$intent['scope']['ownerNodeId']!==$intent['owner']['nodeId'])throw new InvalidArgumentException('Local edit must belong to its initiating owner.');
        }elseif($intent['scope']['kind']!=='GLOBAL'||$intent['scope']['ownerNodeId']!==null)throw new InvalidArgumentException('Global edit scope mismatch.');
        $seen=[];
        foreach($intent['outbox'] as $delivery){
            if(!is_array($delivery))throw new InvalidArgumentException('Expected a delivery reference.');
            self::fields($delivery,['recipientId','pairingRef']);$this->codec->validate($delivery['recipientId'],'UUID');$this->codec->validate($delivery['pairingRef'],'RecordRef');
            if(isset($seen[$delivery['recipientId']]))throw new InvalidArgumentException('Duplicate delivery recipient.');$seen[$delivery['recipientId']]=true;
        }
        // Same strict parser/limits and object/array semantics as the Go core.
        $this->codec->decode(SecretsBackendCodec::canonical($intent));
    }
    public function digest(array $intent): string
    {
        $this->validate($intent);
        return hash('sha256',"SymconSecrets/DC01/CoreUserIntent/v1\0".SecretsBackendCodec::canonical($intent));
    }
    public function sign(array $intent,array $approvalRef,string $keyId,string $private): array
    {
        $this->validate($intent);$this->codec->validate($approvalRef,'RecordRef');$this->codec->validate($keyId,'B64_32');
        if(strlen($private)!==SODIUM_CRYPTO_SIGN_SECRETKEYBYTES)throw new InvalidArgumentException('Expected the enrolled owner signing key.');
        $approved=['intent'=>$intent,'approvalRef'=>$approvalRef,'keyId'=>$keyId,'signature'=>''];
        $approved['signature']=SecretsBackendCodec::b64(sodium_crypto_sign_detached("SymconSecrets/DC01/CoreUserSignature/v1\0".SecretsBackendCodec::canonical($approved),$private));
        $this->codec->decode(SecretsBackendCodec::canonical($approved));
        return $approved;
    }
    public function verify(string $raw,string $currentOwnerPublicKey,string $currentOwnerKeyId): array
    {
        $a=$this->codec->decode($raw);self::fields($a,['intent','approvalRef','keyId','signature']);
        if(!is_array($a['intent'])||!is_array($a['approvalRef'])||!is_string($a['keyId'])||!is_string($a['signature']))throw new InvalidArgumentException('Invalid approved intent.');
        $this->validate($a['intent']);$this->codec->validate($a['approvalRef'],'RecordRef');$this->codec->validate($a['keyId'],'B64_32');
        $sig=SecretsBackendCodec::unb64($a['signature'],64);$pub=SecretsBackendCodec::unb64($currentOwnerPublicKey,32);$unsigned=$a;$unsigned['signature']='';
        if($a['keyId']!==$currentOwnerKeyId||!sodium_crypto_sign_verify_detached($sig,"SymconSecrets/DC01/CoreUserSignature/v1\0".SecretsBackendCodec::canonical($unsigned),$pub))throw new RuntimeException('Core owner signature mismatch.');
        return $a;
    }
}
