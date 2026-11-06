<?php
declare(strict_types=1);
require_once __DIR__ . '/Codec.php';
require_once __DIR__ . '/../SecretsFrontend/Configuration.php';
require_once __DIR__ . '/../SecretsManager/libs/PortalSecurity.php';
require_once __DIR__ . '/../SecretsManager/libs/WebAuthn/src/WebAuthn.php';

/** Shared verifier. Browser PoP is deliberately separate from WebAuthn wire signatures. */
final class SecretsBootstrapVerifier
{
    public const FIELDS = ['version','purpose','origin','path','frontend','intent','candidate','candidateDigest','keyDigest','epoch','request','nonce','operation','action','body','signature'];
    public static function exact(array $value, array $fields): void
    {
        if (array_diff(array_keys($value), $fields) || array_diff($fields, array_keys($value))) throw new InvalidArgumentException('Unexpected bootstrap fields.');
    }
    public static function digest(array $value): string
    {
        $sort = static function ($v) use (&$sort) { if (is_array($v)) { if (!array_is_list($v)) ksort($v, SORT_STRING); return array_map($sort, $v); } return $v; };
        return hash('sha256', SecretsBackendCodec::json($sort($value)));
    }
    public static function uuid(string $id): void
    {
        if (!preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/D', $id)) throw new InvalidArgumentException('Invalid bootstrap UUID.');
    }
    public static function counter(string $value): void
    {
        if (!preg_match('/^(0|[1-9][0-9]*)$/D', $value) || strlen($value) > 16 || (strlen($value) === 16 && strcmp($value, '9007199254740991') > 0)) throw new InvalidArgumentException('Invalid bootstrap counter.');
    }
    public static function publicKey(array $jwk): array
    {
        self::exact($jwk, ['kty','crv','x','y']);
        foreach ($jwk as $v) if (!is_string($v)) throw new InvalidArgumentException('Invalid browser key.');
        if ($jwk['kty'] !== 'EC' || $jwk['crv'] !== 'P-256') throw new InvalidArgumentException('Use a P-256 browser key.');
        $x = SecretsBackendCodec::unb64($jwk['x'], 32); $y = SecretsBackendCodec::unb64($jwk['y'], 32);
        $der = hex2bin('3059301306072a8648ce3d020106082a8648ce3d03010703420004') . $x . $y;
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
        $key = openssl_pkey_get_public($pem); $details = $key === false ? false : openssl_pkey_get_details($key);
        if (!is_array($details) || ($details['ec']['curve_name'] ?? '') !== 'prime256v1'
            || str_pad($details['ec']['x'],32,"\0",STR_PAD_LEFT) !== $x || str_pad($details['ec']['y'],32,"\0",STR_PAD_LEFT) !== $y) throw new InvalidArgumentException('Invalid P-256 point.');
        return ['pem' => $pem, 'digest' => hash('sha256', "SECF.BOOTSTRAP.KEY.1\0" . $x . $y)];
    }
    public static function rawSignature(string $raw): string
    {
        if (strlen($raw) !== 64) throw new InvalidArgumentException('Browser signatures must be 64 bytes.');
        $order = hex2bin('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'); $out = '';
        foreach ([substr($raw,0,32),substr($raw,32,32)] as $n) {
            if ($n === str_repeat("\0",32) || strcmp($n,$order) >= 0) throw new InvalidArgumentException('Invalid ECDSA scalar.');
            $n = ltrim($n,"\0"); if (ord($n[0]) & 128) $n = "\0" . $n;
            $out .= "\x02" . chr(strlen($n)) . $n;
        }
        return "\x30" . chr(strlen($out)) . $out;
    }
    public static function verifySignature(string $bytes, string $signature, array $jwk): void
    {
        if (openssl_verify($bytes, self::rawSignature(SecretsBackendCodec::unb64($signature,64)), self::publicKey($jwk)['pem'], OPENSSL_ALGO_SHA256) !== 1) throw new RuntimeException('Browser possession proof failed.');
    }
    public static function signingBytes(array $message, string $body): string
    {
        $parts = ['SECF.BOOTSTRAP.POP.1'];
        foreach (['purpose','origin','path','frontend','intent','candidate','candidateDigest','keyDigest','epoch','request','nonce','operation','action'] as $key) $parts[] = $message[$key];
        $parts[] = hash('sha256',$body); return implode("\n",$parts) . "\n";
    }
    public static function message(array $message, array $jwk): array
    {
        self::exact($message,self::FIELDS);
        if (strlen(SecretsBackendCodec::json($message)) > 65536) throw new InvalidArgumentException('Bootstrap request too large.');
        foreach ($message as $v) if (!is_string($v) || strlen($v)>61000 || preg_match('/[^\x20-\x7e]/',$v)) throw new InvalidArgumentException('Invalid bootstrap string.');
        if ($message['version'] !== 'SECF.Bootstrap.PoP.1') throw new InvalidArgumentException('Invalid bootstrap version.');
        self::uuid($message['frontend']); self::uuid($message['request']); self::counter($message['epoch']);
        if ($message['operation'] !== '-') self::uuid($message['operation']);
        foreach (['intent','candidate','nonce'] as $k) SecretsBackendCodec::unb64($message[$k],32);
        foreach (['candidateDigest','keyDigest'] as $k) if (!preg_match('/^[a-f0-9]{64}$/D',$message[$k])) throw new InvalidArgumentException('Invalid bootstrap digest.');
        $actions = ['candidateStatus','planPreview','applyOptions','applyVerify','operationStatus','cancel'];
        if (!(($message['purpose']==='request' && in_array($message['action'],$actions,true)) || ($message['purpose']==='resume' && $message['action']==='resumeVerify'))) throw new InvalidArgumentException('Invalid bootstrap purpose.');
        if (!hash_equals(self::publicKey($jwk)['digest'],$message['keyDigest'])) throw new RuntimeException('Browser key changed.');
        $body = SecretsBackendCodec::unb64($message['body']);
        $data = SecretsFrontendConfiguration::decodeBounded($body,45056,24);
        $bytes = self::signingBytes($message,$body); self::verifySignature($bytes,$message['signature'],$jwk);
        return ['body'=>$data,'digest'=>hash('sha256',$bytes)];
    }
    public static function webauthn(string $origin): \lbuchs\WebAuthn\WebAuthn
    {
        if ($origin === '' || SecretsFrontendConfiguration::origin($origin) !== $origin) throw new InvalidArgumentException('Invalid pinned origin.');
        return new \lbuchs\WebAuthn\WebAuthn('Secrets administration',(string)parse_url($origin,PHP_URL_HOST),['none','packed','fido-u2f','apple','tpm','android-key'],true);
    }
    private static function client(string $encoded,string $type,string $challenge,string $origin): string
    {
        $raw = SecretsBackendCodec::unb64($encoded); $data = SecretsFrontendConfiguration::decode($raw);
        if (($data['type']??'')!==$type || ($data['challenge']??'')!==$challenge || ($data['origin']??'')!==$origin || ($data['crossOrigin']??false)!==false || isset($data['topOrigin'])) throw new RuntimeException('WebAuthn context mismatch.');
        return $raw;
    }
    public static function registration(array $credential,array $context): array
    {
        self::exact($credential,['type','rawId','response']); self::exact($credential['response'],['clientDataJSON','attestationObject']);
        if ($credential['type']!=='public-key') throw new RuntimeException('Invalid registration type.');
        $client = self::client($credential['response']['clientDataJSON'],'webauthn.create',$context['challenge'],$context['origin']);
        $auth = self::webauthn($context['origin']);
        $c = $auth->processCreate($client,SecretsBackendCodec::unb64($credential['response']['attestationObject']),SecretsBackendCodec::unb64($context['challenge'],32),true,true,true);
        if (SecretsBackendCodec::b64($c->credentialId)!==$credential['rawId'] || !SecretsPortalSecurity::validateBackupFlags($c->isBackupEligible,$c->isBackedUp)) throw new RuntimeException('Invalid credential binding.');
        $entry=['id'=>$credential['rawId'],'publicKey'=>$c->credentialPublicKey,'label'=>'Administrator','active'=>true,'administrator'=>$context['owner'],
            'hardware'=>false,'aaguid'=>bin2hex($c->AAGUID),'attestationFormat'=>$c->attestationFormat,'attestationEvidence'=>$credential['response']['attestationObject'],
            'trustVersion'=>'none','tested'=>false,'counter'=>(int)($c->signatureCounter??0),'backupEligible'=>$c->isBackupEligible,'userHandle'=>$context['userHandle']];
        if(isset($context['reuseAssertion'],$context['reuseChallenge']))$entry['counter']=self::assertion($entry,$context['reuseAssertion'],$context['reuseChallenge'],$context['origin']);
        return $entry;
    }
    public static function assertion(array $entry,array $assertion,string $challenge,string $origin): int
    {
        self::exact($assertion,['type','rawId','response']); self::exact($assertion['response'],['clientDataJSON','authenticatorData','signature','userHandle']);
        if ($assertion['type']!=='public-key' || $assertion['rawId']!==$entry['id']) throw new RuntimeException('Wrong approved credential.');
        $r = $assertion['response']; $client = self::client($r['clientDataJSON'],'webauthn.get',$challenge,$origin);
        if ($r['userHandle']!==null && $r['userHandle']!==$entry['userHandle']) throw new RuntimeException('Wrong user handle.');
        $authData = SecretsBackendCodec::unb64($r['authenticatorData']); $auth = self::webauthn($origin);
        $auth->processGet($client,$authData,SecretsBackendCodec::unb64($r['signature']),$entry['publicKey'],SecretsBackendCodec::unb64($challenge,32),$entry['counter'],true,true);
        $flags = new \lbuchs\WebAuthn\Attestation\AuthenticatorData($authData);
        if (!SecretsPortalSecurity::validateBackupFlags($flags->getIsBackupEligible(),$flags->getIsBackup(),$entry['backupEligible'])) throw new RuntimeException('Credential backup flags changed.');
        return (int)($auth->getSignatureCounter()??0);
    }
    public static function genesis(array $admission,array $binding,string $vault): array
    {
        self::exact($admission,['format','operation','vault','candidateDigest','planDigest','binding','registration','registrationContext','assertion','challenge']);
        if ($admission['format']!=='SECF.Genesis.1' || $admission['vault']!==$vault || self::digest($admission['binding'])!==self::digest($binding)
            || $admission['registrationContext']['origin']!==$binding['origin']) throw new RuntimeException('Genesis admission binding failed.');
        self::uuid($vault); self::uuid($admission['operation']);
        foreach (['candidateDigest','planDigest'] as $k) if (!preg_match('/^[a-f0-9]{64}$/D',$admission[$k])) throw new RuntimeException('Invalid genesis digest.');
        $entry = self::registration($admission['registration'],$admission['registrationContext']);
        $entry['counter'] = self::assertion($entry,$admission['assertion'],$admission['challenge'],$binding['origin']); $entry['tested']=true;
        return $entry;
    }
}
