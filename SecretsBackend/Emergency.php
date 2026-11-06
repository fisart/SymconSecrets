<?php
declare(strict_types=1);
require_once __DIR__.'/NativePeer.php';
require_once __DIR__.'/LegacyAPI.php';
require_once __DIR__.'/EmergencyCapsule.php';

final class SecretsBackendEmergencyRefused extends RuntimeException {
    public function __construct(public readonly string $reason) { parent::__construct('Emergency Global read refused: '.$reason); }
}
final class SecretsBackendEmergencyUnavailable extends RuntimeException {}
final class SecretsBackendEmergencyNeeded extends RuntimeException {}

/** Explicit read-only authority; pairing and health alone never authorize a read. */
final class SecretsBackendEmergency
{
    public const FORMAT='SECB.EmergencyRead.1';
    public static function compare(array $a,array $b): int {
        $greater=false;$less=false;
        foreach(array_unique([...array_keys($a),...array_keys($b)])as$id){$x=$a[$id]??'0';$y=$b[$id]??'0';$c=strlen($x)<=>strlen($y)?:strcmp($x,$y);$greater=$greater||$c>0;$less=$less||$c<0;}
        return $greater&&$less?2:($greater?1:($less?-1:0));
    }
    public static function stamp(array $stamp): void {
        SecretsBackendNativePeer::exact($stamp,['clock','digest','conflicts']);
        if(!is_array($stamp['clock'])||!is_string($stamp['digest'])||!preg_match('/^[a-f0-9]{64}$/D',$stamp['digest'])||!is_int($stamp['conflicts'])||$stamp['conflicts']<0)throw new SecretsBackendEmergencyRefused('INVALID_RESPONSE');
        SecretsBackendSharedGlobal::validate(['format'=>'SECB.SharedGlobal.1','clock'=>$stamp['clock'],'records'=>[]]);
    }
    public static function arguments(string $method,array $args): array {
        if(!array_is_list($args))throw new SecretsBackendEmergencyRefused('INVALID_REQUEST');
        if($method==='GetKeys'&&$args===[])return [];
        if(!in_array($method,['GetSecret','GetExplorerFields'],true)||count($args)!==1||!is_string($args[0])||$args[0]===''||strlen($args[0])>4096)throw new SecretsBackendEmergencyRefused('GLOBAL_READ_ONLY');
        $path=$method==='GetSecret'?[$args[0]]:explode('/',$args[0]);
        if(in_array('',$path,true)||str_starts_with($path[0],'__'))throw new SecretsBackendEmergencyRefused('GLOBAL_READ_ONLY');
        SecretsBackendTree::path($path);return $path;
    }
    private static function pair(array $s,string $id): array {
        $p=$s['pairing']['peers'][$id]??null;
        if(!is_array($p)||!$p['active']||$p['state']!=='ACTIVE'||!SecretsBackendNativePeer::shared($p))throw new SecretsBackendEmergencyRefused('PAIRING_NOT_ACTIVE');return $p;
    }
    public static function grant(array $s,string $source): array {
        $p=self::pair($s,$source);
        if(count($s['native']['emergencyGrants']??[])>=64)throw new RuntimeException('Emergency grant capacity reached.');
        return ['id'=>SecretsBackendCodec::uuid(),'source'=>$source,'pairingId'=>$p['pairingId'],'token'=>SecretsBackendCodec::b64(random_bytes(32)),'name'=>SecretsBackendPeerName::display($p)];
    }
    public static function applyGrant(array $s,array $grant): array {
        $p=self::pair($s,$grant['source']);if($p['pairingId']!==$grant['pairingId'])throw new RuntimeException('Emergency pairing changed.');
        if(isset($s['native']['emergencyGrants'][$grant['id']]))throw new RuntimeException('Emergency grant already exists.');
        $s['native']['emergencyGrants'][$grant['id']]=['id'=>$grant['id'],'source'=>$grant['source'],'pairingId'=>$grant['pairingId'],'hash'=>hash('sha256',$grant['token']),'name'=>$grant['name'],'active'=>true];return $s;
    }
    public static function exportGrant(SecretsBackendNativeStore $store,SecretsBackendNativePeer $peer,array $g): string {
        $package=['format'=>'SECB.EmergencyGrant.1','source'=>$g['source'],'receiver'=>$peer->descriptor(),'pairingId'=>$g['pairingId'],'id'=>$g['id'],'token'=>$g['token'],'scope'=>'global-application-read'];
        $package['signature']=$store->sign('SECB.EMERGENCY.GRANT.1\0'.SecretsBackendNativeStore::canonical($package));return SecretsBackendCodec::json($package);
    }
    public static function importGrant(array $s,string $json): array {
        if(strlen($json)>16384)throw new RuntimeException('Emergency approval package too large.');$g=json_decode($json,true,16,JSON_THROW_ON_ERROR);
        SecretsBackendNativePeer::exact($g,['format','source','receiver','pairingId','id','token','scope','signature']);
        if($g['format']!=='SECB.EmergencyGrant.1'||$g['source']!==$s['native']['vaultId']||$g['scope']!=='global-application-read')throw new RuntimeException('Emergency approval belongs to another source or scope.');
        SecretsBackendNativePeer::descriptorCheck($g['receiver']);SecretsBackendNativePeer::uuid($g['id']);SecretsBackendCodec::unb64($g['token'],32);
        $p=self::pair($s,$g['receiver']['vaultId']);
        if($p['pairingId']!==$g['pairingId']||SecretsBackendNativePeer::authority($p['descriptor'])!==SecretsBackendNativePeer::authority($g['receiver']))throw new RuntimeException('Emergency peer identity changed.');
        $signature=$g['signature'];unset($g['signature']);
        if(!sodium_crypto_sign_verify_detached(SecretsBackendCodec::unb64($signature,64),'SECB.EMERGENCY.GRANT.1\0'.SecretsBackendNativeStore::canonical($g),SecretsBackendCodec::unb64($p['descriptor']['signKey'],32)))throw new RuntimeException('Emergency approval signature invalid.');
        return ['peerId'=>$p['id'],'pairingId'=>$p['pairingId'],'grantId'=>$g['id'],'token'=>$g['token'],'name'=>SecretsBackendPeerName::display($p)];
    }
    public static function clients(array $s): array {
        $out=[];foreach($s['native']['emergencyClients']??[]as$id=>$c){
            try{$p=self::pair($s,$id);}catch(Throwable $e){continue;}
            if($p['pairingId']!==$c['pairingId'])continue;
            $out[$id]=$c+['descriptor'=>$p['descriptor'],'routes'=>$p['routes']['endpoints']??[$p['descriptor']['endpoint']],'httpsPolicy'=>$p['httpsPolicy']??['mode'=>'strict']];
        }return $out;
    }
    public static function authorityDigest(array $s): string {
        return hash('sha256',SecretsBackendNativeStore::canonical([$s['native']['legacyAccess']??[],$s['native']['emergencyClients']??[],self::clients($s)]));
    }
    public static function publicMetadata(array $s): array {
        $clients=[];foreach(self::clients($s)as$id=>$c)$clients[]=['peerId'=>$id,'name'=>SecretsBackendPeerName::display($s['pairing']['peers'][$id]),'grantId'=>$c['grantId']];
        $grants=[];foreach($s['native']['emergencyGrants']??[]as$g)$grants[]=array_replace(array_intersect_key($g,array_flip(['id','source','name','active'])),['name'=>isset($s['pairing']['peers'][$g['source']])?SecretsBackendPeerName::display($s['pairing']['peers'][$g['source']]):$g['name']]);
        $offers=[];foreach($s['native']['emergencyOffers']??[]as$id=>$o){try{$p=self::pair($s,$id);$c=self::importGrant($s,$o['package']);$offers[]=['peerId'=>$id,'name'=>SecretsBackendPeerName::display($p),'grantId'=>$c['grantId'],'digest'=>hash('sha256',$o['package'])];}catch(Throwable $ignored){}}
        return ['offers'=>$offers,'supported'=>true,'scope'=>'Global application reads','clients'=>$clients,'grants'=>$grants,'freshness'=>'best-available-not-guaranteed-current'];
    }
    public static function serve(SecretsBackendNativeStore $store,string $bytes): string {
        if(strlen($bytes)>32768)throw new SecretsBackendEmergencyRefused('INVALID_REQUEST');$request=json_decode($bytes,true,16,JSON_THROW_ON_ERROR);
        SecretsBackendNativePeer::exact($request,['format','receiver','payload']);
        if($request['format']!==self::FORMAT||$request['receiver']!==$store->identity()['deploymentId'])throw new SecretsBackendEmergencyRefused('INVALID_REQUEST');
        $q=json_decode($store->openPeer($request['payload']),true,16,JSON_THROW_ON_ERROR);
        SecretsBackendNativePeer::exact($q,['source','grantId','token','nonce','replyKey','phase','method','args']);
        SecretsBackendNativePeer::uuid($q['source']);SecretsBackendNativePeer::uuid($q['grantId']);SecretsBackendCodec::unb64($q['token'],32);SecretsBackendCodec::unb64($q['nonce'],32);$replyKey=SecretsBackendCodec::unb64($q['replyKey'],32);
        if(!in_array($q['phase'],['probe','read'],true)||!is_string($q['method'])||!is_array($q['args']))throw new SecretsBackendEmergencyRefused('INVALID_REQUEST');
        $body=['nonce'=>$q['nonce'],'requestDigest'=>hash('sha256',$bytes),'status'=>'DENIED'];
        // Authorization, conflict check and selected data are read under one active snapshot.
        $result=$store->withActiveSnapshot(function(array $current)use($store,$q):array{
            $s=$current['state'];$g=$s['native']['emergencyGrants'][$q['grantId']]??null;
            if(!is_array($g)||!$g['active']||$g['source']!==$q['source']||!hash_equals($g['hash'],hash('sha256',$q['token'])))return ['status'=>'DENIED'];
            try{$p=self::pair($s,$q['source']);}catch(Throwable $e){return ['status'=>'DENIED'];}
            if($p['pairingId']!==$g['pairingId'])return ['status'=>'DENIED'];
            try{$store->rate('emergency:'.$g['id'],120);}catch(RuntimeException $e){throw new SecretsBackendEmergencyUnavailable('Remote emergency capacity unavailable.');}
            try{$path=self::arguments($q['method'],$q['args']);}catch(Throwable $e){return ['status'=>'DENIED'];}
            try{SecretsBackendSharedGlobal::assertPath($s,$path,false);}catch(Throwable $e){return ['status'=>'CONFLICT'];}
            try{$value=SecretsBackendLegacyAPI::emergencyGlobalRead($s,$q['method'],$q['args']);}catch(Throwable $e){return ['status'=>'MISSING'];}
            $result=['status'=>'OK','stamp'=>SecretsBackendNativeHealth::stamp($s)];if($q['phase']==='read')$result['value']=$value;return $result;
        });
        $body=array_replace($body,$result);$plain=SecretsBackendCodec::json($body);if(strlen($plain)>40000)throw new SecretsBackendEmergencyRefused('RESPONSE_TOO_LARGE');
        $reply=['format'=>'SECB.EmergencyReply.1','sender'=>$store->identity()['deploymentId'],'payload'=>SecretsBackendCodec::b64(sodium_crypto_box_seal($plain,$replyKey))];
        $reply['signature']=$store->sign('SECB.EMERGENCY.REPLY.1\0'.SecretsBackendNativeStore::canonical($reply));return SecretsBackendCodec::json($reply);
    }
}
