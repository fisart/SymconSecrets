<?php
declare(strict_types=1);
require_once __DIR__.'/SharedGlobal.php';

/** Fresh, pair-bound probes. Private fingerprints never enter browser metadata. */
final class SecretsBackendNativeHealth
{
    public const FORMAT='SECB.GlobalHealth.1';
    /** Observations are not a quorum certificate or permission to serve emergency reads. */
    public static function guarantees(): array
    {
        return [
            'protocol' => SecretsBackendSharedGlobal::SCOPE,
            'replication' => 'asynchronous',
            'writeAcknowledgement' => 'local-durable',
            'readGuarantee' => 'local-authenticated-snapshot',
            'healthGuarantee' => 'matched-at-check',
            'quorumCommit' => false,
            'linearizableRead' => false,
            'strictEmergencyReadSupported' => false,
            'emergencyReadReason' => 'QUORUM_COMMIT_READ_PROTOCOL_REQUIRED',
        ];
    }

    private $clock;
    public function __construct(private SecretsBackendNativeStore $store,private SecretsBackendNativePeer $peer,?callable $clock=null){$this->clock=$clock??static fn():int=>time();}
    private function now():int{return ($this->clock)();}
    private static function eligible(array $p):bool{return ($p['active']??false)&&($p['state']??'')==='ACTIVE'&&SecretsBackendNativePeer::shared($p);}
    public static function stamp(array $s):array
    {
        $m=$s['native']['sharedGlobal']??null;if(!is_array($m))throw new RuntimeException('Shared Global is not negotiated.');
        SecretsBackendSharedGlobal::validate($m);$view=SecretsBackendSharedGlobal::view($m);
        if(!hash_equals(SecretsBackendNativePeer::digest($view['node']),SecretsBackendNativePeer::digest($s['vault']['global'])))throw new RuntimeException('Global projection differs from its history.');
        return ['clock'=>$m['clock'],'digest'=>SecretsBackendNativePeer::digest($m),'conflicts'=>count($view['conflicts'])];
    }
    private static function validateReply(array $r):void
    {
        SecretsBackendNativePeer::exact($r,['requestId','requestKind','requestDigest','status','format','clock','digest','conflicts']);
        if($r['status']!=='GLOBAL_HEALTH'||$r['format']!==self::FORMAT||!is_array($r['clock'])||!is_string($r['digest'])||!preg_match('/^[a-f0-9]{64}$/D',$r['digest'])||!is_int($r['conflicts'])||$r['conflicts']<0||$r['conflicts']>5000)throw new RuntimeException('Invalid Global health response.');
        SecretsBackendSharedGlobal::validate(['format'=>'SECB.SharedGlobal.1','clock'=>$r['clock'],'records'=>[]]);
    }
    private function record(array $p):array
    {
        try{$r=$this->store->get('peer-health:'.$p['pairingId'],'peer-health');return ($r['epoch']??null)===$p['epoch']?$r:[];}catch(Throwable $e){return [];}
    }
    private function save(array $p,array $r):void
    {
        $key='peer-health:'.$p['pairingId'];$r['epoch']=$p['epoch'];
        try{$this->store->get($key,'peer-health');$exists=true;}catch(Throwable $e){$exists=false;}
        if($exists)$this->store->replace($key,'peer-health',$r,time()+86400);else $this->store->put($key,'peer-health',$r,time()+86400);
    }
    public static function interval(array $s):int
    {
        // One bounded network check per ten-second worker tick; four systems
        // are checked every minute. Larger groups retain a fair, feasible cadence.
        return max(60,(count(array_filter($s['pairing']['peers'],[self::class,'eligible']))+1)*10);
    }
    public static function repairQueued(array $s,string $id):bool
    {
        foreach($s['outbox']['jobs']as$j)if($j['receiverId']===$id&&in_array($j['kind'],['SYNC','RESYNC'],true))return true;return false;
    }
    /** Reply with the current state if a valid older snapshot arrived unchanged. */
    public static function feedback(array $s,string $id,array $remote):array
    {
        if(!hash_equals(SecretsBackendNativePeer::digest($s['native']['sharedGlobal']),SecretsBackendNativePeer::digest($remote))&&!self::repairQueued($s,$id))return SecretsBackendNativePeer::queueGlobal($s,$id);return $s;
    }
    private function repair(array $cur,array $p):bool
    {
        if(self::repairQueued($cur['state'],$p['id']))return true;
        try{$this->store->change($cur['head'],SecretsBackendCodec::uuid(),SecretsBackendNativePeer::digest(['health-repair'=>$p['pairingId'],'head'=>$cur['head']]),static function($s)use($p){$live=$s['pairing']['peers'][$p['id']]??null;if(!$live||!self::eligible($live)||$live['pairingId']!==$p['pairingId']||$live['epoch']!==$p['epoch'])throw new RuntimeException('Connection changed during health repair.');return self::repairQueued($s,$p['id'])?$s:SecretsBackendNativePeer::queueGlobal($s,$p['id']);},['action'=>'peer-health-repair','actor'=>'background','target'=>$p['pairingId']]);return true;}catch(Throwable $e){return false;}
    }
    public function tick():array
    {
        $cur=$this->store->read();$interval=self::interval($cur['state']);$now=$this->now();$chosen=null;$old=[];
        foreach($cur['state']['pairing']['peers']as$p){if(!self::eligible($p))continue;$r=$this->record($p);$at=$r['lastAttemptAt']??0;
            if($at&&$now>=$at&&$now-$at<$interval)continue;
            if($chosen===null||$at<($old['lastAttemptAt']??0)){$chosen=$p;$old=$r;}}
        if($chosen===null)return ['status'=>'HEALTH_IDLE'];$p=$chosen;
        $r=$old+['lastSuccessAt'=>null,'lastVerifiedAt'=>null,'failures'=>0,'mismatchSince'=>null,'mismatchChecks'=>0];$r['lastAttemptAt']=$now;$r['problem']=null;
        try{$local=self::stamp($cur['state']);}catch(Throwable $e){$r['problem']='local-state-invalid';$r['synchronization']='mismatch';$this->save($p,$r);return ['status'=>'HEALTH_LOCAL_INVALID'];}
        try{
            $reply=$this->peer->exchange($p,'HEALTH',['format'=>self::FORMAT],SecretsBackendCodec::uuid());self::validateReply($reply);
            $cur=$this->store->read();$live=$cur['state']['pairing']['peers'][$p['id']]??null;
            if(!$live||!self::eligible($live)||$live['pairingId']!==$p['pairingId']||$live['epoch']!==$p['epoch'])return ['status'=>'HEALTH_CONNECTION_CHANGED'];
            $local=self::stamp($cur['state']);$r['lastSuccessAt']=$now;$r['failures']=0;$r['localDigest']=$local['digest'];$r['remoteConflicts']=$reply['conflicts'];
            $same=hash_equals($local['digest'],$reply['digest']);$sameClock=SecretsBackendNativeStore::canonical($local['clock'])===SecretsBackendNativeStore::canonical($reply['clock']);
            if($same&&(!$sameClock||$local['conflicts']!==$reply['conflicts']))throw new RuntimeException('Inconsistent health digest and clock.');
            if($same){$r['synchronization']='verified';$r['lastVerifiedAt']=$now;$r['mismatchSince']=null;$r['mismatchChecks']=0;}
            else{
                $r['mismatchSince']=($r['mismatchSince']!==null&&$r['mismatchSince']<=$now)?$r['mismatchSince']:$now;$r['mismatchChecks']=min(100,($old['mismatchChecks']??0)+1);
                $r['synchronization']='synchronizing';if($sameClock){$r['problem']='inconsistent-state';$r['synchronization']='mismatch';}elseif(!$this->repair($cur,$p))$r['problem']='repair-blocked';
            }
        }catch(Throwable $e){$r['failures']=min(100,($old['failures']??0)+1);$r['problem']=$e instanceof SecretsBackendNativePeerDeliveryFailure&&in_array($e->problem,SecretsBackendNativePeerDeliveryFailure::PROBLEMS,true)?$e->problem:'invalid-reply';$r['synchronization']='unknown';$r['lastSuccessAt']=$old['lastSuccessAt']??null;}
        $this->save($p,$r);return ['status'=>'HEALTH_CHECKED','peerId'=>$p['id']];
    }
    /** Local-only metadata; never contacts a peer or changes a session. */
    public function statuses(array $s):array
    {
        $now=$this->now();$interval=self::interval($s);$local=null;try{$local=self::stamp($s);}catch(Throwable $e){}$out=[];
        foreach($s['pairing']['peers']as$p){if(!self::eligible($p))continue;$r=$this->record($p);$last=$r['lastSuccessAt']??null;$fresh=$last!==null&&$now>=$last&&$now-$last<$interval*3;$attempt=$r['lastAttemptAt']??null;
            $connection=$fresh?(($r['failures']??0)?'retrying':'reachable'):(($r['failures']??0)?'unreachable':'unknown');$sync=$fresh?($r['synchronization']??'unknown'):'unknown';$problem=$r['problem']??null;if(!$fresh&&$problem===null&&(($last!==null)||(!$r&&$p['lastSync']!==null&&$now-(strtotime($p['lastSync'])?:$now)>=$interval*3)))$problem='check-overdue';
            if(!$local){$sync='mismatch';$problem='local-state-invalid';}
            elseif(in_array($problem,['inconsistent-state','local-state-invalid'],true))$sync='mismatch';
            elseif($fresh&&($r['localDigest']??'')!==$local['digest'])$sync='synchronizing';
            elseif($fresh&&$sync==='synchronizing'&&($r['mismatchSince']??null)!==null&&$now>=$r['mismatchSince']&&$now-$r['mismatchSince']>=$interval*3&&($r['mismatchChecks']??0)>=3)$sync='mismatch';
            if(($r['failures']??0)>=3||($attempt!==null&&$now<$attempt)){$connection=($r['failures']??0)>=3?'unreachable':'unknown';if($attempt!==null&&$now<$attempt)$problem='clock-changed';if($problem!=='inconsistent-state'&&$problem!=='local-state-invalid')$sync='unknown';}
            $pending=count(array_filter($s['outbox']['jobs'],static fn($j)=>$j['receiverId']===$p['id']));
            $out[$p['id']]=['connection'=>$connection,'synchronization'=>$sync,'lastAttemptAt'=>$attempt,'lastSuccessAt'=>$last,'lastVerifiedAt'=>$r['lastVerifiedAt']??null,'pendingMessages'=>$pending,'problem'=>$problem,'failedChecks'=>$r['failures']??0,'intervalSeconds'=>$interval,'staleAfterSeconds'=>$interval*3,'remoteConflicts'=>$fresh?($r['remoteConflicts']??null):null];
        }return $out;
    }
}
