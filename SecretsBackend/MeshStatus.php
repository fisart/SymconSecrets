<?php
declare(strict_types=1);
require_once __DIR__.'/Mailbox.php';

/** Bounded diagnostic reports. Never authority, secret data, or transitive network discovery. */
final class SecretsBackendMeshStatus
{
    public const FORMAT='SECB.MeshStatus.1';
    public const MAILBOX='SECB.MeshStatus.Mailbox.1';
    public const DETAILS='SECB.MeshStatus.Details.1';
    private $clock;
    public function __construct(private SecretsBackendNativeStore $store,private SecretsBackendNativePeer $peer,?callable $clock=null) { $this->clock=$clock??static fn():int=>time(); }
    private function now():int { return ($this->clock)(); }
    private static function eligible(array $p):bool { return ($p['active']??false)&&($p['state']??'')==='ACTIVE'&&SecretsBackendNativePeer::shared($p); }
    private static function age(int $now,?int $at):?int { return $at!==null&&$at>0&&$now>=$at?min(86400,$now-$at):null; }
    private static function key(array $p,string $url):string { return 'mesh:'.hash('sha256',$p['pairingId'].':'.$p['epoch'].':'.$url); }
    private function record(array $p,string $url):array { try{return $this->store->get(self::key($p,$url),'mesh-status');}catch(Throwable $e){return [];} }
    private function save(array $p,string $url,array $r):void {
        $key=self::key($p,$url);try{$this->store->get($key,'mesh-status');$exists=true;}catch(Throwable $e){$exists=false;}
        if($exists)$this->store->replace($key,'mesh-status',$r,time()+86400);else $this->store->put($key,'mesh-status',$r,time()+86400);
    }
    public static function interval(array $s):int {
        $routes=0;foreach($s['pairing']['peers']as$p)if(self::eligible($p))$routes+=count($p['routes']['endpoints']??[$p['descriptor']['endpoint']]);
        return max(60,($routes+1)*10);
    }
    public function route(array $s,array $p,bool $backup):array {
        $urls=$p['routes']['endpoints']??[$p['descriptor']['endpoint']];
        $url=null;foreach($urls as$candidate){$magic=preg_match('/^[a-z0-9]{32}\.ipmagic\.de$/D',(string)parse_url($candidate,PHP_URL_HOST))===1;if($magic===$backup){$url=$candidate;break;}}
        if($url===null)return ['state'=>'none','age'=>null];
        $r=$this->record($p,$url);$age=self::age($this->now(),$r['at']??null);
        return ['state'=>$age===null||$age>=self::interval($s)*3?'unknown':($r['state']??'unknown'),'age'=>$age]+array_intersect_key($r,array_flip(['problem','httpStatus','certificateReason','failedChecks']))+['lastSuccessAge'=>self::age($this->now(),$r['lastSuccessAt']??null)];
    }
    /** One exact approved route per worker tick; neither fallback nor a co-located shortcut proves that route. */
    public function tick():array {
        $s=$this->store->read()['state'];$now=$this->now();$chosen=null;$oldest=PHP_INT_MAX;
        foreach($s['pairing']['peers']as$p){if(!self::eligible($p))continue;
            foreach($p['routes']['endpoints']??[$p['descriptor']['endpoint']]as$url){$r=$this->record($p,$url);$at=$r['at']??0;
                if($at&&$now>=$at&&$now-$at<self::interval($s))continue;
                if($at<$oldest){$chosen=[$p,$url];$oldest=$at;}
            }
        }
        if($chosen===null)return ['status'=>'MESH_IDLE'];[$p,$url]=$chosen;$previous=$this->record($p,$url);$r=['at'=>$now,'state'=>'unknown','problem'=>null,'httpStatus'=>0,'certificateReason'=>'unknown','failedChecks'=>0,'lastSuccessAt'=>$previous['lastSuccessAt']??null];$report=null;
        try{
            $target=$p;$target['routes']['endpoints']=[$url];
            $formats=isset($previous['protocol'],$previous['protocolAt'])&&$now-$previous['protocolAt']<3600?array_slice([self::MAILBOX,self::DETAILS,self::FORMAT],array_search($previous['protocol'],[self::MAILBOX,self::DETAILS,self::FORMAT],true)):[self::MAILBOX,self::DETAILS,self::FORMAT];
            foreach($formats as$format){try{$reply=$this->peer->exchange($target,'MESH_STATUS',['format'=>$format],SecretsBackendCodec::uuid());break;}catch(SecretsBackendNativePeerDeliveryFailure $e){if($format===self::FORMAT||$e->problem!=='http'||$e->httpStatus!==403)throw $e;}}
            SecretsBackendNativePeer::exact($reply,['requestId','requestKind','requestDigest','status','report']);
            if($reply['status']!=='MESH_STATUS')throw new RuntimeException('Unexpected mesh reply.');
            self::validate($reply['report'],$p['id']);$report=$reply['report'];$r['protocol']=$format;$r['protocolAt']=($previous['protocol']??null)===$format?($previous['protocolAt']??$now):$now;$r['state']='ok';$r['lastSuccessAt']=$now;
        }catch(Throwable $e){$r['failedChecks']=min(100,($previous['failedChecks']??0)+1);$r['problem']=$e instanceof SecretsBackendNativePeerDeliveryFailure&&in_array($e->problem,SecretsBackendNativePeerDeliveryFailure::PROBLEMS,true)?$e->problem:'invalid-reply';if($e instanceof SecretsBackendNativePeerDeliveryFailure){$r['httpStatus']=max(0,min(599,$e->httpStatus));$r['certificateReason']=in_array($e->certificateReason,SecretsBackendNativePeerDeliveryFailure::CERTIFICATE_REASONS,true)?$e->certificateReason:'unknown';}$r['state']=$e instanceof SecretsBackendNativePeerDeliveryFailure&&$e->problem==='http'&&in_array($e->httpStatus,[400,403,404],true)?'unknown':'error';}
        $live=$this->store->read()['state']['pairing']['peers'][$p['id']]??null;
        if(!$live||!self::eligible($live)||$live['pairingId']!==$p['pairingId']||$live['epoch']!==$p['epoch']||!in_array($url,$live['routes']['endpoints']??[$live['descriptor']['endpoint']],true))return ['status'=>'MESH_CONNECTION_CHANGED'];
        if($report!==null){
            // Diagnostics must not consume an unbounded part of the secret journal.
            $budget=max(800,(int)floor($this->store->metadata()['capacityBytes']/8/max(1,count(array_filter($s['pairing']['peers'],[self::class,'eligible'])))));
            $localId=$s['native']['vaultId'];usort($report['links'],static fn($a,$b)=>($b['id']===$localId)<=>($a['id']===$localId));
            while(strlen(SecretsBackendCodec::json($report))>$budget&&!empty($report['mailbox']['rows'])){array_pop($report['mailbox']['rows']);$report['mailbox']['partial']=true;}
            while(strlen(SecretsBackendCodec::json($report))>$budget&&$report['links']){array_pop($report['links']);$report['truncated']=true;}
            $this->save($p,'report',['at'=>$now,'endpoint'=>$url,'report'=>$report]);
        }
        $this->save($p,$url,$r);return ['status'=>'MESH_CHECKED','peerId'=>$p['id']];
    }
    private static function indicator(array $v,bool $none=false,bool $diagnostic=false):void {
        SecretsBackendNativePeer::exact($v,array_merge(['state','age'],$diagnostic?array_values(array_intersect(array_keys($v),['problem','httpStatus','certificateReason','failedChecks','lastSuccessAge'])):[]));
        if($diagnostic){if(isset($v['problem'])&&!in_array($v['problem'],SecretsBackendNativePeerDeliveryFailure::PROBLEMS,true))throw new RuntimeException('Invalid route problem.');if(isset($v['certificateReason'])&&!in_array($v['certificateReason'],SecretsBackendNativePeerDeliveryFailure::CERTIFICATE_REASONS,true))throw new RuntimeException('Invalid TLS reason.');foreach(['httpStatus'=>599,'failedChecks'=>100,'lastSuccessAge'=>86400]as$k=>$max)if(isset($v[$k])&&(!is_int($v[$k])||$v[$k]<0||$v[$k]>$max))throw new RuntimeException('Invalid diagnostic count.');}
        if(!in_array($v['state'],$none?['ok','error','unknown','none']:['ok','error','unknown'],true)||($v['age']!==null&&(!is_int($v['age'])||$v['age']<0||$v['age']>86400)))throw new RuntimeException('Invalid mesh indicator.');
    }
    public static function validate(array $r,string $id):void {
        if(strlen(SecretsBackendCodec::json($r))>24000)throw new RuntimeException('Mesh report too large.');
        if(isset($r['mailbox'])){self::mailboxCheck($r['mailbox']);unset($r['mailbox']);}
        SecretsBackendNativePeer::exact($r,['format','id','name','components','backupService','source','fallback','activeSource','conflicts','storagePercent','links','ttl','truncated']);
        if($r['format']!==self::FORMAT||$r['id']!==$id||!is_string($r['name'])||strlen($r['name'])>160||!is_int($r['ttl'])||$r['ttl']<180||$r['ttl']>2000)throw new RuntimeException('Invalid mesh report.');
        SecretsBackendNativePeer::uuid($r['id']);SecretsBackendNativePeer::exact($r['components'],['frontend','backend','vault']);
        foreach($r['components']as$v){if(!is_array($v))throw new RuntimeException('Invalid component.');self::indicator($v);}
        if($r['activeSource']!==null)SecretsBackendNativePeer::uuid($r['activeSource']);
        self::indicator($r['backupService'],true);self::indicator($r['source']);
        if(!is_bool($r['truncated'])||!is_bool($r['fallback'])||!is_int($r['conflicts'])||$r['conflicts']<0||$r['conflicts']>5000||($r['storagePercent']!==null&&(!is_int($r['storagePercent'])||$r['storagePercent']<0||$r['storagePercent']>100)))throw new RuntimeException('Invalid mesh service state.');
        if(!is_array($r['links'])||!array_is_list($r['links'])||count($r['links'])>32)throw new RuntimeException('Invalid mesh links.');$seen=[];
        foreach($r['links']as$l){SecretsBackendNativePeer::exact($l,['id','name','paired','connection','sync','age','ttl','primary','backup','consumes','grants','clientGrant','grantIds']);SecretsBackendNativePeer::uuid($l['id']);
            if(isset($seen[$l['id']])||$l['id']===$id||!is_string($l['name'])||strlen($l['name'])>160||!is_bool($l['paired'])||!is_bool($l['consumes'])||!is_bool($l['grants'])||!in_array($l['connection'],['reachable','retrying','unreachable','unknown'],true)||!in_array($l['sync'],['verified','synchronizing','mismatch','unknown'],true)||($l['age']!==null&&(!is_int($l['age'])||$l['age']<0||$l['age']>86400))||!is_int($l['ttl'])||$l['ttl']<180||$l['ttl']>2000)throw new RuntimeException('Invalid mesh link.');
            if($l['clientGrant']!==null)SecretsBackendNativePeer::uuid($l['clientGrant']);if(!is_array($l['grantIds'])||!array_is_list($l['grantIds'])||count($l['grantIds'])>64)throw new RuntimeException('Invalid grant metadata.');foreach($l['grantIds']as$g)SecretsBackendNativePeer::uuid($g);
            self::indicator($l['primary'],true,true);self::indicator($l['backup'],true,true);$seen[$l['id']]=true;
        }
    }
    private static function mailboxCheck(array $m):void { SecretsBackendMailbox::validate($m); }
    /** A node reports only its own observations, never repeats another node's report. */
    public function report(array $s,array $runtime=[]):array {
        $unknown=['state'=>'unknown','age'=>null];$components=($runtime['components']??[])+['frontend'=>$unknown,'backend'=>$unknown,'vault'=>$unknown];
        $health=(new SecretsBackendNativeHealth($this->store,$this->peer,$this->clock))->statuses($s);$links=[];
        foreach($s['pairing']['peers']as$p){if(($p['state']??'')==='REVOKED')continue;$id=$p['id'];$h=$health[$id]??[];$active=self::eligible($p);$client=$s['native']['emergencyClients'][$id]??null;$granted=false;$grantIds=[];
            foreach($s['native']['emergencyGrants']??[]as$g)if($active&&$g['active']&&$g['source']===$id&&$g['pairingId']===$p['pairingId']){$granted=true;$grantIds[]=$g['id'];}
            $links[]=['id'=>$id,'name'=>substr($p['name'],0,160),'paired'=>$active,'connection'=>$h['connection']??'unknown','sync'=>$h['synchronization']??'unknown','age'=>self::age($this->now(),$h['lastAttemptAt']??null),'ttl'=>$h['staleAfterSeconds']??180,
                'primary'=>$this->route($s,$p,false),'backup'=>$this->route($s,$p,true),'consumes'=>$active&&is_array($client)&&$client['pairingId']===$p['pairingId'],'grants'=>$granted,'clientGrant'=>$active&&is_array($client)&&$client['pairingId']===$p['pairingId']?$client['grantId']:null,'grantIds'=>$grantIds];
        }
        $r=['format'=>self::FORMAT,'id'=>$s['native']['vaultId'],'name'=>substr((string)parse_url($this->store->identity()['binding']['origin'],PHP_URL_HOST),0,160),'components'=>$components,'backupService'=>$runtime['backupService']??$unknown,'source'=>$runtime['source']??$unknown,'fallback'=>$runtime['fallback']??false,'activeSource'=>$runtime['activeSource']??null,'conflicts'=>isset($s['native']['sharedGlobal'])?SecretsBackendNativeHealth::stamp($s)['conflicts']:0,'storagePercent'=>($storage=$this->store->metadata())['capacityBytes']>0?min(100,(int)ceil(100*$storage['usedBytes']/$storage['capacityBytes'])):null,'links'=>$links,'ttl'=>self::interval($s)*3,'truncated'=>false];self::validate($r,$r['id']);return $r;
    }
    public function view(array $s):array {
        $reports=[['report'=>$this->peer->meshReport($s),'age'=>0,'direct'=>true]];$now=$this->now();
        foreach($s['pairing']['peers']as$p){if(!self::eligible($p))continue;$r=$this->record($p,'report');
            if(isset($r['report'])&&in_array($r['endpoint'],$p['routes']['endpoints']??[$p['descriptor']['endpoint']],true))$reports[]=['report'=>$r['report'],'age'=>self::age($now,$r['at']),'direct'=>true];
        }
        return ['localId'=>$s['native']['vaultId'],'reports'=>$reports,'observedAt'=>$now];
    }
}
