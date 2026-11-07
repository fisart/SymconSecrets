<?php
declare(strict_types=1);

/** Symcon-side presentation of authenticated monitoring observations.
 * No network requests, persistence or authority decisions. Browser transit and
 * browser clocks never participate in health, freshness or readiness decisions.
 */
final class SecretsFrontendMonitoringView
{
    private const WORDS=['ok'=>'Healthy','error'=>'Error','unknown'=>'Unknown / stale','none'=>'Not configured'];
    private static function fresh(?array $x):bool {return $x!==null&&is_int($x['age']??null)&&$x['age']>=0&&$x['age']<($x['report']['ttl']??0);}
    private static function age(?array $x,?array $v):?int {return is_int($x['age']??null)&&$x['age']>=0&&is_int($v['age']??null)&&$v['age']>=0?$x['age']+$v['age']:null;}
    private static function item(?array $x,?array $v,?int $ttl=null):array {
        $age=self::age($x,$v);$state=!self::fresh($x)?'unknown':(($v['state']??'')==='none'?'none':($age===null||$age>=($ttl??$x['report']['ttl'])?'unknown':($v['state']??'unknown')));
        return ['state'=>$state,'age'=>$age];
    }
    private static function checked(?int $age,?int $ttl):string {return $age===null?'No current check':$age.'s since check'.($ttl?' · age warning after '.round($ttl/60).' min':'');}
    private static function routeReason(?array $v):string {
        if(empty($v['problem']))return ($v['state']??'')==='error'?' Detailed reason unavailable; update the reporting installation.':'';
        $labels=['dns'=>'DNS lookup failed','connect'=>'Connection failed','timeout'=>'Request timed out','certificate'=>'HTTPS certificate verification failed','tls'=>'TLS handshake failed','http'=>'HTTP request refused','response-size'=>'Response exceeded its size limit','invalid-reply'=>'Reply could not be authenticated or validated','transport'=>'HTTPS transport unavailable','unconfirmed'=>'Delivery unconfirmed'];
        return ' '.($labels[$v['problem']]??'Check failed').(!empty($v['httpStatus'])?' (HTTP '.$v['httpStatus'].')':'').(!empty($v['certificateReason'])&&$v['certificateReason']!=='unknown'?' · '.$v['certificateReason']:'').(!empty($v['failedChecks'])?' · '.$v['failedChecks'].' consecutive failure(s)':'').'.';
    }
    private static function link(?array $x,string $id):?array {foreach($x['report']['links']??[]as$l)if($l['id']===$id)return $l;return null;}
    public static function mesh(array $n):?array {
        $m=$n['mesh']??null;if(!$m)return null;$local=$m['localId'];$rows=[$local=>['id'=>$local,'name'=>'This installation','direct'=>true]];$reports=[];
        foreach($m['reports']??[]as$x){$id=$x['report']['id'];$reports[$id]=$x;$rows[$id]=['id'=>$id,'name'=>$x['report']['name'],'direct'=>true];}
        foreach($n['peers']??[]as$p)if($p['state']!=='REVOKED')$rows[$p['id']]=['id'=>$p['id'],'name'=>$reports[$p['id']]['report']['name']??$p['name'],'direct'=>true];
        foreach($reports as$x)foreach($x['report']['links']??[]as$l)if(!isset($rows[$l['id']])&&count($rows)<64)$rows[$l['id']]=['id'=>$l['id'],'name'=>$l['name'],'direct'=>false];
        $nodes=array_values($rows);usort($nodes,static fn($a,$b)=>$a['id']===$b['id']?0:($a['id']===$local?-1:($b['id']===$local?1:strnatcasecmp($a['name'],$b['name']))));
        $problems=0;$pending=0;$fallbacks=0;$warnings=[];$cells=[];
        foreach($nodes as&$node){
            $x=$reports[$node['id']]??null;$r=$x['report']??[];$current=self::fresh($x);$fallback=$current&&($r['fallback']??false);$indicators=[];$summary=[];
            foreach(['frontend','backend','vault','source','backupService']as$key){
                $v=in_array($key,['source','backupService'],true)?($r[$key]??null):($r['components'][$key]??null);$h=self::item($x,$v);
                if($h['state']==='error')$problems++;if($h['state']==='unknown')$pending++;
                $label=$key==='source'&&$fallback?'Remote fallback':self::WORDS[$h['state']];
                $h['label']=$label;$h['description']=$node['name'].' · '.$key.': '.$label.'. '.self::checked($h['age'],$r['ttl']??null).($node['id']!==$local?'. Reported by this node.':'');$indicators[$key]=$h;
            }
            if($fallback)$fallbacks++;
            $conflicts=$current?($r['conflicts']??null):null;$storage=$current?($r['storagePercent']??null):null;
            $indicators['conflicts']=['state'=>$conflicts===null?'unknown':($conflicts?'error':'ok'),'label'=>$conflicts===null?'Unknown':(string)$conflicts];
            $indicators['storage']=['state'=>$storage===null?'unknown':($storage>=90?'error':($storage>=75?'unknown':'ok')),'label'=>$storage===null?'Unknown':$storage.'%'];
            foreach(['conflicts','storage']as$key)if($indicators[$key]['state']==='error')$problems++;
            $sync='ok';if(!$current||!empty($r['truncated']))$sync='unknown';
            foreach($r['links']??[]as$l){$a=self::age($x,$l);if($sync!=='error'&&($a===null||$a>=$l['ttl']||$l['sync']!=='verified'||$l['connection']!=='reachable'))$sync='unknown';if($current&&($l['sync']==='mismatch'||$l['connection']==='unreachable')&&$a!==null&&$a<$l['ttl'])$sync='error';}
            $indicators['sync']=['state'=>$sync];
            foreach(['Frontend'=>'frontend','Backend'=>'backend','Vault'=>'vault','Source'=>'source','Backup'=>'backupService','Sync'=>'sync']as$label=>$key)$summary[]=$label.': '.$indicators[$key]['state'].($key==='source'&&$fallback?' (remote fallback from '.($rows[$r['activeSource']]['name']??'approved peer').')':'');
            $extra=$current?($r['conflicts']??0).' conflict(s) · '.($storage??'?').'% storage':'Waiting for a fresh report';
            $node+=['indicators'=>$indicators,'subtitle'=>$fallback?'Remote fallback active':($node['id']===$local?'This installation':(!$node['direct']?'Indirect · status unknown':($current?'Authenticated peer report':($x?'Report stale':'No report yet')))),
                'extra'=>$extra,'extraClass'=>$current&&($conflicts>0||$storage>=90)?' meshNodeFault':($current&&$storage>=75?' meshNodeWarning':''),
                'reportAge'=>is_int($x['age']??null)?$x['age'].'s'.($current?'':' · stale'):'No report',
                'description'=>$node['name'].'. '.implode('. ',$summary).'. '.$extra.'. '.(is_int($x['age']??null)?'Report '.$x['age'].'s old.':'No authenticated report.')];
        }unset($node);
        foreach($nodes as$from)foreach($nodes as$to){
            if($from['id']===$to['id'])continue;$x=$reports[$from['id']]??null;$y=$reports[$to['id']]??null;$l=self::link($x,$to['id']);$reverse=self::link($y,$from['id']);$live=self::fresh($x);$other=self::fresh($y);
            $primary=self::item($x,$l['primary']??null);$backup=self::item($x,$l['backup']??null);$a=self::age($x,$l);
            if($live&&!$l&&!$x['report']['truncated']){$primary['state']='none';$backup['state']='none';}
            $sync=$live&&!$l&&!$x['report']['truncated']?'none':(!$live||!$l||$a===null||$a>=$l['ttl']?'unknown':($l['sync']==='mismatch'||$l['connection']==='unreachable'?'error':($l['sync']==='verified'&&$l['connection']==='reachable'?'ok':'unknown')));
            $auth='unknown';$authText='Authorization cannot be confirmed from fresh reports.';
            if($live&&$other&&(!$x['report']['truncated']||$l)&&(!$y['report']['truncated']||$reverse)){
                $enabled=!empty($l['consumes'])&&!empty($l['clientGrant']);$granted=$enabled&&!empty($reverse['grants'])&&in_array($l['clientGrant'],$reverse['grantIds']??[],true);
                $auth=$enabled&&$granted?'ok':($enabled?'error':(empty($reverse['grants'])?'none':'unknown'));
                $authText=['ok'=>'Exact emergency read grant approved on both installations.','none'=>'Emergency reads are not configured in this direction.','error'=>'The consuming installation’s exact grant is no longer approved by the provider.','unknown'=>'Only the provider is configured. Accept its offer on the consuming installation.'][$auth];
            }
            $observations=[['P',$primary['state'],'Primary route: '.self::WORDS[$primary['state']].'. '.self::checked($primary['age'],$x['report']['ttl']??null).self::routeReason($l['primary']??null)],['B',$backup['state'],'Backup route: '.self::WORDS[$backup['state']].'. '.self::checked($backup['age'],$x['report']['ttl']??null).self::routeReason($l['backup']??null)],['S',$sync,'Global synchronization: '.($live&&$l?$l['sync']:'unknown').'. '.self::checked($a,$l['ttl']??null)],['A',$auth,$authText]];
            foreach($observations as$o){if($o[1]==='error'){$problems++;$warnings[]=$from['name'].' → '.$to['name'].': '.$o[2];}if($o[1]==='unknown')$pending++;}
            $key=$from['id'].'|'.$to['id'];$cells[]=['key'=>$key,'observations'=>$observations,'paired'=>$l['paired']??false,'description'=>$from['name'].' → '.$to['name'].'. '.implode(' ',array_column($observations,2)).($from['id']!==$local?' Observations reported by '.$from['name'].'.':' Observed on this installation.')];
        }
        $indirect=(bool)array_filter($nodes,static fn($n)=>!$n['direct']);$truncated=(bool)array_filter($reports,static fn($x)=>$x['report']['truncated']??false);
        return ['localId'=>$local,'observedAt'=>$m['observedAt']??($n['serverTime']??null),'nodes'=>$nodes,'cells'=>$cells,'warnings'=>$warnings,'problems'=>$problems,'pending'=>$pending,'fallbacks'=>$fallbacks,
            'info'=>(!empty($m['unavailable'])?'Mesh diagnostics are temporarily unavailable. ':'').count($nodes).' known node(s). '.($problems?$problems.' health warning(s). ':'').'Rows show the observing installation; A means the row may read Global secrets from the column. Reports are authenticated observations, not proof of current availability. '.($indirect?'Indirect nodes remain unknown until directly paired. ':'').($truncated?'Some remote detail is omitted to protect journal capacity; missing details remain unknown. ':'').(count($nodes)>=64?'Display limited to 64 known nodes. ':'')];
    }
    private static function peer(array $p,array $n):array {
        $received=false;$sent=false;foreach($n['pairingReceived']??[]as$r)if($r['id']===($p['descriptor']['treeId']??null)&&$r['owner']===$p['id']&&($r['pairingId']??null)===($p['pairingId']??null))$received=true;
        foreach($n['pairingSent']??[]as$r)if($r['peerId']===$p['id']&&($r['pairingId']??null)===($p['pairingId']??null)&&$r['status']==='APPLIED'&&$r['treeId']===($n['globalTreeId']??null)&&$r['revision']===($n['globalRevision']??null))$sent=true;
        $queued=array_values(array_filter($n['outbox']??[],static fn($j)=>$j['receiverId']===$p['id']&&in_array($j['kind'],['GLOBAL_ENABLE','PAIR_REQUEST','PAIR_ACCEPT','SYNC','RESYNC'],true)));
        $blocked=!empty($p['delivery']['problem'])&&$p['delivery']['problem']!=='not-attempted';$expired=in_array($p['state'],['PENDING_REMOTE','PENDING_APPROVAL'],true)&&($p['expires']??0)>0&&$p['expires']<($n['serverTime']??time());
        $shared=($p['globalMode']??$p['pair']['scope']??null)==='shared-global-v1';$h=$p['health']??null;
        $ready=$shared&&($p['active']??false)&&$p['state']==='ACTIVE'&&$received&&$sent&&!$queued&&($n['globalWritable']??false)&&!$blocked&&(!$h||$h['synchronization']==='verified');
        $healthProblem=$h&&(!empty($h['problem'])||in_array($h['connection'],['unreachable','retrying'],true)||$h['synchronization']==='mismatch');
        $label=['PENDING_REMOTE'=>'Waiting for the first platform','PENDING_APPROVAL'=>'Waiting for your approval','ACTIVE'=>'Pairing approved','REVOKED'=>'Removed'][$p['state']]??'Check connection';
        if($expired)$label='Approval window expired';elseif($p['state']==='ACTIVE'){
            if($h)$label=(['verified'=>'Verified in sync','synchronizing'=>'Synchronizing','mismatch'=>'Not synchronized','unknown'=>'Status unknown'][$h['synchronization']]??'Status unknown').($h['connection']==='unreachable'?' · unreachable':($h['connection']==='retrying'?' · check retry pending':'')).(!empty($n['globalConflictCount'])?' · resolve conflicts':'');
            elseif($blocked)$label='Pairing approved · delivery blocked';else $label=$ready?(!empty($n['globalConflictCount'])?'Shared · resolve conflicts':($shared?'Ready · Global synchronized':'Legacy connection · separate copies')):'Pairing approved · waiting for data exchange';
        }
        return ['expired'=>$expired,'blocked'=>$blocked,'healthProblem'=>(bool)$healthProblem,'warning'=>$blocked||$expired||$healthProblem,'label'=>$label,'state'=>$h['synchronization']??'unknown','sharing'=>['received'=>$received,'sent'=>$sent,'queued'=>$queued,'ready'=>$ready]];
    }
    private static function setup(array $a):array {
        $members=$a['members']??[];$ready=count(array_filter($members,static fn($m)=>!empty($m['ready'])&&(!empty($m['local'])||!empty($m['fresh']))));$completed=!empty($a['completedAt'])&&empty($a['running']);
        $a['display']=count($members)&&$ready===count($members)&&empty($a['running'])?'OK — all '.count($members).' servers completed mesh setup. Primary and backup routes, synchronization and emergency access were verified.':(!empty($a['running'])?'Setup is running in the background. '.$ready.' of '.count($members).' servers ready. Slow servers are retried automatically.':(!empty($a['completedAt'])?'Mesh setup completed. Current health is shown in Overview; expired setup confirmations do not require another setup run.':(!empty($a['policy'])||($a['report']['state']??'')==='incomplete'?'Setup is incomplete. See the connection details and error report below. Select Finish setup to resume.':'Click once to configure the mesh across your existing trusted Global connections.')));
        foreach($members as$i=>$m)$a['members'][$i]['display']=$completed?'Included in the completed mesh setup. '.(!empty($m['local'])?'Current local checks are shown below.':'See Overview for current authenticated health reports.'):(!empty($m['ready'])&&(!empty($m['local'])||!empty($m['fresh']))?'Mesh setup verified.':(!empty($m['enrollment'])?'Delivering automatic authorization. Attempts: '.$m['enrollment']['attempts'].'.':(!empty($m['deliveryPending'])?'Waiting for this server’s reply.':(($m['authorized']??null)===false?'Automatic authorization has not been accepted. Check delivery errors and the installed module version.':(empty($m['fresh'])&&empty($m['local'])?'Waiting for a fresh authenticated reply.':'Completing connections and verification.')))));
        return $a;
    }
    public static function decorate(array $n,string $frontendPath=''):array {
        foreach($n['peers']??[]as$i=>$p)$n['peers'][$i]['display']=self::peer($p,$n);
        $n['monitoring']=self::mesh($n);
        $n['automaticSetup']=self::setup($n['automaticSetup']??[]);
        if(isset($n['overview']))$n['overviewDisplay']=self::overview($n,$frontendPath);
        return $n;
    }
    private static function overview(array $n,string $path):array {
        $o=$n['overview'];$peers=array_values(array_filter($n['peers']??[],static fn($p)=>$p['state']!=='REVOKED'));$active=array_filter($peers,static fn($p)=>($p['active']??false)&&$p['state']==='ACTIVE');$pending=count($peers)-count($active);
        $blocked=count(array_filter($peers,static fn($p)=>$p['display']['blocked']));$expired=count(array_filter($peers,static fn($p)=>$p['display']['expired']));$ready=count(array_filter($active,static fn($p)=>isset($p['health'])?$p['health']['synchronization']==='verified':$p['display']['sharing']['ready']));$unready=count($active)-$ready;$conflicts=$n['globalConflictCount']??count($n['sharedGlobal']['conflicts']??[]);
        $connectionDetail=[$ready.' synchronized'];if($unready)$connectionDetail[]=$unready.' awaiting data or delivery';if($pending)$connectionDetail[]=$pending.' awaiting approval';if($blocked)$connectionDetail[]=$blocked.' delivery blocked';if($expired)$connectionDetail[]=$expired.' expired';
        $p=$n['backupOrigin']??[];$magicActive=($p['status']??'')==='active';$magicMissing=$magicActive&&($o['magicCredentials']??null)===0;$c=$n['connectDiscovery']??null;
        $relayProblem=$magicActive&&preg_match('~^https://[a-z0-9]{32}\.ipmagic\.de$~D',$p['origin'])&&$c!==null&&(($c['available']??false)!==true||($c['origin']??null)!==$p['origin']);
        $routePending=$magicActive&&($p['version']??0)===2?count(array_filter($active,static fn($peer)=>($peer['routeReceipt']??null)!==($n['routeRevision']??'0'))):0;
        $magic=$relayProblem?(!empty($c['available'])?'Address changed':'Connect unavailable'):($magicMissing?'No usable passkey':($magicActive?(($p['version']??0)===2?'Full access active':'Limited access active'):(['pending'=>'Setup incomplete','revoked'=>'Removed'][$p['status']??'']??'Not configured')));
        $magicDetail=$relayProblem?'Access is configured, but the local Connect service does not report this address as active. Check Symcon Connect and review the address in Key enrollment.':($magicMissing?'Enroll and test an eligible Magic passkey in Key enrollment.':($magicActive?((($p['version']??0)===2?'Same vault and administration functions.':'Approve full Magic access in Key enrollment or the Symcon console.').($active&&($p['version']??0)===2?' Address delivery: '.(count($active)-$routePending).' of '.count($active).' platforms.':'')):(($p['status']??'')==='pending'?'Finish the numbered setup in Key enrollment.':'Set up a second HTTPS address in Key enrollment.')));
        $storage=$o['storage']??$n['info']??[];$percent=($storage['capacityBytes']??0)>0?(int)ceil($storage['usedBytes']/$storage['capacityBytes']*100):null;
        $healthProblems=count(array_filter($active,static fn($p)=>$p['display']['healthProblem']));$m=$n['monitoring']??[];$issues=[];$waiting=[];
        foreach([[$m['problems']??0,($m['problems']??0).' mesh health issue(s)'],[$m['fallbacks']??0,($m['fallbacks']??0).' installation(s) using emergency fallback'],[$healthProblems,$healthProblems.' platform(s) need synchronization attention — see Connection status below'],[$blocked,'delivery blocked'],[$expired,'expired connection approval'],[$conflicts,'secret conflicts'],[$relayProblem,'Magic connection unavailable'],[$magicMissing,'Magic passkey unavailable'],[$percent!==null&&$percent>=75,'storage nearing capacity'],[($n['globalWritable']??true)===false,'Global changes paused'],[$o['providerIssues']??0,'OAuth providers need review'],[$active&&($n['remoteHttpsAvailable']??true)===false,'connection transport unavailable']]as[$condition,$text])if($condition)$issues[]=$text;
        $setup=$n['automaticSetup']??[];$complete=!empty($setup['completedAt'])&&empty($setup['running']);
        if(!empty($setup['running']))$waiting[]='Mesh setup is running';elseif(!empty($setup['policy'])&&!$complete)$waiting[]='Mesh setup is incomplete — see Mailbox';
        foreach([[$pending,$pending.' connection(s) awaiting approval'],[$unready,$unready.' connection(s) awaiting synchronization verification — see Connection status below'],[($p['status']??'')==='pending','Magic backup access setup is incomplete'],[$routePending,'Backup address delivery pending on '.$routePending.' platform(s)'],[$o['pendingEffects']??0,($o['pendingEffects']??0).' OAuth operation(s) in progress']]as[$condition,$text])if($condition)$waiting[]=$text;
        $parts=[];if($issues)$parts[]='Needs attention · '.implode(' · ',$issues).'.';if($waiting)$parts[]=implode(' · ',$waiting).'.';if(!empty($m['pending']))$parts[]=$m['pending'].' mesh check(s) unknown or stale — select a node or connection in Mesh health for details.';
        return ['evaluatedAt'=>$n['serverTime']??time(),'readiness'=>($complete?'Mesh setup completed. ':'').($parts?implode(' ',$parts):'Vault ready.'),'success'=>!$issues&&!$waiting&&empty($m['pending']),'peerIds'=>array_column($peers,'id'),
            'fields'=>['globalCount'=>$o['globalValues']??0,'localCount'=>$o['localValues']??0,'overviewConnections'=>count($active),'overviewConnectionDetail'=>$peers?implode(' · ',$connectionDetail):'Standalone · no connected platforms.',
            'overviewMagic'=>$magic,'overviewMagicDetail'=>$magicDetail,'overviewMagicURL'=>$magicActive?$p['origin'].$path:'','overviewConflicts'=>$conflicts,'overviewConflictDetail'=>$conflicts?'Resolve these secrets in Conflicts. Other secrets remain available.':'No unresolved conflicts.',
            'overviewStorage'=>$percent===null?'Unavailable':$percent.'% used','overviewStorageDetail'=>$percent===null?'Refresh to check storage.':ceil($storage['usedBytes']/1024).' of '.floor($storage['capacityBytes']/1024).' KiB'.($percent>=75?' · Export and verify an encrypted backup, then review storage.':'.'),
            'overviewAccess'=>($o['credentials']??0).' tested passkey(s) · '.($o['hardwareCredentials']??0).' hardware · '.($o['machines']??0).' automation grant(s) · '.($o['providers']??0).' OAuth provider(s).',
            'overviewEffects'=>!empty($o['providerIssues'])?$o['providerIssues'].' OAuth provider(s) need review in OAuth providers.':(!empty($o['pendingEffects'])?$o['pendingEffects'].' OAuth operation(s) in progress.':'')]];
    }
}
