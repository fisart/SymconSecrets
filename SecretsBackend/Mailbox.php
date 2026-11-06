<?php
declare(strict_types=1);

/** Read-only workflow projection. No challenges, packages, tokens or secret paths. */
final class SecretsBackendMailbox
{
    public const LIMIT=32;
    public const STATES=['APPROVAL_REQUIRED','WAITING_REMOTE','SENDING','CONFIRMATION_PENDING','COMPLETED','EXPIRED','REVOKED','UNKNOWN'];
    public static function local(array $s,bool $bounded=true,bool $backupReady=false):array {
        $rows=[];$local=$s['native']['vaultId'];
        $add=static function(string $id,string $type,string $state,?string $peer,string $direction,string $action,?int $expires=null)use(&$rows):void{
            $rows[]=['id'=>$id,'type'=>$type,'state'=>$state,'peerId'=>$peer,'direction'=>$direction,'action'=>$action,'requestedAt'=>null,'expiresAt'=>$expires];
        };
        $queued=static function(string $kind,string $peer,?string $grant=null)use($s):bool{foreach($s['outbox']['jobs']as$j)if($j['kind']===$kind&&$j['receiverId']===$peer&&($grant===null||($j['payload']['grantId']??null)===$grant))return true;return false;};
        foreach($s['pairing']['peers']as$p){
            $state=match($p['state']){'PENDING_APPROVAL'=>'APPROVAL_REQUIRED','PENDING_REMOTE'=>$queued('PAIR_REQUEST',$p['id'])?'SENDING':'WAITING_REMOTE','REVOKED'=>'REVOKED',default=>$queued('PAIR_ACCEPT',$p['id'])?'CONFIRMATION_PENDING':'COMPLETED'};
            $expires=isset($p['expires'])?(int)$p['expires']:null;if($expires!==null&&$expires<time()&&$state==='APPROVAL_REQUIRED')$state='EXPIRED';
            $add('pair:'.$p['pairingId'],'pairing',$state,$p['id'],'connection','nativePeers',$expires);
        }
        foreach($s['native']['emergencyGrants']??[]as$g){
            $p=$s['pairing']['peers'][$g['source']]??null;$active=$g['active']&&($p['active']??false)&&($p['pairingId']??null)===$g['pairingId'];
            $add('grant:'.$g['id'],'emergency',$active?($queued('EMERGENCY_OFFER',$g['source'],$g['id'])?'SENDING':'WAITING_REMOTE'):'REVOKED',$g['source'],'provider','nativePeers');
        }
        foreach($s['native']['emergencyOffers']??[]as$id=>$o){
            // Parse only the identifier; the signed package never leaves this projection.
            $g=json_decode($o['package'],true);$grant=$g['id']??null;if(!is_string($grant))continue;
            $p=$s['pairing']['peers'][$id]??null;
            $add('grant:'.$grant,'emergency',($p['active']??false)&&($p['pairingId']??null)===($g['pairingId']??null)?'APPROVAL_REQUIRED':'REVOKED',$id,'consumer','nativePeers');
        }
        foreach($s['native']['emergencyClients']??[]as$id=>$c){
            $p=$s['pairing']['peers'][$id]??null;
            $add('grant:'.$c['grantId'],'emergency',($p['active']??false)&&($p['pairingId']??null)===$c['pairingId']?'CONFIRMATION_PENDING':'REVOKED',$id,'consumer','nativePeers');
        }
        foreach($s['native']['transfers']??[]as$id=>$t)$add('transfer:'.$id,'ownership',match($t['state']){'PENDING_APPROVAL'=>'APPROVAL_REQUIRED','ACCEPTED','TRANSFERRED'=>'COMPLETED',default=>$queued('OWNER_OFFER',$t['peerId']??'')?'SENDING':'WAITING_REMOTE'},$t['peerId']??null,$t['direction']==='incoming'?'consumer':'provider','nativePeers');
        $p=$s['policy']['backupOrigin']??null;if(is_array($p))$add('magic:'.$local,'backup-access',match($p['status']){'pending'=>$backupReady?'APPROVAL_REQUIRED':'CONFIRMATION_PENDING','active'=>'COMPLETED',default=>'REVOKED'},null,'local','nativeKeys');
        foreach($s['native']['effects']??[]as$e)if(in_array($e['state'],['PREPARED','SENT_UNKNOWN','RETRY_SAFE','QUARANTINED'],true))$add('effect:'.$e['id'],'provider-operation',$e['state']==='SENT_UNKNOWN'?'UNKNOWN':($e['state']==='QUARANTINED'?'APPROVAL_REQUIRED':'SENDING'),null,'local','nativeProviders');
        // Consumer acceptance supersedes an older offer for the same grant.
        $unique=[];foreach($rows as$r)$unique[$r['id'].':'.$r['direction']]=$r;$rows=array_values($unique);
        usort($rows,static fn($a,$b)=>(in_array($a['state'],['COMPLETED','REVOKED','EXPIRED'],true)<=>in_array($b['state'],['COMPLETED','REVOKED','EXPIRED'],true))?:strcmp($a['id'],$b['id']));
        return ['rows'=>$bounded?array_slice($rows,0,self::LIMIT):$rows,'partial'=>$bounded&&count($rows)>self::LIMIT];
    }
    public static function validate(array $m):void {
        SecretsBackendNativePeer::exact($m,['rows','partial']);if(!is_bool($m['partial'])||!is_array($m['rows'])||!array_is_list($m['rows'])||count($m['rows'])>self::LIMIT)throw new RuntimeException('Invalid mailbox summary.');
        foreach($m['rows']as$r){SecretsBackendNativePeer::exact($r,['id','type','state','peerId','direction','action','requestedAt','expiresAt']);
            if(!is_string($r['id'])||!preg_match('/^(?:(pair|grant|transfer|magic):[a-f0-9-]{36}|effect:[a-f0-9]{64})$/D',$r['id'])||!in_array($r['type'],['pairing','emergency','ownership','backup-access','provider-operation'],true)||!in_array($r['state'],self::STATES,true)||!in_array($r['direction'],['connection','provider','consumer','local'],true)||!in_array($r['action'],['nativePeers','nativeKeys','nativeProviders'],true))throw new RuntimeException('Invalid mailbox entry.');
            if($r['peerId']!==null)SecretsBackendNativePeer::uuid($r['peerId']);foreach(['requestedAt','expiresAt']as$k)if($r[$k]!==null&&(!is_int($r[$k])||$r[$k]<0))throw new RuntimeException('Invalid mailbox time.');
        }
    }
    public static function view(array $s,array $mesh,bool $backupReady=false):array {
        $nodes=[];$now=time();$local=$s['native']['vaultId'];$reports=[];
        foreach($mesh['reports']??[]as$entry)$reports[$entry['report']['id']]=$entry;
        foreach([$local,...array_keys($s['pairing']['peers'])]as$id){
            $own=$id===$local;$entry=$reports[$id]??null;$r=$entry['report']??[];$age=$entry['age']??null;$fresh=$own||($age!==null&&$age<($r['ttl']??0));$m=$own?self::local($s,false,$backupReady):($r['mailbox']??null);
            $rows=$m['rows']??[];
            foreach($rows as&$row){
                if(!$fresh){$row['lastKnownState']=$row['state'];$row['state']='UNKNOWN';continue;}
                if($row['type']!=='emergency'||!in_array($row['state'],['WAITING_REMOTE','CONFIRMATION_PENDING'],true))continue;
                $other=$reports[$row['peerId']]??null;$otherReport=$other['report']??[];$otherFresh=($other['age']??null)!==null&&$other['age']<($otherReport['ttl']??0);$link=null;
                foreach($otherReport['links']??[]as$l)if($l['id']===$id){$link=$l;break;}
                $grant=substr($row['id'],6);
                if($otherFresh&&$link&&($row['direction']==='provider'?($link['clientGrant']??null)===$grant:in_array($grant,$link['grantIds']??[],true)))$row['state']='COMPLETED';
                elseif(!$otherFresh){$row['lastKnownState']=$row['state'];$row['state']='UNKNOWN';}
            }unset($row);
            $nodes[]=['id'=>$id,'name'=>$own?SecretsBackendPeerName::address($s['policy']['origin']):SecretsBackendPeerName::display($s['pairing']['peers'][$id]),'local'=>$own,'fresh'=>$fresh,'available'=>$m!==null,'checkedAt'=>$own?$now:($age!==null?$now-$age:null),'partial'=>$m['partial']??false,'rows'=>$rows];
        }
        return ['nodes'=>$nodes,'observedAt'=>$now];
    }
}
