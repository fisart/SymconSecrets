<?php
declare(strict_types=1);

/** Reachable-owner transfer: freeze -> explicitly accept -> scoped signed ownership chain. */
trait SecretsBackendNativeTransfer
{
    public static function authority(array $descriptor): string { unset($descriptor['treeId'],$descriptor['endpoint']);return self::digest($descriptor); }
    public function ownerOffer(array $state,string $treeId,string $targetId): array
    {
        $target=$state['pairing']['peers'][$targetId]??null;if(!is_array($target)||!$target['active'])throw new RuntimeException('Pair the intended new owner before transferring a tree.');
        $local=$this->descriptor();$isGlobal=$treeId===$state['native']['globalTreeId'];
        if($isGlobal)foreach($state['native']['effects']as$effect){
            $provider=$state['native']['providers'][$effect['providerId']]??null;
            if(is_array($provider)&&in_array('global',[$provider['resultScope'],$provider['refreshScope']],true)&&in_array($effect['state'],['PREPARED','SENT_UNKNOWN','RETRY_SAFE','QUARANTINED'],true))throw new RuntimeException('Resolve outstanding global provider effects before transferring ownership.');
        }
        $owned=$isGlobal?['node'=>$state['vault']['global'],'revision'=>$state['stream']['globalRevision'],'epoch'=>$state['native']['ownershipEpoch'],'frozen'=>!$state['native']['globalWritable']]:($state['native']['trees'][$treeId]??null);
        if(!is_array($owned)||$owned['frozen'])throw new RuntimeException('This vault cannot transfer a frozen or non-owned tree.');
        $recipients=[];
        if($isGlobal){foreach($state['pairing']['peers']as$p)if($p['active']&&$p['id']!==$targetId)$recipients[]=['recipient'=>$p['descriptor'],'sourcePairingId'=>$p['pairingId'],'subscriptionId'=>SecretsBackendCodec::uuid()];}
        else{foreach($owned['subscribers']as$p)if($p['descriptor']['vaultId']!==$targetId)$recipients[]=['recipient'=>$p['descriptor'],'sourcePairingId'=>$p['subscriptionId'],'subscriptionId'=>SecretsBackendCodec::uuid()];}
        $recipients[]=['recipient'=>$local,'sourcePairingId'=>$target['pairingId'],'subscriptionId'=>SecretsBackendCodec::uuid()];
        $cert=['format'=>'SECB.OwnerTransfer.1','id'=>SecretsBackendCodec::uuid(),'treeId'=>$treeId,'oldOwner'=>$local,'newOwner'=>$target['descriptor'],'oldEpoch'=>$owned['epoch'],
            'newEpoch'=>SecretsBackendCodec::increment($owned['epoch']),'revision'=>$owned['revision'],'nodeDigest'=>self::digest($owned['node']),'recipients'=>$recipients];
        return ['kind'=>'nativeTransferOffer','peerId'=>$targetId,'treeId'=>$treeId,'certificate'=>$this->signed($cert),'node'=>$owned['node']];
    }
    public function acceptance(array $certificate): array
    {
        return $this->signed(['format'=>'SECB.OwnerAcceptance.1','transferId'=>$certificate['id'],'certificateDigest'=>self::digest($certificate),'newOwner'=>$this->descriptor()['vaultId']]);
    }
    private static function certificate(array $cert): void
    {
        self::exact($cert,['format','id','treeId','oldOwner','newOwner','oldEpoch','newEpoch','revision','nodeDigest','recipients','signature']);
        if($cert['format']!=='SECB.OwnerTransfer.1')throw new RuntimeException('Invalid ownership certificate purpose.');
        foreach(['id','treeId']as$k)self::uuid($cert[$k]);self::descriptorCheck($cert['oldOwner']);self::descriptorCheck($cert['newOwner']);
        foreach(['oldEpoch','newEpoch','revision']as$k)self::decimal($cert[$k]);
        if($cert['newEpoch']!==SecretsBackendCodec::increment($cert['oldEpoch'])||$cert['oldOwner']['vaultId']===$cert['newOwner']['vaultId']||!is_array($cert['recipients'])||count($cert['recipients'])>33)throw new RuntimeException('Invalid ownership epoch or recipient set.');
        $seen=[];foreach($cert['recipients']as$r){self::exact($r,['recipient','sourcePairingId','subscriptionId']);self::descriptorCheck($r['recipient']);self::uuid($r['sourcePairingId']);self::uuid($r['subscriptionId']);if(isset($seen[$r['recipient']['vaultId']]))throw new RuntimeException('Duplicate transfer recipient.');$seen[$r['recipient']['vaultId']]=true;}
        self::verify($cert,$cert['oldOwner']['signKey']);
    }
    private function receiveOwnerOffer(array $m,array $payload,array $peer,array $current,string $digest): string
    {
        self::exact($payload,['certificate','node']);$cert=$payload['certificate'];self::certificate($cert);
        if(self::authority($cert['oldOwner'])!==self::authority($peer['descriptor'])||self::authority($cert['newOwner'])!==self::authority($this->descriptor())||self::digest($payload['node'])!==$cert['nodeDigest'])throw new RuntimeException('Owner offer was swapped or misaddressed.');
        $existing=$current['state']['native']['transfers'][$cert['id']]??null;
        if($existing!==null){if(self::digest($existing['certificate'])!==self::digest($cert))throw new RuntimeException('Conflicting owner transfer.');}
        else $this->store->change($current['head'],$m['id'],$digest,static function($s)use($cert,$payload,$m){$s['native']['transfers'][$cert['id']]=['direction'=>'incoming','state'=>'PENDING_APPROVAL','certificate'=>$cert,'node'=>$payload['node'],'peerId'=>$m['sender']];return $s;},['action'=>'owner-offer','actor'=>$m['sender'],'target'=>$cert['treeId']]);
        return $this->reply($m,$peer['descriptor'],$digest,['status'=>'OFFER_RECEIVED','transferId'=>$cert['id']]);
    }
    public static function queueOwned(array $state,string $treeId): array
    {
        $tree=$state['native']['trees'][$treeId]??null;if(!is_array($tree)||$tree['frozen']||$tree['owner']!==$state['native']['vaultId'])throw new RuntimeException('Only the current unfrozen owner can publish this tree.');
        foreach($tree['subscribers']as$id=>$recipient){
            if(count($state['outbox']['jobs'])>=128)throw new RuntimeException('Owner outbox is full.');
            $seq=SecretsBackendCodec::increment($recipient['sequence']);$nodeDigest=self::digest($tree['node']);
            $payload=['certificate'=>$tree['certificate'],'acceptance'=>$tree['acceptance'],'tree'=>['treeId'=>$treeId,'owner'=>$tree['owner'],'ownershipEpoch'=>$tree['epoch'],'revision'=>$tree['revision'],
                'previousDigest'=>$recipient['nodeDigest'],'nodeDigest'=>$nodeDigest,'node'=>$tree['node']]];
            $peer=['id'=>$id,'pairingId'=>$recipient['subscriptionId'],'epoch'=>$tree['epoch']];
            $job=self::job($peer,'TREE_SYNC',$payload,$seq);$job['targetDescriptor']=$recipient['descriptor'];$job['treeId']=$treeId;$state['outbox']['jobs'][]=$job;
            $state['native']['trees'][$treeId]['subscribers'][$id]['sequence']=$seq;$state['native']['trees'][$treeId]['subscribers'][$id]['nodeDigest']=$nodeDigest;
        }return $state;
    }
    private function receiveOwnedTree(array $m): string
    {
        $current=$this->store->read();$payload=SecretsFrontendConfiguration::decodeBounded($this->store->openPeer($m['payload']),$this->store->metadata()['capacityBytes'],96);
        self::exact($payload,['certificate','acceptance','tree']);$cert=$payload['certificate'];self::certificate($cert);$accept=$payload['acceptance'];
        self::exact($accept,['format','transferId','certificateDigest','newOwner','signature']);
        if($accept['format']!=='SECB.OwnerAcceptance.1'||$accept['transferId']!==$cert['id']||$accept['certificateDigest']!==self::digest($cert)||$accept['newOwner']!==$cert['newOwner']['vaultId'])throw new RuntimeException('Missing exact new-owner acceptance.');
        self::verify($accept,$cert['newOwner']['signKey']);self::verify($m,$cert['newOwner']['signKey']);
        $local=$this->descriptor();$grant=null;foreach($cert['recipients']as$r)if(self::authority($r['recipient'])===self::authority($local))$grant=$r;
        if($grant===null||$m['sender']!==$cert['newOwner']['vaultId']||$m['pairingId']!==$grant['subscriptionId']||$m['epoch']!==$cert['newEpoch'])throw new RuntimeException('Owner certificate does not authorize this destination.');
        $tree=$payload['tree'];self::exact($tree,['treeId','owner','ownershipEpoch','revision','previousDigest','nodeDigest','node']);self::decimal($tree['revision']);
        if($tree['treeId']!==$cert['treeId']||$tree['owner']!==$m['sender']||$tree['ownershipEpoch']!==$cert['newEpoch']||($tree['node']['type']??'')!=='object'||self::digest($tree['node'])!==$tree['nodeDigest']
            ||self::digest(SecretsBackendTree::parseBounded(SecretsBackendCodec::json(SecretsBackendTree::value($tree['node'])),$this->store->metadata()['capacityBytes']))!==$tree['nodeDigest'])throw new RuntimeException('Invalid owned-tree payload.');
        $sub=$current['state']['native']['subscriptions'][$cert['treeId']]??null;$old=$current['state']['native']['received'][$cert['treeId']]??null;
        if($sub!==null&&!$sub['active'])throw new RuntimeException('This shared-tree subscription was explicitly revoked.');
        $already=$sub!==null&&$sub['epoch']===$cert['newEpoch']&&$sub['certificateDigest']===self::digest($cert);
        if(!$already){
            $authorized=false;
            if($sub!==null&&$sub['epoch']===$cert['oldEpoch']&&self::authority($sub['ownerDescriptor'])===self::authority($cert['oldOwner'])&&$sub['subscriptionId']===$grant['sourcePairingId'])$authorized=true;
            $p=$current['state']['pairing']['peers'][$cert['oldOwner']['vaultId']]??null;
            if($sub===null&&is_array($p)&&$p['active']&&$p['pairingId']===$grant['sourcePairingId']&&$p['descriptor']['treeId']===$cert['treeId']&&self::authority($p['descriptor'])===self::authority($cert['oldOwner'])&&$cert['oldEpoch']==='1')$authorized=true;
            $own=$current['state']['native']['transfers'][$cert['id']]??null;
            if($cert['oldOwner']['vaultId']===$local['vaultId']&&is_array($own)&&$own['direction']==='outgoing'&&$own['state']==='FROZEN'&&self::digest($own['certificate'])===self::digest($cert))$authorized=true;
            if(!$authorized)throw new RuntimeException('The previous owner did not have authority over this received tree.');
            $knownRevision=$old['revision']??($cert['treeId']===$current['state']['native']['globalTreeId']?$current['state']['stream']['globalRevision']:'0');
            if(self::compare($knownRevision,$cert['revision'])>0||self::compare($tree['revision'],$cert['revision'])<0||($tree['revision']===$cert['revision']&&$tree['nodeDigest']!==$cert['nodeDigest']))throw new RuntimeException('Stale owner-transfer snapshot.');
        }
        $digest=self::logical($m,$payload);
        if($already&&$old!==null&&$m['sequence']===$old['sequence']){if(($old['requestDigest']??'')!==$digest||$old['requestId']!==$m['id'])throw new RuntimeException('Conflicting owner delivery.');return $this->reply($m,$cert['newOwner'],$digest,$old['receipt']);}
        if($already&&($old===null||$m['sequence']!==SecretsBackendCodec::increment($old['sequence'])||$tree['previousDigest']!==$old['nodeDigest']||self::compare($tree['revision'],$old['revision'])<0||($tree['revision']===$old['revision']&&$tree['nodeDigest']!==$old['nodeDigest'])))throw new RuntimeException('Owned-tree delivery is stale, divergent or out of order.');
        $receipt=['status'=>'TREE_APPLIED','treeId'=>$cert['treeId'],'revision'=>$tree['revision'],'sequence'=>$m['sequence'],'nodeDigest'=>$tree['nodeDigest']];
        $this->store->change($current['head'],$m['id'],$digest,static function($s)use($m,$cert,$grant,$tree,$digest,$receipt){
            $s['native']['subscriptions'][$cert['treeId']]=['ownerDescriptor'=>$cert['newOwner'],'epoch'=>$cert['newEpoch'],'subscriptionId'=>$grant['subscriptionId'],'certificateDigest'=>self::digest($cert),'active'=>true];
            $s['native']['received'][$cert['treeId']]=['owner'=>$m['sender'],'epoch'=>$cert['newEpoch'],'revision'=>$tree['revision'],'sequence'=>$m['sequence'],'nodeDigest'=>$tree['nodeDigest'],'node'=>$tree['node'],
                'pairingId'=>$m['pairingId'],'requestId'=>$m['id'],'requestDigest'=>$digest,'receipt'=>$receipt,'at'=>gmdate('c')];
            if($cert['treeId']===$s['native']['globalTreeId']){$s['vault']['global']=$tree['node'];$s['vault']['revision']=SecretsBackendCodec::increment($s['vault']['revision']);$s['stream']['globalRevision']=$tree['revision'];$s['native']['globalWritable']=false;$s['native']['ownershipEpoch']=$cert['newEpoch'];}
            if(isset($s['native']['transfers'][$cert['id']]))$s['native']['transfers'][$cert['id']]['state']='TRANSFERRED';return $s;
        },['action'=>'owner-publish','actor'=>$m['sender'],'target'=>$cert['treeId']]);return $this->reply($m,$cert['newOwner'],$digest,$receipt);
    }
}
