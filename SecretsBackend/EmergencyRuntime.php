<?php
declare(strict_types=1);
require_once __DIR__.'/EmergencyClient.php';

trait SecretsBackendEmergencyRuntime
{
    private function emergencyCapsule(): SecretsBackendEmergencyCapsule {
        return new SecretsBackendEmergencyCapsule(rtrim(IPS_GetKernelDir(),'/\\').'/secrets-native-emergency/'.$this->InstanceID);
    }
    private function emergencyBinding(): string {
        return hash('sha256',SecretsBackendNativeStore::canonical([$this->InstanceID,$this->ReadAttributeString('NativeVaultUUID'),$this->configuration(),$this->frontendSecurity()]));
    }
    private function syncEmergencyAccess(bool $approvedCreate=false): bool {
        $store=$this->nativeStore();$capsule=$this->emergencyCapsule();$binding=$this->emergencyBinding();
        return $store->withActiveSnapshot(function(array $current)use($capsule,$binding,$approvedCreate):bool{
            $s=$current['state'];$clients=SecretsBackendEmergency::clients($s);
            if(!$clients&&!$capsule->exists())return true;
            if(!isset($s['native']['sharedGlobal'])){$capsule->invalidate();return true;}
            $p=SecretsBackendLegacyAPI::access($s,$this->InstanceID,$this->InstanceID);
            $allowed=is_array($p)&&($p['enabled']??false)&&($p['read']??false)&&($p['treeId']??'')===$s['native']['globalTreeId'];
            return $capsule->synchronize($s,$binding,$clients,$allowed,SecretsBackendNativeHealth::stamp($s),$approvedCreate);
        });
    }
    private function emergencyStatus(array $s): void {
        $s+=['mode'=>'UNAVAILABLE','ready'=>false,'activeSource'=>'','reason'=>'','checkedAt'=>time(),'freshnessUncertain'=>false];
        $this->SetBuffer('EmergencyStatus',SecretsBackendCodec::json($s));
        $this->SetValue('EmergencyStatus',SecretsBackendCodec::json($s));
        $this->SetValue('FallbackActive',$s['mode']==='REMOTE'&&$s['ready']);
        $this->SetValue('SecretsUnavailable',!$s['ready']);
        $this->SetValue('SynchronizationProblem',($s['synchronizationProblem']??false)||$s['freshnessUncertain']||in_array($s['reason'],['KNOWN_OLDER_OR_CONCURRENT','INCONSISTENT_HISTORY'],true));
        $this->SetValue('ActiveSource',$s['activeSource']);
    }
    public function GetEmergencyStatus(): string {
        $s=json_decode($this->GetBuffer('EmergencyStatus'),true)?:['mode'=>'UNKNOWN','ready'=>false,'checkedAt'=>0];
        $age=time()-(int)$s['checkedAt'];$s['stale']=$age<0||$age>90||$s['checkedAt']===0;if($s['stale'])$s['ready']=false;
        return SecretsBackendCodec::json($s);
    }
    /** Local console can always stop emergency access; re-enabling requires reviewed import. */
    public function StopEmergencyAccess(): void {
        $this->emergencyCapsule()->invalidate(true);$this->SetBuffer('EmergencyLocalHealthyCount','0');
        $this->emergencyStatus(['reason'=>'MANUALLY_STOPPED']);
    }
    private function emergencyLocalGate(SecretsBackendNativeStore $store): void {
        $capsule=$this->emergencyCapsule();if(!$capsule->exists())return;
        try{$floor=$capsule->checkpoint($store->identity()['deploymentId']);}catch(Throwable $e){return;}
        $stamp=SecretsBackendNativeHealth::stamp($store->read()['state']);
        $relation=SecretsBackendEmergency::compare($stamp['clock'],$floor['clock']);
        if(!in_array($relation,[0,1],true)||($relation===0&&$floor['digest']!==null&&!hash_equals($floor['digest'],$stamp['digest'])))throw new SecretsBackendEmergencyNeeded('Local Global state is behind the emergency checkpoint.');
        try{$access=$capsule->load($this->emergencyBinding());}catch(Throwable $e){return;}
        $status=json_decode($this->GetBuffer('EmergencyStatus'),true)?:[];
        if(($status['mode']??'')==='REMOTE'&&(int)$this->GetBuffer('EmergencyLocalHealthyCount')<2)throw new SecretsBackendEmergencyNeeded('Local recovery confirmation pending.');
        // Checkpoint observation contains no credentials or values and never lowers known history.
        $capsule->observe($this->emergencyBinding(),$access['authorization'],$stamp);
    }
    protected function emergencyHTTPS(string $url,string $bytes,array $policy,float $timeout): string { return SecretsBackendNativeLegacyHTTPS::post($url,$bytes,$policy,$timeout); }
    private function emergencyRead(string $method,array $args,?string $expectedVault=null,bool $probeOnly=false) {
        if(!$this->ReadPropertyBoolean('Enabled')||IPS_HasChanges($this->InstanceID)||IPS_GetKernelRunlevel()!==10103)throw new SecretsBackendEmergencyRefused('BACKEND_DISABLED_OR_PENDING');
        $lock='SECB.EmergencyRead.'.$this->InstanceID;
        if(!IPS_SemaphoreEnter($lock,1000))throw new SecretsBackendEmergencyRefused('BUSY');
        $backoff=json_decode($this->GetBuffer('EmergencyBackoff'),true)?:[];$client=null;
        try{
            $client=new SecretsBackendEmergencyClient($this->emergencyCapsule(),$this->emergencyBinding(),fn($url,$bytes,$policy,$timeout)=>$this->emergencyHTTPS($url,$bytes,$policy,$timeout),$backoff);
            $r=$client->read($method,$args,$expectedVault,$probeOnly);
            $this->emergencyStatus(['mode'=>'REMOTE','ready'=>true,'activeSource'=>$r['name'].' ('.$r['source'].')','sourceVault'=>$r['source'],'freshnessUncertain'=>true,'unreachableOrUnprobed'=>$r['unreachableOrUnprobed']]);
            return $r['value'];
        }catch(Throwable $e){
            $reason=$e instanceof SecretsBackendEmergencyRefused?$e->reason:'EMERGENCY_UNAVAILABLE';
            $this->emergencyStatus(['reason'=>$reason]);throw new SecretsBackendEmergencyRefused($reason);
        }finally{if($client!==null)$this->SetBuffer('EmergencyBackoff',SecretsBackendCodec::json($client->backoff()));IPS_SemaphoreLeave($lock);}
    }
    private function emergencyMeshProblem(): bool {
        $store=$this->nativeStore();$s=$store->read()['state'];
        if(!isset($s['native']['sharedGlobal']))return false;
        if(SecretsBackendNativeHealth::stamp($s)['conflicts']>0)return true;
        foreach((new SecretsBackendNativeHealth($store,$this->nativePeer($store)))->statuses($s)as$h)if($h['synchronization']!=='verified'||$h['connection']!=='reachable')return true;
        return false;
    }
    /** Runs from the existing watchdog; normal local operation makes no network calls here. */
    private function observeEmergencyAvailability(bool $localReady): void {
        $current=null;
        try{
            if($localReady){
                try{$current=$this->syncEmergencyAccess();}catch(SecretsBackendEmergencyRefused $e){$current=false;}
                $s=json_decode($this->GetBuffer('EmergencyStatus'),true)?:[];
                if($current){
                    $count=min(2,(int)$this->GetBuffer('EmergencyLocalHealthyCount')+1);$this->SetBuffer('EmergencyLocalHealthyCount',(string)$count);
                    if(($s['mode']??'')!=='REMOTE'||$count>=2){$this->emergencyStatus(['mode'=>'LOCAL','ready'=>true,'activeSource'=>'Local vault','synchronizationProblem'=>$this->emergencyMeshProblem()]);return;}
                }else $this->SetBuffer('EmergencyLocalHealthyCount','0');
            }else $this->SetBuffer('EmergencyLocalHealthyCount','0');
            if(!$this->emergencyCapsule()->exists()){$this->emergencyStatus(['reason'=>'NO_EMERGENCY_ACCESS']);return;}
            $this->emergencyRead('GetKeys',[],null,true);
        }catch(Throwable $e){
            if($localReady&&$current!==false){
                // Credential-copy errors do not shut down a functioning standalone/local vault.
                $this->emergencyStatus(['mode'=>'LOCAL','ready'=>true,'activeSource'=>'Local vault','reason'=>'EMERGENCY_ACCESS_NEEDS_REVIEW','synchronizationProblem'=>true]);
            }else $this->emergencyStatus(['reason'=>$e instanceof SecretsBackendEmergencyRefused?$e->reason:'EMERGENCY_UNAVAILABLE']);
        }
    }
}
