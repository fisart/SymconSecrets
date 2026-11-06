<?php
declare(strict_types=1);

/** Delegate to the existing opt-in, private-repository, allowlisted uploader. */
final class SecretsBackendSupportReport
{
    private const MODULE='{0E51F4D8-5A8C-46B3-8F77-610C3F9493AC}';
    public static function discovery():array {
        if(!function_exists('IPS_GetInstanceListByModuleID'))return ['code'=>'DISCOVERY_UNAVAILABLE','targets'=>[]];
        try{$ids=IPS_GetInstanceListByModuleID(self::MODULE);if(!is_array($ids))throw new RuntimeException();}
        catch(Throwable $ignored){return ['code'=>'INSTANCE_LOOKUP_FAILED','targets'=>[]];}
        $out=[];$api=function_exists('MCB_UploadSecretsDiagnostics');
        foreach(array_slice($ids,0,32)as$id){
            $row=['id'=>$id,'name'=>'Configuration Backup '.$id,'repository'=>'','branch'=>'','enabled'=>false,'code'=>'CONFIGURATION_UNREADABLE'];
            try{$row['name']=IPS_GetName($id);}catch(Throwable $ignored){}
            try{
                $c=json_decode(IPS_GetConfiguration($id),true,32,JSON_THROW_ON_ERROR);if(!is_array($c))throw new RuntimeException();
                $row['repository']=(string)($c['GitHubOwner']??'').'/'.(string)($c['GitHubRepository']??'');$row['branch']=(string)($c['GitHubBranch']??'');
                $row['code']=!$api?'UPDATE_BACKUP_REQUIRED':(IPS_HasChanges($id)?'SETTINGS_NOT_APPLIED':(($c['ReadableSecretsDiagnostics']??false)!==true?'DIAGNOSTICS_DISABLED':'READY'));
                $row['enabled']=$row['code']==='READY';
            }catch(Throwable $ignored){}
            $out[]=$row;
        }
        return ['code'=>$out?'INSTANCES_FOUND':'NO_INSTANCE_ON_THIS_SERVER','targets'=>$out];
    }
    public static function targets():array { return self::discovery()['targets']; }
    public static function upload(int $id=0):array {
        try{
            // Resolve only when the user actually sends. The uploader owns all configuration checks.
            $ids=IPS_GetInstanceListByModuleID(self::MODULE);
            if($id===0){if(count($ids)!==1)return ['ok'=>false,'error'=>count($ids)?'Upload not started: multiple Configuration Backup instances exist on this server. Select one in its own HTML page.':'Upload not started: no Configuration Backup instance exists on this server. Add one, then retry.'];$id=(int)$ids[0];}
            if(!in_array($id,$ids,true))return ['ok'=>false,'error'=>'Upload not started: the selected Configuration Backup instance is absent on this server.'];
            if(!function_exists('MCB_UploadSecretsDiagnostics'))return ['ok'=>false,'error'=>'Upload not started: MCB_UploadSecretsDiagnostics is unavailable. Update Configuration Backup on this server.'];
            $json=MCB_UploadSecretsDiagnostics($id);if(!is_string($json)||strlen($json)>16384)throw new RuntimeException();$r=json_decode($json,true,16,JSON_THROW_ON_ERROR);
            if(($r['ok']??false)!==true){
                $safe=['Apply valid settings and wait until Symcon is ready.','Enable and save readable Secrets diagnostics first; automatic refresh also needs GitHub uploads enabled.','Cannot read the GitHub backup secret record.','Secret record requires Token and EncryptionKey fields.','EncryptionKey must encode exactly 32 bytes.','Select an active old SecretsManager or new Secrets backend.','Backup storage must be the configured private repository.','Another backup/upload/restore is running.','An automatic restore test is running. Finish or stop it before another backup/upload/restore or settings change.'];
                $reason=in_array($r['error']??'', $safe,true)?$r['error']:'GitHub save was not confirmed. Check repository access and Configuration Backup status.';
                if(preg_match('/^GitHub request failed \(HTTP (401|403|404|409|422|429|5[0-9]{2})\)\. Check the token, Contents read\/write permission, private repository and branch\.$/D',(string)($r['error']??'')))$reason=$r['error'];
                return ['ok'=>false,'error'=>'Configuration Backup instance '.$id.': '.$reason];
            }
            if(!is_string($r['commit']??null)||!preg_match('/^[a-f0-9]{40}$/D',$r['commit'])||!preg_match('~^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$~D',(string)($r['repository']??''))||!is_string($r['branch']??null)||strlen($r['branch'])>255)throw new RuntimeException();
            return ['ok'=>true,'repository'=>$r['repository'],'branch'=>$r['branch'],'commit'=>$r['commit'],'incomplete'=>($r['warning']??'')!==''];
        }catch(Throwable $ignored){return ['ok'=>false,'error'=>'Report upload failed or its result could not be validated. Check Configuration Backup and the repository before starting another upload.'];}
    }
    private const JOB='support-report-job';
    private static function save(SecretsBackendNativeStore $store,array $job):void {
        try{$store->replace(self::JOB,self::JOB,$job,time()+3600);}catch(Throwable $e){$store->put(self::JOB,self::JOB,$job,time()+3600);}
    }
    public static function queue(SecretsBackendNativeStore $store,array $session,int $instance):array {
        $lock='SECB.SupportQueue.'.$store->read()['state']['native']['vaultId'];$locked=false;
        if(function_exists('IPS_SemaphoreEnter')){if(!IPS_SemaphoreEnter($lock,1))return ['ok'=>false,'error'=>'An upload request is already being recorded. Wait for its progress, then retry if needed.'];$locked=true;}
        try{return self::queueUnlocked($store,$session,$instance);}finally{if($locked)IPS_SemaphoreLeave($lock);}
    }
    private static function queueUnlocked(SecretsBackendNativeStore $store,array $session,int $instance):array {
        try{$j=$store->get(self::JOB,self::JOB);if($j['expires']>=time()&&in_array($j['state'],['queued','running'],true))return ['job'=>$j['id'],'state'=>$j['state']];}catch(Throwable $ignored){}
        $s=$store->read()['state'];$store->rate('support-upload:'.$s['native']['vaultId'],2);$j=['id'=>SecretsBackendCodec::uuid(),'state'=>'queued','instance'=>$instance,'credential'=>$session['credential'],'revocation'=>$s['identity']['revocation'],'expires'=>time()+1200];self::save($store,$j);return ['job'=>$j['id'],'state'=>'queued'];
    }
    public static function status(SecretsBackendNativeStore $store,string $id):array {
        try{$j=$store->get(self::JOB,self::JOB);if($j['id']!==$id)throw new RuntimeException();if($j['expires']<time()&&in_array($j['state'],['queued','running'],true))return ['state'=>'unknown','ok'=>false,'error'=>'Upload has not been confirmed after 20 minutes. It may have been interrupted. Check Configuration Backup and the repository before starting another upload.'];return ['job'=>$id,'state'=>$j['state']]+($j['result']??[]);}catch(Throwable $ignored){return ['state'=>'unknown','ok'=>false,'error'=>'Upload progress is unavailable or expired. Check the repository before requesting another upload.'];}
    }
    public static function pending(SecretsBackendNativeStore $store):bool { try{return $store->get(self::JOB,self::JOB)['state']==='queued';}catch(Throwable $ignored){return false;} }
    public static function tick(SecretsBackendNativeStore $store):array {
        if(!self::pending($store))return ['status'=>'SUPPORT_IDLE'];
        $j=$store->get(self::JOB,self::JOB);$s=$store->read()['state'];$c=$s['identity']['credentials'][$j['credential']]??[];
        if($j['expires']<time()||$j['revocation']!==$s['identity']['revocation']||!($c['active']??false)||!SecretsBackendBackupOriginPolicy::credentialFull($s,$c))$result=['ok'=>false,'error'=>'Upload cancelled: the requesting administrator’s authorization expired or was revoked.'];
        else{
            // Mark before sending; a crash must never silently replay an uncertain upload.
            $j['state']='running';self::save($store,$j);if(function_exists('set_time_limit'))@set_time_limit(300);$result=self::upload($j['instance']);
        }
        $j['state']='finished';$j['result']=$result;self::save($store,$j);return ['status'=>'SUPPORT_FINISHED'];
    }
}
