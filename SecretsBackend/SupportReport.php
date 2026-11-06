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
    public static function upload(int $id):array {
        $target=null;foreach(self::targets()as$t)if($t['id']===$id)$target=$t;
        if(!$target||!$target['enabled'])return ['ok'=>false,'error'=>match($target['code']??'MISSING'){'UPDATE_BACKUP_REQUIRED'=>'The backup instance was found, but its upload API is missing. Update Symcon-Backup-Module on main in this server’s Symcon console, then refresh the upload destination.','SETTINGS_NOT_APPLIED'=>'Open Configuration Backup in this server’s Symcon console and select Apply changes, then refresh the upload destination.','DIAGNOSTICS_DISABLED'=>'In this server’s Symcon console, open Configuration Backup → 3. Choose uploads and diagnostics → enable Upload readable Secrets diagnostics to the private repository (no secrets) → Apply changes. Then refresh the upload destination.','CONFIGURATION_UNREADABLE'=>'The backup instance was found, but its configuration could not be read. Check that instance in this server’s Symcon console.',default=>'The selected backup instance was not found on this Symcon server. Refresh the upload destination.'}];
        try{$json=MCB_UploadSecretsDiagnostics($id);if(!is_string($json)||strlen($json)>16384)throw new RuntimeException();$r=json_decode($json,true,16,JSON_THROW_ON_ERROR);
            if(($r['ok']??false)!==true)return ['ok'=>false,'error'=>'GitHub save was not confirmed. Check the Secrets diagnostics status in Configuration Backup.'];
            if(!is_string($r['commit']??null)||!preg_match('/^[a-f0-9]{40}$/D',$r['commit']))throw new RuntimeException();
            return ['ok'=>true,'repository'=>$target['repository'],'branch'=>$target['branch'],'commit'=>$r['commit'],'incomplete'=>($r['warning']??'')!==''];
        }catch(Throwable $ignored){return ['ok'=>false,'error'=>'GitHub save could not be confirmed. Check Configuration Backup before trying again.'];}
    }
}
