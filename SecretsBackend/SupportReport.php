<?php
declare(strict_types=1);

/** Delegate to the existing opt-in, private-repository, allowlisted uploader. */
final class SecretsBackendSupportReport
{
    private const MODULE='{0E51F4D8-5A8C-46B3-8F77-610C3F9493AC}';
    public static function targets():array {
        if(!function_exists('IPS_GetInstanceListByModuleID'))return [];$out=[];
        foreach(array_slice(IPS_GetInstanceListByModuleID(self::MODULE),0,32)as$id){
            try{$c=json_decode(IPS_GetConfiguration($id),true,32,JSON_THROW_ON_ERROR);$out[]=['id'=>$id,'name'=>IPS_GetName($id),'repository'=>(string)($c['GitHubOwner']??'').'/'.(string)($c['GitHubRepository']??''),'branch'=>(string)($c['GitHubBranch']??''),'enabled'=>($c['ReadableSecretsDiagnostics']??false)===true&&function_exists('MCB_UploadSecretsDiagnostics')&&!IPS_HasChanges($id)];}catch(Throwable $ignored){}
        }return $out;
    }
    public static function upload(int $id):array {
        $target=null;foreach(self::targets()as$t)if($t['id']===$id)$target=$t;
        if(!$target||!$target['enabled'])return ['ok'=>false,'error'=>'Enable and save readable Secrets diagnostics in Configuration Backup, then refresh this page.'];
        try{$json=MCB_UploadSecretsDiagnostics($id);if(!is_string($json)||strlen($json)>16384)throw new RuntimeException();$r=json_decode($json,true,16,JSON_THROW_ON_ERROR);
            if(($r['ok']??false)!==true)return ['ok'=>false,'error'=>'GitHub save was not confirmed. Check the Secrets diagnostics status in Configuration Backup.'];
            if(!is_string($r['commit']??null)||!preg_match('/^[a-f0-9]{40}$/D',$r['commit']))throw new RuntimeException();
            return ['ok'=>true,'repository'=>$target['repository'],'branch'=>$target['branch'],'commit'=>$r['commit'],'incomplete'=>($r['warning']??'')!==''];
        }catch(Throwable $ignored){return ['ok'=>false,'error'=>'GitHub save could not be confirmed. Check Configuration Backup before trying again.'];}
    }
}
