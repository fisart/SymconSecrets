<?php
declare(strict_types=1);
require_once __DIR__.'/SymconHarness.php';
if (!function_exists('IPS_GetConfiguration')) {
    function IPS_GetConfiguration(int $id): string { return json_encode($GLOBALS['instances'][$id]->properties, JSON_THROW_ON_ERROR); }
}
require_once __DIR__.'/../module.php';
require_once __DIR__.'/../../SecretsBackend/module.php';
function backupExpect(bool $value,string $message): void { if (!$value) throw new RuntimeException($message); }
$front=new SecretsFrontend(8100);$front->Create();$back=new SecretsBackend(8101);$back->Create();
$front->properties['AdminOrigin']='https://fixture.example';$back->properties['AdminOrigin']='https://fixture.example';
$front->properties['BackendInstanceID']=8101;$back->properties['FrontendInstanceID']=8100;
$front->attributes['BootstrapIdentity']='PRIVATE-IDENTITY-CANARY';$back->attributes['StorageBinding']='PRIVATE-STORAGE-CANARY';
foreach ([$front,$back] as $module) {
    $before=serialize($module);$e=json_decode($module->ExportConfigurationBackup(),true,128,JSON_THROW_ON_ERROR);
    $v=json_decode($module->ValidateConfigurationBackup(json_encode($e['payload'],JSON_THROW_ON_ERROR)),true,128,JSON_THROW_ON_ERROR);
    backupExpect($v['valid']&&$v['scope']==='format','Native importer did not validate its own export.');
    backupExpect($v['payloadHash']===hash('sha256',SecretsConfigurationBackup::canonical($e['payload'])),'Validation bound to a different payload.');
    backupExpect(serialize($module)===$before,'Export/validation changed module state, UI, timers, properties or attributes.');
    $native=json_decode($module->ExportConfiguration(),true,128,JSON_THROW_ON_ERROR);
    backupExpect(SecretsConfigurationBackup::canonical($native)===SecretsConfigurationBackup::canonical($e['payload']),'Backup payload differs from ordinary native export.');
    backupExpect(!str_contains(json_encode($e),'PRIVATE-'),'Runtime security data leaked.');
    $bad=$e['payload'];unset($bad['configuration']['AdminOrigin']);
    backupExpect(json_decode($module->ValidateConfigurationBackup(json_encode($bad)),true)['valid']===false,'Missing required setting accepted.');
    $bad=$e['payload'];$bad['configuration']['Enabled']='yes';
    backupExpect(json_decode($module->ValidateConfigurationBackup(json_encode($bad)),true)['valid']===false,'Incompatible setting type accepted.');
    $bad=$e['payload'];$bad['schema']='Unsupported.Config.v999';
    backupExpect(json_decode($module->ValidateConfigurationBackup(json_encode($bad)),true)['valid']===false,'Unsupported schema accepted.');
}
$draft=['authorities'=>array_fill(0,3,['name'=>'Authority','endpoint'=>'','failureDomain'=>'']),
    'peers'=>[['name'=>'Local','origin'=>'https://fixture.example','failureDomain'=>''],['name'=>'Peer','origin'=>'','failureDomain'=>'']],
    'recoveryLocations'=>['Offline','']];
$front->attributes['DeploymentDraft']=json_encode($draft,JSON_THROW_ON_ERROR);$before=serialize($front);
$e=json_decode($front->ExportConfigurationBackup(),true);backupExpect($e['payload']['schema']==='SECF.Config.v2'&&SecretsConfigurationBackup::canonical($e['payload']['deploymentDraft'])===SecretsConfigurationBackup::canonical($draft),'Required configuration draft was omitted.');
backupExpect(json_decode($front->ValidateConfigurationBackup(json_encode($e['payload'])),true)['valid'],'Native v2 draft failed importer validation.');
backupExpect(serialize($front)===$before,'Draft export/validation mutated state.');
$root=sys_get_temp_dir().'/configuration-backup-'.bin2hex(random_bytes(8));mkdir($root,0700);$GLOBALS['testKernel']=$root.'/';
$GLOBALS['moduleIDs']=[8100=>'{8D6AE8F7-EA3A-4513-AA14-C3F9613B0E83}',8101=>'{52165EDD-B2C0-40EC-8A59-42A97319B6E2}',
    8200=>'{8D6AE8F7-EA3A-4513-AA14-C3F9613B0E83}',8201=>'{52165EDD-B2C0-40EC-8A59-42A97319B6E2}',700=>'{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}'];
$hooks=new IPSModule(700);$hooks->properties['Hooks']='[]';
try {
    foreach ([[$front,new SecretsFrontend(8200)],[$back,new SecretsBackend(8201)]] as [$source,$target]) {
        $target->Create();$envelope=json_decode($source->ExportConfigurationBackup(),true);
        $payload=json_encode($envelope['payload'],JSON_THROW_ON_ERROR);
        backupExpect(json_decode($target->ValidateConfigurationBackup($payload),true)['valid'],'Isolated target refused format validation.');
        backupExpect($target->ImportConfiguration($payload),'Native importer rejected its configuration backup.');
        backupExpect($target->properties['Enabled']===false,'Configuration restore enabled automation.');
        foreach ($envelope['payload']['configuration'] as $key=>$value) {
            if ($key==='Enabled') continue;
            if (is_array($value)) $value=SecretsFrontendConfiguration::encode($value);
            backupExpect($target->properties[$key]===$value,'Isolated native restore lost setting '.$key.'.');
        }
    }
    backupExpect(SecretsConfigurationBackup::canonical(json_decode($GLOBALS['instances'][8200]->attributes['DeploymentDraft'],true))===SecretsConfigurationBackup::canonical($draft),'Isolated native restore lost the deployment draft.');
} finally {
    $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $file) { if ($file->isDir()) rmdir($file->getPathname());else unlink($file->getPathname()); }rmdir($root);
}
$GLOBALS['changed'][8100]=true;
try { $front->ExportConfigurationBackup();throw new RuntimeException('Pending settings exported.'); }
catch (RuntimeException $ex) { backupExpect(str_contains($ex->getMessage(),'pending'),'Pending settings guard failed.'); }
echo "PASS module-owned Secrets native export parity, read-only validation, isolated native configuration restores, safe disable, versioned drafts, private-data exclusion, invalid fields/types/formats and pending-setting guards\n";
