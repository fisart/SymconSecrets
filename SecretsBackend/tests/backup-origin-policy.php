<?php
declare(strict_types=1);
require_once __DIR__ . '/../BackupOriginPolicy.php';

function backupExpect(bool $value, string $message): void { if (!$value) throw new RuntimeException($message); }
function backupReject(callable $call, string $message): void { try { $call(); } catch (Throwable $e) { return; } throw new RuntimeException($message); }

$origin = 'https://example.ipmagic.de'; $generation = str_repeat('a', 64);
$policy = ['version'=>1, 'origin'=>$origin, 'generation'=>$generation, 'status'=>'pending'];
$state = ['policy'=>['backupOrigin'=>$policy]];
backupExpect(SecretsBackendBackupOriginPolicy::requireRoute($state, $origin, $generation, 'register-options')['status'] === 'pending', 'Restricted enrollment was not available.');
foreach (['authenticate','session','list','reveal','write','approve','export'] as $action) {
    backupReject(static fn()=>SecretsBackendBackupOriginPolicy::requireRoute($state,$origin,$generation,$action), 'Pending origin admitted '.$action);
}
backupReject(static fn()=>SecretsBackendBackupOriginPolicy::requireRoute(['policy'=>[]],$origin,$generation,'authenticate'), 'Missing policy admitted backup.');
backupReject(static fn()=>SecretsBackendBackupOriginPolicy::requireRoute($state,'https://other.ipmagic.de',$generation,'register-options'), 'Wrong origin admitted.');
backupReject(static fn()=>SecretsBackendBackupOriginPolicy::requireRoute($state,$origin,str_repeat('b',64),'register-options'), 'Stale generation admitted.');
foreach (['http://example.ipmagic.de','https://example.ipmagic.de/path','https://192.0.2.1','https://127.1','https://-bad.ipmagic.de','https://*.ipmagic.de','https://Example.ipmagic.de'] as $bad) {
    backupReject(static fn()=>SecretsBackendBackupOriginPolicy::exactOrigin($bad), 'Invalid origin admitted: '.$bad);
}
$state['policy']['backupOrigin']['status']='active';
$credential=['id'=>'credential','administrator'=>'owner','active'=>true,'tested'=>true,'origin'=>$origin,'originGeneration'=>$generation];
SecretsBackendBackupOriginPolicy::requireCredential($state,$credential,$origin,$generation);
foreach ([['active'=>false],['tested'=>false],['origin'=>null],['originGeneration'=>str_repeat('b',64)],['administrator'=>'']] as $change) {
    backupReject(static fn()=>SecretsBackendBackupOriginPolicy::requireCredential($state,array_replace($credential,$change),$origin,$generation), 'Ineligible credential admitted.');
}
$state['policy']['backupOrigin']['status']='revoked';
backupReject(static fn()=>SecretsBackendBackupOriginPolicy::requireCredential($state,$credential,$origin,$generation), 'Revoked origin admitted an old credential.');
$state['policy']['backupOrigin']['status']='active'; $state['policy']['backupOrigin']['generation']=str_repeat('b',64);
backupReject(static fn()=>SecretsBackendBackupOriginPolicy::requireCredential($state,$credential,$origin,$generation), 'Re-added origin revived an old credential.');
$state['policy']['backupOrigin']['unexpected']='invalid';
backupReject(static fn()=>SecretsBackendBackupOriginPolicy::requireRoute($state,$origin,str_repeat('b',64),'authenticate'), 'Malformed policy was accepted.');
$primary='https://primary.example.test';
$initial=['policy'=>['origin'=>$primary,'hardware'=>['write'=>false,'identity'=>false,'export'=>false,'reveal'=>false]], 'identity'=>['credentials'=>['primary'=>['active'=>true,'tested'=>true]]]];
$staged=SecretsBackendBackupOriginPolicy::stage($initial,$origin);
$first=$staged['policy']['backupOrigin']['generation'];
backupExpect($staged['policy']['backupOrigin']['status']==='pending' && strlen($first)===64, 'A new route was not staged.');
backupReject(static fn()=>SecretsBackendBackupOriginPolicy::stage($initial,$primary), 'Primary origin was admitted as backup.');
backupReject(static fn()=>SecretsBackendBackupOriginPolicy::stage($staged,$origin), 'A pending enrollment was overwritten.');
backupReject(static fn()=>SecretsBackendBackupOriginPolicy::revoke($staged,$origin,str_repeat('0',64)), 'Stale revocation succeeded.');
$unusable=$staged; $unusable['identity']['credentials']['primary']['tested']=false;
backupReject(static fn()=>SecretsBackendBackupOriginPolicy::revoke($unusable,$origin,$first), 'An untested primary was counted as a usable route.');
$hardware=$staged; $hardware['policy']['hardware']['identity']=true;
backupReject(static fn()=>SecretsBackendBackupOriginPolicy::revoke($hardware,$origin,$first), 'A non-hardware primary was counted as a hardware route.');
$staged['identity']['credentials']['backup']=['active'=>true,'origin'=>$origin,'originGeneration'=>$first];
$revoked=SecretsBackendBackupOriginPolicy::revoke($staged,$origin,$first);
backupExpect($revoked['identity']['credentials']['primary']['active'] && !$revoked['identity']['credentials']['backup']['active'], 'Revocation affected the wrong credentials.');
$again=SecretsBackendBackupOriginPolicy::stage($revoked,$origin); $second=$again['policy']['backupOrigin']['generation'];
backupExpect($first!==$second,'Re-adding an origin reused its generation.');
backupReject(static fn()=>SecretsBackendBackupOriginPolicy::requireRoute($again,$origin,$first,'register-options'),'Old enrollment revived after re-addition.');
echo "Backup origin policy checks passed.\n";
