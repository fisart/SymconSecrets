<?php
declare(strict_types=1);
require_once __DIR__.'/../Deployment.php';
$count=0;
$ok=static function(bool $v) use (&$count):void{if(!$v)throw new RuntimeException('Deployment assertion failed.');++$count;};
$no=static function(callable $f) use (&$count):void{try{$f();}catch(Throwable $e){++$count;return;}throw new RuntimeException('Expected deployment rejection.');};
$origin='https://symcon.example.test';$d=SecretsFrontendDeployment::defaults($origin);$summary=SecretsFrontendDeployment::describe($d,$origin);
$ok($summary['defaults']['voters']===3&&$summary['defaults']['durableCopies']===2&&$summary['defaults']['offlineRecoveryCopies']===2);
$ok($summary['activationAllowed']===false&&count($summary['missing'])>0&&$summary['status']==='DRAFT_NOT_ADMITTED');
$ok($d['peers'][0]['origin']===$origin&&$d['authorities'][0]['endpoint']==='');
for($i=0;$i<3;$i++){$d['authorities'][$i]['endpoint']='https://authority'.($i+1).'.example.test';$d['authorities'][$i]['failureDomain']='Location '.($i+1);}
$d['peers'][0]['failureDomain']='Berlin';$d['peers'][1]['origin']='https://second.example.test';$d['peers'][1]['failureDomain']='Florida';$d['recoveryLocations']=['Protected location A','Protected location B'];
$s=SecretsFrontendDeployment::describe($d,$origin);$ok($s['missing']===[]&&!$s['activationAllowed']&&count($s['verificationRequired'])>0);
$bad=$d;$bad['authorities'][2]['failureDomain']='location 1';$ok(count(SecretsFrontendDeployment::describe($bad,$origin)['missing'])>0);
$bad=$d;$bad['recoveryLocations']=['same','SAME'];$ok(count(SecretsFrontendDeployment::describe($bad,$origin)['missing'])>0);
foreach(['https://user:pass@host.test','http://host.test','https://host.test/path','https://host.test?token=secret'] as $endpoint){$bad=$d;$bad['authorities'][0]['endpoint']=$endpoint;$no(fn()=>SecretsFrontendDeployment::validate($bad,$origin));}
$bad=$d;$bad['authorities'][0]['endpoint']=$bad['authorities'][1]['endpoint'];$no(fn()=>SecretsFrontendDeployment::validate($bad,$origin));
$bad=$d;$bad['peers'][0]['origin']='https://other.test';$no(fn()=>SecretsFrontendDeployment::validate($bad,$origin));
$bad=$d;array_pop($bad['authorities']);$no(fn()=>SecretsFrontendDeployment::validate($bad,$origin));
$bad=$d;$bad['trustApproved']=true;$no(fn()=>SecretsFrontendDeployment::validate($bad,$origin));
$bad=$d;$bad['authorities'][0]['certificatePin']='made-up';$no(fn()=>SecretsFrontendDeployment::validate($bad,$origin));
$bad=$d;$bad['authorities'][0]['name']="bad\nlabel";$no(fn()=>SecretsFrontendDeployment::validate($bad,$origin));
echo "PASS $count deployment defaults, closed fields, pinned origin, independent-placement checks and non-activation assertions\n";
