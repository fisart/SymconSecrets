<?php
declare(strict_types=1);
require_once __DIR__.'/Fixture.php';
require_once __DIR__.'/../MonitoringFreshness.php';
$cadence=[];$now=1000;
secExpect(SecretsBackendMonitoringFreshness::seconds()===900,'Initial remote warning allowance is not generous.');
foreach([0,350,395,360]as$gap){$now+=$gap;$cadence=SecretsBackendMonitoringFreshness::observe($cadence,$now,true);}
secExpect(SecretsBackendMonitoringFreshness::seconds($cadence)===1185,'Normal slow cycles were not learned with a three-cycle margin.');
$healthy=$cadence;$before=SecretsBackendMonitoringFreshness::seconds($cadence);
$now+=5000;$cadence=SecretsBackendMonitoringFreshness::observe($cadence,$now,true);
secExpect(SecretsBackendMonitoringFreshness::seconds($cadence)===$before,'Outage recovery inflated the baseline.');
$now+=700;$cadence=SecretsBackendMonitoringFreshness::observe($cadence,$now,false);$now+=700;$cadence=SecretsBackendMonitoringFreshness::observe($cadence,$now,true);
secExpect(SecretsBackendMonitoringFreshness::seconds($cadence)===$before,'Failed or recovery checks inflated the baseline.');
$now+=700;$cadence=SecretsBackendMonitoringFreshness::observe($cadence,$now,true);
secExpect(SecretsBackendMonitoringFreshness::seconds($cadence)===1800,'Very slow healthy cycles were not capped at 30 minutes.');
$backwards=SecretsBackendMonitoringFreshness::observe($healthy,$healthy['lastAt']-10,true);
$corrected=SecretsBackendMonitoringFreshness::observe($backwards,$healthy['lastAt']+600,true);
secExpect($corrected['gaps']===$healthy['gaps'],'The check following clock correction inflated the baseline.');
$limit=$cadence;$now-=10;$cadence=SecretsBackendMonitoringFreshness::observe($cadence,$now,true);
secExpect($cadence['gaps']===$limit['gaps'],'Clock reversal entered cadence samples.');
// One recovery observation followed by eight healthy intervals.
for($i=0;$i<9;$i++){$now+=60;$cadence=SecretsBackendMonitoringFreshness::observe($cadence,$now,true);}
secExpect(SecretsBackendMonitoringFreshness::seconds($cadence)===900&&count($cadence['gaps'])===8,'Old slow cycles never aged out or sample retention was unbounded.');
secExpect(SecretsBackendMonitoringFreshness::seconds(['gaps'=>[-1,0,999999,'600',600]])===1800,'Invalid samples escaped the fixed bound.');
echo "PASS monitoring freshness: 15-minute floor, healthy slow-cycle learning, three-cycle margin, bounded retention, 30-minute cap, outage/failure exclusion and clock reversal\n";
