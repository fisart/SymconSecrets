<?php
declare(strict_types=1);
require __DIR__.'/../../SecretsFrontend/tests/SymconHarness.php';
require __DIR__.'/../Availability.php';
function check(bool $v,string $m):void { if(!$v)throw new RuntimeException($m); }
class AvailabilityProbe extends IPSModule {
    use SecretsBackendAvailability;
    public bool $initialized=true;
    public string $failure='';
    public int $recoveries=0;
    public bool $recoverWorks=true;
    private function nativeInitialized():bool{return $this->initialized;}
    private function nativeApplication():void{if($this->failure!=='')throw new RuntimeException($this->failure);}
    public function Recover():bool{++$this->recoveries;if($this->recoverWorks)$this->failure='';return $this->recoverWorks;}
}
$p=new AvailabilityProbe(1);$p->properties['Enabled']=true;
check(!json_decode($p->GetAvailability(),true)['ready'],'Unknown heartbeat reported ready');
$r=json_decode($p->CheckAvailability(),true);check($r['ready']&&$p->recoveries===0,'Healthy probe invoked recovery');
$p->failure='Native runtime is fenced or recovery is pending.';
$r=json_decode($p->CheckAvailability(),true);check($r['ready']&&$p->recoveries===1,'Missed startup did not recover');
$p->failure='Native identity authentication failed.';
$r=json_decode($p->CheckAvailability(),true);check(!$r['ready']&&$p->recoveries===1,'Integrity error triggered recovery');
$p->failure='Native runtime is fenced or recovery is pending.';$p->recoverWorks=false;
$p->buffers['AvailabilityState']='';
for($i=0;$i<5;$i++){
    $s=json_decode($p->CheckAvailability(),true);check(!$s['ready'],'Failed recovery reported ready');
    $n=$p->recoveries;$p->CheckAvailability();check($n===$p->recoveries,'Backoff did not bound recovery');
    $s['nextRecoveryAt']=time()-1;$p->buffers['AvailabilityState']=json_encode($s);
}
$n=$p->recoveries;$p->CheckAvailability();check($n===$p->recoveries,'Retry budget exceeded');
$p->properties['Enabled']=false;$p->CheckAvailability();check($n===$p->recoveries,'Disabled backend recovered');
$p->properties['Enabled']=true;$p->initialized=false;$p->CheckAvailability();check($n===$p->recoveries,'Uninitialized backend recovered');
$p->initialized=true;$GLOBALS['changed'][1]=true;$p->CheckAvailability();check($n===$p->recoveries,'Pending configuration recovered');
$GLOBALS['changed'][1]=false;$p->failure='';$p->CheckAvailability();
$s=json_decode($p->buffers['AvailabilityState'],true);$s['checkedAt']=time()-100;$p->buffers['AvailabilityState']=json_encode($s);
check(!json_decode($p->GetAvailability(),true)['ready'],'Stale heartbeat reported ready');
echo "PASS availability: pending startup, integrity refusal, retry budget/backoff, disabled/uninitialized/pending settings, staleness\n";
