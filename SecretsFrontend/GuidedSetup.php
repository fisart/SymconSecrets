<?php
declare(strict_types=1);
require_once __DIR__ . '/Bootstrap.php';

trait SecretsFrontendGuidedSetup
{
    use SecretsFrontendBootstrap;
    private function guidedActive(): bool { $s=$this->bootstrapState();return $s && ($s['expires']??0)>=time(); }
    private function setupName(int $id,string $fallback): string { return function_exists('IPS_GetName')?IPS_GetName($id).' · '.$id:$fallback.' · '.$id; }
    private function initialBackend(int $id): array
    {
        if($id<=0||!IPS_InstanceExists($id)||strtoupper(IPS_GetInstance($id)['ModuleInfo']['ModuleID']??'')!==self::BACKEND||!function_exists('SECB_GetInitialSetupInfo'))throw new RuntimeException('Choose an eligible native backend.');
        return json_decode(SECB_GetInitialSetupInfo($id),true,16,JSON_THROW_ON_ERROR);
    }
    private function discovered(string $module,string $fallback): array
    {
        $out=[];foreach(IPS_GetInstanceListByModuleID($module)as$id)if(!IPS_HasChanges($id))$out[]=['id'=>(int)$id,'name'=>$this->setupName((int)$id,$fallback)];return $out;
    }
    private function forgetGuidedSetup(): void
    {
        $reset=function():void{$this->SetBuffer('GuidedSetup','');$this->SetBuffer('Bootstrap','');$this->SetBuffer('BootstrapRuntime',SecretsBackendCodec::b64(random_bytes(32)));};
        $base=rtrim(str_replace('\\','/',IPS_GetKernelDir()),'/');
        if(is_dir($base.'/secrets-native-data/bootstrap'))$this->bootstrapJournal()->locked($reset);else $reset();
    }
    public function BeginGuidedSetup(string $Address,string $ProxyIPs): string { throw new RuntimeException('Setup codes have been removed. Use Open setup.'); }
    public function CancelGuidedSetup(): void { $this->CancelBootstrap(); }
    public function BeginAdministratorEnrollment(string $Label,bool $Hardware): string { throw new RuntimeException('Manual administrator codes have been removed. Use a passkey candidate.'); }
    private function gateway(array $request): array
    {
        $action=$request['action'];
        if(in_array($action,['bootstrapPrepare','bootstrapSubmit','bootstrapProof','bootstrapResumeOptions'],true)){
            try{return ['status'=>200]+$this->bootstrapRequest($request);}catch(Throwable $e){return ['status'=>403,'data'=>['error'=>$e->getMessage()],'cookie'=>''];}
        }
        if(in_array($action,['guidedDiscover','guidedPreview','guidedApply','guidedCancel','setupPreview','setupCreate','enrollmentOptions','enrollmentVerify'],true))return ['status'=>403,'data'=>['error'=>'Code-based setup and enrollment have been removed.'],'cookie'=>''];
        $native=$this->bootstrapNative();
        if(!($native['initialized']??false))return ['status'=>$action==='status'?200:503,'data'=>$action==='status'?['ready'=>false,'guidedV2Only'=>true,'setupAvailable'=>$this->guidedActive(),'message'=>'Open setup in the trusted Symcon console, then prepare your first passkey here.']:['error'=>'Native vault not initialized.'],'cookie'=>''];
        return json_decode(SECB_HandleFrontendRequest($this->backend(),$this->InstanceID,SecretsFrontendConfiguration::encode($request)),true,96,JSON_THROW_ON_ERROR);
    }
}
