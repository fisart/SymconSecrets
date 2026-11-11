<?php
declare(strict_types=1);
require_once __DIR__.'/BootstrapFixture.php';
// Symcon generates wrappers with every method argument required, including PHP defaults.
function SECF_OpenBootstrapFromConsole(int $id,string $address,bool $confirmed,bool $recovery): string { return $GLOBALS['instances'][$id]->OpenBootstrapFromConsole($address,$confirmed,$recovery); }
$GLOBALS['moduleIDs']=[6600=>SecretsBackend::FRONTEND,6601=>'{52165EDD-B2C0-40EC-8A59-42A97319B6E2}',700=>'{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}'];
$hooks=new IPSModule(700);$hooks->properties['Hooks']='[]';$front=new SecretsFrontend(6600);$front->Create();$back=new SecretsBackend(6601);$back->Create();$front->properties['BackendInstanceID']=6601;
$form=json_decode($front->GetConfigurationForm(),true,32,JSON_THROW_ON_ERROR);$fields=[];foreach($form['actions']as$field)if(isset($field['name']))$fields[$field['name']]=$field;
secExpect(!$fields['OpenBootstrap']['enabled']&&!isset($fields['OpenBootstrap']['link'])&&!isset($fields['OpenRecoveryBootstrap']['link']),'Console setup still forces errors to open as links.');
$id=6600;$BootstrapJournalStorage=true;
$click=static function(string $script,string $address)use($id,$BootstrapJournalStorage):string{$SetupAddress=$address;ob_start();try{eval($script);return ob_get_contents();}finally{ob_end_clean();}};
$before=[$front->properties,$front->attributes,$front->buffers];
foreach(['','heartbeat.ap-fischer.de','http://heartbeat.ap-fischer.de','https://host.example:99999','https://user:DO-NOT-LEAK@example.test','javascript:alert(1)']as$invalid){
    $front->PreviewWizardURL($invalid);secExpect(!$front->form['OpenBootstrap']['enabled']&&$front->form['WizardURL']['value']==='','Invalid address retained a stale enabled link.');
    $reply=$click($fields['OpenBootstrap']['onClick'],$invalid);
    secExpect(str_starts_with($reply,'Step 1:')&&!str_contains($reply,'://')&&!str_contains($reply,'Fatal')&&!str_contains($reply,'Stack trace')&&!str_contains($reply,'DO-NOT-LEAK'),'Invalid address did not produce a safe plain console message.');
    secExpect(str_contains($front->form['SetupAddressStatus']['caption'],'https://'),'Correction message does not show the required scheme.');
    secExpect([$front->properties,$front->attributes,$front->buffers]===$before,'Invalid console input changed setup state or authority.');
}
$address='https://heartbeat.example.test:46910/console/';$expected='https://heartbeat.example.test:46910/hook/secrets_frontend_6600';
$front->PreviewWizardURL($address);secExpect($front->form['OpenBootstrap']['enabled']&&$front->form['WizardURL']['value']===$expected,'Valid full console URL did not enable Step 1 with the exact port/instance.');
$GLOBALS['changed'][6600]=true;$reply=$click($fields['OpenBootstrap']['onClick'],$address);secExpect(str_starts_with($reply,'Setup could not be opened.')&&!str_contains($reply,'://')&&str_contains($front->form['SetupAddressStatus']['caption'],'pending edits'),'Setup precondition failure escaped as a fatal link.');$GLOBALS['changed'][6600]=false;
$url=$click($fields['OpenBootstrap']['onClick'],$address);secExpect($url===$expected,'Valid Step 1 output is not the exact browser URL.');
$state=$front->buffers['Bootstrap'];$properties=$front->properties;$attributes=$front->attributes;
$reply=$click($fields['OpenBootstrap']['onClick'],'missing-prefix.example.test');secExpect(str_starts_with($reply,'Step 1:')&&$front->buffers['Bootstrap']===$state&&$front->properties===$properties&&$front->attributes===$attributes,'Invalid input cancelled or replaced an existing setup intent.');
secReject(static fn()=>$front->OpenBootstrap('missing-prefix.example.test','',false,true),'Core API lost strict address validation.');
$recovery=$click($fields['OpenRecoveryBootstrap']['onClick'],'');secExpect(str_starts_with($recovery,'Setup could not be opened.')&&!str_contains($recovery,'://')&&!str_contains($recovery,'Fatal'),'Recovery failure was still forced into a link.');
$form=json_decode($front->GetConfigurationForm(),true,32,JSON_THROW_ON_ERROR);foreach($form['actions']as$field)if(isset($field['name']))$fields[$field['name']]=$field;
secExpect($fields['OpenBootstrap']['enabled']&&$fields['WizardURL']['value']===$expected,'Reopening an applied configuration lost the valid setup link.');
echo "PASS actual console actions: invalid-address feedback, no forced error links or traces, preserved setup state, valid HTTPS/port/instance link and safe recovery errors\n";
