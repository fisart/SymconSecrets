<?php
declare(strict_types=1);

/** Fixed classifications only. Never retain request bodies, cookies, exception text or traces. */
final class SecretsBackendRequestDiagnostics
{
    public const SCHEMA='SECB.RequestDiagnostics.v1';
    public const CODES=['LOGIN_REQUIRED','SESSION_EXPIRED','SESSION_INVALID','CSRF_INVALID','APPROVAL_EXPIRED','APPROVAL_INVALID','REVISION_CHANGED','EMERGENCY_OFFER_CHANGED','EMERGENCY_PAIRING_CHANGED','EMERGENCY_SIGNATURE_INVALID','HARDWARE_REQUIRED','RATE_LIMITED','BACKEND_UNAVAILABLE','CONFIGURATION_CHANGED','REQUEST_INVALID','REQUEST_FAILED'];
    public const STAGES=['envelope','origin','rate','storage','configuration','login','session','csrf','action','prepare','approval','commit','result'];
    public static function action($value): string
    {
        return is_string($value)&&in_array($value,['status','authOptions','authVerify','session','list','sessionReveal','sessionTimeout','prepare','approve','logout','configurationPreview','nativeOverviewStatus','nativeGlobalStatus','nativePairingStatus','nativeRetryPeerDelivery','nativeOperationStatus','nativeCandidateOptions','nativeCandidateSubmit','legacySources','legacyPreview','nativeUploadBegin','nativeUploadChunk','nativeUploadFinish','connectDiscovery','connectOptions','connectSubmit','connectProof','connectStatus','connectCandidateReview'],true)?$value:'other';
    }
    public static function operation($value): ?string
    {
        return is_string($value)&&in_array($value,['nativeEmergencyGrant','nativeEmergencyAccept','nativeEmergencyImport','nativeEmergencyRemove','nativeEmergencyRevoke','nativeInvite','nativePair','nativeAcceptPair','nativeRevokePeer','save','delete','rename','reveal','nativeGlobalReveal','nativeGlobalResolve','nativeReveal','nativeBackup','nativeRestore','nativeCompact','nativeEnrollment','nativeMachineGrant','nativeMachineRevoke','nativeLegacyAccess','nativeLegacyImport','nativeConnectStage','nativeConnectActivate','nativeConnectRevoke','nativeConnectUpgrade','nativeHardwareProfile','nativeRotateKey','nativeResync','nativeProvider','nativeProviderDisable','nativeRefresh','nativeEffectApply','nativeEffectAbandon','nativeSharedSave','nativeSharedDelete','nativeSharedRename','nativeTransferOffer','nativeTransferAccept','nativeFork','configuration','policy','revoke'],true)?$value:null;
    }
    public static function classify(Throwable $error,string $stage): string
    {
        return match($error->getMessage()){
            'Administrator login is required.'=>'LOGIN_REQUIRED',
            'Administrator session expired.'=>'SESSION_EXPIRED',
            'Administrator session expired or revoked.','Origin authorization changed.'=>'SESSION_INVALID',
            'Session or one-use authorization expired.'=>$stage==='session'?'SESSION_EXPIRED':'APPROVAL_EXPIRED',
            'CSRF verification failed.'=>'CSRF_INVALID',
            'Approval belongs to a different session.','Approval administrator mismatch.','Wrong approval credential.','Invalid WebAuthn client data.','User handle mismatch.','Challenge origin changed.','Native reviewed operation was changed.'=>'APPROVAL_INVALID',
            'Revision conflict; reload and approve the current change.','Invalid scope or stale revision.','Authorization state changed; repeat full verification.','Native operation state changed before its result could be disclosed.'=>'REVISION_CHANGED',
            'Emergency offer changed. Refresh and review again.','Emergency offer changed before approval.'=>'EMERGENCY_OFFER_CHANGED',
            'Emergency source pairing changed.','Emergency peer identity changed.','Emergency pairing changed.','Emergency Global read refused: PAIRING_NOT_ACTIVE'=>'EMERGENCY_PAIRING_CHANGED',
            'Emergency approval signature invalid.'=>'EMERGENCY_SIGNATURE_INVALID',
            'Hardware approval is required.','No eligible administrator key. Use independent recovery if all keys are lost.'=>'HARDWARE_REQUIRED',
            'Rate limit exceeded.','Request limit reached.'=>'RATE_LIMITED',
            'Frontend/backend binding is invalid.','Security profile changed; repeat complete validation.','Pinned native foundation changed. Restore the reviewed settings or use recovery.'=>'CONFIGURATION_CHANGED',
            'Invalid frontend envelope.','Unexpected request fields.'=>'REQUEST_INVALID',
            default=>$stage==='storage'?'BACKEND_UNAVAILABLE':'REQUEST_FAILED'
        };
    }
    public static function message(string $code): string
    {
        return match($code){
            'LOGIN_REQUIRED'=>'Sign in with your administrator passkey, then repeat the action.',
            'SESSION_EXPIRED'=>'Your administrator session expired. Sign in again, then repeat the action.',
            'SESSION_INVALID'=>'Your administrator session is no longer valid. Sign in again, then repeat the action.',
            'CSRF_INVALID'=>'Session verification failed. Reload this page and sign in again before repeating the action.',
            'APPROVAL_EXPIRED'=>'The one-use approval expired or was already used. Refresh and review the action again.',
            'APPROVAL_INVALID'=>'This approval does not match the current session or administrator. Refresh and review the action again.',
            'REVISION_CHANGED'=>'The vault changed during the request. Refresh, check whether the action completed, and review it again if needed.',
            'EMERGENCY_OFFER_CHANGED'=>'The emergency offer changed or was already accepted. Refresh Connections and review the current offer.',
            'EMERGENCY_PAIRING_CHANGED'=>'The emergency source no longer matches the approved connection. Refresh Connections and review its pairing.',
            'EMERGENCY_SIGNATURE_INVALID'=>'The emergency offer could not be authenticated. Keep the existing configuration and provide the diagnostic reference for investigation.',
            'HARDWARE_REQUIRED'=>'An eligible administrator key is required. Check the configured hardware-key policy and use an approved key.',
            'RATE_LIMITED'=>'Too many requests. Wait one minute, refresh and try again.',
            'CONFIGURATION_CHANGED'=>'The backend or its security configuration changed. Check the backend status in the Symcon console.',
            'BACKEND_UNAVAILABLE'=>'The backend could not open its current vault state. Check its status and the diagnostic reference in the Symcon console.',
            default=>'Request refused. Check the diagnostic reference in the Secrets Backend console or upload updated Secrets diagnostics.'
        };
    }
    public static function failure(Throwable $error,array $context,array $request,int $backend,int $frontend): array
    {
        $stage=in_array($context['stage']??'',self::STAGES,true)?$context['stage']:'envelope';
        $code=self::classify($error,$stage);
        return ['reference'=>bin2hex(random_bytes(8)),'at'=>gmdate('c'),'backend'=>$backend,'frontend'=>$frontend,
            'action'=>self::action($request['action']??null),'operation'=>self::operation($context['operation']??null),
            'stage'=>$stage,'code'=>$code,'exception'=>in_array(get_class($error),['RuntimeException','InvalidArgumentException','ErrorException','TypeError','Error','JsonException','SecretsBackendEmergencyRefused'],true)?get_class($error):'other',
            'file'=>dirname($error->getFile())===__DIR__?basename($error->getFile()):null,'line'=>dirname($error->getFile())===__DIR__?$error->getLine():null,'authenticated'=>($context['authenticated']??false)===true,
            'csrfVerified'=>($context['csrfVerified']??false)===true];
    }
    public static function response(array $failure): array
    {
        // Detailed reasons are disclosed only after session and CSRF verification.
        $login=in_array($failure['code'],['LOGIN_REQUIRED','SESSION_EXPIRED','SESSION_INVALID'],true);
        $public=($failure['authenticated']&&$failure['csrfVerified'])||$login||$failure['code']==='CSRF_INVALID'?$failure['code']:'REQUEST_FAILED';
        return ['error'=>self::message($public).' ['.$public.' · '.$failure['reference'].']',
            'code'=>$public,'reference'=>$failure['reference'],'requiresSignIn'=>$login||$public==='CSRF_INVALID'];
    }
}
