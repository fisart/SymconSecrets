<?php
declare(strict_types=1);
require_once __DIR__ . '/BackendStorage.php';
require_once __DIR__ . '/ConnectEnrollment.php';
require_once __DIR__ . '/Tree.php';
require_once __DIR__ . '/HardwareTrust.php';
require_once __DIR__ . '/SecurityConfiguration.php';
require_once __DIR__ . '/../SecretsManager/libs/PortalSecurity.php';
require_once __DIR__ . '/../SecretsManager/libs/WebAuthn/src/WebAuthn.php';

/** Dedicated administrator API. It never accepts a legacy portal session or admin password. */
final class SecretsBackendApplication
{
    use SecretsBackendConnectEnrollment;
    private SecretsBackendStorage $store;
    private array $settings;
    private array $rejectionContext = [];
    private array $requestContext = [];
    public function diagnosticContext(): array { return $this->requestContext; }
    public function __construct(SecretsBackendStorage $store, array $settings) { $this->store = $store; $this->settings = $settings; }
    private function webauthn(bool $hardware = false): \lbuchs\WebAuthn\WebAuthn
    {
        $rp = (string)parse_url($this->settings['origin'], PHP_URL_HOST);
        $auth = new \lbuchs\WebAuthn\WebAuthn('Secrets administration', $rp, $hardware ? ['packed'] : ['none', 'packed', 'fido-u2f', 'apple', 'tpm', 'android-key'], true);
        if ($hardware) {
            $roots = $this->settings['hardwareRoots'] ?? '';
            if (!is_dir($roots) || count(glob($roots . '/*.pem') ?: []) === 0 || empty($this->settings['hardwareAAGUIDs'])) throw new RuntimeException('No reviewed hardware trust profile is installed.');
            // Root verification is exclusively performed by HardwareTrust; never the shared chain helper.
        }
        return $auth;
    }
    private static function exact(array $data, array $fields): void
    {
        if (array_diff(array_keys($data), $fields) || array_diff($fields, array_keys($data))) throw new InvalidArgumentException('Unexpected request fields.');
    }
    private function cookieName(): string { return '__Host-SECB_' . $this->settings['backend']; }
    private function session(array $request, array $current): array
    {
        $cookies = []; preg_match_all('/(?:^|;\s*)' . preg_quote($this->cookieName(), '/') . '=([A-Za-z0-9_-]{43})(?=;|$)/', $request['cookie'] ?? '', $matches);
        if (count($matches[1]) !== 1) throw new RuntimeException('Administrator login is required.');
        $hash = hash('sha256', $matches[1][0]); $session = $this->store->get($hash, 'session');
        $credential = $current['state']['identity']['credentials'][$session['credential']] ?? null;
        if (!is_array($credential) || !$credential['active'] || $session['revocation'] !== $current['state']['identity']['revocation']
            || $session['administrator'] !== $credential['administrator']
            || $session['origin'] !== $this->settings['origin'] || $session['created'] + 3600 < time() || $session['last'] + min(900, max(60, (int)($session['idleLimit'] ?? 900))) < time()) throw new RuntimeException('Administrator session expired or revoked.');
        $this->routeCredential($current['state'], $credential);
        if (($session['originGeneration'] ?? '') !== $this->originGeneration($current['state'])) throw new RuntimeException('Origin authorization changed.');
        $session['hash'] = $hash; return $session;
    }
    /** Read-only authentication predicate for approved legacy protected pages. */
    public function portalAuthenticated(array $request): bool
    {
        try {
            $current=$this->store->read();$session=$this->session($request,$current);
            $credential=$current['state']['identity']['credentials'][$session['credential']];
            if($this->settings['origin']!==$this->primaryOrigin()&&!SecretsBackendBackupOriginPolicy::credentialFull($current['state'],$credential))return false;
            $this->store->authorize('legacy-portal',hash('sha256',$session['hash']),$current,function(array $checked)use($request):void{$this->session($request,$checked);});
            return true;
        } catch(Throwable $error) { return false; }
    }
    private function requireCsrf(array $request, array $session): void
    {
        if (!is_string($request['csrf'] ?? null) || !hash_equals($session['csrf'], $request['csrf'])) throw new RuntimeException('CSRF verification failed.');
    }
    private function credential(array $credential, array $challenge, array $assertion,bool $login=false): int
    {
        $this->routeCredential($this->store->read()['state'], $credential,$login);
        if (($challenge['origin'] ?? $this->primaryOrigin()) !== $this->settings['origin'] || ($challenge['originGeneration'] ?? '') !== $this->originGeneration($this->store->read()['state'])) throw new RuntimeException('Challenge origin changed.');
        self::exact($assertion, ['type', 'rawId', 'response']);
        $response = $assertion['response']; self::exact($response, ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle']);
        if ($assertion['type'] !== 'public-key' || !in_array($assertion['rawId'], $challenge['allowed'], true) || $assertion['rawId'] !== $credential['id']) throw new RuntimeException('Wrong approval credential.');
        $client = SecretsBackendCodec::unb64($response['clientDataJSON']); $authData = SecretsBackendCodec::unb64($response['authenticatorData']);
        $clientObject = SecretsFrontendConfiguration::decode($client);
        if (($clientObject['type'] ?? '') !== 'webauthn.get' || ($clientObject['challenge'] ?? '') !== $challenge['challenge']
            || ($clientObject['origin'] ?? '') !== $this->settings['origin'] || ($clientObject['crossOrigin'] ?? false) !== false) throw new RuntimeException('Invalid WebAuthn client data.');
        if ($response['userHandle'] !== null && (!is_string($response['userHandle']) || $response['userHandle'] !== $credential['userHandle'])) throw new RuntimeException('User handle mismatch.');
        $verifier = $this->webauthn();
        $verifier->processGet($client, $authData, SecretsBackendCodec::unb64($response['signature']), $credential['publicKey'], SecretsBackendCodec::unb64($challenge['challenge'], 32), $credential['counter'], true, true);
        $data = new \lbuchs\WebAuthn\Attestation\AuthenticatorData($authData);
        if (!SecretsPortalSecurity::validateBackupFlags($data->getIsBackupEligible(), $data->getIsBackup(), $credential['backupEligible'])) throw new RuntimeException('Credential backup flags changed.');
        if ($challenge['hardware'] && (!$credential['hardware'] || $data->getIsBackupEligible()
            || $credential['trustVersion'] !== ($this->settings['hardwareTrustVersion'] ?? 'none'))) throw new RuntimeException('Hardware approval is required.');
        return (int)($verifier->getSignatureCounter() ?? 0);
    }
    private function challenge(array $current, array $credentials, bool $hardware, string $kind, array $context): array
    {
        $ids = []; foreach ($credentials as $credential) if ($credential['active'] && $this->eligibleOrigin($current['state'], $credential,$kind==='login') && (!$hardware || ($credential['hardware'] && $credential['trustVersion'] === ($this->settings['hardwareTrustVersion'] ?? 'none')))) $ids[] = $credential['id'];
        if (!$ids) throw new RuntimeException('No eligible administrator key. Use independent recovery if all keys are lost.');
        $seconds=$kind==='approval'&&in_array($context['operation']['kind']??'',['nativeSetupAuthorize','nativeSetupStop'],true)?300:120;
        $verifier = $this->webauthn(); $args = $verifier->getGetArgs(array_map([SecretsBackendCodec::class, 'unb64'], $ids), $seconds, true, true, true, true, true, true);
        $id = SecretsBackendCodec::b64(random_bytes(32));
        $this->store->put($id, $kind, ['challenge' => SecretsBackendCodec::b64($verifier->getChallenge()->getBinaryString()), 'allowed' => $ids,
            'head' => $current['head'], 'hardware' => $hardware, 'context' => $context, 'origin'=>$this->settings['origin'], 'originGeneration'=>$this->originGeneration($current['state'])], time() + $seconds);
        return ['challengeId' => $id, 'options' => $args->publicKey];
    }
    public function beginEnrollment(string $label, bool $hardware, bool $probe = false, ?array $approval = null): string
    {
        if ($this->store instanceof SecretsBackendNativeStore) throw new RuntimeException('Code-based native enrollment is closed. Prepare an exact passkey candidate.');
        if ($label === '' || strlen($label) > 80 || preg_match('/[\x00-\x1f]/', $label)) throw new InvalidArgumentException('Invalid administrator label.');
        $current = $this->store->read(); $token = SecretsBackendCodec::b64(random_bytes(32));
        $body=['label' => $label, 'hardware' => $hardware, 'probe' => $probe, 'independentRecovery' => $approval === null];
        if($approval!==null){$body['approval']=$approval;$this->enrollmentAuthority($body,$current);}
        $this->store->put(hash('sha256', $token), 'enrollment', $body, time() + 600,
            $this->audit($approval===null?'enroll-recovery':'enroll-approved', $approval['credential']??'independent-console-recovery', 'enrollment-authorization'));
        return $token;
    }
    /** Only the local adapter calls this after verified genesis commit and one-use login reservation. */
    public function bootstrapSession(string $id): array
    {
        $current=$this->store->read();$entry=$current['state']['identity']['credentials'][$id]??null;
        if(!$entry||!$entry['active']||!$entry['tested'])throw new RuntimeException('Approved administrator is no longer active.');
        $this->store->authorize('login',hash('sha256','genesis:'.$id),$current,static function(array $checked)use($id,$entry):void{
            $key=$checked['state']['identity']['credentials'][$id]??null;
            if(!$key||!$key['active']||$key['administrator']!==$entry['administrator'])throw new RuntimeException('Administrator changed before login.');
        },$this->audit('login',$id,'genesis-session'));
        $raw=SecretsBackendCodec::b64(random_bytes(32));$csrf=SecretsBackendCodec::b64(random_bytes(32));
        $this->store->put(hash('sha256',$raw),'session',['credential'=>$id,'administrator'=>$entry['administrator'],'revocation'=>$current['state']['identity']['revocation'],'csrf'=>$csrf,'origin'=>$this->settings['origin'],'created'=>time(),'last'=>time()],time()+3600);
        return ['data'=>['authenticated'=>true,'csrf'=>$csrf],'cookie'=>$this->cookieName().'='.$raw.'; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600'];
    }
    private function enrollmentAuthority(array $token,array $current): void
    {
        if(($token['independentRecovery']??false)===true)return;
        $a=$token['approval']??null;$key=is_array($a)?($current['state']['identity']['credentials'][$a['credential']]??null):null;
        if(!is_array($a)||!is_array($key)||!$key['active']||$key['administrator']!==$a['administrator']||!SecretsBackendCodec::same($a['head'],$current['head']))throw new RuntimeException('Credential enrollment approval expired or its authorizer changed.');
        if(in_array(true,$current['state']['policy']['hardware'],true)&&(!$a['hardware']||!$key['hardware']))throw new RuntimeException('Credential enrollment requires the current hardware approval.');
    }
    private function enrollmentOptions(array $data): array
    {
        self::exact($data, ['code']); $token = $this->store->get(hash('sha256', $data['code']), 'enrollment');
        $current = $this->store->read(); $this->enrollmentAuthority($token,$current); $auth = $this->webauthn($token['hardware']); $user = random_bytes(32);
        $args = $auth->getCreateArgs($user, $token['label'], $token['label'], 120, 'preferred', true, $token['hardware'] ? true : null,
            array_map(static fn($c) => SecretsBackendCodec::unb64($c['id']), array_values($current['state']['identity']['credentials'])));
        if ($token['hardware'] || ($token['probe'] ?? false)) $args->publicKey->attestation = 'direct';
        $id = SecretsBackendCodec::b64(random_bytes(32));
        $this->store->put($id, 'registration', ['tokenHash' => hash('sha256', $data['code']), 'challenge' => SecretsBackendCodec::b64($auth->getChallenge()->getBinaryString()),
            'head' => $current['head'], 'userHandle' => SecretsBackendCodec::b64($user), 'label' => $token['label'], 'probe' => $token['probe'] ?? false, 'hardware' => $token['hardware']], time() + 120);
        return ['challengeId' => $id, 'options' => $args->publicKey];
    }
    private function enrollmentVerify(array $data): array
    {
        self::exact($data, ['challengeId', 'credential']);
        $registration = $this->store->get($data['challengeId'], 'registration', true);
        $token=$this->store->get($registration['tokenHash'], 'enrollment', true);
        $this->enrollmentAuthority($token,$this->store->read());
        $credential = $data['credential']; self::exact($credential, ['type', 'rawId', 'response']); self::exact($credential['response'], ['clientDataJSON', 'attestationObject']);
        $client = SecretsBackendCodec::unb64($credential['response']['clientDataJSON']); $object = SecretsFrontendConfiguration::decode($client);
        if ($credential['type'] !== 'public-key' || ($object['type'] ?? '') !== 'webauthn.create' || ($object['challenge'] ?? '') !== $registration['challenge']
            || ($object['origin'] ?? '') !== $this->settings['origin'] || ($object['crossOrigin'] ?? false) !== false) throw new RuntimeException('Registration context mismatch.');
        $verifier = $this->webauthn($registration['hardware']);
        $created = $verifier->processCreate($client, SecretsBackendCodec::unb64($credential['response']['attestationObject']), SecretsBackendCodec::unb64($registration['challenge'], 32), true, true, true);
        $id = SecretsBackendCodec::b64($created->credentialId);
        if ($id !== $credential['rawId'] || !SecretsPortalSecurity::validateBackupFlags($created->isBackupEligible, $created->isBackedUp)) throw new RuntimeException('Registration credential mismatch.');
        $aaguid = bin2hex($created->AAGUID);
        if ($registration['hardware']) {
            SecretsBackendHardwareTrust::verify(SecretsBackendCodec::unb64($credential['response']['attestationObject']),
                $this->settings['hardwareRoots'], $this->settings['hardwareAAGUIDs'], $created->AAGUID);
            if ($created->isBackupEligible) throw new RuntimeException('Backup-eligible credentials cannot approve hardware actions.');
        }
        $current = $this->store->read();
        $entry = ['id' => $id, 'publicKey' => $created->credentialPublicKey, 'label' => $registration['label'], 'active' => true, 'administrator' => $current['state']['identity']['ownerId'],
            'hardware' => $registration['hardware'], 'aaguid' => $aaguid, 'attestationFormat' => $created->attestationFormat,
            'attestationEvidence' => $credential['response']['attestationObject'], 'trustVersion' => $this->settings['hardwareTrustVersion'] ?? 'none',
            'tested' => false, 'counter' => (int)($created->signatureCounter ?? 0), 'backupEligible' => $created->isBackupEligible, 'userHandle' => $registration['userHandle']];
        $this->store->change($registration['head'], SecretsBackendCodec::uuid(), hash('sha256', SecretsBackendCodec::json($entry)), static function (array $state) use ($id, $entry): array {
            if (isset($state['identity']['credentials'][$id])) throw new RuntimeException('Credential already exists.');
            $state['identity']['credentials'][$id] = $entry; $state['identity']['revocation'] = SecretsBackendCodec::increment($state['identity']['revocation']); return $state;
        }, $this->audit('enroll-recovery', 'independent-console-recovery', $id));
        return ['registered' => true];
    }
    private function nativeCandidate(string $action,array $data,array $session,array $current): array
    {
        if(!($this->store instanceof SecretsBackendNativeStore))throw new RuntimeException('Native candidates require the native backend.');
        if($action==='nativeCandidateOptions'){
            self::exact($data,['label','hardware','probe']);
            if(!is_string($data['label'])||$data['label']===''||strlen($data['label'])>80||preg_match('/[\x00-\x1f]/',$data['label'])||!is_bool($data['hardware'])||!is_bool($data['probe'])||($data['hardware']&&$data['probe']))throw new RuntimeException('Invalid candidate settings.');
            $auth=$this->webauthn($data['hardware']);$user=SecretsBackendCodec::b64(random_bytes(32));
            $args=$auth->getCreateArgs(SecretsBackendCodec::unb64($user),$data['label'],$data['label'],90,'preferred',true,$data['hardware']?true:null,array_map(static fn($c)=>SecretsBackendCodec::unb64($c['id']),array_values($current['state']['identity']['credentials'])));
            if($data['hardware']||$data['probe'])$args->publicKey->attestation='direct';
            $id=SecretsBackendCodec::b64(random_bytes(32));$ctx=['challenge'=>SecretsBackendCodec::b64($auth->getChallenge()->getBinaryString()),'origin'=>$this->settings['origin'],'owner'=>$session['administrator'],'userHandle'=>$user];
            $this->store->put($id,'candidate-prepare',['session'=>$session['hash'],'context'=>$ctx,'settings'=>$data,'head'=>$current['head']],time()+90);
            return ['prepare'=>$id,'options'=>$args->publicKey];
        }
        self::exact($data,['prepare','key','credential','signature']);$p=$this->store->get($data['prepare'],'candidate-prepare');
        if($p['session']!==$session['hash']||!SecretsBackendCodec::same($p['head'],$current['head']))throw new RuntimeException('Candidate preparation context changed.');
        $key=SecretsBootstrapVerifier::publicKey($data['key']);
        $bytes="SECF.ADDKEY.SUBMIT.1\n".$this->settings['origin']."\n".$data['prepare']."\n".$p['context']['challenge']."\n".$key['digest']."\n".SecretsBootstrapVerifier::digest($data['credential'])."\n";
        SecretsBootstrapVerifier::verifySignature($bytes,$data['signature'],$data['key']);
        $entry=SecretsBootstrapVerifier::registration($data['credential'],$p['context']);$entry['label']=$p['settings']['label'];$entry['origin']=$this->settings['origin'];$entry['originGeneration']=$this->originGeneration($current['state']);if($entry['origin']!==$this->primaryOrigin())$entry['rights']=SecretsBackendBackupOriginPolicy::FULL_RIGHTS;
        $entry['hardware']=$p['settings']['hardware'];$entry['trustVersion']=$this->settings['hardwareTrustVersion']??'none';
        if($entry['hardware']){
            if($entry['backupEligible'])throw new RuntimeException('Hardware candidates cannot be backup eligible.');
            SecretsBackendHardwareTrust::verify(SecretsBackendCodec::unb64($data['credential']['response']['attestationObject']),$this->settings['hardwareRoots'],$this->settings['hardwareAAGUIDs'],hex2bin($entry['aaguid']));
        }
        if(isset($current['state']['identity']['credentials'][$entry['id']]))throw new RuntimeException('This credential already exists.');
        $this->store->get($data['prepare'],'candidate-prepare',true);
        $candidate=SecretsBackendCodec::b64(random_bytes(32));$body=['entry'=>$entry,'keyDigest'=>$key['digest'],'registrationDigest'=>SecretsBootstrapVerifier::digest($data['credential']),'session'=>$session['hash'],'head'=>$current['head']];
        $digest=SecretsBootstrapVerifier::digest($body);$this->store->put($candidate,'key-candidate',$body,time()+300);
        return ['candidate'=>$candidate,'digest'=>$digest,'label'=>$entry['label'],'keyDigest'=>$key['digest']];
    }
    private function audit(string $action, string $actor, string $target): array
    {
        return ['action' => $action, 'actor' => $actor, 'target' => $target,
            'backend' => $this->settings['backend'], 'frontend' => $this->settings['frontend']];
    }
    public function handle(string $action, array $data, array $request): array
    {
        $this->rejectionContext = [];
        $this->requestContext = ['stage'=>'origin','authenticated'=>false,'csrfVerified'=>false,'operation'=>null];
        try { return $this->dispatch($action, $data, $request); }
        catch (Throwable $exception) {
            try { $this->store->auditRejected($this->rejectionContext); } catch (Throwable $ignored) {}
            throw $exception;
        }
    }
    private function dispatch(string $action, array $data, array $request): array
    {
        if (($request['origin'] ?? '') !== $this->settings['origin']) throw new RuntimeException('Origin mismatch.');
        $this->requestContext['stage']='rate';
        $this->store->rate(hash('sha256', ($request['remote'] ?? '') . ':' . $action), in_array($action, ['authOptions', 'authVerify', 'enrollmentOptions', 'enrollmentVerify','connectOptions','connectSubmit','connectProof'], true) ? 10 : 120);
        $this->requestContext['stage']='storage';
        $current = $this->store->read();
        $this->requestContext['stage']='configuration';
        if (isset($this->settings['managementProfile']) && SecretsBackendSecurityConfiguration::digest($this->settings['managementProfile']) !== SecretsBackendSecurityConfiguration::digest($current['state']['policy']['management'])) throw new RuntimeException('Security profile changed; repeat complete validation.');
        if ($current['state']['policy']['origin'] !== $this->primaryOrigin() || $current['state']['policy']['frontend'] !== (string)$this->settings['frontend']) throw new RuntimeException('Protected origin or frontend binding differs; use independent recovery.');
        $this->checkRoute($current['state'], $action);
        if (in_array($action, ['connectOptions','connectSubmit','connectProof','connectStatus'], true)) return ['data'=>$this->connectEnrollment($action, $data, $current)];
        if ($action === 'status') { self::exact($data, []); return ['data' => ['ready' => true, 'enrollmentNeeded' => count($current['state']['identity']['credentials']) === 0]]; }
        if ($this->store instanceof SecretsBackendNativeStore && in_array($action,['enrollmentOptions','enrollmentVerify'],true)) throw new RuntimeException('Code-based enrollment is closed.');
        if ($action === 'enrollmentOptions') return ['data' => $this->enrollmentOptions($data)];
        if ($action === 'enrollmentVerify') return ['data' => $this->enrollmentVerify($data)];
        if ($action === 'portalAuthOptions') {
            self::exact($data, []);
            // Reuse only a currently valid, origin-bound full session. This
            // predicate neither extends its lifetime nor builds a vault view.
            if ($this->portalAuthenticated($request)) return ['data'=>['authenticated'=>true]];
            $eligible = array_filter($current['state']['identity']['credentials'], fn(array $entry): bool => $this->settings['origin'] === $this->primaryOrigin() || SecretsBackendBackupOriginPolicy::credentialFull($current['state'], $entry));
            if (!$eligible) throw new RuntimeException('No full-access passkey is approved at this address.');
            // New login challenges share the existing limit; ordinary session
            // reuse does not consume the passkey ceremony allowance.
            $this->store->rate(hash('sha256', ($request['remote'] ?? '') . ':authOptions'), 10);
            return ['data'=>$this->challenge($current, $eligible, false, 'login', [])];
        }
        if ($action === 'authOptions') { self::exact($data, []); return ['data' => $this->challenge($current, $current['state']['identity']['credentials'], false, 'login', [])]; }
        if ($action === 'authVerify') {
            $this->requestContext['stage']='login';
            self::exact($data, ['challengeId', 'credential']); $challenge = $this->store->get($data['challengeId'], 'login', true);
            $id = $data['credential']['rawId'] ?? ''; $entry = $current['state']['identity']['credentials'][$id] ?? null;
            if (!is_array($entry) || !$entry['active']) throw new RuntimeException('Credential is not an administrator.');
            $this->rejectionContext = $this->audit('login', $id, 'session');
            $counter = $this->credential($entry, $challenge, $data['credential'],true);
            $committed = $this->store->change($challenge['head'], SecretsBackendCodec::uuid(), hash('sha256', $data['challengeId']), static function (array $state) use ($id, $counter): array { $state['identity']['credentials'][$id]['counter'] = $counter; $state['identity']['credentials'][$id]['tested'] = true; return $state; }, $this->audit('login', $id, 'session'));
            $current = $this->store->read();
            if (!SecretsBackendCodec::same($current['head'], $committed)) throw new RuntimeException('Login state changed before authorization.');
            $this->store->authorize('login', hash('sha256', $id . ':' . $data['challengeId']), $current, static function (array $checked) use ($id, $entry): void {
                if (($checked['state']['identity']['credentials'][$id]['active'] ?? false) !== true
                    || $checked['state']['identity']['credentials'][$id]['administrator'] !== $entry['administrator']) throw new RuntimeException('Login credential was revoked.');
            }, $this->audit('login', $id, 'session'));
             $raw = SecretsBackendCodec::b64(random_bytes(32)); $csrf = SecretsBackendCodec::b64(random_bytes(32));
            $this->store->put(hash('sha256', $raw), 'session', ['credential' => $id, 'administrator' => $entry['administrator'], 'revocation' => $current['state']['identity']['revocation'], 'csrf' => $csrf,
                'origin' => $this->settings['origin'], 'originGeneration'=>$this->originGeneration($current['state']), 'created' => time(), 'last' => time()], time() + 3600);
            return ['data' => ['authenticated' => true, 'portalAuthenticated' => $this->settings['origin'] === $this->primaryOrigin() || SecretsBackendBackupOriginPolicy::credentialFull($current['state'], $entry), 'csrf' => $csrf], 'cookie' => $this->cookieName() . '=' . $raw . '; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600'];
        }
        $this->requestContext['stage']='session';
        $session = $this->session($request, $current);
        $this->requestContext['authenticated']=true;
        $native = $this->settings['nativeOps'] ?? null;
        if ($native instanceof SecretsBackendNativeOperations) $native->bindSession($session['hash']);
        $this->rejectionContext = $this->audit('request', $session['credential'], 'management');
        $this->requestContext['stage']='csrf';
        if ($action !== 'session') { $this->requireCsrf($request, $session); $this->requestContext['csrfVerified']=true; }
        $this->requestContext['stage']='action';
        if ($this->settings['origin'] !== $this->primaryOrigin() && !SecretsBackendBackupOriginPolicy::credentialFull($current['state'],$current['state']['identity']['credentials'][$session['credential']]) && !in_array($action,['session','list','sessionReveal','sessionTimeout','prepare','approve','logout','nativeOverviewStatus'],true)) throw new RuntimeException('Use the primary address for setup and integration management.');
        if ($action === 'connectCandidateReview') { self::exact($data,['candidate']); $c=$this->connectCandidate($data['candidate'],$current['state']); return ['data'=>['candidate'=>$data['candidate'],'digest'=>SecretsBootstrapVerifier::digest($c),'label'=>$c['entry']['label'],'origin'=>$c['origin'],'administrator'=>$c['entry']['administrator'],'rights'=>$c['rights'],'fingerprint'=>hash('sha256',$c['entry']['publicKey'])]]; }
        if ($action === 'connectDiscovery') { self::exact($data, []); return ['data'=>['permitted'=>true]]; }
        if ($native instanceof SecretsBackendNativeOperations && in_array($action, ['nativeSetupPreview','nativeSetupRun','nativeSupportStatus','nativeSupportUpload','nativeSupportUploadStatus','nativeOverviewStatus','nativeGlobalStatus','nativePairingStatus','nativeRetryPeerDelivery','legacySources','legacyPreview','nativeUploadBegin','nativeUploadChunk','nativeUploadFinish','nativeOperationStatus'], true)) return ['data' => $native->request($action, $data)];
        if (in_array($action,['nativeCandidateOptions','nativeCandidateSubmit'],true)) return ['data'=>$this->nativeCandidate($action,$data,$session,$current)];
        if ($action === 'logout') { self::exact($data, []); $this->store->delete($session['hash']); return ['data' => ['loggedOut' => true], 'cookie' => $this->cookieName() . '=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0']; }
        if ($action === 'sessionTimeout') {
            if (!($this->store instanceof SecretsBackendNativeStore)) throw new RuntimeException('Session settings are available only for the native vault.');
            self::exact($data, ['seconds']);
            if (!is_int($data['seconds']) || !in_array($data['seconds'], [60, 300, 900], true)) throw new InvalidArgumentException('Choose 1, 5 or 15 minutes.');
            $updated = $this->store->refreshAdministratorSession($session['hash'], $data['seconds']);
            return ['data' => ['idleLimit' => $updated['idleLimit']]];
        }
        if ($action === 'sessionReveal') {
            if (!($this->store instanceof SecretsBackendNativeStore)) throw new RuntimeException('Session reveal is available only for the native vault.');
            self::exact($data, ['operation']);
            if (!is_array($data['operation']) || !in_array($data['operation']['kind'] ?? null, ['reveal', 'nativeReveal','nativeGlobalReveal'], true)) throw new InvalidArgumentException('Only an exact reveal is permitted.');
            $operation = $this->operation($data['operation'], $current['state']);
            if ($current['state']['policy']['hardware']['reveal']) return ['data' => ['requiresHardware' => true]];
            $target = SecretsBackendCodec::json(array_intersect_key($operation, array_flip(['kind','scope','treeId','path'])));
            $this->rejectionContext = $this->audit('reveal', $session['credential'], $target);
            $this->store->authorize('reveal', hash('sha256', SecretsBackendCodec::json($operation)), $current,
                function (array $checked) use ($request, $data): void {
                    $this->session($request, $checked);
                    if ($checked['state']['policy']['hardware']['reveal']) throw new RuntimeException('Hardware approval is now required.');
                    $this->operation($data['operation'], $checked['state']);
                }, $this->audit('reveal', $session['credential'], $target));
            $this->store->refreshAdministratorSession($session['hash']);
            if (in_array($operation['kind'],['nativeReveal','nativeGlobalReveal'],true)) return ['data' => $native->result($operation, $current)];
            return ['data' => ['fields' => SecretsBackendTree::reveal(SecretsBackendTree::at($operation['scope']==='global'&&isset($current['state']['native'])?SecretsBackendSharedGlobal::available($current['state']):$current['state']['vault'][$operation['scope']], $operation['path'])), 'clearAfterSeconds' => 30]];
        }
        if ($action === 'session' || $action === 'list') {
            self::exact($data, []); $this->store->authorize('metadata', hash('sha256', $session['hash'] . ':' . $current['head']['digest']), $current,
                function (array $checked) use ($request): void { $this->session($request, $checked); }, $this->audit('metadata', $session['credential'], 'listing'));
            if ($this->store instanceof SecretsBackendNativeStore) $session = $this->store->refreshAdministratorSession($session['hash']) + ['hash' => $session['hash']];
            else { $session['last'] = time(); $this->store->replace($session['hash'], 'session', array_diff_key($session, ['hash' => true]), $session['created'] + 3600); }
            return ['data' => ['authenticated' => true, 'csrf' => $session['csrf'], 'idleLimit' => (int)($session['idleLimit'] ?? 900), 'revision' => $current['state']['vault']['revision'], 'hardware' => $current['state']['policy']['hardware'],
                'global' => SecretsBackendTree::listing(isset($current['state']['native'])?SecretsBackendSharedGlobal::available($current['state']):$current['state']['vault']['global']), 'local' => SecretsBackendTree::listing($current['state']['vault']['local']),
                'native' => $native instanceof SecretsBackendNativeOperations ? $native->metadata($current['state']) : null,
                'credentials' => array_map(static fn($c) => array_intersect_key($c, array_flip(['id', 'label', 'active', 'hardware', 'aaguid', 'trustVersion', 'tested'])), array_values($current['state']['identity']['credentials']))]];
        }
        if ($action === 'configurationPreview') {
            self::exact($data, []); $candidate = $this->candidateProfile($current['state']);
            $this->store->authorize('metadata', SecretsBackendSecurityConfiguration::digest($candidate), $current,
                function (array $checked) use ($request): void { $this->session($request, $checked); }, $this->audit('metadata', $session['credential'], 'configuration-preview'));
            return ['data' => ['profile' => $candidate, 'digest' => SecretsBackendSecurityConfiguration::digest($candidate)]];
        }
        if ($action === 'prepare') {
            $this->requestContext['stage']='prepare';
            $this->requestContext['operation']=$data['operation']['kind']??null;
            self::exact($data, ['operation']); $operation = $this->operation($data['operation'], $current['state']);
            $this->rejectionContext = $this->audit($operation['kind'], $session['credential'], SecretsBackendCodec::json(array_intersect_key($operation, array_flip(['kind', 'scope', 'path', 'credentialId']))));
            if ($this->settings['origin'] !== $this->primaryOrigin() && !SecretsBackendBackupOriginPolicy::credentialFull($current['state'],$current['state']['identity']['credentials'][$session['credential']]) && !in_array($operation['kind'],['save','delete','rename','reveal','nativeReveal','nativeGlobalReveal','nativeGlobalResolve','nativeBackup'],true)) throw new RuntimeException('Use the primary address for administrator changes.');
            $class = str_starts_with($operation['kind'], 'native') && $native instanceof SecretsBackendNativeOperations ? SecretsBackendNativeOperations::actionClass($operation['kind']) : (in_array($operation['kind'], ['save', 'delete', 'rename'], true) ? 'write' : ($operation['kind'] === 'reveal' ? 'reveal' : 'identity'));
            $hardware = $class === 'identity' ? in_array(true, $current['state']['policy']['hardware'], true) : $current['state']['policy']['hardware'][$class];
            if ($operation['kind'] === 'policy' && in_array(true, $operation['hardware'], true)) $hardware = true;
            $eligible = array_filter($current['state']['identity']['credentials'], static fn($credential) => $credential['administrator'] === $session['administrator']);
            $operationId = SecretsBackendCodec::uuid();
            $args = $this->challenge($current, $eligible, $hardware, 'approval',
                ['session' => $session['hash'], 'operation' => $operation, 'operationId' => $operationId]);
            return ['data' => $args + ['requiresHardware' => $hardware, 'operationId' => $operationId, 'reviewSummary' => str_starts_with($operation['kind'], 'native') && $native instanceof SecretsBackendNativeOperations ? $native->summary($operation) : null]];
        }
        if ($action === 'approve') {
            $this->requestContext['stage']='approval';
            self::exact($data, ['challengeId', 'credential']); $challenge = $this->store->get($data['challengeId'], 'approval', true);
            $this->requestContext['operation']=$challenge['context']['operation']['kind']??null;
            if ($challenge['context']['session'] !== $session['hash']) throw new RuntimeException('Approval belongs to a different session.');
            $approvalCredential = $data['credential']['rawId'] ?? '';
            $entry = $current['state']['identity']['credentials'][$approvalCredential] ?? null;
            if (!is_array($entry) || !$entry['active'] || $entry['administrator'] !== $session['administrator']) throw new RuntimeException('Approval administrator mismatch.');
            $counter = $this->credential($entry, $challenge, $data['credential']); $operation = $this->operation($challenge['context']['operation'], $current['state'], true);
            $this->rejectionContext = $this->audit($operation['kind'], $approvalCredential, SecretsBackendCodec::json(array_intersect_key($operation, array_flip(['kind', 'scope', 'path', 'credentialId']))));
            $id = $approvalCredential; $operationId = $challenge['context']['operationId'];
            $digest = hash('sha256', SecretsBackendCodec::json(['operation' => $operation, 'session' => $session['hash'], 'credential' => $id, 'approval' => $data['challengeId']]));
            $commit = fn() => $this->store->change($challenge['head'], $operationId, $digest, function (array $state) use ($operation, $id, $counter): array {
                $state = $this->apply($operation, $state); $state['identity']['credentials'][$id]['counter'] = $counter; $state['identity']['credentials'][$id]['tested'] = true; return $state;
            }, $this->audit($operation['kind'], $id, SecretsBackendCodec::json(array_intersect_key($operation, array_flip(['kind', 'scope', 'path', 'credentialId'])))));
            $this->requestContext['stage']='commit';
            $committed = $native instanceof SecretsBackendNativeOperations ? $native->commit($operation,$commit) : $commit();
            $this->requestContext['stage']='result';
            if ($operation['kind'] === 'nativeEnrollment') return ['data'=>['committed'=>true,'operationId'=>$operationId,'reloginRequired'=>true]];
            if ($operation['kind'] === 'reveal') {
                $latest = $this->store->read();
                if (!SecretsBackendCodec::same($latest['head'], $committed)) throw new RuntimeException('Reveal state changed before authorization.');
                $this->store->authorize('reveal', $digest, $latest, function (array $checked) use ($request, $id, $challenge): void {
                    $session = $this->session($request, $checked);
                    $credential = $checked['state']['identity']['credentials'][$id] ?? null;
                    if (!is_array($credential) || !$credential['active'] || $credential['administrator'] !== $session['administrator']
                        || ($checked['state']['policy']['hardware']['reveal'] && (!$challenge['hardware'] || !$credential['hardware']))) throw new RuntimeException('Reveal authority changed.');
                }, $this->audit('reveal', $id, SecretsBackendCodec::json([$operation['scope'], $operation['path']])));
                // The protected counter commit is not permission to read a different record revision.
                if ($latest['state']['vault']['revision'] !== $operation['revision']) throw new RuntimeException('Record changed before reveal.');
                return ['data' => ['fields' => SecretsBackendTree::reveal(SecretsBackendTree::at($operation['scope']==='global'&&isset($latest['state']['native'])?SecretsBackendSharedGlobal::available($latest['state']):$latest['state']['vault'][$operation['scope']], $operation['path'])), 'clearAfterSeconds' => 30]];
            }
            if (str_starts_with($operation['kind'], 'native') && $native instanceof SecretsBackendNativeOperations) {
                $latest = $this->store->read();
                if (!SecretsBackendCodec::same($latest['head'], $committed)) throw new RuntimeException('Native operation state changed before its result could be disclosed.');
                $this->store->authorize(SecretsBackendNativeOperations::actionClass($operation['kind']), $digest, $latest,
                    function(array $checked) use($request,$id):void{$session=$this->session($request,$checked);$key=$checked['state']['identity']['credentials'][$id]??null;if(!is_array($key)||!$key['active']||$key['administrator']!==$session['administrator'])throw new RuntimeException('Native result authority changed.');},
                    $this->audit($operation['kind'],$id,'native-result'));

                return ['data' => ['committed'=>true,'operationId'=>$operationId]+$native->result($operation,$latest)];
            }
            return ['data' => ['committed' => true, 'operationId' => $operationId]];
        }
        throw new InvalidArgumentException('Unknown frontend action.');
    }
    private function operation(array $operation, array $state, bool $stored = false): array
    {
        $kind = $operation['kind'] ?? '';
        if (is_string($kind) && str_starts_with($kind, 'native') && ($this->settings['nativeOps'] ?? null) instanceof SecretsBackendNativeOperations) return $this->settings['nativeOps']->normalize($operation, $state, $stored);
        if (in_array($kind, ['save', 'delete', 'rename', 'reveal'], true)) {
            self::exact($operation, $kind === 'save' ? ['kind', 'scope', 'path', 'revision', 'mode', 'json'] : ($kind==='rename'?['kind','scope','path','revision','newName']:['kind', 'scope', 'path', 'revision']));
            if (!in_array($operation['scope'], ['global', 'local'], true) || !is_array($operation['path']) || (!$operation['path'] && $kind !== 'reveal') || !is_string($operation['revision']) || $operation['revision'] !== $state['vault']['revision']) throw new RuntimeException('Invalid scope or stale revision.');
            SecretsBackendTree::path($operation['path']);
            if($operation['scope']==='global'&&isset($state['native']['sharedGlobal']))SecretsBackendSharedGlobal::assertPath($state,$operation['path'],$kind==='reveal');
            if ($kind === 'save') { if (!is_string($operation['json']) || !in_array($operation['mode'], ['create', 'replace'], true)) throw new InvalidArgumentException('Invalid save.'); SecretsBackendTree::parse($operation['json']); }
            elseif($kind==='rename'){if(!is_string($operation['newName']))throw new InvalidArgumentException('Enter a folder name.');$copy=$state['vault'][$operation['scope']];SecretsBackendTree::rename($copy,$operation['path'],$operation['newName']);}
            else SecretsBackendTree::at($state['vault'][$operation['scope']], $operation['path']);
        } elseif ($kind === 'revoke') {
            self::exact($operation, ['kind', 'credentialId']);
            if (!isset($state['identity']['credentials'][$operation['credentialId']])) throw new RuntimeException('Unknown credential.');
        } elseif ($kind === 'configuration') {
            self::exact($operation, ['kind', 'profile']);
            if (!is_array($operation['profile']) || SecretsBackendSecurityConfiguration::digest($operation['profile']) !== SecretsBackendSecurityConfiguration::digest($this->candidateProfile($state))) throw new RuntimeException('Security configuration candidate changed; review again.');
        } elseif ($kind === 'policy') {
            self::exact($operation, ['kind', 'hardware']); self::exact($operation['hardware'], ['write', 'identity', 'export', 'reveal']);
            foreach ($operation['hardware'] as $required) if (!is_bool($required)) throw new InvalidArgumentException('Invalid hardware policy.');
        } else throw new InvalidArgumentException('Unknown operation.');
        return $operation;
    }
    private function candidateProfile(array $state): array
    {
        if (!is_callable($this->settings['candidateProfile'] ?? null) || !is_array($state['policy']['management'])) throw new RuntimeException('Security configuration changes are unavailable.');
        $candidate = ($this->settings['candidateProfile'])(); $old = $state['policy']['management'];
        if(in_array(true,$state['policy']['hardware'],true)&&SecretsBackendSecurityConfiguration::digest($old)!==SecretsBackendSecurityConfiguration::digest($candidate))throw new RuntimeException('Hardware enforcement is active; trust profile replacement is blocked.');
        if (!SecretsBackendSecurityConfiguration::sameFoundation($old['settings'], $candidate['settings'])
            || SecretsBackendSecurityConfiguration::digest($old['frontendSecurity']) !== SecretsBackendSecurityConfiguration::digest($candidate['frontendSecurity'])) throw new RuntimeException('Foundation changes require independent reprovisioning, not ordinary configuration import/apply.');
        if (SecretsBackendSecurityConfiguration::digest($old) !== SecretsBackendSecurityConfiguration::digest($candidate)
            && $old['settings']['HardwareTrustVersion'] === $candidate['settings']['HardwareTrustVersion']) throw new RuntimeException('Every hardware trust-profile change requires a new reviewed revision.');
        if ($old['settings']['HardwareTrustVersion'] !== $candidate['settings']['HardwareTrustVersion']) {
            foreach ($state['identity']['credentials'] as $credential) if ($credential['hardware'] && $credential['trustVersion'] === $candidate['settings']['HardwareTrustVersion']) throw new RuntimeException('Hardware trust revisions already used by credentials cannot be reused.');
        }
        return $candidate;
    }
    private function apply(array $operation, array $state): array
    {
        if (str_starts_with($operation['kind'], 'native') && ($this->settings['nativeOps'] ?? null) instanceof SecretsBackendNativeOperations) return $this->settings['nativeOps']->apply($operation, $state);
        if (in_array($operation['kind'], ['save', 'delete', 'rename'], true)) {
            if ($operation['scope'] === 'global' && isset($state['native']) && !$state['native']['globalWritable']) throw new RuntimeException('This global tree is frozen or owned by a different vault.');
            if($operation['kind']==='rename')SecretsBackendTree::rename($state['vault'][$operation['scope']],$operation['path'],$operation['newName']);
            else SecretsBackendTree::edit($state['vault'][$operation['scope']], $operation['path'], $operation['kind'] === 'save' ? SecretsBackendTree::parse($operation['json']) : null, $operation['kind'] === 'save' ? $operation['mode'] : 'delete');
            $state['vault']['revision'] = SecretsBackendCodec::increment($state['vault']['revision']);
            if ($operation['scope'] === 'global') {
                $state['stream']['globalRevision'] = SecretsBackendCodec::increment($state['stream']['globalRevision']);
                // Every configured peer receives an immutable complete snapshot in this SAME core.
                if (isset($state['native']['vaultId']) && class_exists(SecretsBackendNativePeer::class)) $state = SecretsBackendNativePeer::queueGlobal($state);
                else foreach ($state['pairing']['peers'] as $peer) {
                    if (!$peer['active']) continue;
                    $sequence = $state['stream']['next'][$peer['id']] ?? '0'; $sequence = SecretsBackendCodec::increment($sequence); $state['stream']['next'][$peer['id']] = $sequence;
                    $snapshot = SecretsBackendCodec::json($state['vault']['global']);
                    $state['outbox']['jobs'][] = ['operationId' => SecretsBackendCodec::uuid(), 'receiverId' => $peer['id'], 'pairingId' => $peer['pairingId'], 'epoch' => $peer['epoch'],
                        'sourceRevision' => $state['stream']['globalRevision'], 'sequence' => $sequence, 'payloadDigest' => hash('sha256', $snapshot), 'snapshot' => $snapshot, 'status' => 'queued'];
                }
            }
        } elseif ($operation['kind'] === 'revoke') {
            $state['identity']['credentials'][$operation['credentialId']]['active'] = false;
            $active = array_filter($state['identity']['credentials'], fn($credential) => $credential['active'] && (!isset($state['native'])||SecretsBackendBackupOriginPolicy::credentialFull($state,$credential)) && (!isset($state['native'])||($credential['tested']??false)===true));
            if (!$active || (in_array(true, $state['policy']['hardware'], true) && !array_filter($active, fn($credential) => $credential['hardware'] && $credential['trustVersion']===($this->settings['hardwareTrustVersion']??'none')))) throw new RuntimeException('Cannot revoke the last eligible administrator.');
            $state['identity']['revocation'] = SecretsBackendCodec::increment($state['identity']['revocation']);
        } elseif ($operation['kind'] === 'configuration') {
            if(in_array(true,$state['policy']['hardware'],true)&&SecretsBackendSecurityConfiguration::digest($state['policy']['management'])!==SecretsBackendSecurityConfiguration::digest($operation['profile']))throw new RuntimeException('Hardware enforcement is active; trust profile replacement is blocked.');
            $state['policy']['management'] = $operation['profile'];
            $state['policy']['version'] = SecretsBackendCodec::increment($state['policy']['version']);
        } elseif ($operation['kind'] === 'policy') {
            $eligible = array_filter($state['identity']['credentials'], fn($credential) => $credential['active'] && $credential['hardware'] && $credential['trustVersion'] === ($this->settings['hardwareTrustVersion'] ?? 'none'));
            if (($this->settings['nativeOps'] ?? null) instanceof SecretsBackendNativeOperations) $eligible = array_filter($eligible, static fn($c) => ($c['tested'] ?? false) === true && SecretsBackendBackupOriginPolicy::credentialFull($state,$c));
            if (in_array(true, $operation['hardware'], true) && count($eligible) < 2) throw new RuntimeException('Enroll and test two separate approved hardware credentials before enforcement.');
            $state['policy']['hardware'] = $operation['hardware']; $state['policy']['version'] = SecretsBackendCodec::increment($state['policy']['version']);
        }
        return $state;
    }
}
