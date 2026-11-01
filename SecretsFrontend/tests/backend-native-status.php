<?php
declare(strict_types=1);

// Reuse the lifecycle simulator loaded by guided-setup.php. A native settings
// instance must never enter legacy storage during apply, recovery or refusal.
class NativeBackendStatusProbe extends SecretsBackend
{
    public int $legacyStoreCalls = 0;
    protected function store(bool $allowDrift = false): SecretsBackendStore
    {
        ++$this->legacyStoreCalls;
        throw new RuntimeException('Unexpected legacy storage access from native setup.');
    }
}
$GLOBALS['moduleIDs'][3980] = '{52165EDD-B2C0-40EC-8A59-42A97319B6E2}';
$nativeStatus = new NativeBackendStatusProbe(3980); $nativeStatus->Create();
$nativeStatus->attributes['GuidedV2Only'] = true;
$nativeStatus->properties['Enabled'] = true; // Old console setting must not activate V1.
$nativeStatus->ApplyChanges();
secExpect($nativeStatus->status === 201 && $nativeStatus->timers['Recovery'] === 0, 'Native apply reported active/error or scheduled legacy recovery.');
secExpect(str_contains($nativeStatus->values['Status'], 'not initialized') && !str_contains($nativeStatus->values['Status'], 'SQLite'), 'Native status retained the misleading database diagnosis.');
secExpect(!$nativeStatus->Recover() && $nativeStatus->status === 201, 'Native recovery activated an unfinished vault.');
$nativeStatus->MessageSink(time(), 0, 10103, []);
secExpect($nativeStatus->timers['Recovery'] === 0, 'Runlevel notification scheduled legacy recovery in native mode.');

$GLOBALS['moduleIDs'][3981] = SecretsBackend::FRONTEND;
$nativeStatusFrontend = new SecretsFrontend(3981); $nativeStatusFrontend->Create();
$nativeStatusFrontend->properties['BackendInstanceID'] = 3980;
$nativeStatusFrontend->properties['AdminOrigin'] = 'https://wizard.example.test';
$nativeStatus->properties['FrontendInstanceID'] = 3981;
$nativeStatus->properties['AdminOrigin'] = 'https://wizard.example.test';
foreach (['status' => 200, 'authOptions' => 403] as $action => $expectedStatus) {
    $reply = json_decode($nativeStatus->HandleFrontendRequest(3981, json_encode(['action' => $action, 'data' => [], 'origin' => 'https://wizard.example.test', 'cookie' => '', 'csrf' => '', 'remote' => 'test'])), true);
    secExpect($reply['status'] === $expectedStatus, 'Native status/refusal semantics changed.');
    if ($action === 'status') secExpect($reply['data']['ready'] === false && $reply['data']['nativeBackendImplemented'] === true, 'Backend status overstated native readiness.');
}
secExpect($nativeStatus->legacyStoreCalls === 0 && $nativeStatus->timers['Recovery'] === 0 && $nativeStatus->status === 201, 'Native status/refusal entered legacy storage or scheduled recovery.');

$nativeForm = json_decode($nativeStatus->GetConfigurationForm(), true);
foreach ($nativeForm['status'] as $entry) secExpect(!preg_match('/sqlite|anchor|quorum/i', $entry['caption']), 'Generic backend status still prescribes an obsolete dependency.');
$nativeFields = []; $nativeButtons = [];
$walkNativeForm = static function (array $items) use (&$walkNativeForm, &$nativeFields, &$nativeButtons): void {
    foreach ($items as $item) {
        if (isset($item['name'])) $nativeFields[$item['name']] = $item;
        if (isset($item['onClick'])) $nativeButtons[$item['onClick']] = $item;
        if (isset($item['items'])) $walkNativeForm($item['items']);
    }
};
$walkNativeForm($nativeForm['elements']); $walkNativeForm($nativeForm['actions']);
secExpect($nativeFields['Enabled']['enabled'] === false, 'Native form offered the old backend activation switch.');
foreach (['SECB_BeginStorageSetup($id);', 'SECB_SecurityConfigurationDigest($id);', 'SECB_SealInitialSecurityConfiguration($id, $ProvisioningDigest);', 'SECB_Recover($id);', 'SECB_BeginAdminEnrollment($id, $AdminLabel, $HardwareEnrollment);'] as $script) {
    secExpect($nativeButtons[$script]['enabled'] === false, 'Native form offered an old activation action.');
}
secExpect(($nativeButtons['SECB_ExportConfiguration($id);']['enabled'] ?? true) === true, 'Native status correction disabled settings export.');
secExpect($nativeStatus->legacyStoreCalls === 0, 'Opening the native backend form accessed legacy storage.');
echo "PASS native backend form/status, apply/recovery/runlevel and refused requests: no SQLite diagnosis, activation or legacy storage/recovery fallback\n";
