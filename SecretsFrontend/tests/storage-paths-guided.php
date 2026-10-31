<?php
declare(strict_types=1);

// Loaded by the real commissioning simulator; all objects and paths are synthetic.
$pathRoot = sys_get_temp_dir() . '/secrets-path-guided-' . bin2hex(random_bytes(8));
mkdir($pathRoot, 0700); mkdir($pathRoot . '/same', 0700);
$GLOBALS['moduleIDs'][3001] = '{8D6AE8F7-EA3A-4513-AA14-C3F9613B0E83}';
$pathFrontend = new SecretsFrontend(3001); $pathFrontend->Create();
$GLOBALS['moduleIDs'][3002] = '{52165EDD-B2C0-40EC-8A59-42A97319B6E2}';
$pathBackend = new SecretsBackendTestModule(3002); $pathBackend->Create();
$pathCode = $pathFrontend->BeginGuidedSetup('https://wizard.example.test', '');
$pathGateway = new ReflectionMethod(SecretsFrontend::class, 'gateway');
$pathRequest = static fn(string $action, array $data): array => $pathGateway->invoke($pathFrontend, ['action' => $action, 'data' => $data, 'origin' => 'https://wizard.example.test', 'remote' => 'test', 'cookie' => '', 'csrf' => '']);
$pathChoice = ['backend' => 3002, 'portal' => 0, 'documentation' => 0, 'theme' => 'system', 'vaultDirectory' => $pathRoot . '/vault', 'keyDirectory' => $pathRoot . '/keys', 'proxyIPs' => [], 'addPortalLink' => false, 'debugEnabled' => false];
$pathBefore = [$pathBackend->properties, $pathBackend->attributes];
try {
    foreach ([[$pathRoot . '/same', $pathRoot . '//same'], [$pathRoot . '/same/child', $pathRoot . '//same'], [$pathRoot . '/new/child', $pathRoot . '//new'], ['/var//lib/symcon/new-vault', $pathRoot . '/keys']] as [$vaultPath, $keyPath]) {
        $badChoice = array_replace($pathChoice, ['vaultDirectory' => $vaultPath, 'keyDirectory' => $keyPath]);
        secExpect($pathRequest('guidedPreview', ['code' => $pathCode, 'configuration' => $badChoice])['status'] === 403, 'Reviewed preview accepted aliased storage paths.');
        $info = json_decode($pathBackend->GetInitialSetupInfo(), true);
        secReject(static fn() => $pathBackend->ConfigureInitialSetup(3001, $info['digest'], json_encode(['origin' => 'https://wizard.example.test', 'vaultDirectory' => $vaultPath, 'keyDirectory' => $keyPath, 'debugEnabled' => false])), 'Direct backend initial configuration accepted aliased paths.');
        secExpect([$pathBackend->properties, $pathBackend->attributes] === $pathBefore, 'Rejected storage paths changed applied settings or authority mode.');
    }
    $review = $pathRequest('guidedPreview', ['code' => $pathCode, 'configuration' => $pathChoice]);
    secExpect($review['status'] === 200, 'Valid separate-path preview failed.');
    symlink($pathRoot . '/same', $pathRoot . '/vault');
    secExpect($pathRequest('guidedApply', ['code' => $pathCode, 'planId' => $review['data']['planId']])['status'] === 403, 'Apply accepted a symlink introduced after preview.');
    secExpect([$pathBackend->properties, $pathBackend->attributes] === $pathBefore, 'Failed revalidation changed backend settings.');
    // Recheck the actual production creation entry point before any database/key write.
    $createStorage = new ReflectionMethod(SecretsBackend::class, 'initializeStorage');
    secReject(static fn() => $createStorage->invoke($pathBackend, ['vault' => $pathRoot . '/vault', 'keys' => $pathRoot . '/keys'], ['AdminOrigin' => 'https://wizard.example.test', 'FrontendInstanceID' => 3001]), 'Creation accepted a newly introduced symlink.');
    secExpect(!file_exists($pathRoot . '/same/master.key') && !file_exists($pathRoot . '/keys'), 'Rejected creation wrote key/state files.');
    unlink($pathRoot . '/vault');
    $normalizedChoice = array_replace($pathChoice, ['vaultDirectory' => $pathRoot . '//vault///', 'keyDirectory' => $pathRoot . '//keys/']);
    $review = $pathRequest('guidedPreview', ['code' => $pathCode, 'configuration' => $normalizedChoice]);
    secExpect($review['status'] === 200, 'Separate alias-normalized sibling paths were rejected.');
    $applied = $pathRequest('guidedApply', ['code' => $pathCode, 'planId' => $review['data']['planId']]);
    secExpect($applied['status'] === 200 && $pathBackend->properties['DataDirectory'] === $pathRoot . '/vault' && $pathBackend->properties['KeyDirectory'] === $pathRoot . '/keys' && !$pathBackend->properties['Enabled'], 'Reviewed apply failed to save canonical separate paths with activation disabled.');
    echo "PASS C-01 reviewed preview/direct apply reject aliases; symlink introduced before apply/creation is refused; valid siblings save canonical paths\n";
} finally {
    if (is_link($pathRoot . '/vault')) unlink($pathRoot . '/vault');
    rmdir($pathRoot . '/same'); rmdir($pathRoot);
}
