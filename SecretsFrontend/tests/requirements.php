<?php
declare(strict_types=1);
require_once __DIR__ . '/../Commissioning.php';

// Run with php -n: absent PDO/SQLite must not prevent native setup diagnostics.
if (extension_loaded('pdo_sqlite') || class_exists('PDO', false)) {
    throw new RuntimeException('Run this regression with php -n and no PDO extension.');
}
$requirements = SecretsFrontendCommissioning::requirements();
if ($requirements['scope'] !== 'settings-only' || $requirements['runtime'] !== 'symcon-native'
    || $requirements['nativeBackendImplemented'] !== true) {
    throw new RuntimeException('Setup diagnostics must report the available native implementation separately from vault initialization.');
}
foreach (['extensions', 'sqlite', 'legacyWalSupported', 'quorumConnected'] as $legacyField) {
    if (array_key_exists($legacyField, $requirements)) throw new RuntimeException('Legacy prerequisite leaked into native setup checks.');
}
foreach (['JSON', 'SHA-256', 'Secure randomness'] as $core) {
    if ($requirements['capabilities'][$core] !== true) throw new RuntimeException('Bundled PHP setup function reported unavailable.');
}
if ($requirements['capabilities']['Symcon semaphores'] !== (function_exists('IPS_SemaphoreEnter') && function_exists('IPS_SemaphoreLeave'))) {
    throw new RuntimeException('Unavailable Symcon APIs must not be reported as present.');
}
echo "PASS native setup diagnostics execute without PDO/SQLite or loaded extensions; actual setup capabilities remain separate from vault initialization\n";
