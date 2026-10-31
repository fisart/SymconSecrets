<?php
declare(strict_types=1);
require_once __DIR__ . '/Configuration.php';
require_once __DIR__ . '/Deployment.php';
require_once __DIR__ . '/../SecretsBackend/StoragePaths.php';

/** Settings-only initial commissioning. No vault, trust enrollment or runtime activation. */
final class SecretsFrontendCommissioning
{
    public static function digest(array $value): string { return hash('sha256', SecretsFrontendConfiguration::encode($value)); }
    public static function address(string $url): string
    {
        $parts = parse_url(trim($url));
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || isset($parts['user']) || isset($parts['pass']) || !isset($parts['host'])) throw new InvalidArgumentException('Paste the trusted HTTPS address you use for Symcon.');
        return SecretsFrontendConfiguration::origin('https://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : ''));
    }
    public static function proxies(string $text): array
    {
        $list = trim($text) === '' ? [] : array_map('trim', explode(',', $text));
        return SecretsFrontendConfiguration::validate(array_replace(SecretsFrontendConfiguration::DEFAULTS, ['TrustedHTTPSProxyIPs' => $list]))['TrustedHTTPSProxyIPs'];
    }
    public static function defaults(int $backend): array
    {
        return ['vaultDirectory' => '/var/lib/symcon-secrets-development/' . $backend . '/vault', 'keyDirectory' => '/var/lib/symcon-secrets-development-keys/' . $backend];
    }
    public static function paths(string $vault, string $keys, string $kernel): array
    {
        return SecretsBackendStoragePaths::pair($vault, $keys, $kernel);
    }
    public static function writable(string $path): bool
    {
        while (!file_exists($path) && dirname($path) !== $path) $path = dirname($path);
        return is_dir($path) && is_writable($path);
    }
    public static function requirements(): array
    {
        // This assistant saves settings only. Legacy SQLite/anchor diagnostics
        // do not describe the planned Symcon-native backend or its prerequisites.
        return ['php' => PHP_VERSION, 'phpSupported' => version_compare(PHP_VERSION, '8.2.0', '>='),
            'scope' => 'settings-only', 'runtime' => 'symcon-native', 'nativeBackendImplemented' => false,
            'capabilities' => [
                'JSON' => function_exists('json_encode') && function_exists('json_decode'),
                'SHA-256' => function_exists('hash') && function_exists('hash_equals') && function_exists('hash_algos') && in_array('sha256', hash_algos(), true),
                'Secure randomness' => function_exists('random_bytes'),
                'Symcon instance API' => function_exists('IPS_GetInstance') && function_exists('IPS_GetProperty') && function_exists('IPS_SetProperty') && function_exists('IPS_ApplyChanges'),
                'Symcon semaphores' => function_exists('IPS_SemaphoreEnter') && function_exists('IPS_SemaphoreLeave')]];
    }
    public static function choice(array $data): array
    {
        $fields = ['backend', 'portal', 'documentation', 'theme', 'vaultDirectory', 'keyDirectory', 'proxyIPs', 'addPortalLink', 'debugEnabled'];
        if (array_diff(array_keys($data), array_merge($fields, ['deployment'])) || array_diff($fields, array_keys($data))) throw new InvalidArgumentException('Unexpected setup fields.');
        foreach (['backend', 'portal', 'documentation'] as $key) if (!is_int($data[$key]) || $data[$key] < 0) throw new InvalidArgumentException('Choose an available instance.');
        foreach (['theme', 'vaultDirectory', 'keyDirectory'] as $key) if (!is_string($data[$key])) throw new InvalidArgumentException('Invalid setup text.');
        if (!is_bool($data['debugEnabled'])) throw new InvalidArgumentException('Choose a Boolean Debug setting.');
        if (!is_bool($data['addPortalLink'])) throw new InvalidArgumentException('Choose whether to add the Portal link.');
        SecretsFrontendConfiguration::validate(array_replace(SecretsFrontendConfiguration::DEFAULTS, ['Theme' => $data['theme'], 'TrustedHTTPSProxyIPs' => $data['proxyIPs']]));
        return $data;
    }
}
