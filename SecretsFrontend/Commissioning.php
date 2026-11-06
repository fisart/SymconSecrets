<?php
declare(strict_types=1);
require_once __DIR__ . '/Configuration.php';
require_once __DIR__ . '/Deployment.php';
require_once __DIR__ . '/../SecretsBackend/StoragePaths.php';
require_once __DIR__ . '/../SecretsBackend/NativePlatform.php';

/** Reviewed initial commissioning; native initialization is explicitly selected by the HTML wizard. */
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
        return SecretsBackendNativePlatform::defaults($backend, IPS_GetKernelDir());
    }
    public static function paths(string $vault, string $keys, string $kernel): array
    {
        try { return SecretsBackendNativePlatform::paths($vault, $keys, $kernel, true); }
        catch (RuntimeException $error) { throw new InvalidArgumentException($error->getMessage(), 0, $error); }
    }
    public static function writable(string $path): bool
    {
        while (!file_exists($path) && dirname($path) !== $path) $path = dirname($path);
        return is_dir($path) && is_writable($path);
    }
    public static function requirements(): array
    {
        // Core setup and optional native capabilities are reported separately.
        // Old prototype dependencies never become native prerequisites.
        return ['php' => PHP_VERSION, 'phpSupported' => version_compare(PHP_VERSION, '8.2.0', '>='),
            'scope' => 'native-vault', 'runtime' => 'symcon-native', 'nativeBackendImplemented' => true, 'native' => SecretsBackendNativePlatform::capabilities(),
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
        if (array_diff(array_keys($data), array_merge($fields, ['deployment', 'initialize', 'privateACLConfirmed', 'persistenceConfirmed', 'administratorLabel'])) || array_diff($fields, array_keys($data))) throw new InvalidArgumentException('Unexpected setup fields.');
        foreach (['backend', 'portal', 'documentation'] as $key) if (!is_int($data[$key]) || $data[$key] < 0) throw new InvalidArgumentException('Choose an available instance.');
        foreach (['theme', 'vaultDirectory', 'keyDirectory'] as $key) if (!is_string($data[$key])) throw new InvalidArgumentException('Invalid setup text.');
        if (!is_bool($data['debugEnabled'])) throw new InvalidArgumentException('Choose a Boolean Debug setting.');
        if (!is_bool($data['addPortalLink'])) throw new InvalidArgumentException('Choose whether to add the Portal link.');
        SecretsFrontendConfiguration::validate(array_replace(SecretsFrontendConfiguration::DEFAULTS, ['Theme' => $data['theme'], 'TrustedHTTPSProxyIPs' => $data['proxyIPs']]));
        foreach (['initialize', 'privateACLConfirmed', 'persistenceConfirmed'] as $flag) { if (isset($data[$flag]) && !is_bool($data[$flag])) throw new InvalidArgumentException('Use Boolean initialization confirmations.'); $data[$flag] ??= false; }
        $data['administratorLabel'] ??= 'Administrator';
        if (!is_string($data['administratorLabel']) || $data['administratorLabel'] === '' || strlen($data['administratorLabel']) > 80 || preg_match('/[\x00-\x1f]/', $data['administratorLabel'])) throw new InvalidArgumentException('Choose a short administrator label.');
        return $data;
    }
}
