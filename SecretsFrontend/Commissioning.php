<?php
declare(strict_types=1);
require_once __DIR__ . '/Configuration.php';
require_once __DIR__ . '/Deployment.php';

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
        $paths = ['vaultDirectory' => rtrim($vault, '/'), 'keyDirectory' => rtrim($keys, '/')];
        foreach ($paths as $path) {
            if ($path === '' || $path === '/' || strlen($path) > 1024 || $path[0] !== '/' || preg_match('~[\x00-\x1f\x7f\\\\]|(?:^|/)\.{1,2}(?:/|$)~', $path)
                || str_starts_with($path . '/', rtrim($kernel, '/') . '/')) throw new InvalidArgumentException('Choose private absolute folders outside the Symcon installation.');
            $part = '';
            foreach (explode('/', ltrim($path, '/')) as $segment) { $part .= '/' . $segment; if (is_link($part) || (file_exists($part) && !is_dir($part))) throw new InvalidArgumentException('Use ordinary folders without symbolic links or file components.'); }
            if (is_dir($path) && count(scandir($path) ?: []) > 2) throw new InvalidArgumentException('Choose new or empty storage folders. Existing data is never adopted.');
        }
        if (str_starts_with($paths['vaultDirectory'] . '/', $paths['keyDirectory'] . '/') || str_starts_with($paths['keyDirectory'] . '/', $paths['vaultDirectory'] . '/')) throw new InvalidArgumentException('Vault and key folders must be separate and must not contain each other.');
        return $paths;
    }
    public static function writable(string $path): bool
    {
        while (!file_exists($path) && dirname($path) !== $path) $path = dirname($path);
        return is_dir($path) && is_writable($path);
    }
    public static function requirements(): array
    {
        $extensions = []; foreach (['sodium', 'openssl', 'curl', 'pdo_sqlite'] as $name) $extensions[$name] = extension_loaded($name);
        $sqlite = null;
        if ($extensions['pdo_sqlite']) { try { $db = new PDO('sqlite::memory:'); $sqlite = (string)$db->query('SELECT sqlite_version()')->fetchColumn(); } catch (Throwable $ignored) {} }
        return ['php' => PHP_VERSION, 'phpSupported' => version_compare(PHP_VERSION, '8.2.0', '>='), 'extensions' => $extensions, 'sqlite' => $sqlite,
            'legacyWalSupported' => $sqlite !== null && version_compare($sqlite, '3.51.3', '>='), 'quorumConnected' => false];
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
