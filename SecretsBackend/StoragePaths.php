<?php
declare(strict_types=1);

/** Canonical storage validation shared by review, applied settings and creation. */
final class SecretsBackendStoragePaths
{
    private static function lexical(string $path): string
    {
        if ($path === '' || strlen($path) > 1024 || $path[0] !== '/' || preg_match('~[\x00-\x1f\x7f\\\\]|(?:^|/)\.{1,2}(?:/|$)~', $path)) {
            throw new InvalidArgumentException('Choose ordinary absolute storage folders without dot components or control characters.');
        }
        return rtrim((string)preg_replace('~/+~', '/', $path), '/') ?: '/';
    }

    private static function directory(string $raw, bool $trustedKernel = false): string
    {
        $path = self::lexical($raw); $part = '';
        foreach (explode('/', ltrim($path, '/')) as $segment) {
            if ($segment === '') continue;
            $part .= '/' . $segment;
            clearstatcache(true, $part);
            if ((!$trustedKernel && is_link($part)) || ((file_exists($part) || is_link($part)) && !is_dir($part))) {
                throw new InvalidArgumentException('Use ordinary folders without symbolic links or file components.');
            }
        }
        // realpath() alone cannot validate a destination that has not been created.
        // Resolve its nearest existing directory, then append normalized components.
        $ancestor = $path;
        while (!is_dir($ancestor)) {
            $parent = dirname($ancestor);
            if ($parent === $ancestor) throw new InvalidArgumentException('Cannot resolve the storage ancestor.');
            $ancestor = $parent;
        }
        $resolved = realpath($ancestor);
        if ($resolved === false) throw new InvalidArgumentException('Cannot resolve the storage ancestor.');
        $suffix = ltrim(substr($path, strlen($ancestor)), '/');
        return self::lexical(rtrim($resolved, '/') . ($suffix === '' ? '' : '/' . $suffix) ?: '/');
    }

    private static function contains(string $parent, string $path): bool
    {
        return $parent === '/' || $path === $parent || str_starts_with($path, $parent . '/');
    }

    public static function pair(string $vault, string $keys, string $kernel, bool $mustBeEmpty = true, bool $allowIncomplete = false): array
    {
        $kernel = self::directory($kernel, true);
        $paths = [];
        foreach (['vaultDirectory' => $vault, 'keyDirectory' => $keys] as $name => $raw) {
            if ($raw === '' && $allowIncomplete) { $paths[$name] = ''; continue; }
            $path = self::directory($raw);
            if ($path === '/' || self::contains($kernel, $path)) throw new InvalidArgumentException('Choose private absolute folders outside the Symcon installation.');
            if ($mustBeEmpty && is_dir($path)) {
                $entries = scandir($path);
                if ($entries === false || count($entries) !== 2) throw new InvalidArgumentException('Choose new or empty storage folders. Existing data is never adopted.');
            }
            $paths[$name] = $path;
        }
        if ($paths['vaultDirectory'] !== '' && $paths['keyDirectory'] !== '' && (self::contains($paths['vaultDirectory'], $paths['keyDirectory']) || self::contains($paths['keyDirectory'], $paths['vaultDirectory']))) {
            throw new InvalidArgumentException('Vault and key folders must be separate and must not contain each other.');
        }
        return $paths;
    }
}
