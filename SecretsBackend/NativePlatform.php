<?php
declare(strict_types=1);

/** Supplied-PHP platform operations; never executes a shell or installs a dependency. */
final class SecretsBackendNativePlatform
{
    public static function normalize(string $path, ?bool $windows = null): string
    {
        $windows ??= PHP_OS_FAMILY === 'Windows';
        if ($path === '' || strlen($path) > 1024 || preg_match('/[\x00-\x1f\x7f]/', $path) || str_contains($path, '://')) throw new InvalidArgumentException('Choose a local absolute private folder.');
        if ($windows) {
            $path = str_replace('\\', '/', $path);
            if (!preg_match('~^[A-Za-z]:/~', $path)) throw new InvalidArgumentException('Choose a local drive folder, not a network share.');
            $path = strtoupper($path[0]) . substr($path, 1);
            $parts = explode('/', substr($path, 3));
            foreach ($parts as $part) if ($part !== '' && (preg_match('/[<>:"|?*]|[. ]$/', $part) || preg_match('/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i', $part))) throw new InvalidArgumentException('Unsupported Windows folder component.');
        } else {
            if ($path[0] !== '/' || str_contains($path, '\\')) throw new InvalidArgumentException('Choose an absolute private folder.');
            $parts = explode('/', $path);
        }
        if (in_array('.', $parts, true) || in_array('..', $parts, true)) throw new InvalidArgumentException('Dot folder components are not allowed.');
        $path = preg_replace('~/+~', '/', $path);
        if($windows&&preg_match('~^[A-Z]:/$~D',$path))return $path;
        return rtrim($path, '/') ?: '/';
    }
    public static function contains(string $parent, string $path): bool
    {
        if (PHP_OS_FAMILY === 'Windows') { $parent = strtolower($parent); $path = strtolower($path); }
        return $parent === '/' || $path === $parent || str_starts_with($path, rtrim($parent, '/') . '/');
    }
    public static function directory(string $raw): string
    {
        $path = self::normalize($raw); $cursor = $path; $suffix = [];
        for ($i = 0; $i < 256; ++$i) {
            clearstatcache(true, $cursor);
            if (is_link($cursor) || (file_exists($cursor) && !is_dir($cursor))) throw new RuntimeException('Use ordinary directories without symbolic links or file components.');
            $parent = dirname($cursor);
            if ($parent === $cursor || $parent === '.') break;
            $cursor = $parent;
        }
        $ancestor = $path;
        while (!is_dir($ancestor)) {
            $parent = dirname($ancestor);
            if ($parent === $ancestor || $parent === '.') throw new RuntimeException('Cannot resolve the storage ancestor.');
            array_unshift($suffix, basename($ancestor)); $ancestor = $parent;
        }
        $resolved = realpath($ancestor);
        if ($resolved === false) throw new RuntimeException('Cannot resolve the storage ancestor.');
        return self::normalize(rtrim(str_replace('\\', '/', $resolved), '/') . ($suffix ? '/' . implode('/', $suffix) : '') ?: '/');
    }
    public static function paths(string $vault, string $keys, string $kernel, bool $empty = false, string|array|null $legacyParent = null): array
    {
        $kernel = self::normalize(str_replace('\\', '/', realpath($kernel) ?: $kernel));
        $out = ['vaultDirectory' => self::directory($vault), 'keyDirectory' => self::directory($keys)];
        foreach ($out as $name => $path) {
            if ($path === '/' || preg_match('~^[A-Za-z]:/?$~', $path)) throw new RuntimeException('Do not use a filesystem root.');
            $reserved = $kernel . ($name === 'vaultDirectory' ? '/secrets-native-data/' : '/secrets-native-keys/');
            $legacyAllowed=false;
            $legacyFolder=is_array($legacyParent)?($legacyParent[$name]??null):$legacyParent;
            if($legacyFolder!==null){
                $parent=self::directory($legacyFolder);$relative=substr($path,strlen(rtrim($parent,'/'))+1);
                $legacyAllowed=dirname($path)===$parent&&preg_match('/^secrets-native-(?:data|keys)-[0-9]+$/D',$relative)===1&&$parent!==$kernel;
                foreach(['webfront','user','modules','scripts','templates'] as $public)if(self::contains($kernel.'/'.$public,$path))$legacyAllowed=false;
            }
            if (self::contains($kernel, $path) && !self::contains(rtrim($reserved, '/'), $path) && !$legacyAllowed) throw new RuntimeException('Choose folders outside the Symcon installation or its dedicated native storage folders.');
            if ($empty && is_dir($path)) { $list = scandir($path); if ($list === false || count($list) !== 2) throw new RuntimeException('Choose new or empty storage folders; existing vaults are never adopted.'); }
        }
        if (self::contains($out['vaultDirectory'], $out['keyDirectory']) || self::contains($out['keyDirectory'], $out['vaultDirectory'])) throw new RuntimeException('Vault and key folders must be separate and must not contain each other.');
        return $out;
    }
    public static function defaults(int $id, string $kernel): array
    {
        $base = rtrim(str_replace('\\', '/', $kernel), '/');
        return ['vaultDirectory' => $base . '/secrets-native-data/' . $id, 'keyDirectory' => $base . '/secrets-native-keys/' . $id];
    }
    public static function capabilities(): array
    {
        $missing = [];
        foreach (['json_encode','json_decode','random_bytes','hash','hash_hmac','hash_equals','openssl_encrypt','openssl_decrypt','fopen','fwrite','fflush','fsync','flock','rename','mkdir','chmod','unlink','realpath','sodium_crypto_sign_keypair','sodium_crypto_sign_detached','sodium_crypto_sign_verify_detached','sodium_crypto_box_keypair','sodium_crypto_box_seal','sodium_crypto_box_seal_open'] as $fn) if (!function_exists($fn)) $missing[] = $fn;
        if (function_exists('openssl_get_cipher_methods') && !in_array('aes-256-gcm', openssl_get_cipher_methods(), true)) $missing[] = 'AES-256-GCM';
        return ['php' => PHP_VERSION, 'platform' => PHP_OS_FAMILY, 'architectureBits' => PHP_INT_SIZE * 8,
            'missing' => $missing, 'maxPlainBytes' => self::budget(), 'windowsACLConfirmationRequired' => PHP_OS_FAMILY === 'Windows',
            'directorySync' => PHP_OS_FAMILY === 'Windows' ? 'not-provided-by-php-profile' : 'verified-during-initialization'];
    }
    public static function budget(): int
    {
        $raw = trim((string)ini_get('memory_limit')); $limit = 128 * 1024 * 1024;
        if ($raw !== '' && $raw !== '-1') { $unit = strtolower(substr($raw, -1)); $limit = (int)$raw * match ($unit) { 'g' => 1073741824, 'm' => 1048576, 'k' => 1024, default => 1 }; }
        $available = $limit - memory_get_usage(true) - 8 * 1024 * 1024;
        if ($available < 2 * 1024 * 1024) throw new RuntimeException('Insufficient free PHP memory for a bounded encrypted vault.');
        return min(4 * 1024 * 1024, max(65536, intdiv($available, 24 * 16384) * 16384));
    }
    public static function makePrivate(string $path): void
    {
        $path = self::directory($path);
        if (!is_dir($path)) {
            $parent = dirname($path); if (!is_dir($parent)) self::makePrivate($parent);
            $mask = umask(0077); try { if (!mkdir($path, 0700)) throw new RuntimeException('Symcon cannot create the private folder.'); } finally { umask($mask); }
            self::syncDirectory($parent);
        }
        clearstatcache(true, $path);
        if (!is_writable($path) || (PHP_OS_FAMILY !== 'Windows' && (fileperms($path) & 0077) !== 0)) throw new RuntimeException('Use a writable private folder with mode 0700 (or a confirmed private Windows ACL).');
    }
    public static function syncDirectory(string $path): void
    {
        if (PHP_OS_FAMILY === 'Windows') return; // Explicit file-sync-only profile, never a directory durability claim.
        $h = @fopen($path, 'r'); if ($h === false) throw new RuntimeException('Cannot open the directory for synchronization.');
        try { if (!fsync($h)) throw new RuntimeException('Directory synchronization failed. Choose storage supporting native synchronization.'); } finally { fclose($h); }
    }
    public static function writeNew(string $path, string $bytes): void
    {
        if (is_link($path)) throw new RuntimeException('Unsafe security file.');
        $mask = umask(0077); try { $h = @fopen($path, 'x+b'); } finally { umask($mask); }
        if ($h === false) throw new RuntimeException('Refusing to overwrite existing security storage.');
        try {
            if (!chmod($path, 0600)) throw new RuntimeException('Cannot protect the security file.');
            for ($at = 0, $length = strlen($bytes); $at < $length;) { $n = fwrite($h, substr($bytes, $at, 65536)); if ($n === false || $n === 0) throw new RuntimeException('Incomplete security file write.'); $at += $n; }
            if (!fflush($h) || !fsync($h)) throw new RuntimeException('Security file synchronization failed.');
        } finally { fclose($h); }
    }
    public static function readPrivate(string $path, int $limit): string
    {
        clearstatcache(true, $path);
        if (is_link($path) || !is_file($path) || (PHP_OS_FAMILY !== 'Windows' && (fileperms($path) & 0077) !== 0) || filesize($path) > $limit) throw new RuntimeException('Missing, oversized or unsafe private security file.');
        // Empty lock files need metadata validation only. Windows mandatory locks
        // deny even a one-byte read while our own worker holds the lock.
        if($limit===0)return '';
        $bytes = file_get_contents($path, false, null, 0, $limit + 1);
        if (!is_string($bytes) || strlen($bytes) > $limit) throw new RuntimeException('Cannot read bounded private security storage.');
        return $bytes;
    }
    public static function persistence(string $vault, string $keys, string $kernel): array
    {
        $container = is_file('/.dockerenv') || is_file('/run/.containerenv'); $result = [];
        $lines = $container && is_readable('/proc/self/mountinfo') ? file('/proc/self/mountinfo', FILE_IGNORE_NEW_LINES) : [];
        foreach (['vault' => $vault, 'keys' => $keys] as $kind => $path) {
            $mount = '/'; $type = null;
            foreach ($lines ?: [] as $line) { $halves = explode(' - ', $line, 2); $fields = explode(' ', $halves[0]); $target = isset($fields[4]) ? preg_replace_callback('/\\\\([0-7]{3})/', static fn($m) => chr(octdec($m[1])), $fields[4]) : ''; if ($target !== '' && self::contains($target, $path) && strlen($target) >= strlen($mount)) { $mount = $target; $type = explode(' ', $halves[1] ?? '')[0]; } }
            $result[$kind] = ['container' => $container, 'mountPoint' => $container ? $mount : null, 'filesystem' => $type,
                'confirmationRequired' => $container && ($mount === '/' || in_array($type, ['overlay','tmpfs'], true)), 'powerLossTested' => false];
        }
        return $result;
    }
}
