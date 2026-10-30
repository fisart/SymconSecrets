<?php
declare(strict_types=1);

final class SecretsBackendCodec
{
    public static function json($value): string
    {
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
    }
    /** JCS profile for protocol/manifest metadata only: ASCII strings and no JSON numbers. */
    public static function canonical($value): string
    {
        $walk = static function ($node) use (&$walk) {
            if (is_string($node)) {
                if (preg_match('/[^\x20-\x7e]/', $node)) throw new InvalidArgumentException('Non-ASCII protocol string.');
                return $node;
            }
            if (is_bool($node) || $node === null) return $node;
            if (is_object($node)) { $fields = get_object_vars($node); ksort($fields, SORT_STRING); return (object)array_map($walk, $fields); }
            if (is_array($node)) {
                if (array_values($node) === $node) return array_map($walk, $node);
                ksort($node, SORT_STRING); return (object)array_map($walk, $node);
            }
            throw new InvalidArgumentException('Protocol integers must be decimal strings.');
        };
        return self::json($walk($value));
    }
    public static function b64(string $bytes): string { return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '='); }
    public static function unb64(string $text, ?int $length = null): string
    {
        if ($text === '' || !preg_match('/^[A-Za-z0-9_-]+$/D', $text)) throw new InvalidArgumentException('Invalid binary encoding.');
        $bytes = base64_decode(strtr($text, '-_', '+/'), true);
        if ($bytes === false || self::b64($bytes) !== $text || ($length !== null && strlen($bytes) !== $length)) throw new InvalidArgumentException('Invalid binary length.');
        return $bytes;
    }
    public static function uuid(): string
    {
        $b = random_bytes(16); $b[6] = chr((ord($b[6]) & 15) | 64); $b[8] = chr((ord($b[8]) & 63) | 128);
        $h = bin2hex($b); return substr($h, 0, 8) . '-' . substr($h, 8, 4) . '-' . substr($h, 12, 4) . '-' . substr($h, 16, 4) . '-' . substr($h, 20);
    }
    public static function same($left, $right): bool { return hash_equals(self::canonical($left), self::canonical($right)); }
    public static function increment(string $number): string
    {
        if (!preg_match('/^(0|[1-9][0-9]*)$/D', $number) || strlen($number) > 19 || (strlen($number) === 19 && strcmp($number, '9223372036854775807') >= 0)) throw new RuntimeException('Counter exhausted.');
        return (string)((int)$number + 1);
    }
    public static function seal(string $plain, string $key, string $context): string
    {
        $iv = random_bytes(12); $tag = '';
        $cipher = openssl_encrypt($plain, 'aes-128-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $context, 16);
        if ($cipher === false || strlen($key) !== 16) throw new RuntimeException('Encryption failed.');
        return self::json(['cipher' => 'aes-128-gcm', 'iv' => bin2hex($iv), 'tag' => bin2hex($tag), 'data' => base64_encode($cipher)]);
    }
    public static function open(string $sealed, string $key, string $context): string
    {
        $data = json_decode($sealed, true, 8, JSON_THROW_ON_ERROR);
        if (!is_array($data) || count($data) !== 4 || ($data['cipher'] ?? '') !== 'aes-128-gcm'
            || !preg_match('/^[a-f0-9]{24}$/D', $data['iv'] ?? '') || !preg_match('/^[a-f0-9]{32}$/D', $data['tag'] ?? '') || strlen($key) !== 16) throw new RuntimeException('Invalid encrypted payload.');
        $cipher = base64_decode($data['data'], true);
        $plain = $cipher === false ? false : openssl_decrypt($cipher, 'aes-128-gcm', $key, OPENSSL_RAW_DATA, hex2bin($data['iv']), hex2bin($data['tag']), $context);
        if ($plain === false) throw new RuntimeException('Payload authentication failed.');
        return $plain;
    }
    public static function privateDirectory(string $path): void
    {
        if ($path === '' || $path[0] !== '/' || str_contains($path, "\0") || preg_match('~(?:^|/)\.{1,2}(?:/|$)~', $path)) throw new RuntimeException('Use an absolute storage directory.');
        $current = '';
        foreach (explode('/', trim($path, '/')) as $component) {
            $current .= '/' . $component;
            if (is_link($current)) throw new RuntimeException('Symlinked storage is not allowed.');
            if (!is_dir($current)) {
                if (!mkdir($current, 0700)) throw new RuntimeException('Cannot create private storage.');
                self::syncDirectory(dirname($current));
            }
        }
        if (!is_writable($path) || (fileperms($path) & 0077) !== 0) throw new RuntimeException('Storage directory must have mode 0700.');
    }
    public static function writeNew(string $path, string $bytes): void
    {
        $oldMask = umask(0077);
        try { $handle = fopen($path, 'x+b'); } finally { umask($oldMask); }
        if ($handle === false) throw new RuntimeException('Refusing to overwrite an existing security file.');
        try {
            if (!chmod($path, 0600) || fwrite($handle, $bytes) !== strlen($bytes) || !fflush($handle) || (function_exists('fsync') && !fsync($handle))) throw new RuntimeException('Security file was not durably written.');
        } finally { fclose($handle); }
        self::syncDirectory(dirname($path));
    }
    /** Linux/Symcon storage: fail closed if directory entry durability is unavailable. */
    public static function syncDirectory(string $directory): void
    {
        $handle = fopen($directory, 'r');
        if ($handle === false) throw new RuntimeException('Cannot open storage directory for synchronization.');
        try { if (!function_exists('fsync') || !fsync($handle)) throw new RuntimeException('Storage directory synchronization is required.'); }
        finally { fclose($handle); }
    }
    public static function privateFile(string $path): string
    {
        if (is_link($path) || !is_file($path) || (fileperms($path) & 0077) !== 0) throw new RuntimeException('Missing private security file or unsafe permissions.');
        $bytes = file_get_contents($path);
        if (!is_string($bytes)) throw new RuntimeException('Cannot read security file.');
        return $bytes;
    }
}
