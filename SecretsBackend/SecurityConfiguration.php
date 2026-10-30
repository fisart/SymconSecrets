<?php
declare(strict_types=1);
require_once __DIR__ . '/Codec.php';

/** Provisioning trust is pinned once. Normal hardware-profile updates are anchored operations. */
final class SecretsBackendSecurityConfiguration
{
    public const FOUNDATION = ['FrontendInstanceID', 'DataDirectory', 'KeyDirectory', 'AdminOrigin', 'AnchorURL', 'AnchorPublicKey', 'AnchorKeyID', 'ClientCertificatePath', 'ClientKeyPath', 'AnchorCAFile'];
    public const HARDWARE = ['HardwareRootsDirectory', 'HardwareAAGUIDs', 'HardwareTrustVersion'];
    public static function settings(array $settings): array
    {
        return array_intersect_key($settings, array_flip(array_merge(self::FOUNDATION, self::HARDWARE)));
    }
    public static function profile(array $settings, array $frontend): array
    {
        $protected = self::settings($settings);
        return ['version' => '1', 'settings' => $protected, 'frontendSecurity' => $frontend, 'files' => self::fingerprints($protected)];
    }
    private static function fingerprints(array $settings): array
    {
        $result = [];
        foreach (['ClientCertificatePath', 'ClientKeyPath', 'AnchorCAFile'] as $field) {
            $path = $settings[$field];
            if ($path === '' || is_link($path) || !is_file($path)) throw new RuntimeException('Provisioning requires the exact reviewed TLS files.');
            $bytes = $field === 'ClientKeyPath' ? SecretsBackendCodec::privateFile($path) : file_get_contents($path);
            if (!is_string($bytes) || $bytes === '') throw new RuntimeException('Cannot fingerprint security configuration.');
            $result[$field] = hash('sha256', $bytes);
        }
        $roots = $settings['HardwareRootsDirectory']; $files = [];
        if ($roots !== '') {
            if (!is_dir($roots) || is_link($roots)) throw new RuntimeException('Hardware trust directory is unavailable.');
            foreach (glob($roots . '/*.pem') ?: [] as $path) {
                if (is_link($path) || !is_file($path)) throw new RuntimeException('Unsafe hardware trust material.');
                $files[basename($path)] = hash_file('sha256', $path);
            }
            if (!$files) throw new RuntimeException('Hardware trust directory contains no reviewed roots.');
        }
        ksort($files, SORT_STRING); $result['HardwareRoots'] = $files;
        return $result;
    }
    public static function verify(array $profile, array $frontend): void
    {
        if (($profile['version'] ?? '') !== '1' || !hash_equals(self::digest($profile['frontendSecurity']), self::digest($frontend))
            || !hash_equals(self::digest($profile['files']), self::digest(self::fingerprints($profile['settings'])))) throw new RuntimeException('Protected security configuration drifted; restore approved files or use explicit independent recovery.');
    }
    public static function sameFoundation(array $old, array $new): bool
    {
        return self::digest(array_intersect_key($old, array_flip(self::FOUNDATION))) === self::digest(array_intersect_key($new, array_flip(self::FOUNDATION)));
    }
    public static function digest(array $value): string
    {
        $sort = static function ($value) use (&$sort) {
            if (!is_array($value)) return $value;
            if (!array_is_list($value)) ksort($value, SORT_STRING);
            return array_map($sort, $value);
        };
        return hash('sha256', SecretsBackendCodec::json($sort($value)));
    }
}
