<?php
declare(strict_types=1);

/** Shared wire format only. Each module owns its native configuration and importer. */
final class SecretsConfigurationBackup
{
    public const SCHEMA = 'Symcon.ConfigurationBackup.v1';
    public const VALIDATION = 'Symcon.ConfigurationBackupValidation.v1';
    public static function canonical($value): string
    {
        $sort = static function ($v) use (&$sort) {
            if (!is_array($v)) return $v;
            if (!array_is_list($v)) ksort($v, SORT_STRING);
            foreach ($v as &$child) $child = $sort($child);
            return $v;
        };
        return json_encode($sort($value), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
    }
    public static function sourceHash(array $properties, array $attributes): string
    {
        return hash('sha256', self::canonical(['properties' => $properties, 'attributes' => $attributes]));
    }
    public static function export(string $module, array $payload, array $properties, array $attributes): string
    {
        return self::canonical(['schema' => self::SCHEMA, 'moduleID' => $module, 'format' => $payload['schema'],
            'payload' => $payload, 'sourceHash' => self::sourceHash($properties, $attributes), 'attributeNames' => array_keys($attributes),
            'restoreMode' => 'manual-native-import',
            'exclusions' => ['vault-contents', 'private-key-material', 'administrator-credentials', 'sessions', 'runtime-state', 'automatic-setup-authorizations-and-capabilities'],
            'notes' => ['Configuration only; vault recovery uses the separate encrypted vault backup.', 'Native import leaves Enabled false and preserves existing provisioning protections.']]);
    }
    public static function validation(array $payload, callable $validate): string
    {
        $valid = true;
        try { $validate(); } catch (Throwable $e) { $valid = false; }
        return self::canonical(['schema' => self::VALIDATION, 'valid' => $valid, 'scope' => 'format',
            'payloadHash' => hash('sha256', self::canonical($payload)),
            'issues' => $valid ? [] : ['Native configuration importer rejects the format or required fields.'],
            'checks' => ['native-import-format', 'required-fields', 'value-types'],
            'notes' => ['Read-only format validation; no restore was executed. Target provisioning, paths and object references are checked by the native importer at restore time.']]);
    }
}
