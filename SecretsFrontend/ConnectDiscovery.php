<?php
declare(strict_types=1);
require_once __DIR__ . '/Configuration.php';

/** Read-only suggestion; this never approves an origin or changes vault policy. */
final class SecretsFrontendConnectDiscovery
{
    public const MODULE = '{9486D575-BE8C-4ED8-B5B5-20930E26DE6F}';

    public static function discover(callable $instances, callable $status, callable $url): array
    {
        try {
            $ids = $instances(self::MODULE);
            if (!is_array($ids) || count($ids) !== 1 || !is_int($ids[0]) || $ids[0] <= 0) {
                return ['available'=>false, 'message'=>'Connect Control was not found uniquely. Check Symcon Connect and try again.'];
            }
            if ($status($ids[0]) !== 102) return ['available'=>false, 'message'=>'Activate Symcon Connect and wait until it is connected.'];
            $value = $url($ids[0]);
            if (!is_string($value) || $value === '') return ['available'=>false, 'message'=>'Symcon Connect did not provide an address. Try again when it is connected.'];
            $origin = SecretsFrontendConfiguration::origin($value);
            $host = parse_url($origin, PHP_URL_HOST);
            if ($origin === '' || !is_string($host) || filter_var($host, FILTER_VALIDATE_IP) !== false || !str_contains($host, '.') || str_ends_with($host, '.')) throw new RuntimeException('Invalid Connect origin.');
            return ['available'=>true, 'origin'=>$origin];
        } catch (Throwable $e) {
            return ['available'=>false, 'message'=>'The Connect address is unavailable or is not an exact HTTPS address. Check Symcon Connect and try again.'];
        }
    }
}
