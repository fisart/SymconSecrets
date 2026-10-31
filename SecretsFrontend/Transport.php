<?php
declare(strict_types=1);

/** Transport evidence from the Symcon engine, never from browser input. */
final class SecretsFrontendTransport
{
    // Core WebServer ID documented by IPS_GetModuleList.
    private const WEB_SERVER = '{D83E9CCF-9869-420F-8306-2B043E9BA180}';

    public static function nativeTLS(array $context, array $server): bool
    {
        // WebHook inherits WebInterface's engine-supplied calling WebServer ID.
        // Do not search for any other SSL listener: it did not serve this request.
        if (($context['SENDER'] ?? '') !== 'WebHook' || !is_int($context['INSTANCE'] ?? null) || $context['INSTANCE'] <= 0) return false;
        if (in_array(strtolower((string)($server['HTTPS'] ?? '')), ['off', '0'], true)) return false;
        try {
            $id = $context['INSTANCE'];
            if (!IPS_InstanceExists($id) || IPS_HasChanges($id)) return false;
            $instance = IPS_GetInstance($id);
            if (strtoupper((string)($instance['ModuleInfo']['ModuleID'] ?? '')) !== self::WEB_SERVER || ($instance['InstanceStatus'] ?? 0) !== 102) return false;
            // Do not read certificates, private keys, passwords or whole configurations.
            return IPS_GetProperty($id, 'Active') === true && IPS_GetProperty($id, 'EnableSSL') === true;
        } catch (Throwable $exception) {
            return false;
        }
    }
}
