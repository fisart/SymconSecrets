<?php
declare(strict_types=1);

/** Frontend settings only: never a vault, credential, role or security-policy import. */
final class SecretsFrontendConfiguration
{
    public const SCHEMA = 'SECF.Config.v1';
    public const DEFAULTS = [
        'Enabled' => false, 'DebugEnabled' => false, 'BackendInstanceID' => 0,
        'PortalInstanceID' => 0, 'DocumentationInstanceID' => 0,
        'AdminOrigin' => '', 'TrustedHTTPSProxyIPs' => [], 'Theme' => 'system',
    ];

    public static function encode(array $value): string
    {
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
    }

    public static function decode(string $json): array
    {
        return self::decodeBounded($json, 65536, 12);
    }
    /** Server-selected bounds for encrypted native peer envelopes; browser requests stay at 64 KiB. */
    public static function decodeBounded(string $json, int $limit, int $depth = 32): array
    {
        if ($limit < 1 || $limit > 13 * 1024 * 1024 || strlen($json) > $limit) throw new InvalidArgumentException('JSON exceeds its selected size limit.');
        $value = json_decode($json, true, $depth, JSON_THROW_ON_ERROR);
        $offset = 0;
        self::scan($json, $offset);
        if (!is_array($value) || substr(ltrim($json), 0, 1) !== '{') throw new InvalidArgumentException('Expected a JSON object.');
        return $value;
    }

    /** Detect duplicate keys after unescaping; json_decode alone silently accepts them. */
    private static function scan(string $json, int &$offset): void
    {
        self::space($json, $offset);
        $token = $json[$offset] ?? '';
        if ($token === '{' || $token === '[') {
            $object = $token === '{'; $end = $object ? '}' : ']'; ++$offset; $keys = [];
            self::space($json, $offset);
            if (($json[$offset] ?? '') === $end) { ++$offset; return; }
            do {
                if ($object) {
                    self::space($json, $offset);
                    $key = self::string($json, $offset);
                    if (array_key_exists($key, $keys)) throw new InvalidArgumentException('Duplicate JSON key.');
                    $keys[$key] = true;
                    self::space($json, $offset); ++$offset; // JSON syntax already validated: colon.
                }
                self::scan($json, $offset); self::space($json, $offset);
                $separator = $json[$offset++] ?? '';
            } while ($separator === ',');
            return;
        }
        if ($token === '"') { self::string($json, $offset); return; }
        while (isset($json[$offset]) && !str_contains(",]} \t\r\n", $json[$offset])) ++$offset;
    }

    private static function space(string $json, int &$offset): void
    {
        while (isset($json[$offset]) && str_contains(" \r\n\t", $json[$offset])) ++$offset;
    }

    private static function string(string $json, int &$offset): string
    {
        $start = $offset++;
        while (isset($json[$offset])) {
            $character = $json[$offset++];
            if ($character === '\\') { ++$offset; continue; }
            if ($character === '"') break;
        }
        return json_decode(substr($json, $start, $offset - $start), true, 2, JSON_THROW_ON_ERROR);
    }

    public static function origin(string $origin): string
    {
        if ($origin === '') return '';
        if (strlen($origin) > 253 || preg_match('/[\x00-\x20\x7f\\\\]/', $origin)) throw new InvalidArgumentException('Use an exact HTTPS origin.');
        $url = parse_url($origin);
        if (!is_array($url) || ($url['scheme'] ?? '') !== 'https' || !isset($url['host'])
            || array_diff(array_keys($url), ['scheme', 'host', 'port', 'path'])
            || !in_array($url['path'] ?? '', ['', '/'], true)
            || !preg_match('/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/Di', $url['host'])
            || str_contains($url['host'], '..') || ($url['port'] ?? 443) < 1 || ($url['port'] ?? 443) > 65535) {
            throw new InvalidArgumentException('Use an exact HTTPS origin without credentials, query or path.');
        }
        return 'https://' . strtolower($url['host']) . (isset($url['port']) && $url['port'] !== 443 ? ':' . $url['port'] : '');
    }

    public static function validate(array $settings): array
    {
        if (array_diff(array_keys($settings), array_keys(self::DEFAULTS)) || array_diff(array_keys(self::DEFAULTS), array_keys($settings))) {
            throw new InvalidArgumentException('Unexpected or missing configuration field.');
        }
        foreach (['Enabled', 'DebugEnabled'] as $key) if (!is_bool($settings[$key])) throw new InvalidArgumentException('Expected a Boolean setting.');
        foreach (['BackendInstanceID', 'PortalInstanceID', 'DocumentationInstanceID'] as $key) {
            if (!is_int($settings[$key]) || $settings[$key] < 0 || $settings[$key] > 2147483647) throw new InvalidArgumentException('Invalid instance ID.');
        }
        if (!is_string($settings['AdminOrigin'])) throw new InvalidArgumentException('Invalid origin setting.');
        $settings['AdminOrigin'] = self::origin($settings['AdminOrigin']);
        $ips = $settings['TrustedHTTPSProxyIPs'];
        if (!is_array($ips) || array_values($ips) !== $ips || count($ips) > 16) throw new InvalidArgumentException('Use a list of exact proxy IP addresses.');
        foreach ($ips as $ip) if (!is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false) throw new InvalidArgumentException('Invalid proxy IP address.');
        if (count(array_unique($ips)) !== count($ips)) throw new InvalidArgumentException('Duplicate proxy IP address.');
        if (!is_string($settings['Theme']) || !in_array($settings['Theme'], ['system', 'light', 'dark'], true)) throw new InvalidArgumentException('Invalid theme.');
        return $settings;
    }

    public static function export(array $settings, ?array $deploymentDraft = null): string
    {
        $settings = self::validate($settings);
        if ($deploymentDraft === null) return self::encode(['schema' => self::SCHEMA, 'configuration' => $settings]);
        require_once __DIR__ . '/Deployment.php';
        return self::encode(['schema' => 'SECF.Config.v2', 'configuration' => $settings,
            'deploymentDraft' => SecretsFrontendDeployment::validate($deploymentDraft, $settings['AdminOrigin'])]);
    }

    public static function import(string $json): array
    {
        $data = self::decode($json);
        $v2 = ($data['schema'] ?? '') === 'SECF.Config.v2';
        $fields = $v2 ? ['schema', 'configuration', 'deploymentDraft'] : ['schema', 'configuration'];
        if (array_diff(array_keys($data), $fields) || array_diff($fields, array_keys($data)) || (!$v2 && ($data['schema'] ?? '') !== self::SCHEMA) || !is_array($data['configuration'] ?? null)) throw new InvalidArgumentException('Expected SECF.Config.v1 or SECF.Config.v2.');
        $settings = self::validate($data['configuration']);
        if ($v2) {
            require_once __DIR__ . '/Deployment.php';
            if (!is_array($data['deploymentDraft'])) throw new InvalidArgumentException('Expected a deployment draft.');
            SecretsFrontendDeployment::validate($data['deploymentDraft'], $settings['AdminOrigin']);
        }
        $settings['Enabled'] = false; // Imported settings never publish a web endpoint automatically.
        return $settings;
    }
}
