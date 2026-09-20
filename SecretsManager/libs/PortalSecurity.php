<?php

declare(strict_types=1);

/**
 * Pure helpers for the public SecretsManager WebAuthn portal.
 *
 * Kept independent from IPSModule so the security invariants can be tested
 * without an IP-Symcon runtime.
 */
final class SecretsPortalSecurity
{
    public const CREDENTIAL_SCHEMA_VERSION = 2;

    public static function base64UrlEncode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $encoded): ?string
    {
        if ($encoded === '' || strlen($encoded) > 65536) {
            return null;
        }
        if (preg_match('/^[A-Za-z0-9_-]+$/D', $encoded) !== 1) {
            return null;
        }

        $padding = strlen($encoded) % 4;
        if ($padding !== 0) {
            $encoded .= str_repeat('=', 4 - $padding);
        }

        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);
        return ($decoded === false) ? null : $decoded;
    }

    /**
     * Validate an RP configuration without trusting the request Host header.
     */
    public static function validateRpConfiguration(string $rpId, string $origin, string &$error): bool
    {
        $error = '';
        $rpId = strtolower(trim($rpId));
        $origin = rtrim(trim($origin), '/');

        if ($rpId === '' || strlen($rpId) > 253) {
            $error = 'Portal RP ID is missing or invalid.';
            return false;
        }
        if (filter_var($rpId, FILTER_VALIDATE_IP) !== false) {
            $error = 'Portal RP ID must be a DNS host name, not an IP address.';
            return false;
        }
        if ($rpId !== 'localhost' && preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $rpId) !== 1) {
            $error = 'Portal RP ID is not a valid DNS host name.';
            return false;
        }

        $parts = parse_url($origin);
        if (!is_array($parts) || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            $error = 'Portal origin must contain only scheme, host, and optional port.';
            return false;
        }

        $scheme = strtolower((string)($parts['scheme'] ?? ''));
        $host = strtolower(rtrim((string)($parts['host'] ?? ''), '.'));
        $path = (string)($parts['path'] ?? '');

        if ($host === '' || ($path !== '' && $path !== '/')) {
            $error = 'Portal origin must not contain a path.';
            return false;
        }
        if ($rpId === 'localhost') {
            if ($scheme !== 'https' && $scheme !== 'http') {
                $error = 'Localhost portal origin must use HTTP or HTTPS.';
                return false;
            }
        } elseif ($scheme !== 'https') {
            $error = 'Portal origin must use HTTPS.';
            return false;
        }

        if ($host !== $rpId && !str_ends_with($host, '.' . $rpId)) {
            $error = 'Portal origin host is outside the configured RP ID.';
            return false;
        }

        $normalizedOrigin = $scheme . '://' . $host;
        if (isset($parts['port'])) {
            $port = (int)$parts['port'];
            if ($port < 1 || $port > 65535) {
                $error = 'Portal origin contains an invalid port.';
                return false;
            }
            $normalizedOrigin .= ':' . $port;
        }

        if (!hash_equals($normalizedOrigin, $origin)) {
            $error = 'Portal origin must use its canonical form without a trailing slash.';
            return false;
        }

        return true;
    }

    /**
     * Decode and validate collected client data before the WebAuthn library
     * performs its own complete ceremony validation.
     *
     * @return array<string, mixed>|null
     */
    public static function validateClientData(
        string $clientDataJson,
        string $expectedType,
        string $expectedChallenge,
        string $expectedOrigin
    ): ?array {
        if ($clientDataJson === '' || strlen($clientDataJson) > 16384) {
            return null;
        }

        $clientData = json_decode($clientDataJson, true);
        if (!is_array($clientData)) {
            return null;
        }
        if (($clientData['type'] ?? null) !== $expectedType) {
            return null;
        }
        if (($clientData['origin'] ?? null) !== $expectedOrigin) {
            return null;
        }

        $receivedChallenge = self::base64UrlDecode((string)($clientData['challenge'] ?? ''));
        if ($receivedChallenge === null || !hash_equals($expectedChallenge, $receivedChallenge)) {
            return null;
        }

        if (isset($clientData['crossOrigin']) && $clientData['crossOrigin'] !== false) {
            return null;
        }

        return $clientData;
    }

    public static function sanitizeReturnUrl(string $returnUrl): string
    {
        $returnUrl = trim($returnUrl);
        if ($returnUrl === '' || strlen($returnUrl) > 2048) {
            return '/';
        }
        if ($returnUrl[0] !== '/' || str_starts_with($returnUrl, '//')) {
            return '/';
        }
        if (str_contains($returnUrl, "\\") || preg_match('/[\x00-\x1F\x7F]/', $returnUrl) === 1) {
            return '/';
        }

        $parts = parse_url($returnUrl);
        if ($parts === false || isset($parts['scheme']) || isset($parts['host']) || isset($parts['user'])) {
            return '/';
        }

        return $returnUrl;
    }

    /**
     * Parse a small JSON request body and reject ambiguous structures.
     *
     * @return array<string, mixed>|null
     */
    public static function decodeJsonRequest(string $input): ?array
    {
        if ($input === '' || strlen($input) > 131072) {
            return null;
        }

        $data = json_decode($input, true);
        return is_array($data) ? $data : null;
    }
}
