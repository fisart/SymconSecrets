<?php
declare(strict_types=1);
require_once __DIR__ . '/Configuration.php';

/** Static commissioning UI. No authentication proxy and no legacy secret API calls. */
final class SecretsFrontendHttp
{
    public static function response(array $settings, int $instance, array $server, string $path, string $portal, string $documentation, string $input = '', ?callable $gateway = null, array $ui = []): array
    {
        $nonce = base64_encode(random_bytes(24));
        $headers = [
            'Content-Type' => 'text/html; charset=utf-8', 'Cache-Control' => 'no-store',
            'X-Content-Type-Options' => 'nosniff', 'Referrer-Policy' => 'no-referrer',
            'X-Frame-Options' => 'DENY', 'Permissions-Policy' => 'camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self)',
            'Content-Security-Policy' => "default-src 'none'; script-src 'nonce-" . $nonce . "'; style-src 'nonce-" . $nonce . "'; img-src 'none'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
        ];
        $reply = static fn(int $status, string $body, array $extra = []) => ['status' => $status, 'headers' => array_merge($headers, $extra), 'body' => $body];
        if (!$settings['Enabled']) return $reply(503, 'Secrets frontend is disabled.');
        $method = $server['REQUEST_METHOD'] ?? '';
        if (!in_array($method, ['GET', 'HEAD', 'POST'], true)) return $reply(405, 'Unsupported method.', ['Allow' => 'GET, HEAD, POST']);
        foreach (['HTTP_X_HTTP_METHOD_OVERRIDE','HTTP_X_METHOD_OVERRIDE','HTTP_X_HTTP_METHOD'] as $override) if (isset($server[$override])) return $reply(405, 'Method override is not accepted.');
        // Never interpret a query as an operation, file name, redirect or module function.
        if (($server['QUERY_STRING'] ?? '') !== '') return $reply(400, 'Query parameters are not supported.');
        $requestPath = parse_url((string)($server['REQUEST_URI'] ?? ''), PHP_URL_PATH);
        if ($requestPath !== $path) return $reply(404, 'Not found.');
        $origin = SecretsFrontendConfiguration::origin($settings['AdminOrigin']);
        if ($origin === '') return $reply(503, 'Configure the administrator HTTPS origin in the instance.');
        $proxy = in_array($server['REMOTE_ADDR'] ?? '', $settings['TrustedHTTPSProxyIPs'], true);
        // Match the existing Symcon modules: TLS terminates at the configured HTTPS
        // endpoint, which may be a native listener, NAT or relay. PHP transport flags
        // and a core WebServer caller are not guaranteed. Never infer TLS from headers.
        // The browser checks the pinned HTTPS origin before any credential/API use;
        // the server independently checks host, Origin, JSON and backend authorization.
        $headers['Content-Security-Policy'] = str_replace("connect-src 'self'", 'connect-src ' . $origin, $headers['Content-Security-Policy']);
        $host = $proxy && isset($server['HTTP_X_FORWARDED_HOST']) ? $server['HTTP_X_FORWARDED_HOST'] : ($server['HTTP_HOST'] ?? '');
        try { $requestOrigin = SecretsFrontendConfiguration::origin('https://' . $host); }
        catch (Throwable $exception) { return $reply(403, 'Invalid request host.'); }
        if ($requestOrigin !== $origin) {
            if ($method === 'POST') return $reply(403, 'Wrong administrator origin.');
            // Portal additional pages are local paths. Redirect only to the fixed configured origin,
            // dropping every query; never forward a request, cookie or state-changing operation.
            return $reply(303, '', ['Location' => $origin . $path]);
        }
        $headers['Strict-Transport-Security'] = 'max-age=31536000';
        if ($method === 'POST') {
            // WebHook Control can expose Content-Type under either PHP key. Reject
            // conflicting mirrored headers rather than choosing one interpretation.
            $types = [];
            foreach (['CONTENT_TYPE', 'HTTP_CONTENT_TYPE'] as $field) {
                $type = trim((string)($server[$field] ?? ''));
                if ($type !== '') $types[strtolower(trim(explode(';', $type, 2)[0]))] = true;
            }
            if (($server['HTTP_ORIGIN'] ?? '') !== $origin || count($types) !== 1 || !isset($types['application/json'])
                || !in_array($server['HTTP_SEC_FETCH_SITE'] ?? 'same-origin', ['same-origin', 'none'], true)) return $reply(403, 'Same-origin JSON requests are required.');
            try {
                $body = SecretsFrontendConfiguration::decode($input);
                $allowed = ['bootstrapPrepare','bootstrapSubmit','bootstrapProof','bootstrapResumeOptions','nativeCandidateOptions','nativeCandidateSubmit', 'guidedDiscover', 'guidedPreview', 'guidedApply', 'guidedCancel', 'status', 'setupPreview', 'setupCreate', 'authOptions', 'authVerify', 'enrollmentOptions', 'enrollmentVerify', 'session', 'list', 'configurationPreview', 'nativeUploadBegin', 'nativeUploadChunk', 'nativeUploadFinish', 'nativeOperationStatus', 'prepare', 'approve', 'logout'];
                if (count($body) !== 2 || !is_string($body['action'] ?? null) || !in_array($body['action'], $allowed, true) || !is_array($body['data'] ?? null) || $gateway === null) return $reply(400, 'Unsupported API request.');
                $result = $gateway(['action' => $body['action'], 'data' => $body['data'], 'origin' => $origin,
                    'remote' => (string)($server['REMOTE_ADDR'] ?? ''), 'cookie' => (string)($server['HTTP_COOKIE'] ?? ''), 'csrf' => (string)($server['HTTP_X_CSRF_TOKEN'] ?? '')]);
                if (!is_array($result) || !in_array($result['status'] ?? 0, [200, 400, 401, 403, 409, 429, 503], true) || !is_array($result['data'] ?? null)) throw new RuntimeException('Invalid backend response.');
                $apiHeaders = $headers; $apiHeaders['Content-Type'] = 'application/json; charset=utf-8';
                if (($result['cookie'] ?? '') !== '') {
                    if (!is_string($result['cookie']) || !preg_match('/^__Host-(?:SECB_[1-9][0-9]*|SECFB_[a-f0-9]{32}_[a-f0-9]{16})=(?:[A-Za-z0-9_-]{43})?; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=(?:0|900|3600)$/D', $result['cookie'])) throw new RuntimeException('Invalid backend cookie.');
                    $apiHeaders['Set-Cookie'] = $result['cookie'];
                }
                return ['status' => $result['status'], 'headers' => $apiHeaders, 'body' => SecretsFrontendConfiguration::encode($result['data'])];
            } catch (Throwable $exception) { return $reply(503, 'Backend request could not be completed. Check the backend status.'); }
        }
        if ($method === 'HEAD') return ['status' => 200, 'headers' => $headers, 'body' => ''];
        $boot = json_encode(['origin' => $origin, 'path' => $path, 'theme' => $settings['Theme'], 'guidedV2Only' => ($ui['guidedV2Only'] ?? false) === true], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
        $escape = static fn(string $text): string => htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $links = '';
        foreach (['Portal' => $portal, 'Dokumentation' => $documentation] as $label => $target) {
            if (preg_match('~^/hook/[A-Za-z0-9_-]+$~D', $target)) $links .= '<a href="' . $escape($target) . '">' . $label . '</a>';
        }
        $html = str_replace(['%%NONCE%%', '%%BOOT%%', '%%NAVIGATION%%', '%%NATIVE_PANELS%%', '/* %%NATIVE_ADMIN%% */', '/* %%BOOTSTRAP%% */'], [$escape($nonce), $boot, $links, (string)file_get_contents(__DIR__ . '/native-panels.html'), (string)file_get_contents(__DIR__ . '/native-admin.js'), (string)file_get_contents(__DIR__ . '/bootstrap.js')], (string)file_get_contents(__DIR__ . '/page.html'));
        return ['status' => 200, 'headers' => $headers, 'body' => $html];
    }
}
