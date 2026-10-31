<?php
declare(strict_types=1);

// Include before modules.php prints anything: exercise the actual generated hook.
$relayFrontend = new HookInstance(50365); $relayFrontend->Create();
$origin = 'https://test.hermitage.ap-fischer.de:46910';
$path = '/hook/secrets_frontend_50365';
$relayFrontend->properties['Enabled'] = true; $relayFrontend->properties['AdminOrigin'] = $origin;
$relayServer = ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => $path, 'HTTP_HOST' => 'test.hermitage.ap-fischer.de:46910', 'REMOTE_ADDR' => '198.51.100.24'];
$savedServer = $_SERVER; $savedContext = $GLOBALS['_IPS'] ?? null;
// Built-in listeners/relays need not supply a core WebServer instance or HTTPS flag.
$GLOBALS['_IPS'] = ['SENDER' => 'WebHook', 'INSTANCE' => 0];
foreach ([null, '', 'off', 'on'] as $phpHTTPS) {
    $_SERVER = $relayServer;
    if ($phpHTTPS !== null) $_SERVER['HTTPS'] = $phpHTTPS;
    ob_start(); $relayFrontend->ProcessHookData(); $body = ob_get_clean();
    secExpect(http_response_code() === 200 && str_contains(strtolower($body), '<!doctype html>') && str_contains($body, json_encode($origin)) && str_contains($body, json_encode($path)), 'Generated Symcon hook rejected a valid configured endpoint based on internal transport metadata.');
}
$_SERVER = $savedServer;
if ($savedContext === null) unset($GLOBALS['_IPS']); else $GLOBALS['_IPS'] = $savedContext;
$relaySettings = SecretsFrontendConfiguration::validate(array_replace(SecretsFrontendConfiguration::DEFAULTS, ['Enabled' => true, 'AdminOrigin' => $origin]));
$reply = SecretsFrontendHttp::response($relaySettings, 50365, $relayServer, $path, '', '');
secExpect($reply['status'] === 200 && str_contains($reply['headers']['Content-Security-Policy'], 'connect-src ' . $origin . ';') && !str_contains($reply['headers']['Content-Security-Policy'], "connect-src 'self'") && isset($reply['headers']['Strict-Transport-Security']), 'CSP did not pin browser connections to the exact HTTPS origin and port.');
$relayServer['REQUEST_METHOD'] = 'HEAD';
$reply = SecretsFrontendHttp::response($relaySettings, 50365, $relayServer, $path, '', '');
secExpect($reply['status'] === 200 && $reply['body'] === '', 'Symcon HEAD response was not empty.');
$relayServer['REQUEST_METHOD'] = 'POST'; $relayServer['HTTP_ORIGIN'] = $origin;
$relayServer['HTTP_X_CSRF_TOKEN'] = 'test-csrf'; $relayServer['HTTP_COOKIE'] = 'test-cookie';
$input = '{"action":"status","data":{}}'; $apiCalls = 0;
$gateway = static function (array $request) use (&$apiCalls, $origin): array {
    $apiCalls++;
    secExpect($request['origin'] === $origin && $request['csrf'] === 'test-csrf' && $request['cookie'] === 'test-cookie', 'Origin or backend authentication/CSRF inputs changed.');
    return ['status' => 200, 'data' => ['ok' => true]];
};
foreach ([['CONTENT_TYPE' => 'application/json'], ['HTTP_CONTENT_TYPE' => 'application/json; charset=utf-8'], ['CONTENT_TYPE' => '', 'HTTP_CONTENT_TYPE' => 'Application/JSON'], ['CONTENT_TYPE' => 'application/json', 'HTTP_CONTENT_TYPE' => 'application/json; charset=utf-8']] as $types) {
    $reply = SecretsFrontendHttp::response($relaySettings, 50365, array_replace($relayServer, $types), $path, '', '', $input, $gateway);
    secExpect($reply['status'] === 200 && json_decode($reply['body'], true)['ok'] === true, 'Symcon JSON Content-Type variant was rejected.');
}
secExpect($apiCalls === 4, 'A valid JSON request missed gateway authorization.');
foreach ([[], ['CONTENT_TYPE' => 'text/plain'], ['HTTP_CONTENT_TYPE' => 'text/plain'], ['CONTENT_TYPE' => 'application/json', 'HTTP_CONTENT_TYPE' => 'text/html'], ['CONTENT_TYPE' => 'text/plain', 'HTTP_CONTENT_TYPE' => 'application/json']] as $types) {
    $reply = SecretsFrontendHttp::response($relaySettings, 50365, array_replace($relayServer, $types), $path, '', '', $input, $gateway);
    secExpect($reply['status'] === 403, 'Missing, non-JSON or conflicting Content-Type reached gateway authorization.');
}
$relayServer['HTTP_CONTENT_TYPE'] = 'application/json';
foreach (['', 'http://test.hermitage.ap-fischer.de:46910', 'https://evil.example.test', 'https://test.hermitage.ap-fischer.de'] as $wrongOrigin) {
    $reply = SecretsFrontendHttp::response($relaySettings, 50365, array_replace($relayServer, ['HTTP_ORIGIN' => $wrongOrigin, 'HTTP_X_FORWARDED_PROTO' => 'https']), $path, '', '', $input, $gateway);
    secExpect($reply['status'] === 403, 'Missing, HTTP, foreign or wrong-port Origin reached gateway authorization.');
}
foreach (['cross-site', 'same-site'] as $site) {
    $reply = SecretsFrontendHttp::response($relaySettings, 50365, array_replace($relayServer, ['HTTP_SEC_FETCH_SITE' => $site]), $path, '', '', $input, $gateway);
    secExpect($reply['status'] === 403, 'Cross-site JSON request reached gateway authorization.');
}
$wrongHost = array_replace($relayServer, ['HTTP_HOST' => 'evil.example.test', 'HTTP_X_FORWARDED_HOST' => 'test.hermitage.ap-fischer.de:46910', 'HTTP_X_FORWARDED_PROTO' => 'https']);
$reply = SecretsFrontendHttp::response($relaySettings, 50365, $wrongHost, $path, '', '', $input, $gateway);
secExpect($reply['status'] === 403 && $apiCalls === 4, 'Untrusted forwarded host bypassed origin checks or a rejected request invoked the gateway.');
$wrongHost['REQUEST_METHOD'] = 'GET'; $wrongHost['QUERY_STRING'] = '';
$reply = SecretsFrontendHttp::response($relaySettings, 50365, $wrongHost, $path, '', '');
secExpect($reply['status'] === 303 && $reply['headers']['Location'] === $origin . $path, 'Wrong-host navigation did not target the fixed configured wizard URL.');
$trustedSettings = array_replace($relaySettings, ['TrustedHTTPSProxyIPs' => ['198.51.100.24']]);
$wrongHost['REQUEST_METHOD'] = 'POST';
$reply = SecretsFrontendHttp::response($trustedSettings, 50365, $wrongHost, $path, '', '', $input, $gateway);
secExpect($reply['status'] === 200 && $apiCalls === 5, 'Explicitly trusted proxy host support broke.');
$reply = SecretsFrontendHttp::response($relaySettings, 50365, $relayServer, $path, '', '', $input, static fn() => ['status' => 401, 'data' => ['error' => 'Session required.']]);
secExpect($reply['status'] === 401, 'Transport compatibility bypassed backend authentication.');
$reply = SecretsFrontendHttp::response($relaySettings, 50365, $relayServer, $path, '', '', $input, static fn() => ['status' => 200, 'data' => [], 'cookie' => 'session=insecure']);
secExpect($reply['status'] === 503 && !isset($reply['headers']['Set-Cookie']), 'An insecure backend cookie reached the browser.');
echo "PASS Symcon native/NAT/relay compatibility without PHP TLS/caller metadata; exact HTTPS CSP, JSON header variants, host/Origin/proxy and backend-authentication checks\n";
