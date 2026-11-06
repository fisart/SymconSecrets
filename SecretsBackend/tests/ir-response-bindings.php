<?php
declare(strict_types=1);
require_once __DIR__ . '/../QuorumProtocol.php';
$codec = new SecretsBackendQuorumProtocol();
$v = json_decode(file_get_contents(__DIR__ . '/../quorum/tests/response-bindings.json'), true, 32, JSON_THROW_ON_ERROR);
secBindingsAssert($v['profileSha256'] === SecretsBackendQuorumProtocol::PROFILE_SHA256, 'Wrong baseline');
$gateway = $v['gateway']; $pins = [$gateway['serverId'] => ['keyId'=>$gateway['keyId'],'publicKey'=>$gateway['publicKey']]];
foreach ($v['cases'] as $case) {
    $codec->verify('response', $case['wire']['response'], $case['wire']['signature'], SecretsBackendCodec::unb64($gateway['publicKey'], 32));
    $accepted = true;
    try { $codec->verifyResponse(SecretsBackendCodec::json($case['wire']), $case['request'], $v['trustPack'], $pins, $case['original']); }
    catch (Throwable $error) { $accepted = false; }
    secBindingsAssert($accepted === $case['accept'], $case['name']);
}
echo 'PASS IR-03 ' . count($v['cases']) . " shared, validly signed PHP/Go binding vectors\n";
function secBindingsAssert(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
