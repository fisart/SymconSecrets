<?php
declare(strict_types=1);
require_once __DIR__ . '/../QuorumProtocol.php';
$codec = new SecretsBackendQuorumProtocol();
$profile = json_decode(file_get_contents(__DIR__ . '/../quorum/protocol/profile.json'), true, 32, JSON_THROW_ON_ERROR);
$vectors = $profile['illustrativeVectors']; $checks = 0;
$expectReject = static function (callable $callback) use (&$checks): void { try { $callback(); } catch (Throwable $exception) { ++$checks; return; } throw new RuntimeException('Expected quorum rejection.'); };
foreach ($vectors['wireOutcomes'] as $name => $vector) {
    $request = $vector['wireRequest']['request']; $wire = $vector['wireResponse']; $response = $wire['response'];
    $trust = $vectors['recoveryManifest']['trustedContext']['acceptedTrustPack'];
    $gateways = [$response['serverId'] => ['keyId' => $wire['keyId'], 'publicKey' => $vector['gatewayPublicKey']]];
    $observed = $codec->verifyResponse(SecretsBackendCodec::json($wire), $request, $trust, $gateways);
    if (!SecretsBackendCodec::same($observed, $response)) throw new RuntimeException('Quorum response changed.');
    $codec->verify('request', $request, $vector['wireRequest']['signature'], SecretsBackendCodec::unb64($vector['requestPublicKey'], 32));
    $seed = hex2bin($vectors['publicTestSeedsOnly']['nodeEd25519SeedHex']); $key = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed));
    if ($codec->signRequest($request, $key) !== SecretsBackendCodec::json($vector['wireRequest'])) throw new RuntimeException('PHP/Go request bytes differ.');
    ++$checks;
    $badTrust = $trust; $badTrust['nativeClusterId'] = '0000000000000002';
    $expectReject(fn() => $codec->verifyResponse(SecretsBackendCodec::json($wire), $request, $badTrust, $gateways));
    $expectReject(fn() => $codec->verifyResponse(SecretsBackendCodec::json($wire), $request, $trust, []));
}
foreach (['hostAdmission' => 'hostAdmission', 'recoveryManifest' => 'recoveryManifest', 'committedCopyReceipt' => 'archiveReattestation'] as $name => $domain) {
    $v = $vectors[$name]; $record = $v['record']; $signature = $record['signature']; unset($record['signature']);
    $codec->verify($domain, $record, $signature, SecretsBackendCodec::unb64($v['publicKey'], 32)); ++$checks;
    $expectReject(fn() => $codec->verify('request', $record, $signature, SecretsBackendCodec::unb64($v['publicKey'], 32)));
}
foreach (['{"a":"1","a":"2"}', '{"n":1}', '{"n":"\u00e4"}', '{} {}', str_repeat('{"a":', 9) . '{}' . str_repeat('}', 9)] as $bad) $expectReject(fn() => $codec->decode($bad));
$ambiguous = $codec->decode('{"array":[],"object":{}}');
if (!is_array($ambiguous['array']) || !$ambiguous['object'] instanceof stdClass) throw new RuntimeException('Object/array distinction lost.');
$expectReject(fn() => $codec->validate($ambiguous['object'], 'ObjectRef[]'));
$v = $vectors['wireOutcomes']['rejectedAuthorize']; $wire = $v['wireResponse']; $wire['response']['result'] = $vectors['wireOutcomes']['authorized']['wireResponse']['response']['result'];
$serverSeed = hex2bin($vectors['publicTestSeedsOnly']['gatewayEd25519SeedHex']); $serverKey = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($serverSeed));
$wire['signature'] = SecretsBackendCodec::b64(sodium_crypto_sign_detached($profile['domains']['response'] . SecretsBackendCodec::canonical($wire['response']), $serverKey));
$response = $wire['response']; $gateways = [$response['serverId'] => ['keyId' => $wire['keyId'], 'publicKey' => $v['gatewayPublicKey']]];
$trust = $vectors['recoveryManifest']['trustedContext']['acceptedTrustPack'];
$expectReject(fn() => $codec->verifyResponse(SecretsBackendCodec::json($wire), $v['wireRequest']['request'], $trust, $gateways));
echo "PASS $checks quorum PHP/Go fixture, pinned trust, signature, rejection and parser checks; no runtime activation\n";
