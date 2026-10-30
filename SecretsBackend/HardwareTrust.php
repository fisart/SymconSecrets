<?php
declare(strict_types=1);

/** Isolated trust decision for the NEW backend; the legacy verifier is unchanged. */
final class SecretsBackendHardwareTrust
{
    private static function pem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
    }
    public static function verify(string $attestation, string $directory, array $models, string $aaguid): void
    {
        $object = \lbuchs\WebAuthn\CBOR\CborDecoder::decode($attestation);
        if (!is_array($object) || ($object['fmt'] ?? '') !== 'packed' || ($object['attStmt']['alg'] ?? null) !== -7
            || isset($object['attStmt']['ecdaaKeyId']) || !in_array(bin2hex($aaguid), $models, true)) throw new RuntimeException('Unsupported hardware attestation profile.');
        $chain = $object['attStmt']['x5c'] ?? null;
        if (!is_array($chain) || !array_is_list($chain) || count($chain) < 1 || count($chain) > 8) throw new RuntimeException('Hardware attestation requires a bounded X.509 chain.');
        $certificates = [];
        foreach ($chain as $certificate) {
            if (!$certificate instanceof \lbuchs\WebAuthn\Binary\ByteBuffer || $certificate->getLength() > 16384) throw new RuntimeException('Invalid hardware certificate.');
            $pem = self::pem($certificate->getBinaryString());
            if (openssl_x509_read($pem) === false) throw new RuntimeException('Invalid hardware certificate encoding.');
            $certificates[] = $pem;
        }
        $roots = glob($directory . '/*.pem') ?: [];
        if (!$roots) throw new RuntimeException('No configured hardware trust roots.');
        foreach ($roots as $root) {
            if (is_link($root) || !is_file($root)) throw new RuntimeException('Unsafe hardware trust root.');
            $parsed = openssl_x509_parse((string)file_get_contents($root));
            if (!is_array($parsed) || !str_contains($parsed['extensions']['basicConstraints'] ?? '', 'CA:TRUE')) throw new RuntimeException('Configured trust root is not a CA certificate.');
        }
        // The fourth OpenSSL argument is UNTRUSTED intermediate material. Never append x5c to $roots.
        $intermediates = null;
        try {
            if (count($certificates) > 1) {
                $mask = umask(0077);
                try { $intermediates = tempnam(sys_get_temp_dir(), 'secb-untrusted-'); } finally { umask($mask); }
                if (!is_string($intermediates) || file_put_contents($intermediates, implode('', array_slice($certificates, 1))) === false) throw new RuntimeException('Cannot prepare untrusted certificate chain.');
            }
            $valid = $intermediates === null ? openssl_x509_checkpurpose($certificates[0], -1, $roots)
                : openssl_x509_checkpurpose($certificates[0], -1, $roots, $intermediates);
            if ($valid !== true && $valid !== 1) throw new RuntimeException('Hardware certificate is not rooted in the configured trust profile.');
        } finally { if (is_string($intermediates) && is_file($intermediates)) unlink($intermediates); }
        $leaf = openssl_x509_parse($certificates[0]);
        $subject = $leaf['subject'] ?? []; $extensions = $leaf['extensions'] ?? [];
        if (($leaf['version'] ?? null) !== 2 || ($subject['OU'] ?? '') !== 'Authenticator Attestation'
            || !is_string($subject['C'] ?? null) || strlen($subject['C']) !== 2 || empty($subject['O']) || empty($subject['CN'])
            || ($extensions['basicConstraints'] ?? '') !== 'CA:FALSE') throw new RuntimeException('Invalid packed attestation certificate profile.');
        // This first hardware profile requires the signed model extension, even when optional in WebAuthn.
        // Fail closed for devices without it; AAGUID text supplied by the browser alone is insufficient.
        $extension = $extensions['1.3.6.1.4.1.45724.1.1.4'] ?? '';
        if (!is_string($extension) || !hash_equals("\x04\x10" . $aaguid, $extension)) throw new RuntimeException('Hardware certificate model binding does not match.');
        $key = openssl_pkey_get_details(openssl_pkey_get_public($certificates[0]));
        if (($key['type'] ?? null) !== OPENSSL_KEYTYPE_EC || ($key['ec']['curve_name'] ?? '') !== 'prime256v1') throw new RuntimeException('Unsupported hardware attestation key.');
    }
}
