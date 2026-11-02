# Public CA fallback

`mozilla-ca.pem` is the unmodified curl CA Extract bundle of Mozilla public roots,
dated 2026-10-20, containing 118 certificates.

- Distribution: https://curl.se/docs/caextract.html
- Download: https://curl.se/ca/cacert.pem
- Published checksum: https://curl.se/ca/cacert.pem.sha256
- SHA-256: `796f1389bfea13c0ed78f663b765baaff54a508e5483786bd6ece73c5e3e3cbe`
- Source: Mozilla NSS `security/nss/lib/ckfw/builtins/certdata.txt`
- License: Mozilla Public License 2.0, https://mozilla.org/MPL/2.0/

This file is Source Code Form governed by MPL 2.0. The original distribution
comments and certificates are retained. No private keys or deployment certificates
are included. Updates must replace the file and its checksum/date together in
a reviewed module release. Nothing is downloaded or trusted dynamically at runtime.
The fallback is used only when no explicit or usable host trust store exists;
explicit settings are never bypassed after a verification failure.
