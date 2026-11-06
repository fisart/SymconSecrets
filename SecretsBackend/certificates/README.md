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


## Let’s Encrypt issuer completion

`letsencrypt-issuers.pem` contains the public YE2 certificate and the cross-signed
Root YE / ISRG Root X2 issuer certificates obtained from the CA's official site:

- https://letsencrypt.org/certs/gen-y/int-ye2.pem
- https://letsencrypt.org/certs/gen-y/root-ye-by-x2.pem
- https://letsencrypt.org/certs/gen-y/root-x2-by-x1.pem

SHA-256: `3b91762c45be2dbc4a5fe358b03ce40df2541c6c857fc8329c4a6dc4c3f09d7e`.
They are chain-building material, not new trusted roots. Each issuer is checked
against a snapshot of the already configured OpenSSL CA file before use. Only
validated issuers are added to a temporary per-request copy, deleted afterwards.
The configured CA file and Symcon/server settings are never modified. Strict
TLS still validates the actual server certificate, hostname and dates before POST.
No certificate is downloaded from the peer or fetched at runtime. When the supplied
issuers cannot be used, the ordinary configured strict validation remains in force.
