# Independent development anchor

This is a development witness, not a production-approved service. Read the [outstanding release gates](../../SecretsFrontend/RELEASE_STATUS.md). Run it outside the Symcon VM, its snapshots and its restore scope. It stores no managed secret values or vault master keys, but its own TLS/signing private keys must be protected.

Requirements: Python 3.10+, `cryptography` (tested 50.0.2), local durable storage, an independently controlled OS account and a TLS server certificate/private key plus a private CA for approved client certificates. Deployment, firewall, service limits, monitoring, certificate lifecycle and host recovery need review on the actual installation.

1. Create an independent private directory and initialize once:

```sh
python3 service.py --directory /var/lib/symcon-secrets-anchor init
```

Record the returned `anchorPublicKey` and `anchorKeyId` independently and enter them in the new backend. Initialization refuses existing key files. Do not copy the anchor database back from a Symcon guest backup.

2. Run the frontend storage wizard and download its **public provisioning metadata**. Independently confirm the deployment ID, expected genesis head, client signing key and client TLS certificate fingerprint. Determine the SHA-256 fingerprint from the certificate's DER bytes, not the PEM file's text.

```sh
openssl x509 -in symcon-client.crt -outform DER | openssl dgst -sha256
python3 service.py --directory /var/lib/symcon-secrets-anchor provision \
  --info secrets-anchor-provisioning.json --certificate-sha256 CONFIRMED_DER_SHA256
```

Provision never overwrites an existing deployment. It does not bootstrap from a guest request. Do not mistake the placeholder for a literal fingerprint.

3. Run the service with mutual TLS, e.g. under a restricted supervised service account:

```sh
python3 service.py --directory /var/lib/symcon-secrets-anchor serve \
  --bind 127.0.0.1 --port 9443 \
  --cert /secure/anchor-server.crt --key /secure/anchor-server.key \
  --client-ca /secure/client-ca.crt
```

Choose a deliberate reachable bind address or reviewed TLS passthrough route for the Symcon test VM; the sample loopback address alone is not remotely reachable. Do not remove mandatory client certificates or proxy an unauthenticated plaintext endpoint to the service. Configure the exact HTTPS `/v1/anchor` URL, client certificate/key and server CA in the backend, then enable it and run Recover.

Each request has a closed schema and fresh nonce. Requests and responses have distinct Ed25519 domain prefixes. Numeric counters are exact decimal strings. A decision and its head/fence change commit together with FULL synchronous SQLite persistence before the response is signed. Retries bind a stable operation digest/ID. Read/status use the current authoritative database; no stale replica/cache fallback exists.

This version has no self-service guest rebase, key-renewal or generation-reset endpoint. Operational renewal, revocation and independent disaster recovery must be implemented/reviewed before production. There is no suggestion to erase the record or reprovision an old guest state when a mismatch occurs.
