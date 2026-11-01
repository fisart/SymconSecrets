# Native implementation and release gates

Date: 1 November 2026 (Europe/Rome).

The Symcon-native backend is implemented and locally exercised. This replaces
the earlier settings-only/native-not-implemented checkpoint. Standalone is the
default; two, three, five and larger explicitly paired sets use the same optional
protocol. No external runtime service, database or added PHP extension is required.
No production/migration acceptance is implied. Existing SecretsManager and all
33 original repository blobs remain unchanged.

## Implemented

- Code-free console/browser candidate approval, strict browser PoP and nonce
  recovery, immutable encrypted initial decisions, exact restart completion and
  mandatory first-administrator genesis. Optional backend creation handles UNKNOWN
  object results without repeating creation. See BOOTSTRAP_IMPLEMENTATION.md.
- Automatic instance/capability/path/capacity discovery and reviewed HTML defaults.
- Console administrator recovery is disabled until a native vault exists, with
  initial-setup guidance. Local recovery also rejects uninitialized storage before
  opening it; an existing unreadable vault cannot fall back to initialization.
- Complete encrypted snapshot journal and separate keys; immutable authenticated
  publication marker; injected interruption recovery; runtime/session fencing;
  exact operation outcomes and protected disclosure.
- Masked hierarchy; session-authorized reveal unless hardware policy requires
  a fresh hardware assertion; operation-bound WebAuthn changes, ordinary and
  reviewed hardware credentials, authority-bound additional-key enrollment.
- Bilateral signed/encrypted pairing, ordered immutable outbox, exact receipts,
  lost-response deduplication, catch-up, revocation, ownership freeze/accept and
  explicit forks. Replayed old acceptances cannot reactivate revoked pairings.
- Scoped integration tokens with default read-only access, revision/sequence/UUID
  writes and revocation.
- Complete encrypted portable backup, separate recovery key, authenticated chunks,
  reviewed local-copy/replace-values recovery preserving current authority,
  data-key rotation and verified backup compaction.
- OAuth exact intents, encrypted response capture, predecessor/policy validation,
  unknown-outcome quarantine and bounded declared-idempotent retries.
- HTML administration for those operations, cleared one-use outputs, lost-result
  lookup and re-login after credential changes.

## Local evidence

The development PHP is 8.3. Native checks run with no PDO/SQLite and a 32 MiB memory
limit using actual temporary encrypted files and real cryptographic WebAuthn test
assertions (not physical keys). Native test groups cover:

| Group | Evidence |
| --- | --- |
| bootstrap-security.php | 83 console/candidate/PoP/resume/cancel/restart/reuse/recovery/object/I/O checks |
| native-store.php | 52 persistence/fencing/idempotence/corruption/path checks |
| native-lifecycle.php | Wizard, first/extra WebAuthn credentials, scoped machines, key rotation, backup authentication/compaction/value recovery, stale admission and restart fencing |
| native-peers.php | 84 checks over 1/2/3/5 vaults, bilateral approval, lost replies, transfer, replay/forgery/revocation and aggregate trees larger than 64 KiB |
| native-effects.php | 22 exact-intent/capture/unknown/retry/restart/revocation checks |
| HTML DOM tests | Complete rendered native assets, setup/defaults, exact-origin transport, late-response cleanup, approval, one-use output and additional-key re-login |
| Original-code check | All 33 original blobs unchanged; existing password regressions pass |

The workflow additionally exercises PHP 8.2/8.4/8.5 on Linux and the Windows
file-sync profile. Read the actual commit's Actions results before calling these
CI jobs passed. Their presence in YAML is not executed evidence. Historical
prototype regressions remain separate from native qualification.

## Required before production/migration

1. Independent security audit of the exact native implementation, including the
   changed guarantees and all new privileged routes.
2. Actual Symcon installation/reload/timers with the supplied PHP, multiple real
   hosts, mobile/desktop browsers and physical passkeys/hardware attestations.
3. Actual public HTTPS, alternate/plaintext listener and proxy/relay isolation.
   A configured origin/browser check is not transport-security evidence.
4. Real filesystem/private Windows ACL, Docker persistence across container
   replacement, power interruption and recovery. Exception injection against
   temporary files is not physical power-loss or OS-process-death testing.
5. The separately planned one-time old-vault migration and integration parity.
   No old secret was read, changed, migrated or activated by this implementation.

A consistent rollback of all trusted standalone files remains undetectable without
an independent current reference. Cached disconnected copies do not learn remote
revocation immediately. There is no automatic writer promotion. Recovery imports
reviewed secret values and retains current authority; it does not restore an old
instance's credentials/peer identity automatically.

Earlier audits and closed fixes remain in AUDIT_REMEDIATION.md and
AUDIT_CORRECTIONS_154d575.md. Their Go/SQLite component results do not approve
this new persistence or synchronization implementation.

The CI test-cluster helper reserves all six member ports until startup, avoiding
duplicate voter addresses observed in a historical component test. Native OAuth
intents additionally bind client-secret bytes and the writable global lineage;
active unresolved global effects block ordinary owner transfer.

The code-free v1.2 setup change replaces manual first-admin and recovery codes.
Its real WebCrypto signatures interoperate with PHP/OpenSSL in the DOM tests.
The actual Symcon console and physical authenticators remain unqualified; local
check counts do not represent completion of every T01–T64 design test. Independent
review of this new journal/initializer/request verifier remains required.


Symcon Connect backup access now has a development implementation with automatic
address discovery, a four-step HTML wizard, separate origin/RP-bound passkeys,
restricted enrollment, primary-side fresh exact approval and generation-based
revocation. Synthetic PHP/WebAuthn and browser tests exercise these paths. The
backup HTTP route accepts native HTTPS, an explicitly trusted HTTPS proxy,
or the documented exact-active-Connect loopback profile. The latter trusts local
loopback services and the Connect service; it does not identify the sending
process cryptographically. Untrusted local proxies must not expose that hop. Actual Connect transport, physical-key behavior and primary-
certificate outage remain unqualified. Independent review of the exact completed
implementation is outstanding; the design audit is not production acceptance.

The backup enrollment popup now waits for signed, candidate-bound activation
status before enabling Continue to sign in. Passkey creation/testing alone is
not activation. Continue switches to the normal sign-in screen without reloading
the still-pending enrollment page. The status endpoint discloses only activation
state and creates no general session; expiry, cancellation and origin-generation
changes reject the status proof.
