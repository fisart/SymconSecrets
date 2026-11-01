# Native implementation and release gates

Date: 1 November 2026 (Europe/Rome).

The Symcon-native backend is implemented and locally exercised. This replaces
the earlier settings-only/native-not-implemented checkpoint. Standalone is the
default; two, three, five and larger explicitly paired sets use the same optional
protocol. No external runtime service, database or added PHP extension is required.
No production/migration acceptance is implied. Existing SecretsManager and all
33 original repository blobs remain unchanged.

## Implemented

- Automatic instance/capability/path/capacity discovery; reviewed HTML setup with
  defaults, selected native initialization and first passkey registration.
- Complete encrypted snapshot journal and separate keys; immutable authenticated
  publication marker; injected interruption recovery; runtime/session fencing;
  exact operation outcomes and protected disclosure.
- Masked hierarchy, fresh operation-bound WebAuthn changes/reveal, ordinary and
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
| native-store.php | 40 persistence/fencing/idempotence/corruption/path checks |
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
