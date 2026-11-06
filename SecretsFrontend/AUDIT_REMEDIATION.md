# PR #8 implementation audit — remediation evidence

Reviewed baseline: `c0e995d8f355a36c19349e2b56ad223184accf4f` (30 October 2026). The auditor's adverse hardware, revocation, acquisition and DOM outputs were reproduced on that exact source before editing. This change addresses the concrete findings without changing the old SecretsManager, its dependencies, or any other existing module. Independent verification of the replacement commit remains pending.

## Changes and executable checks

| Finding | Implementation correction | Regression evidence |
|---|---|---|
| A01 hardware trust | A new backend-only verifier passes configured CA files as trust anchors and supplied intermediates only as OpenSSL's untrusted chain argument. The inherited root-validation helper is never used for the new hardware decision. The initial supported hardware profile is packed ES256, X.509v3 attestation subject/basic constraints and a signed matching model/AAGUID extension. Unknown roots, self-attestation and unsupported profiles fail closed. | `SecretsBackend/tests/hardware.php`: rogue chain with/without its own self-signed root, expired leaf, wrong/missing signed model, invalid subject and CA leaf rejected. Configured root and configured-root/intermediate paths succeed with synthetic certificates. Mixed write-only hardware policy refuses ordinary-passkey credential and trust-profile changes. No physical hardware was tested. |
| A02 authorization race | A final grant claims an exact validated head/owner in a SQLite transaction, revalidates session/credential/policy there and sends that exact predecessor to the witness. Login/reveal require the exact counter-publication head; responses use their held, authorized snapshot. Newer heads are never silently substituted. | `SecretsBackend/tests/audit-races.php`: the auditor's two-connection, real-Python-witness interleavings reject reveal after revocation and metadata after session invalidation. A response already authorized before later revocation is still permitted to finish. |
| A03 stuck acquisition | A signed definitive rejection closes that attempt; a subsequent automatic recovery revalidates the current recoverable head before allocating another attempt. Unknown/lost responses preserve the durable existing ID. A superseded successful acquisition remains locked. | `audit-races.php`: delayed old advance wins, acquire is rejected, next recovery publishes the exact pending head. Existing lost-acquire-ack test still verifies no duplicate fence transition. |
| A04 recovery scheduling | Ambiguous request-time commits visibly lock management and schedule coordinated recovery, with 1–30 second backoff. Recovery does not replay the browser mutation. Explicit initial-provisioning commits also schedule recovery on failure. | `SecretsFrontend/tests/module-security.php`: outage before persistence discards the unanchored prepare; lost acknowledgement after persistence publishes the exact anchored state. Recovery timer, backoff and eventual resumption are checked in the Symcon simulator. |
| A05 security configuration | Explicit initial sealing is available only before any administrator exists. It pins a separately encrypted bootstrap profile and records the active management profile in the anchored policy. Normal apply/import cannot replace provisioned foundation trust, paths or frontend binding. Hardware settings are staged; activation is an exact passkey-approved configuration operation, requiring current eligible hardware whenever any hardware action is enabled. Approved file contents are fingerprinted; external drift locks management. An already-used hardware credential profile revision cannot be reused. | `module-security.php`: wrong digest/refused reseal, rejected foundation import without partial mutation, staged settings remaining inactive, approved profile publication and file-drift refusal. `hardware.php`: mixed-policy hardware boundary and stale-profile worker refusal. Foundation relocation/anchor rotation remain unavailable pending independent recovery tooling. |
| A06 audit semantics | Anchored mutation events include opaque actor/target, action, deployment/backend/frontend, before/after vault revision/index, application ID, witness advance ID and outcome. Final grant claims are transactionally logged with exact request body, operation digest and a digest bound to the audit context; verified signed witness receipts correlate completion. Console enrollment authorization issuance is logged atomically with its disposable authorization. Rejection telemetry excludes raw input and is capped at 20/minute and 1,000 retained rows. | `module-security.php`: durable fields, secret canary absence, encrypted grant-context/receipt correlation and rejection limits. Successful/core/grant audit retention is not pruned; safe retention/GC and operational investigation tooling remain release gates. |
| A07 browser lifecycle | A UI generation invalidates outstanding fetch/WebAuthn continuations on hide, navigation, selection/context changes, cancellation, clear and logout. Abort signals are an optimization; ignored aborts still cannot publish old results. Temporary input clears on in-app navigation and has a local ten-minute expiry; WebAuthn ceremonies also expire locally. | `SecretsFrontend/tests/ui-races.cjs`: delayed reveal after eight cleanup triggers, cancelled WebAuthn, delayed setup/enrollment, credential expiry and navigation clearing. Mocks deliberately ignore abort signals. DOM evidence only. |

## Additional concrete review gaps addressed

- **R68 ownership:** persistent instance/storage binding, encrypted bootstrap identity/path pin, duplicate-storage rejection, one module transition semaphore and a stable OS lock. Apply/disable installs `INSTALLING` and invalidates old local authority before successful return. Final authorization holds a shared transition lock through the bounded witness request; reload/recovery needs its exclusive lock. If a transition cannot acquire its lock it fails explicitly and does not report a new active runtime. Paused grants/writes are refused after invalidation. `runtime-lock.php` uses a real second OS process to verify lock exclusion.
- **R71 signed response validation:** closed Response/Head/Owner/Decision schemas, decimal/UUID/digest checks, request/operation/action bindings and successful head/owner transition checks. Current envelope state must not precede or contradict a historical durable decision. `anchor-responses.php` supplies independently signed malformed/contradictory responses; interoperability still uses the real Python service.
- **R72 initialization:** private files are created with a restrictive umask; each new local storage directory entry and final vault/key directories are explicitly fsynced. Witness initialization also fsyncs its directory and parent. These calls do not establish host power-loss acceptance.

## Reproduce

From the repository root with PHP 8.2+ (OpenSSL, sodium, mbstring, PDO SQLite), Python/cryptography 50.0.2 and Node/jsdom 26.1.0:

```sh
php SecretsBackend/tests/run.php
php SecretsBackend/tests/interoperability.php
php SecretsBackend/tests/hardware.php
php SecretsBackend/tests/audit-races.php
php SecretsBackend/tests/anchor-responses.php
php SecretsBackend/tests/runtime-lock.php
php SecretsFrontend/tests/module-security.php
python3 SecretsBackend/tests/anchor_test.py
python3 SecretsFrontend/tests/structure.py
```

Run `npm ci --ignore-scripts`, `npm test` and `npm run test:security` in `SecretsFrontend/tests`. The dedicated GitHub workflow executes these alongside unchanged legacy regressions on PHP 8.2 and 8.4. Its run identifies the exact commit tested. A failed security assertion exits nonzero; a completed reproduction script is not automatically a security pass.

Local evidence uses PHP 8.3.6, SQLite 3.45.1 with the explicit test-only DELETE journal, Python and jsdom. The PHP/Python bridge exercises the real witness protocol without network TLS. The module lifecycle and timer checks simulate Symcon. No real Symcon host, browser, hardware device, production TLS/proxy layout or WAL power-loss behavior was verified here.

## Remaining acceptance gates

These fixes do not certify v1.3 or claim the 92 baseline/11 hardware checks passed. Re-review the exact replacement commit. Physical-key/metadata lifecycle and compatibility, real Symcon supervision, the deployed WAL/OS/filesystem failure matrix, TLS/proxy deployment tests, capacity/monitoring/GC, full protected-field tamper coverage, user-visible unknown-operation recovery and witness credential rotation/recovery remain open. Synchronization, OAuth, vault backup/restore and migration remain unfinished and are not enabled by these corrections. The central documentation/backup integration remains outside the authorized changes to other modules.

If an earlier development vault already contains administrator credentials, this change does **not** grandfather their old hardware classification or silently provision it. Use a new empty test vault; preserve any old test data for controlled investigation. There is no migration or production rollout in this PR.
