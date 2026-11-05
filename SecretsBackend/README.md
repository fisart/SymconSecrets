# SecretsBackend: native Symcon vault

The new default is a standalone encrypted native vault with optional bilateral
peers. The existing SecretsManager is a different module and stays unchanged.
Use the [HTML setup guide](../SecretsFrontend/README.md). Current evidence and
remaining qualification are in [release status](../SecretsFrontend/RELEASE_STATUS.md).

## Runtime

`NativeStore.php` implements the shared storage interface with complete AES-256-GCM
encrypted snapshots, immutable authenticated commit markers, separate key files,
exclusive file locking, checked writes/file synchronization and platform-specific
directory synchronization. Highest-state corruption locks recovery; an old state
is not substituted. Runtime nonces fence workers, sessions and one-use grants.
Values, permissions, audit, outcomes and pending jobs publish in one snapshot.
This supplies local integrity/recovery, not independent rollback detection.

Capabilities are detected in supplied PHP. Defaults use dedicated private folders
under `IPS_GetKernelDir()`. Capacity adapts to free memory and is capped at 4 MiB
per complete plaintext snapshot. Ordinary changes leave 25% capacity reserved for
recovery/revocation/backup. There are at most 32 peers, 128 queued delivery jobs,
128 machine grants, 32 providers, 128 retained effects and 512 transient records.
Ordinary retained outcomes stop at 3500; recovery actions have a reserved limit
of 4112. Verified explicit backup compaction keeps the latest 512 outcomes/audit
entries, current receiver cursors and uncertain effects. A full outbox blocks
further shared publication before any partial state is committed.

`NativePeer.php` / `NativeTransfer.php` implement purpose-bound signed envelopes
and sealed recipient payloads, bilateral invitation approval, ordered delivery,
exact receipts, lost-response idempotence, authenticated catch-up, revocation,
reachable-owner transfer and explicit new-lineage forks. Local values never enter
peer payloads. Unknown fields/keys/epochs/recipients are rejected. Same-process
routing verifies the complete public descriptor before calling another backend;
remote delivery uses supplied curl with certificate/hostname verification, no
redirects, bounded responses and short timeouts. Missing supplied transport is
reported; no package installation is requested.

`NativeOperations.php` connects management to the existing fresh exact WebAuthn
approval. Additional-key candidates are bound to the authorizing head, credential and
browser-key digest; changes/revocation invalidate them. Independent console
recovery uses an explicitly approved replacement passkey candidate. Ordinary credentials cannot bypass
an enforced hardware policy to add a new approver.

`NativeBackup.php` exports complete authenticated state/key material inside a
separately encrypted recovery envelope. Authenticated session-bound chunks carry
browser uploads below the 64 KiB request cap. Supported restore imports reviewed
values into the current vault and retains its current authority; it does not
resurrect older permissions, peer identities or external-effect execution.

`NativeEffects.php` commits PREPARED and SENT_UNKNOWN before provider dispatch,
captures encrypted completions and conditionally commits token pairs. Uncertain
non-idempotent requests are quarantined. Only explicitly declared idempotent
providers may reuse the same request key for bounded retries. Provider-specific
idempotency and real network behavior require acceptance testing.

## Scoped local integration APIs

Create the capability in the HTML interface; a token permits only its approved
scope, path and descendants. Scopes are `local`, `global`, `received:<tree UUID>`
(read-only cached copy) and `owned:<tree UUID>` (current shared owner). The HTML
selection supplies the full scope automatically. These are local Symcon calls,
not anonymous hooks.

```php
$result = json_decode(SECB_ReadNativeSecret(
    $backendID, $capabilityToken, 'local', '["ASK","Pass"]'
), true);
// $result contains value and current revision.
```

Read/write capabilities additionally permit:

```php
$result = SECB_WriteNativeSecret(
    $backendID, $capabilityToken, 'local', '["ASK","Pass"]',
    json_encode($newValue), $expectedRevision, $nextSequence, $stableOperationUUID
);
```

A successful write increments the revision/sequence once. Repeating the exact
last UUID/bytes returns the committed outcome. Different bytes, older sequences,
stale revisions, revoked tokens and wrong paths are rejected. Local integrations
must keep tokens protected; a compromised Symcon process is outside this vault's
isolation boundary.

## Qualification

No installed database/extension, external service, shell or other executable is
used by native operation. Go/Python/SQLite files retained in the repository are
historical test/reference components, never a native fallback. Fresh instances
refuse existing storage. The old SEC APIs and vault are not called or migrated.

Local automated tests are not a certificate for arbitrary filesystems/hardware.
Real Symcon lifecycle, HTTPS isolation, physical passkeys, different hosts,
Docker replacement/restore and physical power interruption still need acceptance.

## Refused-request diagnostics

A refusal now records a random reference, UTC time, backend/frontend IDs, allowlisted action and operation, failed stage, fixed reason code, exception type, backend source filename/line and session/CSRF verification facts. The last twenty records survive recovery and remain available with debug disabled or a locked vault. No exception messages, traces, request bodies, cookies, CSRF tokens, credentials, secret paths or secret values are retained in this report.

1. Update the Secrets library on `migration/legacy-sec-replacement`, then reopen the administration page and sign in again.
2. Repeat the refused action once. The page identifies session expiry, invalid session/CSRF, expired approval, changed emergency offer or a concurrent revision where known; it shows a diagnostic reference. Details requiring authorization are returned only after session and CSRF verification. Unauthenticated failures retain a generic response except safe sign-in guidance.
3. In the Secrets Backend console, use **Show refused-request diagnostics**, or inspect **Last refused request (safe diagnostics)** below the backend. `SECB_GetRequestDiagnostics` is local/read-only and does not open the vault.
4. Update Configuration Backup to 1.3.10 and upload **GitHub diagnostics**. Reports include these failures and pending emergency offers even if mesh collection is unavailable.

An expired session returns the browser to sign-in, clears sensitive controls and stops status polling. It never repeats an approved mutation automatically. A refusal after commit can still mean the action completed; review current configuration/outcome before requesting another grant. Earlier generic failures cannot be reconstructed retroactively from these new records.
