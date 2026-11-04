# Native-only replacement branch

`migration/legacy-sec-replacement` replaces the old module implementation. It does not install or switch anything on Symcon by itself. Keep this branch separate from `feature/secrets-frontend` until deployment acceptance is complete.

## What runs

The original module GUID `{7C5A3841-3F7B-4D2A-9E1C-5B6D8F9A0E12}`, `SEC` function prefix and existing Symcon instance IDs are preserved. The registered `SecretsManager/module.php` contains only the new backend adapter. For example, `SEC_GetSecret(49800, 'Hikvision')` uses the new native vault. Consumer IDs and application calls stay unchanged. Native `SECB_*` and capability APIs remain available in parallel.

The old manager has no executable storage, login, key-generation, synchronization or fallback path. Its saved properties, Vault variable and key files are retained snapshots; an administrator can explicitly import their values into the new vault. Old master/slave roles and PortalEnabled do not authorize the native system. Import old vault defaults to Local secrets only and requires a fresh preview and native administrator approval. It never calls old manager code or updates old storage. Discovery of native peer trust from old connection settings remains disabled. Native peer sharing uses only native policy.

A single ready native backend is discovered automatically, then its instance and vault identity are pinned. Automatic mode leaves the selection property at zero; it never recursively changes/applies its own settings. If the backend is still recovering at startup/update, a five-second binding retry completes setup once it is ready. Several ready backends require selecting the intended backend by name. No numeric ID or API mode selection is required. A missing, disabled or changed pinned backend refuses calls; it cannot fall back to old data or silently choose another vault.

All old instances on an installation switch together. On the test system that includes PasswordSafe 49800 and Standalone PasswordSafe 59597. Both will use the selected native backend, so verify that its Global and installation-private Local data meet the needs of both consumers before selecting this branch.

## Access and behavior

Application reads default to enabled. Explicit native access revocations and Global-identity restrictions remain effective. Writes default to frozen and require native approval under Automation access → Existing SEC applications → This native backend. Bulk application replacement requires its additional permission. These trusted local PHP calls expose application Global and Local data; native administrator credentials remain excluded.

Protected pages use the native passkey login and current native session. Old passkeys, tokens, cookies and portal settings have no authority. The preserved `/hook/secrets_<oldID>` redirects GET requests to the current approved native administration origin. Plain local hook returns are supported; old sync/admin requests are refused.

Old administrative functions such as shared-key setup, `SyncSlaves`, credential reset and old Explorer actions explicitly refuse execution. Their signatures remain discoverable; their former behavior is not reproduced. Migrate any consumers of those functions to native workflows before acceptance. Details: [API compatibility](../SecretsBackend/LEGACY_API_COMPATIBILITY.md).

## Before switching the test installation

1. Remain on `feature/secrets-frontend` at source commit `d612e52c772beea3c39f7994a2f354169e451ac1` or an appropriately reviewed successor while preparing data. Finish any old-vault import there; this replacement branch cannot read old storage.
2. Save complete Symcon configuration, both old vaults and key files, plus a native encrypted backup and its separate recovery key. Rehearse restoration in isolation. Record the source branch/commit. Keep rollback copies offline.
3. Freeze manual and automated secret updates, including OAuth/provider jobs and other platforms. Native compatibility write freeze alone does not freeze browser writes, machine tokens, peer input or provider refreshes. Keep the migration window stable.
4. Run [Preflight_Native_Replacement.php](Preflight_Native_Replacement.php) as a new local Symcon script BEFORE switching. It discovers instances and compares old Global/Local application values with the ready native vault, showing counts only. Missing/different values, unreadable or empty old baselines, changed state or ambiguous backends block this check. A pass establishes data coverage only, not complete deployment acceptance.
5. Review the inventoried 18 scripts and eight configured consumers for unsupported administrative calls. Record the expected read results and tests without logging secret values. Stop old synchronization across affected platforms for the cutover.
6. Select this branch in the test installation's module control. Every old instance now runs the native adapter. Check `SEC_GetReplacementInfo($existingID)` for `engine: native-only` and `ready: true`; the selected backend is reported. On the known test installation the intended native backend is 18262; nothing needs entering if it is the only ready backend.
7. Exercise the original calls and IDs from local scripts and all inventoried consumers; verify Local scope, native authentication, expiry/logout/revocation, restart, peer synchronization and full Magic access during a primary outage. Keep writes frozen until these checks pass, then approve only the required native write permissions.

The reported 32 top-level Global keys and UI totals of 142 Global values / eight Local values are different measurements. A successful key listing does not establish value equality, backup restorability or consumer acceptance. No live switch or value comparison has been performed by this branch preparation.

## Rollback and later removal

Restore the saved code commit AND saved Symcon configuration/state before re-enabling old synchronization. Branch rollback alone cannot undo native writes or reverse the new bindings. There is no dual write or copying back to old files. Reconcile any native changes explicitly if writers were enabled.

After acceptance and the rollback retention period, inactive old files and configuration can be deleted separately. Keep the small SEC entrypoint for as long as consumers require the original function names and instance IDs. It belongs to the new manager and contains no old vault implementation.

## Automated evidence

`.migration/tests/replacement-runtime.php` runs the actual registered adapter against a real encrypted native fixture, with nonexistent old key files and unreadable retired configuration. It checks original IDs/calls, automatic selection, pinned identity, native reads, freeze/approval, native login, rejected old synchronization, explicit revocation, ambiguity and restart. `.migration/tests/preflight.php` tests matching/missing/unstable baselines and concealed warning failures. The native runner covers encrypted storage, WebAuthn, backup/restore, peers, conflicts, Magic and provider operations without database drivers and within 32 MiB. Browser controls and manifest hashes are checked separately.

Pinned old-code regressions run only in a temporary build/test fixture, restored in `finally`; old code is never loaded by the installed module. Retired old-import and old-TLS-discovery suites are explicitly skipped, with native-only refusal checked instead. Laboratory checks do not substitute for the live acceptance above.

## Read-failure containment and diagnostics

SEC and SECB application read failures return their compatible empty/false values without PHP warning/notice output, so a consumer's configuration-form JSON and RPC response remain parseable. A sanitized message is logged at most once per minute per instance; the latest failed method/code/time remains available in status diagnostics. Missing application records are reported as `APPLICATION_RECORD_MISSING`, without names or values in logs. This does not enable a denied read or access old storage.

Open the preserved Secrets instance and select **Show native connection status**, or call `SEC_GetReplacementInfo($existingID)`. The form also shows binding/access status, including `NO_READY_BACKEND`, `BACKEND_NOT_READY`, `PENDING_SETTINGS`, `AMBIGUOUS_BACKENDS`, `PINNED_VAULT_CHANGED` and the native read-access code. Automatic retry does not apply pending edits, replace a pinned vault or override revocation.

The reproduced warning-prefix failure explains the broken consumer form. The startup/update-order test reproduces an instance applied before native recovery and verifies later automatic binding. Neither laboratory finding establishes the cause of a reported host/process crash; deployment logs and an actual post-update read remain necessary.
