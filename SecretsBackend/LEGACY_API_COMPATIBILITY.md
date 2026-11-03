# Legacy SEC API compatibility — development implementation

Status: application-data and protected-page compatibility implemented; migration has not started. No existing installation, object ID, old vault, old key file or legacy synchronization configuration has been changed by this work.

## What stays identical

The new backend exposes the original public method names, parameter names/types, required argument counts and return types. Its installed prefix remains `SECB` so the two implementations can coexist. A separately built replacement of the original `SecretsManager/module.php` retains the original module GUID and `SEC` prefix. Existing `SEC_GetSecret(49800, 'Hikvision')` calls then dispatch through the same instance to an explicitly selected new backend. Consumer code does not change. Updating only the ordinary development branch does **not** activate this replacement.

The original module and its 33 baseline files remain unchanged in the development source. The replacement template contains no old decryption, key-generation or legacy synchronization implementation. Merely selecting the branch is insufficient: the existing instance must be explicitly bound to its initialized backend, and the exact instance, original role and application permissions must already be approved.

## Compatibility coverage and boundaries

| Original API | Native behavior |
|---|---|
| `GetKeys(): string` | JSON string of top-level Global application names; hides internal areas and omits unavailable conflicted entries. |
| `GetSecret(string $ident): string` | Exact top-level key lookup, scalar-to-string conversion, structured JSON text, legacy empty-folder/list formatting, and empty-string failure. `__LOCAL__` returns this installation's Local application data. A slash in the identifier remains a literal key, not a nested lookup. |
| `GetExplorerFields(string $ident): array` | Nested application path lookup with `Key`/`Value` rows and legacy scalar conversions. Uses a root-relative path; the old console Explorer's transient navigation state and `EXPL_*` UI actions are not replicated. |
| `SetRecordFields(string $path, array $fields, string $scope): bool` | Same path/field normalization and scalar replacement while preserving nested folders. Local works in all old roles; Global retains the original Master-only rule. Changes commit through the new encrypted journal and Global peer queue. Unrelated typed native subtrees remain unchanged. |
| `ExportLocalSecrets(): string` | Same pretty-printed `__LOCAL__` application envelope and folder markers. Native administrator credentials are deliberately excluded. |
| `ImportLocalSecrets(string $json): bool` | Replaces only Local application data; malformed inputs fail. Any `__AUTH__` input is rejected atomically, including otherwise valid Local data in the same request. |
| `EncryptAndSave(string $jsonInput): void` | Explicitly approved bulk application replacement, with the original success/error output and Master/Standalone role behavior. Omitted Local data is cleared as in the old implementation. Native administrators, policy, pairings and keys are preserved. Internal/credential injection is rejected. Requires separate bulk permission and an unfrozen writer. |
| `IsPortalAuthenticated(): bool` | Checks the new origin-bound server-side session, actual credential, administrator, origin generation, revocation, idle/absolute expiry, and backend readiness. Anonymous/error cases return false. Does not refresh or extend the administrator session. |
| `ClearVault(): void` | Clears compatibility editor state only. The old function also only hid/cleared its editor; it did not erase the vault. |
| `CheckLocalSecretStore(): string`, `CheckDirectory(): void` | Native status diagnostics, rather than diagnostics for obsolete `system.vault`/legacy keys. |
| Legacy admin/UI APIs listed below | Their exact method signatures are present for discovery, but execution explicitly refuses and points to the native approved workflow. These are **not behavior-compatible operations**. |

Explicitly unavailable legacy operations: `SaveAuthToken`, `ShowToken`, `SaveHookPass`, `SaveSlavePass`, `GenerateToken`, `SyncSlaves`, `InitializeSlaveSecretStore`, `LoadVault`, `UpdateUI`, `RemoveAllPasskeys`, `RevokePortalSessions`, `ResetPortalLoginPageRateLimit`, `ResetPortalChallengeRateLimit`, and old `RequestAction` console Explorer actions. Master/slave shared-key transport has no safe equivalent in the peer protocol. Credential administration and throttling cannot bypass the new approval rules. `__AUTH__` and other reserved identity data are never exposed by the compatibility application view.

Thus **application interface compatibility is implemented; universal behavioral equivalence is not claimed**. Scripts using those administrative calls must use the new approved workflows before being accepted for migration. This distinction is intentional and must remain visible in migration reports.

## Approval and freeze

For a local script calling `SECB_GetKeys` or `SECB_GetSecret` directly, approve the **new backend instance ID itself**, select Standalone, allow application reads and leave write/bulk/protected-page rights off with writes frozen. Administrator browser sign-in is separate from this local application grant. The Overview automation count currently refers to per-token capabilities; it is not proof that a direct legacy-shaped read grant exists.

For the later same-ID replacement, in **Automation access → Existing SEC applications**, enter the old instance ID and its unchanged role (0 receiver, 1 sender, 2 standalone). Review enabled/read/write/protected-page/bulk rights and the write freeze. Access defaults to disabled; write and bulk permission default off; freeze defaults on. Approval uses the existing exact, fresh WebAuthn operation and hardware policy. The approval includes the precise instance, role, rights and Global tree identity. Grant revocation, changed backend/role, pending configuration, inactive instance or changed tree identity denies access. Grants are local to this installation and are not shared as Global secrets.

Legacy local PHP callers have the original trusted-host authority model: no extra token argument is added. Approving read access permits those callers to read **all application Global and Local data** exposed by that manager. It does not identify individual scripts. This broad grant is a deliberate migration permission, distinct from new per-path capability tokens. The browser request allowlist does not expose `CallLegacyAPI` or arbitrary PHP methods.

Writes check freeze and approved binding again inside the journal transaction, validate native limits and record a sanitized audit event. Conflicts fail the affected exact read/write rather than selecting a version. API failures retain legacy empty/false fallback values. Refused read calls now issue a sanitized PHP warning, and the internal dispatch envelope includes an explicit error instead of representing refusal as a successful empty result. `SECB_GetLegacyAPIStatus($backendID)` reports the direct backend read grant and readiness without record names, values, storage paths or raw exception text. It distinguishes missing/disabled/read-denied grants, changed Global identity, disabled backend, pending settings and unavailable native storage/security configuration. The backend clears its generic `LegacyAPILastError` buffer after a successful operation. Bulk failures produce the original encryption-error output. No automatic legacy fallback runs.

## Existing login hook

The replacement preserves `/hook/secrets_<instance>`. A GET with `portal=1&return=/hook/library` uses the new passkey login at the current approved origin and returns to that local hook after a full administrator login. Existing sessions go straight back. The same secure, host-only session cookie is validated locally; there is no token in the return URL, cross-origin cookie transfer, secondary session or independent expiry to reconcile. The fragment stores only the public return path in the current page and is never persisted in browser storage.

Only a plain local `/hook/<name>` return path is accepted. Query-bearing return URLs, external addresses and authentication-hook return loops are refused. Old registration, administrative and synchronization requests are refused. Primary and full approved Magic access keep separate cookies/credentials and use the current origin; a Magic login does not contact or redirect through the primary hostname. Pending/limited/revoked Magic access grants no protected-page access. Logout, credential revocation, origin removal, expiry and restart invalidate access. The session parser rejects duplicate cookies, including adjacent duplicates.

## Building the later replacement branch

After reviewing and committing this development change, use a **clean disposable checkout of the exact commit**:

```sh
git switch -c migration/legacy-sec-replacement
python migration/build-replacement.py .
git diff -- SecretsManager/module.php migration/replacement-manifest.json
```

The builder changes only the original module implementation and adds a manifest of the source commit, original SHA-256 and preserved identity. It does not connect to Symcon or activate anything. Commit the result to that dedicated branch only after migration preparation. Do not run the old implementation's unchanged-file or state-machine test suites against the replacement implementation: those suites verify the original implementation. The application differential suite in the development source loads the real original implementation and the exact replacement template together and tests unchanged `SEC_*` dispatch against both.

Before selecting the replacement in Symcon: finish the per-installation backup/restore rehearsal, import and verify Global/Local application data, approve the existing instance with writes frozen, disable legacy synchronization on all platforms, then bind each preserved instance explicitly. Preserve all original properties, child variables, old Vault ciphertext and key files. The template re-registers the existing legacy fields/variables with their original identifiers. Rollback requires the previous code **and** the saved configuration; changing branches alone does not reverse new data writes. Old storage is never dual-written. The test installation must exercise its 18 scripts and eight configured instances before any operational replacement.

## Verification evidence

`SecretsBackend/tests/legacy-api.php` compares real old encrypted-vault calls with the native implementation and exact replacement template, checks every original public signature and dispatches unchanged `SEC_GetSecret(49800, ...)` calls. It covers scalar/JSON/empty-folder behavior, nested field writes, Local export/import, roles, freeze including bulk replacement, reserved-area rejection, old storage preservation, applied configuration, source status, precise backend binding, protected hooks, return-path rejection, duplicate cookies, expiry, revocation and restart. It runs without database drivers under the 32 MiB native runtime profile.

`SecretsBackend/tests/legacy-peers.php` verifies real encrypted delivery of compatibility Global writes, per-installation Local isolation, concurrent conflict rejection, unaffected records, atomic rejected writes, freeze and revocation.

The native runner also exercises existing passkey, backup, peer, four-platform synchronization, Global-conflict and provider regressions. Full Magic lifecycle fixtures verify compatibility login and returns entirely at the approved Magic origin. Browser tests check permission defaults, exact approval data and return-path restrictions alongside the existing import wizard. Real device/passkey, Connect outage, backup restore and inventoried deployment acceptance remain outstanding; no laboratory test is evidence that migration has taken place.
