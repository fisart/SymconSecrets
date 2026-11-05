# Availability-first emergency Global access

Implemented for the native replacement branch. Runtime qualification on the actual installations remains a deployment check. No remote access is enabled merely by installing the module update or by pairing vaults.

## Policy and supported applications

Use the local vault normally, including standalone and disconnected operation. If the local vault cannot open, or is behind the last authenticated emergency checkpoint, existing Global `SEC_GetKeys`, `SEC_GetSecret` and `SEC_GetExplorerFields` calls (through their pinned native replacement backend) can use an explicitly approved remote source. The equivalent backend compatibility calls use the same path.

This release does not forward administrator sessions, passkeys, writes, imports, exports, Local records, OAuth effects, or separately scoped `ReadNativeSecret` capability calls. The latter continue to require their local authorization; a broken local vault is not permission to widen those capabilities. Remote Local data never substitutes for `__LOCAL__`. Large individual responses exceeding the bounded emergency reply size (40,000 bytes including JSON metadata, under the 64 KiB transport envelope) fail explicitly rather than truncate.

Standalone operation requires no peer, quorum or emergency setup. With one approved reachable peer, fallback can work regardless of how many other installations exist. Multiple alternatives are supported within the existing 32-peer limit. Updates are still acknowledged locally and replicated asynchronously. Remote freshness is **best available, not guaranteed current**.

Known older versions are refused using the persisted causal checkpoint and fresh authenticated observations. A candidate must dominate the known checkpoint and all successful observations made for that request. Incomparable histories, same-clock/different-content histories, conflicts in the selected subtree, missing records, denied grants and invalid replies are errors. Only availability/transport failures can move a request to another equally eligible approved source. Data may still lag an unreachable writer whose newer version has not been observed; the alarm indicators make that uncertainty explicit.

## Setup — two approvals, no credential copying

Update SymconSecrets on every participating source and receiving installation to the compatible native replacement version. Existing pairing must be active and shared Global synchronization should have settled.

1. Open **Connections → Emergency Global access** on the vault that will supply data.
2. Select the paired installation whose applications may read from it. Click **Approve emergency read access** and approve the exact Global-only grant with the normal administrator passkey/hardware policy.
3. The existing encrypted peer outbox delivers an offer automatically. No emergency access is activated on the receiving installation yet.
4. Open **Connections → Emergency Global access** on the receiving installation. Under **Offers awaiting approval**, choose **Enable this emergency source** and approve the exact provider and scope.
5. Wait for its watchdog check. The source appears under **Emergency sources for this installation**. Check the backend's emergency status and variables.
6. Repeat for other providers if wanted. Reverse direction is a separate, explicit grant. Neither pairing nor receipt of an offer grants emergency authority automatically.

Approval authorizes trusted local SEC applications on the selected installation to read all replicated Global application data from that provider. It grants no Local data, write or administrator authority. The dedicated credential cannot be used as an ordinary native machine capability or administrator session. Both the current grant and current pairing are checked by the remote provider on every request.

**Revoke emergency access** on the provider takes effect at that provider's next request authorization. **Remove source** on the consumer stops using that provider. A denied grant is terminal for that read; remove a deliberately revoked provider from the consumer's sources to use its remaining independently approved providers. The backend console's **Stop emergency fallback** button is available even if the local vault cannot open. Automatic monitoring does not undo that stop; re-enable through a newly approved offer/import while the local vault is healthy.

## Independent credential storage

Each consuming backend stores a private credential capsule in:

`<Symcon kernel directory>/secrets-native-emergency/<backend ID>/`

`access.key` encrypts `access.sealed` using supplied sodium authenticated encryption. The separate key is not the local vault's master key. The encrypted capsule contains approved remote credentials, pinned recipient identities/routes, a source/configuration binding and version checkpoints. It contains **no cached secret values**. Files use the native private-file checks and 0600 mode; directories use private permissions (and the deployment's required private ACLs on Windows). Atomic publication and fsync follow the supported platform profile; Windows does not acquire a new directory power-loss guarantee from this feature.

Persist and protect this directory with the Symcon installation and treat its contents as sensitive credentials. A full host/standby backup must include it. Ordinary configuration exports should not contain it. Native encrypted backups retain the approved configuration in their protected state, but value-only restore does not activate authority. Do not copy a capsule to an unrelated backend or different installation identity. Source identity, instance and applied security configuration are checked before use. Missing/corrupt independent keys or files cause refusal and require reviewed re-provisioning; they are never silently replaced while serving fallback.

Before local compatibility permissions, emergency clients or trusted peer/routes change, the runtime blocks the external credential copy. A healthy watchdog can publish the current approved copy afterward. A crash in between fails closed. In-flight reads recheck that copy after network I/O and before exposing any result. Remote grant revocation is checked against the provider's current encrypted state, not against the capsule's last checkpoint.

## Data path and return to local

Requests use the already approved native peer HTTPS endpoint. Credentials and request details are sealed to the pinned provider key. Each response is signed by that provider and sealed to a new ephemeral reply key; request digest, nonce and phase bind it to the exact call. Old signed replies cannot satisfy a new call. HTTPS uses the existing strict/pinned-primary policy and only approved routes; redirects and arbitrary new targets are refused.

Each emergency operation has an eight-second application budget, with at most 1.5 seconds per transport attempt and a reserved read phase. DNS/OS/filesystem stalls can exceed userland timeout enforcement; the existing watchdog/remote monitoring limits still apply. Each provider permits 120 emergency requests per minute per grant (probes and reads both count). Capacity exhaustion is temporary unavailability and may use another eligible provider. A per-peer circuit breaker avoids repeatedly calling unavailable peers. Candidates not reached within the budget remain unprobed and freshness remains uncertain. No local vault file lock is held across network I/O. Emergency reads are serialized per backend to bound load; contention produces an explicit unavailable result. Normal local calls do not perform remote requests.

Successful observations advance the independent causal checkpoint, including when a later read fails. Older data can never lower it. A recovered local vault stays behind emergency access until its Global state reaches that checkpoint; two consecutive healthy watchdog checks then return use to local. The watchdog probes emergency availability without reading values when local validation is unavailable. It never initializes a missing vault, replaces local keys or writes a remote value into the local vault. The normal authenticated synchronization process performs catch-up.

The current source must be running Symcon and have the updated backend module loaded. If the entire production process or host is stopped, its code and Boolean variables cannot run: use the established Proxmox standby procedure and monitoring from another installation. This feature is application-read fallback, not automatic host promotion.

## Alarm variables below the backend

| Ident | Meaning |
|---|---|
| `FallbackActive` | An approved remote source is currently selected and available. |
| `ActiveSource` | Local vault, or the selected peer's name and identity. |
| `SecretsUnavailable` | No usable source has been confirmed by the current watchdog/read attempt. |
| `SynchronizationProblem` | Emergency freshness is uncertain, a known history mismatch exists, or local mesh synchronization/credential-copy status needs review. |
| `EmergencyStatus` | Metadata only: mode, readiness, source, last check, fixed reason code and uncertainty. |

Existing `VaultError`, `BackendError` and `FrontendError` keep their local meanings. During successful remote fallback, `VaultError` can remain true while `FallbackActive` is true and `SecretsUnavailable` is false. This lets an alarm system distinguish a degraded local vault from a complete loss of application secret access. Prefer a sustained-error delay for expected restarts. A stopped process cannot update any of these variables; a remote observer is still required for whole-system outage detection.

`SECB_GetEmergencyStatus` reports stale metadata after 90 seconds. `SECB_GetLegacyAPIStatus` retains its local permission meaning and additionally reports whether emergency Global reads were last confirmed available. It does not claim Local or native capability reads are available through fallback.

## Validation and deployment acceptance

Automated tests exercise independent encrypted credentials; five fully meshed native vaults; one and multiple approved alternatives without a quorum; manual/passkey offer acceptance; source identity and configuration binding; actual pinned SEC calls; missing local master key; known older/incomparable versions; missing/conflicting records; denied/revoked grants; response replay; peer loss after probe; cooldown; local revocation during transport; source permission changes; manual stop; source catch-up and stable return to local; no Local forwarding; no credential/value exposure in metadata; and DOM approval controls. Native tests use supplied crypto and no database drivers with a 32 MiB memory limit.

For deployment, provision one provider on a test installation first. Verify its normal reads remain local, then use a controlled test outage/lock while retaining the complete original vault and keys. Confirm the same Global SEC call returns through the peer, Local calls remain unavailable, alarms identify the active source, and recovery returns to local after synchronization. Do not delete production keys or corrupt data to perform this test. Repeat using the normal backup/restart and established standby procedure once the isolated test passes. Real routes, filesystem durability, alarm delivery and host switchover remain deployment checks.

## Relationship to the earlier strict-consistency review

The four-vault stale-majority counterexample remains valid. The approved design was subsequently changed to prioritize availability for any node count. This implementation deliberately does not add a quorum, claim linearizable reads, or block ordinary offline local writes. `strictEmergencyReadSupported` remains false; `bestAvailableEmergencyReadSupported` reports the optional feature. The earlier strict-quorum requirements are retained as a historical alternative, not an activation prerequisite for this availability-first feature.
