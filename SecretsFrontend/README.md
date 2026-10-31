# Secrets Frontend and separate Secrets Backend

Development implementation 0.1.0. These are **two new modules in SymconSecrets**, not an update or replacement of the existing `SecretsManager` module. Existing module source, storage, passkeys and configuration remain unchanged. Do not migrate production data yet.

## Current V2 availability

The HTML setup assistant provides discovery, defaults, exact review, settings
application and a saved peer-deployment draft. The interface now uses a
responsive card layout, clear progress, light/dark appearance and collapsed
advanced settings. On the Storage step, expand **Peer services & recovery** to
prepare three authority locations, two Symcon peers and two recovery locations.
The current installation's HTTPS origin is prefilled. Unknown addresses and
trust remain unconfigured. You can download the reviewed draft separately.
Native exports with a draft use `SECF.Config.v2`; older v1 exports remain
accepted. Imports stay disabled and a v2 draft never enables V1 fallback.

New PHP V2 bundle/key-envelope and original-intent components pass component
interop tests, but are not connected to a management route. The wizard still
ends at **connection pending**. It cannot yet initialize a working V2 vault.
See [the current checkpoint and remaining implementation](V2_INTEGRATION_CHECKPOINT.md).

## Earlier V1 development components

The following features describe the separate earlier single-anchor development
path. Fresh guided V2 setup blocks that path; these are not usable V2 functions.


- `SecretsFrontend` (`SECF`): responsive HTML interface with overview, typed secret hierarchy, selected-record reveal, reviewed create/replace/delete, administrator credentials, hardware policy, storage commissioning wizard and guide.
- `SecretsBackend` (`SECB`): separate encrypted SQLite vault, separate key directory, administrator-only WebAuthn API, one-use approvals, protected core manifests and external-anchor Prepare/advance/Publish recovery.
- Independent development anchor service under `SecretsBackend/anchor`, using mutual TLS, signed messages and a durable decision ledger. It must run outside the Symcon VM and its backup/restore scope.
- Both instances have a `Debug` text variable and `DebugEnabled` switch immediately below the instance. Diagnostics use fixed event codes; request bodies, credentials, secret values and key bytes are not logged.
- Both modules have strict configuration import/export. Imports leave the target disabled. Exports contain settings and file references only: no vault contents, master/private keys, passkeys, sessions, setup codes or pending approvals.
- The frontend can add its link to the existing Portal's **AdditionalPages → Administration** setting. This is an explicit console action; it preserves existing rows and does not change Portal source code.

Read [the audit remediation and evidence](AUDIT_REMEDIATION.md) and [the release status](RELEASE_STATUS.md) before testing. A working development flow is not evidence that the complete v1.3 suite has passed.

## Start with the HTML setup assistant

1. Update the installed `feature/secrets-frontend` branch in Module Control. Keep your existing SecretsManager unchanged.
2. Open **SecretsFrontend**. Paste the trusted HTTPS address you use for Symcon. A saved origin is prefilled; paths/query are discarded. If TLS terminates at a reverse proxy, specify only its exact trusted IPs. Neither browser Host headers nor forwarded headers establish trust automatically.
3. Click **Start HTML setup**. Open the displayed wizard URL and copy its ten-minute setup code into the page. The code authorizes initial settings for new, empty backend instances only; it is not an administrator credential.
4. The HTML wizard discovers eligible backends, Portal and Dokumentation. Existing valid selections are reused; a unique candidate is auto-selected. Ambiguous backends require a choice. Review suggested vault/key folders, appearance, proxy list and Debug. **Restore suggested defaults** restores recommendations for the selected backend.
5. Review the exact summary and save. The wizard applies reciprocal instance references and origin, storage path settings and preferences, optionally registers the Portal link through its existing extension, and offers a settings-only download. It does not create folders, keys, a vault, administrators or connection trust.

**The V2 quorum runtime is still unconnected.** Initial configuration ends at **Settings saved · connection pending**. The backend stays disabled. The new guided mode explicitly blocks the earlier V1 anchor routes; it never silently activates that architecture. Storage creation, runtime connection and administrator enrollment will continue in this assistant when their V2 integration is available. A partial apply consumes its code and requires inspection/fresh authorization rather than automatic replay.

Every wizard entry has a declared default: existing value first, unique detected instance next, otherwise a safe explicit choice. New backends receive private per-instance folder suggestions. Appearance follows the device; Debug defaults off; proxy list defaults empty; optional integrations default to none when not found. Connection credentials, authority pins and hardware trust default to **not configured**. No authority or hardware root is trusted by default. Suggested parent folders may need OS administrator permissions; no root/SSH password is collected.

The initial console step remains because a publicly reachable setup page cannot issue its own configuration authority. The temporary code is stored only as a hash in a transient buffer, scoped to the origin/frontend/backend roster and exact reviewed plan, bounded by expiry/failed attempts, consumed before mutation and invalidated on reload. Browser inputs and in-memory copies clear on cancellation, navigation, expiry and page hiding. Explicit cancellation also revokes the server grant when reachable. No code is put into URLs, properties, exports, Debug or browser persistent storage.

Both forms retain their previous controls in collapsed advanced sections for independent development/recovery. The earlier V1 commissioning guide below applies only to that separate development path; it does not create a V2 quorum system.

The PHP modules require PHP 8.2+, sodium, OpenSSL, curl and PDO SQLite. The earlier PHP WAL vault additionally requires SQLite 3.51.3+ and refuses older versions. The new wizard reports runtime requirements without creating or activating that old vault.

## Wizard: vault and key storage

The two storages are the encrypted vault database and a separate protected key directory, as selected by the owner.

1. Apply the intended paths, frontend binding and HTTPS origin in the backend console.
2. Click **Issue one-use setup credential**. Copy the short-lived code directly into the HTML wizard's password field. It expires after ten minutes and is not a saved module property.
3. The browser sends it only in a same-origin HTTPS JSON POST. The backend stores only its hash, expiry, attempt counter and exact setup binding in its transient buffer. The wizard clears the input after submission and previews the exact two paths and permissions.
4. Review and click **Create both storages**. The code and plan are checked again, consumed before any filesystem mutation and removed from the console field. Existing files are never overwritten. A partial/error result is inspected explicitly; the wizard never manufactures replacement keys for an existing database.
5. Download the resulting **public anchor provisioning metadata** and complete the external anchor setup. It contains no master key, private signing key or setup credential.

No SSH, root or sudo password is collected. The wizard operates with the Symcon service account; collecting an OS password would not grant that process filesystem privileges automatically. Temporary credential inputs are not stored in localStorage, sessionStorage, URLs, module configuration, backup exports or Debug. They are cleared on cancellation, error, navigation and page hiding. JavaScript/PHP memory and browser/OS internals cannot promise perfect physical erasure of every copy; proxy/body logging, crash dumps and swap remain deployment controls to verify.

Master and private connection keys must persist for normal operation, with directory mode 0700 and file mode 0600. They are distinct from the disposable setup/enrollment credentials. Do not delete them after commissioning.

## Secret hierarchy and change approval

The backend stores typed JSON nodes. `{}` and `[]`, numeric object names and numeric array indexes remain distinct. Paths are JSON lists such as `["Mail", "Password"]` or `["Accounts", 0, "Password"]`. Reserved internal names beginning `__` are rejected. Lists support append at the next exact index; no silent gaps or key coercion.

Names and types are loaded after administrator authentication. Values are not prefilled in editors. Enter a new JSON value and explicitly choose Create or Replace; an empty editor makes no change. Every save/delete is reviewed and bound to a fresh passkey assertion and current vault revision. Stale changes are refused. Revealing an object returns only its immediate scalar fields, not values in nested records; visible values clear after 30 seconds, page hiding, navigation or logout.

The new backend verifies hardware chains separately from the untouched legacy verifier: supplied intermediates never become trust anchors. The first supported hardware profile is **packed ES256**, with the certificate subject/basic constraints and signed matching AAGUID/model extension checked. U2F-only devices and devices without that signed model extension are refused for hardware approval. Real-device compatibility remains unverified.

Hardware-only actions require an active credential enrolled with validated attestation, an approved AAGUID/trust profile, user presence, user verification and consistent non-backup-eligible flags. No roots/model profile is trusted by default. Certificate/metadata maintenance and real devices must be reviewed before enabling this policy. A label or USB transport hint is not proof of hardware.

The present enrollment route is explicitly **independent console enrollment/recovery**: an ordinary web session cannot issue its own enrollment code or activate a new approver. Key revocation/policy changes use bound WebAuthn approval; whenever any hardware action is enabled, identity/policy changes also require an eligible hardware key. There is no normal web bypass through a weaker action-class setting. Two eligible hardware credentials must exist before enforcement; the operator must separately establish that these are two physical keys and test both.

## Security configuration and audit

After initial sealing, ordinary form saves/imports cannot replace storage paths, anchor pins/TLS references, administrator origin or frontend binding. These controls are disabled in the sealed backend form; import rejects differing foundation fields before changing properties. Their eventual relocation/rotation needs the independent recovery tooling, which is not released yet. The encrypted `management-bootstrap.json` and persistent storage binding must remain intact. Missing or changed protected trust files lock management. Debug/cosmetic settings require no passkey approval.

Hardware trust settings saved/imported in the console are **staged**. On the HTML Configuration & backup tab, review their exact revision, roots, models and fingerprints, then approve the configuration operation. Whenever any action requires hardware, an existing eligible hardware credential must approve it. Every changed profile needs a new reviewed revision; credentials from the old trust revision cannot approve under the new profile and need independent recovery enrollment. Stage new root files separately rather than replacing files belonging to the active profile. Do not turn an unavailable key into a weaker fallback.

Mutations have structured, secret-free audit context inside the anchored core. Grant claims and verified signed receipts are encrypted locally and correlated with the witness, with bounded rejected-request telemetry. These records supplement the short Debug variable; production audit retention, safe GC and investigation tooling still need acceptance.

## Portal, Dokumentation and configuration backup

Portal registration uses an existing configuration extension. It does not edit Portal source, enable the Portal or grant authorization through it. `IncludeAdministration` must be enabled in Portal for that category to appear.

The complete guide is bundled here and the HTML interface has a Guide section. [Integration files](integrations/README.md) contain the proposed central Dokumentation catalog entry and configuration-backup registration package. The existing central modules use fixed catalogs/registries. **No files in those modules are modified in this development change**, honoring the instruction not to change other modules. Therefore their central registration is pending an explicit exception for those registration changes; they are not reported as already activated.

Each new module can already export/import its own configuration. The central backup module can discover newly installed exporting instance modules as review candidates, but a candidate is not backup coverage. Its new adapters must be registered and parity-tested before the UI claims native restore support. Do not masquerade as another module ID or use an unchecked property-only restore to bypass disabled-on-import behavior.

Vault backup is a separate requirement. Configuration exports do not back up the encrypted database or external keys. Production vault backup/restore, migration, automatic synchronization and provider/OAuth refresh are not released by this development implementation; see the explicit release gates.

## Trust boundary

The original form.json editor belongs to the untouched old SecretsManager and still controls that old vault. It is not a route into the new vault. New backend changes use only its dedicated API, local commissioning/recovery methods and protected storage. Arbitrary privileged same-process PHP or host administrators can still bypass application rules; the design never claimed process isolation from them. A hardware touch does not verify what a compromised browser displayed.
