# Secrets Frontend and separate Secrets Backend

Development implementation 0.1.0. These are **two new modules in SymconSecrets**, not an update or replacement of the existing `SecretsManager` module. Existing module source, storage, passkeys and configuration remain unchanged. Do not migrate production data yet.

## What is implemented

- `SecretsFrontend` (`SECF`): responsive HTML interface with overview, typed secret hierarchy, selected-record reveal, reviewed create/replace/delete, administrator credentials, hardware policy, storage commissioning wizard and guide.
- `SecretsBackend` (`SECB`): separate encrypted SQLite vault, separate key directory, administrator-only WebAuthn API, one-use approvals, protected core manifests and external-anchor Prepare/advance/Publish recovery.
- Independent development anchor service under `SecretsBackend/anchor`, using mutual TLS, signed messages and a durable decision ledger. It must run outside the Symcon VM and its backup/restore scope.
- Both instances have a `Debug` text variable and `DebugEnabled` switch immediately below the instance. Diagnostics use fixed event codes; request bodies, credentials, secret values and key bytes are not logged.
- Both modules have strict configuration import/export. Imports leave the target disabled. Exports contain settings and file references only: no vault contents, master/private keys, passkeys, sessions, setup codes or pending approvals.
- The frontend can add its link to the existing Portal's **AdditionalPages → Administration** setting. This is an explicit console action; it preserves existing rows and does not change Portal source code.

Read [the release status](RELEASE_STATUS.md) before testing. A working development flow is not evidence that the complete v1.3 suite has passed.

## Install on the separate test system

1. In Module Control, select the `feature/secrets-frontend` branch of the existing `https://github.com/fisart/SymconSecrets.git` library. The shared library version remains unchanged to avoid modifying existing library files. Reload the library, then create a new **SecretsBackend** instance and a new **SecretsFrontend** instance. Do not replace or reconfigure your old SecretsManager.
2. Set each new module's reference to the other. Configure the same exact HTTPS administrator origin in both, for example `https://secrets.example.com`. This is a separate administrator login, not a reuse of Portal privileges.
3. In SecretsBackend, choose two separate, non-nested, absolute paths for new/empty private directories. Example: `/var/lib/symcon-secrets-development/vault` and `/var/lib/symcon-secrets-development-keys`. Do not use any old SecretsManager directory. The Symcon account must be allowed to create/write these locations. An OS administrator may need to prepare the empty directories first.
4. Configure the frontend's trusted reverse-proxy IPs if that proxy terminates HTTPS. Only exact listed proxy addresses may supply forwarded host/protocol information. Enable the frontend and apply settings. Keep the backend disabled until the anchor is provisioned.
5. Open the frontend URL shown below its instance. Run the **Setup wizard** described below.
6. Provision the independent anchor, install its client TLS certificate/key and CA file, and configure its URL, signature key ID and pinned public key in SecretsBackend. See [anchor operation](../SecretsBackend/anchor/README.md).
7. Enable the new backend and run **Recover / check independent anchor**. Normal restart recovery runs automatically; failed recovery retries after 30 seconds without ignoring a mismatch.
8. In the backend console, issue a temporary administrator-enrollment credential. Use it in the frontend wizard to enroll a new passkey, then sign in. Old Portal/admin-password sessions cannot grant rights in this backend.
9. Select the Portal instance in the frontend, apply settings and click **Add to Portal → Administration**. The link is a registered local hook; if the Portal has a different hostname, the frontend GET redirects only to its fixed configured HTTPS origin. POST requests are never redirected with credentials.

The module needs PHP 8.2+, sodium, OpenSSL, curl and PDO SQLite. This implementation requires **SQLite 3.51.3 or later for WAL** and refuses to initialize a WAL vault on an older version. There is no runtime switch to ignore that check. Unit tests explicitly use a separate DELETE-journal harness on older developer runtimes; that is not a production WAL test or a supported bypass.

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

Hardware-only actions require an active credential enrolled with validated attestation, an approved AAGUID/trust profile, user presence, user verification and consistent non-backup-eligible flags. No roots/model profile is trusted by default. Certificate/metadata maintenance and real devices must be reviewed before enabling this policy. A label or USB transport hint is not proof of hardware.

The present enrollment route is explicitly **independent console enrollment/recovery**: an ordinary web session cannot issue its own enrollment code or activate a new approver. Key revocation/policy changes use bound WebAuthn approval; whenever any hardware action is enabled, identity/policy changes also require an eligible hardware key. There is no normal web bypass through a weaker action-class setting. Two eligible hardware credentials must exist before enforcement; the operator must separately establish that these are two physical keys and test both.

## Portal, Dokumentation and configuration backup

Portal registration uses an existing configuration extension. It does not edit Portal source, enable the Portal or grant authorization through it. `IncludeAdministration` must be enabled in Portal for that category to appear.

The complete guide is bundled here and the HTML interface has a Guide section. [Integration files](integrations/README.md) contain the proposed central Dokumentation catalog entry and configuration-backup registration package. The existing central modules use fixed catalogs/registries. **No files in those modules are modified in this development change**, honoring the instruction not to change other modules. Therefore their central registration is pending an explicit exception for those registration changes; they are not reported as already activated.

Each new module can already export/import its own configuration. The central backup module can discover newly installed exporting instance modules as review candidates, but a candidate is not backup coverage. Its new adapters must be registered and parity-tested before the UI claims native restore support. Do not masquerade as another module ID or use an unchecked property-only restore to bypass disabled-on-import behavior.

Vault backup is a separate requirement. Configuration exports do not back up the encrypted database or external keys. Production vault backup/restore, migration, automatic synchronization and provider/OAuth refresh are not released by this development implementation; see the explicit release gates.

## Trust boundary

The original form.json editor belongs to the untouched old SecretsManager and still controls that old vault. It is not a route into the new vault. New backend changes use only its dedicated API, local commissioning/recovery methods and protected storage. Arbitrary privileged same-process PHP or host administrators can still bypass application rules; the design never claimed process isolation from them. A hardware touch does not verify what a compromised browser displayed.
