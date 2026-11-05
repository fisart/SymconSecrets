# Local-only import when joining an existing Secrets network

Available on `feature/secrets-frontend` and `migration/legacy-sec-replacement`. On the migration branch the old manager remains disabled: import reads its retained encrypted Vault variable and existing master.key directly, only for this explicit administrator operation. Application reads, writes, login and synchronization continue using only the native vault. Retained data is a pre-switch snapshot and can be stale; keep current native values unless intentionally replacing them. If the old instance, Vault variable or key has been deleted, it is no longer an available source. In **Import old vault → Secrets to import**, the browser now defaults to **Local secrets only**. **Global and Local secrets** remains available for a full import. The old manager and its storage remain unchanged.

Local-only copies the source's `__LOCAL__` application data. It does not import ordinary Global records, `__AUTH__`, old passkeys, sessions or administrator authority. Ordinary top-level records in a Standalone vault are still Global; selecting Local-only will not copy them. An empty/missing `__LOCAL__` area does not delete destination Local values and does not fall back to importing Global.

The keep/replace policy applies only to the selected scope. Local-only leaves the exact destination Global tree, shared versions, Global revision and existing peer trust/queue unchanged; it does not enqueue an imported Global update. Background peer synchronization can still run independently. Local-only works even when the destination Global tree is not writable. Source settings and sanitized connection proposals are recorded without activating old connections. Storage location choices remain separate and explicit, with current locations selected by default.

The server stores the scope inside the authenticated import candidate, includes it in the passkey approval review and records it in the result/history. Changing the selection requires a fresh preview. Source fingerprint and destination-head checks remain in force through commit, as do existing authorization/hardware policies. The encrypted pre-import backup and separate recovery key still cover the complete destination vault. Existing API callers omitting `scope` retain the previous full-import behavior; new clients should send `scope: "local"` or `scope: "all"` to `legacyPreview`. Scope cannot be overridden on the approval operation.

For Production:

1. Keep verified old/native backups and set up the native backend/frontend on the coexistence branch.
2. Open Import old vault; select the old instance (automatic when only one is ready), Local secrets only, and normally Keep the current value/current storage locations.
3. Review and approve. Check Local secrets in the new vault and retain the backup/recovery key separately.
4. Pair with the existing Test and Heartbeat native vaults, receive their Global state, and resolve any relevant conflicts. Local values remain private to Production.
5. Compare every Production old instance's Global and Local application data before switching. Production-only Global records are intentionally absent from a Local-only import and must be reconciled separately. Pause secret writers for the final comparison.
6. Only after verification switch to `migration/legacy-sec-replacement`, preserving instance IDs and application calls. Confirm native binding and required read/write access. Native compatibility writes remain frozen until approved. The replacement branch also supports explicit import of retained old snapshots, without restoring the old manager.

The coexistence branch's migration helper directory is now `.migration`, avoiding Symcon's attempt to load it as a module without `module.json`. The original SecretsManager implementation is unchanged.

Validation covers Local-only keep/replace, an empty Local area, unchanged Global data/versions/revisions/sharing, non-writable Global, invalid scopes, scope/digest tampering, source changes during approval, pre-import backups, authentication exclusion, retained full-import behavior, storage relocation/recovery, and browser scope selection/approval/result text.
