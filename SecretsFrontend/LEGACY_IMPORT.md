# Legacy PasswordSafe import

Development feature, available on the primary HTML page under **Import old vault**.
The old module remains installed and unchanged during migration.

1. Select an active old PasswordSafe. Multiple instances are never selected silently.
   For **Vault folder** and **Key folder**, choose **Keep current location**
   (default) or **Use imported location** independently. Confirm persistence and
   private folder permissions when selecting imported locations.
2. Review global/local entries, exact conflict paths, excluded internal areas,
   old storage locations, current folders, exact selected folders and inactive connection proposals.
3. Approve the immutable import with an existing administrator passkey. Current
   hardware policy applies. Save the pre-import encrypted backup and its separate
   recovery key when offered.
4. Check **Import verified**, inspect Secrets, then pair new vault connections
   explicitly. Migrate consumers separately; unmodified consumers still use old data.

## Data and configuration

The source adapter reads the old encrypted `Vault` variable and the existing
hexadecimal `master.key` using the supported AES-128-GCM format. It never invokes
old APIs that might generate a key or normalize JSON types. Objects, lists,
strings, numbers, booleans and null values retain their types. `__LOCAL__` becomes
the new local scope. `__AUTH__` and other reserved top-level areas are listed as
excluded; old passkeys and system.vault credentials never become authority.
The Explorer's `__folder: true` marker is removed. Unsupported native names,
limits or structures reject the complete import rather than partially copying.

Folders merge recursively. Identical leaves are unchanged. Conflicting leaves
and changed lists follow the explicitly reviewed **keep** or **replace** policy;
keep is the default. Preview shows names/types/counts and conflict paths, never
values or raw source JSON. Native limits and a maximum 512 KiB source plaintext
budget apply; capacity failure must leave both vaults unchanged.

Source role and key/storage locations are retained as migration metadata. Known
replication hook addresses are copied into inactive proposals, stripping URL
credentials, query strings and fragments. Public TLS mode/fingerprint and old
key-transport choices are annotations only. No remote connection, key transfer,
legacy password, passkey or session is activated.

## Storage choices

**Keep current location** retains that component's active folder. **Use imported
location** selects `secrets-native-data-ID` for the vault or
`secrets-native-keys-ID` for keys beneath the selected old key folder. The old
ciphertext lives in a Symcon variable, so it has no directly reusable file path;
`system.vault` is a separate legacy system-credential file. Neither it nor the
old `master.key` is adopted or overwritten. Paths are server-derived and bound
to the exact preview, source fingerprint and administrator approval.

The approved native commit records the selected paths and updates the pinned
management profile. An authenticated redirect freezes the previous native copy
under its existing lock. A bounded, verified copy retains the journal, all data
keys, signing/wrapping keys, hardware-root folders and captured completions.
Copying uses private files, chunked I/O, file synchronization and the platform's
existing directory-sync profile. A signed completion receipt precedes switching
workers to the destination. Interrupted publication/copy resumes the same move;
existing matching copied files are verified, and conflicts fail closed. There is
no fallback to an earlier writable copy. Original native folders are retained;
this wizard does not delete them.

The backend's durable binding and console paths are reconciled from the approved
handoff. Only that exact path change can preserve the current runtime; unrelated
configuration changes keep the usual invalidation behavior. Both components can
move together or independently. Active backup uploads and unresolved OAuth effects
must finish before moving. New destinations must be empty, private, local,
nonoverlapping ordinary folders; symbolic links and existing unrelated files are
rejected. Imported subfolders under the Symcon installation are accepted only
beneath the verified legacy folder, outside public/code directories. Windows
private ACLs and container persistence need explicit confirmation. Actual backup
coverage of the chosen paths must still be verified on the deployment.

## Authorization, consistency and recovery

Discovery/preview require the primary administrator session and CSRF. Snapshot
candidates are bound to that session, current native head, source ciphertext/key/
configuration fingerprint, conflict policy, keyed expected result and expiry.
Values stay in encrypted native ephemeral state. Final approval uses the existing
fresh exact passkey challenge, with hardware approval whenever current policy
requires it. The source fingerprint is checked again and the old vault semaphore
is held until the native commit completes. This assumes supported legacy writers
honor their vault semaphore; do not edit/reconfigure the source during migration.

Import keeps existing administrators, grants, identities and peer trust. Global
changes follow existing approved new-vault sharing; local data does not synchronize.
The result is checked against the reviewed expected tree digest. An uncertain
reply is resolved through the original operation identity, not a blind retry.
Restart clears unfinished candidates; completed imported data and source settings
remain in the native journal. Reopen review after changes, expiry or restart.

## Validation

Synthetic PHP tests use actual encrypted legacy-format fixtures and native storage.
They cover preserved types/scopes, masked output, source/destination changes,
conflict choices, excluded credentials, inactive/missing-key sources, hardware
policy, pre-import backup, unchanged legacy files, independent location choices,
occupied-destination rejection, interrupted publication/copy/receipt recovery,
retained keys/completions, stale-worker redirects and restart handoff. Browser tests cover
the four steps, safe source labels, exact approval and backup-key cleanup. These
checks do not establish real deployment or independent security acceptance.
