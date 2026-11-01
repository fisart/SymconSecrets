# Legacy PasswordSafe import

Development feature, available on the primary HTML page under **Import old vault**.
The old module remains installed and unchanged during migration.

1. Select an active old PasswordSafe. Multiple instances are never selected silently.
2. Review global/local entries, exact conflict paths, excluded internal areas,
   old storage locations, current folders and inactive connection proposals.
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

## Storage limitation

This importer keeps the current initialized native vault and key directories.
Suggested `secrets-native-data-ID` and `secrets-native-keys-ID` subfolders beneath
the old key location are displayed and retained for a separately reviewed move.
**It does not relocate initialized storage or change its pinned foundation.**
The old ciphertext lives in a Symcon variable; system.vault is a separate legacy
system-credential file, not the user's secret-tree ciphertext.

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
policy, pre-import backup, unchanged legacy files and restart. Browser tests cover
the four steps, safe source labels, exact approval and backup-key cleanup. These
checks do not establish real deployment or independent security acceptance.
