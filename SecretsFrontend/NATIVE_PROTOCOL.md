> Shared Global update (2026-11-02): new wizard pairings use `shared-global-v1`
> and the multi-writer merge/authorization contract in [SHARED_GLOBAL.md](SHARED_GLOBAL.md).
> The single-owner sections below describe legacy `global` pairings and their
> compatibility/transfer implementation; they do not govern the new shared Global
> namespace. Existing pairings require fresh bilateral approval to upgrade.

# Symcon-native vault protocol — native implementation profile

Date: 1 November 2026 (Europe/Rome).

**Status: implemented development profile; independent audit and real deployment qualification pending.** See RELEASE_STATUS.md for executed native checks and explicit limits. This revises the earlier proposal; historical component audits do not independently close B-01/B-02/B-03 for the replacement.

## 1. Scope and changed guarantees

The replacement supports one fully standalone logical vault and optional sets of two, three, five or more explicitly paired vaults. Multiple vaults may share a Symcon process/origin or use different hosts. Each has its own identity, encrypted state, keys and administrators. The default is standalone. No other vault, three-node membership, external authority or synchronization connection is required for its own local operation.

Runtime dependencies are Symcon APIs and functions available in its supplied PHP: JSON, cryptographic randomness, hashing/OpenSSL, supplied sodium for authenticated peer key operations, filesystem operations, semaphores, timers and supplied HTTPS client functionality. No PDO/SQLite, Python/Go process, etcd, shell command, installed PHP extension, OS package or external database is a runtime prerequisite. Development test tools are not runtime dependencies. Exact available functions, algorithms and platform permission behavior must be checked inside the actual Symcon process, without installing a replacement runtime.

The external Go/Python/SQLite authority architecture is retired as the replacement's architecture. Its retained components and correction tests are historical/reference work, not an allowed native-mode fallback. Guided native mode refuses V1 fallback and initializes the native store explicitly. Earlier prototype code remains accessible only to separately provisioned historical instances; no native route selects it. Native imports/activation must refuse external-runtime configurations rather than silently choosing them.

The existing SecretsManager, its SEC APIs, vault variables, key files, portal settings and integrations remain unchanged. A new vault never automatically adopts its data or authority. Migration is separately reviewed and explicitly authorized.

| Property | Replacement contract |
| --- | --- |
| Passkey presence/UV, exact-operation approval, hardware anti-downgrade, CSRF and scoped machine permissions | Retained and checked again at the native commit boundary |
| Global consensus history and quorum-backed freshness | Replaced by one owner-authoritative history per shared tree |
| Standalone detection of a consistent restoration of all trusted state | **Unavailable without an independent current reference** |
| Immediate revocation at a disconnected recipient | Unavailable; local authorization and last-known remote membership are distinct |
| Split-brain-safe automatic promotion after timeout | Not provided; timeouts do not transfer ownership |
| Power-loss durability | Only the qualified native filesystem profile may claim it; Symcon variable/attribute updates alone do not establish it |

## 2. Logical identity, state and keys

Generate a random stable vault UUID at explicit initialization, independent of host-local Symcon IDs, URLs and paths. Generate separate encryption, signing and peer wrapping keys. A locally pinned binding maps the UUID to the intended backend/frontend instance IDs and canonical storage locations. Every encrypted record authenticates format, vault UUID, storage generation, key ID, commit counter and predecessor digest as associated data. Never derive a vault key from a passkey signature.

One complete authenticated snapshot contains values and typed hierarchies, administrator credentials/counters, local rights and revocation generations, shared-tree ownership/membership, received-tree cursors, key references, audit entries, mutation outcomes, outbox jobs and OAuth intent/result references. Values and permissions never publish as separate variable writes. Secret values, credentials and private keys never enter unencrypted properties, logs or configuration exports.

The encryption key remains in a separate private key location. Symcon's encrypted Vault-style variable may mirror the committed snapshot for existing native persistence/export conventions, but the mirror is not a second authority. Sessions, challenges and browser setup rights remain transient and bound to a new random runtime nonce on every reload/restart. Reboot invalidation does not establish independent rollback detection.

Keys are immutable files named by vault UUID and key ID. Initialization uses exclusive creation, validates the result and refuses an existing identity/state. A missing/mismatched key locks the affected state; recovery never invents a replacement key for existing ciphertext. Reviewed creation revalidates canonical path separation, ancestors, permissions and symlinks immediately before writes. Platform-specific ACL/path handling needs qualification; the present POSIX path correction is not evidence of Windows qualification.

## 3. Native publication, commit point and recovery — B-01

Use a bounded private encrypted snapshot journal, not independent updates to several Symcon variables. The implementation must provide a supplied-PHP filesystem adapter with injected-failure tests and real platform qualification. No shell fsync helper is permitted.

Publication sequence, under the native exclusive file lock, with Symcon semaphores additionally serializing initialization/lifecycle/job entry points:

1. Read the complete current committed snapshot. Revalidate the actual runtime, expected commit digest, current actor/rights, exact reviewed change, key generation and operation UUID/digest. A UUID with a different digest is rejected. An already committed exact operation returns its stored metadata outcome after current disclosure authorization; it does not execute again.
2. Construct the successor snapshot in memory. Include values, permission changes, audit, original operation outcome and immutable outbox entries in that same snapshot. Increment the local commit counter once. A metadata-only update need not increment a shared-tree revision.
3. Ensure all newly referenced keys/envelopes exist, are verified and are synchronized before publishing any state that requires them. Keep old keys needed by current/retained snapshots, pending effects or approved recovery copies.
4. Write the successor ciphertext to an exclusively created temporary file, fully check writes/flushes and synchronize it. Publish it under a new immutable counter/digest filename; synchronize its directory. Never overwrite the current snapshot in place.
5. Write an authenticated commit record under a new immutable name. It binds the complete successor digest, exact predecessor, operation UUID/digest and required key IDs. Synchronize the record and directory. **The completed publication of this commit record is the logical commit point.** Update encrypted Symcon mirrors afterward; they do not select a different state.
6. Return success only after the selected storage adapter's required checks succeed. If any required write/synchronization fails, return failure or UNKNOWN where publication may already have happened. Do not report success from an in-memory SetValue/attribute call. Resolve UNKNOWN using the same operation ID; do not automatically rerun its mutation with a new ID.

Recovery selection is deterministic:

| Observed state after restart | Required result |
| --- | --- |
| Valid old committed snapshot plus uncommitted successor bytes | Keep old state; quarantine uncommitted bytes |
| Valid successor commit record and matching complete snapshot/key set | Select successor, even if its reply or mirror update was lost |
| Highest observed commit record is incomplete, corrupt, key-mismatched or has a broken retained predecessor relationship | Lock for explicit recovery; do not silently select older permissions/data |
| Mirror points to a newer committed state absent from the journal | Lock and investigate the inconsistency; mirror contents cannot manufacture a commit |
| Mirror is older than a valid committed journal successor | Rebuild the mirror from the journal |
| Two authenticated successors claim the same predecessor/counter | Quarantine and require reconciliation; do not choose by timestamp |
| Entire consistent older state/key/binding set restored | May be undetectable standalone; B-03 applies |

Retain the current and immediately preceding complete generations plus all live pending references. Cleanup must never remove a file/key needed by either selected generation or a pending effect/backup. The implementation caps a complete plaintext snapshot at 4 MiB or a lower automatically derived memory budget. Ordinary writes reserve 25% capacity for maintenance. There are 3500 ordinary retained mutation outcomes, 4112 including reserved maintenance outcomes, 128 undelivered jobs and 32 peers. Explicit verified-backup compaction retains the latest 512 outcomes/audit entries. At capacity, refuse the affected new operation before side effects; an explicitly approved authenticated compaction/checkpoint may retire history. Never evict retry state and then accept an old sequence as a new mutation.

**Durability boundary:** file/rename/readback success alone is not proof of power-loss durability. A qualified adapter must support the necessary supplied-PHP file and directory synchronization, filesystem/permission assumptions and actual interruption tests. Unsupported/unqualified adapters cannot advertise strict durable success or production readiness. Any weaker development acknowledgement must be explicitly labelled unqualified. Native mode does not add a database to conceal this gap.

Ordinary restart automatically validates integrity and establishes a fresh runtime/session boundary. It does not require console approval merely to pretend a local boot marker defeats full-state restoration.

## 4. Pairing, roles and authenticated messages — B-02

Each shared tree has a stable tree UUID, one writer vault UUID, ownership epoch, per-tree revision and predecessor/payload digests. Revisions are monotonic decimal strings within an epoch, independent of wall clocks and the vault's local metadata commit counter. Subscribers keep independent local-only trees. The default subscriber is read-only for that shared tree. A subscriber user changes it through fresh authorization on the owner's frontend; a peer signature is not a substitute for that administrator's passkey approval. Delegated machine mutation requires a separately approved, owner-enforced path/action capability.

Pairing is bilateral: PROPOSED → APPROVED_BOTH → ACTIVE → REVOKED. Record a random pair UUID, both stable vault UUIDs, signing/wrapping key IDs and fingerprints, endpoint/hook routing bindings, pairing epoch, tree IDs, exact permitted selectors/actions and whether later authenticated cached reads are allowed. Both administrators approve the same descriptor digest. Pairing grants no administrator enrollment, blanket secret access or local-only key access. Endpoint/origin alone is never an instance identity.

Peer messages use a separate native protocol/domain, never the old quorum wire format. A closed versioned signed envelope binds: message purpose, pair UUID/epoch, sender/recipient vault UUIDs and key IDs, intended destination backend/hook, tree UUID/ownership epoch, immutable operation UUID, delivery sequence, owner revision, predecessor and content digests, payload length/digest, and a receiver challenge for sensitive delivery. IDs/counters/digests have strict formats; Browser management JSON requests remain bounded at 64 KiB; backup uploads use session-bound staged chunks and a final whole-payload digest. Native peer envelopes carry a complete sealed typed tree and are bounded at twice the receiver’s native capacity plus 64 KiB. Combined shared trees may exceed one browser-edit request, within the complete-state budget. Peer responses remain bounded at 64 KiB.

Encrypt selected data to the explicitly approved recipient with the supplied reviewed primitive and authenticate the exact envelope with the sender's pinned key. Verify all bindings, sizes and current permissions before decrypting or dispatching. Unknown fields, algorithms, identities, hooks or epochs are rejected. No generic PHP function, file path or URL dispatch is accepted. Multiple vaults sharing an HTTPS origin must still fail sender/recipient swaps and wrong-backend delivery.

## 5. Ordering, retry and rejoin

The owner commits a shared-tree successor together with its immutable operation outcome and one recipient-specific outbox entry per active approved subscriber. Jobs keep the same sequence, payload digest, owner revision and target across retry; no later job renumbers an earlier one. Timers perform bounded retries with backoff; they do not block ordinary Symcon script workers indefinitely.

Receiver processing verifies the active pairing/ownership epoch, sender, recipient, challenge and exact predecessor/cursor. It commits the received values, cursor, operation/digest receipt and audit in one local snapshot before acknowledging. An exact duplicate returns the stored receipt without reapplying; reused IDs/sequences with different bytes are rejected. The owner records an authenticated exact receipt in a later metadata commit; a lost receipt causes retransmission of the same job, not another tree mutation.

A gap returns RESYNC_REQUIRED and quarantines the update. Catch-up uses an owner-authenticated full snapshot for the current epoch/revision and a challenge bound to the receiver's known cursor. A snapshot can advance a cursor after explicit scope/membership checks; it cannot lower a revision, change writer/epoch or overwrite local-only data. Delayed deltas at or below the accepted cursor are historical/rejected, including after deduplication compaction.

A returning restored owner below a subscriber's known revision/epoch must reconcile; the subscriber never overwrites its newer history by timestamp. Divergent digests at the same revision are a conflict, not last-write-wins. Preserve both ciphertext histories for explicit administrator resolution.

## 6. Ownership changes, revocation and disconnected operation

In a two-vault partition, owner A may continue its own authorized writes; subscriber B cannot promote itself for A's tree. Both retain independent operation of their own local trees. Cached reads on B follow its explicit local permissions and pairing policy and expose last synchronization/freshness. They do not claim instantaneous knowledge of A's revocations. Removing B stops new sharing and rejects future messages but cannot erase data B already received.

An ordinary ownership transfer requires reachable old and new owners. The old owner first commits an irreversible-within-current-history FREEZING record stopping new writes, naming the new owner/key, successor epoch and exact transfer snapshot. It signs that frozen state. The new owner verifies the encrypted state/key envelope and commits acceptance of the exact certificate before issuing new-epoch writes. Subscribers accept only the authenticated old-to-new transfer chain. A lost acknowledgement is resolved by the same transfer ID; the old owner does not resume writing because a timer expires.

If the old owner is lost and its shutdown cannot be positively established, recovery cannot silently create a second writer under the old tree identity. Recovery may create a new explicitly approved tree identity and re-pair selected recipients, preserving and reporting the old lineage. This is an administrator-visible fork/reconciliation, not proof that the old writer is fenced. No automatic failover or third-node requirement is disguised in this rule.

## 7. Backup, key changes, OAuth and limits

Backups are authenticated encrypted snapshots with explicit key/recovery envelopes; ordinary settings exports omit keys, vault values, sessions, setup codes and approvals. Verify backup digest, identity, key coverage and generation before an explicitly approved restore. Standalone restore resumes native integrity validation and fresh login; shared-tree restore additionally follows epoch/cursor reconciliation. Existing SecretsManager data is imported only through a separate reviewed migration operation.

Key rotation prepares/verifies new key material before the successor commit references it. Retained snapshots, approved recovery envelopes and uncertain effects keep their required key generations pinned. Interrupted rotation never replaces a missing old key with random bytes. Key removal is a separate approved cleanup after reference checks.

OAuth/external effects retain uncertainty handling: commit an exact PREPARED intent and then SENT_UNKNOWN before dispatch, serialize that slot, and never automatically repeat an uncertain non-idempotent request. Capture a provider response into an authenticated encrypted local completion record before acknowledging it. A completion applies only against the same current provider policy, token predecessor and effect ID; otherwise quarantine it. A new runtime may recover a captured completion but cannot turn UNKNOWN into permission to resend. These native paths are implemented and exercised with injected provider transport; actual provider idempotency and HTTPS behavior remain deployment tests.

## 8. Route/dependency and deployment inventory

| Surface | Native replacement contract |
| --- | --- |
| Configuration form | Display/configuration; exact console-approved passkey candidate and durable initial decision; no ordinary permission, key or secret mutation bypass |
| Frontend management hook | Fixed same-origin schema; passkey/session/CSRF; exact expected state and action approval; bounded JSON |
| Native peer hook | Only closed signed/encrypted native messages addressed to this vault/backend; no browser session as peer authority |
| Local machine APIs | Explicit per-instance/tree/path/action capability; rights and runtime checked at commit/read boundary |
| Symcon timers | Bounded recovery/outbox/effect scheduling using the same checked state APIs |
| Old prototype setup/anchor/quorum routes | Never loaded or used as a fallback for native mode; reject incompatible imports/dispatch |
| Existing SEC APIs and old vault | Unchanged; neither paired nor migrated implicitly |

The public HTTPS listener and protected relay hop remain deployment requirements. Host/Origin checks and a secure browser context do not prove receiving-API transport encryption. Native Symcon metadata can be absent, so the old false-rejection check must not be restored as proof. Probe all direct HTTP, alternate ports, HTTPS, NAT and relay routes from permitted and untrusted network positions. A public plaintext path capable of sensitive operations is unacceptable. An unprotected remote relay hop must be replaced by a protected/encrypted hop. Current live-site qualification is NOT_RUN.

## 9. Required independent acceptance

Test 1, 2, 3 and at least 5 logical vaults, both in one Symcon process and across hosts. Include injected interruption before/after every key/snapshot/commit/mirror boundary; real restart/storage interruption; lost acknowledgement; duplicate and conflicting IDs; forged/recipient-swapped messages; reordered/gapped/replayed deliveries; revoked/offline subscribers; same-host instance confusion; owner transfer and divergent backup restore; missing/old/new keys; authorization revocation during a paused commit; hardware policy and every privileged route; bounded cleanup and uncertain OAuth completion.

Record PASS/FAIL/NOT_RUN/N/A against the exact native implementation and runtime. Prior Go/SQLite test results do not qualify the replacement. The native tests now provide implementation evidence listed in RELEASE_STATUS.md. They do not establish real deployment acceptance or production/migration approval.

Native persistence references: [Symcon backup/write frequency](https://www.symcon.de/en/service/documentation/backup-and-restore/), [service/configuration recovery](https://www.symcon.de/en/service/documentation/components/service/), [semaphores](https://www.symcon.de/en/service/documentation/command-reference/process-control/ips-semaphoreenter/). These document API behavior; they are not executed power-loss evidence.

The code-free setup, mandatory first-administrator genesis, restart decision journal,
additional-key candidates and independent recovery use BOOTSTRAP_IMPLEMENTATION.md.
Manual native setup/enrollment code methods are closed, including cached callers.
