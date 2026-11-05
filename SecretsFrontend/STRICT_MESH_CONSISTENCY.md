# Strict emergency freshness: verification and implementation contract

Date: 2026-11-05 UTC. Examined baseline: `2734ee25ffce855833724045dd4dd829760926b8`, `migration/legacy-sec-replacement`.

## Verdict

The current native mesh does **not** guarantee that a remote read includes every previously acknowledged Global write. It provides asynchronous causal replication with preserved concurrent versions, authenticated messages and local durable storage. Eventual convergence is valuable, but is not a quorum commit/read protocol. A complete four-vault mesh does not remove this distinction.

The approved emergency policy is **confirmed current secret or unavailable**. Automatic remote secret fallback remains disabled. This change documents the actual guarantee and adds an executable four-vault counterexample; it does not implement quorum commits, strict reads or emergency credentials. Existing local API behavior is unchanged. No production vault, peer membership, permissions, or runtime was modified by this review.

## What the existing code does

| Path | Observed behavior | Consequence |
|---|---|---|
| `NativeRuntime.php::WriteNativeSecret` | Changes local durable state and returns `committed: true`; no peer round trip precedes that acknowledgement. | A successful API result is a local commit, not a replicated quorum commit. |
| `NativeStore.php::change` | Persists the mutation, outcome and queued publication in one local encrypted snapshot. | Crash safety of the local record does not imply another vault has received it. |
| `NativePeer.php::queueGlobal` / `dispatch` | Queues snapshots; background delivery records exact authenticated receipts afterward. | A writer can acknowledge a change before delivery, then become unreachable. |
| `SharedGlobal.php` | Merges causal histories and retains conflicting concurrent versions. | Later convergence does not prove currentness during an outage. |
| `NativeHealth.php` | Signed nonce-bound comparison of Global history; normally one comparison per peer per minute for four installations. Cached observations expire. | A match establishes equality at comparison, not a read barrier against a later write. |
| `NativeRuntime.php::ReadNativeSecret` | Checks the local capability and local active snapshot. | Existing machine reads do not contact a quorum. |
| `LegacyAPI.php::read` / `GetSecret` | Checks current local authorization and reads the local snapshot. | Compatibility APIs share the same freshness limit. |
| `NativeOperations.php::commit` | Ordinary operations delegate to the local commit; the special path coordinates legacy import locally. | Browser approval does not add remote durable confirmation. |
| `NativeBackend.php::nativeStore` / `nativeApplication` | Creates the native filesystem-backed store and validates the native profile. | Historical Go/anchor components in the repository are not the active native mesh authority. |

Transport sequence numbers, local storage indexes and local vault revisions are not a common mesh commit index. Comparing them across installations or choosing the largest wall-clock timestamp is unsafe. A pairing graph is not an agreed voting membership. Multiple instances restored from one identity must never count as separate voters.

## Executed counterexamples

`SecretsBackend/tests/mesh-consistency.php` creates four real encrypted native stores, six approved pairings (three direct neighbors per vault), supplied-crypto signed/sealed in-memory peer transport, and scoped machine grants. It does not access production or real secret values.

1. Converge all four replicas on an initial password and obtain a matching HEALTH observation.
2. Isolate the writer in the test transport. Call the actual `WriteNativeSecret` implementation. It returns `committed: true` without any remote exchange; three publications remain queued.
3. The other three replicas retain the old password. Fresh signed HEALTH exchanges among that majority agree on the old model. That agreement does not include the isolated writer's acknowledged change.
4. The existing machine API and compatibility API on a reachable replica both return the old password. A previous comparison with the isolated writer can still show verified during its configured observation window.
5. Reconnect and deliver the outbox: all replicas converge on the new value, demonstrating the current asynchronous contract works as designed.
6. Form a matching signed HEALTH response, then commit another writer change before delivering that response to the caller. The response is authentic and correctly bound, but is not proof that the writer has not changed afterward.
7. Confirm Local values were not replicated and diagnostic metadata contains no canary values.

The test passes when it reproduces these documented boundaries and the module explicitly reports `strictEmergencyReadSupported: false`. Its 35 checks are a characterization of the present protocol, **not acceptance evidence for strict fallback**. A future quorum implementation must replace the stale-read expectations with the strict acceptance tests below; it must not merely flip a metadata Boolean.

## Meaning of confirmed current

The target is linearizable reads of committed Global data: a successful read must include writes acknowledged before that read began, and concurrent reads/writes must have a coherent order. It cannot promise that no new write happens after its chosen read point or just after its response reaches the caller. That is a concurrency limit, not permission to use an older acknowledged value.

For reference, etcd's primary API specification distinguishes quorum-backed linearizable reads from potentially stale local/serializable reads: https://etcd.io/docs/v3.5/learning/api_guarantees/ . This reference explains the semantic target; it is not a proposal to add etcd or any external runtime dependency.

## Required native protocol upgrade

1. **Agreed membership and baseline.** Provision an explicit mesh identity, versioned member/key roster and initial shared-state checkpoint approved across all participating writers. Reconcile the existing CRDT history and unresolved conflicts first. Pairing alone is not authority to change quorum membership. Old asynchronous writers must be fenced at activation; mixed-version nodes cannot continue acknowledging Global changes under the strict epoch.
2. **Durable quorum commit.** Use a reviewed consensus/atomic-register protocol with persisted promises/terms, proposals and commit evidence, or an equivalently justified construction. State, authorization, operation identity and outcome must be bound to the exact mesh epoch and mutation. Merely sending the existing snapshot to three peers or counting receipt rows is insufficient. A lost reply is an uncertain outcome resolved by the same operation ID, not a reason to repeat the mutation under a new ID.
3. **Read barrier and conflict handling.** Establish current committed state on every strict read through the active quorum protocol; validate the selected data and current authorization against it. Do not substitute cached health, local revision, majority equality or timestamp freshness. Concurrent updates need explicit conditional revisions/conflict resolution, not silent timestamp-based overwrite. Catch-up is authenticated before reads become eligible.
4. **Every mutation route.** Cover browser save/delete/rename and conflict resolution, machine writes and duplicate-outcome paths, compatibility writes and bulk replacement, imports/restores, OAuth result application, peer receipt, key/configuration/authorization changes that affect access, and membership transitions. No legacy path may publish or acknowledge an unfenced Global mutation outside the protocol.
5. **Independent emergency identity.** Provision an explicit scoped read-only fallback credential while healthy, protected outside the unavailable vault. Bind it to mesh, source installation, approved application scope and recipient keys. Each response must prove current authorization/revocation, not just current data. Global data only; remote Local data is never a replacement for this installation's Local records. Pairing does not grant emergency application reads.
6. **Bounded, observable operation.** Use bounded native HTTPS calls without holding the local vault file lock over network I/O; enforce total request budgets, retry/idempotence, circuit breakers, active-source telemetry and stable return-to-local rules. Distinguish failure to contact a peer from denied access, missing records, corrupt storage and invalid signatures. Do not mask those security/data errors by trying a different authority.
7. **Restart, standby and restore fencing.** Persist protocol state with the native journal durability profile. Count stable independent member identities once. Production and a cloned Proxmox standby must not concurrently act as the same voter/writer; promotion/rejoin must fence stale protocol epochs. A coordinated rollback of all quorum state cannot be detected without an independent current reference; do not claim that guarantee for the current standalone/native persistence model.

For a fixed four-member majority design, three distinct members are needed. It can tolerate one unavailable member; a 2–2 partition must refuse strict operations on both sides. Never shrink membership because a timer reports a member unreachable. A three-member group needs two, but changing which installations vote requires explicit, safely committed membership changes. No such membership was selected or activated by this review.

Local private records can retain their standalone behavior, but the approved strict Global policy changes offline availability: an isolated installation must stop acknowledging strict Global writes, and strict reads may be unavailable until a quorum can be reached. Silent local reads during that condition would violate the requested guarantee. This behavior needs to be made explicit in configuration and application error reporting before activation.

The native-only runtime constraint remains: supplied Symcon PHP, crypto, filesystem and HTTPS functions; no new Go/Python process, database, daemon or package installation. Existing historical quorum tests cannot qualify a different native implementation.

## Strict acceptance tests before enabling fallback

| Scenario | Required result |
|---|---|
| Acknowledged write, then writer crash | Every successful subsequent strict read includes that write; otherwise unavailable. |
| 3–1 partition | Only the approved quorum side may complete strict operations; the isolated member cannot acknowledge a Global write. |
| 2–2 partition | Neither side serves unproven strict reads or acknowledges writes. |
| Concurrent writers with the same predecessor | One coherent committed order or explicit conflict; no lost update. |
| Crash before/after each durable protocol boundary | No double vote, split history, rollback, or invented successful outcome on restart. |
| Lost commit reply and repeated operation ID | Resolve the original outcome; never double-apply or change the request bytes. |
| Fresh signed old response / replay / clock jump | No bypass of the current read barrier. |
| Member revocation or roster change during read/write | Old-epoch evidence cannot authorize the operation. |
| Fallback grant revoked / unknown caller / wrong path | Refuse without switching to a less restrictive peer. |
| Remote missing/conflicting secret | Explicit error; never select an arbitrary candidate or remote Local record. |
| Frozen or restored Proxmox clone | Rejoin against the approved current epoch; never count duplicate identity as another voter. |
| Local vault locked/corrupt/missing | Emergency access uses independently provisioned authority and a valid read proof, or refuses. |
| All mesh nodes rolled back | Report the explicit independent-reference limitation; do not invent rollback detection. |
| Deadlock/slow filesystem/network / total timeout | Bound or report blocked work; watchdogs expose loss of service. |
| Recovered local backend still behind | Do not return to local until it can satisfy the same strict-read policy. |

## Change delivered by this verification

- Executable full-mesh counterexamples in the native CI runner.
- Explicit protocol guarantees in native-info, authenticated session and pairing-progress metadata.
- Overview explanation that synchronization happens after the local save and emergency remote reads are unavailable.
- Corrected health documentation and this implementation/acceptance contract.

No runtime strict read/write protocol or emergency fallback was enabled. This verification is complete; the quorum protocol and independently approved fallback-access implementation remain outstanding.
