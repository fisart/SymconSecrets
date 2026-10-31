# Internal core-change checkpoint

This package adds the human GLOBAL_EDIT / LOCAL_EDIT reservation, READY,
commit/abort lifecycle to the existing quorum and archive components. It has no
network listener or Symcon route. The existing password module and development
V1 backend remain unchanged. Request a security implementation review of this
checkpoint before connecting it to management routes.

## Original operation contract

`contract.go` defines the closed `Intent`, `ApprovedIntent` and `UserOutcome`
records. The standalone deterministic `intent-vector.json` was signed with the
published test seed by an independent Python Ed25519 implementation. Go verifies
its digest/signature and reproduces exactly the same signature.

An Intent binds schema version `1`, original UUID, predecessor and candidate
heads, initiating owner boot/fence, exact policy/membership/permission/session/
credential references, old scope and new scope revision/object digest, change
class, reviewed diff digest, complete candidate bundle descriptor/index digest,
and zero to four recipient/pairing references. It contains no plaintext secret.
Its candidate bundle/commit UUID is also the reservation UUID in a separate
namespace; original user and coordinator command identities remain independent.

All metadata uses the frozen codec's bounded ASCII canonical JSON subset:
closed objects, no duplicate keys or JSON numbers, decimal string counters,
canonical base64url values, maximum 65,536 bytes and depth/array limits. The exact
intent digest is SHA-256 of UTF-8 `SymconSecrets/DC01/CoreUserIntent/v1` followed
by one NUL byte followed by canonical Intent. The owner's Ed25519 signature covers
UTF-8 `SymconSecrets/DC01/CoreUserSignature/v1`, one NUL byte, and canonical
ApprovedIntent **with its required signature field set to the empty string**.
The public key/key ID is resolved from the current enrolled owner record.

Authorization facts bind the Intent digest; the digest excludes ApprovalRef and
owner signature. A changed intent must not reuse its user UUID. The signed
wrapper binds the exact approval reference. Stored permission/session/credential/
approval references must all still match at final publication; authority leases
make expired sessions and approvals disappear from the final CAS read set.

This is a new **internal** contract, not an amendment to the frozen v1.2 wire
profile. `UserOutcome` has COMMITTED or ABORTED, its original digest, bound head
or null, and reason. It is never serialized as the frozen `Decision` for an
`authorize` or `reserveCandidate` action. Mapping this original-user record to
an explicit reviewed wire operation/result remains a connection gate. Existing
PHP/Go wire rejection semantics and all 71 signed vectors remain unchanged.

## Trusted authorization inputs

Core reads pre-existing authority records for policy, membership, enrolled owner
and coordinator keys/scopes, permission, leased session, credential and leased
approval. It cannot create or weaken those records. Approval must bind this
exact Intent, permission/session/credential references, verified UP/UV and a
verified permitted diff. Hardware-required classes also need the independently
verified credential hardware fact. Approval consumption is durable and one-use.

These are **not browser booleans or caller-supplied Guard/Snapshot values**.
The V2 WebAuthn/attestation and encrypted-diff verifier that produces those facts
is not connected yet. It must verify the real assertion, origin/frontend/session,
credential eligibility and complete manifest/object diff before issuing the
leased record. Fixture provisioning is synthetic and does not qualify hardware
or diff verification. SECURITY, enrollment, machine, counter and recovery changes
are deliberately unsupported here. A local-only edit must bind its owner and
scope; these tests do not prove that an unimplemented PHP packer preserves other
encrypted scope objects.

Internal method actor parameters represent already authenticated node identities.
The future dispatcher must derive them from current credentials and validate
scope/current admission on every route, including status/history. None of these
methods is a safe unauthenticated RPC surface. `AlreadyDecided` is historical
control evidence, not a fresh grant. `ResolveUser` returning null means UNKNOWN,
not failed/cancelled. Caller input is copied and validated before command hashing.

## State transitions and publication

- Reserve checks exact H/P/N/U/C, owner signature, scope, one-use approval,
  absence of another realm candidate and two current predecessor copies. An
  immutable `core/originals/<userOperationId>` index binds that ID to exactly one
  intent digest and reservation UUID. Reserve or CancelUnknown creates it in the
  same transaction, so cancellation of a differently signed intent cannot settle
  or block another intent with the same user UUID. It
  installs PREPARING, the original index, a pending pointer, approval consumption and review audit
  together. Stable command retry resolves the original reservation.
- Archives reread the live reservation, head/coordinator, membership/uploader
  and their admitted runtime. They verify every candidate byte/index/digest,
  durably store immutable bytes and pin, recheck state, then persist/sign the
  exact candidate receipt. Registration checks signature, descriptor, admission,
  current ACTIVE generation and reservation again.
- READY records the exact receipt references only with two independent current
  failure domains. It grants no publication. Final commit rechecks all receipts,
  admissions, deletion fences and predecessor-copy evidence, plus the original
  authorization and coordinator. A new coordinator cannot adopt the old approval.
- One etcd transaction writes head, scope revision/object digest, core revision,
  COMMITTED reservation, original COMMITTED outcome, head/reference and retained
  inventory pins, terminal audit, sequence cursors and immutable outgoing job
  batch, and removes pending. The coordinator command outcome is in that same
  transaction. No transmission or external provider action is performed.
- Candidate upload receipts count as committed-copy evidence only after that
  transaction has made their linked reservation COMMITTED. They must still match
  current ACTIVE admitted generations. READY alone never counts as a committed
  copy. Existing re-attestation/activation and generation invalidation remain.
- Abort by the current coordinator competes on the same reservation, original
  outcome, head and pending pointer. It may close an abandoned old-coordinator
  candidate, including after permission/owner revocation; it cannot commit it.
  A committed candidate cannot be aborted. CancelUnknown writes an original
  terminal tombstone only when its reservation is absent; a delayed Reserve then
  cannot execute, and another operation's pending pointer is not touched.

Candidate receipt references are internal to their reservation: archive UUID,
version `1`, and receipt digest. A wire adapter must preserve that lookup context
rather than treating an archive UUID as a globally unique receipt operation.

The immutable outgoing batch binds each recipient, pairing, source revision,
sequence and exact candidate ciphertext bundle reference/digest. A protected
cursor record holds per-recipient high-water values; retries cannot renumber old
jobs. This is durable queue metadata, **not** an implemented sender or a grant to
export all ciphertext to a cross-realm recipient. Recipient-specific sync payload
construction, key/scope filtering, machine grants, recipient nonces/receipts and
transport remain required before that queue may be sent.

## Evidence and limits

Tests exercise real three-process etcd and actual archive file writes/signatures:
atomic revision equality, lost reservation/commit replies, two successive writes
and immutable sequences, maximum four-recipient/three-copy batches, one-use facts,
UP/UV/hardware/diff refusal, LOCAL owner binding, corrupt bytes/signatures, one-copy
and same-domain refusal, cancellation after UNKNOWN, paused final-CAS revocation,
coordinator change, commit/abort races, and worker SIGKILL immediately before and
after final transaction. The committed case also kills/restarts the Raft leader
and resolves the same outcome. Status reads may retry transient leader-change
errors; they never allocate another mutation UUID or use a stale fallback.

Fault hooks must be nil in deployment. SIGKILL and injected fsync failures are not
physical power-loss tests. Test authorization/guard inventory and ciphertext are
synthetic. Browser/Symcon, host fencing, real keys, real encrypted diff verification,
V2 wire/packer/key-envelope and runtime integration remain unfinished. The
conservative inventory cap remains 15 retained bundles; sequence registry capacity
is 100 recipients and each operation is capped at four outgoing jobs. Capacity
failure is fail-closed; retention, GC/repair and production sizing remain gates.
All Q01-Q48 remain NOT_RUN end to end. This checkpoint is for review, not merge,
production deployment or migration approval.
