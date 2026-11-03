# One shared Global vault

Implemented for development on `feature/secrets-frontend`. Automated tests are
not live deployment qualification or independent security acceptance.

## User contract

**Global** is one merged namespace on connected platforms. **Local** remains
private. Both administrators may edit Global. Disconnected changes are retained
locally and merge after reconnection. There is no timestamp-based winner.

| Situation | Result |
|---|---|
| Entry exists on one platform | Included in Global on all connected platforms |
| Identical typed values at the same path | One visible entry |
| Different secrets changed, including in the same folder | Automatic merge |
| Same secret changed concurrently to different values | Preserve versions; Resolve conflict |
| Deletion versus concurrent edit | Preserve deletion and edit as choices |
| Folder deletion/replacement versus new child | Preserve the surviving folder and the other choice |
| Concurrent changes inside a list | Compare the entire list; no guessing about shifted indexes |
| Conflict resolution races with another edit | Reject stale approval or preserve a new conflict |

Applications refuse exact conflicted paths. Reads of containing folders return
only usable entries; mutations of containing subtrees require resolution first. Unrelated paths remain usable. A display projection is
never permission to return an arbitrary version. Received transport snapshots
cannot be used to bypass the Global conflict check.

## Automatic operation

Update the module on every connected platform and reload its page. Existing
active connections automatically negotiate shared Global through their signed,
encrypted peer channel. No reset, import, merge button, new pairing or additional
passkey approval is needed. Pending and revoked connections cannot enable it.
New connections use the normal numbered connection wizard once.

The editor offers only **Global** and **Local**. Conflicting versions are omitted
from normal Global listings and reads and appear in **Conflicts**. A folder read
continues returning its unconflicted contents. Exact reads of a conflicted secret
fail explicitly; the module never guesses a password. Writes replacing a folder
with unresolved versions are refused until those versions are resolved.

In **Conflicts**, choose **Show versions**, then keep a selected version or keep
all under different names. Confirm the exact choice with the existing passkey
and hardware policy. Resolutions propagate automatically. Existing application
grants keep their approved paths and existing OAuth configurations keep working
where their referenced secrets have no conflict.

The page refreshes masked metadata in the background without refreshing session
idle activity. It pauses during editing, reveal and approvals. Background
synchronization also repairs a delivery gap using signed cursor/challenge checks;
a manual resynchronization is unnecessary. Restored senders still cannot
overwrite a newer receiver.

The old SecretsManager remains independent. Local credentials, tokens, hardware
policies and private Local values do not replicate.

## Trust and membership

Approving shared Global grants the partner permission to read and modify **all
Global contents**, and to share Global with its other explicitly approved Global
partners. Data can therefore propagate through an approved connected graph;
three platforms need not have every possible direct connection. Local access
policy is still enforced before each local read/write and conflict resolution.
A peer signature is authorization from an approved Global writer, not a new
administrator credential or permission to access Local.

Removing one connection stops that link and its queued messages. It does not
erase already shared values or disconnect other approved routes to that
platform. To isolate a platform in a graph, remove every link to it. This is not
a centralized group-membership or immediate remote data-erasure guarantee.

## Replicated state and publication

`native.sharedGlobal` uses `SECB.SharedGlobal.1`: a bounded version clock and
per-path multi-value registers. Platform UUID plus monotonic decimal counter
identifies a local mutation. Each register retains current versions and their
causal context. A null register node is a deletion marker; a typed JSON null is
a distinct actual value. Object folders have their own markers; lists are atomic.
Object-property order is normalized, while list order and scalar types survive.

Join retains versions not superseded by the other side's observed clock. It is
commutative, associative and idempotent for valid replica states. An identical
causal version with different bytes is rejected. Wall clocks are not part of
ordering. Deletion history is retained so old snapshots cannot resurrect values.

The local edit, version history and encrypted outgoing snapshots commit in the
same native journal operation. Receipt processing commits the merged history,
Global projection, incoming cursor and onward snapshots together. It acknowledges
only after publication. Lost acknowledgements retry the immutable message;
unchanged joins do not generate another round of updates.

Existing signed/encrypted peer envelopes and recipient/pairing bindings remain.
Shared snapshots bind both the typed projection and version model into their
digest. Legacy snapshots cannot supply merge metadata. Delivery counters restart
for a new pairing identity; rollback/divergence checks still retain the last
source revision. Resynchronization uses the existing authenticated cursor and
challenge. A restored sender cannot overwrite a newer receiver by timestamp.

Conflict choices bind the current causal version set and exact output names.
Fresh passkey approval uses the existing write/hardware policy. Metadata omits
values and hashes of guessable values. Comparison uses the authenticated reveal
path, respects hardware requirements, limits output to 64 KiB, and does not
persist values in browser storage. Nested conflicts must be resolved before a
containing folder conflict can be resolved.

## Persistence and limits

Encrypted backups preserve the complete shared version history. Value-only
restore of a backup containing unresolved conflicts is refused rather than
silently choosing its display projection. Ordinary restart preserves shared
history and invalidates volatile authentication through the existing runtime
boundary. Do not downgrade a participating installation to code which predates
this state model.

Existing native storage/memory and outbox limits remain enforced. The model has
at most 64 historical writer identities, 5,000 registers and 200 live children
per folder; exceeding a bound refuses publication. Deletion history is not
silently discarded to reclaim space. Long-running tombstone compaction and a
coordinated membership-epoch reset are not implemented. Full-state rollback of
an isolated host still has the previously documented native-mode limitations.

## Validation

- `shared-global.php`: merge algebra, three-replica interleavings, typed values,
  object order, deletion history, folder conflicts, no timestamp winner,
  masked metadata, exact choices, Keep all and stale-resolution refusal.
- `shared-global-peers.php`: real signed/encrypted exchange and on-disk journals;
  automatic existing-connection join, preserved initial contents, three-platform relay,
  offline conflicts, lost reply, machine fencing, resync, restart and backup.
- `pairing-wizard.php`: actual passkey approvals, session/CSRF checks, restricted
  conflict reveal, hardware reveal gating, resolution and bidirectional exchange.
- Browser suites: one Global selection, masked conflict cards, per-version reveal,
  exact keep/rename requests, hardware handoff, automatic pairing and automatic existing-connection join.
- Existing native storage, import, ownership, machine, OAuth, setup, passkey and
  backup suites remain regression tests. Original repository blobs remain intact.

Deployment acceptance still requires updating both live modules, checking Test's known Global entries on Heartbeat, editing in both
directions, testing an offline conflict and restarting both Symcon instances.
No live vault has been reset or migrated by the development tools.

## Automatic connection protocol

`GLOBAL_ENABLE` and its `GLOBAL_ENABLED` acknowledgement bind to the existing
active pair UUID/epoch, sender, recipient, immutable job and mode through the
existing authenticated envelope. It changes a separate runtime Global-mode field;
the original pairing descriptor and comparison digest remain immutable. Both
updated peers must speak this mode. An unavailable or older peer stays pending
background retry; no TLS or signature check is bypassed. Lost acknowledgements
retry the same operation. Revocation fences activation and its acknowledgement.

Old queued snapshots drain in sequence before the shared model snapshots. Every
subsequent shared snapshot authenticates its model and projection. Only the
approved peer channel can start the automatic transition; public page access and
pending enrollment grant no authority. Installing this release adopts the unified
Global behaviour for existing active connections as requested by the operator.
