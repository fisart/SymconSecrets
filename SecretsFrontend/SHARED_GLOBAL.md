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

Applications and ordinary reveal/edit operations refuse a conflicted path and
any containing subtree. Unrelated paths remain usable. A display projection is
never permission to return an arbitrary version. Received transport snapshots
cannot be used to bypass the Global conflict check.

## Upgrade: retain both existing vaults

1. Update this module on **every** participating platform and reload its page.
2. On the initiating platform, open **Connections**. For the existing connection,
   select **Merge into one Global vault**. No vault reset is required.
3. Follow the numbered connection wizard. It opens the other platform and asks
   for exact approvals to retire the old connection and create the new one.
   Both existing Global contents are retained. Existing Local data is not shared.
4. Wait for the signed exchange. Open **Global secrets**. Test's existing Global
   contents and Heartbeat's existing Global contents are merged; a different
   value at the same path requires a choice.
5. Resolve each conflict: **1 · Show versions**, **2 · Keep selected version**
   or **Keep all versions with these names**, then **3 · Confirm**. Choosing a
   radio option before Show versions displays just that version. Values clear
   after 30 seconds. The existing reveal hardware policy still applies.
6. Review and reissue Global **Automation access** grants and Global OAuth
   provider configurations. Old Global grants/providers are disabled on initial
   activation so old permissions do not silently expand to newly shared secrets.

The ordinary setup wizard also uses this new model for new connections. Local
administrators, passkeys, machine tokens, hardware policy and Local secrets do
not replicate. The old SecretsManager is unchanged.

A legacy connection remains read-only/separate until a fresh bilateral approval
names `shared-global-v1`. New scope is bound into the signed invitation, pairing
proof, comparison code and approval digest. The browser coordinator verifies
support on both sides before creating the new invitation. Older peers reject
the new scope; existing connections are never silently upgraded.

A platform with several old active separate-tree connections must remove those
connections before activating the new shared model, then pair them under the
new permissions. Existing single-owner transfers/frozen trees must be resolved
first. The old owner-transfer mechanism cannot change shared Global authority.

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
  explicit legacy upgrade, preserved initial contents, three-platform relay,
  offline conflicts, lost reply, machine fencing, resync, restart and backup.
- `pairing-wizard.php`: actual passkey approvals, session/CSRF checks, restricted
  conflict reveal, hardware reveal gating, resolution and bidirectional exchange.
- Browser suites: one Global selection, masked conflict cards, per-version reveal,
  exact keep/rename requests, hardware handoff, automatic pairing and legacy upgrade.
- Existing native storage, import, ownership, machine, OAuth, setup, passkey and
  backup suites remain regression tests. Original repository blobs remain intact.

Deployment acceptance still requires updating both live modules, approving the
upgrade, checking Test's known Global entries on Heartbeat, editing in both
directions, testing an offline conflict and restarting both Symcon instances.
No live vault has been reset or migrated by the development tools.
