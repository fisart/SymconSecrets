# Background Global synchronization checks

Current native-only replacement on migration/legacy-sec-replacement (runtime baseline 5.4.6 build 16). These are authenticated observations of
trusted peers, not remote host attestation or proof that an unreachable platform
is offline. Actual deployment checks remain separate from automated tests.

## What the user sees

Overview and Connections show each directly connected platform's connection and
Global synchronization status, last attempt, last successful response, last
verified matching state, pending delivery count and a fixed diagnostic message.
All problems also appear in Overview's overall status. No state fingerprint,
secret value or version clock is exposed to the browser.

| Synchronization | Meaning |
|---|---|
| Verified in sync | A recent authenticated response matched this vault’s shared state at the comparison. Remote changes after that response are not ruled out. |
| Synchronizing | The known states differ and normal causal synchronization is running. |
| Not synchronized | Differences persisted through repeated checks, or inconsistent history was detected. |
| Status unknown | No fresh comparison is available. A failed connection does not prove different data. |

Reachability is separate: Reachable, Retrying, Unreachable or Not checked.
Conflicts are also separate: matching replicas may contain the same unresolved
conflict versions. Local values never participate in comparison or replication.

The page refreshes metadata every ten seconds while Overview or Connections is
visible. All freshness, color and readiness evaluation is performed in Symcon. A failed browser retrieval shows a separate notice beside the last server evaluation; JavaScript does not re-age or reclassify it. No refresh extends the administrator's idle limit.

## Background cadence and bounded work

The existing ten-second backend worker performs at most one health request per
run, independently of browser activity. It selects the oldest due peer fairly.
For four platforms in a full mesh, each platform checks its three peers every
60 seconds as a target, subject to load/latency and fair bounded work. Remote age-only warnings allow 15–30 minutes. MonitoringFreshness uses a 900-second minimum and up to three times the largest of the last eight consecutive successful gaps, capped at 1800 seconds. Failure, overdue/outage gaps and clock reversal cannot extend the allowance. Latest real failures remain visible immediately. Larger groups expose their actual interval in metadata. Local watchdog/heartbeat alarms retain their independent timing.

Each check uses the existing bounded HTTPS exchange, at most two
approved addresses, strict TLS/pinned-primary rules and Magic-first failover.
No redirect, new peer, URL discovery result or unapproved route creates trust.

## Protocol and freshness

HEALTH uses the existing signed and sealed peer envelope, bound to the active
vault keys, recipient, pairing, epoch and a new random request UUID. The reply
must authenticate the exact request ID, kind and digest. Old signed replies
cannot answer a later check. Pending/revoked pairs cannot query health.

A request carries only SECB.GlobalHealth.1. The receiver reads its current shared
state and returns its causal clock, canonical model fingerprint and conflict
count inside the encrypted reply. It validates that the stored Global projection
matches that history. The fingerprint includes typed values, deletion markers,
concurrent versions and causal history; secret counts, per-platform transport
revisions, wall-clock ordering and last delivery timestamps cannot prove equality.

Receiving a HEALTH request is read-only and does not establish liveness for its
sender. Only an outbound fresh request/response establishes a local observation.
Replayed requests cannot refresh a remote observation or create repair jobs.

Comparison records are bounded, encrypted transient data keyed by pairing and
epoch. Matching probes do not advance the reviewed vault head, create mutation
outcomes or grow the mutation audit. A new backend runtime clears the records. A local
Global change invalidates an older matching proof immediately; Local edits do not.
Network error details use fixed codes and never include response/exception text.

## Repair and inconsistent history

Different valid clocks trigger the existing causal snapshot protocol, coalescing
with pending SYNC/RESYNC work. If an older snapshot reaches a peer with newer
history and does not change it, that peer queues its current state back. This
repairs a lost remote publication without selecting a master or requiring a
manual resynchronization. The existing signed cursor/challenge mechanism repairs
sequence gaps; rollback protection remains enforced.

Continuously different states are escalated after three intervals and repeated
successful comparisons. Matching states clear the warning. Conflicts remain for
an administrator to resolve using the normal exact passkey/hardware policy.

The same causal clock with different history is inconsistent. Monitoring flags it
and does not initiate repair or choose a winner. Ordinary shared snapshot receipt
also rejects that inconsistency, including a missing record with an increased
transport revision. A local projection/history mismatch is likewise refused.
Investigate the affected platform and use the existing reviewed recovery process.
Removing/replacing a pair fences in-flight results; a new pair cannot inherit old
health. Monitoring never overwrites Local, approves a credential or changes trust.

## Automated checks

The native runner exercises four fully connected replicas, quiescence and minute
cadence, stale/stopped checks, failed connections and recovery, private Local
isolation, lost-publication repair, bounded pending repair, persistent mismatch,
same-clock conflicts/truncation refusal, synchronized conflict versions, signed
reply/request replay, sanitized failures, revocation races, replacement pairs and
restart fencing. Magic routing tests check fresh health without primary hostname
attempts. DOM tests verify Overview alerts, timestamps and pending counts, separate
conflicts, live Connections refresh and stale-page handling.

## Emergency-read limit

This protocol provides asynchronous causal replication, not quorum commit or
linearizable reads. Even a live majority can agree on an older value if the
latest writer acknowledged its local change before losing connectivity. A cached
matching HEALTH response, a completed outbox, or a wall-clock timestamp is not
an emergency-read authorization. `consistency` metadata in native info/session
and pairing progress makes these limits explicit; its fields are diagnostics,
not a signed certificate. Emergency reads require a separate explicit grant; peer health alone never enables fallback.

See [strict mesh consistency verification](STRICT_MESH_CONSISTENCY.md) for the
four-vault counterexamples and the historical strict-consistency proposal.

Availability-first emergency access is now separately available through [two-sided approval](EMERGENCY_GLOBAL_ACCESS.md). The health comparison itself still does not authorize an emergency read or prove a latest committed value.

## Graphical mesh health

Overview now includes a graphical network with component lights, primary/backup route lines, directional emergency authorization arrows and an expandable comparison matrix. See [Mesh health display](MESH_HEALTH_DISPLAY.md) for interpretation, refresh intervals and limits.
