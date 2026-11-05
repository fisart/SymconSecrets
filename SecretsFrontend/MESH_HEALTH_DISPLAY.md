# Graphical mesh health

The native Secrets **Overview → Mesh health** displays a graphical network and an expandable colored-dot matrix. Update every participating installation on the native replacement branch. Existing approved shared Global pairings supply the nodes; no new pairing or emergency grant is created by monitoring.

## Reading the display

Each installation is a tile with separate lights for **Frontend**, **Backend**, **Vault**, **Source**, **Backup** and **Sync**. Green means a fresh healthy observation; yellow means unknown, pending or stale; red means a fresh fault. The source light describes usable local/remote source availability, while the vault light retains its local meaning. Remote fallback is explicitly labelled and its last selected provider appears in the node details. Conflicts and journal capacity are shown on the tile; capacity warns at 75% and turns red at 90%.

Solid connections show the **primary route**, dashed connections the **Magic/Connect backup route**. Each half of a line uses that installation's own outbound check, so one direction can fail while the other works. A backup success never makes a failed primary route green. Routes are classified from approved advertised URLs, including when the original pairing invitation was opened through Magic. No endpoint is guessed or discovered from a report.

**A →** means that the installation at the arrow's origin may consume emergency Global reads from the installation it points toward. Green requires fresh reports from both ends and the exact client grant ID appearing in the provider's current approved grants. A different grant for the same peer does not count. Yellow means incomplete or unknown approval; red means the consumer's configured grant no longer matches the provider; a dash means neither side has configured that direction. Approval is separate from operational availability and does not prove that the consumer's independent credential storage is usable. Monitoring never grants access or invokes recovery.

Select a node, line or authorization badge for details. **Show connections for** focuses on one installation; meshes larger than eight nodes start focused on this installation. The expandable matrix includes every known displayed node, with P (primary), B (backup), S (Global synchronization) and A (emergency authorization) per direction. Names use safe text, and controls have keyboard labels. Wide graphs and tables scroll horizontally on narrow screens.

## What each check proves

- Frontend: the frontend module's independent heartbeat and local readiness, including correct backend binding. It does not prove an external browser can log in with a passkey.
- Backend: local module status, enabled state, kernel readiness and applied configuration.
- Vault: the existing validated-vault watchdog state and age.
- Source: the existing local/emergency source availability state; this is not a guarantee that every requested record exists or that a separately scoped native capability works remotely.
- Backup service: the local Connect core reports the approved backup origin as active. The separate dashed route is a real authenticated HTTPS peer exchange.
- Sync: the existing causal Global health comparison, with conflicts separately visible. Matching observations do not prove the newest value during a network partition.

A healthy backup connection does **not** prove a backup job succeeded, that its retained copies are current, or that a restore has been tested. Those require backup-module evidence. This display adds no backup-job success assertion.

## Reports, freshness and failure behavior

A separate `MESH_STATUS` exchange uses existing encrypted, signed, exact-request-bound native peer envelopes. Only active, approved shared Global pairings can request it. It contains local component indicators, names/identities, the sender's own direct connection observations and grant IDs; never secret names/values, tokens, passkeys, key material, private paths or history fingerprints. It does not relay other nodes' reports. Third-party identities in a report never become trusted destinations or authorized peers.

The background worker tests at most one exact approved route per tick, in addition to its existing work. It uses real HTTPS even for a co-located backend, so a local function call cannot falsely prove the backup URL works. The minimum route cadence is 60 seconds; larger route sets increase it to `(route count + 1) × 10 seconds`. Route checks expire after three cadences. Component heartbeats expire after 90 seconds, counting both their age at reporting and report transit/cache age. Clock reversal, page refresh failure and stale data turn indicators yellow. An older module refusing the optional report is unknown; its existing Global HEALTH protocol continues unchanged.

Reports and route observations are encrypted ephemeral diagnostics, without advancing the reviewed mutation head. Report caching is budgeted to roughly one eighth of journal capacity across active peers; large reports can omit link details, explicitly marked partial. Missing details from a partial report remain unknown. The browser displays up to 64 known nodes and identifies truncation. Nodes seen only in another node's report remain unknown until directly paired and observed. Revoked/replaced pairings cannot inherit route checks. In-flight replies are discarded if pairing or route authority changes.

When an entire host, backend or vault is unavailable, its own authenticated page/report may be unavailable too. View the mesh from another healthy installation; a failed connection does not establish which remote component failed. The last observation ages out instead of inventing a green frontend or vault. The independent alarm-system observer remains necessary for whole-process outage notification.

## Validation

Encrypted integration tests cover component separation, exact directional grant identities, primary failure with successful backup, Magic-origin pairing labels, bounded polling, stale and unsupported modules, forged/replayed or misbound reports, revocation during a request, replacement pairing and secret-free metadata. Module lifecycle tests cover independent frontend heartbeat expiry and readiness. DOM tests cover a five-node graphical mesh, separate route lights, exact grants, focus, selected-detail refresh, stale-page behavior, partial reports, unsafe names and standalone display. The SVG graph is also rendered for visual inspection.

## Route failure details

The warning list identifies each failing direction and its fixed diagnostic category: DNS, connection, timeout, certificate/TLS, HTTP status or rejected/oversized reply. Details include consecutive failures; no raw exception text is shared. Selected connection details show the same information. Reports from an older version remain usable, but may require updating the reporting node before a detailed reason appears. The new dialect is requested explicitly; old clients receive the original compact schema and updated clients retry the original dialect if an older receiver refuses the new one.

The local console API `SECB_GetMeshHealth($backendId)` returns the same sanitized observations for troubleshooting, without recovery or network calls. It requires the current native vault to be usable.

## Relay latency and frontend heartbeat

Native Magic/Connect peer requests allow up to 12 seconds, while ordinary primary routes retain a 4.5-second limit. Emergency operations use a 20-second total budget and up to six seconds per relay attempt, including a reserved read phase. TLS, request binding and signature verification remain mandatory. Deadline expiry before HTTP headers is classified as timeout, including PHP's generic HTTP-request-failed warning. These are userland limits; DNS/OS stalls can exceed them.

The frontend publishes its existing heartbeat as the `FrontendHealth` string variable. Backend report generation reads this snapshot and current instance settings rather than making a synchronous frontend module callback. An absent or stale heartbeat remains unknown. No live certificate chain is repaired or replaced by this change.
