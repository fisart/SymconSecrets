# One-button mesh setup

## User flow

Update every participating installation to the supporting `migration/legacy-sec-replacement` branch. Sign in as a full administrator on any existing member and select **Mailbox → Finish setup on all servers** once. This queues discovery and setup in the backend. The browser never waits for a remote server and can be closed while work continues.

No per-server passkey authorization is required for mesh setup. Existing active shared-Global connections provision the protected setup credential and forward the signed server list. Missing direct connections, primary/Magic routes and reciprocal Global emergency access are established automatically. Confirmed obsolete emergency grants are retired with the existing two-sided acknowledgement protocol.

The page reports progress, then **OK** only when every member has a fresh authenticated completion report. Each server checks direct connections, synchronization, matching reciprocal emergency grants, acknowledged routes and separate successful probes of primary and Magic routes. A queued or unconfirmed request is not success. The Download detailed report button saves the current per-server evidence and bounded attempt history as JSON.

Browser login through Magic is a separate feature under Access & keys. Mesh setup discovers its peer-only Magic origin from the local active Symcon Connect core, without creating browser credentials or granting browser administrator access. Missing or inactive Connect service is reported on the responsible server. The receiver accepts that exact peer origin only through the existing verified HTTPS/Connect transport checks; signed, encrypted peer authentication remains required.

## Authorization model

Version 2 intentionally changes the previous independent per-server opt-in model. Existing active shared-Global peers are trusted to establish **mesh administration within the pinned group**. A newly discovered public endpoint, pending pair, revoked pair, browser-provided token or ordinary application Global record grants no authority. Initial membership still requires an existing authenticated connection into the trusted group. Completely disconnected installations cannot bootstrap through an unavailable Global vault.

The initiating full administrator's authenticated, CSRF-protected click creates a bounded background request. Before execution the backend rechecks that credential and its revocation generation. Discovery produces a signed plan naming the exact vault IDs, encryption/signing keys, tree IDs and permitted routes. The plan binds the hash of a random 256-bit setup token.

The token is a **protected Global control secret**, stored in each backend's encrypted native journal as `native.globalSetupSecret`, replicated through signed and sealed `SETUP_ENROLL` messages along existing approved shared-Global connections. It is deliberately outside the application-readable Global tree: ordinary SEC/SECB reads, secret listing/reveal, configuration export and support diagnostics cannot expose it. There is no manual token creation or copying. Each server derives its own setup master from the shared token and its vault ID. Short-lived capabilities additionally bind the caller, target generation, plan and expiry; caller identity still requires the server's signing key.

The authority permits fixed mesh operations only: pairing pinned members, publishing peer routes, reciprocal Global-only emergency reads and confirmed obsolete-grant cleanup. It cannot create administrators, read Local secrets, alter arbitrary secret values, change hardware policies or perform OAuth operations. A local stop revokes the current generation and blocks subsequent remote enrollment. Replaying a plan never re-enables suspended authority. Identity revocation, changed keys, revoked pairings and manual emergency-permission changes retain their suspension behavior.

Old version-1 per-node proposals are replaced automatically by the new flow. Existing version-2 plans resume with the same credentials. Conflicting concurrent plans or changed membership fail visibly rather than silently expanding authority. All nodes must run the supporting protocol; an older endpoint's refusal is reported with the route and HTTP status.

## Background work, deadlines and errors

One worker phase performs a bounded local step or one outbound exchange with route failover. Setup uses a shared 90-second worker budget, with up to 45 seconds on primary and 60 seconds on Magic, capped by remaining budget. Health and route verification receive these generous allowances while setup is active. The existing per-instance semaphore prevents concurrent workers. Peer work rotates so a slow server cannot permanently block another.

Discovery retains confirmed replies, retries failures after 90 seconds and reports incomplete discovery after 20 minutes. A setup run has a 60-minute bound; completed connections and credentials are retained for the next explicit retry. Setup-time route/health observations allow up to 30 minutes for high-latency verification; completion acknowledgements must still be within 15 minutes. Ordinary health monitoring retains its normal freshness rules outside setup.

Reports contain server/direction, operation, fixed error category, HTTP/certificate details when available, each attempted route and elapsed milliseconds, attempt count, next retry time and a correlation reference. Local failures include an exception class and source location, with safe fixed messages rather than raw potentially secret-bearing exceptions. Delivery details include queued operation and retry metadata. Each server also reports outstanding connection, route, synchronization and emergency-permission checks. Earlier failures remain labelled as history and are not mistaken for current failure after recovery.

CSRF recovery can refresh the session and repeat safe reads. It never automatically replays the setup-start mutation. If its response is lost, the page explains that the backend may already be working and that status should be checked before retrying. Repeated starts resume confirmed work.

## Backup and verification

Configuration backup format is unchanged. Configuration export excludes setup credentials, authority and runtime reports. Complete encrypted vault backups include native state; ordinary configuration import cannot grant mesh authority. Existing module-owned read-only export/validation and provisioning protections remain in force.

Tests cover four encrypted native vaults starting from a sparse three-link topology, one initiating administrator, indirect fourth-member discovery, automatic enrollment, all six direct connections, automatic local-core Magic discovery without browser credentials, reciprocal emergency access, distinct route checks, detailed primary/backup failures, retained credentials on retry, token tampering, inactive peers, replay/suspension, capability misuse and secret exclusion. Legacy setup tests remain for compatibility; browser tests exercise the actual single-click handler, absence of approval calls, progress, stale-result rejection and detailed errors. All tests use isolated disposable fixtures.

## Enrollment ordering and report consistency (2026-11-06)

An observed failure had a healthy primary and Magic route but received HTTP 403 for `SETUP_HELLO` while the same receiver's `SETUP_ENROLL` remained unattempted. Setup now gives enrollment its own priority delivery opportunity before requesting capabilities. A receiver whose enrollment is backing off is skipped for capability requests; other receivers can progress. Existing retry/backoff, pairing identity checks, signed replies, suspension and token restrictions remain enforced. Ordinary delivery ordering is unchanged.

During active setup, worker phases alternate setup with delivery, health and mesh, retaining provider work and the shared deadline. This increases progress without stacking network phases or shortening the high-latency allowances. Remote authorization failures remain visible in queued delivery details, including operation, HTTP status, attempted routes and retry times. A failed setup exchange is recorded once rather than again as a generic local failure.

Setup status is assembled under one local store snapshot, including member contacts and the report. Queued enrollment has its own per-server delivery record even when ordinary synchronization is also queued. Downloading a report first requests fresh status; a failed refresh shows an error rather than downloading cached results with a new timestamp. The status includes `observedAt`; individual remote `checkedAt` timestamps still show when each server was last authenticated.

Regression coverage runs four encrypted vaults through the real fair worker scheduler, one network phase at a time, without draining queues between setup attempts. It rejects `SETUP_HELLO` overtaking a queued enrollment, checks fresh snapshot selection without peer I/O, and tests fresh-report download and refresh failures. Apply the module update to all four servers and use the existing **Finish setup on all servers** button to resume; existing authorization and completed connections are retained.


## Completion on slow connections (2026-11-06)

The live four-server report exposed two completion defects. A finished node stopped using the 30-minute setup verification window and reverted to the ordinary 3–3.5 minute monitoring window. Successful checks 219–350 seconds old then appeared unknown while the rest of the group was still finishing. In addition, due status polls could repeatedly return before reaching the final completion decision.

Setup readiness and its detailed report now explicitly use the same bounded 30-minute route/digest verification window regardless of whether that node has stopped its setup worker. Fresh authenticated member confirmations remain limited to 15 minutes. A failed latest probe, changed Global digest, missing route receipt, queued delivery, incomplete emergency permission, duplicate grant awaiting cleanup, revoked authority, or expired proof still prevents completion. Routine monitoring and emergency-read authorization keep their existing rules.

Completion is evaluated before another status poll, after pending enrollment and incoming emergency offers are handled. `localCompletedAt` records this node's milestone; public `completedAt` is only populated after whole-mesh completion. Repeated successful status reads no longer fill the progress log with authorization events. A previously completed run is displayed separately from current checks awaiting refresh.

Selecting **Finish setup on all servers** starts a new verification run even if this coordinator was still waiting for an older run. It retains existing credentials, pairings and grants, and wakes remote setup workers that had already stopped. All prior ready results must be confirmed for the new run. Update all servers before selecting the button once; no per-server approval is added.

Regression coverage includes the reported 350-second successful checks on a finished node, genuine failure and expiry rejection, completion before due polls, distinct local/mesh timestamps, and retry while the coordinator is running but its peers have finished. The four-vault fixture uses a shared clock and the fair worker scheduler through final completion, including slower worker opportunities; it no longer drains queues or gives health checks a different clock to reach the final result. Configuration backup format is unchanged; the added completion timestamp is runtime state excluded from configuration export.


## Receiver workload and timeout evidence (2026-11-06)

A subsequent live report showed repeated `SETUP_HELLO` timeouts to Test Hermitage from all other servers on both routes. This establishes a failure to obtain a response within the caller's deadline; it does not identify whether the cause is network transport, script scheduling, storage or receiver processing. Prior successful route/digest checks remain historical observations and must not be presented as recovery from a later timeout.

The signed setup, discovery, health and mesh-status receivers now assemble each response under one fresh local snapshot. Their nested metadata/cache reads previously reloaded and decrypted the full vault repeatedly. An isolated four-vault fixture measures 27 loads for `SETUP_HELLO`, 14 for `SETUP_INFO`, 10 for `HEALTH` and 20 for `MESH_STATUS` on commit `70cd237`; each requires two loads after the change. Signed rejected requests still consume the rate allowance. Signature, sender, pairing, runtime and current authorization checks remain active; nothing is cached across requests. The scoped handlers perform no outbound peer I/O while holding the snapshot. Worker readiness evaluation also batches its local reads, and the module reuses the verified store object within a receiver call.

Incoming receiver diagnostics retain bounded timings without envelopes, values, tokens or raw exception messages. `claimedPeerId` is an untrusted header label, not proof of authentication. `response` means the handler returned a response, not that a caller received it. The last unfinished marker can reflect a terminated script and is not an inventory of simultaneous requests. Timings start at `ReceiveNativePeer`, so they do not measure earlier HTTP/TLS processing or script-queue delay. The detailed setup report includes recent receiver observations for nodes that reply; transport diagnostics include the longer bounded history. If a node remains unreachable, collect its report locally to inspect these observations.

A newly accepted run clears that server's prior-run error history and includes the run identifier. This prevents an old 60-minute deadline from appearing to describe a newly restarted run. Existing credentials and links remain intact. Configuration backup format is unchanged; timing buffers and transient run reports are not configuration.

The workload reduction is verified locally. Whether it resolves a particular deployment's timeouts requires a new live run; local tests are not a substitute for that result.

## Overview after setup completion (2026-11-07)

The overview keeps the completed setup result separate from ongoing monitoring. Previously any unknown mesh observation triggered the generic ‘Setup or synchronization in progress’ banner, even after `SETUP_COMPLETE`. It now identifies unknown/stale mesh checks and points to their node/connection details. Actual setup runs, incomplete setup, pending approvals, synchronization verification, backup address delivery and OAuth work have separate descriptions. Existing faults still require attention, and unknown checks prevent a green ready indication. Expired setup-contact records do not erase the recorded completion milestone. This is a presentation change; it does not refresh expired evidence or change authorization, verification windows or configuration formats.
