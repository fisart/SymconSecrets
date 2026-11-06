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
