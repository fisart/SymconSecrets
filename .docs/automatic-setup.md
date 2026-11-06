# Coordinated automatic setup

## User flow

Update every participating server to the same supporting Secrets branch. In Mailbox, select **Finish setup on all servers**. Discovery contacts only existing approved connections, one peer per request, and assembles a bounded, signed list of up to eight servers, including indirectly connected servers. Review that list and select **Authorize automatic setup on this server** once with a passkey or the required hardware key.

The signed plan is forwarded across existing connections. Each other installation independently approves the exact same server list once. The setup page links to those installations when their frontend is known. A received proposal, a Global record or another administrator's approval never enables local delegation.

After enrollment, **Finish setup on all servers** starts or resumes the same coordinated operation from any member. Background work completes missing direct links, publishes approved primary and Magic routes, establishes reciprocal Global-only emergency access and retires confirmed obsolete grants. Progress separates pending local authorization, replies not yet received, delivery retries, device steps and completion. Existing sharing continues during setup.

Magic passkey creation/testing and the primary administrator's exact backup activation remain device-confirmed steps. The worker can stage an exact address supplied by the local active Symcon Connect core when no backup origin exists; staging grants no general access. It cannot enroll or activate arbitrary administrator credentials. When a tested candidate is available, the existing exact-fingerprint approval is available in Mailbox. Network timeouts, unresolved conflicts and unavailable Connect service are not automatically approved away.

## Authority and storage

A plan has a version, random plan UUID, coordinator UUID, fixed purpose, sorted members and a coordinator signature. A member pins the vault/backend identity, encryption and signing public keys, Global tree, reviewed HTTPS address/routes and an optional frontend instance. Conflicting keys, a different local identity, revoked peers and a changed known pairing stop automatic execution. Newly introduced members still require an explicit local plan approval; discovery is not authority.

Each opt-in generates a random local generation and 256-bit master, stored only in the encrypted native journal. The policy binds the authorizing credential and identity revocation generation. The public plan and HTML status never contain these credentials. Short-lived peer capabilities and progress observations use the encrypted runtime cache, so polling does not advance the permission head or invalidate an in-progress browser passkey enrollment. Only actual setup/authority changes are committed to native state. Configuration export excludes setup authorization/capabilities; a freshly provisioned installation must authorize again. Existing complete encrypted vault backups protect native authority together with the other vault state.

A server issues an HMAC capability for one pinned caller, recipient policy/generation and expiry. It expires after one hour and is exchanged only inside signed, sealed peer envelopes. The capability permits only fixed setup advancement and confirmed obsolete-grant cleanup. It does not permit value reads/writes, Local access, arbitrary management calls, administrator enrollment, ownership changes, hardware policy or OAuth operations. It is never stored in Global or Local application secrets.

Every command is verified against the recipient's local opt-in and pinned sender before effects. Stopping setup revokes the local generation and prevents delayed proposals from re-enabling it. Credential/identity revocation, removed pairings and manual emergency-permission edits suspend delegated work. A manual emergency change is never silently reversed by automatic regrant.

## Protocol and idempotence

- `SETUP_INFO`: authenticated discovery over an existing active pair. Returns public descriptors/routes, without capabilities.
- `SETUP_OFFER`: forwards the exact signed plan through existing pairs. Stores a pending proposal only; forwarding is bounded and deduplicated.
- `SETUP_HELLO`: signed, sealed request to a member of the locally pinned plan. Returns current progress; an enabled recipient additionally issues a short-lived caller-bound capability. An unapproved recipient returns pending authorization without a capability.
- `SETUP_ADVANCE`: capability-authenticated run request. Queues bounded local work and establishes only the caller's exact plan-authorized missing pair. Both sides derive the same pair UUID from the plan and server identities. Existing pairs retain their identity.
- `SETUP_PRUNE`: the consumer confirms its accepted provider grant and permanently rejects reimport of the exact obsolete grant IDs. Only after that authenticated acknowledgement does the provider retire those IDs. The kept grant remains active. Newly issued grants outside the reviewed retirement set are untouched. Lost acknowledgements are retryable; old credential reimport cannot race cleanup.

No receiving endpoint makes nested network calls. Each worker phase performs one bounded local change or one outbound exchange, including normal route failover. Setup is an additional fair phase under the ordinary 45-second best-effort worker budget for normal work, with a setup-specific 90-second bound and PHP execution reserve. Setup requests allow up to 45 seconds on the primary route and 60 seconds on Magic, capped by the remaining shared budget; the current worker requests a 100-second PHP execution allowance when permitted. The per-instance semaphore prevents overlapping setup workers. Peer work rotates fairly even if each request takes longer than the usual polling interval, with 90-second retry backoff and 15-minute confirmation freshness. Failures use bounded backoff; completed setup stops its own work. Existing health and mesh checks continue independently.

Completion requires a tested, active full Magic credential, active approved connections, reciprocal matching emergency grants, acknowledged route publication, fresh verified peer health, no queued delivery and no unresolved Global conflicts. Per-server completion is reported before the initiating server finishes collecting all remote completion acknowledgements. Last completed setup is distinct from a linearizable proof of the latest distributed secret values.

## Verification

Disposable encrypted four-server fixtures start with three sparse links, discover the fourth server indirectly, require independent local opt-ins, build all six links and obtain three emergency sources per server. They exercise duplicate retirement/reimport tombstones, private status, capability misuse/revocation, suspension after manual permission edits, explicit device prerequisites, route publication and eventual bounded completion. A real WebAuthn fixture checks plan preparation, signed-scope rejection, passkey authorization/start/stop and configuration export exclusion/read-only validation. Browser/UI checks cover discovery, the exact roster, in-place authorization, remote/device progress and the single run button. Tests never restore or alter a live installation.
