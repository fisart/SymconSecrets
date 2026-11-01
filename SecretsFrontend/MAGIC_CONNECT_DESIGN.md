# Backup HTTPS origin for Symcon Connect — implementation contract

Status: **development implementation; live qualification and independent implementation audit pending**. This document describes required controls, not production acceptance.
The audit of proposal `b19e0f3` identified three requirements that must be
resolved before security acceptance: exact enrollment authorization, complete
revocation, and verification of the deployed Connect transport and outage path.
The requirements below incorporate the full audit and developer acceptance
tests, including MC01–MC03. The implementation has not itself been independently audited.

## Goal and existing behavior

One initialized native vault must remain accessible at its current primary HTTPS
origin and a separately configured Symcon Connect HTTPS origin. The primary `AdminOrigin` remains pinned in the native storage binding,
management profile; backup routing and credential eligibility use additive authenticated policy. Adding a
second hostname to only the frontend would therefore fail or weaken security.
Existing initialized vaults and their current primary credentials must continue
to work; no vault reset, destructive reinitialization or secret copying.

## Requirements

1. **Explicit trust.** A backup origin is an exact normalized HTTPS origin,
   with no userinfo, paths, wildcard, query, fragment or IP shortcut. It is
   admitted through a state-changing, audited operation that requires an
   existing eligible administrator's fresh passkey and current hardware policy.
   A console setting, observed Host, forwarded header, untrusted browser request
   or imported configuration alone cannot establish trust.
2. **Preserve pinned foundation.** Primary origin, deployment identity, storage
   binding and existing signed management profile remain unchanged. An additive,
   versioned authenticated vault-policy record tracks the approved backup origin
   and its lifecycle. Legacy states without this record mean no backup origin.
   Restart and state recovery must understand both versions without treating a
   missing/invalid record as permission to trust a new origin.
3. **Separate credentials and sessions.** Each credential is explicitly bound to
   the origin and RP ID used for its registration. Existing credentials that
   lack origin metadata are treated as primary-origin credentials only, after
   verifying the existing genesis/registration binding. Auth challenges offer
   only credentials eligible at the current approved origin. Assertions must
   validate the exact origin, RP ID, challenge, credential and hardware policy.
   Host-only cookies, CSRF tokens, login challenges and session records remain
   origin-bound; primary-origin proof or cookies cannot log in on the backup.
4. **Cross-origin enrollment.** The primary administrator authorizes a
   short-lived, single-use backup enrollment intent bound to vault identity,
   backend/frontend IDs, exact backup origin, browser public key, purpose,
   expiry, policy/head and hardware requirements. On the backup origin the
   candidate creates a passkey and demonstrates possession of its browser key.
   The primary administrator reviews and approves the exact candidate and
   backup origin with a fresh eligible passkey. Before backup use, prove the
   candidate can authenticate at the backup origin. Stale, cancelled, replayed,
   altered, cross-vault or wrong-origin intents and signatures fail closed.
   Backup setup must not silently enroll a credential or bypass hardware policy.
   Approval must cover a canonical, immutable representation of the exact
   candidate administrator identity, user handle, credential ID and public key fingerprint, granted
   permissions, backup origin and RP ID, browser-key digest, vault and instance
   identities, policy version, lifecycle generation, expiration and purpose.
   The administrator must be shown the identity, origin and permissions being
   approved. Any change requires a new candidate and approval. The approving
   credential and its authority must remain valid at the time of activation.
   A pending or merely approved candidate has no general vault session, read,
   write, reveal, administration, or approval authority. Its only permitted
   actions are the narrowly scoped enrollment and proof steps. Activation must
   atomically recheck the exact approval, proof, current policy and origin
   generation before granting the explicitly approved permissions.
   The lifecycle is pending origin, restricted enrollment, possession tested,
   active, then revoked. Possession testing does not grant self-approval. Publish
   the policy and credential grant consistently; after interruption or a lost
   final response, resolve the original operation identity without creating a
   second credential or activating incomplete state. Browser messaging, if used,
   must validate exact source and target origins; do not use wildcard CORS,
   URL-carried bearer invitations or a parent-domain RP.
5. **No weaker recovery.** Origin addition, credential addition, origin changes,
   revocation and recovery cannot be weaker than existing administrator and
   hardware policy. An ordinary credential cannot introduce a bypass when any
   protected administrator action requires hardware. Prevent accidentally
   removing the last usable administrator route, or require the explicitly
   designed independent recovery path. Inactive, revoked, untested or
   hardware-ineligible credentials do not count as a usable administrator route.
6. **Host and transport.** Host/origin checks select only an already approved
   exact origin, using validated transport/proxy evidence; never trust arbitrary
   forwarded headers. Symcon Connect webhook/host/Origin/cookie behavior and
   HTTPS must be tested on the actual service. A deployment that cannot safely
   identify the browser-facing origin must fail closed. Direct plaintext and
   alternate listeners must not become an authentication bypass.
7. **Availability.** Once provisioned and tested, primary certificate failure
   must not require local console access: open the saved Connect address and
   authenticate using its already registered passkey. This does not protect
   against a Symcon host, network or Connect-service outage.
8. **Consistent UI and recovery.** Wizard presents primary and backup links,
   independent setup/test status, clear failure states and an explicit approval
   step. No secrets, cookies or setup authority in URLs, logs or persistent
   browser storage. Enrolling the backup must not replace existing primary keys
   or alter vault contents, storage, peer identity or integration grants.
   Suggest the Connect address by locating the Connect Control core instance
   (`{9486D575-BE8C-4ED8-B5B5-20930E26DE6F}`) and, where available, calling
   `CC_GetConnectURL`; older compatibility environments may expose `CC_GetURL`.
   This is a discovery suggestion only: require a normalized exact HTTPS origin,
   explicit administrator review and the same approval/enrollment protocol.
   Missing, inactive, ambiguous, malformed or non-HTTPS results must give a clear
   setup message and never change trusted policy. Recheck the discovered address
   at review and activation; do not silently follow a later change. Discovery
   does not verify the relay transport or authorize access.

9. **Complete revocation.** Removing or replacing the backup origin is an
   audited, authorized policy change. It must immediately invalidate all of
   that origin's sessions, login and registration challenges, enrollment
   intents, candidates, proofs and pending approvals. Bind every such artifact
   to a durable, non-reusable origin generation and validate it on use and
   again under the commit or authorization lock. Concurrent in-flight login,
   approval, reveal and mutation must fail if revocation wins the race for
   authorization. An operation irrevocably authorized before revocation follows
   the existing narrow completion rule; already returned plaintext cannot be
   recalled. Adding
   the same origin again uses a new generation and cannot revive old artifacts
   or credentials. Invalidation must survive restart and recovery. Keep the
   primary origin and its credentials usable, subject to the existing policy.

## Connect deployment evidence

Do not assume that `Host`, `Origin`, `Forwarded`, `X-Forwarded-*` or a TLS flag
reaches the module unchanged or proves browser-facing HTTPS. On the actual
Connect deployment, record the externally visible URL and certificate, the
proxy or relay path, and the headers and transport evidence the Symcon hook
actually receives. Establish and test a trusted, unambiguous origin-selection
boundary before enabling backup access. Spoofed, conflicting, missing or
untrusted forwarding evidence must not select an approved origin. If the
deployment cannot establish that boundary, backup access remains disabled.
Record the relay's and any intermediary's ability to inspect or modify traffic
or the served application. A provider able to terminate or modify the page is
part of the browser application's trust boundary. Do not accept wildcard tenant
hosts, disable certificate verification, or bypass webhook authentication.

After setup and a successful backup login, perform a controlled test in which
the primary certificate is invalid or unavailable. Open the saved Connect URL
and sign in with its separately enrolled passkey in a fresh browser session;
repeat after a Symcon restart. Verify through browser and network observations
that assets, redirects, recovery and login do not contact the primary hostname.
Restore and retest the primary route. Record the environment and results
without recording passkeys, session cookies, credentials or vault contents.

## Required verification before use

- Synthetic end-to-end test: initialize existing primary-only vault, add backup,
  enroll and test backup credential, sign in at each origin, and recover after
  restart with the same vault contents and primary passkeys intact.
- Reject unexpected hosts, malformed origins, untrusted forwarded host headers,
  cross-origin WebAuthn assertions, reused challenges, cookie/CSRF swapping,
  stale approvals and backup candidate self-approval.
- Attempt to alter each approved administrator, credential and permission field
  between review and activation; reject every mismatch. Exercise every general
  access endpoint during pending enrollment and confirm it is denied.
- Pause after registration, approval and possession testing; change approver,
  role, hardware policy or origin generation, or cancel before resuming. Test
  two candidates and administrators, wrong user handles and a lost final reply.
- Revoke during each enrollment stage and while login, reveal, approval and
  mutation are in flight; verify all old artifacts fail after revocation,
  restart and re-adding the same origin, while primary access remains usable.
- Test hardware-policy enforcement, origin revocation, last-key protection,
  competing/cancelled enrollment, lost responses, interruption and restart.
- Verify session expiry/revocation independently at both origins and ensure
  backup access cannot revive a revoked primary or revoked backup credential.
- Test actual HTTPS Symcon Connect, its observed TLS and header behavior, and
  real browsers and passkeys, including a controlled primary-certificate failure,
  proof that backup login makes no request to the primary hostname, repeat after
  Symcon restart, and later primary recovery. Test wrong tenant hosts, Host and
  Origin pairs, forwarding headers, direct HTTP, alternate listeners, changed
  Connect address, redirects and cookies.
- Independent security audit of the exact completed implementation before
  production; no live certificate failure or production rollout is performed by
  the implementation tests.

## Implemented enrollment sequence and remaining evidence

The primary administrator approves a pending exact origin. This only admits
restricted registration/testing APIs. The backup browser submits a P-256 public
key, signs the exact registration transcript, and proves possession of its new
origin/RP-bound passkey with a second signed transcript. The resulting candidate
is bound to current vault head, administrator, user handle, credential/public key,
browser key, origin generation, fixed backup authority and five-minute expiry.
The primary reviews the exact candidate digest and key fingerprint and approves
activation with a fresh current eligible passkey. Policy activation and credential
publication happen in the same native mutation. There is no candidate session.
A lost activation reply is resolved using the existing operation UUID/outcome API.

Popup messages use an exact target origin and the primary verifies both source
window and exact source origin. They contain only a candidate reference/digest,
which are not approval authority. A hidden primary window queues the notification
until it is visible. No authority is carried in a URL.

Backup sessions are limited to browsing/revealing, approved vault edits and export;
administrator, setup and integration management use the primary route. The
primary foundation and genesis remain pinned. Revocation preserves a tested
primary route and disables backup credentials; every backup session and challenge
uses its exact generation. Re-addition requires a fresh candidate and generation.

The HTTP adapter accepts native HTTPS evidence, an explicitly trusted HTTPS proxy,
or the narrowly scoped built-in Connect loopback profile documented below. Actual relay headers, internal
hop trust, physical passkeys, full outage/no-primary-contact tests and independent
review of the completed commit remain deployment acceptance gates.

## Observed Symcon Connect loopback transport profile

The installation diagnostic supplied no HTTPS flag, request scheme or trusted
forwarding metadata, with REMOTE_ADDR=127.0.0.1 and Symcon caller instance 0.
These missing fields are also covered by the existing primary-URL compatibility
profile; requiring them unconditionally made the Connect route unusable.

The Connect loopback profile requires the exact approved HTTPS origin to equal
the address independently returned by the single active local Connect Control
instance. It accepts only the direct Host for that exact 32-character tenant at
ipmagic.de, a loopback peer (127.0.0.1 or ::1), and no conflicting scheme, HTTPS
flag, Forwarded, X-Forwarded-Host or X-Forwarded-Proto. X-Forwarded-For is never
transport authority. Remote clients cannot qualify by supplying the same Host.
Address changes, inactive/ambiguous discovery and revoked policy fail closed.

This profile explicitly trusts the local host's loopback services and the Connect
service as transport intermediaries. It does not cryptographically identify the
process that opened a loopback socket or infer browser TLS from the Host header.
Untrusted local proxies must not expose or impersonate this loopback hop. Browser
HTTPS/secure-context checks, exact Origin checks, independent passkey/RP contexts,
primary-side exact approval and per-origin sessions remain mandatory. The profile
is not administrator authority. Physical Connect browser testing, provider/internal
hop trust qualification and independent audit remain pending.
