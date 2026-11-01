# Backup HTTPS origin for Symcon Connect — implementation contract

Status: **design only, not implemented**. No second origin is trusted by this file.

## Goal and existing behavior

One initialized native vault must remain accessible at its current primary HTTPS
origin and a separately configured Symcon Connect HTTPS origin. The current
implementation has a single `AdminOrigin`, pinned in the native storage binding,
management profile, request validation, WebAuthn RP ID and sessions. Adding a
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
5. **No weaker recovery.** Origin addition, credential addition, origin changes,
   revocation and recovery cannot be weaker than existing administrator and
   hardware policy. An ordinary credential cannot introduce a bypass when any
   protected administrator action requires hardware. Prevent accidentally
   removing the last usable administrator route, or require the explicitly
   designed independent recovery path.
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

## Required verification before use

- Synthetic end-to-end test: initialize existing primary-only vault, add backup,
  enroll and test backup credential, sign in at each origin, and recover after
  restart with the same vault contents and primary passkeys intact.
- Reject unexpected hosts, malformed origins, untrusted forwarded host headers,
  cross-origin WebAuthn assertions, reused challenges, cookie/CSRF swapping,
  stale approvals and backup candidate self-approval.
- Test hardware-policy enforcement, origin revocation, last-key protection,
  competing/cancelled enrollment, lost responses, interruption and restart.
- Verify session expiry/revocation independently at both origins and ensure
  backup access cannot revive a revoked primary or revoked backup credential.
- Test actual HTTPS Symcon Connect with real browsers and passkeys, including a
  controlled primary-certificate failure and later primary recovery.
- Independent security audit of the exact completed implementation before
  production; no live certificate failure or production rollout is performed by
  the implementation tests.
