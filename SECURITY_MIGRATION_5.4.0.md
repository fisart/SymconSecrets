# Security migration: WebAuthn portal 5.4.0

Version 5.4.0 replaces the former credential-ID/challenge comparison with
complete server-side WebAuthn registration and assertion verification.

## Safe upgrade order

1. Install version 5.4.0. The WebAuthn portal is disabled by default.
2. Configure PortalOrigin with the exact primary HTTPS origin. The RP ID is
   derived from its hostname.
3. Optionally configure PortalBackupOrigin with a second exact HTTPS origin.
   Include a nonstandard port if one is used. Do not include paths, default
   ports, or trailing slashes.
4. Visit /hook/secrets_INSTANCE-ID?admin=1 and authenticate with the
   AdminPortal/PW password through the form. A passkey portal session cannot
   authorize migration, registration, or other administrator actions.
5. Choose Start verified migration. Touch each existing passkey once. Repeat
   this through the backup URL for credentials registered under that hostname. The
   module extracts its stored public key and upgrades it only after a fresh
   assertion verifies the signature, current challenge, exact origin, RP ID,
   user presence, and user verification. No new credential is registered.
6. Rotate AdminPortal/PW and RegistrationPassword/PW after migration.
7. Enable PortalEnabled and apply the module configuration.
8. Test the login URL and every custom webhook that calls
   SEC_IsPortalAuthenticated().

Repeat the verified migration separately on every configured origin/RP ID. The existing
master-to-slave preservation of the local __AUTH__ area remains in place.

Portal origins are user-configurable and are never hardcoded. One primary
origin is required; the backup origin is optional. Requests whose Host header
does not exactly match a configured origin are rejected before any ceremony.
Primary and backup URLs are deliberately separate WebAuthn relying parties;
each must use the exact public HTTPS origin shown in the browser.

Disabling the portal, selecting Revoke portal sessions, deleting a passkey, or
removing all passkeys also invalidates relevant pending ceremonies. Challenges
are one-time, short-lived, user-agent-bound, generation-bound, and stored in a
bounded in-memory set. Authentication attempts are limited per client and per
configured origin and operation without creating unbounded state. Traffic on
the primary URL cannot consume the backup URL's rate-limit capacity.

If a revocation must be retried because portal state is busy, new portal
sessions and credential changes fail closed. Ordinary vault reads remain
available to runtime integrations. An AdminPortal/PW login also retains the
optional password fallback for portal-protected pages on the same origin.
Password authorization captures the current revocation generation before
verification and may commit a session or registration ceremony only in that
same generation. Session validation rechecks pending revocation after taking
the portal-state lock. Passkey sessions are also bound to the exact live local
credential record; deleting or modifying it through any vault editing path
invalidates the session on its next use.

Use Remove all passkeys only if you intentionally want a clean reset. Use the
registration page only when adding a genuinely new device.

## Compatibility

Legacy passkey records cannot authenticate normal portal sessions. They are
accepted only by the admin-authenticated migration route, and only after a
fresh cryptographically valid assertion. Successful migration updates the
existing record to schemaVersion 2 with a verified credentialPublicKey. The
original legacy credentialId encoding and attestation are retained in that
same record solely so the unchanged rollback branch can still use the passkey;
the secure verifier uses credentialIdV2. Newly registered 5.4.0 credentials
also store the padded legacy encoding, so their credential data remains
readable after a code rollback. A damaged record whose attestation
cannot be parsed cannot be migrated and remains unusable. Alarm runtime, vault
read APIs, scoped write APIs, local secret backup/restore, and master/slave
synchronization are unchanged.

## Rollback

The reviewed remediation is developed on security/webauthn-hardening-v2 on top
of security/webauthn-verification. Returning the
IP-Symcon module to mit-grafischem-Editor restores the previous code. Do not
re-enable internet access to the old portal after rollback because its
authentication bypass remains present. Existing legacy passkeys continue to
work after rollback, including passkeys already migrated by 5.4.0, because the
migration retains the old credentialId and attestation fields unchanged. New
credentials created on the hardened branch use a dual encoding for the same
credential ID and retain the legacy attestation field as well. This
compatibility does not make the rolled-back verifier safe: the old endpoint's
signature-verification bypass becomes reachable again as soon as that code is
restored and exposed.
