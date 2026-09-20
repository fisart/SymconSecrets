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
   AdminPortal/PW password through the form.
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

Use Remove all passkeys only if you intentionally want a clean reset. Use the
registration page only when adding a genuinely new device.

## Compatibility

Legacy passkey records cannot authenticate normal portal sessions. They are
accepted only by the admin-authenticated migration route, and only after a
fresh cryptographically valid assertion. Successful migration updates the
existing record to schemaVersion 2 with a verified credentialPublicKey. The
original legacy credentialId encoding and attestation are retained in that
same record solely so the unchanged rollback branch can still use the passkey;
the secure verifier uses credentialIdV2. A damaged record whose attestation
cannot be parsed cannot be migrated and remains unusable. Alarm runtime, vault
read APIs, scoped write APIs, local secret backup/restore, and master/slave
synchronization are unchanged.

## Rollback

The remediation is developed on security/webauthn-verification. Returning the
IP-Symcon module to mit-grafischem-Editor restores the previous code. Do not
re-enable internet access to the old portal after rollback because its
authentication bypass remains present. Existing legacy passkeys continue to
work after rollback, including passkeys already migrated by 5.4.0, because the
migration retains the old credentialId and attestation fields unchanged. This
compatibility does not make the rolled-back verifier safe.
