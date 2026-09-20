# Security migration: WebAuthn portal 5.4.0

Version 5.4.0 replaces the former credential-ID/challenge comparison with
complete server-side WebAuthn registration and assertion verification.

## Safe upgrade order

1. Install version 5.4.0. The WebAuthn portal is disabled by default.
2. Configure PortalRpId with the DNS name used by the passkey.
3. Configure PortalOrigin with the exact HTTPS origin, including a nonstandard
   port if one is used. Do not include a path or trailing slash.
4. Visit /hook/secrets_INSTANCE-ID?admin=1 and authenticate with the
   AdminPortal/PW password through the form.
5. Choose Start verified migration. Touch each existing passkey once. The
   module extracts its stored public key and upgrades it only after a fresh
   assertion verifies the signature, current challenge, exact origin, RP ID,
   user presence, and user verification. No new credential is registered.
6. Rotate AdminPortal/PW and RegistrationPassword/PW after migration.
7. Enable PortalEnabled and apply the module configuration.
8. Test the login URL and every custom webhook that calls
   SEC_IsPortalAuthenticated().

Repeat the verified migration separately on every host/RP ID. The existing
master-to-slave preservation of the local __AUTH__ area remains in place.

Use Remove all passkeys only if you intentionally want a clean reset. Use the
registration page only when adding a genuinely new device.

## Compatibility

Legacy passkey records cannot authenticate normal portal sessions. They are
accepted only by the admin-authenticated migration route, and only after a
fresh cryptographically valid assertion. Successful migration updates the
existing record to schemaVersion 2 with a verified credentialPublicKey. A
damaged record whose attestation cannot be parsed cannot be migrated and
remains unusable. Alarm runtime, vault read APIs, scoped write APIs, local
secret backup/restore, and master/slave synchronization are unchanged.

## Rollback

The remediation is developed on security/webauthn-verification. Returning the
IP-Symcon module to mit-grafischem-Editor restores the previous code. Do not
re-enable internet access to the old portal after rollback because its
authentication bypass remains present.
