# Symcon-native secrets administration

This development branch adds two separate modules, `SecretsFrontend` (SECF) and
`SecretsBackend` (SECB). The existing `SecretsManager` and its SEC APIs are
unchanged. No old vault, passkey or integration is adopted automatically.

The native backend now implements encrypted local storage, passkey administration,
optional peer synchronization, scoped integration access, backups/value recovery,
data-key rotation and OAuth uncertainty handling. It requires only functions in
the supplied Symcon PHP. No SQLite/PDO, database, Go/Python service, shell command
or installed extension is used by the native runtime. Development tools and the
retained historical prototype tests are separate.

See [release status](RELEASE_STATUS.md) for executed checks and acceptance gates.
This is a development implementation awaiting independent audit and real Symcon
qualification, not production/migration approval.

## Initial setup

1. Update `feature/secrets-frontend` in Module Control. Use separate new backend
   and frontend instances. Existing instance selections and a unique eligible
   backend are detected automatically.
2. In SecretsFrontend, enter the trusted HTTPS address normally used for Symcon.
   A saved address is prefilled. The form immediately generates the complete
   clickable wizard URL, including port and its own instance ID, with a copyable
   field. Only a deliberately trusted exact proxy IP may rewrite Host routing.
3. Generate the ten-minute one-use setup code in that form and open the HTML
   wizard. No script, object-ID lookup or external command is needed.
4. Review detected instances, suggested storage locations and capabilities.
   Defaults use separate private per-instance folders inside Symcon's data
   directory, device appearance, Debug off and standalone operation. Keep native
   initialization selected to create the new vault; settings-only remains an
   explicit option. The earlier external-service draft is hidden from this flow.
5. Review the exact plan. If the host cannot establish container persistence or
   a private Windows ACL, confirm or correct that specific condition in the HTML
   wizard. A mount observation does not prove the backup/power-loss properties.
6. Apply the reviewed plan and register the first administrator passkey. The
   initialization authorization is consumed before effects; existing storage is
   never replaced. A lost/expired first registration code can be regenerated in
   the frontend form's administrator enrollment/recovery section.
7. Sign in and test with invented secrets first. Changes and selected-record
   reveal require a fresh passkey approval. Listings stay masked. Configuration
   downloads contain settings only, never vaults, keys or credentials.

The trusted HTTPS origin cannot safely be inferred from an unauthenticated
request header. Available PHP/Symcon functions, storage capacity, instance IDs,
paths and peer descriptors are detected; only unresolved choices are requested.
Default folders are recommendations, never an assertion that a Docker volume is
persisted or privately backed up.

## HTML administration

- **Secrets:** global/local typed records, masked listing, reviewed edits and
  exact-record reveal. Local values are never synchronized. Received shared
  trees show source/freshness and stay read-only on subscribers.
- **Peers:** create a short-lived invitation, approve its exact recipient on the
  issuing vault, inspect immutable pending deliveries and revoke connections.
  Every vault works standalone. One owner writes each shared tree. Optional
  transfer freezes the old owner before the selected new owner accepts. A fork
  creates a different tree identity and never claims to fence a lost old writer.
- **Recovery:** approve an encrypted complete backup and keep the separately
  displayed recovery key apart from it. Recover into a separately initialized
  vault if needed. The default restore creates a local copy; replace-values is
  explicit. Current administrators, rights and peer identities are retained.
  Thus a backup never silently restores old administrative authority.
- **Automation access:** grant one named integration an exact local/global path
  and its descendants. Read-only is the default. Tokens are shown once; writes
  require an expected revision, sequence and stable operation UUID. Revoke grants
  individually. See the backend README for callable APIs.
- **Keys:** approve new credentials and independently reviewed public hardware
  trust roots/AAGUIDs. Ordinary attestation inspection never establishes hardware
  trust. Two eligible hardware credentials must pass real assertion tests before
  hardware-only policy is enabled. Adding a key invalidates previous sessions.
- **OAuth:** choose an HTTPS provider and stored token references. Recognized
  field names are suggested from masked metadata. Manual approved refresh is
  available; automatic refresh requires explicitly confirmed provider idempotency.
  Unknown non-idempotent outcomes are quarantined, not retried automatically.

One-use outputs clear on navigation/page hiding and are never put in URLs,
properties, exports, logs or browser persistent storage. A lost commit response
is resolved by its operation ID; the browser never automatically repeats the
change. A lost secret-bearing output must be regenerated through fresh approval.

## Deployment and recovery limits

HTTPS must be provided by the configured public listener and any relay hops.
The browser enforces secure context/exact origin, and server requests enforce
fixed Host/Origin/schema, authentication and CSRF. These checks do not prove that
an alternate plaintext listener is isolated. Verify the real endpoints.

Every restart invalidates sessions/approvals and checks the committed snapshot.
Corrupt newest state or missing keys lock the vault rather than selecting older
permissions. Standalone cannot detect a consistent restoration of *all* trusted
files without an independent current reference. Directory/file sync does not
certify physical power-loss durability. Windows uses an explicitly labelled
file-sync-only profile and requires private-ACL confirmation.

The earlier external anchor/quorum prototypes remain in repository history and
component tests. They are never a native-mode fallback or runtime requirement.
