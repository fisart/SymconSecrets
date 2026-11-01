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

1. Update the development branch and use the separate SecretsFrontend. A unique
   eligible backend is selected automatically; if none exists, setup proposes one.
2. In the console, choose **Open setup / administration**. Enter the trusted HTTPS
   origin only if unknown. Verify private/persistent setup storage only when the
   supplied platform cannot establish it. The complete link is displayed without
   any code or other authorization in its URL.
3. In the browser choose **Prepare first passkey**. For a recent interrupted
   preparation, **Use an already prepared passkey** proves possession again.
4. Refresh the console request list, compare all four identifier groups against
   the browser and approve that exact request. No candidate is selected by arrival
   order or automatically trusted because it is the only one.
5. Review the detected defaults. Change optional settings only when needed;
   confirm any unresolved vault persistence/Windows ACL condition.
6. Choose **Set up and sign in** and confirm the exact plan with your prepared
   passkey. Its administrator entry, initial audit and operation outcome publish
   in the first usable encrypted state, before activation and session creation.
7. Test with invented secrets. After a lost completion reply, resolve the accepted
   operation in the console and use normal passkey sign-in; never start a second
   setup to replace an uncertain operation.

The [code-free implementation contract](BOOTSTRAP_IMPLEMENTATION.md) documents
nonce recovery, cancellation/restart, automatic backend creation and test limits.
Additional keys are prepared before an existing administrator approves the exact
credential. Independent console recovery uses a replacement candidate and preserves
current data/policy. Ordinary-key recovery is blocked under an active hardware
policy until a separate hardware-recovery procedure is qualified. No manual-code
setup or administrator-enrollment fallback remains in native mode.

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
