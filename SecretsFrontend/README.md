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

Update the development branch and use the separate SecretsFrontend. A unique
eligible backend is selected automatically; if none exists, setup proposes one.

1. In the console, click **Step 1: Open setup**. Enter the trusted HTTPS address
   if requested and confirm private persistent setup storage if asked.
2. In the browser, click **Prepare first passkey** and follow the device prompt.
   Leave the browser open.
3. In the console, click **Step 3: Refresh approval requests**. Compare all four
   identifier groups and click the matching **Step 3: Approve** button. Return
   to the browser; it checks automatically and continues after approval.
4. Review the suggested settings in the browser. Confirm storage persistence or
   permissions if requested, then click **Review setup plan**.
5. Check the summary, click **Set up and sign in**, and confirm with the prepared
   passkey. The vault contains that administrator when it becomes usable.

Test with invented secrets. After a lost completion reply, use **Resolve accepted
setup** in the console; never start a second setup to replace an uncertain operation.

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

- **Secrets:** browse folders on the left and contents on the right. Choose
  **Show folder values** to show direct values beside their names, or select a
  secret and use the eye icon. Click a displayed text value to edit or delete
  it. The eye shows or masks the value being edited.
  Changes and deletion require review and passkey approval. Hide values
  manually or wait 30 seconds. Hardware-protected reveal still requires a key.
  Lists and other typed values remain in the advanced editor. Local values are
  not synchronized and received shared trees are read-only. Each sign-in can
  use a 1, 5 or 15-minute inactivity timeout (maximum session: one hour).
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
