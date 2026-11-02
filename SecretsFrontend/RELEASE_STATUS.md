# Native implementation and release gates

Date: 1 November 2026 (Europe/Rome).

The Symcon-native backend is implemented and locally exercised. This replaces
the earlier settings-only/native-not-implemented checkpoint. Standalone is the
default; two, three, five and larger explicitly paired sets use the same optional
protocol. No external runtime service, database or added PHP extension is required.
No production/migration acceptance is implied. Existing SecretsManager and all
33 original repository blobs remain unchanged.

## Implemented

- Code-free console/browser candidate approval, strict browser PoP and nonce
  recovery, immutable encrypted initial decisions, exact restart completion and
  mandatory first-administrator genesis. Optional backend creation handles UNKNOWN
  object results without repeating creation. See BOOTSTRAP_IMPLEMENTATION.md.
- Automatic instance/capability/path/capacity discovery and reviewed HTML defaults.
- Console administrator recovery is disabled until a native vault exists, with
  initial-setup guidance. Local recovery also rejects uninitialized storage before
  opening it; an existing unreadable vault cannot fall back to initialization.
- Complete encrypted snapshot journal and separate keys; immutable authenticated
  publication marker; injected interruption recovery; runtime/session fencing;
  exact operation outcomes and protected disclosure.
- Masked hierarchy; session-authorized reveal unless hardware policy requires
  a fresh hardware assertion; operation-bound WebAuthn changes, ordinary and
  reviewed hardware credentials, authority-bound additional-key enrollment.
- Bilateral signed/encrypted pairing, ordered immutable outbox, exact receipts,
  lost-response deduplication, catch-up, revocation, ownership freeze/accept and
  explicit forks. Replayed old acceptances cannot reactivate revoked pairings.
- Scoped integration tokens with default read-only access, revision/sequence/UUID
  writes and revocation.
- Complete encrypted portable backup, separate recovery key, authenticated chunks,
  reviewed local-copy/replace-values recovery preserving current authority,
  data-key rotation and verified backup compaction.
- OAuth exact intents, encrypted response capture, predecessor/policy validation,
  unknown-outcome quarantine and bounded declared-idempotent retries.
- HTML administration for those operations, cleared one-use outputs, lost-result
  lookup and re-login after credential changes.

## Local evidence

The development PHP is 8.3. Native checks run with no PDO/SQLite and a 32 MiB memory
limit using actual temporary encrypted files and real cryptographic WebAuthn test
assertions (not physical keys). Native test groups cover:

| Group | Evidence |
| --- | --- |
| bootstrap-security.php | 83 console/candidate/PoP/resume/cancel/restart/reuse/recovery/object/I/O checks |
| native-store.php | 52 persistence/fencing/idempotence/corruption/path checks |
| native-lifecycle.php | Wizard, first/extra WebAuthn credentials, scoped machines, key rotation, backup authentication/compaction/value recovery, stale admission and restart fencing |
| native-peers.php | 84 checks over 1/2/3/5 vaults, bilateral approval, lost replies, transfer, replay/forgery/revocation and aggregate trees larger than 64 KiB |
| native-effects.php | 22 exact-intent/capture/unknown/retry/restart/revocation checks |
| HTML DOM tests | Complete rendered native assets, setup/defaults, exact-origin transport, late-response cleanup, approval, one-use output and additional-key re-login |
| Original-code check | All 33 original blobs unchanged; existing password regressions pass |

The workflow additionally exercises PHP 8.2/8.4/8.5 on Linux and the Windows
file-sync profile. Read the actual commit's Actions results before calling these
CI jobs passed. Their presence in YAML is not executed evidence. Historical
prototype regressions remain separate from native qualification.

## Required before production/migration

1. Independent security audit of the exact native implementation, including the
   changed guarantees and all new privileged routes.
2. Actual Symcon installation/reload/timers with the supplied PHP, multiple real
   hosts, mobile/desktop browsers and physical passkeys/hardware attestations.
3. Actual public HTTPS, alternate/plaintext listener and proxy/relay isolation.
   A configured origin/browser check is not transport-security evidence.
4. Real filesystem/private Windows ACL, Docker persistence across container
   replacement, power interruption and recovery. Exception injection against
   temporary files is not physical power-loss or OS-process-death testing.
5. The separately planned one-time old-vault migration and integration parity.
   No old secret was read, changed, migrated or activated by this implementation.

A consistent rollback of all trusted standalone files remains undetectable without
an independent current reference. Cached disconnected copies do not learn remote
revocation immediately. There is no automatic writer promotion. Recovery imports
reviewed secret values and retains current authority; it does not restore an old
instance's credentials/peer identity automatically.

Earlier audits and closed fixes remain in AUDIT_REMEDIATION.md and
AUDIT_CORRECTIONS_154d575.md. Their Go/SQLite component results do not approve
this new persistence or synchronization implementation.

The CI test-cluster helper reserves all six member ports until startup, avoiding
duplicate voter addresses observed in a historical component test. Native OAuth
intents additionally bind client-secret bytes and the writable global lineage;
active unresolved global effects block ordinary owner transfer.

The code-free v1.2 setup change replaces manual first-admin and recovery codes.
Its real WebCrypto signatures interoperate with PHP/OpenSSL in the DOM tests.
The actual Symcon console and physical authenticators remain unqualified; local
check counts do not represent completion of every T01–T64 design test. Independent
review of this new journal/initializer/request verifier remains required.


Symcon Connect backup access now has a development implementation with automatic
address discovery, a four-step HTML wizard, separate origin/RP-bound passkeys,
restricted enrollment, primary-side fresh exact approval and generation-based
revocation. Synthetic PHP/WebAuthn and browser tests exercise these paths. The
backup HTTP route accepts native HTTPS, an explicitly trusted HTTPS proxy,
or the documented exact-active-Connect loopback profile. The latter trusts local
loopback services and the Connect service; it does not identify the sending
process cryptographically. Untrusted local proxies must not expose that hop. Actual Connect transport, physical-key behavior and primary-
certificate outage remain unqualified. Independent review of the exact completed
implementation is outstanding; the design audit is not production acceptance.

The backup enrollment popup now waits for signed, candidate-bound activation
status before enabling Continue to sign in. Passkey creation/testing alone is
not activation. Continue switches to the normal sign-in screen without reloading
the still-pending enrollment page. The status endpoint discloses only activation
state and creates no general session; expiry, cancellation and origin-generation
changes reject the status proof.


The legacy import wizard reads supported aes-128-gcm encrypted Vault variables
and existing master.key files without executing legacy secret APIs. It previews
masked metadata, merges global/local scopes under an explicit keep/replace
conflict policy and saves source paths plus sanitized inactive replication
proposals. A fresh administrator approval covers the immutable staged snapshot;
the existing hardware policy is enforced. The old source is rechecked and its
vault semaphore held through the native commit. A pre-import encrypted native
backup and separate recovery key are returned, and the committed trees are
verified against keyed expected digests. Legacy passkeys/system credentials do
not become new authority. The old module and its files remain unchanged.

Vault and key locations can independently keep the current folder or use separate
subfolders beneath the imported legacy key folder. Exact selected paths are
approved with the import. An authenticated, locked, crash-resumable handoff copies
and verifies encrypted state, all keys and auxiliary material, fences retained old
copies, and updates the pinned profile, binding and console paths. Occupied or
unsafe destinations fail closed; storage/ACL confirmations apply. See
`LEGACY_IMPORT.md` for protocol, bounds and deployment limitations. Old replication endpoints require
new pairing. Source snapshots are bounded to the native memory budget (at most
512 KiB plaintext); oversized or unsupported data fails before mutation. Static
and simulated tests do not qualify a real production migration.

## Folder editing

Opening a folder keeps that folder selected, including when it has no children.
The existing pencil becomes **Rename folder** and the bin deletes the selected
folder with the usual exact approval; folders can also be selected from their
parent's contents. Rename is one atomic tree mutation, preserving the complete
typed subtree without sending its values to the browser. Name collisions, root
renames and list-position renames are rejected. Global/local and owned shared
trees retain their existing revision, hardware-write, ownership and replication
rules; received and frozen trees stay read-only. After a confirmed rename the
breadcrumb/history follows the new name, and deleting the open folder returns to
its parent. Cancellation leaves navigation unchanged.

## Copy visible secret values

Each revealed value has a **Copy value** clipboard button, in the folder browser
and advanced reveal area. It copies the exact displayed value without another
request or passkey prompt. Hardware reveal policy still governs the initial
disclosure. Copy stays available for revealed read-only values. The control is a
sibling of the record button so copying does not select, open or edit the entry.
If clipboard access is unavailable or denied, the visible text is selected for
the browser's Copy command. Clearing/hiding values, expiry, navigation or sign-out
removes the controls; detached controls cannot copy old values and late clipboard
completion cannot restore cleared UI. Clipboard contents are not automatically
cleared. Browser tests cover exact whitespace/Unicode, copy without network calls,
manual fallback, hardware reveal gating, read-only values, expiry and late replies.

## Console setup address validation

Step 1 previews and validates the trusted HTTPS address before enabling **Open
setup**. Missing schemes, insecure addresses, invalid ports and credentials clear
the preview, disable the action and display an HTTPS example below the field. The
console action revalidates independently of that preview. It outputs either the
exact validated wizard URL or a fixed plain error message, while the form displays
the reason; PHP exceptions and traces are not returned as links. Recovery uses
the same console boundary. Core setup/recovery APIs retain their strict failure
behavior and authorization checks. Rejected address input does not change applied
configuration, acknowledge storage or cancel an existing setup intent.

The buttons use Symcon's documented automatic URL/dialog dispatch with the
`link` override omitted, so success still opens the browser in one click:
https://www.symcon.de/en/service/documentation/developer-area/sdk-tools/sdk-php/configuration-forms/button/
Tests execute the actual form action strings against the native setup fixture,
including bare hostnames, invalid ports, embedded credentials, pending edits,
existing setup state and exact custom-port/instance URLs.

Console setup calls explicitly supply the recovery flag even for first-time setup.
Symcon's generated wrapper requires every parameter despite PHP method defaults.
The console regression wrapper therefore has no optional parameters, and a
dependency-free form audit checks all frontend/backend callback argument counts
against the public module methods plus their instance ID.

## Password generator

The graphical new-secret and change-value editor includes **Generate password**,
**Length** (12–128, default 24), and **Include symbols** (enabled by default).
Passwords always include uppercase/lowercase letters and digits, plus a symbol
when enabled. Browser Web Crypto supplies the randomness; byte rejection avoids
modulo bias and whole-candidate rejection enforces the selected character groups.
Failures are bounded and never fall back to weak randomness. Generation only
fills the masked, unsaved value field; the existing eye reveals/remasks it. Save
still follows the usual exact approval and hardware-write policy. No request,
clipboard write or persistent browser storage occurs while generating. Existing
cancel/navigation/hide cleanup also clears generated drafts. Browser tests cover
new/edit flows, options, rejection sampling, missing/failing random generation,
no requests until review, masking, approval staging and draft cleanup.

## Shared-installation wizard

**Connections** now provides the same numbered six-step wizard on each platform:
**1 · Prepare**, **2 · Invitation**, **3 · Request**, **4 · Approve**,
**5 · Check sharing**, **6 · Ready**. Each screen identifies the current platform,
explains which tab needs the next action, and advances from authenticated progress.
Invitation creation opens the existing timed one-use popup; a matching consumed
invitation closes it so Step 4 is visible. Confirmation popups describe the exact
platform and matching connection code in plain language. Unrelated requests are
not selected automatically. Existing/pending connections can be resumed explicitly.

The wizard requires both current-pairing incoming evidence and a verified outgoing
receipt for the current Global revision, with no pending sharing messages, before
showing Ready. Pairing activation, stale snapshots and receipts from a previous
pairing are insufficient. Read-only progress polling is authenticated/CSRF-checked,
pauses when hidden or approving, stops after completion/15 minutes and does not
extend session inactivity. It never submits or approves another mutation. Stored
receipts now retain their already-verified pairing ID; protocol wire messages and
existing approval/security policies are unchanged. Missing remote HTTPS transport
is explained during preparation. Global sections keep independent editing owners;
Local secrets, passkeys and keys remain local. Ownership transfer is collapsed
under Advanced. The operating guide, console help and `SHARED_INSTALLATION.md` use
the same six names and sequence.

Tests exercise both browser roles, automatic progress, exact invitation/code
binding, cancellation/resume, stale/replaced pairings, hidden/delayed replies and
received-scope navigation. PHP integration fixtures exercise real signed/encrypted
two-vault exchanges, current-pairing receipts, masked HTTP progress and unchanged
session inactivity. Deployment-specific remote TLS and network testing remains
outstanding; standalone rollback limitations and independent review gates remain.

Connection progress now includes fixed, masked delivery diagnostics from the local
retry record: transport category, HTTP/cURL codes, attempt count and retry timing.
No remote response or arbitrary exception text is stored or exposed. Expired
requests use a numbered restart flow, hide the submitted-request button and block
expired approvals. Server time avoids false expiry from a fast browser clock;
manual progress can still observe a previously approved late acceptance. Explicit
removal followed by a new pairing retires the old undelivered revocation notice
on each side, preventing it from blocking the replacement. Tests cover categorized
failures, diagnostic redaction, clock skew, expired/cancelled cleanup and actual
signed/encrypted re-pairing with both old revocations still undelivered.

The connection wizard now prominently separates local passkey approval from
acknowledged delivery. Buttons give immediate inline progress and outcome
feedback, including confirmation/cancellation and unchanged status checks.
**Try delivery now** uses an authenticated, CSRF-checked, primary-origin request,
bound to the peer and current pairing ID, limited to six attempts per peer/minute.
It sends at most one existing immutable approved job and does not create or
approve a new pairing. No arbitrary destination or message is accepted. Background
retry remains unchanged and status polling performs no remote requests. TLS
failures add a fixed certificate-reason enum, numeric verification result and
nullable booleans for configured CA-location readability. No CA path, raw cURL
error or response body is returned. Unknown/native trust sources stay unknown;
absence of a file path is not treated as proof of a missing trust store.

## Initiating-platform connection coordinator

Connections defaults to **Other platform → Connect from here**. A known peer URL
opens that backend's own pinned frontend using a read-only GET/HEAD redirect.
POST peer envelopes and wire formats remain unchanged. The browser coordinates
existing exact passkey approvals via a temporary nonce/origin/window-bound popup
channel. No invitation is copied, persisted or placed in a URL. The other vault
must authenticate its administrator before coordination, and explicitly approve
its request/removal; the initiator explicitly approves invitation creation and
final acceptance. Pending replacements are separately approved on both sides.
Existing public identity changes pause before any removal or approval. Current
pairing/invitation/code checks gate the final acceptance dialog. Remote retry
issues the existing approved immutable request and reports its result centrally.
The popup returns automatically after acknowledged delivery; current signed
bidirectional exchange evidence still gates Ready. Cancellation, page exit,
timeout and stale/foreign popup replies cannot confer authority. The earlier
Magic Connect transport handling and server-side TLS validation remain enforced.
Deployment testing of actual popup/passkey behavior and remote TLS is outstanding.
