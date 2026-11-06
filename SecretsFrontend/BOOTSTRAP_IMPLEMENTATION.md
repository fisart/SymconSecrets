# Code-free setup implementation

Date: 1 November 2026 (Europe/Rome). Development branch only.
Design reference: approved code-free setup draft v1.2; previous code baseline 43726e1.

## User flow

1. Open setup from the trusted Symcon console. A known HTTPS origin is reused;
   an unknown origin is entered once. The URL contains no setup authority.
2. Prepare the first passkey in the browser. The page also creates a separate
   non-exportable, memory-only P-256 browser key. No manual code is generated.
3. Refresh the console request list, compare all four identifier groups, and
   approve the exact frozen candidate. Approval is never automatic.
4. Review detected defaults and choose Set up and sign in. A fresh passkey
   assertion authorizes that exact plan and the initial login. The first usable
   encrypted vault state already contains the approved administrator, audit,
   initialization UUID, admission and operation outcome.

A recent prepared passkey can be reused after page loss using a new possession
proof, browser key and console approval. Its encrypted public registration record
confers no rights. This does not import an existing production passkey or vault.

## Authority and transport

`Bootstrap.php` owns the bounded volatile console/candidate state machine.
`BootstrapVerifier.php` is shared by frontend and backend for strict JWK/PoP,
registration and assertion verification. Original clientDataJSON bytes are passed
unchanged to WebAuthn. Cross-origin/top-origin ceremonies are rejected.

All Bootstrap actions are POST-only behind the normal exact-origin JSON gate.
GET/HEAD serve only the unprivileged page; method-override headers and other
methods do not dispatch. No hook exposes console methods or a generic PHP RPC.
Requests bind the fixed origin/path, frontend UUID, intent, candidate and browser
key digests, epoch, UUID, nonce, operation, action and exact decoded body digest.
Duplicate JSON fields, noncanonical encodings, unknown fields and invalid P-256
points/scalars are rejected. The browser signature is exactly 64-byte r||s;
WebAuthn uses its own original signature encoding.

A frontend/origin-specific Secure/HttpOnly/SameSite=Strict cookie and CSRF value
are also required. Invalid proofs do not consume live nonces. A successful normal
request rotates its nonce. Request replay never reissues a nonce or secret result.
The stateless MAC-bound resume challenge cannot invalidate a live request;
only a valid proof by the bound browser key can increment the transport epoch.
The browser serializes signed requests and pauses polling when hidden. A native
passkey dialog's temporary focus loss does not discard its key.

Console button payloads embed literal candidate/digest/view-proof snapshots.
New rows, sorting and other consoles cannot change those server bindings. The
actual Symcon 9.0 dialog behavior still requires live acceptance testing.

## Durable initial decision and completion

`BootstrapJournal.php` uses separate private setup-data and setup-key directories
under the dedicated native storage roots. Every immutable decision/progress record
is AES-256-GCM encrypted with name/domain binding. File and supported directory
sync/readback precede positive acknowledgement. The journal key is not regenerated
if records or interrupted publication files exist. Capacity is bounded; authority
records/tombstones are not automatically deleted to create space.

Initial ACCEPTED and CANCELLED compete for the same immutable decision name under
the shared file lock. Acceptance is bound to the original passkey evidence, exact
plan/digests, origin/frontend, stable operation and planned vault UUID. Once accepted,
ordinary cancellation cannot promise to stop it. A failed/uncertain publication
returns no success; unresolved temporary files block competing decisions.

Completion uses durable worker generations separate from browser transport epochs.
The backend independently reads the accepted record, rechecks the target, security
foundation and final WebAuthn evidence, and validates the worker immediately before
native publication under the same journal lock. Frontend reload invalidation also
uses this lock. Frontend calls release that lock before invoking a backend that
acquires it: no cross-module PHP-context lock reentrancy is assumed.

After restart the recovery timer resumes only the exact accepted operation.
Corrupt records, missing keys, changed trust, conflicting plans or unsupported
old empty genesis states lock recovery. No empty activated vault or first-admin
code window exists. The native first snapshot requires a verified genesis admission;
there is no production/test flag to skip it. Tests supply explicit synthetic
cryptographic admissions.

With no eligible backend, setup proposes one new instance and UUID-based paths.
A creating record precedes object creation; its resulting ID is recorded separately.
A lost object-create acknowledgement stays UNKNOWN and cannot create another object.
Only an explicit console selection of the inspected disabled empty instance resolves
that gap. Backend activation follows the complete admitted vault commit.

The successful original completion can issue one normal session after current
rights checks. A durable one-use login reservation prevents replay of its response.
Status/resume routes never return a previous session/CSRF cookie. After a lost login
reply, use normal passkey login to the already-created vault.

## Additional keys and recovery

Additional keys are prepared in an authenticated session with a separate browser
possession proof. An existing administrator approves the exact credential/candidate
and browser-key digest with a fresh eligible passkey. The identity commit checks
the current state and policy and invalidates existing sessions. Hardware candidates
must satisfy the reviewed root/model/backup rules. A candidate cannot approve itself.

Independent recovery is explicitly opened in the console, uses the same visual
candidate comparison, and is bound to the current vault/head/policy. It adds only
the approved replacement key; it does not reset secrets or hardware trust. This
mode's authority is checked at the native identity commit, not carried across a
stale initial ACCEPTED record. Ordinary-key recovery is blocked whenever a hardware
policy is active: an independent hardware-recovery procedure must first be specified
and qualified. No manual-code fallback exists.

Cached code-based frontend requests and native local initialization/enrollment
methods reject without creating authority. Historical V1 backend tests/components
remain separate; the original SecretsManager and all 33 original blobs are unchanged.

## Evidence and remaining gates

- 77 Bootstrap integration/adversarial assertions, including actual encrypted files,
  real cryptographic test passkeys, two-process decision contention, I/O exceptions,
  cancellation, resume, exact console payloads, reuse, restart, recovery, automatic
  object creation and lost creation acknowledgement.
- 52 native-storage assertions, including interrupted first genesis publication
  before/after every existing frame/marker checkpoint, exact admission replay,
  correlated first audit/outcome, missing-key and highest-state corruption.
- Existing native lifecycle, 84 peer checks and 22 external-effect checks.
- Rendered DOM tests of actual bundled assets, real WebCrypto signatures verified
  independently with PHP/OpenSSL, late-response cleanup and normal administration.

These counts are not a claim that every design T01–T64 scenario has been executed.
Independent exact-commit security review remains pending. Actual Symcon 9.0 dialogs,
real browsers and physical authenticators, multi-host operation, Windows ACLs,
Docker replacement, public TLS/listener isolation and physical power-loss testing
remain NOT_RUN here. Uncertain journal files deliberately fail closed and require
operator inspection; automatic authority-history archival is not provided.

No merge, installation, pairing, production activation or old-vault migration is
performed by this implementation. Standalone full-state rollback and compromised
Symcon/browser limitations remain unchanged.
