# Response to the independent audit of 154d575

Date: 31 October 2026 (Europe/Rome).

Reviewed baseline: `154d575e26507bac175943bb617764bb6b910bc9`.
Status: source corrections and local regression evidence; independent re-review pending.
No merge, migration, production settings change or deployment is included.

## C-01: canonical storage separation

The shared `SecretsBackend/StoragePaths.php` validator now normalizes repeated
separators and trailing slashes, resolves the nearest existing ancestor for new
destinations, rejects dot components, files and symbolic-link components, and
compares canonical component boundaries. Equal vault/key destinations, either
direction of nesting, root storage and aliases inside the Symcon kernel are
refused. Sibling names remain distinct.

The frontend review and the backend's applied-settings validation share this
validator. Backend storage initialization rechecks the paths immediately before
creation. An ancestor changed to a symlink after review therefore causes refusal
at apply or initialization rather than creating keys/state there. This is the
existing POSIX storage profile, not qualification of Windows ACLs, bind mounts or
hostile concurrent filesystem administrators.

Reproductions: `php -n SecretsFrontend/tests/storage-paths.php` performs 22
checks without loading PHP extensions. `php SecretsFrontend/tests/guided-setup.php`
also runs `storage-paths-guided.php`: rejected plans preserve settings, valid
separate siblings are saved canonically with the backend disabled, and symlink
substitution before apply/creation leaves key/state files absent. The exact
equal-alias case failed against the reviewed baseline before this correction.

## C-02: surviving archive copies

This corrects the retained Go prototype. It does not add Go, etcd or an external
service to the planned Symcon-native runtime.

READY and commit now count valid, current, authenticated receipts from distinct
failure domains. An optional stale, forged, malformed or incorrectly bound
receipt is retained as non-live historical evidence rather than vetoing two
surviving valid copies. Commit accepts only a surviving subset of the exact
receipts approved at READY: replacements, expansions, changed digests and duplicate
archive IDs are refused. Only the selected current receipts become committed
archive evidence. The atomic audit records both READY and committed receipt refs.

Membership, incarnation, authorization, predecessor-copy, inventory, deletion and
final atomic read-set comparisons remain enforced. A restart between verification
and the final comparison still refuses publication. History is not rewritten to
pretend the restarted archive currently holds a valid copy.

`SecretsBackend/quorum/core/copy_availability_test.go` covers the auditor's third
archive restart before READY and after READY, zero/one surviving copies, forged
and wrong-archive receipts, same-domain copies, changed/duplicate/expanded refs,
and a restart during the final commit. Both positive cases reproduced the original
failure against the reviewed baseline, then passed with the correction.

## TLS boundary remains unverified

Authorized direct plaintext API requests are accepted by the current adapter.
Browser HTTPS/secure-context checks, pinned Origin/Host checks and CSP do not prove
network encryption to PHP. No source correction here claims otherwise.

The earlier WebServer-caller/TLS-flag check rejected the user's valid Symcon
endpoint and is not restored. Deployment approval requires testing the actual
public HTTPS listener and any relay/proxy/backend hop: untrusted clients must not
reach an authorized plaintext listener; headers alone cannot establish that fact.
These deployment checks are **NOT_RUN** because the real installation is not
accessible in this environment. Passing local component checks does not close
this deployment finding.

## Native replacement: B-01/B-02/B-03

See [NATIVE_PROTOCOL.md](NATIVE_PROTOCOL.md), a review draft, **not an implemented
backend**. It specifies a complete encrypted snapshot/commit journal, recovery and
unknown outcomes, stable vault UUIDs, per-tree ownership and membership epochs,
authenticated ordered/idempotent delivery, rejoin, explicit owner transfer and
bounded retention. Runtime dependencies must be supplied by Symcon/PHP; PDO,
SQLite, external Go/Python processes and etcd are excluded from native mode.

Standalone is the default; two, three and larger sets are optional pairings,
including multiple logical vaults on one host. Consistent full-state rollback
detection in standalone operation is explicitly unavailable without an independent
current reference. Native persistence durability, synchronization, route retirement
and actual activation still require implementation and qualification. These design
findings remain open for independent review.

## Local evidence

| Check | Result |
| --- | --- |
| Go race tests | 210 passing test/subtest events across the component packages |
| Injected file/rename/directory I/O tests | 23 passing test/subtest events |
| PHP/Python/Node regression commands | 27 passed, including the new extension-free path command |
| PHP syntax checks | Passed |
| `go vet ./...` and `go mod verify` | Passed |
| Original 33 repository blobs | Unchanged; structural check passed |
| GitHub CI PHP matrix | 8.2, 8.4 and newly added 8.5; correction-head run required |
| Actual embedded Symcon PHP 8.5.12 | NOT_RUN |
| Physical keys, power loss, real listener/relay TLS | NOT_RUN |

The final local race evidence consists of the successful non-core package run,
a complete successful core rerun and the additional zero/one-survivor cases.
The first new core test run had an incorrect test-fixture argument and panicked;
the fixture was corrected before the successful core rerun. No failed run is
counted as passing evidence. CI will run the complete suite together on the
published correction head.

Previously closed findings remain covered by their unchanged regressions. A
passing source test is not independent audit closure or production approval.

The existing SecretsManager, its original files and user settings are unchanged.
