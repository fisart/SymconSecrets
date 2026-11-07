> Historical design, review or incident record. Current operation and implemented behavior: [OPERATING_GUIDE.md](OPERATING_GUIDE.md) and [RELEASE_STATUS.md](RELEASE_STATUS.md). This record is retained as evidence and does not override the current native-only replacement.

# HTML design and V2 integration components

Development parent: `240c9a72265068d8eb192040df0c721905d41646`.
This checkpoint adds implementation; it is not covered by the earlier component
review closures and requires review of its exact replacement commit.

## Available in Symcon

The HTML interface has a new responsive layout: a dark green navigation area,
light cards, clearer typography, consistent spacing, larger controls, light/dark
appearance, a five-stage progress indicator, completed-stage markers, keyboard
focus on step changes and collapsed advanced settings. It remains self-contained,
with nonce-protected CSS/JavaScript, no external fonts/scripts and no persistent
browser credential storage.

The existing console-authorized configuration wizard now also prepares a peer
placement draft. It reuses saved valid choices and otherwise proposes exactly
three authority locations, two Symcon peers and two offline recovery locations.
The local peer reuses the console-pinned HTTPS origin. Names have defaults;
unknown endpoints, failure domains and recovery locations remain explicitly
unconfigured. The UI supplies no invented trust values.

The server validates the complete draft at review and again before consuming
setup authority. Unknown fields, embedded URL credentials, non-HTTPS origins,
paths/queries, duplicate endpoints and a changed local origin are rejected.
Missing or repeated location labels become preparation tasks. Distinct labels
are explicitly not proof of independent failure domains. Even a complete draft
always has `DRAFT_NOT_ADMITTED` and `activationAllowed=false`.

The reviewed draft is included in the combined settings download and can also
be downloaded separately. Native frontend exports containing placement choices
use `SECF.Config.v2`, with exactly `schema`, `configuration` and `deploymentDraft`.
The old `SECF.Config.v1` remains accepted for settings without a draft. Import
preserves placement through the native importer, remains disabled and forces
V2-only mode for a v2 draft; it cannot restore an active runtime, setup grant or
trusted host. The proposed central-backup contract is updated, but its adapter
registration remains inactive. No other repository is changed.

These are configuration and planning functions. Saving a draft does not install
etcd, issue certificates, admit hosts, create a vault, generate administrator
credentials or initialize the quorum runtime. The wizard still ends with
connection pending. The existing V1 development path is not a substitute.

## New internal V2 components

`SecretsBackend/QuorumBundle.php` adds:

- PHP framing and strict reading of the existing Go archive `SYMCB2` bundle
  format, with descriptor, coverage-index, manifest and object digest/length
  checks, duplicate-object refusal, no trailing bytes, bounded memory inputs and
  a 64 MiB bundle limit. Empty reservation IDs are omitted to match Go's
  canonical struct serialization.
- AES-128-GCM object encryption/decryption, with authenticated context binding
  realm/cluster/incarnation, scope/owner, key generation/key ID, object ID,
  protected root kind and schema. Secret JSON is kept as plaintext bytes inside
  encryption, preserving Unicode, empty object/list and number distinctions.
- Standard libsodium sealed boxes for approved peer and offline-recovery key
  recipients. A local scope refuses a peer recipient other than its logical
  owner; an explicit recovery recipient remains possible. A scoped authenticated
  test object verifies that the recovered key is correct.

The sealed-key record and envelope descriptor are **new concrete implementation
contracts requiring review**. They do not change `protocol/profile.json`.
Context fields are closed:
`version`, `clusterId`, `realmId`, `incarnation`, `scopeId`, `scopeKind`,
`ownerNodeId`, `generation`, `keyId`, `algorithm`. Version is `1`; the data cipher
is `AES-128-GCM`; GLOBAL has a null owner; LOCAL requires its owner UUID.
A recipient has exactly `id`, `kind` (`PEER` or `RECOVERY`) and X25519 `publicKey`.
The sealed plaintext record has `version`, `context`, `recipient`,
`keyTestDigest`, `key` (base64url 16-byte data key). Its public descriptor has
`version`, `context`, `recipient`, `keyTestDigest`, `digest`, `length`; it contains
no unwrapped data key. Object AAD uses
`SymconSecrets/DC01/Object/v1` + NUL + canonical `{context,object}`. The key-test
AAD uses `SymconSecrets/DC01/ScopeKeyTest/v1` + NUL + canonical context; its fixed
plaintext is `SymconSecrets/DC01/ScopeKeyTest/v1`.

Sealed boxes do not authenticate their sender. A caller must independently
verify the current authority-approved context, recipient, descriptor and test
object before unwrapping. These methods do not establish current membership,
obtain approval, grant decryption access or authorize a plaintext diff. They are
not exposed as browser routes. The complete encrypted manifest/packer, review
semantics and durable production key storage are still required. Temporary
serialized key records are cleared on exit where PHP/libsodium allows; this is
not a promise to erase every interpreter/OS copy.

`SecretsBackend/QuorumIntent.php` implements the existing Go
`CoreUserIntent/v1` digest and signed wrapper in PHP. It reproduces the frozen
Go/Python public intent vector, validates closed fields and the same human
GLOBAL_EDIT/LOCAL_EDIT scope, predecessor, revision and bundle constraints, and
binds approval and enrolled owner key identity. This is a node signature, not a
WebAuthn approval. It cannot issue approvals or turn caller booleans into facts.
The original-user contract is still an internal record, not an unreviewed new
operation inside the frozen wire Request/Decision union.

## Executed checks

- 196 Go test/subtest pass events under the race detector; 23 injected-I/O pass
  events. These include the existing core crash/fencing/admission regressions
  and the new PHP/Go exact bundle reconstruction check.
- All 25 PHP/Python/Node commands passed. New checks include 33 bundle/key-envelope
  checks, 15 original-intent checks and 16 deployment validation checks, plus the
  server/DOM commissioning tests for preservation, source drift, exact review,
  draft export/import, V2-only disabled restore and no authority creation.
- All original 33 repository blobs and the accepted protocol profile remain
  unchanged. New PHP lint and the existing structural checks passed.
- Static desktop and mobile layout inspection is narrower than browser
  qualification. A real browser preview could not be opened in this environment;
  neither screenshot-style static rendering nor DOM simulation establishes
  Safari/Chrome/mobile compatibility.

Counts are test/subtest events, not accepted end-to-end requirements. The new
fixtures contain deliberately public synthetic keys/data, clearly labeled as
such; no production key or secret is included.

## Outstanding work

The user's complete outstanding-feature request remains open. This checkpoint
advances the UI, placement planning and two integration components; it does not
claim to finish the system. Required remaining implementation includes:

1. Restricted authenticated V2 gateway/archive services, reviewed original-user
   wire mapping and a connected Symcon runtime/client lifecycle.
2. Complete encrypted manifests/packing and permitted-diff verification; real
   WebAuthn/session/hardware facts connected to quorum, and initialization plus
   administrator enrollment through the wizard.
3. Independent host-guard admission issuance, TLS/trust provisioning, service
   installation, boot/volume checks, positive fencing and host replacement.
4. Machine/security/counter operations, filtered peer synchronization, delivery
   grants/nonces/receipts and external OAuth effects.
5. Production encrypted backup/restore, retention/GC/repair, recovery orchestration
   and reviewed migration tooling.
6. Independent review and real Symcon, physical-key, browser, deployment and
   failure qualification. All Q01–Q48 remain NOT_RUN end to end.

No merge, production deployment, migration or automatic adoption of the old
password vault is performed. The existing SecretsManager remains unchanged.
