# DC-01 v1.2 implementation checkpoint

This directory starts the implementation of the independently accepted DC-01
peer/quorum design. It is a **component checkpoint for implementation review**,
not a finished gateway, a complete Symcon quorum backend, or production approval.
There is no network listener or executable deployment entry point in this
checkpoint. None of these internal Go APIs is a generic remote write API.

The existing development Symcon backend still uses its V1 witness/store. It does
not silently adopt this V2 authority or claim quorum protection. The old password
module and every original repository blob remain unchanged.

## Immutable review baseline

- Design: DC-01 v1.2, independently accepted for focused findings R1-R3.
- Normative profile: `protocol/profile.json`, copied byte-for-byte from the
  accepted artifact, SHA-256
  `d406bb26320866f390b4d2222f6307516ff0edadcdd2ef166277f9ec739176fc`.
- Implementation parent: `3c5d111bbeff1055b591731f726362dc2387e619`.
- Compiler: Go 1.26.10. Official etcd client and test members: v3.7.3.
  `go.mod`/`go.sum` lock transitive dependencies. Go module verification is required.
- Original A01-A07 fixes still need independent review. Component tests do not
  independently establish physical-key enforcement or close those findings.

## Implemented and exercised

| Component | Behavior |
| --- | --- |
| Go closed protocol codec | Profile integrity, duplicate-key rejection, ASCII/string-valued metadata, size/depth/array limits, tagged types, canonical signatures, action and response binding, success/rejection/status consistency |
| PHP V2 codec | Same pinned profile and signed fixtures; independent gateway/native-lineage pin checks; preserves empty-object/empty-array distinctions; no V1 fallback or runtime activation |
| etcd transaction primitives | Linearizable reads, native-lineage checks, exact predecessor/value/lease comparisons, immutable operation outcomes, stable status lookup, final stale-worker fencing |
| Application coordinator primitive | Non-leased durable epoch, lease-bound role, atomic election, exact current node binding; losing the coordinator role does not revoke ordinary peer role |
| Private durable storage | 0700 directories, 0600 regular files, root-relative paths, cross-process locks, fsync-before-acknowledgement, immutable content and directory persistence |
| Admission consumption journal | Pinned independent signer/context verification, component/boot/volume/generation/trust binding and durable monotonic consumption; a retry resolves history rather than creating another boot |
| Recovery journal | Pre-pinned recovery signer, actual evidence-digest checks, mandatory independent fencing/approval callbacks, PREPARED/locked state, conditional durable trust-floor advancement and idempotent lost-ack recovery |
| Committed archive recovery | Current-reference/generation/deletion comparisons, complete opaque bundle/manifest/object coverage checks, durable pins, separately signed first-copy re-attestation without source receipts, classified inventory activation and per-bundle copy health |

Tests use actual three-member etcd clusters in separately killable processes.
They kill the observed Raft leader, test one surviving majority versus a minority,
and restart members from intact durable directories. Archive worker and recovery
journal processes are also killed around durable-write/acknowledgement boundaries.
Other tests pause workers between validation and their final transaction, change
policy or runtime generation, and then resume them. These are component tests;
the Symcon management routes and an independently managed host guard are not
connected to this authority yet.

The V2 bundle framing has a bounded public coverage index, an already encrypted
manifest and already encrypted object bodies. Both the full bundle and the
complete index are digest-bound to the authority record. Archive code receives
no vault decryption key. This implementation format requires review with the
future V2 PHP packer; it is not an import path for the V1 store.

## Explicit unfinished work and gates

IR-01--IR-03, G-01 and follow-up FR-01--FR-02 corrections are described in
[`../../SecretsFrontend/IMPLEMENTATION_REVIEW_FIXES.md`](../../SecretsFrontend/IMPLEMENTATION_REVIEW_FIXES.md).
They require independent re-review at the replacement commit. The frozen example
with a null rejection epoch for a coordinator-bound reservation is retained as
a negative test; `tests/response-bindings.json` contains its signed correction.

1. Restricted HTTPS/mTLS gateway/archive transport, service admission, boot
   registration issuance and complete dispatch of the 24 accepted operations.
   Internal `Guard`, `Snapshot`, provisioning and write methods must never be
   exposed to callers as request-controlled authority.
2. Full user/session/credential validation, challenges, one-use approvals and
   hardware policy connected to quorum. `Guarded` tests final CAS fencing; it is
   not a complete passkey authorization endpoint.
3. Core reservation/READY/commit/abort protocol, outbox-in-commit behavior,
   retention/deletion/repair tickets and all late-retry interleavings. Existing
   committed-copy recovery tests do not test new vault commits or authorize GC.
4. Symcon V2 store/client lifecycle and the storage wizard, peer key envelopes,
   local-only owner proposals, replacement/restore tooling and Portal integration
   through the new runtime. Existing V1 frontend features are not V2 acceptance.
5. Synchronization, OAuth uncertainty, backup/restore and the one tested migration.
6. Real independent host admission/fencing infrastructure and signer issuance/
   rotation/revocation/recovery. Journal callbacks must validate real independent
   evidence. A callback returning success without that evidence is not permitted
   in deployment. No unique physical original host may hold the only recovery key.
7. Production TLS/proxies, real Symcon/browsers/physical keys, power-loss and storage
   controller/flush qualification, true independent domains and WAN performance.

This checkpoint intentionally fails activation above **15 retained bundles per
archive** and caps transaction operations. Complete paginated inventory support
is unfinished; it never accepts a partial scan as complete. Operation evidence is
retained without GC. The production capacity/retention gates remain blocked.
An ACTIVE archive can honestly have missing/quarantined copies. New core writers
must enforce derived two-copy health; those writers are not implemented here.

Archive `Boot` now requires an opaque runtime capability created only after
signed independent admission consumption and an explicit volume verifier. It
verifies the installed admission under the same independently pinned guard and
requires a strictly increasing admission counter in the same transaction that
installs the new registration. Completed exact retries resolve as history without
reinstalling a generation. Ordinary Boot cannot reset a counter by changing a
guard/trust identity. `Open` binds
that capability to one opened directory and a monotonic durable local marker;
no service derives its local generation from the latest catalog registration.
Re-attestation and activation compare that admitted identity before work and at
their final authority transaction. Unit fixtures use synthetic guard inventories;
they do not demonstrate real platform attestation. Runtime admission and TLS identity must prevent an endpoint/client
from silently changing native etcd lineage after its initial verification.

All formal **Q01-Q48 remain NOT_RUN end to end**. Targeted component evidence is
useful input to those scenarios, not a claim that their complete required results
have been established. Baseline/hardware suites remain required. A SIGKILL is not
a physical power-loss test, and test loopback plaintext is not production TLS.

## Reproduce

```sh
cd SecretsBackend/quorum
go mod verify
go vet ./...
go test -race -count=1 -timeout=5m -json ./... > quorum-tests.json
python tests/io_faults.py --output ir-io-tests.json
python tests/summarize.py quorum-tests.json quorum-evidence.json ir-io-tests.json
cd ../..
php SecretsBackend/tests/quorum-protocol.php
php SecretsBackend/tests/ir-runtime.php
php SecretsBackend/tests/ir-response-bindings.php
python SecretsFrontend/tests/structure.py
```

The development workflow records the tested GitHub commit, profile hash, compiler,
test outcomes, source hashes and explicit end-to-end limitations in its retained
`quorum-component-evidence` artifact. No merge, deployment or production migration
is part of this checkpoint.
