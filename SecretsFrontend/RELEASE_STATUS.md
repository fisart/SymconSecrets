# Development status and release gates

This branch creates the two new modules and their first integrated development implementation. It is **not production-approved**, does not migrate the old vault and does not assert that v1.3's 92 acceptance tests or the 11 hardware-option checks have passed.

The first implementation audit found A01–A07 defects on commit `c0e995d8f355a36c19349e2b56ad223184accf4f`. Corrections and targeted regression tests are now implemented; independent re-review is pending. See the [remediation evidence](AUDIT_REMEDIATION.md). Passing these targeted tests does not close the remaining release gates.

## Implemented and locally exercised

- Typed JSON hierarchy and configuration validation, including duplicate-key rejection.
- New encrypted SQLite core, separate keys and strict initialization refusal for existing/nonempty storage.
- Signed external-anchor client/service, durable decisions, stable acquire retries and local Prepare/advance/Publish recovery.
- New administrator registration/login, fresh bound changes and selected-record reveal; no old Portal/password session reuse.
- One-use volatile-credential storage wizard, two-path review, fixed frontend/backend binding and disabled-on-import settings.
- Exact-head final grant claims; isolated configured-root hardware verification; staged/anchored security configuration; structured encrypted audit context; UI generation cancellation; reload transition locks and request-time recovery scheduling.
- Debug child variables, Portal additional-page registration, a pinned HTTPS browser origin and server-side host/Origin checks. Native/NAT/relay compatibility follows the existing working modules; TLS terminates at the configured public listener. Browser secure-context checks and an exact HTTPS CSP connection target gate credential/API use; PHP transport flags and native WebServer caller metadata are not required. This deployment boundary needs real endpoint verification.

Local tests cover interrupted prepare/publish, lost acquire acknowledgements, stale backups, superseded workers, altered signatures/nonces, real cryptographic WebAuthn assertions, masked listings, selected-record disclosure and replay refusal. PHP/Python tests use the actual message signatures across languages. DOM tests cover credential clearing and wizard requests. These are narrower implementation tests, not a substitute for the full acceptance suite.

## Explicitly outstanding before migration

1. **Real Symcon/runtime verification:** actual module lifecycle, proxy/header behavior, two physical hardware keys, mobile/desktop browsers and attestation trust maintenance. Chromium could not be installed in the authoring environment; DOM tests do not establish visual/browser compatibility.
2. **WAL deployment:** local development SQLite is 3.45.1, so storage tests use an explicit test-only DELETE journal. The production module refuses older WAL runtimes. Power-loss, filesystem/disk durability and the actual supported SQLite build still need the v1.3 tests.
3. **Sync:** global writes prepare immutable per-peer outbox entries inside the encrypted core, but pairing setup, the complete signed wire protocol, authenticated receipts and automatic sending are not exposed/released. No source/recipient pairing is created by default.
4. **OAuth/external effects:** no provider refresh endpoint is exposed. Provider-specific intent/quarantine/recovery behavior remains to be implemented and tested.
5. **Vault backup/migration:** no automatic old-vault import, portable secret export/restore or GC is exposed. An old database that disagrees with the independent anchor remains locked. Consistent production backup, retention/GC and the tested one-time migration remain release gates.
6. **Anchor operations:** independent key renewal/revocation/recovery tooling, cross-deployment sync-grant query permissions, bounded production service operation and physical host crash tests remain incomplete. Provision/read/acquire/advance/authorize/status for one deployment are implemented; do not infer a fully audited production witness from that.
7. **Central integrations:** Dokumentation and backup registration packages are provided without changing their existing module files. Activation and native backup adapters require an explicit scope exception and parity tests.
8. **Security acceptance:** review exact frontend/backend/anchor commits and actual deployment settings against the stable v1.3 concept plus hardware note. Record PASS/FAIL/NOT_RUN/N/A and unresolved findings. Do not treat this file as a security certificate.

The local commissioning/enrollment methods are explicitly independent recovery operations. They are not public browser routes that issue their own authority. Normal web management always needs the new backend's administrator checks. No request is delegated to the old password module's unrestricted APIs.
# DC-01 peer/quorum implementation checkpoint

The accepted DC-01 v1.2 protocol is now pinned in `SecretsBackend/quorum` with Go
and PHP codecs, real-etcd transaction/fencing/election primitives, durable
admission/recovery journals and committed archive re-attestation/activation.
See `SecretsBackend/quorum/README.md` for implemented behavior, component tests
and explicit unfinished work. This does not activate a quorum runtime in Symcon.
The complete Q01-Q48 scenarios and production qualification remain unexecuted.
The existing V1 development implementation and earlier evidence below remain
separate. Earlier A01-A07 fixes still need independent replacement-commit review.


## Independent correction closure — 31 October 2026

The [independent correction review](https://chatgpt.com/library?file_id=libfile_4b429795c00c8191865fa1e16b9793dd&account_id=personal)
reviewed `79c6a0fe5186f687c6b030d0fb46b2ef13c7c67c` and closes FR-01
(archive admission ordering) and FR-02 (operation-aware historical outcomes) for
the tested component behavior. The reviewer independently reran 156 passing Go
test/subtest events, 19 injected-I/O events and 20 regression commands, plus the
additional rejection checks, and confirmed exact-commit CI success. No additional
confirmed defect emerged in the focused review. The earlier scoped IR-01/IR-02
closures and response/runtime binding corrections remain in place.

Development may continue. The next checkpoint is the original-user contract and
core reservation/READY/commit/abort lifecycle described in the quorum README.
The original-user lifecycle and complete V2 integration are still unfinished;
synthetic codec tests do not close them. All Q01-Q48 remain NOT_RUN end to end.
No production or migration approval, merge or deployment follows from this review.

## Internal human core lifecycle implementation

The next component checkpoint adds `SecretsBackend/quorum/core`: an independent
signed original-user record, human secret-change reservation/READY/commit/abort,
actual archive candidate verification/receipts, atomic original outcome/audit/
retention pins/outbox and cancellation tombstones. Tests include paused revocation
races, competing terminal transitions and actual process death. See its README
for the exact contract, limits and evidence. This new behavior requires review.

No V2 management route is enabled. Authorization facts are provisioned in tests;
the real WebAuthn/hardware/diff producer, original-user wire binding, PHP packer,
key envelopes, authenticated dispatch and full runtime remain gates. Frozen
v1.2 wire bytes and the existing password module remain unchanged. All Q01-Q48
remain NOT_RUN end to end; no production or migration approval is implied.

## HTML initial configuration assistant

Routine initial settings now run through one HTML wizard: console authorization,
instance discovery and defaults, storage recommendations, runtime checks, exact
review, reciprocal pairing/preferences, optional Portal registration and a settings
export. All entries have explicit defaults and recommendations can be restored.
The bootstrap grant is settings-only, initial-only, expiring, failed-attempt-
bounded, plan-bound, consumed before mutation and invalidated on reload.

The fresh guided mode is V2-only and blocks V1 fallback. It ends at connection
pending, creates no vault/keys/administrators and keeps the backend disabled.
Actual V2 activation and the remaining full-system acceptance remain pending.
This new commissioning flow needs review separately from the previous core
lifecycle checkpoint. Existing password-module code remains unchanged.

## Current HTML and V2 integration checkpoint

The HTML interface is restyled with responsive navigation/cards, clearer wizard
progress, mobile controls and collapsible advanced settings. The wizard now
validates and saves a non-authoritative peer deployment draft with explicit
defaults and missing-placement checks. Native SECF.Config.v2 exports preserve
the draft; imports remain disabled and V2-only. Existing v1 settings still load.
PHP V2 object/bundle/key-envelope and original-intent components are added with
shared PHP/Go fixtures and rejection tests. See V2_INTEGRATION_CHECKPOINT.md.

The complete outstanding-feature request is not finished. No V2 runtime,
administrator enrollment, service installation, synchronization, backup/migration
or production activation follows from these new components. The configuration
wizard still ends at connection pending. All Q01-Q48 remain NOT_RUN end to end.
