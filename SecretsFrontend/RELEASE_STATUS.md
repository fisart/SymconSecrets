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
- Debug child variables, Portal additional-page registration and fail-closed HTTPS/origin checks.

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
