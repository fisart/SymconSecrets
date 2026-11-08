# Secrets administration

The native **SecretsFrontend (SECF)** and **SecretsBackend (SECB)** provide passkey administration, encrypted local storage, one shared writable Global namespace, private Local values, peer/Magic routes, emergency Global reads and independent recovery material. The supported installed branch is **migration/legacy-sec-replacement**. It preserves original SEC module identity/instance IDs through the native-only adapter; retired master/slave transport and old credential administration do not run in parallel on this branch.

Start with the [operating and recovery manual](OPERATING_GUIDE.md). It covers all tabs, initial setup, production permissions, Mailbox, primary/Magic access, monitoring, backup/restore, configuration backup, migration, limits, troubleshooting and the current parameter/child-variable inventory. [Current release status](RELEASE_STATUS.md) distinguishes shipped code, owner-supplied deployment observations, executed CI and outstanding acceptance. Older checkpoint files are historical.

## Compact protected-page authorization · build 20

Scripts and protected HTML pages now open a small **Confirm access** view, not the administration dashboard. A valid full session returns directly without a new passkey ceremony or extending its expiry. Otherwise the browser starts the usual passkey prompt automatically; if a gesture is required, use **Continue with passkey** once. Successful verification returns immediately to the original local hook. The page contains no secrets, hierarchy, mesh status or administration navigation. Existing SEC/native login-URL APIs select it automatically; no consumer-script change is required when those APIs are used.

The view is selected by the exact GET-only `?authorize=1`; the bounded local return hook remains in the fragment. POST authorization retains independent HTTPS, same-origin JSON, WebAuthn user verification, one-use challenges, active credential/revocation checks and secure HttpOnly cookies. Full Magic credentials stay on the Magic origin; limited backup credentials cannot authorize protected pages. Cancellation and navigation never replay a mutation. Directly opening the Secrets administration address still opens administration.

## Existing installations

Update this branch through Module Control and reload the existing page. Keep instance IDs, data/key folders, credentials and approved bindings. Completed mesh setup remains completed; use Overview for current health. Confirm required native/SEC applications and protected pages after an update. Full browser administration uses separately enrolled passkeys at each approved origin.

**Mailbox → Production application writes → Enable production writes** and the identical Automation access shortcut enable ordinary local application writes and clear the compatibility freeze after passkey approval. They preserve current read, protected-page and bulk permissions. To authorize older SEC HTML pages, explicitly enable **Authenticate protected pages** through **Review & approve access changes**. An update itself does not grant these rights.

## Connections and availability

Every approved member can edit Global; Local stays private. Use Connections for the first trusted pair, then **Mailbox → Finish setup on all servers** for the existing group. Background work handles pinned pairs, peer routes and reciprocal Global-only emergency grants. The restricted mesh authority does not grant arbitrary application-write or administrator rights.

All monitoring evaluation runs in Symcon. The browser displays it; it does not calculate staleness from its clock or network delay. Remote age-only warnings allow 15–30 minutes; genuine failed checks remain visible. Current complete Global verification satisfies sharing even if an old ACK is absent, provided no pending sharing or failures remain. [Shared Global](SHARED_GLOBAL.md), [monitoring](GLOBAL_HEALTH.md), [mesh display](MESH_HEALTH_DISPLAY.md) and [emergency access](EMERGENCY_GLOBAL_ACCESS.md) give technical detail.

## Recovery and limits

Keep a complete encrypted backup and separate recovery key, plus module configuration backups. Configuration export is not a value/key backup. Default recovery prepares a separate Local copy and preserves current authority; conflict-containing backups retain all variants. Actual saved-file recovery must be tested on an isolated installation. No live test restore is performed automatically.

Vault storage is the complete snapshot's memory-derived byte budget, not VM disk use. Retained operations are completed receipts, not waiting deliveries. The small Heartbeat ceiling is unresolved work; existing compaction keeps up to 512 receipts and does not solve a 157-receipt byte-limit case.

The runtime requires only supplied Symcon PHP/crypto, with no added database or external process. Strict HTTPS uses native listener/proxy/qualified Connect evidence; build 16 includes IPv4-mapped IPv6 matching. A public certificate screenshot alone is not server-side request binding. The module changes no router, VM, Docker or certificate configuration to qualify transport.

Standalone has no independent whole-state rollback reference; asynchronous peers do not prove the newest value during a partition. Read the [current audit disposition](../.docs/security-remediation.md) before interpreting a green Overview as final security acceptance.
