# Native Secrets — current release status

Reviewed 8 November 2026. Current release **5.4.6 build 20**, based on installed build-19 commit `58049e54b4f7e403f2698d033bf7bb82d30b4ae2`; installed branch **migration/legacy-sec-replacement**. This is the native-only replacement preserving the original module GUID, SEC prefix and installed instance IDs. Main/coexistence history is not this branch's active implementation.

The native vault is in production use. Supplied four-node reports record completed setup; the later Heartbeat Overview reports Production system, Vault ready, three synchronized connections and full Magic access. Production labels derive from the saved local unfrozen application-write grant, not audit certification. Production121, Heartbeat and Test Hermitage migration were owner-confirmed. Hermitage's native participation is observed; its final unchanged-SEC application acceptance is not separately recorded.

## Build 20: compact authorization

Protected scripts/pages using existing login-URL APIs open the separate approximately 6 KiB **Confirm access** view instead of the approximately 256 KiB administration page. Valid full sessions return after one read-only check without extending expiry; fresh sign-in automatically invokes WebAuthn and returns after challenge/verification. A single Continue button handles gesture-required browsers and cancellation. The view requests no hierarchy, mesh or dashboard data. Same-origin HTTPS, full-Magic restrictions, replay, expiry, revocation and cancellation checks remain. Direct administration still opens the full page. The 8 November canonical `/hook/portal` navigation from build 19 is retained.

## Implemented

- Shared writable Global across approved peers, private Local, explicit concurrent-version resolution and asynchronous replication.
- Passkey administration, one-use outputs, exact approvals, additional-key enrollment, session fencing and conditional hardware enforcement.
- Guided pairing and Mailbox one-button mesh completion, restricted protected mesh authority, direct local approvals and queued GitHub support reports.
- Full separately enrolled Magic browser access, approved primary/backup peer routes and reciprocal Global-only emergency reads.
- Symcon-side freshness/readiness/color evaluation; remote age-only allowance 15–30 minutes; real failures reported promptly; browser only renders the evaluation.
- Current complete HEALTH verification can satisfy wizard sharing checks despite an older missing receipt; delivery failures and pending sharing still block readiness.
- Explicit local production SEC write approval in Mailbox and Automation access, independent read/bulk/protected-page permissions and native scoped APIs.
- Encrypted snapshot/marker storage, complete encrypted backups, conflict-preserving Local recovery, current-authority retention, atomic verified receipt compaction and bounded recovery allowance.
- Module-owned versioned configuration export/read-only validation, separate from secret-value recovery.
- Local-only rotating OAuth refresh credentials with exact-intent/captured-result/quarantine controls.
- Native Symcon HTTPS recognition without standard PHP flags, including NAT/Docker and IPv4-mapped tcp6 sockets; strict peer TLS and validated YE2 issuer completion retained.

## Executed evidence

For the earlier pinned build-16 runtime commit, hosted runs [frontend/backend](https://github.com/fisart/SymconSecrets/actions/runs/42390333793), [Portal navigation](https://github.com/fisart/SymconSecrets/actions/runs/42390333815) and [Native production acceptance](https://github.com/fisart/SymconSecrets/actions/runs/42390333817) passed. Tests cover supplied crypto with no database drivers, bounded memory, synthetic WebAuthn, encrypted recovery/faults, four-node sharing and protected browser behavior. Fifty focused listener checks include five actual dual-stack loopback sockets. This does not claim a physical key, external saved-file restore or real primary-outage login.

## Open work and qualification

1. Explain Heartbeat's 592 KiB byte ceiling versus other installations and fix safe small-vault capacity/retention handling. Current compaction keeps 512 receipts, so 157 outcomes will not be pruned by count. No capacity expansion or automatic cleanup change is included in this documentation update.
2. Record per-installation automated production checks and critical SEC/native/HTML consumer tests.
3. Restore a separately saved encrypted backup/key on an isolated installation and record fresh Magic login during primary unavailability.
4. Perform physical-key/provider-specific acceptance only where those optional features are used; close the final audit with exact-version evidence.

Standalone cannot independently detect a consistent rollback of all trusted files. File/directory synchronization does not certify physical power-loss durability. Global replication is not quorum/linearizable latest-value access. See the [operating and recovery manual](OPERATING_GUIDE.md) and [audit disposition](../.docs/security-remediation.md).

Earlier chronological checkpoints are preserved as [history](../.docs/history/secrets-release-status-through-2026-11-06.md), not current operating instructions. Documentation completion does not grant permissions, migrate values or change infrastructure.
