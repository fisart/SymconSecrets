# Native vault availability: 5 November 2026

## Observed incident and timing

Production121 backend 18655 remained in status 201 with `Native encrypted vault: recovery check pending.` Kernel runlevel was 10103. Both Recovery and NativeJobs existed with interval 0, LastRun 0, NextRun 0. At 05:12:44 UTC the owner's explicit `SECB_Recover(18655)` succeeded, produced status 102, and scheduled NativeJobs at 10000 ms. Existing encrypted data passed the recovery checks; no initialization was performed.

The QNAP → Symcon-Standby email for 5 November records these Europe/Berlin times, converted below to UTC (CET minus one hour):

| Event | UTC |
|---|---|
| Scheduled module configuration backup starts | 01:30:21 |
| QNAP → standby backup starts | 02:00:04 |
| Production Symcon stop signal | 02:01:57 |
| Consistent backup state | 02:02:01 |
| Latest vault frame/commit 2200 mtime, from owner diagnostic | 02:03:21 |
| Production Symcon kernel ready | 02:03:23 |
| QNAP → standby backup ends | 02:09:06 |
| Separate Proxmox VM110 backup starts | 02:45:00 |
| Separate Proxmox VM110 backup ends | 02:59:22 |

The two-second proximity strongly connects the pending activation to the production restart during backup. File mtime is not an error timestamp and does not prove which call wrote that frame. The earlier request-rejected events were on 4 November, before this restart, and are not attributed to it. There is no evidence in these emails of a live production takeover to Proxmox; the report describes a production stop/restart and an isolated standby start test.

The archived standby code in Dokumentation/SystemDocumentation/manuals/symcon-hot-standby.md stops the source services for its consistent copy and restores them. Its kernel-readiness wait does not validate Secrets backend availability. This source archive predates the incident; it does not prove the exact deployed script bytes.

## Code finding and implemented safeguards

Baseline 1525c0621e7bc35eeacf175ac77a8eedb60c0830 leaves Recovery disabled during nativeApply while kernel initialization is in progress. It relies on the 10103 notification to re-arm it. There was no independent local availability watchdog. The precise reason that notification did not produce a scheduled recovery on this boot remains unproven; obtain startup kernel logs/message delivery records before claiming an exact event-delivery defect.

Changes in this branch:

- Arm startup recovery even before kernel readiness; defer its work until the kernel is ready. Also listen for IPS_KERNELSTARTED (10001).
- Separate 30-second backend watchdog validates the active vault and pinned security foundation.
- Automatic recovery is restricted to the explicit fenced/pending-runtime condition. It uses the existing validating Recover method, never initialization or administrator credential recovery.
- Five attempts with 30/60/120/240/300-second backoff per failure episode, then remain unavailable. Healthy recovery resets the budget. Missing/invalid storage and configuration failures do not trigger activation retries.
- Independent frontend observer checks the backend heartbeat every 30 seconds; a heartbeat older than 90 seconds is unhealthy. Whole-process failure needs an observer on another installation.
- Metadata is available via SECB_GetAvailability and under the backend Availability variable; frontend BackendAvailability reports observer state. Logs record transitions without secret contents. Health probes do not intentionally append telemetry to the encrypted journal. The existing native storage layer may complete an already-approved storage relocation during reads.
- A disabled NativeJobs timer is re-armed after successful validation. GetNativeInfo includes availability metadata.

This does not claim timer code can run while Symcon is stopped, or guarantee a read timeout if the existing filesystem lock implementation blocks. The independent observer reports stale checks, including a blocked watchdog.

## Remote fallback: required next implementation, not enabled here

Connected Global peers currently synchronize data; their trust and authorization state are inside the local encrypted vault. Reading peer credentials from a vault that cannot open cannot provide an independent fallback. Treating peer pairing alone as application read permission would expand authority.

A supported fallback needs an independently protected, explicitly approved client identity and endpoint policy provisioned while healthy, with an authenticated read-only endpoint on the remote peer. Scope must be Global only, bound to the same shared tree and allowed application paths. Remote Local data, administrator access, writes, imports, and OAuth effects are excluded. Missing-record, denied-access, revoked-grant, conflicting-version and security-validation errors must not be converted into availability failover.

The remote server must validate the current grant/revocation state on every read and return a signed nonce-bound response with provenance and shared causal version. A disconnected peer cannot prove it has the newest Global state; the UI must describe this limitation and enforce an approved freshness policy. Requests need bounded timeouts, ordered eligible peers, circuit breakers, observable active source and safe return to local after consecutive successful checks. No plaintext persistent secret cache.

Local records needed during site failure require a separately approved replication/recovery design. This branch does not enable remote secret reads or claim remote fallback is implemented. The existing local access APIs retain their authorization decisions.

## Deployment and acceptance

This is a candidate branch targeting migration/legacy-sec-replacement, not main. Updating main will not install it. Frontend branch also needs the lifecycle change through its own compatible patch before use there. A test on an isolated installation must cover missed ready notification, normal reboot, deliberate pending settings, corrupt/missing key, inaccessible disk, recovery lock contention and disabled jobs timer. Then perform the actual nightly backup/restart and verify fresh availability, status 102 and application reads. Do not equate kernel ready with Secrets ready.
