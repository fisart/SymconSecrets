# Mailbox and HTML support reports

The native Secrets page has a Mailbox tab. It projects saved pairing, emergency access, backup-access setup, ownership transfer and uncertain OAuth workflows. Opening it never grants authority. Each available local decision includes a detailed scope description and an approval button. `Approve with passkey` prepares the exact action, requests the existing passkey or hardware-key assertion, submits it and refreshes the entry directly in Mailbox; it does not open a separate approval workflow. Cancellation, stale state and hardware requirements retain the same enforcement as other approval paths. Tested backup candidates are shown with their exact credential fingerprint; setup without a tested candidate is waiting for setup, rather than ready for approval. OAuth captured-result application and abandonment are separate explicit decisions. Remote approvals must be made on their own server.

## Reading the state

- Your approval required: this server has a concrete request to review.
- Waiting for the other server: delivery was acknowledged; the other administrator's decision is still outstanding.
- Sending / retrying delivery: receipt is unconfirmed. It is not evidence that approval was refused.
- Approval sent — confirmation pending: approved locally; delivery or matching remote evidence is outstanding.
- Completed: current workflow records establish completion. Emergency access needs the exact grant identifier in fresh bilateral observations.
- Status unknown: the remote summary or exact corroborating evidence is unavailable or stale. Last known states remain visible.
- Expired / revoked: the saved request expired or local authority/pairing was retired.

Emergency direction is stated as “consumer may read Global from provider”; provider permission and consumer acceptance are separate facts. Pairing alone grants no emergency access. Optional access without an offer is not an outstanding request.

The badge separates approvals needed here from waiting entries. Filters select this server, an individual server or all servers, and outstanding/all records. Historical request times were not saved by older workflows and display “Time not recorded”; last-confirmed update times are explicit. Completed records remain visible while their source records exist, rather than forming an unbounded new audit archive.

Remote summaries use the existing authenticated mesh checks, with no per-row polling or transitive discovery. They contain only fixed workflow types/states, opaque identifiers, directions, safe navigation targets and timestamps, never approval challenges, packages, tokens, secret names/paths or credential material. At most 32 rows per remote report are included, with explicit partial coverage. The local view includes all retained rows. Older peers retain their existing mesh report protocol and show Mailbox unavailable; protocol capability is rechecked hourly. Update all participating servers for complete remote coverage.

## Send diagnostics and configuration to GitHub

In Mailbox, select **Send diagnostics and configuration**. There is no advance lookup, destination refresh or separate checkbox. The button explicitly requests a readable report for this server’s saved private backup repository.

The request queues local background work and returns a job identifier immediately. The existing Secrets job worker locates the Configuration Backup instance only when executing the send and calls `MCB_UploadSecretsDiagnostics` directly. It does not read Configuration Backup settings to decide whether sending should be available; the uploader remains authoritative for its saved readable-diagnostics opt-in, private-repository restriction and field allowlist. Missing instances or API functions, known configuration errors and GitHub HTTP failures are returned as actionable outcomes. Raw dependency errors remain excluded.

The browser polls local job progress; it does not hold the upload request open for network I/O. Duplicate pending requests reuse the job, the background worker has a five-minute execution allowance, and completion requires a validated GitHub commit. The job is bound to the authorizing credential and revocation generation; revoked authority cancels a queued send. An interrupted running upload is not silently replayed. After 20 minutes without confirmation, the page reports the uncertain outcome and asks the operator to check the repository before starting another upload. Runtime queue changes do not advance the passkey permission head. Encrypted vault and complete configuration recovery backups remain separate artifacts.

## Production application writes

The local Mailbox includes Production application writes. Enable production writes uses the existing exact nativeLegacyAccess passkey approval for this backend, enabling ordinary writes and clearing its compatibility freeze while retaining current read/protected-page/bulk settings. It is also available in Automation access. Completed rows disappear under the outstanding filter and return if access is frozen/disabled. This row and action inputs stay local; signed remote mailbox schemas and mesh authority are not extended to arbitrary remote write grants.
