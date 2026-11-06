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

In Mailbox, choose the discovered Configuration Backup instance, review the repository/branch, tick the destination acknowledgement and select **Send diagnostics and configuration**. No instance ID or GitHub token is entered on the Secrets page.

This calls the existing `MCB_UploadSecretsDiagnostics` uploader. Configuration Backup must support that API, have saved settings, and have **Upload readable Secrets diagnostics to the private repository (no secrets)** enabled. In the Symcon console for the same server as this Secrets page, open the backup instance in the object tree, expand **3. Choose uploads and diagnostics**, enable that checkbox and select **Apply changes**. Return to Mailbox and select **Refresh upload destination**. A return to the browser tab also rechecks the destination. Detection names the server and found instance, and distinguishes no local instance, a failed lookup/configuration read, an outdated backup API, unsaved settings and a disabled option; failed reads never remove an installed instance from the list. Its private-repository verification and data allowlist remain authoritative. The readable report contains diagnostics and redacted configuration for Secrets backends on this installation; encrypted vault backup and complete configuration recovery backups remain separate artifacts.

The browser shows success only after the uploader returns a GitHub commit SHA. Failed/unconfirmed requests are not automatically repeated. Check Configuration Backup's Secrets diagnostics status before retrying an uncertain upload. The API requires an authenticated full administrator and same-origin CSRF validation, verifies the selected instance belongs to Configuration Backup, and limits repeated uploads. Raw dependency errors are never returned to the browser.

Incoming connection placeholders are displayed using their saved server hostname and port, preferring the approved primary address to a Magic relay. Custom names are preserved. This also corrects existing entries without altering pairing identity or grants.

No new module properties, configuration formats or restore behavior are introduced. Existing module-owned configuration export and read-only validation remain unchanged.
