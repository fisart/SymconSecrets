# Shared installation: steps 1–6

Use **Connections** in the HTML administration page on each platform. The wizard
advances as authenticated requests, approvals and synchronization receipts arrive.
It explicitly tells you which platform needs the next action.

The **first platform** is normally the installation where you maintain the shared
secrets. The **second platform** receives its Global section. Pairing also shares
the second platform’s own Global section back to the first as a separate tree.
Each tree has one editing owner. Received copies are read-only; Local secrets,
administrators and keys stay private to their own platform.

1. **Prepare.** Complete the Setup assistant on both platforms. Open both HTML
   administration pages in separate tabs and sign in. Both HTTPS addresses must
   be reachable from the other platform with valid certificates. The supplied PHP
   needs cURL for remote delivery; the wizard reports when it is unavailable.
   On the first platform select **Create an invitation here**. On the second
   select **I have an invitation**.
2. **Invitation.** On the first platform select **2 · Create one-use invitation**
   and approve with its passkey. A popup opens automatically. Copy the complete
   invitation while visible; it is valid for 15 minutes, and the display clears
   after 60 seconds. Paste it into Step 2 on the second platform, give the first
   platform a recognizable name, and select **3 · Review connection request**.
3. **Request.** On the second platform select **3 · Review and request pairing**.
   Check the first platform’s address in the popup and approve with the second
   platform’s passkey. The invitation is cleared when submitted. Automatic
   delivery continues; checking progress never sends a second pairing request.
4. **Approve.** Return to the first platform’s wizard. It opens Step 4 for the
   request bound to the invitation you created. Compare its **Connection check
   code** with Step 4 on the second platform and check the second platform’s
   address. Tick the confirmation, select **4 · Review and accept**, and approve
   with the first platform’s passkey. The second platform waits for this approval.
5. **Check sharing.** Keep the wizard open. It checks that a Global snapshot was
   received for the current pairing and that the other platform acknowledged the
   current outgoing Global revision for the same pairing, with no pending sharing
   messages. Pairing activation alone does not complete this step. Delivery
   retries automatically. **Check progress** reads status; **5 · Resend my shared
   secrets** requires a separate explicit approval and requests authenticated
   resynchronization. Check connectivity, HTTPS certificates, module versions
   and PHP HTTPS transport if waiting continues.
6. **Ready.** Use **Open my shared secrets** on the first platform and create a
   harmless test entry in **Global · owned**. Use **Open received secrets** on the
   second platform and check the value. Change it on the first platform and check
   again on the second. Applications need an **Automation access** grant for the
   correct Global or Received section; pairing does not migrate old consumers.

**Continue an existing connection** resumes a pending or active pairing after a
page reload. With multiple connections, choose the intended one explicitly.
**Back to Step 1** leaves the wizard; existing server-side requests remain listed
under **Your connections**. **Remove connection** requires approval and stops that
connection; copies already received by the other platform remain there.

Automatic checks run only while the Connections page is visible, pause around
approval dialogs, stop after completion or 15 minutes, and do not extend session
inactivity. Sign in again if the session expires, then continue the existing
connection. Invitations are never stored in URLs or persistent browser storage.
Ownership transfer stays in the separate, collapsed Advanced section.

Implementation evidence is covered by two independent native-vault fixtures and
browser tests for both roles, exact invitation/code binding, fresh approvals,
current-pairing receipts, stale/replaced pairs, delayed replies, inactive windows,
manual continuation and read-only received navigation. Actual remote TLS/network
and deployment qualification remains part of installation testing.
