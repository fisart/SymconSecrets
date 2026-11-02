# Shared installation: connect from one platform

Use **Connections** in the HTML administration page of the platform where you
want to start. Keep this page open. The wizard coordinates the other vault using
an approval popup; you do not copy invitations or navigate its administration menus.
Every vault retains its own administrator authentication and exact approvals.

1. **Prepare.** Install/update the module and complete the initial Setup assistant
   on both platforms once. Sign in on the initiating platform and open
   **Connections**. In **Other platform**, choose a known address or enter the
   complete HTTPS Secrets administration or peer URL. A sole known peer is
   prefilled. Select **Connect from here**. Allow the approval popup and sign in
   there if asked. A peer URL opens its own configured frontend automatically.
2. **Invitation.** Confirm the invitation-creation popup on the initiating platform.
   The wizard transfers its one-use invitation directly to the selected HTTPS
   approval popup. The invitation is not put on the clipboard, in a URL or in
   browser storage. If a previous pending connection exists, the wizard first
   opens exact removal approvals here and in the other popup before replacing it.
3. **Request.** Confirm the request in the other platform's popup. The wizard sends
   the approved request automatically. Delivery problems appear in the initiating
   wizard; **Retry delivery on the other platform** retries that existing message.
   Use **Show approval popup** if the browser does not bring it forward. No menus,
   manual invitation transfer or second administration tab are needed.
4. **Approve.** After the request arrives, the other popup closes and the initiating
   wizard opens the final confirmation automatically. It checks the exact vault,
   invitation, pairing ID and matching connection code before opening this approval.
   Confirm the exact displayed platform and sharing scope with your passkey.
5. **Check sharing.** Stay in the initiating wizard. It checks current-pairing
   receipt of the other Global section and acknowledgement of the current outgoing
   Global revision, with no pending sharing messages. Approval alone is insufficient.
   The wizard reports a blocked connection rather than asking you to approve a
   request that never arrived. HTTPS/certificate errors still need correcting;
   browser coordination does not bypass server-side TLS verification.
6. **Ready.** The wizard confirms the exchange. Select **Open my shared secrets**
   to create a harmless test entry in **Global · owned**, or **Open received secrets**
   to inspect the other platform's read-only section. Local secrets, administrators
   and keys remain private. Applications need their own **Automation access** grant.

**Cancel guided connection**, cancelling an approval, leaving Connections or
closing the initiating page stops coordination. Saved server-side requests remain
available under **Your connections**. Completion is never inferred from closing a
popup. Browser channels are temporary, origin/window/nonce-bound and time out after
10 minutes. Credentials, sessions, tokens and vault values never cross this channel.
A changed existing public vault identity pauses setup before removal or approval.

## Advanced: manual invitation setup

Open **Advanced: manual invitation setup** only when the automatic approval-popup
flow cannot be used. The original bilateral protocol remains available:

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
   and PHP HTTPS transport if waiting continues. **Connection check** shows the
   recorded delivery category (DNS, connection, timeout, certificate, HTTP or
   invalid signed response), attempts and retry timing. Expand **Connection details
   for support** and select **Copy connection details** if support is needed. The
   copied report excludes invitations, credentials, response bodies and values. **Try
   delivery now** retries only the saved, already-approved message for this exact
   connection and shows its result immediately. It creates no new pairing and
   needs no second approval. **Check progress** continues to read local status only.
   A prominent **Connection blocked** notice explains that local passkey approval
   does not mean the first platform received the request. A valid site certificate
   may fail validation in Symcon because its CA trust store or server-supplied
   chain differs from the browser's. TLS diagnostics include the verification
   result, a fixed reason and configured CA-location readability; they do not
   expose certificate files, local paths or raw error text.
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

If the approval window expires, the wizard shows **Start again after an expired
request** instead of asking you to submit the same request again:

1. Select **Check progress** first: an approval already sent may still arrive.
2. Correct the problem shown by **Connection check**. An HTTP refusal alone does
   not prove whether a proxy, backend configuration or expired invitation caused it.
3. Select **Remove expired request** and approve. Remove the corresponding expired
   pending request on the other platform too, if it exists. This does not erase
   either platform's own Global or Local secrets.
4. Create a new invitation on the first platform, use it on the second and finish
   request/approval within 15 minutes. Both platforms must approve the new pairing.

Expiry is evaluated using the Symcon server's time rather than the browser clock.
Old undelivered revocation notifications are retired when a removed pairing is
replaced, so they cannot block or apply to the new connection. Certificate checking,
signed acknowledgements and exact administrator approval remain required.

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
