# Secrets administration — operating and recovery manual

Reviewed 8 November 2026. Current release: SymconSecrets 5.4.6 build 20 on migration/legacy-sec-replacement. The earlier documented runtime baseline is build 16, 051f61a635fd4cc6fbb95a21f4f1e97d128ede15. Implemented behavior, supplied deployment observations and remaining acceptance are distinguished explicitly.

## Contents

1. Purpose, release and installation evidence
2. Architecture and trust boundaries
3. Requirements and updating an existing installation
4. First-time setup: steps 1–5
5. Tabs and everyday navigation
6. Daily use of the Secrets editor
7. Sign-in, sessions and approvals
8. Register a passkey on a new device
9. Hardware-key protection
10. Full backup access through Symcon Connect / Magic
11. Connect platforms: steps 1–6
12. Four-platform mesh and one-button completion
13. One Global namespace and automatic merging
14. Conflicts and their resolution
15. Background synchronization and meaningful freshness
16. Overview, production readiness and storage meaning
17. Import old vault: steps 1–4
18. Storage paths and legacy location choices
19. Dependency inventory and consumer migration
20. Automation access and PHP APIs
21. OAuth providers and uncertain outcomes
22. Encrypted backup and value recovery
23. Configuration backup, readable diagnostics and integration
24. Administrator recovery and interrupted setup
25. Maintenance, restart, revocation and retirement
26. Troubleshooting by symptom
27. Complete frontend parameter reference
28. Complete backend parameter reference
29. Variables, timers, hooks and persisted state
30. Implementation and security protocol
31. Capacity and operational limits
32. Source map, audit remediation and executed evidence
33. Remaining acceptance and release closure

## 1. Purpose, release and installation evidence

This guide documents **SymconSecrets 5.4.6, build 16**, runtime source `051f61a635fd4cc6fbb95a21f4f1e97d128ede15` on **migration/legacy-sec-replacement**, reviewed 7 November 2026. The native vault is in production use; a production label is not an independent security-acceptance certificate. Subsequent documentation-only changes do not alter this pinned runtime baseline.

Connected installations share one writable **Global** set. Every member can edit it; there is no Global master/slave hierarchy. **Local** remains private. Concurrent changes are preserved for explicit resolution. Peer synchronization is asynchronous: matching background observations do not promise the latest value during an outage.

| Installation | Backend / frontend | Supplied operating evidence |
| --- | --- | --- |
| production121 (Berlin) | 18655 / 29568 | Owner confirmed application migration. Participates in the four-node native Global mesh. Earlier frozen writes were a historical migration setting, not a permanent production requirement. |
| heartbeat | 39686 / 50093 | Owner confirmed migration; runs on Proxmox. The supplied 7 November Overview shows Production system, completed setup, three synchronized connections, full Magic access and no conflicts. |
| test.hermitage | 18262 / 50365 | Owner confirmed migration and participation in the four-node native mesh. |
| hermitage (production) | 31055 / 32186 | Supplied native reports show an active member of the completed four-node setup. Final unchanged-SEC application and recovery acceptance is not separately recorded here; the older planned-cutover statement is superseded. |

These are supplied observations, not a new live interrogation. The installed version and actual application permissions must be checked on each platform. Keep the separate original-manager reference for retained backups/rollback; use this guide for current native operation. No source or documentation update silently enables application writes.

## 2. Architecture and trust boundaries

The two new modules have independent IDs and API prefixes:

| Component | Module ID | Prefix |
| --- | --- | --- |
| SecretsFrontend | {8D6AE8F7-EA3A-4513-AA14-C3F9613B0E83} | SECF |
| SecretsBackend | {52165EDD-B2C0-40EC-8A59-42A97319B6E2} | SECB |
| Original SecretsManager | {7C5A3841-3F7B-4D2A-9E1C-5B6D8F9A0E12} | SEC |

The frontend supplies the HTML interface, origin checks, session transport and setup coordination. The backend independently validates authority, exact reviewed operations, storage binding and current state before publication. Encrypted snapshots commit values, permissions, audit, outcomes and pending work together. Peer exchange is signed and encrypted for its exact recipient. Browsers receive masked metadata until an authorized reveal.

The native runtime uses PHP functions supplied with Symcon, including OpenSSL and sodium. It does not require an added database, PDO/SQLite, shell command, Python/Go service or separately installed extension. Retained SQL, external-anchor, ownership-transfer and quorum code is not a native fallback. Do not follow historical commissioning instructions for normal native setup.

The Symcon service account, console administrators and the local host remain trusted. An attacker controlling Symcon/PHP, the administrator browser or the operating system is outside vault process isolation. Global partners are trusted writers of Global and may relay it to their other approved Global peers; they do not thereby obtain this platform's Local values or administrator credentials. See chapter 13 before approving a peer.

Integrity of local encrypted files does not give an isolated standalone host an independent reference for detecting a consistent rollback of all trusted files. Filesystem synchronization also does not prove power-loss durability or persistent container mounting. These limitations require deployment qualification, not an undocumented recovery shortcut.

## 3. Requirements and updating an existing installation

Use **migration/legacy-sec-replacement** in Symcon Module Control for the native-only SEC replacement. Keep the existing module GUID, SEC prefix, instances, vault UUID, private data/key folders and approved bindings. Updating the library is separate from changing a vault permission. Do not switch to an older main branch as a routine update.

The runtime uses Symcon-supplied PHP, OpenSSL and sodium; it does not require an added database, PDO/SQLite, external anchor, Go/Python process or extra service. Keys and encrypted state must remain private and persistent through Docker/VM maintenance. Initial setup requires a trusted exact HTTPS origin and an administrator passkey. Existing installations use their saved origins and credentials.

1. Update the library on each participating installation and reload the administration page.
2. Allow the watchdog and background checks to refresh after the update. Cached route observations may need rebuilding; completed setup remains completed.
3. Check Overview, ordinary sign-in, application access and protected pages. Use the already approved Magic address if the primary address is temporarily unavailable.
4. Retain independent Symcon console access and separately saved encrypted recovery material. A code rollback does not undo new secret values or permission changes.

Symcon may omit PHP's HTTPS flag and caller ID. The module recognizes an applied active SSL WebServer from engine evidence or a matching local kernel connection on Linux/Docker. Public NAT ports may differ from internal ports. Build 16 recognizes IPv4-mapped IPv6 sockets for IPv4 wildcard listeners. It reads no certificate/private-key file and changes no router, proxy, Docker or certificate settings. Unrecognized requests remain refused with safe listener details. Remote peer TLS still verifies the certificate/hostname, with the existing validated YE2 issuer completion. An explicit proxy setting applies only when a real trusted TLS proxy is used.

## 4. First-time setup: steps 1–5

These are the five initial-setup steps, not the six connection steps or the four Magic enrollment steps.

1. **Symcon console — Step 1: Open setup.** Open SecretsFrontend. Enter Trusted Symcon HTTPS address (including public port). Include https://; the complete public Symcon console URL can be pasted. Confirm Setup records use private persistent storage when required. Select Step 1: Open setup. If the address is invalid, correct the field and reopen; the button must not be treated as a generic URL launcher.
2. **Browser — Prepare first passkey.** Follow the device's registration prompt and leave this browser window open. Preparing a credential does not make it an administrator. No manual enrollment password/code grants general access.
3. **Symcon console — Step 3: Refresh approval requests.** Compare all four displayed identifier groups with the browser. Select the matching Step 3: Approve button. The approval binds this exact candidate, browser key, frontend and origin. Return to the browser; it checks for approval automatically.
4. **Browser — Review setup plan.** Review the backend choice, suggested vault/key folders, HTTPS address and optional integrations. Confirm persistence/private permissions when asked. Select Review setup plan and inspect the exact summary.
5. **Browser — Set up and sign in.** Confirm the reviewed plan with the prepared passkey. The first usable vault state already contains the approved administrator. Confirm that Overview and Secrets open and that a fresh normal passkey sign-in works.

After successful initialization, Setup assistant is hidden, including after sign-out. It is first-time setup, not a permanent settings or reset tab. Use the purpose-specific tabs thereafter. The frontend console retains independent administrator recovery controls for an initialized vault.

If completion is uncertain after approval, use Resolve accepted setup in the console. Do not create another initialization operation, delete journal files or activate an empty replacement vault. The original accepted operation has a stable identity and is resumed after restart. If object creation was acknowledged uncertainly, inspect the disabled empty candidate and use the explicit console resolution path; automatic retry must not create another backend.

## 5. Tabs and everyday navigation

| Tab | Purpose |
| --- | --- |
| Overview | Symcon-evaluated readiness, connections, synchronization, primary/backup routes, conflicts, storage and fallback. |
| Secrets | Explorer-style Global and Local folders/values. |
| Conflicts | Review and resolve concurrent Global versions when present. |
| Access & keys | Sessions, administrator credentials and hardware-enforcement policy. |
| Backup & settings | Appearance and approved administration settings. |
| Mailbox | Outstanding approvals and progress; Finish setup on all servers; Send diagnostics and configuration. |
| Connections | Guided connection steps 1–6, existing peer status and Emergency Global access. |
| Import old vault | Explicit reviewed import from retained legacy encrypted data; Local secrets only is the default. |
| Encrypted backup | Complete encrypted backup, recovery, verified compaction and automated production checks. |
| Automation access | Existing SEC permissions, Enable production writes and scoped machine capabilities. |
| Key enrollment | Additional administrator credentials and full Magic enrollment/activation. |
| OAuth providers | Provider configuration, refresh execution and uncertain results. |
| Operating guide | Built-in reference for the administration page. |

Setup assistant is only for first initialization and disappears afterwards. The header says **Production system** when this installation's saved grant enables unfrozen application writes; otherwise it says **Secrets system**. It does not grade the security audit.

Mailbox approvals apply directly with a fresh passkey or required hardware key. Each row states the responsible installation and scope. **Production application writes → Enable production writes** is also available under Automation access; both locations change the same local grant. Remote summaries do not authorize local approval of another server's application permissions. The production-write row is local-only to preserve compatibility with existing signed mesh reports.

## 6. Daily use of the Secrets editor

1. Open Secrets and select Global or Local. Global is available across approved connected installations. Local belongs only to the current platform.
2. Use the folder tree or double-click a folder in Contents. Single-click selects an item. Use the path, Back or Up one level to navigate. On touch screens, select a folder and use Open folder.
3. Select Show folder values to reveal direct values beside their names, or select a secret and use the existing eye/Show value control. Normal session authorization is reused for viewing unless the active hardware reveal policy requires a fresh hardware assertion.
4. Use the copy icon beside a visible value. If clipboard access is unavailable, the interface selects the value for the browser's Copy command. Clipboard contents remain outside the page after masking or sign-out.
5. Click a displayed value to change or delete it. New secret creates a named value; New folder creates a folder. Use the existing eye beside the entry field to show/hide typed or generated content. There is no second visibility toggle to learn.
6. For a new password, select Generate password. The default is 24 characters. Length can be 12–128; Include symbols is optional. Generation uses browser cryptographic randomness. Generating fills the editor; Save plus exact passkey approval stores it.
7. Select/open a folder and use the pencil to rename it or the bin to delete it. Empty folders support these actions too. Check the exact target in the confirmation; deleting a folder also deletes its contents. The root cannot be renamed/deleted as an ordinary child.
8. Review and approve changes/deletion with the required passkey. A stale reviewed state requires a new review. A lost result is resolved by its operation identity, not by automatically replaying a mutation.
9. Use Hide values when finished. Revealed values also clear after 30 seconds and on navigation/session invalidation. One-use outputs and editor contents are not saved in browser persistent storage.

Objects are graphical folders; lists and scalar types remain typed. The advanced editor supports lists, numbers, booleans and JSON null. A path such as ["Accounts", 0, "Password"] uses strings for object keys and integers for list positions. It must be a JSON list, not a slash-delimited guess. Root object data, a stored null and a deletion marker are different concepts.

## 7. Sign-in, sessions and approvals

A passkey signs in at the selected exact HTTPS origin. A successful sign-in authorizes ordinary browsing/reveal under the current policy. It does not make every later change automatically acceptable: mutations, grants, pairing, restore and security-policy changes require fresh approval of their exact summary. Hardware-protected reveal may also require its own eligible key.

Select Lock this session after inactivity: 1 minute, 5 minutes or 15 minutes. This selection lasts until sign-out. A session also requires sign-in again after one hour. Metadata polling does not count as user activity and must not keep an unattended session alive. Runtime restart and relevant authority changes invalidate sessions/approvals; sign in again rather than reusing an old popup.

Primary and Magic have separate host-only cookies, CSRF tokens, passkeys and sessions. Knowing the URL alone grants no enrollment, secret access or approval rights. A pending candidate remains unprivileged. An existing administrator or the independently trusted console must approve the exact candidate through the applicable flow. A new candidate cannot approve itself.

### Fast authorization for protected scripts and HTML

From build 20, callers using the SEC/native login-URL APIs open **Confirm access**, a separate small authorization view. Symcon checks an existing origin-bound full session; if it is valid, the page returns immediately without another passkey prompt or prolonging the session. Otherwise it automatically opens the passkey chooser. If the browser requires a user gesture or you cancel, select **Continue with passkey** to retry. After success it returns directly to the protected local hook, without loading the vault dashboard, secret hierarchy, mesh reports or administration controls. A fresh sign-in uses two API requests; session reuse uses one.

The original HTTPS, actual passkey verification, expiry, revocation, restart and full-Magic authorization rules still apply. Limited backup credentials cannot authorize protected pages. No credential/token travels in a return URL; external, query-bearing and recursive Secrets targets are rejected. Cancel stops navigation and further requests; it cannot undo a sign-in already verified by Symcon. Returning through browser history requires an explicit retry. To administer the vault, open its normal address directly.

## 8. Register a passkey on a new device

1. Keep a working administrator credential and the existing session available. Decide which exact address the new device will use: primary, Magic, or both through separate enrollments.
2. Open that approved address on the new device and sign in using an available existing passkey or the browser/device's supported cross-device passkey sign-in. A passkey synchronized by the authenticator provider may already work; that does not enroll a different hardware key automatically.
3. Open Key enrollment → Add an administrator credential. Enter a recognizable Credential label and choose the appropriate Enrollment mode. Select Approve credential enrollment and follow the candidate preparation/registration prompts.
4. An existing eligible administrator must approve the exact displayed new credential and its browser possession binding with a fresh passkey. Use the offered cross-device/physical authenticator prompt if the existing credential is on another device. Do not assume an unrelated signed-in browser tab can authorize a different candidate silently.
5. Allow the policy/identity change to finish. Adding a credential invalidates previous sessions. Sign in again at that exact address using the new passkey and verify access before removing any old key.
6. Repeat the separate Magic enrollment when backup-origin access is needed. A primary-origin passkey cannot simply be reused at another RP ID.

If no existing credential can authorize the new device, use the independent console's Administrator recovery flow in chapter 24. Do not reset the vault or open first-time setup. When a hardware policy is active, ordinary console replacement-key recovery is blocked; a separately specified and qualified hardware recovery procedure is still required. Preserve the last working eligible hardware key.

## 9. Hardware-key protection

Ordinary passkey registration does not prove a credential is a hardware security key. A verified hardware policy requires independently reviewed attestation CA roots, allowed AAGUID models and actual assertion tests. Candidate-discovered models are suggestions, not automatically trusted manufacturers or roots.

1. Open Key enrollment → Hardware trust profile.
2. Supply independently reviewed public CA certificates, exact allowed AAGUIDs and the trust-profile version. Inspect the displayed certificate fingerprints.
3. Select Review certificate fingerprints and activate profile. Approve the exact policy change with the currently required key.
4. Enroll eligible hardware credentials and complete actual assertion tests. Two eligible tested hardware credentials are required before enabling hardware-only protection.
5. Apply the intended policy for reveals, writes, export and administration; inspect Access & keys and Overview for tested/eligible key counts.
6. Test the same requirements independently at Magic before an outage. Upgrading Magic through the console is blocked whenever hardware enforcement is active.

Replacing an enforced trust generation requires re-enrollment and testing; enforcement remains until valid replacement conditions are met. A discovered root, console action, ordinary passkey or changed file cannot silently bypass enforced hardware trust. Public-root paths are pinned/checked; changing files behind an approved path may lock management pending reviewed recovery.

Trust-profile replacement is refused while any hardware action policy is enforced, at review and commit. Disable enforcement with an eligible current key, replace the reviewed trust profile, enroll and test two replacement keys, then explicitly re-enable policy. This guide does not claim physical-key qualification on installations reporting zero hardware credentials.

## 10. Full backup access through Symcon Connect / Magic

The approved full Magic origin provides the same native vault functions as the primary address: browsing, editing, conflicts, pairing, import, backups, automation grants, OAuth administration, key enrollment and administrator recovery. It keeps the existing vault identity, storage and peer relationships. It is hostname/route redundancy, not a second host or a replacement for encrypted backups.

### 10.1 New Magic enrollment: steps 1–4

1. At the usual working address, open Key enrollment → Backup access with Symcon Connect. Select 1 · Find Symcon Connect. Check the exact local Connect address discovered from Symcon's active Connect Control.
2. Select 2 · Allow backup setup and approve with the current administrator passkey.
3. Select 3 · Create backup passkey. Allow the popup. In it, select Create and test backup passkey and follow both registration and assertion prompts. Keep it open.
4. Return to the primary window, compare the exact fingerprint/administrator/permissions, select 4 · Review and activate and approve. The popup checks automatically. When offered, select Continue to sign in and use its approved Magic passkey.

The activation binds the exact administrator, user handle, credential public-key fingerprint, origin generation and full rights. Pending enrollment grants no general access. Save the displayed Magic administration URL; the console also exposes Magic URL, Open Magic URL and Recover administrator access using Magic. Do not rely on having to retrieve it from the broken primary address later.

### 10.2 Existing limited Magic access

Version-1 limited access is not automatically elevated. Sign in at the primary origin and select Approve full Magic access, review the tested eligible credentials/full rights and confirm with the required existing key. The independent console can offer Magic URL · approve full access when no hardware enforcement is active. With enforced hardware policy, perform the upgrade at the primary address using an eligible hardware key before an outage.

The upgrade rotates the origin generation, invalidates old Magic sessions/challenges and requires a fresh Magic login with an approved existing Magic key. It does not require resetting, importing or pairing the vault again. A limited Magic session cannot approve its own elevation.

### 10.3 Transport qualification

Native HTTPS metadata or an explicitly trusted exact proxy may prove HTTPS. For Symcon's metadata-poor local Connect relay, the narrow profile requires the exact active tenant https://[32 lowercase alphanumeric characters].ipmagic.de discovered locally, the loopback peer 127.0.0.1 or ::1, and no contradictory transport/forwarding indicators. It relies on the local core/relay and the Connect provider. An arbitrary ipmagic.de host, remote forwarded header or guessed hostname is not authorized.

Discovery uses the unique active Connect Control module {9486D575-BE8C-4ED8-B5B5-20930E26DE6F}, preferring CC_GetConnectURL and falling back to CC_GetURL. Discovery is a suggestion for review, not approval. Actual TLS and header behavior must still be tested on the deployment. Do not fix missing evidence by trusting every proxy, tenant or Host header.

### 10.4 Make it a real backup route

1. Update every participating platform to compatible code.
2. Enroll full Magic access on each platform while its known route still works.
3. Wait until Publishing its address… clears: every active peer must acknowledge the current signed route revision. There are at most two approved endpoints, Magic first and primary second.
4. Test a fresh Magic sign-in and every required administrative function.
5. In a controlled outage test, make the primary hostname unavailable to the browser and peers. Verify Magic-only sign-in, editing, pairing, Global synchronization and health without primary hostname contact.
6. Restart Symcon, repeat Magic login/sharing, then restore and retest primary access.

An unknown remote Magic address cannot be learned after the only known route has failed. A signed encrypted ROUTES announcement binds exact endpoints to the current vault/pair/epoch and monotonic revision. A primary certificate pin is origin-specific and never copied to Magic. TLS verification remains enabled; redirects cannot introduce routes.

Remove backup access / cancel setup immediately denies that local origin, sessions, challenges, pending approvals and peer hook. A newer signed route list is sent to peers. An unreachable peer can retain a stale address, but the revoked local route already refuses it. Re-adding the same origin requires a fresh generation/enrollment. A Connect-service, local-host or network outage can affect both routes.

The approved Magic URL provides the same administration functions using its separately enrolled credential and session. Heartbeat's supplied address is https://56607d722a79adee0d0b7e1cbfe57dab.ipmagic.de/hook/secrets_frontend_50093. The other platforms obtain their own address from the local Connect core; do not copy one installation's address to another. Successful peer-route checks do not prove a fresh browser passkey login or a backup job. A primary-unavailable login remains a real deployment check.

## 11. Connect platforms: steps 1–6

Use the coordinator on one initiating platform. The browser opens the other platform's approval popup and transfers invitations automatically. The other platform still independently requires its authorized passkey confirmation. An API transports messages; a browser approval is the administrator's authorization, not the replication transport itself.

1. **1 · Prepare.** Complete initial setup once on both platforms. On the initiator open Connections, enter/select Other platform using its complete Secrets administration or peer URL, then select Connect from here. Allow the popup and sign in there when requested.
2. **2 · Invitation.** Confirm invitation creation when prompted. The coordinator transfers the one-use invitation to the selected popup; normally there is nothing to copy. Previous pending pairings require their exact removal approvals before replacement.
3. **3 · Request.** Confirm the connection request with the second platform's passkey. Keep the initiating wizard open. It reports delivery feedback. Use Open approval popup if the browser hides it, or Retry delivery on the other platform after correcting its reported error.
4. **4 · Approve.** After acknowledged request delivery, the initiator compares the exact invitation, vault and connection code and opens final approval. Check the platform identity and Global sharing scope, then approve. In manual fallback, compare the displayed code and select 4 · Review and accept.
5. **5 · Check sharing.** Wait for both the incoming Global state and acknowledgement of the current outgoing state. Pairing approval alone is not proof of data exchange or current synchronization. Correct delivery problems before proceeding; keep the page open for automatic progress.
6. **6 · Ready.** Select Open Global secrets. Verify expected entries on both platforms. Each can edit Global. Use Automation access separately for applications. Local remains private.

The advanced manual fallback uses Create an invitation here / I have an invitation and the same security approvals. An invitation expires after 15 minutes. An expired pending request is not an active connection; first use Check progress for a possible late acknowledgement, correct transport, then remove expired requests explicitly before creating a new invitation. Repeated invitation creation does not repair TLS.

Cancel guided connection or leaving the page stops browser coordination, not necessarily already approved durable deliveries. Inspect Your connections before restarting. If delivery was approved but its response was lost, retry the saved immutable message; do not create an unrelated duplicate pairing.

**Step 5 → Step 6:** a current signed HEALTH response matching the complete local Global state satisfies sharing verification even if an older outgoing snapshot acknowledgement is missing. It does not fabricate a receipt. Pairing must be active and writable, with no pending sharing messages, delivery blockage or health problem. Read the current server-produced explanation rather than repeating invitations when the connection already says Verified in sync.

## 12. Four-platform mesh and one-button completion

The supplied group contains production121, hermitage, test.hermitage and heartbeat. A complete four-node mesh has six bilateral connections; each platform lists three peers. Every platform can edit Global, while Local stays private.

For an existing trusted Global group, sign in as a full administrator and choose **Mailbox → Finish setup on all servers** once. The backend discovers approved members, delivers the signed plan and protected control credential, connects missing pairs, publishes primary/Magic peer routes and establishes reciprocal Global-only emergency permissions. Work continues with the browser closed. No invitation/token copying or separate per-server mesh passkey approval is required.

This authority is restricted to the pinned mesh operations. It cannot enable arbitrary application writes, create administrators, reveal Local values, alter hardware policy or perform OAuth operations. Initial trust still requires an approved connection into the group. Stop setup locally to revoke/suspend that setup authority; ordinary connections remain separately managed.

Discovery and worker work use generous shared deadlines and automatic retries. One setup phase has a shared 90-second budget, with route attempts capped by remaining time (up to 45 seconds primary / 60 seconds Magic); local PHP execution constraints can lower these budgets. Discovery has a 20-minute bound and a run a 60-minute bound. Confirmed work survives explicit retry. See the detailed attempt report for actual allowances rather than adding individual timeouts.

**Completed setup is historical completion.** `localCompletedAt` is the local milestone; `completedAt` records whole-mesh completion. Expired setup confirmations, an absent old log or remote setup rows with null details do not require another setup run. Overview supplies current authenticated health. A completed run may have `historyAvailable: false`; that means its bounded step log is unavailable, not that approvals were lost.

Download the detailed report from Mailbox for safe per-server evidence and failures. It contains observations and public identities, not the protected control token. Do not rerun completed setup merely to refresh yellow monitoring indicators.

## 13. One Global namespace and automatic merging

After both ends update, existing active pairs automatically negotiate shared Global over their authenticated channel. No new reset, import, merge button or pairing is required. Pending/revoked pairs cannot enable it; incompatible older peers stay pending rather than bypassing checks.

| Concurrent state | Result |
| --- | --- |
| Entry exists on only one platform | Appears in merged Global. |
| Same path and identical typed value | One visible usable value. |
| Changes at different secret paths | Merge automatically, including siblings in one folder. |
| Different concurrent values at one path | Preserve versions in Conflicts. |
| Delete versus concurrent change | Preserve both deletion and changed value as choices. |
| Folder delete/replace versus a new child | Preserve the surviving folder and alternative; resolve explicitly. |
| Concurrent list edits | Treat the whole list atomically; never guess shifted positions. |
| Offline changes | Retained locally and merged when approved connectivity returns. |

Causal clocks and per-path multi-value registers order observed operations. Wall-clock timestamps do not select a winner. An actual JSON null is a value; a deletion has a distinct marker. Object ordering is normalized; list order and scalar types survive. Deletion history remains so an old snapshot cannot resurrect removed data.

A peer can read/change all Global and share it onward through other approved Global peers. Approval is therefore broader than a single isolated link's data. Credentials, sessions, machine tokens, hardware policy and Local do not replicate as general peer authority. An inbound signature identifies an approved Global writer, not a local administrator.

To isolate a platform, remove every incident approved link. Removing only one mesh edge leaves other relay paths available. Revocation cannot erase values already received or copied by a previously trusted host. There is no centralized membership controller or remote data-erasure guarantee.

## 14. Conflicts and their resolution

1. Check the Overview warning, then open Conflicts.
2. Select Show versions. Values are revealed only through the authorized bounded reveal path; hardware reveal rules still apply.
3. Compare the exact path and available versions, including deletion where applicable.
4. Keep one selected version, or keep all under explicitly chosen different names.
5. Review the exact result and approve with the current eligible passkey/hardware key.
6. Wait for automatic propagation. The resolved entry returns to usable Global on connected platforms. A concurrent new edit may legitimately produce another conflict.

Only conflicted entries have multiple alternatives. Unrelated secrets remain usable. An exact application read of a conflicted path fails explicitly; a containing folder read returns only usable entries. The module must not choose an arbitrary password from the display projection. Replacing/mutating a subtree with unresolved conflicts is refused until resolved. Resolve nested conflicts before a containing-folder conflict.

The approval binds the current version set and output names. Stale approvals fail or preserve a new conflict; they do not overwrite later work. Two replicas can be perfectly synchronized while both contain the same unresolved conflicts. Synchronization health and conflict health are separate.

## 15. Background synchronization and meaningful freshness

All health, freshness, color, warning and sharing-readiness calculations run in **Symcon**. The browser displays the evaluated result and formats timestamps. Browser clock, browser latency and polling delay do not decide whether a server is stale. The page refreshes status every 10 seconds while relevant tabs are open; backend work continues with the browser closed. Polling does not extend session inactivity.

| Display | Meaning |
| --- | --- |
| Verified in sync | An authenticated complete Global comparison matched at the stated observation. Later remote changes are still possible. |
| Synchronizing | Valid states differ and ordinary repair/exchange is in progress. |
| Not synchronized | Persistent or inconsistent state needs attention; no winner is invented. |
| Status unknown | The required observation is missing or expired. It is not proof of an outage or of different secret values. |

Remote age-only warnings allow **15–30 minutes**: the minimum is 900 seconds; healthy cadence learning uses the last eight successful gaps and up to three times the largest recent gap, capped at 1800 seconds. Failed/overdue checks, outages and clock reversals cannot increase that allowance. A real failed check is reported immediately; the generous age allowance does not hide it. A local Global change immediately invalidates a comparison against older local state. Missing reports, component observations and directional permission evidence remain distinct unknowns.

A browser refresh failure gets a separate connection notice beside the last Symcon evaluation. It does not recalculate all indicators as stale in JavaScript. Local watchdog/startup alarms retain their independent timing and should not be confused with remote age-only warnings.

HEALTH and MESH_STATUS are signed, encrypted, request-bound exchanges. A receiver handling an incoming HEALTH request does not prove the reverse outbound route. Primary and Magic routes are checked separately. Each half of a mesh line belongs to that installation's observation. A → means the row/origin installation may read emergency Global from the destination; matching current bilateral grant IDs are required.

Background probes are fair and bounded. The target cadence is normally about a minute for a small mesh, with actual throughput depending on load and latency. Failed/missing observations cannot be made green merely by leaving a browser open. Detailed route categories distinguish DNS, timeout, certificate/TLS, HTTP and invalid reply. Matching Global state and unresolved conflicts are separate facts; Local never participates in replication.

## 16. Overview, production readiness and storage meaning

Overview joins current connection, synchronization, route, Magic, conflict, source/fallback and storage observations. **Mesh setup completed. Vault ready.** describes current operational state; it is not independent audit certification. A setup completion timestamp can coexist with temporarily unknown route checks after a restart/update.

**Vault storage** is the serialized complete encrypted-state payload budget, not Proxmox disk use or the count/size of password values alone. It includes values, causal synchronization state, identities/permissions, operation receipts/audit, queued work and temporary session/diagnostic state. Limits depend on PHP's execution-memory budget and the ceiling saved at initialization. The Overview does not yet provide an exact per-component byte breakdown.

The supplied Heartbeat page showed **302 of 592 KiB (52%) and 157 retained operations**. Earlier other installations used a 4096 KiB ceiling; 302 KiB would be about 8% against that ceiling. Heartbeat runs on Proxmox, but that alone does not establish PHP's limit or the saved ceiling. The exact cause of the small capacity and its safe adjustment remain open work; no VM/router/storage setting is prescribed by this percentage.

Retained operations are completed request outcomes used for deduplication and lost-result lookup, with audit/head metadata. Sign-ins and approved actions can add records; 157 does not mean 157 waiting jobs or secret edits. These records are local and need not match other installations. Ordinary healthy metadata/secret reads and background health checks do not create mutation outcomes.

Ordinary publication reserves the final 25% of the byte budget for maintenance/recovery. The count limit is separate. Current explicit compaction keeps up to 512 outcomes; compacting at 157 cannot prune those records by count. Do not delete journal files or assume compaction solves a small byte ceiling. See chapter 31 and the remaining work in chapter 33.

## 17. Import old vault: steps 1–4

On the native-only branch, **Import old vault** defaults to **Local secrets only** from retained encrypted old data and its original key. Global and Local requires explicit selection and a fresh reviewed approval. Local-only preserves the shared Global state and queued peer delivery. The retained copy may be stale. Keep the current value is the default conflict policy. Use a fresh preview if you switch the scope or branch. Preserve the encrypted pre-import backup and separate recovery key. Switching back to the old code does not copy native changes into the retained old vault.

On the coexistence branch, unmodified applications keep reading the original vault until their own cutover. Once the authoritative copy is selected, direct routine secret changes to that copy and promptly update consumers of rotating credentials.

1. **Select source and locations.** At an approved full-access primary or Magic address open Import old vault. Select Find old vaults and the correct active Old vault. Multiple candidates are never chosen silently. Choose the conflict policy; Keep the current value is the default. Independently select Keep current location or Use imported location for Vault folder and Key folder. Confirm selected folders' actual persistence and privacy when requested.
2. **2 · Review import.** Inspect Global/Local counts, conflicts, excluded internal areas, old/current/exact selected folders and inactive connection proposals. A preview contains names/types and paths, not values/raw JSON. If the source or destination changed, review again.
3. **3 · Approve import.** Review the immutable summary and approve with the current administrator's required passkey. Save the pre-import encrypted backup and its separately displayed recovery key. A source/state/plan change invalidates the review.
4. **Import verified.** Open Secrets and inspect expected paths/types. Select Review new vault connections to explicitly pair new systems. Migrate consumers separately and test them before retiring old PasswordSafe instances.

The adapter reads supported AES-128-GCM old Vault ciphertext and its existing hexadecimal master.key directly. It avoids legacy APIs that might generate keys or normalize types. Objects, lists, strings, numbers, booleans and null retain type. __LOCAL__ becomes Local. __AUTH__ and other reserved top-level internal areas are excluded. Old passkeys, sessions and system.vault credentials do not become new authority. The old Explorer __folder marker is removed.

Folders merge recursively; identical leaves remain unchanged. Conflicting leaves/lists follow the reviewed keep/replace choice. Unsupported names, structures or native limits reject the complete import; there is no partially accepted vault. The source plaintext budget is 512 KiB. Existing new administrators, grants and peer identities remain current. Imported Global then follows approved native sharing; imported Local does not.

Old role/path/configuration and sanitized replication destinations are retained as migration metadata. Old destination URLs strip embedded credentials, query and fragment. TLS mode/fingerprint/key-transport options are annotations only. Connection proposals are inactive: no old passwords, shared keys or approval rights are silently copied into live native pairing.

## 18. Storage paths and legacy location choices

Vault files and key files require separate private local directories that neither overlap nor contain one another. Ordinary setup uses new/empty destinations, rejects symbolic links and unrelated existing files, and pins the approved binding. Defaults are <kernel>/secrets-native-data/<backendID> and <kernel>/secrets-native-keys/<backendID>; guided setup may propose UUID-based private paths instead. Review the actual plan, not a sample ID.

During import each component can independently retain its current location or use an imported location. The old encrypted Vault itself is a Symcon variable, not a reusable native vault file. The safe imported choices are separate secrets-native-data-ID and secrets-native-keys-ID subfolders beneath the verified old key folder. The old master.key and system.vault are neither adopted nor overwritten.

The supported move uses an approved commit and authenticated redirect under the old lock, copies bounded private files with verification/sync, retains journal/data/signing/wrapping keys, hardware roots and captured completions, records signed completion, then switches the durable binding. An interrupted copy resumes the exact move. Old native directories remain frozen/retained; the wizard does not delete them or fall back to an older writable copy.

Active backup uploads and unresolved OAuth effects must finish before a move. Windows private ACLs, actual disk permissions and persistent container mounts require confirmation. Choosing a subfolder only helps existing backups/Standby if those tools actually include it. Verify their inclusion and test restore; do not infer coverage from a familiar parent path. Do not edit DataDirectory/KeyDirectory to move a commissioned vault or copy live files into another active writer.

## 19. Dependency inventory and consumer migration

The inventory is a static, read-only search of installed scripts, events, readable module sources and exact instance-ID references in instance configuration. It reports object IDs/names/paths, API names, line numbers, literal IDs where detectable and coverage/skips. It must not print secret names/values, raw source lines, tokens or complete configurations.

Review both data consumers (SEC_GetSecret/GetKeys/write/export/import) and authentication consumers (SEC_IsPortalAuthenticated). Source matches can be unused code/examples; dynamic calls, wrappers, external RPC/programs and unreadable code can be missed. A clean static report is necessary evidence, not execution tracing or proof of no external clients.

The provided November inventory found two old instances, 18 matching scripts and eight instance configuration references, with potential consumers including RemoteMirror, Tempest, Webhook Library, Alarm modules and Google Nest Cameras. These are historical supplied observations, not a fresh scan. Dokumentation uses the SEC_IsPortalAuthenticated interface and belongs in the protected-page checks.

Compare Global and private Local data separately for each instance. The 3 November preflight reported two missing or different Global entries and no completed Local comparison for **59597**. **49800** passed the 32-entry Global and Local comparisons. Neither result should be carried forward as evidence for a changed vault or branch.

Per-installation migration and verification sequence:

1. Inventory each of the four platforms and save sanitized reports.
2. Establish/verify the new vault and make a tested encrypted backup.
3. Import the authoritative source with explicit location/conflict choices.
4. Verify the one Global set and the intended private Local data.
5. Grant each application only its required native scope/path; keep tokens private.
6. Test unchanged SEC consumers through the reviewed adapter, or update them to the native APIs. Handle conflict and stale-revision errors explicitly.
7. Migrate legacy portal-authentication integrations separately; a frontend link is not authentication compatibility.
8. Repeat inventory and inspect external/dynamic clients. Observe important scheduled tasks/refresh jobs.
9. Keep old vault backups and rollback instructions, then retire the old deployment after remaining dependencies and recovery checks are resolved. Use the reviewed native-only branch if unchanged SEC consumers need the replacement adapter.

Current installation evidence is in chapter 1. Historical comparison counts and pending migration plans are not current defects. Verify critical SEC reads/writes, protected pages and scheduled clients on each platform; a successful browser login alone does not establish every integration.

## 20. Automation access and PHP APIs

The historical **coexistence** branch kept original and native managers side by side. The installed branch documented here is **migration/legacy-sec-replacement**. The **native-only replacement** branch keeps the original module GUID, SEC prefix and instance IDs, and routes supported SEC calls to the native backend. The branch switch affects all instances of that module on one installation. Existing SEC calls and native APIs can operate in parallel; a failed or mismatched binding stops access. The compatibility layer excludes retired master/slave transport and old admin or credential operations.

Direct backend legacy-shaped reads can work by default for trusted local PHP, with writes frozen. Explicit denials and identity or role constraints take precedence. An empty legacy result can mean refusal; check `SECB_GetLegacyAPIStatus($backendID)` or `SEC_GetReplacementInfo($instanceID)` and retry a known required read without printing its value. A browser login grants browser access; application authorization is checked separately. See [the compatibility changes](https://github.com/fisart/SymconSecrets/pull/9), [read diagnostics](https://github.com/fisart/SymconSecrets/pull/10) and [default local read policy](https://github.com/fisart/SymconSecrets/pull/11).

Open Automation access. Enter Integration name, choose Scope and Exact JSON path, then select Review scoped machine access. Read-only is the default. Enable Also allow revision-checked writes to this path and its children only where required. Approve the exact grant and protect its one-time token. Tokens are revocable and local; peer sharing does not distribute them.

For new integrations use global or local. Paths are JSON arrays and descendants are included only beneath the granted prefix. Legacy owned:<UUID>/received:<UUID> scopes remain implementation compatibility surfaces; they are not a reason to add multiple Global selections or use them for a new shared installation.

Read signature (the backend instance ID is added by Symcon's generated wrapper):

```php
SECB_ReadNativeSecret($backendID, $capabilityToken, $scope, $pathJSON);
// Returns JSON: {"value": ..., "revision": "..."}.
```

Example with placeholders supplied by the application, never printed:

```php
$result = json_decode(SECB_ReadNativeSecret(
    $backendID, $capabilityToken, 'global', '["Accounts","Example","Password"]'
), true, 32, JSON_THROW_ON_ERROR);
$password = $result['value'];
// Pass it only to the intended service. Never echo/log it.
```

Write signature:

```php
SECB_WriteNativeSecret(
    $backendID, $capabilityToken, $scope, $pathJSON, $valueJSON,
    $expectedRevision, $sequence, $operationID
);
```

Expected revision and sequence are canonical decimal strings. Use the current read revision and next sequence for that grant; use a stable UUID for one attempted write. Success returns committed, operationId and sequence. Repeating the exact last UUID and bytes resolves that committed write once. Reusing a UUID with different bytes, using an old sequence, stale revision, wrong path or revoked token fails. After an uncertain result preserve the original request/identity for resolution; do not generate a new UUID and blindly repeat. After compaction, old unknown operations must not be replayed automatically.

The implementation rate-limits capability traffic to 120 per minute per token. Scope is at most 48 bytes, path JSON 4096 bytes and value JSON 49152 bytes, also subject to tree/storage bounds. Exact conflicted Global reads fail; containing reads omit conflicted entries. Writes replacing a conflicted subtree require resolution. Catch explicit errors and stop dependent operations instead of choosing an arbitrary cached password or clearing live credentials.

These are local Symcon PHP calls, not anonymous public HTTP APIs or generic RPC. A compromised Symcon process can access its execution environment; capability tokens still need private storage, careful logging and individual revocation.

### Production application access and all checkboxes

The target is detected automatically: on Heartbeat it is backend **39686**. These permissions are independent of an administrator's ability to edit through the native HTML page.

| Control | Effect |
| --- | --- |
| Allow these application calls | Enables the explicit compatibility grant. |
| Read application secrets | Allows application reads under the existing backend/identity binding. |
| Write application secrets | Allows ordinary application changes. |
| Replace all application data with EncryptAndSave | Separately permits bulk replacement; enable only for an application that requires it. |
| Authenticate protected pages | Enables compatibility login/session checks for older HTML pages using SEC. |
| Freeze compatibility writes | Blocks application writes despite checked write permission. |

For ordinary production application access, Allow, Read and Write are normally selected and Freeze compatibility writes cleared. Select Authenticate protected pages when older HTML pages need the SEC login bridge. Review the exact requirements before enabling bulk replacement. **Review & approve access changes** opens an exact passkey review; the checkboxes themselves do not save a grant.

**Enable production writes**, under Automation access and in Mailbox, enables ordinary writes and clears the compatibility freeze on this installation. It preserves current Read, protected-page and bulk-replacement settings. Explicit read revocation is not silently restored. Approve on each installation that needs it. The native application token APIs remain available alongside supported SEC calls.

For Dokumentation's current authentication adapter, keep its configured SEC-compatible vault instance and required Portal settings; enable Authenticate protected pages on that native backend. A navigation link is not authentication, and selecting an arbitrary SECB instance is not a substitute for the SEC-compatible instance expected by the Documentation form.

## 21. OAuth providers and uncertain outcomes

Open OAuth providers → Provider wizard. Configure Provider name, HTTPS token endpoint, OAuth client ID and Client authentication (basic, body or none). Select stored client-secret and refresh-token scopes/JSON paths, the result-record scope/object path and access-token field. The wizard suggests recognized field names from masked metadata, not secret values. Review provider configuration and approve.

A rotating **refresh credential must be Local to one executor**. New Global refresh references are refused and previously saved unsafe Global refresh configurations cannot dispatch/apply a rotation. Access-token results may be Global. Do not copy the Local refresh token to a second executor; no distributed lease or automatic rotation failover is claimed. A conflict at a referenced Global path blocks use rather than choosing a token. Endpoint transport verifies HTTPS, refuses embedded URL credentials/redirects, bounds response and timeout, and uses cURL supplied with PHP. This provider transport requirement is separate from peer exchange's PHP streams.

Manual approved refresh is available. Automatically refresh before known token expiry is enabled only with an explicitly confirmed provider idempotency contract and the configured idempotency header. Do not claim a provider is idempotent because repeating a test happened to succeed.

The backend durably records PREPARED then SENT_UNKNOWN before dispatch, captures encrypted completion and conditionally publishes token pairs. A lost response may mean the provider already rotated its token. Non-idempotent uncertain work is quarantined, including across restart; no automatic blind replay. Review captured results when available, or explicitly abandon and reauthorize through the provider's supported flow. Pending work and uncertain effects are different states and both surface in Overview. Provider-specific network/idempotency behavior remains a deployment acceptance item.

## 22. Encrypted backup and value recovery

### 22.1 Create and verify a backup

1. Open Encrypted backup → Complete encrypted backup.
2. Select Approve and download encrypted backup and confirm the exact export with the required key.
3. Save the encrypted package and separately displayed recovery key in independent protected locations. Losing the key prevents recovery; storing it beside the file weakens that separation.
4. Test recovery using invented data in a separately initialized test vault. Confirm that the intended storage folders, keys and current permissions survive the real platform backup/restore process.

The authenticated complete package includes the state, key material, shared causal history, policy/authority information, audit, outcomes and pending work needed for verification. That does not mean value restore reinstates old administrators or replays external work. Filesystem backups, configuration exports and peer replication serve different purposes. Replication propagates deletion/conflict; it is not historical recovery.

### 22.2 Recover values

1. Initialize/open the intended current vault and sign in using its current authority.
2. Under Recover values from a backup, choose Encrypted native backup file, enter its Separate recovery key and select Recovery mode.
3. Prefer the default Local recovered copy for inspection. Replacing Global and Local is an explicit alternative that must be reviewed carefully; Global replacement propagates through approved sharing.
4. Select Upload and review recovery, inspect exact scope/result and approve with the required passkey.
5. Verify values, current administrators, application grants and connections. Keep original recovery material until acceptance is complete.

Restore retains current administrative authority and peer identities. It does not resurrect old permissions or automatically execute backed-up OAuth jobs. Default **local-copy** recovery accepts authenticated conflict-containing backups, preserving all concurrent Global variants, deletions, provenance and causal history in separate private Local recovery records. It does not choose a Global winner or reinstall source authority. **replace-values** still refuses unresolved Global conflicts; resolve/review those before replacement.

### 22.3 Key rotation and retention

Rotate the data encryption key is an approved native operation. It is not passkey replacement, peer-signing identity replacement or automatic deletion of all older key material. Make a verified backup first and check current health afterwards.

Verify this current backup and compact retained outcomes requires an uploaded backup verified against the current vault. It keeps the latest 512 outcomes/audit entries and retains pending jobs, uncertain effects and receiver cursors. It does not compact Global tombstones/history or reset membership. Old unknown operations after compaction must never be automatically replayed. A full outbox/capacity warning requires diagnosis before creating more work, not deletion of internal journal files.

### Automated production checks

Open **Encrypted backup → Automated production checks → Run automated checks** and approve the export-class action. It encrypts, authenticates and decrypts the current snapshot and prepares a recovery representation in memory. It compares Global/Local and identity data, reports storage headroom and saved synchronization/route/hardware observations, and includes the current administration-transport evaluation. It does not restore live values, send peer probes, grant permissions or print secrets/keys.

A passed in-memory round trip does not verify your separately retained package/key or boot a replacement installation. Fresh Magic login with primary unavailable, actual saved-file restore on a disposable installation and physical keys when used remain explicit not-tested items. The result deliberately has complete=false; it is not a blanket acceptance certificate.

## 23. Configuration backup, readable diagnostics and integration

Module-owned **ExportConfigurationBackup** and read-only **ValidateConfigurationBackup** use **Symcon.ConfigurationBackup.v1** / **Symcon.ConfigurationBackupValidation.v1** envelopes and the module's ordinary native format/parser. Configuration format versions are independent of code releases. Compatible updates and supported new fields do not require a central backup whitelist change. Source fingerprints alone are informational; warnings require a concrete concern that restoration will fail.

Frontend export is SECF.Config.v1, or SECF.Config.v2 with its validated deployment draft. Backend native configuration import retains provisioning and approved storage/trust protections. Configuration capture excludes secret values, credentials, keys, sessions, setup authority and runtime jobs. A full encrypted vault backup is the separate value/recovery artifact. Import validates required fields and deliberately leaves applicable automation/publication disabled for review; a schema check is not an actual restore rehearsal.

The current [Module Configuration Backup](https://github.com/fisart/Dokumentation/blob/main/SystemDocumentation/manuals/module-configuration-backup.md) source is **Symcon-Backup-Module 1.4.0, build 40**. In its protected page use **Review contents → Download module export**, then the matching instance's native console importer during maintenance. Verify object mappings, paths and dependencies before activation. Native protocol discovery covers modules that implement the interface; properties-only or omitted capture must be reported honestly.

**Mailbox → Send diagnostics and configuration** attempts the saved uploader directly through local background work. It performs no advance dependency lookup. The uploader owns its readable-diagnostics opt-in, configured private repository, allowlist and error reporting. The page reports missing APIs/instances or failed delivery; confirmed completion names a GitHub commit. High-latency work is queued/polled, not a long browser request. Revoked credentials cannot authorize a queued send. A readable support report is neither an encrypted recovery backup nor a complete vault export.

Portal and Dokumentation links open their own separately authenticated pages. This Documentation module uses its SEC-compatible configured instance for authentication; test the protected page after replacing the manager. Backing up Documentation settings does not initialize or restore a Secrets vault.

## 24. Administrator recovery and interrupted setup

For an initialized vault use Administrator recovery from the trusted Symcon console/login guidance or Access & keys; do not restart first-time setup. The flow prepares a replacement credential and binds independent console approval to the current vault, head, origin and policy. Compare the four identifier groups, approve the exact candidate and finish its fresh possession assertion. Existing secrets and policy remain intact. After the identity commit, sign in again; the old signed-in page may be cleared because sessions were revoked.

Full Magic supports the same console-approved recovery intent at its approved origin without contacting primary. It does not weaken hardware rules. Ordinary console key recovery is unavailable under active hardware enforcement pending a separately qualified hardware recovery procedure. Test recovery before deleting or losing the last usable credential.

Before initialization completes, Resolve accepted setup resumes only the durable accepted plan/operation. A restart invalidates volatile sessions/candidates, but it cannot turn a previously accepted operation into a fresh empty setup. CANCELLED and ACCEPTED compete for one immutable decision; once accepted, cancellation cannot promise to stop completion. Missing keys, corrupt decision records, ambiguous object creation or conflicting plans require inspection and fail closed.

A lost successful initialization reply may have created the vault but not delivered the login cookie. Use normal passkey sign-in once status establishes completion. A status/resume route never reissues an old session or secret result. Do not clear attributes, change bindings, regenerate master keys or delete files as a reset workaround.

## 25. Maintenance, restart, revocation and retirement

1. Before updating: verify an encrypted backup/recovery key, working administrator credentials, known primary/Magic URLs and current peer health. Review the pinned implementation/release status.
2. Update compatible native code on all participating platforms. Do not downgrade a shared model to code that predates it. Update Dokumentation separately for new manuals.
3. Restart/apply with attention to intentional invalidation: new runtime fences workers, sessions, challenges, candidate approvals and cached health proofs. The committed snapshot and storage foundation are checked before normal access resumes.
4. Sign in again, verify Overview, current Global/Local, connections and Magic route publication. Background deliveries continue with bounded retry using stable identities.
5. Revoke individual capabilities, credentials, sessions, peers or Magic through the exact reviewed controls. A removed peer link stops its queued effects and fences late replies; remove all graph links to isolate a platform.
6. Never delete the newest corrupt file hoping the runtime will accept an older snapshot. Recovery deliberately refuses silent older-state fallback. Inspect keys/storage and use reviewed recovery.
7. Retire the old module only after chapter 19's dependency and external-client checks. Keep its last encrypted backup and migration records. Do not mistake the new system's successful login for migration of Dokumentation or other SEC authentication users.

A destructive reset is not a normal recovery or synchronization repair. This documentation update does not add or execute a full-platform reset. Reinitialize only through an explicitly reviewed destructive procedure after preserving data and disconnecting old authority; do not improvise by clearing native files/attributes while another platform may still replicate.

Current maintenance boundaries: ordinary retained operations stop at 3500; maintenance has a 4112 ceiling; authenticated login, backup and approved compaction have a separate bounded 32-entry recovery allowance at that ceiling. Compaction is part of the same approved durable commit, not a later best-effort deletion. At most one rejected-request telemetry sample per installation/minute is persisted; existing admission rate limits remain. Count headroom and byte headroom are separate, so investigate a low byte limit even with few outcomes.

## 26. Troubleshooting by symptom

| Symptom | Meaning / next action |
| --- | --- |
| Step 1 says the trusted HTTPS address is invalid | Include https:// and the correct public port. Paste the complete public Symcon URL; review the normalized address. Do not use an uncertified IP. |
| Too few arguments to SECF_OpenBootstrapFromConsole | Installed/cached form or generated wrapper is from a different version. Update the same module version, apply/reopen the frontend form and inspect the generated signature; current button supplies id, address, journal confirmation and recovery=false. Never edit __generated.inc.php. |
| Native storage binding is incomplete | Vault initialization has not finished. Resume the original wizard/accepted operation; administrator recovery is for an initialized vault. |
| Passkey prepared but no administrator access | A candidate is not yet approved/activated. Check console step 3 or the existing administrator's exact candidate approval, then finish assertion. |
| Continue to sign in loops | Confirm activation completed for this exact origin, current module version and an approved tested key. Use fresh normal sign-in after policy generation change. Do not create repeated enrollment candidates. |
| Backup access requires verified HTTPS transport | Inspect the sanitized connection details and exact active Connect tenant/loopback relay conditions. Qualify actual headers/TLS; do not broadly trust forwarding or disable checking. |
| Pairing request approved on second platform but nothing on first | Check second platform delivery. Local passkey approval does not prove remote receipt. Use Try delivery now for the saved message after correcting transport. |
| Pair ACTIVE but no peer secrets | ACTIVE is pairing authority, not current data equality. Check both sharing acknowledgements/health, compatible versions, the Global selection and Conflicts. |
| Global appears empty | Verify Global versus Local, expected source/import, actual exchange, current health and conflicted paths. Do not select an obsolete Received tree to assemble multiple Globals. |
| Browser certificate valid, PHP says issuer-untrusted / cURL 60 / verify result 20 | Browser and Symcon trust sources differ. Inspect the presented chain and PHP CA configuration. A valid leaf alone is insufficient. Use the approved Magic route or the module's strictly validated supported issuer-completion path. Keep hostname/chain validation enabled. |
| One presented leaf issued by Let's Encrypt YE2 | The observed chain may lack its intermediate. Current module-local checksum-pinned issuer completion still validates to configured roots; the observed certificate is untrusted evidence, never automatically trusted. |
| Expired invitation/pending approval | Check for late acknowledged progress first, resolve delivery, then remove the expired request(s) and create one fresh invitation. |
| Retry gives no immediate success | Check visible feedback and pending retry time. A retry reuses approved immutable bytes; transport/remote approval/data checks can still be pending. |
| Synchronizing remains for several intervals | Check last successful authenticated comparisons, queued messages and source health. Valid differences trigger automatic repair; persistent/history mismatch needs investigation, not a forced winner. |
| Status unknown / overdue check | Symcon lacks fresh background evidence; browser retrieval failure is a separate notice. Verify backend enabled/runlevel and reachability; unknown does not prove data mismatch. |
| Verified in sync but conflicts remain | Both replicas contain the same preserved alternatives. Resolve in Conflicts; monitoring does not choose secret values. |
| Permission/revision/sequence error in application | Verify exact grant/path/scope, current revision, sequence, stable UUID and conflict status. Stop dependent action rather than logging/retrying secrets blindly. |
| OAuth result uncertain | Provider may already have rotated the token. Inspect quarantined/captured work and reauthorize as needed; only declared idempotent requests may be retried with their same key. |
| Storage/head/key corruption warning | Preserve evidence/backups and diagnose. Do not delete newest state, generate a replacement key or activate an older writable copy. |
| Dokumentation redirects to old vault | Expected until its authentication integration is migrated; the new guide/link does not replace SEC_IsPortalAuthenticated. |

Connection diagnostics: Connections → Connection check → Connection details for support → Copy connection details. Include the report version, time, target, pairing state/expiry, delivery kind/attempts, fixed certificate reason, policy/CA readability and any authenticated handshake observation. Reports intentionally exclude cookies, invitations, passkeys and vault values. Never attach raw vault files, recovery keys or application tokens to a normal support report.

Earlier supplied diagnostic reports were dated observations. In one report a single YE2-issued leaf and no matching issuer explained strict client path failure; later successful approval did not prove the outgoing PAIR_ACCEPT/data path was healthy. The original manager's past behavior is not proof of the new path's current TLS validity. The complete backup route must be enrolled and announced before an outage.

### Current transport and approval messages

HTTPS_TRANSPORT_UNVERIFIED is an inability to identify the incoming secure listener; it is not a certificate-renewal instruction. The supplied Heartbeat diagnostics identified active SSL listener 45309 on internal port 8443, with exact request sockets in Linux family 6 and an IPv4-any bind. Build 16 corrects the IPv4-mapped IPv6 comparison. Redacted details distinguish kernel family from normalized addressFamily and omit client/local addresses, cookies and key files. Preserve the exact error when escalating; never trust arbitrary Host/Origin/forwarded headers as TLS proof.

CSRF_INVALID may follow a new sign-in in another tab replacing the cookie while the old tab retains its previous CSRF token. The page clears sensitive state and refreshes the current session for safe reads; review and approve mutations again. It never replays a refused mutation or borrows another session's approval.

A stale/unknown remote setup row after whole-mesh completion is not a new authorization request. Check Overview's current reports. Mailbox production-write approval is local; mesh setup authority does not silently enable arbitrary application access on other servers.

## 27. Complete frontend parameter reference

These are registered SecretsFrontend properties, not every temporary wizard input. Defaults are those in Configuration.php. Fields are validated, exported without secrets and disabled on import. The catalogue also displays this property table for quick lookup.

| Property | Stored type / default | Meaning and validation |
| --- | --- | --- |
| Enabled | Boolean / false | Publishes frontend only when valid. Import forces false. Setup/approved runtime controls activation. |
| DebugEnabled | Boolean / false | Enables sanitized bounded diagnostics in Debug; not raw values/tokens/request bodies. |
| BackendInstanceID | Integer / 0 | Selected separate SecretsBackend; reciprocal binding and module ID are checked. 0 is unselected. |
| PortalInstanceID | Integer / 0 | Optional compatible Portal for navigation/AdditionalPages registration. Not administrator authority. |
| DocumentationInstanceID | Integer / 0 | Optional Dokumentation instance for its link. Not conversion of that service's login. |
| AdminOrigin | String / empty | Exact HTTPS origin, normalized host and optional non-default public port. No credentials, query, fragment or application path. Pinned commissioning foundation. |
| TrustedHTTPSProxyIPs | String containing JSON list / [] | At most 16 unique exact IPv4/IPv6 addresses; no wildcards, CIDR or arbitrary proxy chains. Only explicitly trusted TLS termination. Separate narrow active Connect relay handling exists. |
| Theme | String / system | system, light or dark. |

Settings import IDs must be nonnegative integers within 2147483647. Origin text is at most 253 bytes and rejects controls/backslashes and malformed/doubled-dot hosts. A pasted full setup URL is normalized by the setup address parser; AdminOrigin itself stores only the origin.

Console action-only controls include SetupAddress, BootstrapJournalStorage, WizardURL, dynamic candidate approval rows, recovery controls and Magic URL output. These are not additional persistent property defaults. The current Step 1 form action invokes SECF_OpenBootstrapFromConsole(id, address, journalStorageConfirmed, false); do not call a stale three-argument generated wrapper. External generated APIs include the instance ID plus the declared method parameters.

## 28. Complete backend parameter reference

The backend registers 15 properties. Guided native setup supplies the live approved foundation. Some parameters remain for earlier V1 prototypes and must not be presented as native installation requirements.

| Property | Stored type / default | Native meaning or historical status |
| --- | --- | --- |
| Enabled | Boolean / false | Backend/job/hook availability, set through reviewed initialization/lifecycle. The old advanced form's anchor wording describes V1 only. |
| DebugEnabled | Boolean / false | Sanitized bounded backend diagnostics. |
| FrontendInstanceID | Integer / 0 | Paired SecretsFrontend; reciprocal ID and exact origin are checked. |
| DataDirectory | String / <kernel>/secrets-native-data/<backendID> | Private persistent native data directory. Approved binding governs commissioned storage; do not move by editing this property. |
| KeyDirectory | String / <kernel>/secrets-native-keys/<backendID> | Separate private key directory; cannot overlap/contain data directory. |
| AdminOrigin | String / empty | Same exact canonical HTTPS origin as paired frontend. |
| AnchorURL | String / empty | Historical external-anchor prototype only; not required by native runtime. |
| AnchorPublicKey | String / empty | Historical pinned anchor verification key; not native peer/key trust. |
| AnchorKeyID | String / empty | Historical anchor key identifier. |
| ClientCertificatePath | String / empty | Historical anchor mTLS certificate path; not a normal native peer setup step. |
| ClientKeyPath | String / empty | Historical anchor mTLS private-key path; contents never become a frontend configuration value. |
| AnchorCAFile | String / empty | Historical anchor CA path, not a universal peer TLS bypass. |
| HardwareRootsDirectory | String / empty | Approved reviewed hardware trust roots; native trust changes must use exact policy flow. |
| HardwareAAGUIDs | String containing JSON list / [] | Reviewed allowed hardware models; at most 100, each exact 32 lowercase hexadecimal characters. |
| HardwareTrustVersion | String / none | Human-reviewed hardware trust-profile version/generation. |

Backend text settings are bounded to 4096 bytes each; FrontendInstanceID is a nonnegative integer. General backend validation does not imply an arbitrary path/origin is safe for a commissioned native deployment: storage/security profile checks enforce the current approved foundation. Historical advanced buttons for one-use setup credentials, external anchors and sealing are not native onboarding.

## 29. Variables, timers, hooks and persisted state

| Module | Child identifier | Type / purpose |
| --- | --- | --- |
| Frontend | DebugEnabled | Boolean — Debug logging. |
| Frontend | FrontendURL | String — Frontend URL. |
| Frontend | Status | String — Frontend status. |
| Frontend | IntegrationStatus | String — Portal / documentation / backup. |
| Frontend | Debug | String — Debug. |
| Frontend | BackendAvailability | String — Backend availability. |
| Frontend | BackendError | Boolean — Backend error. |
| Frontend | FrontendError | Boolean — Frontend error. |
| Frontend | FrontendHealth | String — Frontend heartbeat. |
| Backend | DebugEnabled | Boolean — Debug logging. |
| Backend | Status | String — Backend status. |
| Backend | StorageStatus | String — Vault / key storage. |
| Backend | Debug | String — Debug. |
| Backend | LastRequestFailure | String — Last refused request (safe diagnostics). |
| Backend | Availability | String — Vault availability. |
| Backend | VaultError | Boolean — Vault error. |
| Backend | FallbackActive | Boolean — Emergency fallback active. |
| Backend | SecretsUnavailable | Boolean — Secrets unavailable. |
| Backend | SynchronizationProblem | Boolean — Synchronization / freshness problem. |
| Backend | ActiveSource | String — Active secrets source. |
| Backend | EmergencyStatus | String — Emergency access status. |

Boolean ~Alert values are true for the indicated fault/degraded state. VaultError, BackendError and FrontendError begin true during startup until validated. FallbackActive marks use of a remote source; SecretsUnavailable marks no usable source; SynchronizationProblem marks freshness/synchronization concern; ActiveSource identifies the selected source. DebugEnabled is an explicit action; alarm/status variables are not control commands.

The backend updates local availability through its watchdog; the frontend independently observes backend readiness. Local heartbeat age rules remain separate from the remote 15–30 minute monitoring allowance. A whole stopped Symcon process cannot update its own Boolean; use an independent observer for host outages.

Frontend timers: BackendAvailability, BootstrapRecovery, Setup. Backend timers: Availability, Recovery, NativeJobs. NativeJobs normally schedules a bounded worker every 10 seconds, with one network phase and shared deadlines. Browser refresh is separate. Hooks are /hook/secrets_frontend_<frontendID> and /hook/secrets_peer_<backendID>; registration never takes over another object's hook.

The encrypted journal retains current values/history, identities, policy, pending deliveries, operation receipts and effects. Setup capabilities, runtime observations, sessions, cursors and outcomes are not ordinary configuration-import authority. Configuration backups intentionally exclude runtime/private state; complete encrypted recovery backups are separate.

## 30. Implementation and security protocol

### 30.1 Local storage publication

NativeStore uses complete AES-256-GCM encrypted snapshots, immutable authenticated commit markers, separate key files, exclusive locks, checked writes, flush/fsync/readback and the platform's directory-sync profile. The newest authenticated state is authoritative; corruption/missing keys lock recovery rather than selecting an earlier permission state. Current keys, values, rights, jobs, audits and operation outcomes publish atomically at this state boundary.

Mutations use stable operation UUIDs and exact digests. Approved plans bind the current head/revision, actor, policy, target and output. Failed/uncertain publication does not return success. Idempotent result resolution cannot reissue a secret-bearing one-use output. Data-key rotation preserves keys needed by retained state until supported compaction permits removal.

### 30.2 Bootstrap and administrator changes

Bootstrap binds exact origin/path/frontend, intent, candidate, browser possession key, epoch, nonce, UUID, operation/action and decoded request digest. The candidate's nonexportable memory-only P-256 key proves browser possession; WebAuthn original clientData bytes are verified independently. Unknown/duplicate fields, invalid points/scalars, noncanonical encodings and cross/top-origin ceremonies are rejected. GET/HEAD serve no setup authority; JSON actions are POST-only with cookie/CSRF/exact-origin gates.

Initial ACCEPTED versus CANCELLED is one immutable locked decision. Journal keys are not regenerated over interrupted state. A durable worker generation is distinct from a browser transport epoch. The first committed vault requires a verified genesis admission containing the approved administrator; there is no empty activated first-admin window. Resume/status does not replay session cookies. Additional keys require an existing eligible approver; console recovery binds the current vault/policy.

### 30.3 Peer delivery and shared state

Peer messages are purpose-bound signed envelopes containing recipient-sealed payloads, exact sender/recipient descriptors, pairing UUID/epoch, immutable job ID and ordered sequence. Unknown keys/fields/epochs/recipients are refused. Receipt and incoming cursor commit with the joined Global state and onward messages. Lost acknowledgement retries identical bytes without repeating the effect. Signed cursor/challenge catch-up repairs delivery gaps without accepting rollback.

Shared Global SECB.SharedGlobal.1 stores bounded writer clocks, per-path versions and causal context. Its join is commutative, associative and idempotent for valid states. Identical causal version IDs with different bytes are rejected. Snapshots authenticate both typed projection and version model. GLOBAL_ENABLE/GLOBAL_ENABLED negotiate the model for an existing approved pair without changing its frozen pairing identity. Legacy snapshots cannot invent merge metadata.

### 30.4 HTTPS and alternative routes

Remote peer transport is bounded PHP HTTPS streams/OpenSSL with hostname and chain validation and no redirects. The supported module-local checksum-pinned Let's Encrypt YE2 intermediate completion still validates the chain to configured trust roots; an observed untrusted leaf never becomes a trust anchor. Optional explicit primary certificate pinning is reviewed and origin-specific. Neither historical success nor the user browser's trust store disables strict checking.

ROUTES binds at most two exact approved endpoints, revision and pair/epoch inside the authenticated channel. Stale/conflicting announcements fail. Magic-first and primary-second use the same immutable signed/sealed operation, and per-host policy remains separate. No unsolicited redirect, DNS observation or remote discovery creates trust. HEALTH uses this same route logic with fresh request binding and encrypted observations.

### 30.5 Browser confidentiality

Normal listings contain names/types only. Reveals use authenticated bounded requests and clear on timer/navigation/session invalidation. Editing/generation uses the existing eye control. One-use tokens/backup keys and setup authority are not stored in URLs, properties, debug, configuration exports or browser persistent storage. Session cookies are Secure, HttpOnly, host-only and SameSite=Strict; CSRF and exact origin are checked. Clipboard copies cannot be recalled by page masking.

### 30.6 External effects

OAuth reservation, dispatch uncertainty, encrypted captured completion and conditional token publication are separate durable states. A provider failure after dispatch is not automatically a safe retry. Provider idempotency must be explicitly reviewed. Compaction retains pending/uncertain work; restore does not blindly revive execution.

## 31. Capacity and operational limits

| Limit in the reviewed implementation | Value / consequence |
| --- | --- |
| Complete native plaintext snapshot | Memory-adaptive, capped at 4 MiB; actual configured capacity is shown by the wizard/status. |
| Ordinary publication reserve | 25% reserved for recovery, revocation and backup-related work. |
| Peers per vault | 32. |
| Queued delivery jobs | 128; full outbox blocks shared publication before partial commit. |
| Machine capabilities | 128. |
| OAuth providers / retained effects | 32 / 128. |
| Transient records | 512, additionally bounded/expired by purpose. |
| Ordinary retained mutation outcomes | Stop at 3500; maintenance ceiling 4112; bounded 32-entry recovery allowance for login/backup/compaction. |
| Explicit verified backup compaction | Keeps latest 512 outcomes/audits, pending effects/jobs and receiver cursors. |
| Shared historical writers | 64. |
| Shared path registers | 5000. |
| Children per object / items per list | 200. |
| Path depth / object-key length | At most 12 components / 160 bytes; nonempty names without __ prefix or control characters. |
| Old-vault plaintext import | 512 KiB plus native state/type/capacity limits. |
| Browser JSON request / conflict reveal | Generally 64 KiB; encrypted backup uploads use bounded chunks. |
| Approved alternative peer endpoints | At most 2, Exact approved route selection/failover; no arbitrary redirect. |
| Native health worker | At most 1 due probe per 10-second run; actual interval adapts to peer count. |
| Session inactivity / absolute duration | 1, 5 or 15 minutes / 1 hour. |
| Visible value lifetime | 30 seconds, also cleared on navigation/session invalidation. |
| Password generator | Default 24 characters, selectable 12–128. |

Capacity errors refuse the whole publication. Global deletion history is not silently garbage-collected. Long-lived tombstone compaction and coordinated membership-epoch reset are not implemented. Adding/removing many writer identities or a long change history can therefore reach bounds even if few secrets are currently visible. Plan maintenance with verified recovery material; do not manually truncate model history.

The byte ceiling is min(saved initialization maxPlainBytes, current memory-derived budget). The current formula subtracts allocated PHP memory and an 8 MiB reserve from memory_limit, budgets about one snapshot byte per 24 available bytes, rounds in 16 KiB steps and caps at 4 MiB. It is an execution safety bound, not disk allocation. Proxmox RAM assigned to a VM is not the same measurement. The exact small-ceiling cause and a safe capacity/retention remedy remain unresolved engineering work; no automatic expansion or pruning below the 512-receipt retention policy has been released.

## 32. Source map, audit remediation and executed evidence

The source manifest pins `051f61a635fd4cc6fbb95a21f4f1e97d128ede15` on migration/legacy-sec-replacement, **5.4.6 build 16**, with byte/hash/Git-blob proofs and a Create-only synthetic inventory (8 frontend properties / 9 variables; 15 backend properties / 12 variables). It stores public source evidence, not deployment credentials.

| Topic | Principal source files |
| --- | --- |
| Listener/HTTPS recognition | SecretsFrontend/Transport.php, Http.php, ConnectDiscovery.php |
| Symcon-side display and freshness | SecretsFrontend/MonitoringView.php; SecretsBackend/MonitoringFreshness.php, NativeHealth.php, MeshStatus.php |
| Mesh completion and authority | SecretsBackend/AutomaticSetup.php, Mailbox.php, NativeOperations.php |
| SEC production permissions | SecretsBackend/LegacyAPI.php, LegacyRuntime.php; SecretsFrontend/native-admin.js |
| Storage/receipts/recovery | SecretsBackend/NativeStore.php, NativePlatform.php, NativeBackup.php, ProductionChecks.php |
| Shared Global / conflicts | SecretsBackend/SharedGlobal.php, NativePeer.php |
| Configuration export / validation | SecretsFrontend/ConfigurationBackup.php; frontend/backend native importers |
| OAuth exact intents | SecretsBackend/NativeEffects.php, NativeRuntime.php |
| Documentation of audit corrections | .docs/security-remediation.md |

The 4 November audit's implemented corrections cover enforced hardware trust replacement, operation-count recovery headroom, Local-only rotating OAuth refresh credentials, bounded rejection telemetry and safe isolated-test cleanup. Conflict-containing backups can now recover variants into Local. The HTTPS gate has native Symcon/Docker recognition and the build-16 mapped-address correction. These corrections do not invent an independent final audit verdict or a fresh physical/outage test.

For the pinned build-16 commit, GitHub runs **42390333793** (frontend/backend), **42390333815** (Portal navigation) and **42390333817** (Native production acceptance) completed successfully. Native tests use disposable encrypted fixtures, supplied crypto, no database drivers and bounded PHP memory. Fifty focused native transport checks include five concurrent real dual-stack kernel connections. The automated workflow retains commit-bound logs/evidence and keeps deployment-only items labelled not tested.

The supplied 7 November Heartbeat Overview reports completed mesh setup and Vault ready, three verified peers, zero conflicts and full Magic access. This is current owner-supplied operating evidence, not fresh proof collected by this static manual. A matching peer report is not a linearizable/latest-value guarantee. Standalone independent rollback detection and physical power-loss durability remain explicitly limited.

## 33. Remaining acceptance and release closure

The module is in production use; complete these remaining items without repeating already completed mesh setup. Record installation, version/origin, date and sanitized result, never secret values or recovery keys.

| Item | Current evidence / remaining action |
| --- | --- |
| Build-16 code regression | Hosted frontend/backend, Portal and production-acceptance workflows passed; mapped-address regression reproduced and corrected. |
| Four-node operation | Supplied reports show completed mesh; Heartbeat's current Overview shows all three peers synchronized. Verify each installation's own primary/Magic login and required application/HTML permissions after updating. |
| Storage capacity | Heartbeat's 592 KiB ceiling and 157 outcomes need the PHP budget/saved-ceiling investigation and a safe small-vault retention plan. A code change is not yet released for this issue. |
| Current production checks | Run Encrypted backup → Automated production checks → Run automated checks on each installation; retain its per-check result. |
| Saved recovery material | Verify an actual separately saved encrypted package/key by restoring into an isolated disposable installation. Never run a test restore against a live vault. |
| Magic outage acceptance | Confirm a fresh Magic passkey login when the primary route is unavailable, with separately retained console access. Do not change production certificate/router configuration merely to clear a module diagnostic. |
| Critical consumers | Test each required SEC/native read/write client and protected HTML page, including scheduled/external clients; a static dependency scan is not execution tracing. |
| Optional hardware/OAuth | Physical hardware-key tests are required if enforcement is used; provider-specific rotation/idempotency acceptance is required if OAuth is used. These are conditional on the feature's use. |
| Final audit / release | Review the final source and record the remaining live qualification. Documentation completion is not security acceptance or a permission grant. |

The in-memory automated round trip does not replace a separately saved-file restore or physical outage/host/power-loss qualification. Configuration backups, complete encrypted vault backups, replication and code rollback are distinct safeguards. The supported active branch is migration/legacy-sec-replacement; main promotion, if chosen, must preserve native-only SEC identity and installed consumers rather than restoring the retired manager implementation.

