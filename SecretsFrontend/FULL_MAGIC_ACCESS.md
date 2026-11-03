# Full administration through the Magic URL

Development implementation. Automated tests pass against injected transport and
real WebAuthn verification. Actual Symcon Connect TLS/header behavior, physical
passkeys and a controlled deployment outage still need verification; this is not
independent security acceptance.

## What changes

Both approved addresses open the same native vault and offer secrets, conflicts,
connections, import, encrypted backup/restore, application access, key enrollment
and administrator recovery. Global remains one shared set across connected
platforms; Local remains private. The storage binding, vault UUID, signing keys,
primary address, existing secrets and approved peer identities are preserved.
No reset, import or re-pair is needed to add Magic access.

The addresses have separate RP IDs, passkeys, host-only cookies, CSRF tokens and
sessions. Authenticate at the address being used. The same hardware requirements
apply at both. Switching addresses cannot reuse an existing browser session.

## 1 · Update both platforms

Install the same development module version on every connected platform. Keep
the primary address working during initial Magic enrollment and route delivery.
Older versions do not understand the signed alternative-address announcement.

## 2 · Enable full Magic access

In **Key enrollment**, use **Backup access with Symcon Connect**.

For a new Magic enrollment, follow the four numbered buttons: **1 · Find Symcon
Connect**, **2 · Allow backup setup**, **3 · Create backup passkey**, then
**4 · Review and activate**. Review the exact origin, administrator, credential
fingerprint and full permissions before approving. The candidate has no general
vault access before approval. Finish by signing in at the Magic URL.

For an existing limited Magic enrollment, sign in at the primary address and
select **Approve full Magic access** in that panel. Review the exact tested
credentials and full permissions and approve with the current administrator's
passkey. If the primary browser address is unavailable, the independent Symcon
console offers **Magic URL · approve full access**, displaying the same exact
credential identities, user handles, public-key fingerprints and permissions.
Reload and review again if the displayed approval has changed.

This upgrade rotates the origin generation. Existing Magic sessions and pending
challenges stop working. Sign in again at Magic with an approved existing Magic
passkey. Untested, revoked or hardware-ineligible keys are not upgraded. A limited
Magic session cannot approve its own elevation.

## 3 · Save and test the Magic URL

The web panel shows **Magic administration URL**. The Symcon console also shows
**Magic URL**, **Open Magic URL** and **Recover administrator access using Magic**.
Use the saved Magic URL directly if the primary certificate fails.

Administrator recovery uses the same console approval and hardware restrictions
as primary recovery. It binds the recovery intent and new credential to Magic,
while retaining the original storage binding. Hardware-only policy still blocks
ordinary console passkey recovery; it does not gain a weaker fallback.

A new installation can use Magic as its initial trusted setup address. No second
hostname is required. Both normal login and recovery stay at the selected
approved origin.

## 4 · Wait for address delivery

Each active peer receives a signed, encrypted announcement of the exact approved
HTTPS peer endpoints, bound to its existing vault keys, backend, pairing and
epoch. Announcements have a monotonic revision; stale or conflicting revisions
are refused. Pair identity never changes with an address.

The web panel reports **Publishing its address…** until all active peers have
acknowledged the current revision. Wait for this to finish on every platform
before relying on Magic during a primary outage. A previously unknown Magic
address cannot be discovered from a remote platform whose only known address
has already failed.

Background delivery prefers the approved Magic endpoint, then the primary.
Each attempt uses the identical signed and sealed operation, so lost replies
cannot duplicate changes. There are at most two endpoint attempts. Each uses the
existing bounded HTTPS transport. TLS verification stays enabled. An explicitly
approved primary certificate pin is never copied to the Magic hostname. HTTP
redirects do not authorize an alternative endpoint.

Revoking Magic immediately denies that local origin, its sessions, challenges,
pending approvals and peer hook. It also increments the route revision and
publishes the remaining primary endpoint to peers. A disconnected peer may keep
its old route until it receives the newer signed announcement; the revoked local
hook already refuses it. Re-adding the same origin creates a fresh generation.

## 5 · Verify the backup on the real deployment

1. Open Magic in a fresh browser session and sign in with its passkey.
2. Verify normal secrets editing, conflicts, key enrollment, application access,
   encrypted backup, import review and connection setup at Magic.
3. Confirm address delivery has completed on every connected platform.
4. In a controlled test, make the primary hostname unavailable to the browser
   and participating platforms. Verify login, editing, new pairing and Global
   synchronization through Magic. Observe requests to ensure no primary contact.
5. Restart Symcon and repeat Magic login and synchronization. Restore and retest
   the primary address. Test console recovery separately without altering live
   secrets or losing the last usable credential.

A Symcon-host, network or Connect-service outage is outside hostname redundancy.
The local relay profile and provider trust assumptions remain documented in
[MAGIC_CONNECT_DESIGN.md](MAGIC_CONNECT_DESIGN.md). There is no wildcard tenant
trust or certificate-validation bypass.

## Automated evidence

`native-runtime.py` includes full Magic lifecycle, version-1 console and passkey
upgrades, Magic-only initial setup and three-platform peer routing. These cover
real registration/assertion verification, exact grants, old-artifact rejection,
CRUD, backup/restore, new-device enrollment, console recovery, restarts, unchanged
vault identity, approved relay acceptance, wrong transport/revocation refusal,
blocked-primary synchronization and new pairing, stale/wrong route rejection,
lost-ACK retry and per-host TLS policy. `ui-full-connect.cjs` rejects primary API
requests while exercising the full Magic navigation. The legacy limited-origin
and all existing native security regressions remain in the runner.
