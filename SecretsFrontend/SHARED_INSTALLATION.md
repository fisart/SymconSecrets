# Shared installation

1. Complete the Setup assistant on each platform.
2. Open Connections on one platform, choose the other platform, and select
   Connect from here.
3. Follow the approval popups. The wizard transfers connection details itself.

Once connected, there is one **Global** vault. Both platforms can edit it.
Synchronization and merging happen automatically. **Local** remains private.
Existing connections automatically adopt this model after both modules update.

Open **Conflicts** only when different versions need a decision. Show the
versions, choose what to keep, and confirm. All other secrets remain usable.
Resolved versions return to Global automatically on every connected platform.

If a platform is offline, changes wait for reconnection. Delivery retries and
signed resynchronization run in the background. Connection status and support
details are under Connections. Older module versions must be updated before
they can participate in the unified Global vault.

See [SHARED_GLOBAL.md](SHARED_GLOBAL.md) for the protocol, limits and acceptance tests.

For an existing trusted multi-platform group, use Mailbox → Finish setup on all servers for missing direct pairs, primary/Magic peer routes and reciprocal emergency Global grants. This does not authorize general application writes. A completed setup remains completed when old setup contacts expire; current readiness is evaluated in Symcon and shown in Overview. See [the current operating manual](OPERATING_GUIDE.md).
