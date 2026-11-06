# HTML commissioning review handoff

Parent: `c43ee3a09f067422ae90f57311b37fb2477c9491`. The Go core lifecycle and frozen
wire profile are unchanged by this UI/configuration checkpoint. Earlier component
closures do not approve this new commissioning flow.

The initial console authorizes a new empty installation at one explicit HTTPS
origin with a ten-minute random code. Saved origin/proxy values are offered as
defaults. Host/forwarded headers never supply trust. A public HTML page cannot
mint this grant. Only its hash, expiry, bounded failed-attempt count, frontend
settings digest, fixed eligible backend roster/digests and one reviewed plan are
held in the transient buffer. No credential is put in properties, export, Debug,
URLs or persistent browser storage. Reload/import clears the grant. Explicit
browser cancellation revokes it; lost network cancellation leaves only its fixed
expiry, with no weaker fallback.

Authorized HTML discovery exposes only eligible fresh backends and installed
integration candidates. Sealed/bound/populated backends are excluded. A fresh empty backend is forced
disabled even if its Enabled box had already been checked.
Instance type, existing pairing, pending edits and exact configuration digest are
checked before review and again before apply. Backend configuration rechecks the
same predecessor under its runtime and storage-setup locks, invalidating any old
V1 storage-setup credential before changing settings. Private absolute non-nested empty paths
outside the Symcon tree are required; symlink/file components are refused.

All entries have defaults: current valid setting, unambiguous discovery, then an
explicit safe unset value. Folders are suggested per backend, theme defaults to
system, Debug off, proxies empty and absent optional integrations disconnected.
Credentials/pins/hardware trust remain unconfigured; no self-announced authority
or attestation root is trusted. Backend ambiguity requires a choice rather than
silently attaching the wrong instance. The HTML page can restore recommendations.

Apply consumes the grant before any side effect, prepares disabled backend
settings and reciprocal frontend binding, preferences and an optional Portal link.
It calls fixed helper methods only; no arbitrary function/instance/RPC dispatch is
accepted. The API cannot create a vault, read old storage, issue administrator
credentials, modify permissions/hardware policy, install TLS keys or enable a
runtime. Configuration changes are not a multi-instance transaction: if an apply
fails, settings may be partly saved. It remains in V2-only mode with vault routes
blocked; the user must inspect/re-authorize. No uncertain apply is replayed or
silently rolled back. Portal registration preserves existing entries through its
already implemented extension; no other module's source is changed.

`GuidedV2Only` persists independently of configuration imports. Both frontend and
backend block V1 vault routes in this mode, even if Enabled is changed manually.
The UI ends at **Settings saved · connection pending**, hides old development
tools and never reports an operational quorum vault. Real V2 service/authorization/
packer and enrollment integration remain unfinished.

New PHP tests cover authority, CORS, roster/existing vault refusal, paths, source
drift, review/apply, one-use/expiry/failed-attempt/cancel/reload, reciprocal binding,
Portal preservation and no vault/V1 activation. New DOM tests cover defaults/reset,
safe rendering, changed-review invalidation, volatile entry clearing, late response
refusal, cancellation and configuration-only completion. Existing V1/backend,
WebAuthn/hardware, UI race and original-file integrity regressions are retained.
Real Symcon/browser and full-system acceptance remain required; this is not a
production approval or a claimed physical-key/host qualification.
