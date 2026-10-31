# IR-01--IR-03 and G-01 correction checkpoint

Review baseline: `ffe0e8d4818b82c6ea48611c08a25cee3e588947`.
[Independent review and runnable reproducers](https://chatgpt.com/library?file_id=libfile_516c34e7c6748191a1617d4148e8b483&account_id=personal).
Disposition: corrections implemented; independent replacement-commit review pending.
No merge, deployment, production acceptance or migration is implied.

The original reproducers were executed against that baseline and reproduced all
three defects and the archive integration gap before the product edits. A PASS
from those original audit reproducers meant that undesirable behavior occurred.
The committed regressions instead require rejection or locked recovery.

| Finding | Correction | Regression evidence |
| --- | --- | --- |
| IR-01 | The development V1 Store reacquires the shared stable runtime lock after prepare, rechecks exact runtime/predecessor/owner/pending/advance identity, and holds it through the bounded external advance. Invalidation cannot report success inside that section. Publication still checks the current local owner; uncertain external results retain the original pending prepare. | `ir-runtime.php` uses the actual Python witness. Invalidation-first sends no advance; protected advance excludes both another Store and an independent OS process; commit-first is recovered only by the new owner; lost acknowledgement recovers without replay. |
| IR-02 | `ReadDurable` re-syncs the opened file and directory under the stable OS lock before journal history or an unlocked floor is returned. Same-byte immutable writes also use that barrier. No in-memory flag is relied on after reopening/crash. Recovery State defaults to locked on errors. | `tests/io_faults.py` builds a narrow overlay injecting file-sync, rename and directory-sync EIO. Admission, recovery, reopening, initialization and immutable retries stay unsuccessful while their required barrier fails, then complete once after successful synchronization. A real process is killed after a failed final directory flush. Physical power-loss qualification remains pending. |
| IR-03 | Both languages bind decisions to the canonical requested predecessor and required-coordinator epoch/null, validate derivable result-head/reference relationships and use the retained original request for historical status. A history query's own null predecessor is not substituted for its target context. | Both languages consume the same 37 validly signed positive/negative vectors, including the auditor's contradictions, rejected actions, coordinator-bound results, election, references and historical context. Missing historical context fails closed. |
| G-01 | Archive construction requires an opaque independently admitted runtime capability. It binds signed boot/generation/volume/target identity to a specific opened directory, with a durable monotonic local marker. Catalog boot installs admission and registration together. Before-work and final-CAS checks compare the same admitted context. | A pre-validation stale service cannot adopt or activate a replacement, transfer its capability to an empty new directory, or restore an old local marker. The during-validation race remains covered. Restart and worker fixtures construct genuinely admitted runtimes. Real host-guard issuance/fencing infrastructure remains unfinished. |

## Follow-up FR-01 and FR-02

Follow-up review baseline: `165b99b5515cd2b13834c9a5f1df5fdf08e951a6`.
[Full independent follow-up and original reproducers](https://chatgpt.com/library?file_id=libfile_de1472e1d0e08191a90963046e922f87&account_id=personal).
The original PHP/Go historical-outcome and real-etcd delayed-admission reproducers
were run before these corrections and reproduced both findings. IR-01 and IR-02
are independently closed for their reviewed component paths; physical power loss
and full-system integration remain outside that closure.

| Finding | Targeted correction | Rejection regression |
| --- | --- | --- |
| FR-01 | Boot validates the installed admission against the current registration, verifies its signature using the capability's independently pinned guard key, and requires a strictly larger admission counter under the same guard/component/target/trust lineage. That exact admission remains in the final atomic CAS read set. A higher registration version cannot substitute for a higher admission counter. | `archive/fr_admission_test.go`: consume counter 2 without Boot, install counter 3 on B, submit counter 2 against the current predecessor; reject, keep B current, deny A receipts/activation. Same-counter different admission, different guard and changed key under the same key ID are refused. |
| FR-01 retry | Exact completed Boot ID/digest/payload resolves as `AlreadyDecided` history, including after supersession; it does not install a generation. ID/digest or payload changes fail. | Lost acknowledgement and superseded-history regressions assert no catalog revision change and that the newer Service remains current. Existing directory marker and during-validation CAS tests remain. |
| FR-02 | One operation-aware semantic validator is used by direct, historical and nested decisions in PHP/Go. Outcomes, reason and head/null rules follow the retained original operation: metadata authorization cannot become COMMITTED, ABORTED or APPLIED; commitment requires a new head and abort publishes none. Historical committed heads must be consistent with the current head. | Shared signed vectors retain all 37 earlier cases and add 34 cases, including the three audit reproductions, valid historical AUTHORIZED/REJECTED, commit/abort terminal outcomes, invalid reasons/heads and nested metadata-as-core outcomes. Both language suites verify the signatures before checking accept/reject. |

Ordinary Boot and local marker advancement intentionally reject guard-key or
trust-lineage changes, even with a higher counter. An approved guard rotation or
counter-reset/recovery transition needs its separate implementation and acceptance;
there is no new-key reset fallback. The stored guard public key is privately copied
into the immutable admitted capability. This is a catalog high-water check against
installed admissions, not evidence that external issuance/revocation infrastructure
has been deployed or qualified.

The semantic validator does not invent a new core-user operation or reinterpret an
authorize/reserve control decision as a terminal browser mutation. The frozen
operation-specific decision contract is enforced on retained request contexts.
Commit/abort fixtures are synthetic codec contexts, not an executed core lifecycle.
The distinct original browser-user lifecycle, its serialization and complete core
integration remain unfinished and must receive an explicit compatible contract
before that path is exposed; missing/unsupported context fails closed. Historical
status still returns no reusable grant or plaintext, and missing original context
continues to fail closed.

## Frozen profile and corrected examples

`DC01_Audit_Profile_v1.2.json` remains byte-for-byte unchanged, SHA-256
`d406bb26320866f390b4d2222f6307516ff0edadcdd2ef166277f9ec739176fc`.
IR-03 enforcement exposed a contradiction in its illustrative `rejectedReservation`
example: its request contains a required coordinator, while its decision epoch is
null. The frozen artifact is preserved for audit traceability. Tests now reject
that exact example and accept a separately signed derivative using the requested
epoch. No protocol fields, signature domains, architecture or recovery policy
were weakened to accommodate an invalid example.

The epoch field binds the coordinator **required by the original action**. Direct
peer actions and election requests have no required coordinator; an election's
new role/epoch is separately bound in its result. A signed rejection can describe
an unsuccessful role claim without claiming the actor actually owned that role.

The PHP `verifyResponse` and Go `ValidateResponse` APIs now take optional retained
original-request context. It is mandatory when a successful status response
contains a historical target decision, and for nested original user decisions in
commit/abort responses. Callers must retain the original action, actor, head and
coordinator context; they cannot reconstruct it from the received decision.
These codecs still do not constitute the unfinished V2 authorization service.

## Remaining gates

The archive capability factory requires an independently managed signer/context
and a real volume verifier outside archive rollback scope. The test inventory's
device/inode binding is not proof of an unrestored VM or positive host fencing.
Network service identity, admission issuance, revocation and recovery deployment
remain unqualified. A whole service restart requires fresh external admission;
worker tests reuse their still-live parent's admitted runtime under its lock.

Complete V2 integration, core commit/abort/repair/retention, synchronization, OAuth,
backup/restore, migration, actual Symcon/browsers/hardware keys, real failure
domains and controller/power-loss testing remain unfinished. Q01-Q48 remain
NOT_RUN end to end. Earlier A01-A07 assessments and their device/operational
limitations remain as scoped by the independent review.

Only the new modules and their development workflow are changed. The original
SecretsManager/password module, its form.json editor and all 33 original repository
blobs remain unchanged.
