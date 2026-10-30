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
