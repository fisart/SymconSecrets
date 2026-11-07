> Historical design, review or incident record. Current operation and implemented behavior: [OPERATING_GUIDE.md](OPERATING_GUIDE.md) and [RELEASE_STATUS.md](RELEASE_STATUS.md). This record is retained as evidence and does not override the current native-only replacement.

# Human core lifecycle — implementation review handoff

Development parent: `e6958bd79d4debda2dc0604dae352af99db617d6`.
Previously independently reviewed product code: `79c6a0fe5186f687c6b030d0fb46b2ef13c7c67c`.
The FR-01/FR-02 closures remain scoped to that reviewed code. This checkpoint adds
new security-critical behavior and requires its own implementation review.

## What changed

- `SecretsBackend/quorum/core` defines a separate signed original-user Intent,
  authoritative authorization-fact references, immutable terminal UserOutcome and
  protected reservation state machine for human GLOBAL_EDIT/LOCAL_EDIT changes.
- Reserve, actual archive candidate upload/receipt registration, READY, final
  commit, abort and cancellation after UNKNOWN now run against real etcd/archive
  components. Final publication compares the complete current security/copy read
  set. The current coordinator can close abandoned work but cannot reuse an old
  coordinator's approval to commit.
- One final transaction publishes head, scope/core revisions, user and command
  outcomes, reservation, retained pins/inventories, audit, outgoing job batch and
  sequence cursors. It clears pending. A retry cannot reallocate or renumber jobs.
- Archive copy health can count signed candidate receipts only for their linked
  COMMITTED reservation/current admitted ACTIVE generation. Existing fresh
  re-attestation and activation recover those copies after archive restart.
- Election can read the new enrolled-node wrapper while still comparing its
  complete key/scope/active record in the same CAS. The existing primitive binding
  form remains for its earlier fixtures; the core mutation API requires enrolled
  records. This is not a deployed election or host-admission service.

The exact internal record/signature contract and its deterministic public test
vector are documented in [core/README.md](../SecretsBackend/quorum/core/README.md).
The frozen v1.2 profile, PHP/Go wire codec behavior, original password module,
form.json editor and all original repository blobs remain unchanged.

## Test mapping

| Behavior | Main executed regressions |
| --- | --- |
| Stable original identity/approval binding | `TestOriginalIDCannotBeReboundByCancellation`, `TestCoreOriginalContractGoldenVector`, `TestOriginalIntentSignatureScopeAndOneUseApproval`, `TestHardwareAndDiffFactsCannotBeOmitted` |
| Atomic head/outcome/audit/pin/outbox publication | `TestCoreCommitPublishesOneAtomicOutcomeAndOutbox`; asserts equal etcd transaction revisions and two successive immutable sequence mappings |
| Bounded batch capacity | `TestFourRecipientBatchFitsWithThreeVerifiedCopies`; four recipients with all three candidate/predecessor copies |
| UNKNOWN/lost reserve reply | `TestUnknownCancellationPreventsDelayedOriginal`, `TestPreparedReservationLostReplyResolvesWithoutNewApproval` |
| Terminal competition | `TestCoreCommitAbortRaceHasOneTerminalOutcome` |
| Post-validation invalidation | `TestCoreFinalCASRejectsRevokedAuthorizationAndCopies`; permission, owner, coordinator lease, session/approval expiry, policy, pairing, candidate generation and predecessor deletion fence |
| Copy authenticity/independence | `TestCoreReceiptsAndApprovalsFailClosed`, `TestCandidateDurabilityRetryAndIndependentDomains` |
| Coordinator and local owner boundaries | `TestCurrentCoordinatorCanCloseRevokedOwnerWork`, `TestCoreCoordinatorChangeCannotAdoptOldApproval`, `TestLocalScopeChangePreservesOwnerBoundary` |
| Actual process/leader death | `TestCoreProcessDeathBeforeAndAfterCommit`; SIGKILL at before-CAS/after-commit-before-ACK, fresh controller status, delayed command refusal and observed Raft leader kill/restart |
| Archive restart integration | `TestCommittedCandidateRecoversThroughArchiveRestart`; old generation becomes noncounting, old service is fenced, fresh receipts/activation recover current copies without reopening COMMITTED |
| File/rename/directory persistence errors | New core build-overlay tests plus retained IR-02 admission/recovery tests; failed candidate writes return no successful receipt, persistent-error retries fail, cleared-fault retry re-verifies and durably completes |

Local final suite: **195 passing Go test/subtest events**, seven expected
child-helper skips, no failures. Injected-I/O overlay: **23 passing events**, one
expected child-helper skip, no failures. All **20 PHP/Python/Node commands** passed,
including the unchanged password-module regressions and 71 shared signed wire
vectors. Static analysis and locked module verification are required as well.
Counts include parent/subtest events and are not end-to-end requirement counts.
CI records the exact source commit, actual checkout, source hashes and results.

Implementation also reproduced and corrected a cancellation identity-reuse case:
an approved second intent with the same user UUID and a different candidate
could otherwise settle that UUID while the first reservation stayed pending.
The immutable original-user index is now compared/created atomically by Reserve
and CancelUnknown. Its rejection regression also proves that cancelling a
different user operation does not damage another pending operation.

## Boundaries the review must retain

This is an internal human core component, not the finished system. No network,
Symcon or browser route is enabled. Actor arguments must come from authenticated
current credentials in the future dispatcher. Pre-verified authorization records
are provisioned in tests; core does not issue them or verify real WebAuthn,
attestation, origin binding or encrypted permitted diffs. The real authorizer and
PHP encrypted packer must be connected and reviewed before activation.

The new original-user contract is not silently added to the frozen Request/
Decision enum. An explicit reviewed wire binding and client interoperability are
still required. SECURITY/enrollment, machine, counter and recovery core changes
are unsupported. No GC, physical deletion, repair workflow or migrations are
exposed. Inventory remains capped at 15 retained bundles, the cursor registry at
100 recipients and one change at four outgoing jobs; over-capacity is refused.
Outgoing metadata grants no sending authority and does not implement recipient-
specific payload filtering, synchronization grants/receipts or OAuth effects.

Real host/guard issuance/revocation/rotation, positive fencing, independent failure
domains, production TLS/WAL/power-loss behavior, real browsers and hardware keys,
full V2 runtime/backup/restore and one tested migration remain gates. All Q01-Q48
remain NOT_RUN end to end. No merge, deployment or production acceptance is implied.
