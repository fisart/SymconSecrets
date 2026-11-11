package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/archive"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/consensus"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
)

func TestCoreCommitPublishesOneAtomicOutcomeAndOutbox(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	a, _, r := f.ready(t)
	id := protocol.Text(r.Record, "id")
	command := uid()
	uncertain := errors.New("lost acknowledgement")
	f.controller.Fault = func(point string) error {
		if point == "after-commit-before-ack" {
			return uncertain
		}
		return nil
	}
	_, e := f.controller.Commit(ctx, command, id, ReservationRef(r), f.actor)
	if !errors.Is(e, uncertain) {
		t.Fatal("commit did not reach lost acknowledgement", e)
	}
	recovered, e := New(f.store)
	must(t, e)
	out, e := recovered.ResolveUser(ctx, a.Intent.UserOperationID, Digest(a.Intent))
	must(t, e)
	if out == nil || out.Result != "COMMITTED" || !protocol.Equal(out.Head, a.Intent.CandidateHead) {
		t.Fatal(out)
	}
	var history *consensus.AlreadyDecided
	_, e = recovered.Commit(ctx, command, id, ReservationRef(r), f.actor)
	if !errors.As(e, &history) {
		t.Fatal("lost ACK was replayed", e)
	}
	jobKey := "core/outbox/" + a.Intent.UserOperationID
	v, e := f.store.Read(ctx, "head", "core/revision", pendingKey(), reservationKey(id), outcomeKey(a.Intent.UserOperationID), auditKey(id), jobKey, "core/sequences", "core/head-pin", scopeKey(a.Intent))
	must(t, e)
	if len(v.Values[pendingKey()].Bytes) > 0 || string(v.Values["core/revision"].Bytes) != "8" {
		t.Fatal("head/revision/pending inconsistent")
	}
	var committed Reservation
	must(t, load(v, reservationKey(id), &committed))
	if committed.Record["state"] != "COMMITTED" {
		t.Fatal(committed)
	}
	var batch JobBatch
	must(t, load(v, jobKey, &batch))
	job := batch.Jobs[0]
	if job.Sequence != "1" || job.SourceRevision != "8" || job.PayloadDigest != a.Intent.Bundle.Descriptor["bundleDigest"] || !protocol.Equal(job.BundleRef, a.Intent.Bundle.Ref) {
		t.Fatal(job)
	}
	revision := v.Values["head"].Revision
	for _, key := range []string{"core/revision", reservationKey(id), outcomeKey(a.Intent.UserOperationID), auditKey(id), jobKey, "core/sequences", "core/head-pin", scopeKey(a.Intent)} {
		if v.Values[key].Revision != revision {
			t.Fatal("not one transaction", key)
		}
	}
	health, e := f.catalog.Health(ctx, id, f.membership.Archives)
	must(t, e)
	if health != "REDUNDANT" {
		t.Fatal("committed candidate receipts not counted", health)
	}
	// A second change gets the next sequence; retrying the first cannot renumber it.
	f.controller.Fault = nil
	a2, _, r2 := f.ready(t)
	_, e = f.controller.Commit(ctx, uid(), protocol.Text(r2.Record, "id"), ReservationRef(r2), f.actor)
	must(t, e)
	v, e = f.store.Read(ctx, jobKey, "core/outbox/"+a2.Intent.UserOperationID, "core/sequences")
	must(t, e)
	must(t, load(v, jobKey, &batch))
	job = batch.Jobs[0]
	if job.Sequence != "1" || func() bool {
		var cursors SequenceState
		must(t, load(v, "core/sequences", &cursors))
		return len(cursors.Entries) != 1 || cursors.Entries[0].Value != "2"
	}() {
		t.Fatal("old job renumbered")
	}
	if _, e = recovered.ResolveUser(ctx, a.Intent.UserOperationID, protocol.MustDigest("wrong")); !errors.Is(e, consensus.ErrIDReuse) {
		t.Fatal("different digest resolved original", e)
	}
}
func TestUnknownCancellationPreventsDelayedOriginal(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	a, _ := f.change(t)
	out, e := f.controller.ResolveUser(ctx, a.Intent.UserOperationID, Digest(a.Intent))
	must(t, e)
	if out != nil {
		t.Fatal("expected UNKNOWN")
	}
	outValue, e := f.controller.CancelUnknown(ctx, uid(), a, f.actor)
	must(t, e)
	if outValue.Result != "ABORTED" {
		t.Fatal(outValue)
	}
	if _, e = f.controller.Reserve(ctx, uid(), a, f.actor); !errors.Is(e, ErrTerminal) {
		t.Fatal("delayed original executed after terminal cancel", e)
	}
	v, e := f.store.Read(ctx, "head", pendingKey())
	must(t, e)
	if string(v.Values["head"].Bytes) != string(consensus.JSON(a.Intent.ExpectedHead)) || len(v.Values[pendingKey()].Bytes) > 0 {
		t.Fatal("cancel published change")
	}
}
func TestCoreCommitAbortRaceHasOneTerminalOutcome(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	a, _, r := f.ready(t)
	id := protocol.Text(r.Record, "id")
	left, _ := New(f.store)
	right, _ := New(f.store)
	checked := make(chan struct{}, 2)
	resume := make(chan struct{})
	pause := func(point string) error {
		if point == "before-final-cas" {
			checked <- struct{}{}
			<-resume
		}
		return nil
	}
	left.Fault = pause
	right.Fault = pause
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, e := left.Commit(ctx, uid(), id, ReservationRef(r), f.actor); errs <- e }()
	go func() {
		defer wg.Done()
		_, e := right.Abort(ctx, uid(), id, ReservationRef(r), f.actor, "USER_CANCEL")
		errs <- e
	}()
	<-checked
	<-checked
	close(resume)
	wg.Wait()
	close(errs)
	wins := 0
	for e := range errs {
		if e == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatal("terminal winners", wins)
	}
	out, e := f.controller.ResolveUser(ctx, a.Intent.UserOperationID, Digest(a.Intent))
	must(t, e)
	if out == nil || !has([]string{"COMMITTED", "ABORTED"}, out.Result) {
		t.Fatal(out)
	}
	v, e := f.store.Read(ctx, "head", reservationKey(id), pendingKey())
	must(t, e)
	var final Reservation
	must(t, load(v, reservationKey(id), &final))
	if final.Record["state"] != out.Result || len(v.Values[pendingKey()].Bytes) > 0 {
		t.Fatal("inconsistent terminal state")
	}
	if out.Result == "ABORTED" && string(v.Values["head"].Bytes) != string(consensus.JSON(a.Intent.ExpectedHead)) {
		t.Fatal("aborted candidate was published")
	}
}
func TestCoreFinalCASRejectsRevokedAuthorizationAndCopies(t *testing.T) {
	for _, kind := range []string{"permission", "owner", "coordinator", "session", "approval", "policy", "pairing", "candidate-generation", "predecessor-copy"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			a, _, r := f.ready(t)
			ctx := context.Background()
			once := false
			f.controller.Fault = func(point string) error {
				if point != "before-final-cas" || once {
					return nil
				}
				once = true
				switch kind {
				case "coordinator":
					v, e := f.store.Read(ctx, "coordinator")
					must(t, e)
					_, e = f.cluster.Client.Revoke(ctx, v.Values["coordinator"].Lease)
					must(t, e)
				case "permission":
					p := f.permission
					p.Active = false
					f.put(t, "core/permissions/"+p.ID, p)
				case "owner":
					var n Node
					v, e := f.store.Read(ctx, coordinatorKey(f.owner))
					must(t, e)
					must(t, load(v, coordinatorKey(f.owner), &n))
					n.Active = false
					f.put(t, coordinatorKey(f.owner), n)
				case "session":
					_, e := f.cluster.Client.Revoke(ctx, f.sessionLease)
					must(t, e)
				case "approval":
					_, e := f.cluster.Client.Revoke(ctx, f.approvalLease)
					must(t, e)
				case "policy":
					p := f.policy
					p.Version = "2"
					f.put(t, "policy", p)
				case "pairing":
					p := f.pairing
					p.Active = false
					f.put(t, "core/pairings/"+p.ID, p)
				case "candidate-generation":
					reg := f.registrations[0]
					binding := protocol.Obj(object(reg), "binding")
					binding["storageGeneration"] = b64()
					reg.Binding = binding
					f.put(t, "archives/"+f.membership.Archives[0], reg)
				case "predecessor-copy":
					key := "deletions/" + f.membership.Archives[0] + "/" + protocol.Text(a.Intent.ExpectedHead, "commitId")
					f.put(t, key, map[string]string{"fence": "test"})
				}
				return nil
			}
			_, e := f.controller.Commit(ctx, uid(), protocol.Text(r.Record, "id"), ReservationRef(r), f.actor)
			if e == nil {
				t.Fatal("stale validation committed")
			}
			out, e := f.controller.ResolveUser(ctx, a.Intent.UserOperationID, Digest(a.Intent))
			must(t, e)
			if out != nil {
				t.Fatal("stale terminal decision", out)
			}
		})
	}
}
func TestCoreReceiptsAndApprovalsFailClosed(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	a, b, r := f.preparing(t)
	id := protocol.Text(r.Record, "id")
	if _, e := f.controller.Ready(ctx, uid(), id, ReservationRef(r), f.actor); e == nil {
		t.Fatal("zero copies made READY")
	}
	corrupt := append([]byte(nil), b...)
	corrupt[len(corrupt)-1] ^= 1
	if _, e := f.services[0].UploadCandidate(ctx, id, f.owner, corrupt); e == nil {
		t.Fatal("corrupt bytes receipted")
	}
	receipt, e := f.services[0].UploadCandidate(ctx, id, f.owner, b)
	must(t, e)
	bad := protocol.Obj(object(map[string]any{"r": receipt}), "r")
	bad["signature"] = protocol.Base(make([]byte, 64))
	if _, e = f.controller.RegisterReceipt(ctx, uid(), id, ReservationRef(r), bad, f.actor); e == nil {
		t.Fatal("bad signature registered")
	}
	_, e = f.controller.RegisterReceipt(ctx, uid(), id, ReservationRef(r), receipt, f.actor)
	must(t, e)
	if _, e = f.controller.Ready(ctx, uid(), id, ReservationRef(r), f.actor); e == nil {
		t.Fatal("one copy made READY")
	}
	_, e = f.controller.Abort(ctx, uid(), id, ReservationRef(r), f.actor, "USER_CANCEL")
	must(t, e)
	if _, e = f.services[1].UploadCandidate(ctx, id, f.owner, b); e == nil {
		t.Fatal("terminal reservation revived")
	}
	if _, e = f.controller.Reserve(ctx, uid(), a, f.actor); !errors.Is(e, ErrTerminal) {
		t.Fatal("aborted user operation reused", e)
	}
}
func TestCoreCoordinatorChangeCannotAdoptOldApproval(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	a, _, r := f.ready(t)
	v, e := f.store.Read(ctx, "coordinator")
	must(t, e)
	lease := v.Values["coordinator"].Lease
	_, e = f.cluster.Client.Revoke(ctx, lease)
	must(t, e)
	next := protocol.Obj(object(map[string]any{"node": f.owner}), "node")
	next["epoch"] = "2"
	l, e := f.cluster.Client.Grant(ctx, 300)
	must(t, e)
	next["leaseId"] = fmt.Sprintf("%016x", uint64(l.ID))
	f.putLease(t, "coordinator", consensus.JSON(next), l.ID)
	if _, e = f.controller.Commit(ctx, uid(), protocol.Text(r.Record, "id"), ReservationRef(r), f.actor); e == nil {
		t.Fatal("old coordinator committed")
	}
	if _, e = f.controller.Commit(ctx, uid(), protocol.Text(r.Record, "id"), ReservationRef(r), f.owner); e == nil {
		t.Fatal("new coordinator adopted old approval")
	}
	_, e = f.controller.Abort(ctx, uid(), protocol.Text(r.Record, "id"), ReservationRef(r), f.owner, "FENCED_OWNER")
	must(t, e)
	out, e := f.controller.ResolveUser(ctx, a.Intent.UserOperationID, Digest(a.Intent))
	must(t, e)
	if out.Result != "ABORTED" {
		t.Fatal(out)
	}
}

func TestLocalScopeChangePreservesOwnerBoundary(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	f.scope["kind"] = "LOCAL"
	f.scope["ownerNodeId"] = f.owner["nodeId"]
	f.put(t, scopeKey(Intent{Scope: f.scope}), f.scope)
	a, _, r := f.ready(t)
	if a.Intent.ChangeClass != "LOCAL_EDIT" {
		t.Fatal("not a local fixture")
	}
	_, e := f.controller.Commit(ctx, uid(), protocol.Text(r.Record, "id"), ReservationRef(r), f.actor)
	must(t, e)
	v, e := f.store.Read(ctx, scopeKey(a.Intent))
	must(t, e)
	var scope protocol.Object
	must(t, load(v, scopeKey(a.Intent), &scope))
	if scope["ownerNodeId"] != f.owner["nodeId"] || scope["objectDigest"] != a.Intent.NewScopeDigest || scope["revision"] != a.Intent.NewRevision {
		t.Fatal("scope owner/revision lost", scope)
	}
}

func TestFourRecipientBatchFitsWithThreeVerifiedCopies(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	a, bytes := f.change(t)
	// Establish the maximum current copy set and four approved pairings.
	_, e := f.services[2].Reattest(ctx, cmd(), protocol.Text(a.Intent.ExpectedHead, "commitId"))
	must(t, e)
	for len(a.Intent.Outbox) < 4 {
		recipient := uid()
		p := Pairing{ID: uid(), Version: "1", RecipientID: recipient, Active: true}
		f.put(t, "core/pairings/"+p.ID, p)
		a.Intent.Outbox = append(a.Intent.Outbox, Delivery{RecipientID: recipient, PairingRef: Ref(p.ID, p.Version, p)})
	}
	v, e := f.store.Read(ctx, approvalKey(a))
	must(t, e)
	var approval Approval
	must(t, load(v, approvalKey(a), &approval))
	approval.IntentDigest = Digest(a.Intent)
	f.putLease(t, approvalKey(a), consensus.JSON(approval), f.approvalLease)
	a.ApprovalRef = Ref(approval.ID, approval.Version, approval)
	a, e = Signed(a, f.ownerKey)
	must(t, e)
	r, e := f.controller.Reserve(ctx, uid(), a, f.actor)
	must(t, e)
	id := protocol.Text(r.Record, "id")
	for _, service := range f.services {
		receipt, e := service.UploadCandidate(ctx, id, f.owner, bytes)
		must(t, e)
		_, e = f.controller.RegisterReceipt(ctx, uid(), id, ReservationRef(r), receipt, f.actor)
		must(t, e)
	}
	r, e = f.controller.Ready(ctx, uid(), id, ReservationRef(r), f.actor)
	must(t, e)
	_, e = f.controller.Commit(ctx, uid(), id, ReservationRef(r), f.actor)
	must(t, e)
	v, e = f.store.Read(ctx, "core/outbox/"+a.Intent.UserOperationID)
	must(t, e)
	var batch JobBatch
	must(t, load(v, "core/outbox/"+a.Intent.UserOperationID, &batch))
	if len(batch.Jobs) != 4 {
		t.Fatal("partial outgoing batch", batch)
	}
}

func TestPreparedReservationLostReplyResolvesWithoutNewApproval(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	a, bytes := f.change(t)
	command := uid()
	lost := errors.New("lost reserve reply")
	f.controller.Fault = func(point string) error {
		if point == "after-commit-before-ack" {
			return lost
		}
		return nil
	}
	_, e := f.controller.Reserve(ctx, command, a, f.actor)
	if !errors.Is(e, lost) {
		t.Fatal(e)
	}
	fresh, _ := New(f.store)
	var history *consensus.AlreadyDecided
	_, e = fresh.Reserve(ctx, command, a, f.actor)
	if !errors.As(e, &history) {
		t.Fatal("reserve was repeated", e)
	}
	var ref protocol.Object
	must(t, decode(history.Outcome.Payload, &ref))
	id := protocol.Text(a.Intent.CandidateHead, "commitId")
	out, e := fresh.ResolveUser(ctx, a.Intent.UserOperationID, Digest(a.Intent))
	must(t, e)
	if out != nil {
		t.Fatal("PREPARING reported as terminal")
	}
	// The original control outcome supplies the exact reservation; it is neither a
	// second approval nor a second allocation after UNKNOWN.
	for _, s := range f.services[:2] {
		receipt, e := s.UploadCandidate(ctx, id, f.owner, bytes)
		must(t, e)
		_, e = fresh.RegisterReceipt(ctx, uid(), id, ref, receipt, f.actor)
		must(t, e)
	}
	r, e := fresh.Ready(ctx, uid(), id, ref, f.actor)
	must(t, e)
	_, e = fresh.Commit(ctx, uid(), id, ReservationRef(r), f.actor)
	must(t, e)
}

func TestCommittedCandidateRecoversThroughArchiveRestart(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	a, _, r := f.ready(t)
	id := protocol.Text(r.Record, "id")
	_, e := f.controller.Commit(ctx, uid(), id, ReservationRef(r), f.actor)
	must(t, e)
	old := f.registrations[0]
	next := old
	next.Binding = protocol.Obj(object(old), "binding")
	next.Binding["bootId"] = b64()
	next.Binding["storageGeneration"] = b64()
	next.Binding["registrationVersion"] = "2"
	next.State = "VERIFYING"
	boot := cmd()
	next, runtime, _ := f.admit(t, 0, next, boot.ID)
	must(t, f.catalog.Boot(ctx, boot, old, next, runtime))
	fresh, e := archive.Open(f.paths[0], f.membership.Archives[0], f.services[0].Key, f.catalog, runtime)
	must(t, e)
	defer fresh.Close()
	health, e := f.catalog.Health(ctx, id, f.membership.Archives)
	must(t, e)
	if health != "DEGRADED" {
		t.Fatal("old generation kept counting", health)
	}
	if _, e = f.services[0].Reattest(ctx, cmd(), id); e == nil {
		t.Fatal("old archive runtime regained serving")
	}
	for _, bundleID := range []string{protocol.Text(a.Intent.ExpectedHead, "commitId"), id} {
		_, e = fresh.Reattest(ctx, cmd(), bundleID)
		must(t, e)
	}
	_, e = fresh.Activate(ctx, cmd())
	must(t, e)
	health, e = f.catalog.Health(ctx, id, f.membership.Archives)
	must(t, e)
	if health != "REDUNDANT" {
		t.Fatal("new generation did not recover copy", health)
	}
	v, e := f.store.Read(ctx, reservationKey(id))
	must(t, e)
	var committed Reservation
	must(t, load(v, reservationKey(id), &committed))
	if committed.Record["state"] != "COMMITTED" {
		t.Fatal("recovery revived reservation")
	}
}

func TestOriginalIDCannotBeReboundByCancellation(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	original, bytes, r := f.preparing(t)
	id := protocol.Text(r.Record, "id")
	other, _ := f.change(t)
	_, e := f.controller.CancelUnknown(ctx, uid(), other, f.actor)
	must(t, e)
	duplicate, _ := f.change(t)
	duplicate.Intent.UserOperationID = original.Intent.UserOperationID
	v, e := f.store.Read(ctx, approvalKey(duplicate))
	must(t, e)
	var approval Approval
	must(t, load(v, approvalKey(duplicate), &approval))
	approval.IntentDigest = Digest(duplicate.Intent)
	f.putLease(t, approvalKey(duplicate), consensus.JSON(approval), f.approvalLease)
	duplicate.ApprovalRef = Ref(approval.ID, approval.Version, approval)
	duplicate, e = Signed(duplicate, f.ownerKey)
	must(t, e)
	if _, e = f.controller.CancelUnknown(ctx, uid(), duplicate, f.actor); !errors.Is(e, consensus.ErrIDReuse) {
		t.Fatal("another digest settled reserved original identity", e)
	}
	for _, service := range f.services[:2] {
		receipt, e := service.UploadCandidate(ctx, id, f.owner, bytes)
		must(t, e)
		_, e = f.controller.RegisterReceipt(ctx, uid(), id, ReservationRef(r), receipt, f.actor)
		must(t, e)
	}
	r, e = f.controller.Ready(ctx, uid(), id, ReservationRef(r), f.actor)
	must(t, e)
	_, e = f.controller.Commit(ctx, uid(), id, ReservationRef(r), f.actor)
	must(t, e)
	out, e := f.controller.ResolveUser(ctx, original.Intent.UserOperationID, Digest(original.Intent))
	must(t, e)
	if out == nil || out.Result != "COMMITTED" {
		t.Fatal("unrelated cancellation damaged pending original")
	}
}

func TestCurrentCoordinatorCanCloseRevokedOwnerWork(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	a, _, r := f.ready(t)
	v, e := f.store.Read(ctx, coordinatorKey(f.owner))
	must(t, e)
	var owner Node
	must(t, load(v, coordinatorKey(f.owner), &owner))
	owner.Active = false
	f.put(t, coordinatorKey(f.owner), owner)
	permission := f.permission
	permission.Active = false
	f.put(t, "core/permissions/"+permission.ID, permission)
	if _, e = f.controller.Commit(ctx, uid(), protocol.Text(r.Record, "id"), ReservationRef(r), f.actor); e == nil {
		t.Fatal("revoked owner work committed")
	}
	_, e = f.controller.Abort(ctx, uid(), protocol.Text(r.Record, "id"), ReservationRef(r), f.actor, "FENCED_OWNER")
	must(t, e)
	out, e := f.controller.ResolveUser(ctx, a.Intent.UserOperationID, Digest(a.Intent))
	must(t, e)
	if out == nil || out.Result != "ABORTED" {
		t.Fatal("revoked work left the realm blocked")
	}
}
