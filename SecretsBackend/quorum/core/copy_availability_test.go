package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/archive"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
)

// Independent audit C-02: a valid new boot invalidates only the third copy.
func TestTwoSurvivingCandidateCopies(t *testing.T) {
	for _, stage := range []string{"READY", "COMMIT"} {
		t.Run(stage, func(t *testing.T) {
			f := fixture(t)
			ctx := context.Background()
			a, b, r := f.preparing(t)
			id := protocol.Text(r.Record, "id")
			for _, s := range f.services {
				receipt, e := s.UploadCandidate(ctx, id, f.owner, b)
				must(t, e)
				_, e = f.controller.RegisterReceipt(ctx, uid(), id, ReservationRef(r), receipt, f.actor)
				must(t, e)
			}
			if stage == "COMMIT" {
				var e error
				r, e = f.controller.Ready(ctx, uid(), id, ReservationRef(r), f.actor)
				must(t, e)
			}
			restartArchive(t, f, 2)
			_, count, e := f.catalog.CopySnapshot(ctx, protocol.Text(a.Intent.ExpectedHead, "commitId"), f.membership.Archives)
			must(t, e)
			if count != 2 {
				t.Fatal("expected two surviving predecessor copies", count)
			}
			for _, s := range f.services[:2] {
				_, e = s.UploadCandidate(ctx, id, f.owner, b)
				must(t, e)
			}
			if stage == "READY" {
				r, e = f.controller.Ready(ctx, uid(), id, ReservationRef(r), f.actor)
				must(t, e)
			}
			out, e := f.controller.Commit(ctx, uid(), id, ReservationRef(r), f.actor)
			must(t, e)
			if !protocol.Equal(out.Head, a.Intent.CandidateHead) {
				t.Fatal("wrong candidate committed")
			}
			v, e := f.store.Read(ctx, reservationKey(id), candidateReceiptKey(id, f.membership.Archives[2]), "receipts/"+f.membership.Archives[2]+"/"+id)
			must(t, e)
			var final Reservation
			must(t, load(v, reservationKey(id), &final))
			if len(final.Record["receiptRefs"].([]any)) != 2 {
				t.Fatal("stale third receipt remained live")
			}
			if len(v.Values[candidateReceiptKey(id, f.membership.Archives[2])].Bytes) == 0 {
				t.Fatal("historical receipt was destroyed")
			}
			if len(v.Values["receipts/"+f.membership.Archives[2]+"/"+id].Bytes) != 0 {
				t.Fatal("stale receipt was published as a committed copy")
			}
		})
	}
}

func restartArchive(t *testing.T, f *testFixture, index int) {
	t.Helper()
	old := f.registrations[index]
	next := old
	next.Binding = protocol.Obj(object(old), "binding")
	next.Binding["bootId"] = b64()
	next.Binding["storageGeneration"] = b64()
	next.Binding["registrationVersion"] = "2"
	next.State = "VERIFYING"
	boot := cmd()
	next, runtime, _ := f.admit(t, index, next, boot.ID)
	must(t, f.catalog.Boot(context.Background(), boot, old, next, runtime))
}

func TestInvalidCopiesCannotSupplyTheSecondDomain(t *testing.T) {
	for _, kind := range []string{"zero", "one", "forged", "wrong-archive", "same-domain"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			ctx := context.Background()
			a, b, r := f.preparing(t)
			id := protocol.Text(r.Record, "id")
			first, e := f.services[0].UploadCandidate(ctx, id, f.owner, b)
			must(t, e)
			if kind != "zero" {
				_, e = f.controller.RegisterReceipt(ctx, uid(), id, ReservationRef(r), first, f.actor)
				must(t, e)
			}
			if kind == "forged" || kind == "same-domain" {
				receipt, e := f.services[1].UploadCandidate(ctx, id, f.owner, b)
				must(t, e)
				if kind == "forged" {
					receipt["signature"] = protocol.Base(make([]byte, 64))
				} else {
					reg := f.registrations[1]
					reg.Binding = protocol.Obj(object(reg), "binding")
					reg.Binding["failureDomainId"] = f.registrations[0].Binding["failureDomainId"]
					v, e := f.store.Read(ctx, "admissions/"+f.membership.Archives[1])
					must(t, e)
					var admission protocol.Object
					must(t, load(v, "admissions/"+f.membership.Archives[1], &admission))
					admission["targetIdentityDigest"] = archive.IdentityDigest(reg)
					admission["signature"], e = f.catalog.Profile.Sign("hostAdmission", protocol.Unsigned(admission), f.guardKeys[1])
					must(t, e)
					reg.AdmissionDigest = protocol.MustDigest(admission)
					f.put(t, "archives/"+f.membership.Archives[1], reg)
					f.put(t, "admissions/"+f.membership.Archives[1], admission)
					receipt["archive"] = reg.Binding
					receipt["signature"], e = f.catalog.Profile.Sign("archiveReceipt", protocol.Unsigned(receipt), f.services[1].Key)
					must(t, e)
					v, e = f.store.Read(ctx, archiveKeys(f.membership.Archives)...)
					must(t, e)
					domain, e := f.controller.verifyReceipt(v, r, receipt)
					must(t, e)
					if domain != protocol.Text(f.registrations[0].Binding, "failureDomainId") {
						t.Fatal("same-domain fixture was not current/authentic")
					}
				}
				f.put(t, candidateReceiptKey(id, f.membership.Archives[1]), receipt)
			}
			if kind == "wrong-archive" {
				f.put(t, candidateReceiptKey(id, f.membership.Archives[1]), first)
			}
			if _, e = f.controller.Ready(ctx, uid(), id, ReservationRef(r), f.actor); e == nil {
				t.Fatal("invalid evidence reached READY")
			}
			v, e := f.store.Read(ctx, "head")
			must(t, e)
			var head protocol.Object
			must(t, load(v, "head", &head))
			if !protocol.Equal(head, a.Intent.ExpectedHead) {
				t.Fatal("invalid evidence changed the head")
			}
		})
	}
}

func TestSurvivingCopiesRecheckedAtFinalCAS(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	a, _, r := f.ready(t)
	id := protocol.Text(r.Record, "id")
	once := false
	f.controller.Fault = func(point string) error {
		if point == "before-final-cas" && !once {
			once = true
			restartArchive(t, f, 0)
		}
		return nil
	}
	if _, e := f.controller.Commit(ctx, uid(), id, ReservationRef(r), f.actor); e == nil {
		t.Fatal("restart after copy validation escaped final CAS")
	}
	v, e := f.store.Read(ctx, "head")
	must(t, e)
	var head protocol.Object
	must(t, load(v, "head", &head))
	if !protocol.Equal(head, a.Intent.ExpectedHead) {
		t.Fatal("stale final comparison published the candidate")
	}
}

func TestReadyCopiesCannotBeReplacedOrExpanded(t *testing.T) {
	a, b, c := Ref(uid(), "1", protocol.Object{"copy": "first"}), Ref(uid(), "1", protocol.Object{"copy": "second"}), Ref(uid(), "1", protocol.Object{"copy": "third"})
	if !survivingReadyCopies([]any{a, b, c}, []any{a, b}) {
		t.Fatal("unchanged surviving subset rejected")
	}
	for _, current := range [][]any{{a}, {a, a}, {a, Ref(protocol.Text(b, "id"), "2", protocol.Object{"copy": "replacement"})}, {a, b, c}} {
		if survivingReadyCopies([]any{a, b}, current) {
			t.Fatal("unapproved/replaced/duplicate receipt evidence accepted")
		}
	}
}

func TestReadyCandidateRequiresTwoSurvivors(t *testing.T) {
	for _, survivors := range []int{1, 0} {
		t.Run(fmt.Sprint(survivors), func(t *testing.T) {
			f := fixture(t)
			ctx := context.Background()
			a, b, r := f.preparing(t)
			id := protocol.Text(r.Record, "id")
			for _, s := range f.services {
				receipt, e := s.UploadCandidate(ctx, id, f.owner, b)
				must(t, e)
				_, e = f.controller.RegisterReceipt(ctx, uid(), id, ReservationRef(r), receipt, f.actor)
				must(t, e)
			}
			var e error
			r, e = f.controller.Ready(ctx, uid(), id, ReservationRef(r), f.actor)
			must(t, e)
			for index := 2; index >= survivors; index-- {
				restartArchive(t, f, index)
			}
			if _, e = f.controller.Commit(ctx, uid(), id, ReservationRef(r), f.actor); e == nil {
				t.Fatal("insufficient surviving copies committed")
			}
			v, e := f.store.Read(ctx, "head")
			must(t, e)
			var head protocol.Object
			must(t, load(v, "head", &head))
			if !protocol.Equal(head, a.Intent.ExpectedHead) {
				t.Fatal("head changed without enough current copies")
			}
		})
	}
}
