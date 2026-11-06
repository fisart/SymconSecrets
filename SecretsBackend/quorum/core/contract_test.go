package core

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/consensus"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
)

func TestOriginalIntentSignatureScopeAndOneUseApproval(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	approved, _ := f.change(t)
	clone := func() ApprovedIntent {
		var a ApprovedIntent
		must(t, json.Unmarshal(consensus.JSON(approved), &a))
		return a
	}
	for _, kind := range []string{"signature", "revision", "class", "duplicate-recipient", "local-owner", "numeric", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			a := clone()
			switch kind {
			case "signature":
				a.Intent.NewScopeDigest = protocol.MustDigest("changed")
			case "revision":
				a.Intent.NewRevision = "9"
			case "class":
				a.Intent.ChangeClass = "SECURITY"
			case "duplicate-recipient":
				a.Intent.Outbox = append(a.Intent.Outbox, a.Intent.Outbox[0])
			case "local-owner":
				a.Intent.ChangeClass = "LOCAL_EDIT"
			case "numeric":
				a.Intent.Owner["nodeFence"] = float64(1)
			case "unknown-field":
				a.Intent.Owner["extra"] = "invalid"
			}
			if _, e := f.controller.Reserve(ctx, uid(), a, f.actor); e == nil {
				t.Fatal("invalid original intent accepted")
			}
		})
	}
	original := clone()
	snapshot := protocol.Obj(object(map[string]any{"head": original.Intent.CandidateHead}), "head")
	f.controller.Fault = func(point string) error {
		if point == "before-final-cas" {
			original.Intent.CandidateHead["coreDigest"] = protocol.MustDigest("caller mutation")
		}
		return nil
	}
	r, e := f.controller.Reserve(ctx, uid(), original, f.actor)
	must(t, e)
	if !protocol.Equal(r.Record["candidate"], snapshot) {
		t.Fatal("caller mutation changed owned intent")
	}
	reused := clone()
	reused.Intent.UserOperationID = uid()
	reused, e = Signed(reused, f.ownerKey)
	must(t, e)
	if _, e = f.controller.Reserve(ctx, uid(), reused, f.actor); !errors.Is(e, ErrAuthorization) {
		t.Fatal("approval reused for another original intent", e)
	}
	// The pending reservation did not get replaced by that failed attempt.
	v, e := f.store.Read(ctx, reservationKey(protocol.Text(r.Record, "id")))
	must(t, e)
	var current Reservation
	must(t, load(v, reservationKey(protocol.Text(r.Record, "id")), &current))
	if !protocol.Equal(ReservationRef(r), ReservationRef(current)) {
		t.Fatal("failed attempt changed original")
	}
}
func TestHardwareAndDiffFactsCannotBeOmitted(t *testing.T) {
	for _, kind := range []string{"hardware", "diff", "presence", "verification"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			ctx := context.Background()
			if kind == "hardware" {
				f.credential.HardwareVerified = false
				f.put(t, "core/credentials/"+f.credential.ID, f.credential)
			}
			a, _ := f.change(t)
			if kind != "hardware" {
				v, e := f.store.Read(ctx, approvalKey(a))
				must(t, e)
				var approval Approval
				must(t, load(v, approvalKey(a), &approval))
				switch kind {
				case "diff":
					approval.DiffVerified = false
				case "presence":
					approval.UserPresence = false
				case "verification":
					approval.UserVerification = false
				}
				f.putLease(t, approvalKey(a), consensus.JSON(approval), f.approvalLease)
				a.ApprovalRef = Ref(approval.ID, approval.Version, approval)
				a, e = Signed(a, f.ownerKey)
				must(t, e)
			}
			if _, e := f.controller.Reserve(ctx, uid(), a, f.actor); !errors.Is(e, ErrAuthorization) {
				t.Fatal("missing verified authorization fact accepted", e)
			}
		})
	}
}
func TestCandidateDurabilityRetryAndIndependentDomains(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	_, bytes, r := f.preparing(t)
	id := protocol.Text(r.Record, "id")
	// Simulate an interrupted reply after durable local bytes, then fully reverify.
	failure := errors.New("interrupted before receipt")
	f.services[0].Fault = func(point string) error {
		if point == "after-candidate-durability" {
			return failure
		}
		return nil
	}
	if _, e := f.services[0].UploadCandidate(ctx, id, f.owner, bytes); !errors.Is(e, failure) {
		t.Fatal(e)
	}
	f.services[0].Fault = nil
	receipt, e := f.services[0].UploadCandidate(ctx, id, f.owner, bytes)
	must(t, e)
	_, e = f.controller.RegisterReceipt(ctx, uid(), id, ReservationRef(r), receipt, f.actor)
	must(t, e)
	// Two hosts claiming the same approved failure domain do not make READY.
	reg := f.registrations[1]
	reg.Binding = protocol.Obj(object(reg), "binding")
	reg.Binding["failureDomainId"] = f.registrations[0].Binding["failureDomainId"]
	f.put(t, "archives/"+f.membership.Archives[1], reg)
	receipt, e = f.services[1].UploadCandidate(ctx, id, f.owner, bytes)
	must(t, e)
	_, e = f.controller.RegisterReceipt(ctx, uid(), id, ReservationRef(r), receipt, f.actor)
	must(t, e)
	if _, e = f.controller.Ready(ctx, uid(), id, ReservationRef(r), f.actor); e == nil {
		t.Fatal("two receipts from one domain accepted")
	}
}

func TestCoreOriginalContractGoldenVector(t *testing.T) {
	raw, e := os.ReadFile("intent-vector.json")
	must(t, e)
	var vector struct {
		Contract          string         `json:"contract"`
		PublicTestSeedHex string         `json:"publicTestSeedHex"`
		PublicKey         string         `json:"publicKey"`
		IntentDigest      string         `json:"intentDigest"`
		Approved          ApprovedIntent `json:"approved"`
	}
	must(t, decode(raw, &vector))
	if vector.Contract != "CoreUserIntent/v1" {
		t.Fatal("wrong contract")
	}
	must(t, validateIntent(vector.Approved))
	must(t, verify(vector.Approved, vector.PublicKey))
	if Digest(vector.Approved.Intent) != vector.IntentDigest {
		t.Fatal("user digest changed")
	}
	seed, e := hex.DecodeString(vector.PublicTestSeedHex)
	must(t, e)
	signed, e := Signed(vector.Approved, ed25519.NewKeyFromSeed(seed))
	must(t, e)
	if signed.Signature != vector.Approved.Signature {
		t.Fatal("canonical signing representation changed")
	}
	p, _ := protocol.Load()
	if e = p.Verify("ownerProposal", protocol.Unsigned(object(vector.Approved)), vector.Approved.Signature, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("new user signature accepted under frozen owner-proposal domain")
	}
}
