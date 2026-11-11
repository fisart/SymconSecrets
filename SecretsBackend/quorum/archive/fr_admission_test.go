package archive

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/consensus"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/trust"
)

// The delayed capability is validly signed and was durably consumed before the replacement.
func TestFR01DelayedAdmissionCannotReplaceNewerBoot(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	old := f.Registrations[0]
	cloneReg := func(r Registration) Registration {
		b, _ := json.Marshal(r)
		var n Registration
		json.Unmarshal(b, &n)
		return n
	}
	delayed := cloneReg(old)
	delayed.State = "VERIFYING"
	delayed.Binding["bootId"] = randomB64()
	delayed.Binding["storageGeneration"] = randomB64()
	delayed.Binding["registrationVersion"] = "2"
	delayedAttempt := attempt()
	delayed, delayedRuntime, _ := f.admit(t, 0, delayed, f.Paths[0], delayedAttempt.ID)
	// Admission counter 2 is consumed, but its quorum Boot has not happened.
	newerPath := filepath.Join(t.TempDir(), "newer-volume")
	if e := os.Mkdir(newerPath, 0700); e != nil {
		t.Fatal(e)
	}
	newer := cloneReg(old)
	newer.State = "VERIFYING"
	newer.Binding["bootId"] = randomB64()
	newer.Binding["storageGeneration"] = randomB64()
	newer.Binding["registrationVersion"] = "3"
	newerAttempt := attempt()
	newer, newerRuntime, _ := f.admit(t, 0, newer, newerPath, newerAttempt.ID)
	// Admission counters and catalog registration versions are separate sequences.
	newer.Binding["registrationVersion"] = "2"
	if e := f.Catalog.Boot(ctx, newerAttempt, old, newer, newerRuntime); e != nil {
		t.Fatal(e)
	}
	current, e := Open(newerPath, f.IDs[0], f.Services[0].Key, f.Catalog, newerRuntime)
	if e != nil {
		t.Fatal(e)
	}
	defer current.Close()
	if e = current.current(ctx); e != nil {
		t.Fatal(e)
	}
	// Re-submit the unused counter-2 capability against the now-current predecessor.
	delayed.Binding["registrationVersion"] = "3"
	if e = f.Catalog.Boot(ctx, delayedAttempt, newer, delayed, delayedRuntime); e == nil {
		t.Fatal("older unused admission replaced a newer boot")
	}
	// Even if the old directory accepts its unused counter-2 marker, the
	// quorum's current admission must prevent receipts and activation.
	restored, e := Open(f.Paths[0], f.IDs[0], f.Services[0].Key, f.Catalog, delayedRuntime)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	if _, e = restored.Reattest(ctx, attempt(), protocol.Text(f.Bundle.Ref, "id")); !errors.Is(e, ErrRuntimeFenced) {
		t.Fatal("old volume reattested", e)
	}
	if _, e = restored.Activate(ctx, attempt()); !errors.Is(e, ErrRuntimeFenced) {
		t.Fatal("old volume activated", e)
	}
	if e = current.current(ctx); e != nil {
		t.Fatal("replacement was fenced", e)
	}
	snapshot, e := f.Catalog.Store.Read(ctx, "admissions/"+f.IDs[0], archiveKey(f.IDs[0]))
	if e != nil {
		t.Fatal(e)
	}
	var installed protocol.Object
	if e = json.Unmarshal(snapshot.Values["admissions/"+f.IDs[0]].Bytes, &installed); e != nil {
		t.Fatal(e)
	}
	if protocol.Text(installed, "admissionCounter") != "3" {
		t.Fatal(installed)
	}
	if string(snapshot.Values[archiveKey(f.IDs[0])].Bytes) != string(consensus.JSON(newer)) {
		t.Fatal("replacement registration changed")
	}
	f.health(t, "UNAVAILABLE")

	// Exact retry resolves the original outcome even after current state moved;
	// it never allocates another generation or reactivates a historical one.
	var historical *consensus.AlreadyDecided
	if e = f.Catalog.Boot(ctx, newerAttempt, old, newer, newerRuntime); !errors.As(e, &historical) {
		t.Fatal("lost acknowledgement did not resolve history", e)
	}
	after, e := f.Catalog.Store.Read(ctx, "admissions/"+f.IDs[0], archiveKey(f.IDs[0]))
	if e != nil || after.Revision != snapshot.Revision {
		t.Fatal("history mutated current state", e)
	}
	changed := newerAttempt
	changed.Digest = protocol.MustDigest("different action")
	if e = f.Catalog.Boot(ctx, changed, old, newer, newerRuntime); !errors.Is(e, consensus.ErrIDReuse) {
		t.Fatal("different action reused boot ID", e)
	}
}

func TestFR01AdmissionAuthorityCannotResetCounter(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	f.boot(t, 0)
	current := f.Registrations[0]
	guard, guardID := f.Guards[0], f.GuardIDs[0]
	for _, kind := range []string{"same-counter", "different-guard", "different-key-same-id"} {
		t.Run(kind, func(t *testing.T) {
			f.Guards[0], f.GuardIDs[0] = guard, guardID
			var next Registration
			json.Unmarshal(consensus.JSON(current), &next)
			next.State = "VERIFYING"
			next.Binding["bootId"] = randomB64()
			next.Binding["storageGeneration"] = randomB64()
			// The synthetic guard is reset solely to manufacture an otherwise
			// valid capability; the catalog must independently refuse it.
			next.Binding["registrationVersion"] = "2"
			if kind != "same-counter" {
				next.Binding["registrationVersion"] = "10"
			}
			f.GuardJournals[0] = filepath.Join(t.TempDir(), "guard")
			if e := os.Mkdir(f.GuardJournals[0], 0700); e != nil {
				t.Fatal(e)
			}
			j, e := trust.OpenAdmission(f.GuardJournals[0])
			if e != nil {
				t.Fatal(e)
			}
			if e = j.Initialize(); e != nil {
				t.Fatal(e)
			}
			j.Close()
			if kind != "same-counter" {
				_, f.Guards[0], _ = ed25519.GenerateKey(nil)
			}
			if kind == "different-guard" {
				f.GuardIDs[0] = randomB64()
			}
			a := attempt()
			next, runtime, _ := f.admit(t, 0, next, f.Paths[0], a.ID)
			next.Binding["registrationVersion"] = "3"
			if e = f.Catalog.Boot(ctx, a, current, next, runtime); e == nil {
				t.Fatal("unapproved admission reset accepted")
			}
			if e = f.Services[0].current(ctx); e != nil {
				t.Fatal("current service fenced", e)
			}
		})
	}
}

func TestFR01CompletedBootRemainsHistoryAfterSupersession(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	predecessor := f.Registrations[0]
	f.boot(t, 0)
	first, runtime := f.Registrations[0], f.Runtimes[0]
	id := protocol.Text(runtime.Record(), "bootOperationId")
	a := consensus.Attempt{ID: id, Digest: protocol.MustDigest(protocol.Object{"operationId": id})}
	f.boot(t, 0)
	snapshot, e := f.Catalog.Store.Read(ctx, archiveKey(f.IDs[0]), "admissions/"+f.IDs[0])
	if e != nil {
		t.Fatal(e)
	}
	var historical *consensus.AlreadyDecided
	if e = f.Catalog.Boot(ctx, a, predecessor, first, runtime); !errors.As(e, &historical) {
		t.Fatal("superseded completed boot did not resolve history", e)
	}
	after, e := f.Catalog.Store.Read(ctx, archiveKey(f.IDs[0]), "admissions/"+f.IDs[0])
	if e != nil || after.Revision != snapshot.Revision {
		t.Fatal("old history changed current generation", e)
	}
	if e = f.Services[0].current(ctx); e != nil {
		t.Fatal("new current runtime fenced", e)
	}
	altered := first
	altered.State = "ACTIVE"
	if e = f.Catalog.Boot(ctx, a, predecessor, altered, runtime); !errors.Is(e, consensus.ErrIDReuse) {
		t.Fatal("altered boot payload reused history", e)
	}
}
