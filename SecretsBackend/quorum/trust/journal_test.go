package trust

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
)

func fixtures(t *testing.T) protocol.Object {
	t.Helper()
	var p protocol.Object
	if e := json.Unmarshal(protocol.ProfileBytes(), &p); e != nil {
		t.Fatal(e)
	}
	return protocol.Obj(p, "illustrativeVectors")
}

func TestRecoveryJournalChildProcess(t *testing.T) {
	path := os.Getenv("SYMCON_RECOVERY_CHILD_DIR")
	if path == "" {
		t.Skip("recovery crash child only")
	}
	point := os.Getenv("SYMCON_RECOVERY_POINT")
	ready := os.Getenv("SYMCON_RECOVERY_READY")
	r, c, _ := recovery(t)
	j, e := OpenRecovery(path, func(p string) error {
		if p == point {
			if e := os.WriteFile(ready, []byte(p), 0600); e != nil {
				t.Fatal(e)
			}
			select {}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	if _, e = j.Apply(r, c); e != nil {
		t.Fatal(e)
	}
	t.Fatal("crash point not reached")
}
func TestRecoverySurvivesProcessKill(t *testing.T) {
	for _, point := range []string{"after-prepared", "after-floor-before-ack"} {
		t.Run(point, func(t *testing.T) {
			path := privateDir(t)
			r, c, floor := recovery(t)
			j, e := OpenRecovery(path, nil)
			if e != nil {
				t.Fatal(e)
			}
			if e = j.Initialize(floor); e != nil {
				t.Fatal(e)
			}
			j.Close()
			ready := filepath.Join(t.TempDir(), "fault-reached")
			cmd := exec.Command(os.Args[0], "-test.run=^TestRecoveryJournalChildProcess$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), "SYMCON_RECOVERY_CHILD_DIR="+path, "SYMCON_RECOVERY_POINT="+point, "SYMCON_RECOVERY_READY="+ready)
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			killed := false
			defer func() {
				if !killed {
					cmd.Process.Kill()
					cmd.Wait()
				}
			}()
			deadline := time.Now().Add(8 * time.Second)
			reached := false
			for time.Now().Before(deadline) {
				if _, e = os.Stat(ready); e == nil {
					reached = true
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !reached {
				t.Fatal("recovery child did not reach crash point")
			}
			cmd.Process.Kill()
			cmd.Wait()
			killed = true
			j, e = OpenRecovery(path, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			state, locked, e := j.State()
			if e != nil {
				t.Fatal(e)
			}
			if point == "after-prepared" && (!locked || !protocol.Equal(state.TrustPack, floor.TrustPack)) {
				t.Fatal("killed PREPARED recovery did not stay locked")
			}
			if point == "after-floor-before-ack" && (locked || !protocol.Equal(state.TrustPack, r["newTrustPack"])) {
				t.Fatal("acknowledged-boundary floor lost")
			}
			historical, e := j.Apply(r, c)
			if e != nil {
				t.Fatal(e)
			}
			if historical != (point == "after-floor-before-ack") {
				t.Fatal("killed recovery applied twice")
			}
		})
	}
}
func TestIncompleteRecoveryFloorFailsClosed(t *testing.T) {
	path := privateDir(t)
	r, c, floor := recovery(t)
	j, e := OpenRecovery(path, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	if e = j.Initialize(floor); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(path, "recovery.json"), []byte(`{}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = j.State(); e == nil {
		t.Fatal("incomplete floor reported unlocked")
	}
	if _, e = j.Apply(r, c); e == nil {
		t.Fatal("incomplete floor accepted recovery")
	}
}
func privateDir(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "independent-guard")
	if e := os.Mkdir(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
func admission(t *testing.T) (protocol.Object, AdmissionContext) {
	t.Helper()
	v := protocol.Obj(fixtures(t), "hostAdmission")
	r := protocol.Obj(v, "record")
	pub, _ := protocol.Unbase(protocol.Text(v, "publicKey"), 32)
	expected := protocol.Object{}
	for _, k := range []string{"clusterId", "realmId", "incarnation", "nativeClusterId", "trustRevision", "componentKind", "componentId", "targetIdentityDigest", "bootOperationId", "bootId", "storageGeneration", "volumeIdentityDigest", "restartClass", "trustPackDigest", "hostGuardKeyId"} {
		expected[k] = r[k]
	}
	return r, AdmissionContext{Expected: expected, PublicKeys: map[string]ed25519.PublicKey{protocol.Text(r, "hostGuardKeyId"): pub}}
}
func recovery(t *testing.T) (protocol.Object, RecoveryContext, RecoveryFloor) {
	t.Helper()
	v := protocol.Obj(fixtures(t), "recoveryManifest")
	r := protocol.Obj(v, "record")
	pub, _ := protocol.Unbase(protocol.Text(v, "publicKey"), 32)
	evidence := map[string][]byte{}
	for _, k := range []string{"fencingEvidenceDigest", "revocationPlanDigest", "dataLossDispositionDigest", "independentApprovalDigest"} {
		evidence[k] = []byte("public test evidence: " + k)
		r[k] = evidenceDigest(evidence[k])
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(128 + i)
	}
	p, _ := protocol.Load()
	r["signature"], _ = p.Sign("recoveryManifest", protocol.Unsigned(r), ed25519.NewKeyFromSeed(seed))
	c := RecoveryContext{PublicKeys: map[string]ed25519.PublicKey{protocol.Text(r, "recoveryKeyId"): pub}, Evidence: evidence, VerifyFencing: func([]byte) error { return nil }, VerifyIndependentApproval: func([]byte) error { return nil }}
	floor := RecoveryFloor{TrustPack: protocol.Obj(protocol.Obj(v, "trustedContext"), "acceptedTrustPack"), Sequence: "0"}
	return r, c, floor
}
func TestAdmissionDurableConsumption(t *testing.T) {
	path := privateDir(t)
	j, e := OpenAdmission(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = j.Initialize(); e != nil {
		t.Fatal(e)
	}
	r, c := admission(t)
	historical, e := j.Consume(r, c)
	if e != nil || historical {
		t.Fatal(historical, e)
	}
	j.Close()
	j, e = OpenAdmission(path)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	historical, e = j.Consume(r, c)
	if e != nil || !historical {
		t.Fatal(historical, e)
	}
	c.Expected["bootId"] = protocol.Base(make([]byte, 32))
	if _, e = j.Consume(r, c); e == nil {
		t.Fatal("old boot restored")
	}
}
func TestAdmissionBindingAndSignatureNegatives(t *testing.T) {
	for _, field := range []string{"componentId", "incarnation", "storageGeneration", "nativeClusterId", "targetIdentityDigest", "volumeIdentityDigest"} {
		t.Run(field, func(t *testing.T) {
			path := privateDir(t)
			j, _ := OpenAdmission(path)
			defer j.Close()
			j.Initialize()
			r, c := admission(t)
			c.Expected[field] = "wrong independent context"
			if _, e := j.Consume(r, c); e == nil {
				t.Fatal("wrong context admitted")
			}
		})
	}
	t.Run("wrongSigner", func(t *testing.T) {
		j, _ := OpenAdmission(privateDir(t))
		defer j.Close()
		j.Initialize()
		r, c := admission(t)
		c.PublicKeys[protocol.Text(r, "hostGuardKeyId")] = make([]byte, 32)
		if _, e := j.Consume(r, c); e == nil {
			t.Fatal("wrong signer")
		}
	})
}
func TestRecoveryFaultWindows(t *testing.T) {
	for _, point := range []string{"after-prepared", "before-floor", "after-floor-before-ack"} {
		t.Run(point, func(t *testing.T) {
			path := privateDir(t)
			r, c, floor := recovery(t)
			j, e := OpenRecovery(path, func(p string) error {
				if p == point {
					return errors.New("simulated interrupted operation")
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			if e = j.Initialize(floor); e != nil {
				t.Fatal(e)
			}
			if _, e = j.Apply(r, c); e == nil {
				t.Fatal("fault not reached")
			}
			j.Close()
			j, e = OpenRecovery(path, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			observed, locked, e := j.State()
			if e != nil {
				t.Fatal(e)
			}
			if point != "after-floor-before-ack" {
				if !locked || !protocol.Equal(observed.TrustPack, floor.TrustPack) {
					t.Fatal("prepared state failed closed")
				}
			} else if locked || !protocol.Equal(observed.TrustPack, r["newTrustPack"]) {
				t.Fatal("lost-ack durable state")
			}
			historical, e := j.Apply(r, c)
			if e != nil {
				t.Fatal(e)
			}
			if (point == "after-floor-before-ack") != historical {
				t.Fatal("retry classification")
			}
			_, locked, e = j.State()
			if e != nil || locked {
				t.Fatal("recovery did not finish")
			}
			historical, e = j.Apply(r, c)
			if e != nil || !historical {
				t.Fatal("recovery replay executed twice")
			}
		})
	}
}
func TestRecoveryRejectsMissingFencingAndSelfPinnedSigner(t *testing.T) {
	for _, name := range []string{"missingValidator", "badEvidence", "wrongSigner", "fencingRefused"} {
		t.Run(name, func(t *testing.T) {
			j, _ := OpenRecovery(privateDir(t), nil)
			defer j.Close()
			r, c, floor := recovery(t)
			j.Initialize(floor)
			switch name {
			case "missingValidator":
				c.VerifyFencing = nil
			case "badEvidence":
				c.Evidence["fencingEvidenceDigest"] = []byte("wrong")
			case "wrongSigner":
				c.PublicKeys = map[string]ed25519.PublicKey{}
			case "fencingRefused":
				c.VerifyFencing = func([]byte) error { return errors.New("old majority not fenced") }
			}
			if _, e := j.Apply(r, c); e == nil {
				t.Fatal("unsafe recovery accepted")
			}
			current, locked, e := j.State()
			if e != nil || locked || !protocol.Equal(current.TrustPack, floor.TrustPack) {
				t.Fatal("rejected recovery changed floor")
			}
		})
	}
}
