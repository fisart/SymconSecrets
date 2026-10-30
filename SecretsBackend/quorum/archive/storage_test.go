package archive

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	clientv3 "go.etcd.io/etcd/client/v3"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/consensus"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/internal/testcluster"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/trust"
)

func TestEtcdMemberProcess(t *testing.T) { testcluster.MemberProcess(t) }
func attempt() consensus.Attempt {
	id := testcluster.UUID()
	return consensus.Attempt{ID: id, Digest: protocol.MustDigest(protocol.Object{"operationId": id})}
}

type workerConfig struct {
	Directory, ID, PrivateKey, Cluster, Realm, Native, Bundle, Point, Ready string
	Endpoints                                                               []string
	Attempt                                                                 consensus.Attempt
	Admission                                                               protocol.Object
	GuardPublic, GuardJournal, GuardKeyID                                   string
	Expected                                                                protocol.Object
}

func TestArchiveWorkerProcess(t *testing.T) {
	path := os.Getenv("SYMCON_ARCHIVE_WORKER_CONFIG")
	if path == "" {
		t.Skip("archive crash worker only")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var input workerConfig
	if e = json.Unmarshal(b, &input); e != nil {
		t.Fatal(e)
	}
	client, e := clientv3.New(clientv3.Config{Endpoints: input.Endpoints, DialTimeout: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	store, e := consensus.New(client, input.Cluster, input.Realm, input.Native)
	if e != nil {
		t.Fatal(e)
	}
	catalog, e := NewCatalog(store)
	if e != nil {
		t.Fatal(e)
	}
	key, e := protocol.Unbase(input.PrivateKey, 64)
	if e != nil {
		t.Fatal(e)
	}
	journal, e := trust.OpenAdmission(input.GuardJournal)
	if e != nil {
		t.Fatal(e)
	}
	defer journal.Close()
	pub, e := protocol.Unbase(input.GuardPublic, 32)
	if e != nil {
		t.Fatal(e)
	}
	runtime, e := journal.AdmitDirectory(input.Admission, trust.AdmissionContext{Expected: input.Expected, PublicKeys: map[string]ed25519.PublicKey{input.GuardKeyID: pub}}, input.Directory, verifyTestVolume)
	if e != nil {
		t.Fatal(e)
	}
	service, e := Open(input.Directory, input.ID, ed25519.PrivateKey(key), catalog, runtime)
	if e != nil {
		t.Fatal(e)
	}
	defer service.Close()
	service.Fault = func(point string) error {
		if point == input.Point {
			if e = os.WriteFile(input.Ready, []byte(point), 0600); e != nil {
				t.Fatal(e)
			}
			select {}
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, e = service.Reattest(ctx, input.Attempt, input.Bundle); e != nil {
		t.Fatal(e)
	}
	t.Fatal("archive crash point not reached")
}
func TestArchiveWorkerSIGKILLRecovery(t *testing.T) {
	for _, point := range []string{"after-local-durability", "after-registration-before-ack"} {
		t.Run(point, func(t *testing.T) {
			f := fixture(t)
			f.boot(t, 0)
			s := f.Services[0]
			id := protocol.Text(f.Bundle.Ref, "id")
			a := attempt()
			ctx := context.Background()
			ready := filepath.Join(t.TempDir(), "crash-point")
			path := f.Paths[0]
			worker := s
			var e error
			input := workerConfig{Directory: path, ID: s.ID, PrivateKey: protocol.Base(s.Key), Cluster: protocol.Text(f.Head, "clusterId"), Realm: protocol.Text(f.Head, "realmId"), Native: f.Cluster.NativeID, Bundle: id, Point: point, Ready: ready, Endpoints: f.Cluster.Endpoints, Attempt: a, Admission: s.runtime.Record(), GuardPublic: protocol.Base(f.Guards[0].Public().(ed25519.PublicKey)), GuardJournal: f.GuardJournals[0], GuardKeyID: f.GuardIDs[0], Expected: f.Contexts[0].Expected}
			configPath := filepath.Join(t.TempDir(), "worker.json")
			if e = os.WriteFile(configPath, consensus.JSON(input), 0600); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestArchiveWorkerProcess$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), "SYMCON_ARCHIVE_WORKER_CONFIG="+configPath)
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
			reached := false
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) {
				if _, e = os.Stat(ready); e == nil {
					reached = true
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !reached {
				t.Fatal("archive worker did not reach crash point")
			}
			cmd.Process.Kill()
			cmd.Wait()
			killed = true
			result, e := worker.Reattest(ctx, a, id)
			if e != nil {
				t.Fatal(e)
			}
			if result.Historical != (point == "after-registration-before-ack") {
				t.Fatal("archive crash retry misclassified")
			}
			if _, e = worker.Activate(ctx, attempt()); e != nil {
				t.Fatal(e)
			}
			f.health(t, "DEGRADED")
		})
	}
}
func ref(id string) protocol.Object {
	return protocol.Object{"id": id, "version": "1", "digest": hashBytes([]byte(id))}
}
func randomB64() string { b := make([]byte, 32); rand.Read(b); return protocol.Base(b) }
func encrypted(t *testing.T, b []byte) []byte {
	t.Helper()
	key := make([]byte, 16)
	rand.Read(key)
	block, e := aes.NewCipher(key)
	if e != nil {
		t.Fatal(e)
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	return append(nonce, g.Seal(nil, nonce, b, []byte("quorum-storage-test-v2"))...)
}

type archiveFixture struct {
	Paths, GuardJournals, GuardIDs []string
	Guards                         []ed25519.PrivateKey
	Runtimes                       []*trust.AdmittedRuntime
	Contexts                       []trust.AdmissionContext
	Cluster                        *testcluster.Cluster
	Catalog                        *Catalog
	Services                       []*Service
	Registrations                  []Registration
	IDs                            []string
	Bundle                         Bundle
	Bytes                          []byte
	Head                           protocol.Object
}

func fixture(t *testing.T) *archiveFixture {
	t.Helper()
	f := &archiveFixture{Cluster: testcluster.New(t)}
	cluster, realm := testcluster.UUID(), testcluster.UUID()
	store, e := consensus.New(f.Cluster.Client, cluster, realm, f.Cluster.NativeID)
	if e != nil {
		t.Fatal(e)
	}
	f.Catalog, e = NewCatalog(store)
	if e != nil {
		t.Fatal(e)
	}
	manifest := encrypted(t, []byte(`{"typed":"encrypted test manifest"}`))
	object := encrypted(t, []byte("test secret value"))
	objectRef := protocol.Object{"id": randomB64(), "kind": "vault", "schema": "1", "length": number(len(object)), "digest": hashBytes(object), "keyId": randomB64(), "scopeId": testcluster.UUID()}
	var index string
	f.Bytes, index, e = BuildBundle(manifest, []protocol.Object{objectRef}, [][]byte{object})
	if e != nil {
		t.Fatal(e)
	}
	id := testcluster.UUID()
	commit := testcluster.UUID()
	f.Bundle = Bundle{Ref: ref(id), Descriptor: protocol.Object{"commitId": commit, "bundleDigest": hashBytes(f.Bytes), "manifestDigest": hashBytes(manifest), "bundleLength": number(len(f.Bytes))}, IndexDigest: index, Protected: true}
	f.Head = protocol.Object{"clusterId": cluster, "realmId": realm, "incarnation": randomB64(), "index": "7", "commitId": commit, "coreDigest": hashBytes(manifest), "manifestDigest": hashBytes(manifest), "keyEpoch": "1"}
	referenceIndex := ref(testcluster.UUID())
	records := map[string][]byte{"lineage": []byte(f.Cluster.NativeID), "head": consensus.JSON(f.Head), "reference-index": consensus.JSON(referenceIndex), bundleKey(id): consensus.JSON(f.Bundle)}
	keys := []ed25519.PrivateKey{}
	paths := []string{}
	for i := 0; i < 3; i++ {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		keys = append(keys, key)
		id := testcluster.UUID()
		f.IDs = append(f.IDs, id)
		reg := Registration{Binding: protocol.Object{"archiveId": id, "failureDomainId": testcluster.UUID(), "storageGeneration": randomB64(), "registrationVersion": "1", "bootId": randomB64()}, State: "ACTIVE", KeyID: randomB64(), PublicKey: protocol.Base(pub)}

		path := filepath.Join(t.TempDir(), "private-archive")
		if e = os.Mkdir(path, 0700); e != nil {
			t.Fatal(e)
		}
		paths = append(paths, path)
		f.Paths = append(f.Paths, path)
		_, guard, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		f.Guards = append(f.Guards, guard)
		f.GuardIDs = append(f.GuardIDs, randomB64())
		journalPath := filepath.Join(t.TempDir(), "independent-guard")
		if e = os.Mkdir(journalPath, 0700); e != nil {
			t.Fatal(e)
		}
		f.GuardJournals = append(f.GuardJournals, journalPath)
		j, e := trust.OpenAdmission(journalPath)
		if e != nil {
			t.Fatal(e)
		}
		if e = j.Initialize(); e != nil {
			t.Fatal(e)
		}
		j.Close()
		reg, runtime, context := f.admit(t, i, reg, path, attempt().ID)
		f.Registrations = append(f.Registrations, reg)
		f.Runtimes = append(f.Runtimes, runtime)
		f.Contexts = append(f.Contexts, context)
		records[archiveKey(id)] = consensus.JSON(reg)
		records["admissions/"+id] = consensus.JSON(runtime.Record())
	}
	for _, id := range f.IDs {
		records[inventoryKey(id)] = consensus.JSON(Inventory{Ref: ref(testcluster.UUID()), BundleIDs: []string{protocol.Text(f.Bundle.Ref, "id")}, ArchiveIDs: f.IDs})
	}
	if e = store.Initialize(context.Background(), attempt(), records); e != nil {
		t.Fatal(e)
	}
	for i, id := range f.IDs {
		s, e := Open(paths[i], id, keys[i], f.Catalog, f.Runtimes[i])
		if e != nil {
			t.Fatal(e)
		}
		f.Services = append(f.Services, s)
		t.Cleanup(func() { s.Close() })
		if e = s.Preserve(f.Bundle, f.Bytes); e != nil {
			t.Fatal(e)
		}
	}
	return f
}
func (f *archiveFixture) boot(t *testing.T, i int) { f.replace(t, i, f.Paths[i]) }
func (f *archiveFixture) replace(t *testing.T, i int, path string) {
	t.Helper()
	old := f.Registrations[i]
	b, _ := json.Marshal(old)
	var next Registration
	json.Unmarshal(b, &next)
	next.State = "VERIFYING"
	next.Binding["bootId"] = randomB64()
	next.Binding["storageGeneration"] = randomB64()
	next.Binding["registrationVersion"] = increment(protocol.Text(old.Binding, "registrationVersion"))
	a := attempt()
	next, runtime, admissionContext := f.admit(t, i, next, path, a.ID)
	if e := f.Catalog.Boot(context.Background(), a, old, next, runtime); e != nil {
		t.Fatal(e)
	}
	service, e := Open(path, f.IDs[i], f.Services[i].Key, f.Catalog, runtime)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { service.Close() })
	f.Services[i] = service
	f.Paths[i] = path
	f.Registrations[i] = next
	f.Runtimes[i] = runtime
	f.Contexts[i] = admissionContext
}
func (f *archiveFixture) health(t *testing.T, want string) {
	t.Helper()
	health, e := f.Catalog.Health(context.Background(), protocol.Text(f.Bundle.Ref, "id"), f.IDs)
	if e != nil || health != want {
		t.Fatalf("health %s want %s: %v", health, want, e)
	}
}
func TestSimultaneousArchiveRestartRestoresCommittedCopies(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	id := protocol.Text(f.Bundle.Ref, "id")
	// Establish old-generation evidence, then invalidate every archive generation.
	for _, s := range f.Services {
		if _, e := s.Reattest(ctx, attempt(), id); e != nil {
			t.Fatal(e)
		}
	}
	f.health(t, "REDUNDANT")
	for i := range f.Services {
		f.boot(t, i)
	}
	f.health(t, "UNAVAILABLE")
	// No surviving-source receipt is available. Archive A verifies its own bytes.
	if _, e := f.Services[0].Reattest(ctx, attempt(), id); e != nil {
		t.Fatal(e)
	}
	f.health(t, "UNAVAILABLE")
	if _, e := f.Services[0].Activate(ctx, attempt()); e != nil {
		t.Fatal(e)
	}
	f.health(t, "DEGRADED")
	if _, e := f.Services[1].Reattest(ctx, attempt(), id); e != nil {
		t.Fatal(e)
	}
	if _, e := f.Services[1].Activate(ctx, attempt()); e != nil {
		t.Fatal(e)
	}
	f.health(t, "REDUNDANT")
	// One corrupt copy stays unavailable; ACTIVE is not a claim it has this bundle.
	if e := f.Services[2].Directory.Replace(id+".bundle", []byte("corrupt local copy")); e != nil {
		t.Fatal(e)
	}
	if _, e := f.Services[2].Reattest(ctx, attempt(), id); e == nil {
		t.Fatal("corrupt copy reattested")
	}
	if _, e := f.Services[2].Activate(ctx, attempt()); e != nil {
		t.Fatal("honestly quarantined inventory should activate", e)
	}
	f.health(t, "REDUNDANT")
	v, e := f.Catalog.Store.Read(ctx, "head")
	if e != nil || string(v.Values["head"].Bytes) != string(consensus.JSON(f.Head)) {
		t.Fatal("restart recovery changed vault head", e)
	}
}
func TestArchiveGenerationRaceFencesOldWorker(t *testing.T) {
	f := fixture(t)
	f.boot(t, 0)
	ctx := context.Background()
	checked := make(chan struct{})
	resume := make(chan struct{})
	old := f.Services[0]
	old.Fault = func(point string) error {
		if point == "after-authority-check" {
			close(checked)
			<-resume
		}
		return nil
	}
	done := make(chan error, 1)
	a := attempt()
	go func() { _, e := old.Reattest(ctx, a, protocol.Text(f.Bundle.Ref, "id")); done <- e }()
	<-checked
	replacement := filepath.Join(t.TempDir(), "new-volume")
	if e := os.Mkdir(replacement, 0700); e != nil {
		t.Fatal(e)
	}
	f.replace(t, 0, replacement)
	close(resume)
	if e := <-done; !errors.Is(e, consensus.ErrConflict) {
		t.Fatal("old-generation receipt published", e)
	}
	f.health(t, "UNAVAILABLE")
}
func TestReattestationAndActivationLostAcknowledgements(t *testing.T) {
	f := fixture(t)
	f.boot(t, 0)
	s := f.Services[0]
	ctx := context.Background()
	a := attempt()
	s.Fault = func(point string) error {
		if point == "after-registration-before-ack" {
			return errors.New("response lost")
		}
		return nil
	}
	if _, e := s.Reattest(ctx, a, protocol.Text(f.Bundle.Ref, "id")); e == nil {
		t.Fatal("fault not reached")
	}
	s.Fault = nil
	result, e := s.Reattest(ctx, a, protocol.Text(f.Bundle.Ref, "id"))
	if e != nil || !result.Historical {
		t.Fatal("reattestation retry not historical", e)
	}
	activation := attempt()
	s.Fault = func(point string) error {
		if point == "after-activation-before-ack" {
			return errors.New("response lost")
		}
		return nil
	}
	if _, e = s.Activate(ctx, activation); e == nil {
		t.Fatal("activation fault not reached")
	}
	s.Fault = nil
	_, e = s.Activate(ctx, activation)
	var known *consensus.AlreadyDecided
	if !errors.As(e, &known) {
		t.Fatal("lost activation acknowledgement unresolved", e)
	}
	f.health(t, "DEGRADED")
}
func TestDeletionFenceAndIncompleteCoverageBlockReceipt(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	f.boot(t, 0)
	id := protocol.Text(f.Bundle.Ref, "id")
	v, e := f.Catalog.Store.Read(ctx, deleteKey(f.IDs[0], id))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Catalog.Store.Apply(ctx, attempt(), v, []consensus.Write{{Key: deleteKey(f.IDs[0], id), Bytes: []byte("irreversible deletion fence")}}, "APPLIED", nil); e != nil {
		t.Fatal(e)
	}
	if _, e = f.Services[0].Reattest(ctx, attempt(), id); e == nil {
		t.Fatal("deletion-fenced copy resurrected")
	}
	bad := append(append([]byte{}, f.Bytes...), 0)
	if e = VerifyBundle(bad, f.Bundle); e == nil {
		t.Fatal("trailing ciphertext accepted")
	}
	bad = append([]byte{}, f.Bytes...)
	bad[len(bad)-1] ^= 1
	if e = VerifyBundle(bad, f.Bundle); e == nil {
		t.Fatal("changed ciphertext accepted")
	}
}
func TestMissingPinRecoveryAndIncompleteScan(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	f.boot(t, 0)
	id := protocol.Text(f.Bundle.Ref, "id")
	s := f.Services[0]
	if e := s.Directory.Remove(id + ".pin"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Reattest(ctx, attempt(), id); e != nil {
		t.Fatal("live committed reference did not reconstruct pin", e)
	}
	summary, archiveRef, classes, e := s.Scan(ctx)
	if e != nil {
		t.Fatal(e)
	}
	summary["protectedBundleCount"] = "0"
	if _, e = f.Catalog.Activate(ctx, attempt(), s.ID, archiveRef, summary, classes, s.runtime); e == nil {
		t.Fatal("incomplete inventory activated")
	}
}
func TestActivationRejectsLaterGenerationWithAllCopiesMissing(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	f.boot(t, 0)
	s := f.Services[0]
	id := protocol.Text(f.Bundle.Ref, "id")
	if e := s.Directory.Remove(id + ".bundle"); e != nil {
		t.Fatal(e)
	}
	summary, archiveRef, classes, e := s.Scan(ctx)
	if e != nil {
		t.Fatal(e)
	}
	f.boot(t, 0)
	if _, e = f.Catalog.Activate(ctx, attempt(), s.ID, archiveRef, summary, classes, s.runtime); !errors.Is(e, consensus.ErrConflict) && !errors.Is(e, ErrRuntimeFenced) {
		t.Fatal("old missing-data scan activated a new archive boot", e)
	}
	f.health(t, "UNAVAILABLE")
}
