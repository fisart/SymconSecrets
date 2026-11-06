package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/archive"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/consensus"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/durable"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/internal/testcluster"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/trust"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestEtcdMemberProcess(t *testing.T) { testcluster.MemberProcess(t) }
func uid() string                        { return testcluster.UUID() }
func b64() string                        { b := make([]byte, 32); rand.Read(b); return protocol.Base(b) }
func digest(b []byte) string             { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func cmd() consensus.Attempt {
	id := uid()
	return consensus.Attempt{ID: id, Digest: protocol.MustDigest(protocol.Object{"id": id})}
}
func private(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "private")
	if e := os.Mkdir(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}

type testFixture struct {
	cluster                     *testcluster.Cluster
	store                       *consensus.Store
	controller                  *Controller
	catalog                     *archive.Catalog
	services                    []*archive.Service
	registrations               []archive.Registration
	paths                       []string
	guardKeys                   []ed25519.PrivateKey
	guardIDs, guardPaths        []string
	owner, actor                protocol.Object
	ownerKey                    ed25519.PrivateKey
	ownerKeyID                  string
	head, scope                 protocol.Object
	policy                      Policy
	membership                  Membership
	permission                  Permission
	session                     Session
	credential                  Credential
	pairing                     Pairing
	recipient                   string
	sessionLease, approvalLease clientv3.LeaseID
}

func bundle(t *testing.T, scope protocol.Object, head protocol.Object) (archive.Bundle, []byte) {
	t.Helper()
	manifest, payload := make([]byte, 96), make([]byte, 96)
	rand.Read(manifest)
	rand.Read(payload)
	obj := protocol.Object{"id": b64(), "kind": "vault", "schema": "1", "length": fmt.Sprint(len(payload)), "digest": digest(payload), "keyId": scope["keyId"], "scopeId": scope["scopeId"]}
	data, index, e := archive.BuildBundle(manifest, []protocol.Object{obj}, [][]byte{payload})
	must(t, e)
	head["manifestDigest"] = digest(manifest)
	head["coreDigest"] = digest(manifest)
	descriptor := protocol.Object{"commitId": head["commitId"], "bundleDigest": digest(data), "manifestDigest": digest(manifest), "bundleLength": fmt.Sprint(len(data))}
	b := archive.Bundle{Ref: Ref(protocol.Text(head, "commitId"), "1", descriptor), Descriptor: descriptor, IndexDigest: index}
	return b, data
}
func fixture(t *testing.T) *testFixture {
	t.Helper()
	f := &testFixture{cluster: testcluster.New(t)}
	var e error
	f.head = protocol.Object{"clusterId": uid(), "realmId": uid(), "incarnation": b64(), "index": "7", "commitId": uid(), "coreDigest": digest([]byte("old")), "manifestDigest": digest([]byte("old")), "keyEpoch": "1"}
	f.scope = protocol.Object{"scopeId": uid(), "kind": "GLOBAL", "ownerNodeId": nil, "keyId": b64(), "revision": "1", "objectDigest": digest([]byte("old scope"))}
	f.owner = protocol.Object{"nodeId": uid(), "bootId": b64(), "nodeFence": "1"}
	f.actor = protocol.Object{"nodeId": uid(), "bootId": b64(), "nodeFence": "1"}
	var ownerPublic ed25519.PublicKey
	ownerPublic, f.ownerKey, e = ed25519.GenerateKey(rand.Reader)
	must(t, e)
	f.ownerKeyID = b64()
	f.store, e = consensus.New(f.cluster.Client, protocol.Text(f.head, "clusterId"), protocol.Text(f.head, "realmId"), f.cluster.NativeID)
	must(t, e)
	f.controller, e = New(f.store)
	must(t, e)
	f.catalog, e = archive.NewCatalog(f.store)
	must(t, e)
	f.policy = Policy{ID: uid(), Version: "1", HardwareClasses: []string{"GLOBAL_EDIT", "LOCAL_EDIT"}}
	f.membership = Membership{ID: uid(), Version: "1", Nodes: []string{protocol.Text(f.owner, "nodeId"), protocol.Text(f.actor, "nodeId")}, Archives: []string{uid(), uid(), uid()}}
	admin := uid()
	f.permission = Permission{ID: uid(), Version: "1", AdministratorID: admin, Active: true, Classes: []string{"GLOBAL_EDIT", "LOCAL_EDIT"}, Scopes: []string{protocol.Text(f.scope, "scopeId")}}
	f.session = Session{ID: uid(), Version: "1", AdministratorID: admin, Active: true}
	f.credential = Credential{ID: uid(), Version: "1", AdministratorID: admin, Active: true, HardwareVerified: true}
	f.recipient = uid()
	f.pairing = Pairing{ID: uid(), Version: "1", RecipientID: f.recipient, Active: true}
	old, bytes := bundle(t, f.scope, f.head)
	old.Protected = true
	records := map[string][]byte{"lineage": []byte(f.cluster.NativeID), "head": consensus.JSON(f.head), "policy": consensus.JSON(f.policy), "membership": consensus.JSON(f.membership), "epoch": []byte("0"), scopeKey(Intent{Scope: f.scope}): consensus.JSON(f.scope), "core/permissions/" + f.permission.ID: consensus.JSON(f.permission), "core/sessions/" + f.session.ID: consensus.JSON(f.session), "core/credentials/" + f.credential.ID: consensus.JSON(f.credential), "core/pairings/" + f.pairing.ID: consensus.JSON(f.pairing), "core/revision": []byte("7"), "core/head-pin": consensus.JSON(old.Ref), "bundles/" + protocol.Text(old.Ref, "id"): consensus.JSON(old), "reference-index": consensus.JSON(Ref(uid(), "1", map[string]any{"initial": "index"}))}
	records[coordinatorKey(f.owner)] = consensus.JSON(Node{Binding: f.owner, KeyID: f.ownerKeyID, PublicKey: protocol.Base(ownerPublic), Active: true, Scopes: []string{protocol.Text(f.scope, "scopeId")}})
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	records[coordinatorKey(f.actor)] = consensus.JSON(Node{Binding: f.actor, KeyID: b64(), PublicKey: protocol.Base(pub), Active: true, Scopes: []string{protocol.Text(f.scope, "scopeId")}})
	keys := []ed25519.PrivateKey{}
	for i, id := range f.membership.Archives {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		must(t, e)
		keys = append(keys, key)
		_, guard, e := ed25519.GenerateKey(rand.Reader)
		must(t, e)
		f.guardKeys = append(f.guardKeys, guard)
		f.guardIDs = append(f.guardIDs, b64())
		f.guardPaths = append(f.guardPaths, private(t))
		f.paths = append(f.paths, private(t))
		j, e := trust.OpenAdmission(f.guardPaths[i])
		must(t, e)
		must(t, j.Initialize())
		j.Close()
		reg := archive.Registration{Binding: protocol.Object{"archiveId": id, "failureDomainId": uid(), "storageGeneration": b64(), "registrationVersion": "1", "bootId": b64()}, State: "ACTIVE", KeyID: b64(), PublicKey: protocol.Base(pub)}
		reg, runtime, _ := f.admit(t, i, reg, cmd().ID)
		f.registrations = append(f.registrations, reg)
		records["archives/"+id] = consensus.JSON(reg)
		// admit() durably consumes the guard record; retain the exact same record.
		records["admissions/"+id] = consensus.JSON(runtime.Record())
		records["inventory/"+id] = consensus.JSON(archive.Inventory{Ref: Ref(uid(), "1", map[string]any{"inventory": "initial"}), BundleIDs: []string{protocol.Text(old.Ref, "id")}, ArchiveIDs: f.membership.Archives})
		s, e := archive.Open(f.paths[i], id, keys[i], f.catalog, runtime)
		must(t, e)
		f.services = append(f.services, s)
		t.Cleanup(func() { s.Close() })
	}
	must(t, f.store.Initialize(context.Background(), cmd(), records))
	l, e := f.cluster.Client.Grant(context.Background(), 300)
	must(t, e)
	f.sessionLease = l.ID
	l, e = f.cluster.Client.Grant(context.Background(), 300)
	must(t, e)
	f.approvalLease = l.ID
	f.putLease(t, "core/sessions/"+f.session.ID, consensus.JSON(f.session), f.sessionLease)
	var actor Node
	v, e := f.store.Read(context.Background(), coordinatorKey(f.actor))
	must(t, e)
	must(t, load(v, coordinatorKey(f.actor), &actor))
	g := consensus.Guard{Head: consensus.JSON(f.head), Policy: consensus.JSON(f.policy), Membership: consensus.JSON(f.membership), NodeID: protocol.Text(f.actor, "nodeId"), Node: consensus.JSON(actor)}
	l, e = f.cluster.Client.Grant(context.Background(), 300)
	must(t, e)
	_, e = f.store.Elect(context.Background(), cmd(), g, l.ID, f.actor)
	must(t, e)
	for i, s := range f.services {
		must(t, s.Preserve(old, bytes))
		if i < 2 {
			_, e = s.Reattest(context.Background(), cmd(), protocol.Text(old.Ref, "id"))
			must(t, e)
		}
	}
	return f
}
func (f *testFixture) admit(t *testing.T, i int, reg archive.Registration, operation string) (archive.Registration, *trust.AdmittedRuntime, trust.AdmissionContext) {
	t.Helper()
	d, e := durable.Open(f.paths[i])
	must(t, e)
	volume, e := d.Identity()
	must(t, e)
	d.Close()
	record := protocol.Object{"version": "2", "clusterId": f.head["clusterId"], "realmId": f.head["realmId"], "incarnation": f.head["incarnation"], "nativeClusterId": f.cluster.NativeID, "trustRevision": "1", "componentKind": "ARCHIVE", "componentId": reg.Binding["archiveId"], "targetIdentityDigest": archive.IdentityDigest(reg), "bootOperationId": operation, "admissionCounter": reg.Binding["registrationVersion"], "admissionId": uid(), "bootId": reg.Binding["bootId"], "storageGeneration": reg.Binding["storageGeneration"], "volumeIdentityDigest": volume, "restartClass": "INTACT", "trustPackDigest": protocol.MustDigest(f.head), "hostGuardKeyId": f.guardIDs[i]}
	expected := protocol.Object{}
	for k, v := range record {
		if k != "version" && k != "admissionCounter" && k != "admissionId" {
			expected[k] = v
		}
	}
	record["signature"], e = f.catalog.Profile.Sign("hostAdmission", record, f.guardKeys[i])
	must(t, e)
	context := trust.AdmissionContext{Expected: expected, PublicKeys: map[string]ed25519.PublicKey{f.guardIDs[i]: f.guardKeys[i].Public().(ed25519.PublicKey)}}
	j, e := trust.OpenAdmission(f.guardPaths[i])
	must(t, e)
	defer j.Close()
	runtime, e := j.AdmitDirectory(record, context, f.paths[i], func(path, want string) error {
		d, e := durable.Open(path)
		if e != nil {
			return e
		}
		defer d.Close()
		got, e := d.Identity()
		if e != nil {
			return e
		}
		if got != want {
			return fmt.Errorf("synthetic guard inventory mismatch")
		}
		return nil
	})
	must(t, e)
	reg.AdmissionDigest = protocol.MustDigest(record)
	reg.VolumeIdentityDigest = volume
	return reg, runtime, context
}
func (f *testFixture) putLease(t *testing.T, key string, bytes []byte, lease clientv3.LeaseID) {
	t.Helper()
	v, e := f.store.Read(context.Background(), key)
	must(t, e)
	_, e = f.store.Apply(context.Background(), cmd(), v, []consensus.Write{{Key: key, Bytes: bytes, Lease: lease}}, "APPLIED", nil)
	must(t, e)
}
func (f *testFixture) put(t *testing.T, key string, record any) {
	t.Helper()
	f.putLease(t, key, consensus.JSON(record), 0)
}
func (f *testFixture) change(t *testing.T) (ApprovedIntent, []byte) {
	t.Helper()
	v, e := f.store.Read(context.Background(), "head", scopeKey(Intent{Scope: f.scope}))
	must(t, e)
	var head, scope protocol.Object
	must(t, load(v, "head", &head))
	must(t, load(v, scopeKey(Intent{Scope: f.scope}), &scope))
	candidate := protocol.Obj(object(map[string]any{"head": head}), "head")
	next, e := increment(protocol.Text(head, "index"))
	must(t, e)
	candidate["index"] = next
	candidate["commitId"] = uid()
	b, bytes := bundle(t, scope, candidate)
	rev, e := increment(protocol.Text(scope, "revision"))
	must(t, e)
	indexLength := int(binary.BigEndian.Uint32(bytes[8:12]))
	indexObject, err := protocol.Decode(bytes[12 : 12+indexLength])
	must(t, err)
	newScopeDigest := protocol.Text(indexObject["objects"].([]any)[0].(map[string]any), "digest")
	changeClass := "GLOBAL_EDIT"
	if scope["kind"] == "LOCAL" {
		changeClass = "LOCAL_EDIT"
	}
	intent := Intent{NewScopeDigest: newScopeDigest, Version: "1", UserOperationID: uid(), ExpectedHead: head, Owner: f.owner, PolicyRef: Ref(f.policy.ID, f.policy.Version, f.policy), MembershipRef: Ref(f.membership.ID, f.membership.Version, f.membership), PermissionRef: Ref(f.permission.ID, f.permission.Version, f.permission), SessionRef: Ref(f.session.ID, f.session.Version, f.session), CredentialRef: Ref(f.credential.ID, f.credential.Version, f.credential), Scope: scope, NewRevision: rev, ChangeClass: changeClass, PermittedDiffDigest: digest(bytes), CandidateHead: candidate, Bundle: b, Outbox: []Delivery{{RecipientID: f.recipient, PairingRef: Ref(f.pairing.ID, f.pairing.Version, f.pairing)}}}
	approval := Approval{ID: uid(), Version: "1", IntentDigest: Digest(intent), PermissionRef: intent.PermissionRef, SessionRef: intent.SessionRef, CredentialRef: intent.CredentialRef, UserPresence: true, UserVerification: true, DiffVerified: true}
	f.putLease(t, "core/approvals/"+approval.ID, consensus.JSON(approval), f.approvalLease)
	a, e := Signed(ApprovedIntent{Intent: intent, ApprovalRef: Ref(approval.ID, "1", approval), KeyID: f.ownerKeyID}, f.ownerKey)
	must(t, e)
	must(t, validateIntent(a))
	return a, bytes
}
func (f *testFixture) preparing(t *testing.T) (ApprovedIntent, []byte, Reservation) {
	t.Helper()
	a, b := f.change(t)
	r, e := f.controller.Reserve(context.Background(), uid(), a, f.actor)
	must(t, e)
	return a, b, r
}
func (f *testFixture) ready(t *testing.T) (ApprovedIntent, []byte, Reservation) {
	t.Helper()
	a, b, r := f.preparing(t)
	id := protocol.Text(r.Record, "id")
	for _, s := range f.services[:2] {
		receipt, e := s.UploadCandidate(context.Background(), id, f.owner, b)
		must(t, e)
		_, e = f.controller.RegisterReceipt(context.Background(), uid(), id, ReservationRef(r), receipt, f.actor)
		must(t, e)
	}
	r, e := f.controller.Ready(context.Background(), uid(), id, ReservationRef(r), f.actor)
	must(t, e)
	return a, b, r
}
