package archive

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/durable"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/trust"
)

// Synthetic independent guard inventory for component tests only. Device/inode
// identity binds a local directory; it is not evidence of an unrestored platform.
func verifyTestVolume(path, expected string) error {
	d, e := durable.Open(path)
	if e != nil {
		return e
	}
	defer d.Close()
	id, e := d.Identity()
	if e != nil {
		return e
	}
	if id != expected {
		return errors.New("independently inventoried test volume mismatch")
	}
	return nil
}
func (f *archiveFixture) admit(t *testing.T, i int, reg Registration, path, operation string) (Registration, *trust.AdmittedRuntime, trust.AdmissionContext) {
	t.Helper()
	d, e := durable.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	volume, e := d.Identity()
	d.Close()
	if e != nil {
		t.Fatal(e)
	}
	record := protocol.Object{"version": "2", "clusterId": f.Head["clusterId"], "realmId": f.Head["realmId"], "incarnation": f.Head["incarnation"], "nativeClusterId": f.Cluster.NativeID, "trustRevision": "1", "componentKind": "ARCHIVE", "componentId": reg.Binding["archiveId"], "targetIdentityDigest": IdentityDigest(reg), "bootOperationId": operation, "admissionCounter": reg.Binding["registrationVersion"], "admissionId": attempt().ID, "bootId": reg.Binding["bootId"], "storageGeneration": reg.Binding["storageGeneration"], "volumeIdentityDigest": volume, "restartClass": "INTACT", "trustPackDigest": protocol.MustDigest(f.Head), "hostGuardKeyId": f.GuardIDs[i]}
	expected := protocol.Object{}
	for k, v := range record {
		if k != "version" && k != "admissionCounter" && k != "admissionId" {
			expected[k] = v
		}
	}
	record["signature"], e = f.Catalog.Profile.Sign("hostAdmission", record, f.Guards[i])
	if e != nil {
		t.Fatal(e)
	}
	c := trust.AdmissionContext{Expected: expected, PublicKeys: map[string]ed25519.PublicKey{f.GuardIDs[i]: f.Guards[i].Public().(ed25519.PublicKey)}}
	j, e := trust.OpenAdmission(f.GuardJournals[i])
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	runtime, e := j.AdmitDirectory(record, c, path, verifyTestVolume)
	if e != nil {
		t.Fatal(e)
	}
	reg.VolumeIdentityDigest = volume
	reg.AdmissionDigest = protocol.MustDigest(record)
	return reg, runtime, c
}
func TestOldServiceCannotAdoptReplacementGeneration(t *testing.T) {
	f := fixture(t)
	old := f.Services[0]
	oldRuntime := old.runtime
	path := filepath.Join(t.TempDir(), "empty-replacement")
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	f.replace(t, 0, path)
	ctx := context.Background()
	id := protocol.Text(f.Bundle.Ref, "id")
	if _, e := old.Reattest(ctx, attempt(), id); !errors.Is(e, ErrRuntimeFenced) {
		t.Fatal("pre-validation stale archive adopted new generation", e)
	}
	if _, e := old.Activate(ctx, attempt()); !errors.Is(e, ErrRuntimeFenced) {
		t.Fatal("stale archive activated replacement", e)
	}
	if _, e := Open(path, old.ID, old.Key, f.Catalog, oldRuntime); e == nil {
		t.Fatal("old admission opened replacement directory")
	}
	if _, e := os.Stat(filepath.Join(path, id+".bundle")); !os.IsNotExist(e) {
		t.Fatal("replacement unexpectedly contains old bundle", e)
	}
	f.health(t, "UNAVAILABLE")
	// A genuine current replacement may activate honestly with missing data.
	if _, e := f.Services[0].Activate(ctx, attempt()); e != nil {
		t.Fatal(e)
	}
	f.health(t, "UNAVAILABLE")
}
func TestOldAdmissionCannotRestoreAnIntactDirectoryMarker(t *testing.T) {
	f := fixture(t)
	old := f.Services[0]
	oldRuntime := old.runtime
	path := f.Paths[0]
	f.boot(t, 0)
	if _, e := Open(path, old.ID, old.Key, f.Catalog, oldRuntime); e == nil {
		t.Fatal("old admission replaced later local marker")
	}
	if _, e := old.Reattest(context.Background(), attempt(), protocol.Text(f.Bundle.Ref, "id")); e == nil {
		t.Fatal("old local runtime remained serving")
	}
}
