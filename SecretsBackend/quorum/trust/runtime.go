package trust

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/durable"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
)

// AdmittedRuntime cannot be constructed from a catalog registration. It is a
// locally verified, durably consumed guard admission bound to one opened volume.
// The guard's issuance, keys and volume verifier must be outside component rollback.
type AdmittedRuntime struct {
	record            protocol.Object
	directoryIdentity string
	guardKey          ed25519.PublicKey
}

// Succeeds verifies the installed predecessor under the independently pinned
// guard that issued this capability. A different signer/trust lineage is not a
// counter reset: it needs a separately approved transition, not ordinary Boot.
func (r *AdmittedRuntime) Succeeds(previous protocol.Object) error {
	if r == nil {
		return errors.New("independent admission required")
	}
	p, e := protocol.Load()
	if e != nil {
		return e
	}
	if e = p.Validate(previous, "HostAdmission", ""); e != nil {
		return e
	}
	if e = p.Verify("hostAdmission", protocol.Unsigned(previous), protocol.Text(previous, "signature"), r.guardKey); e != nil {
		return e
	}
	for _, k := range []string{"clusterId", "realmId", "incarnation", "nativeClusterId", "trustRevision", "trustPackDigest", "componentKind", "componentId", "targetIdentityDigest", "hostGuardKeyId"} {
		if previous[k] != r.record[k] {
			return errors.New("admission authority transition required")
		}
	}
	prior, e := strconv.ParseInt(protocol.Text(previous, "admissionCounter"), 10, 64)
	if e != nil {
		return e
	}
	next, e := strconv.ParseInt(protocol.Text(r.record, "admissionCounter"), 10, 64)
	if e != nil || next <= prior || previous["admissionId"] == r.record["admissionId"] || previous["bootOperationId"] == r.record["bootOperationId"] {
		return errors.New("superseded or reused admission")
	}
	return nil
}

func (r *AdmittedRuntime) Record() protocol.Object {
	if r == nil {
		return nil
	}
	b, _ := json.Marshal(r.record)
	var v protocol.Object
	json.Unmarshal(b, &v)
	return v
}
func (r *AdmittedRuntime) MatchesDirectory(d *durable.Directory) error {
	if r == nil || d == nil {
		return errors.New("independent local admission required")
	}
	id, e := d.Identity()
	if e != nil {
		return e
	}
	if id != r.directoryIdentity {
		return errors.New("admission belongs to a different local directory")
	}
	return nil
}
func (j *AdmissionJournal) AdmitDirectory(record protocol.Object, c AdmissionContext, path string, verifyVolume func(string, string) error) (*AdmittedRuntime, error) {
	// Own the verified snapshot before invoking any external inventory callback.
	raw, e := json.Marshal(record)
	if e != nil {
		return nil, e
	}
	var snapshot protocol.Object
	if e = json.Unmarshal(raw, &snapshot); e != nil {
		return nil, e
	}
	record = snapshot
	if verifyVolume == nil {
		return nil, errors.New("independent volume verification required")
	}
	d, e := durable.Open(path)
	if e != nil {
		return nil, e
	}
	defer d.Close()
	id, e := d.Identity()
	if e != nil {
		return nil, e
	}
	if e = verifyVolume(path, protocol.Text(record, "volumeIdentityDigest")); e != nil {
		return nil, e
	}
	if _, e = j.Consume(record, c); e != nil {
		return nil, e
	}
	// Recheck the opened root after verification. A caller must not obtain a token
	// by restoring the archive's own marker or by reading a new catalog generation.
	current, e := d.Identity()
	if e != nil || current != id {
		return nil, errors.New("local directory changed during admission")
	}
	b, e := json.Marshal(record)
	if e != nil {
		return nil, e
	}
	var immutable protocol.Object
	if e = json.Unmarshal(b, &immutable); e != nil {
		return nil, e
	}
	return &AdmittedRuntime{record: immutable, directoryIdentity: id, guardKey: append(ed25519.PublicKey(nil), c.PublicKeys[protocol.Text(record, "hostGuardKeyId")]...)}, nil
}
