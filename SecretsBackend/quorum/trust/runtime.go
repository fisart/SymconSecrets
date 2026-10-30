package trust

import (
	"encoding/json"
	"errors"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/durable"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
)

// AdmittedRuntime cannot be constructed from a catalog registration. It is a
// locally verified, durably consumed guard admission bound to one opened volume.
// The guard's issuance, keys and volume verifier must be outside component rollback.
type AdmittedRuntime struct {
	record            protocol.Object
	directoryIdentity string
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
	return &AdmittedRuntime{record: immutable, directoryIdentity: id}, nil
}
