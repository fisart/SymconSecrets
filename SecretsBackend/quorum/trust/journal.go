// Package trust implements consumed boot admission and crash-resumable recovery.
// These journals require independently managed storage; they cannot manufacture
// evidence that a platform volume is intact or an old installation is fenced.
package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/durable"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
)

type AdmissionContext struct {
	Expected   protocol.Object
	PublicKeys map[string]ed25519.PublicKey
}
type admissionState struct {
	LastCounter    string `json:"lastCounter"`
	AdmissionID    string `json:"admissionId"`
	Digest         string `json:"digest"`
	ExpectedDigest string `json:"expectedDigest"`
}
type AdmissionJournal struct {
	directory *durable.Directory
	profile   *protocol.Profile
}

func OpenAdmission(path string) (*AdmissionJournal, error) {
	d, e := durable.Open(path)
	if e != nil {
		return nil, e
	}
	p, e := protocol.Load()
	if e != nil {
		d.Close()
		return nil, e
	}
	return &AdmissionJournal{d, p}, nil
}
func (j *AdmissionJournal) Close() error { return j.directory.Close() }
func (j *AdmissionJournal) Initialize() error {
	return j.directory.Locked(func() error {
		return j.directory.PutImmutable("admission.json", mustJSON(admissionState{LastCounter: "0"}))
	})
}
func (j *AdmissionJournal) Consume(record protocol.Object, c AdmissionContext) (historical bool, err error) {
	if err = j.profile.Validate(record, "HostAdmission", ""); err != nil {
		return
	}
	key := c.PublicKeys[protocol.Text(record, "hostGuardKeyId")]
	if err = j.profile.Verify("hostAdmission", protocol.Unsigned(record), protocol.Text(record, "signature"), key); err != nil {
		return
	}
	// Every context field comes from the independent guard configuration/current boot,
	// never by copying those values from the untrusted signed record.
	required := []string{"clusterId", "realmId", "incarnation", "nativeClusterId", "trustRevision", "componentKind", "componentId", "targetIdentityDigest", "bootOperationId", "bootId", "storageGeneration", "volumeIdentityDigest", "restartClass", "trustPackDigest", "hostGuardKeyId"}
	if len(c.Expected) != len(required) {
		return false, errors.New("complete independent admission context required")
	}
	for _, k := range required {
		if record[k] != c.Expected[k] {
			return false, errors.New("admission context mismatch")
		}
	}
	if record["restartClass"] == "QUARANTINED" {
		return false, errors.New("quarantined boot")
	}
	hash := protocol.MustDigest(record)
	contextHash := protocol.MustDigest(c.Expected)
	err = j.directory.Locked(func() error {
		b, e := j.directory.ReadDurable("admission.json")
		if e != nil {
			return e
		}
		var state admissionState
		if e = json.Unmarshal(b, &state); e != nil {
			return e
		}
		n, e := strconv.ParseInt(protocol.Text(record, "admissionCounter"), 10, 64)
		if e != nil {
			return e
		}
		old, e := strconv.ParseInt(state.LastCounter, 10, 64)
		if e != nil {
			return e
		}
		if state.AdmissionID == record["admissionId"] {
			if state.Digest != hash || state.ExpectedDigest != contextHash || n != old {
				return errors.New("admission replay binding")
			}
			historical = true
			return nil
		}
		if n <= old {
			return errors.New("old admission counter")
		}
		next := admissionState{LastCounter: strconv.FormatInt(n, 10), AdmissionID: protocol.Text(record, "admissionId"), Digest: hash, ExpectedDigest: contextHash}
		return j.directory.Replace("admission.json", mustJSON(next))
	})
	return
}

type RecoveryFloor struct {
	TrustPack  protocol.Object `json:"trustPack"`
	Sequence   string          `json:"sequence"`
	LastID     string          `json:"lastId"`
	LastDigest string          `json:"lastDigest"`
}
type recoveryState struct {
	Floor    RecoveryFloor     `json:"floor"`
	Prepared protocol.Object   `json:"prepared"`
	Evidence map[string][]byte `json:"evidence"`
}
type RecoveryContext struct {
	PublicKeys                map[string]ed25519.PublicKey
	Evidence                  map[string][]byte
	VerifyFencing             func([]byte) error
	VerifyIndependentApproval func([]byte) error
}
type RecoveryJournal struct {
	directory *durable.Directory
	profile   *protocol.Profile
	fault     func(string) error
}

func OpenRecovery(path string, fault func(string) error) (*RecoveryJournal, error) {
	d, e := durable.Open(path)
	if e != nil {
		return nil, e
	}
	p, e := protocol.Load()
	if e != nil {
		d.Close()
		return nil, e
	}
	return &RecoveryJournal{d, p, fault}, nil
}
func (j *RecoveryJournal) Close() error { return j.directory.Close() }
func (j *RecoveryJournal) trip(point string) error {
	if j.fault != nil {
		return j.fault(point)
	}
	return nil
}
func mustJSON(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func (j *RecoveryJournal) Initialize(floor RecoveryFloor) error {
	if e := j.profile.Validate(floor.TrustPack, "TrustPack", ""); e != nil {
		return e
	}
	if e := j.profile.Validate(floor.Sequence, "Q", ""); e != nil {
		return e
	}
	if floor.Sequence != "0" || floor.LastID != "" || floor.LastDigest != "" {
		return errors.New("initial floor only")
	}
	return j.directory.Locked(func() error { return j.directory.PutImmutable("recovery.json", mustJSON(recoveryState{Floor: floor})) })
}
func (j *RecoveryJournal) State() (floor RecoveryFloor, locked bool, err error) {
	locked = true // Errors, including failed re-synchronization, never report unlocked.
	err = j.directory.Locked(func() error {
		b, e := j.directory.ReadDurable("recovery.json")
		if e != nil {
			return e
		}
		var s recoveryState
		if e = json.Unmarshal(b, &s); e != nil {
			return e
		}
		if e = j.validateState(s); e != nil {
			return e
		}
		floor = s.Floor
		locked = s.Prepared != nil
		return nil
	})
	return
}
func (j *RecoveryJournal) validateState(s recoveryState) error {
	if e := j.profile.Validate(s.Floor.TrustPack, "TrustPack", ""); e != nil {
		return e
	}
	if e := j.profile.Validate(s.Floor.Sequence, "Q", ""); e != nil {
		return e
	}
	if s.Floor.Sequence == "0" {
		if s.Floor.LastID != "" || s.Floor.LastDigest != "" {
			return errors.New("invalid initial recovery floor")
		}
	} else {
		if e := j.profile.Validate(s.Floor.LastID, "UUID", ""); e != nil {
			return e
		}
		if e := j.profile.Validate(s.Floor.LastDigest, "DIGEST", ""); e != nil {
			return e
		}
	}
	if s.Prepared != nil {
		if e := j.profile.Validate(s.Prepared, "RecoveryTrustManifest", ""); e != nil {
			return e
		}
		if s.Prepared["oldTrustPackDigest"] != protocol.MustDigest(s.Floor.TrustPack) {
			return errors.New("prepared recovery predecessor mismatch")
		}
		if len(s.Evidence) != 4 {
			return errors.New("prepared evidence missing")
		}
		for _, k := range []string{"fencingEvidenceDigest", "revocationPlanDigest", "dataLossDispositionDigest", "independentApprovalDigest"} {
			if len(s.Evidence[k]) == 0 || evidenceDigest(s.Evidence[k]) != s.Prepared[k] {
				return errors.New("prepared evidence integrity")
			}
		}
	} else if len(s.Evidence) != 0 {
		return errors.New("orphaned recovery evidence")
	}
	return nil
}
func evidenceDigest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func (j *RecoveryJournal) Apply(record protocol.Object, c RecoveryContext) (historical bool, err error) {
	if err = j.profile.Validate(record, "RecoveryTrustManifest", ""); err != nil {
		return
	}
	if err = j.profile.Verify("recoveryManifest", protocol.Unsigned(record), protocol.Text(record, "signature"), c.PublicKeys[protocol.Text(record, "recoveryKeyId")]); err != nil {
		return
	}
	if c.VerifyFencing == nil || c.VerifyIndependentApproval == nil {
		return false, errors.New("independent fencing and approval validators required")
	}
	required := []string{"fencingEvidenceDigest", "revocationPlanDigest", "dataLossDispositionDigest", "independentApprovalDigest"}
	if len(c.Evidence) != len(required) {
		return false, errors.New("complete recovery evidence required")
	}
	for _, k := range required {
		if len(c.Evidence[k]) == 0 || evidenceDigest(c.Evidence[k]) != record[k] {
			return false, errors.New("recovery evidence mismatch")
		}
	}
	if err = c.VerifyFencing(c.Evidence["fencingEvidenceDigest"]); err != nil {
		return
	}
	if err = c.VerifyIndependentApproval(c.Evidence["independentApprovalDigest"]); err != nil {
		return
	}
	hash := protocol.MustDigest(record)
	err = j.directory.Locked(func() error {
		b, e := j.directory.ReadDurable("recovery.json")
		if e != nil {
			return e
		}
		var s recoveryState
		if e = json.Unmarshal(b, &s); e != nil {
			return e
		}
		if e = j.validateState(s); e != nil {
			return e
		}
		next := protocol.Obj(record, "newTrustPack")
		old := s.Floor.TrustPack
		if s.Floor.LastID == record["recoveryId"] {
			if s.Floor.LastDigest != hash || !protocol.Equal(next, s.Floor.TrustPack) {
				return errors.New("recovery ID binding")
			}
			historical = true
			return nil
		}
		n, e := strconv.ParseInt(s.Floor.Sequence, 10, 64)
		if e != nil || n == 9223372036854775807 {
			return errors.New("recovery sequence exhausted")
		}
		if record["oldTrustPackDigest"] != protocol.MustDigest(old) || record["recoverySequence"] != strconv.FormatInt(n+1, 10) {
			return errors.New("recovery predecessor/sequence mismatch")
		}
		for _, k := range []string{"clusterId", "realmId"} {
			if next[k] != old[k] {
				return errors.New("logical recovery identity changed")
			}
		}
		if next["incarnation"] == old["incarnation"] || next["nativeClusterId"] == old["nativeClusterId"] {
			return errors.New("new recovery lineage required")
		}
		oldRev, e := strconv.ParseInt(protocol.Text(old, "trustRevision"), 10, 64)
		if e != nil {
			return e
		}
		newRev, e := strconv.ParseInt(protocol.Text(next, "trustRevision"), 10, 64)
		if e != nil || newRev <= oldRev {
			return errors.New("recovery trust downgrade")
		}
		selected := protocol.Obj(record, "selectedRecoveryHead")
		for _, k := range []string{"clusterId", "realmId", "incarnation"} {
			if selected[k] != old[k] {
				return errors.New("selected recovery lineage mismatch")
			}
		}
		if s.Prepared != nil && !protocol.Equal(s.Prepared, record) {
			return errors.New("another recovery already prepared")
		}
		if s.Prepared == nil {
			s.Prepared = record
			s.Evidence = c.Evidence
			if e = j.directory.Replace("recovery.json", mustJSON(s)); e != nil {
				return e
			}
		}
		if e = j.trip("after-prepared"); e != nil {
			return e
		}
		// One file atomically holds floor, consumed record and cleared PREPARED state.
		// Retain the signed artifacts/evidence first, before acknowledging the floor.
		if e = j.directory.PutImmutable("recovery-"+protocol.Text(record, "recoveryId")+".json", mustJSON(struct {
			Manifest protocol.Object
			Evidence map[string][]byte
		}{record, s.Evidence})); e != nil {
			return e
		}
		if e = j.trip("before-floor"); e != nil {
			return e
		}
		s.Floor = RecoveryFloor{TrustPack: next, Sequence: protocol.Text(record, "recoverySequence"), LastID: protocol.Text(record, "recoveryId"), LastDigest: hash}
		s.Prepared = nil
		s.Evidence = nil
		if e = j.directory.Replace("recovery.json", mustJSON(s)); e != nil {
			return e
		}
		return j.trip("after-floor-before-ack")
	})
	return
}
