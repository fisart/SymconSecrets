package archive

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/consensus"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/trust"
)

var ErrRuntimeFenced = errors.New("archive runtime admission is fenced")

func IdentityDigest(reg Registration) string {
	return protocol.MustDigest(protocol.Object{"archiveId": reg.Binding["archiveId"], "keyId": reg.KeyID, "publicKey": reg.PublicKey})
}
func (c *Catalog) matchesAdmission(reg Registration, runtime *trust.AdmittedRuntime) error {
	if runtime == nil {
		return ErrRuntimeFenced
	}
	r := runtime.Record()
	if r["nativeClusterId"] != c.Store.NativeID() {
		return ErrRuntimeFenced
	}
	if r["componentKind"] != "ARCHIVE" || r["componentId"] != reg.Binding["archiveId"] || r["bootId"] != reg.Binding["bootId"] || r["storageGeneration"] != reg.Binding["storageGeneration"] || r["volumeIdentityDigest"] != reg.VolumeIdentityDigest || r["targetIdentityDigest"] != IdentityDigest(reg) || protocol.MustDigest(r) != reg.AdmissionDigest {
		return ErrRuntimeFenced
	}
	return nil
}
func admissionLineage(head protocol.Object, runtime *trust.AdmittedRuntime) error {
	if runtime == nil {
		return ErrRuntimeFenced
	}
	record := runtime.Record()
	for _, k := range []string{"clusterId", "realmId", "incarnation"} {
		if head[k] != record[k] {
			return ErrRuntimeFenced
		}
	}
	return nil
}
func sameAdmission(v consensus.Snapshot, reg Registration, runtime *trust.AdmittedRuntime) bool {
	var r protocol.Object
	if json.Unmarshal(v.Values["admissions/"+protocol.Text(reg.Binding, "archiveId")].Bytes, &r) != nil {
		return false
	}
	return protocol.Equal(r, runtime.Record())
}
func (s *Service) physical() error {
	if e := s.runtime.MatchesDirectory(s.Directory); e != nil {
		return e
	}
	b, e := s.Directory.ReadDurable("admitted-runtime.json")
	if e != nil {
		return e
	}
	var marker protocol.Object
	if e = json.Unmarshal(b, &marker); e != nil {
		return e
	}
	if !protocol.Equal(marker, s.runtime.Record()) {
		return ErrRuntimeFenced
	}
	return nil
}
func (s *Service) current(ctx context.Context) error {
	return s.Directory.Locked(func() error {
		if e := s.physical(); e != nil {
			return e
		}
		v, e := s.Catalog.Store.Read(ctx, archiveKey(s.ID), "admissions/"+s.ID, "head")
		if e != nil {
			return e
		}
		var reg Registration
		var head protocol.Object
		if e = decode(v.Values["head"].Bytes, &head); e != nil {
			return e
		}
		if e = admissionLineage(head, s.runtime); e != nil {
			return e
		}
		if e = decode(v.Values[archiveKey(s.ID)].Bytes, &reg); e != nil {
			return e
		}
		if !has([]string{"VERIFYING", "REPAIRING", "ACTIVE"}, reg.State) {
			return ErrRuntimeFenced
		}
		if e = s.Catalog.matchesAdmission(reg, s.runtime); e != nil {
			return e
		}
		if !sameAdmission(v, reg, s.runtime) {
			return ErrRuntimeFenced
		}
		return nil
	})
}
