package archive

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/consensus"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
)

// UploadCandidate is an internal authenticated-uploader entry point. A future
// transport must derive uploader from verified current credentials, never JSON
// claims. The archive itself rereads the live reservation before certifying bytes.
func (s *Service) UploadCandidate(ctx context.Context, id string, uploader protocol.Object, b []byte) (receipt protocol.Object, err error) {
	if len(b) > MaxBundleBytes {
		return nil, errors.New("candidate size limit")
	}
	b = append([]byte(nil), b...)
	uploader, err = protocol.Decode(consensus.JSON(uploader))
	if err != nil {
		return
	}
	if err = s.Catalog.Profile.Validate(id, "UUID", ""); err != nil {
		return
	}
	if err = s.Catalog.Profile.Validate(uploader, "NodeBinding", ""); err != nil {
		return
	}
	err = s.Directory.Locked(func() error {
		if e := s.physical(); e != nil {
			return e
		}
		key := "core/reservations/" + id
		keys := []string{key, "head", "coordinator", archiveKey(s.ID), "admissions/" + s.ID, "nodes/" + protocol.Text(uploader, "nodeId"), "membership"}
		v, e := s.Catalog.Store.Read(ctx, keys...)
		if e != nil {
			return e
		}
		var envelope struct {
			Record protocol.Object `json:"record"`
			Bundle Bundle          `json:"bundle"`
		}
		var reg Registration
		var head, coordinator, node, membership protocol.Object
		for _, x := range []struct {
			k      string
			target any
		}{{key, &envelope}, {archiveKey(s.ID), &reg}, {"head", &head}, {"coordinator", &coordinator}, {keys[5], &node}, {"membership", &membership}} {
			if e = decode(v.Values[x.k].Bytes, x.target); e != nil {
				return e
			}
		}
		r := envelope.Record
		if e = s.Catalog.Profile.Validate(r, "Reservation", ""); e != nil {
			return e
		}
		if !has([]string{"PREPARING", "READY"}, protocol.Text(r, "state")) || !protocol.Equal(r["predecessor"], head) || !protocol.Equal(r["coordinator"], coordinator) || v.Values["coordinator"].Lease == 0 || reg.State != "ACTIVE" || !protocol.Equal(node["binding"], uploader) || node["active"] != true {
			return errors.New("candidate upload is not current")
		}
		archiveMember, nodeMember, scopeMember := false, false, false
		for _, value := range list(membership["archives"]) {
			if value == s.ID {
				archiveMember = true
			}
		}
		for _, value := range list(membership["nodes"]) {
			if value == uploader["nodeId"] {
				nodeMember = true
			}
		}
		for _, value := range list(node["scopes"]) {
			if value == protocol.Obj(r, "scope")["scopeId"] {
				scopeMember = true
			}
		}
		if !archiveMember || !nodeMember || !scopeMember || reg.PublicKey != protocol.Base(s.Key.Public().(ed25519.PublicKey)) {
			return errors.New("candidate archive/uploader enrollment")
		}
		memberRef := protocol.Object{"id": membership["id"], "version": membership["version"], "digest": protocol.MustDigest(membership)}
		if !protocol.Equal(memberRef, r["membershipRef"]) {
			return errors.New("candidate membership changed")
		}
		allowed := protocol.Equal(r["initiator"], uploader)
		if !allowed {
			allowed = true
			for _, k := range []string{"nodeId", "bootId", "nodeFence"} {
				if coordinator[k] != uploader[k] {
					allowed = false
				}
			}
		}
		if !allowed {
			return errors.New("uploader is not reservation owner/coordinator")
		}
		if e = s.Catalog.matchesAdmission(reg, s.runtime); e != nil {
			return e
		}
		if !sameAdmission(v, reg, s.runtime) {
			return ErrRuntimeFenced
		}
		if e = admissionLineage(head, s.runtime); e != nil {
			return e
		}
		candidate := protocol.Obj(r, "candidate")
		if envelope.Bundle.Ref["id"] != candidate["commitId"] || envelope.Bundle.Descriptor["bundleDigest"] != r["bundleDigest"] || envelope.Bundle.Descriptor["manifestDigest"] != r["manifestDigest"] || envelope.Bundle.Descriptor["bundleLength"] != r["bundleLength"] {
			return errors.New("reserved bundle mismatch")
		}
		if e = VerifyBundle(b, envelope.Bundle); e != nil {
			return e
		}
		if e = s.trip("after-candidate-check"); e != nil {
			return e
		}
		name := protocol.Text(envelope.Bundle.Ref, "id")
		if e = s.Directory.PutImmutable(name+".bundle", b); e != nil {
			return e
		}
		if e = s.Directory.PutImmutable(name+".pin", consensus.JSON(envelope.Bundle.Ref)); e != nil {
			return e
		}
		if e = s.Directory.Sync(); e != nil {
			return e
		}
		if e = s.trip("after-candidate-durability"); e != nil {
			return e
		}
		fresh, e := s.Catalog.Store.Read(ctx, keys...)
		if e != nil {
			return e
		}
		for k, old := range v.Values {
			next := fresh.Values[k]
			if old.Revision != next.Revision || old.Lease != next.Lease || string(old.Bytes) != string(next.Bytes) {
				return consensus.ErrConflict
			}
		}
		if e = s.physical(); e != nil {
			return e
		}
		receipt = protocol.Object{"version": "2", "clusterId": head["clusterId"], "realmId": head["realmId"], "incarnation": head["incarnation"], "reservationId": id, "candidateCommitId": candidate["commitId"], "bundleDigest": r["bundleDigest"], "manifestDigest": r["manifestDigest"], "bundleLength": r["bundleLength"], "archive": reg.Binding, "keyId": reg.KeyID}
		receipt["signature"], e = s.Catalog.Profile.Sign("archiveReceipt", receipt, s.Key)
		if e != nil {
			return e
		}
		if e = s.Directory.PutImmutable("candidate-"+id+"-"+protocol.MustDigest(reg.Binding)+".json", consensus.JSON(receipt)); e != nil {
			return e
		}
		return s.trip("after-candidate-receipt-before-ack")
	})
	return
}

func list(v any) []any { a, _ := v.([]any); return a }
