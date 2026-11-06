package archive

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/consensus"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
)

// CopySnapshot returns the exact authority read set, so a core commit compares
// every predecessor receipt, archive admission/generation and deletion fence.
// Candidate receipts count only after the same transaction has made their
// reservation COMMITTED; READY or a signed upload alone never publishes a core.
func (c *Catalog) CopySnapshot(ctx context.Context, bundle string, ids []string) (consensus.Snapshot, int, error) {
	empty := consensus.Snapshot{}
	if len(ids) != 3 {
		return empty, 0, errors.New("three enrolled archives required")
	}
	if e := c.Profile.Validate(bundle, "UUID", ""); e != nil {
		return empty, 0, e
	}
	first, e := c.Store.Read(ctx, bundleKey(bundle))
	if e != nil {
		return empty, 0, e
	}
	var b Bundle
	if e = decode(first.Values[bundleKey(bundle)].Bytes, &b); e != nil {
		return empty, 0, e
	}
	keys := []string{"head", bundleKey(bundle)}
	seen := map[string]bool{}
	for _, id := range ids {
		if e = c.Profile.Validate(id, "UUID", ""); e != nil || seen[id] {
			return empty, 0, errors.New("archive set")
		}
		seen[id] = true
		keys = append(keys, archiveKey(id), "admissions/"+id, receiptKey(id, bundle), deleteKey(id, bundle))
	}
	if b.ReservationID != "" {
		if e = c.Profile.Validate(b.ReservationID, "UUID", ""); e != nil {
			return empty, 0, e
		}
		keys = append(keys, "core/reservations/"+b.ReservationID)
	}
	v, e := c.Store.Read(ctx, keys...)
	if e != nil {
		return v, 0, e
	}
	if string(v.Values[bundleKey(bundle)].Bytes) != string(first.Values[bundleKey(bundle)].Bytes) {
		return v, 0, consensus.ErrConflict
	}
	if !b.Protected || protocol.Text(b.Ref, "id") != bundle {
		return v, 0, errors.New("bundle is not committed/protected")
	}
	var head protocol.Object
	if e = decode(v.Values["head"].Bytes, &head); e != nil {
		return v, 0, e
	}
	domains := map[string]bool{}
	for _, id := range ids {
		var reg Registration
		var receipt, admission protocol.Object
		if decode(v.Values[archiveKey(id)].Bytes, &reg) != nil || decode(v.Values[receiptKey(id, bundle)].Bytes, &receipt) != nil || decode(v.Values["admissions/"+id].Bytes, &admission) != nil {
			continue
		}
		if c.Profile.Validate(admission, "HostAdmission", "") != nil || admission["nativeClusterId"] != c.Store.NativeID() || admission["componentKind"] != "ARCHIVE" || admission["componentId"] != id || admission["targetIdentityDigest"] != IdentityDigest(reg) || admission["volumeIdentityDigest"] != reg.VolumeIdentityDigest {
			continue
		}
		if reg.State != "ACTIVE" || len(v.Values[deleteKey(id, bundle)].Bytes) > 0 || !protocol.Equal(receipt["archive"], reg.Binding) || reg.AdmissionDigest != protocol.MustDigest(admission) || admission["bootId"] != reg.Binding["bootId"] || admission["storageGeneration"] != reg.Binding["storageGeneration"] {
			continue
		}
		valid := true
		for _, k := range []string{"clusterId", "realmId", "incarnation"} {
			if receipt[k] != head[k] || admission[k] != head[k] {
				valid = false
			}
		}
		if !valid {
			continue
		}
		pub, e := protocol.Unbase(reg.PublicKey, 32)
		if e != nil || receipt["keyId"] != reg.KeyID {
			continue
		}
		domain, typ := "archiveReattestation", "CommittedCopyReceipt"
		if receipt["reattestationId"] == nil {
			domain, typ = "archiveReceipt", "ArchiveReceipt"
			var envelope struct {
				Record protocol.Object `json:"record"`
			}
			if b.ReservationID == "" || decode(v.Values["core/reservations/"+b.ReservationID].Bytes, &envelope) != nil || c.Profile.Validate(envelope.Record, "Reservation", "") != nil || envelope.Record["state"] != "COMMITTED" || receipt["reservationId"] != b.ReservationID {
				continue
			}
			candidate := protocol.Obj(envelope.Record, "candidate")
			if candidate["commitId"] != b.Descriptor["commitId"] || candidate["manifestDigest"] != b.Descriptor["manifestDigest"] || receipt["candidateCommitId"] != b.Descriptor["commitId"] || receipt["bundleDigest"] != b.Descriptor["bundleDigest"] || receipt["bundleLength"] != b.Descriptor["bundleLength"] || receipt["manifestDigest"] != b.Descriptor["manifestDigest"] {
				continue
			}
		} else if !protocol.Equal(receipt["bundleRef"], b.Ref) || !protocol.Equal(receipt["bundle"], b.Descriptor) {
			continue
		}
		if c.Profile.Validate(receipt, typ, "") != nil || c.Profile.Verify(domain, protocol.Unsigned(receipt), protocol.Text(receipt, "signature"), ed25519.PublicKey(pub)) != nil {
			continue
		}
		domains[protocol.Text(reg.Binding, "failureDomainId")] = true
	}
	return v, len(domains), nil
}
