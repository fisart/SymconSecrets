package archive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/consensus"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/durable"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
)

const MaxBundleBytes = 67108864

var magic = []byte{'S', 'Y', 'M', 'C', 'B', '2', 0, 0}

func hashBytes(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// BuildBundle frames an already encrypted manifest and already encrypted objects.
// The archive never encrypts plaintext or receives any vault decryption key.
// The approved descriptor binds all bytes; IndexDigest binds the complete public
// object-reference index. The PHP V1 store is not compatible with this V2 format.
func BuildBundle(manifest []byte, objects []protocol.Object, payloads [][]byte) ([]byte, string, error) {
	if len(objects) != len(payloads) || len(objects) > 100 {
		return nil, "", errors.New("object coverage")
	}
	p, _ := protocol.Load()
	refs := make([]any, len(objects))
	for i, ref := range objects {
		if e := p.Validate(ref, "ObjectRef", ""); e != nil {
			return nil, "", e
		}
		if ref["length"] != strconv.Itoa(len(payloads[i])) || ref["digest"] != hashBytes(payloads[i]) {
			return nil, "", errors.New("object descriptor")
		}
		refs[i] = ref
	}
	index := protocol.Object{"version": "2", "manifestLength": strconv.Itoa(len(manifest)), "manifestDigest": hashBytes(manifest), "objects": refs}
	meta, e := protocol.Canonical(index)
	if e != nil || len(meta) > 65536 {
		return nil, "", errors.New("bundle index")
	}
	var out bytes.Buffer
	out.Write(magic)
	binary.Write(&out, binary.BigEndian, uint32(len(meta)))
	out.Write(meta)
	out.Write(manifest)
	for _, payload := range payloads {
		out.Write(payload)
	}
	if out.Len() > MaxBundleBytes {
		return nil, "", errors.New("bundle cap")
	}
	return out.Bytes(), hashBytes(meta), nil
}
func VerifyBundle(b []byte, expected Bundle) error {
	if len(b) > MaxBundleBytes || len(b) < 12 || !bytes.Equal(b[:8], magic) || expected.Descriptor["bundleLength"] != strconv.Itoa(len(b)) || expected.Descriptor["bundleDigest"] != hashBytes(b) {
		return errors.New("bundle descriptor mismatch")
	}
	n := int(binary.BigEndian.Uint32(b[8:12]))
	if n <= 0 || n > 65536 || 12+n > len(b) {
		return errors.New("bundle index length")
	}
	meta := b[12 : 12+n]
	if hashBytes(meta) != expected.IndexDigest {
		return errors.New("bundle coverage index mismatch")
	}
	index, e := protocol.Decode(meta)
	if e != nil {
		return e
	}
	if len(index) != 4 || index["version"] != "2" {
		return errors.New("closed bundle index")
	}
	for _, k := range []string{"manifestLength", "manifestDigest", "objects"} {
		if _, ok := index[k]; !ok {
			return errors.New("bundle index fields")
		}
	}
	canonical, e := protocol.Canonical(index)
	if e != nil || !bytes.Equal(meta, canonical) {
		return errors.New("noncanonical bundle index")
	}
	p, _ := protocol.Load()
	if e = p.Validate(index["manifestLength"], "Q", ""); e != nil {
		return e
	}
	if e = p.Validate(index["manifestDigest"], "DIGEST", ""); e != nil {
		return e
	}
	objects, ok := index["objects"].([]any)
	if !ok || len(objects) > 100 {
		return errors.New("bundle index objects")
	}
	length, e := strconv.ParseInt(protocol.Text(index, "manifestLength"), 10, 64)
	offset := 12 + n
	if e != nil || length > int64(len(b)-offset) {
		return errors.New("manifest length")
	}
	manifest := b[offset : offset+int(length)]
	if hashBytes(manifest) != index["manifestDigest"] || index["manifestDigest"] != expected.Descriptor["manifestDigest"] {
		return errors.New("manifest digest")
	}
	offset += int(length)
	seen := map[string]bool{}
	for _, obj := range objects {
		if e = p.Validate(obj, "ObjectRef", ""); e != nil {
			return e
		}
		ref := obj.(map[string]any)
		id := protocol.Text(ref, "id")
		if seen[id] {
			return errors.New("duplicate object reference")
		}
		seen[id] = true
		length, e = strconv.ParseInt(protocol.Text(ref, "length"), 10, 64)
		if e != nil || length > int64(len(b)-offset) {
			return errors.New("object length")
		}
		if hashBytes(b[offset:offset+int(length)]) != ref["digest"] {
			return errors.New("object digest")
		}
		offset += int(length)
	}
	if offset != len(b) {
		return errors.New("unreferenced/trailing ciphertext")
	}
	return nil
}

type Service struct {
	Directory *durable.Directory
	Catalog   *Catalog
	ID        string
	Key       ed25519.PrivateKey
	Fault     func(string) error
}
type Reattested struct {
	Receipt    protocol.Object
	Reference  protocol.Object
	Historical bool
}

func Open(path, id string, key ed25519.PrivateKey, catalog *Catalog) (*Service, error) {
	if catalog == nil || len(key) != 64 {
		return nil, errors.New("archive dependencies")
	}
	if e := catalog.Profile.Validate(id, "UUID", ""); e != nil {
		return nil, e
	}
	d, e := durable.Open(path)
	if e != nil {
		return nil, e
	}
	return &Service{Directory: d, Catalog: catalog, ID: id, Key: key}, nil
}
func (s *Service) Close() error { return s.Directory.Close() }
func (s *Service) trip(point string) error {
	if s.Fault != nil {
		return s.Fault(point)
	}
	return nil
}

// Preserve is a local opaque-ciphertext transfer primitive. It grants no copy
// authority. Reattestation still requires current live quorum references.
func (s *Service) Preserve(expected Bundle, b []byte) error {
	if e := s.Catalog.Profile.Validate(expected.Ref, "RecordRef", ""); e != nil {
		return e
	}
	if e := VerifyBundle(b, expected); e != nil {
		return e
	}
	id := protocol.Text(expected.Ref, "id")
	return s.Directory.Locked(func() error {
		if e := s.Directory.PutImmutable(id+".bundle", b); e != nil {
			return e
		}
		return s.Directory.PutImmutable(id+".pin", consensus.JSON(expected.Ref))
	})
}
func (s *Service) Reattest(ctx context.Context, a consensus.Attempt, bundle string) (result Reattested, err error) {
	if old, e := s.Catalog.Store.Resolve(ctx, a); e != nil {
		return result, e
	} else if old != nil {
		if old.Kind != "APPLIED" {
			return result, errors.New("reattestation previously rejected")
		}
		if e = json.Unmarshal(old.Payload, &result.Reference); e != nil {
			return result, e
		}
		result.Historical = true
		return result, nil
	}
	err = s.Directory.Locked(func() error {
		v, e := s.Catalog.View(ctx, s.ID, bundle)
		if e != nil {
			return e
		}
		pub := s.Key.Public().(ed25519.PublicKey)
		if protocol.Base(pub) != v.Archive.PublicKey {
			return errors.New("wrong archive signing key")
		}
		if e = s.trip("after-authority-check"); e != nil {
			return e
		}
		b, e := s.Directory.Read(bundle + ".bundle")
		if e != nil {
			return e
		}
		if e = VerifyBundle(b, v.Bundle); e != nil {
			return e
		}
		// A missing local pin may be reconstructed only from the fresh live reference.
		pin := consensus.JSON(v.Bundle.Ref)
		if e = s.Directory.PutImmutable(bundle+".pin", pin); e != nil {
			return e
		}
		if e = s.Directory.Sync(); e != nil {
			return e
		}
		if e = s.trip("after-local-durability"); e != nil {
			return e
		}
		receipt := protocol.Object{"version": "2", "clusterId": v.Head["clusterId"], "realmId": v.Head["realmId"], "incarnation": v.Head["incarnation"], "reattestationId": a.ID, "bundleRef": v.Bundle.Ref, "bundle": v.Bundle.Descriptor, "referenceIndexRef": v.Index, "verifiedHeadDigest": protocol.MustDigest(v.Head), "archive": v.Archive.Binding, "keyId": v.Archive.KeyID}
		receipt["signature"], e = s.Catalog.Profile.Sign("archiveReattestation", receipt, s.Key)
		if e != nil {
			return e
		}
		// Persist exact action evidence before its potentially ambiguous remote result.
		intent := struct {
			Attempt consensus.Attempt
			Receipt protocol.Object
		}{a, receipt}
		if e = s.Directory.PutImmutable("operation-"+a.ID+".json", consensus.JSON(intent)); e != nil {
			return e
		}
		result.Receipt = receipt
		result.Reference, e = s.Catalog.Register(ctx, a, v, receipt)
		if e != nil {
			return e
		}
		return s.trip("after-registration-before-ack")
	})
	return
}

func (s *Service) Scan(ctx context.Context) (summary, archiveRef protocol.Object, classes Classification, err error) {
	err = s.Directory.Locked(func() error {
		first, e := s.Catalog.Store.Read(ctx, inventoryKey(s.ID), "head", "reference-index", archiveKey(s.ID))
		if e != nil {
			return e
		}
		var inv Inventory
		var head, index protocol.Object
		var reg Registration
		for _, x := range []struct {
			k      string
			target any
		}{{inventoryKey(s.ID), &inv}, {"head", &head}, {"reference-index", &index}, {archiveKey(s.ID), &reg}} {
			if e = decode(first.Values[x.k].Bytes, x.target); e != nil {
				return e
			}
		}
		if len(inv.BundleIDs) > 15 {
			return errors.New("inventory capacity gate")
		}
		archiveRef = registrationRef(reg, first.Values[archiveKey(s.ID)].Revision)
		verified := []string{}
		classes = Classification{Missing: []string{}, Quarantined: []string{}}
		sorted := append([]string{}, inv.BundleIDs...)
		sort.Strings(sorted)
		if !protocol.Equal(toAny(sorted), toAny(inv.BundleIDs)) {
			return errors.New("inventory must be sorted and unique")
		}
		seen := map[string]bool{}
		for _, id := range inv.BundleIDs {
			if seen[id] {
				return errors.New("duplicate inventory bundle")
			}
			seen[id] = true
			v, e := s.Catalog.View(ctx, s.ID, id)
			if e != nil {
				return e
			}
			if !protocol.Equal(v.Head, head) || !protocol.Equal(v.Index, index) || !protocol.Equal(v.Archive.Binding, reg.Binding) {
				return consensus.ErrConflict
			}
			b, e := s.Directory.Read(id + ".bundle")
			if os.IsNotExist(e) {
				classes.Missing = append(classes.Missing, id)
				continue
			}
			if e != nil || VerifyBundle(b, v.Bundle) != nil {
				classes.Quarantined = append(classes.Quarantined, id)
				continue
			}
			pin, e := s.Directory.Read(id + ".pin")
			if e != nil || !bytes.Equal(pin, consensus.JSON(v.Bundle.Ref)) {
				classes.Quarantined = append(classes.Quarantined, id)
				continue
			}
			var receipt protocol.Object
			if decode(v.Snapshot.Values[receiptKey(s.ID, id)].Bytes, &receipt) != nil || !protocol.Equal(receipt["archive"], reg.Binding) || !protocol.Equal(receipt["bundleRef"], v.Bundle.Ref) || !protocol.Equal(receipt["bundle"], v.Bundle.Descriptor) {
				return errors.New("intact bundle requires fresh reattestation before activation")
			}
			pub, e := protocol.Unbase(reg.PublicKey, 32)
			if e != nil {
				return e
			}
			if e = s.Catalog.Profile.Verify("archiveReattestation", protocol.Unsigned(receipt), protocol.Text(receipt, "signature"), ed25519.PublicKey(pub)); e != nil {
				return e
			}
			verified = append(verified, protocol.MustDigest(receipt))
		}
		sort.Strings(verified)
		sort.Strings(classes.Missing)
		sort.Strings(classes.Quarantined)
		summary = protocol.Object{"state": "COMPLETE", "referenceIndexRef": index, "headDigest": protocol.MustDigest(head), "inventoryDigest": protocol.MustDigest(toAny(inv.BundleIDs)), "verifiedReceiptSetDigest": protocol.MustDigest(toAny(verified)), "missingBundleSetDigest": protocol.MustDigest(toAny(classes.Missing)), "quarantinedBundleSetDigest": protocol.MustDigest(toAny(classes.Quarantined)), "protectedBundleCount": number(len(inv.BundleIDs)), "verifiedBundleCount": number(len(verified)), "missingBundleCount": number(len(classes.Missing)), "quarantinedBundleCount": number(len(classes.Quarantined))}
		return nil
	})
	return
}
func (s *Service) Activate(ctx context.Context, a consensus.Attempt) (Registration, error) {
	var result Registration
	if old, e := s.Catalog.Store.Resolve(ctx, a); e != nil {
		return result, e
	} else if old != nil {
		return result, &consensus.AlreadyDecided{Outcome: *old}
	}
	// Keep the same OS lock from physical scan through authority activation.
	// Scan itself obtains that lock, so use a separate explicit scan-and-recheck:
	summary, archiveRef, classes, e := s.Scan(ctx)
	if e != nil {
		return result, e
	}
	e = s.Directory.Locked(func() error {
		// Revalidate physical state under this second lock, before final CAS. A
		// concurrent deletion cannot be hidden behind a previously checked report.
		if e := s.recheckClassified(ctx, summary, classes); e != nil {
			return e
		}
		if e := s.trip("after-scan-before-activation"); e != nil {
			return e
		}
		var err error
		result, err = s.Catalog.Activate(ctx, a, s.ID, archiveRef, summary, classes)
		if err != nil {
			return err
		}
		return s.trip("after-activation-before-ack")
	})
	return result, e
}
func (s *Service) recheckClassified(ctx context.Context, summary protocol.Object, classes Classification) error {
	first, e := s.Catalog.Store.Read(ctx, inventoryKey(s.ID), "head", "reference-index")
	if e != nil {
		return e
	}
	var inv Inventory
	var head, index protocol.Object
	for _, x := range []struct {
		k      string
		target any
	}{{inventoryKey(s.ID), &inv}, {"head", &head}, {"reference-index", &index}} {
		if e = decode(first.Values[x.k].Bytes, x.target); e != nil {
			return e
		}
	}
	if summary["headDigest"] != protocol.MustDigest(head) || !protocol.Equal(summary["referenceIndexRef"], index) {
		return consensus.ErrConflict
	}
	for _, id := range inv.BundleIDs {
		if has(classes.Missing, id) || has(classes.Quarantined, id) {
			continue
		}
		v, e := s.Catalog.View(ctx, s.ID, id)
		if e != nil {
			return e
		}
		b, e := s.Directory.Read(id + ".bundle")
		if e != nil {
			return e
		}
		if e = VerifyBundle(b, v.Bundle); e != nil {
			return e
		}
		pin, e := s.Directory.Read(id + ".pin")
		if e != nil || !bytes.Equal(pin, consensus.JSON(v.Bundle.Ref)) {
			return errors.New("pin changed after scan")
		}
	}
	return nil
}
