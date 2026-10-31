// Package archive implements current-generation committed-copy recovery.
// Its control methods require an enrolled service and current lineage. They do
// not accept user requests or create/modify vault heads or administrator rights.
package archive

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/consensus"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/trust"
)

type Registration struct {
	Binding              protocol.Object `json:"binding"`
	State                string          `json:"state"`
	KeyID                string          `json:"keyId"`
	PublicKey            string          `json:"publicKey"`
	AdmissionDigest      string          `json:"admissionDigest"`
	VolumeIdentityDigest string          `json:"volumeIdentityDigest"`
}
type Bundle struct {
	ReservationID string          `json:"reservationId,omitempty"`
	Ref           protocol.Object `json:"ref"`
	Descriptor    protocol.Object `json:"descriptor"`
	IndexDigest   string          `json:"indexDigest"`
	Protected     bool            `json:"protected"`
}
type Inventory struct {
	Ref        protocol.Object `json:"ref"`
	BundleIDs  []string        `json:"bundleIds"`
	ArchiveIDs []string        `json:"archiveIds"`
}
type View struct {
	Snapshot consensus.Snapshot
	Head     protocol.Object
	Index    protocol.Object
	Archive  Registration
	Bundle   Bundle
}
type Catalog struct {
	Store   *consensus.Store
	Profile *protocol.Profile
}
type Classification struct {
	Missing     []string
	Quarantined []string
}

func NewCatalog(s *consensus.Store) (*Catalog, error) {
	p, e := protocol.Load()
	if e != nil {
		return nil, e
	}
	return &Catalog{s, p}, nil
}
func archiveKey(id string) string              { return "archives/" + id }
func bundleKey(id string) string               { return "bundles/" + id }
func receiptKey(archive, bundle string) string { return "receipts/" + archive + "/" + bundle }
func deleteKey(archive, bundle string) string  { return "deletions/" + archive + "/" + bundle }
func inventoryKey(archive string) string       { return "inventory/" + archive }
func decode(b []byte, v any) error {
	if len(b) == 0 {
		return errors.New("required authority record missing")
	}
	return json.Unmarshal(b, v)
}
func (c *Catalog) View(ctx context.Context, archive, bundle string) (v View, err error) {
	for _, id := range []string{archive, bundle} {
		if err = c.Profile.Validate(id, "UUID", ""); err != nil {
			return
		}
	}
	v.Snapshot, err = c.Store.Read(ctx, "head", "reference-index", archiveKey(archive), "admissions/"+archive, bundleKey(bundle), deleteKey(archive, bundle), receiptKey(archive, bundle), inventoryKey(archive))
	if err != nil {
		return
	}
	for _, x := range []struct {
		k      string
		target any
	}{{"head", &v.Head}, {"reference-index", &v.Index}, {archiveKey(archive), &v.Archive}, {bundleKey(bundle), &v.Bundle}} {
		if err = decode(v.Snapshot.Values[x.k].Bytes, x.target); err != nil {
			return
		}
	}
	if err = c.Profile.Validate(v.Head, "Head", ""); err != nil {
		return
	}
	if err = c.Profile.Validate(v.Index, "RecordRef", ""); err != nil {
		return
	}
	if err = c.Profile.Validate(v.Archive.Binding, "ArchiveBinding", ""); err != nil {
		return
	}
	if err = c.Profile.Validate(v.Bundle.Ref, "RecordRef", ""); err != nil {
		return
	}
	if err = c.Profile.Validate(v.Bundle.Descriptor, "BundleDescriptor", ""); err != nil {
		return
	}
	var inv Inventory
	if err = decode(v.Snapshot.Values[inventoryKey(archive)].Bytes, &inv); err != nil {
		return
	}
	if !has(inv.BundleIDs, bundle) || !v.Bundle.Protected || protocol.Text(v.Bundle.Ref, "id") != bundle || len(v.Snapshot.Values[deleteKey(archive, bundle)].Bytes) != 0 {
		return v, errors.New("bundle not protected or deletion fenced")
	}
	if !has([]string{"VERIFYING", "REPAIRING", "ACTIVE"}, v.Archive.State) || protocol.Text(v.Archive.Binding, "archiveId") != archive {
		return v, errors.New("archive not admitted")
	}
	return
}
func has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// Boot is called only after independent HostAdmission consumption. A later boot
// changes the generation/registration so every older receipt stops counting.
func (c *Catalog) Boot(ctx context.Context, a consensus.Attempt, previous, next Registration, runtime *trust.AdmittedRuntime) error {
	if e := c.matchesAdmission(next, runtime); e != nil {
		return e
	}
	admission := runtime.Record()
	if admission["bootOperationId"] != a.ID {
		return errors.New("archive boot operation binding")
	}
	if e := c.Profile.Validate(next.Binding, "ArchiveBinding", ""); e != nil {
		return e
	}
	// History resolves the exact immutable attempt; it does not reinstall a
	// generation or bypass present serving checks on an old runtime.
	if outcome, e := c.Store.Resolve(ctx, a); e != nil {
		return e
	} else if outcome != nil {
		if outcome.Kind != "APPLIED" || string(outcome.Payload) != string(consensus.JSON(next)) {
			return consensus.ErrIDReuse
		}
		return &consensus.AlreadyDecided{Outcome: *outcome}
	}
	id := protocol.Text(next.Binding, "archiveId")
	v, e := c.Store.Read(ctx, archiveKey(id), "admissions/"+id, "head")
	if e != nil {
		return e
	}
	var head protocol.Object
	if e = decode(v.Values["head"].Bytes, &head); e != nil {
		return e
	}
	if e = admissionLineage(head, runtime); e != nil {
		return e
	}
	if string(v.Values[archiveKey(id)].Bytes) != string(consensus.JSON(previous)) {
		return consensus.ErrConflict
	}
	var installed protocol.Object
	if e = decode(v.Values["admissions/"+id].Bytes, &installed); e != nil {
		return e
	}
	if e = c.matchesAdmissionRecord(previous, installed); e != nil {
		return e
	}
	if e = runtime.Succeeds(installed); e != nil {
		return e
	}
	if next.State != "VERIFYING" || previous.State == "REMOVED" || previous.State == "QUARANTINED" || next.KeyID != previous.KeyID || next.PublicKey != previous.PublicKey {
		return errors.New("invalid archive boot transition")
	}
	if next.Binding["storageGeneration"] == previous.Binding["storageGeneration"] || next.Binding["bootId"] == previous.Binding["bootId"] || next.Binding["archiveId"] != previous.Binding["archiveId"] || next.Binding["failureDomainId"] != previous.Binding["failureDomainId"] {
		return errors.New("fresh archive boot/generation required")
	}
	if next.Binding["registrationVersion"] != increment(protocol.Text(previous.Binding, "registrationVersion")) {
		return errors.New("archive registration version")
	}
	_, e = c.Store.Apply(ctx, a, v, []consensus.Write{{Key: archiveKey(id), Bytes: consensus.JSON(next)}, {Key: "admissions/" + id, Bytes: consensus.JSON(admission)}}, "APPLIED", next)
	return e
}
func increment(s string) string { // schema validation already bounds the operand
	digits := []byte(s)
	for i := len(digits) - 1; i >= 0; i-- {
		if digits[i] < '9' {
			digits[i]++
			return string(digits)
		}
		digits[i] = '0'
	}
	return "1" + string(digits)
}

func (c *Catalog) Register(ctx context.Context, a consensus.Attempt, v View, receipt protocol.Object, runtime *trust.AdmittedRuntime) (protocol.Object, error) {
	if e := admissionLineage(v.Head, runtime); e != nil {
		return nil, e
	}
	if e := c.matchesAdmission(v.Archive, runtime); e != nil {
		return nil, e
	}
	if !sameAdmission(v.Snapshot, v.Archive, runtime) {
		return nil, ErrRuntimeFenced
	}
	if e := c.Profile.Validate(receipt, "CommittedCopyReceipt", ""); e != nil {
		return nil, e
	}
	id := protocol.Text(v.Archive.Binding, "archiveId")
	bundleID := protocol.Text(v.Bundle.Ref, "id")
	if !protocol.Equal(receipt["archive"], v.Archive.Binding) || !protocol.Equal(receipt["bundleRef"], v.Bundle.Ref) || !protocol.Equal(receipt["bundle"], v.Bundle.Descriptor) || !protocol.Equal(receipt["referenceIndexRef"], v.Index) || receipt["verifiedHeadDigest"] != protocol.MustDigest(v.Head) || receipt["reattestationId"] != a.ID || receipt["keyId"] != v.Archive.KeyID {
		return nil, errors.New("reattestation context")
	}
	for _, k := range []string{"clusterId", "realmId", "incarnation"} {
		if receipt[k] != v.Head[k] {
			return nil, errors.New("reattestation lineage")
		}
	}
	pub, e := protocol.Unbase(v.Archive.PublicKey, 32)
	if e != nil {
		return nil, e
	}
	if e = c.Profile.Verify("archiveReattestation", protocol.Unsigned(receipt), protocol.Text(receipt, "signature"), ed25519.PublicKey(pub)); e != nil {
		return nil, e
	}
	ref := protocol.Object{"id": a.ID, "version": "1", "digest": protocol.MustDigest(receipt)}
	_, e = c.Store.Apply(ctx, a, v.Snapshot, []consensus.Write{{Key: receiptKey(id, bundleID), Bytes: consensus.JSON(receipt)}}, "APPLIED", ref)
	return ref, e
}

// Activate compares the complete classified inventory and every receipt version.
// This checkpoint caps one inventory at 15 retained bundles; it fails closed
// rather than accepting partial scans. Pagination is a release-gated follow-up.
func (c *Catalog) Activate(ctx context.Context, a consensus.Attempt, archive string, expectedArchiveRef, report protocol.Object, classes Classification, runtime *trust.AdmittedRuntime) (Registration, error) {
	if e := c.Profile.Validate(expectedArchiveRef, "RecordRef", ""); e != nil {
		return Registration{}, e
	}
	if e := c.Profile.Validate(report, "ArchiveScanSummary", ""); e != nil {
		return Registration{}, e
	}
	initial, e := c.Store.Read(ctx, inventoryKey(archive))
	if e != nil {
		return Registration{}, e
	}
	var inv Inventory
	if e = decode(initial.Values[inventoryKey(archive)].Bytes, &inv); e != nil {
		return Registration{}, e
	}
	if len(inv.BundleIDs) > 15 {
		return Registration{}, errors.New("inventory capacity gate; partial activation forbidden")
	}
	keys := []string{"head", "reference-index", archiveKey(archive), "admissions/" + archive, inventoryKey(archive)}
	for _, id := range inv.BundleIDs {
		keys = append(keys, bundleKey(id), receiptKey(archive, id), deleteKey(archive, id))
	}
	v, e := c.Store.Read(ctx, keys...)
	if e != nil {
		return Registration{}, e
	}
	if string(v.Values[inventoryKey(archive)].Bytes) != string(initial.Values[inventoryKey(archive)].Bytes) {
		return Registration{}, consensus.ErrConflict
	}
	var reg Registration
	var head, index protocol.Object
	for _, x := range []struct {
		k      string
		target any
	}{{archiveKey(archive), &reg}, {"head", &head}, {"reference-index", &index}} {
		if e = decode(v.Values[x.k].Bytes, x.target); e != nil {
			return reg, e
		}
	}
	if !has([]string{"VERIFYING", "REPAIRING"}, reg.State) {
		return reg, errors.New("archive activation state")
	}
	if e = c.matchesAdmission(reg, runtime); e != nil {
		return reg, e
	}
	if e = admissionLineage(head, runtime); e != nil {
		return reg, e
	}
	if !sameAdmission(v, reg, runtime) {
		return reg, ErrRuntimeFenced
	}
	if !protocol.Equal(expectedArchiveRef, registrationRef(reg, v.Values[archiveKey(archive)].Revision)) {
		return reg, consensus.ErrConflict
	}
	if report["headDigest"] != protocol.MustDigest(head) || !protocol.Equal(report["referenceIndexRef"], index) || report["inventoryDigest"] != protocol.MustDigest(toAny(inv.BundleIDs)) {
		return reg, consensus.ErrConflict
	}
	verified := []string{}
	other := []string{}
	writes := []consensus.Write{}
	for _, id := range inv.BundleIDs {
		var b Bundle
		if e = decode(v.Values[bundleKey(id)].Bytes, &b); e != nil {
			return reg, e
		}
		if !b.Protected {
			return reg, errors.New("inventory reference not protected")
		}
		var r protocol.Object
		if len(v.Values[receiptKey(archive, id)].Bytes) > 0 {
			if e = decode(v.Values[receiptKey(archive, id)].Bytes, &r); e != nil {
				return reg, e
			}
		}
		classifiedBad := has(classes.Missing, id) || has(classes.Quarantined, id)
		if r != nil && !classifiedBad && len(v.Values[deleteKey(archive, id)].Bytes) == 0 && protocol.Equal(r["archive"], reg.Binding) && protocol.Equal(r["bundleRef"], b.Ref) && protocol.Equal(r["bundle"], b.Descriptor) {
			verified = append(verified, protocol.MustDigest(r))
		} else {
			other = append(other, id)
			if classifiedBad && r != nil {
				writes = append(writes, consensus.Write{Key: receiptKey(archive, id), Delete: true})
			}
		}
	}
	sort.Strings(verified)
	sort.Strings(other)
	if report["protectedBundleCount"] != number(len(inv.BundleIDs)) || report["verifiedBundleCount"] != number(len(verified)) || report["verifiedReceiptSetDigest"] != protocol.MustDigest(toAny(verified)) {
		return reg, errors.New("incomplete verified inventory")
	}
	// The archive classifies physical failures; the authority checks complete
	// disjoint coverage and the digest of the supplied classification lists.
	missing, e := strconvCount(report, "missingBundleCount")
	if e != nil {
		return reg, e
	}
	bad, e := strconvCount(report, "quarantinedBundleCount")
	if e != nil {
		return reg, e
	}
	if missing+bad != len(other) {
		return reg, errors.New("incomplete unavailable inventory")
	}
	sort.Strings(classes.Missing)
	sort.Strings(classes.Quarantined)
	all := append(append([]string{}, classes.Missing...), classes.Quarantined...)
	sort.Strings(all)
	if missing != len(classes.Missing) || bad != len(classes.Quarantined) || !protocol.Equal(toAny(all), toAny(other)) || report["missingBundleSetDigest"] != protocol.MustDigest(toAny(classes.Missing)) || report["quarantinedBundleSetDigest"] != protocol.MustDigest(toAny(classes.Quarantined)) {
		return reg, errors.New("classification coverage/digest mismatch")
	}
	// Classification artifacts must be resolved by digest by a future network
	// adapter; this internal API never silently assumes unavailable entries passed.
	reg.State = "ACTIVE"
	writes = append(writes, consensus.Write{Key: archiveKey(archive), Bytes: consensus.JSON(reg)})
	_, e = c.Store.Apply(ctx, a, v, writes, "APPLIED", reg)
	return reg, e
}
func registrationRef(reg Registration, revision int64) protocol.Object {
	record := protocol.Object{"binding": reg.Binding, "state": reg.State, "keyId": reg.KeyID, "publicKey": reg.PublicKey, "admissionDigest": reg.AdmissionDigest, "volumeIdentityDigest": reg.VolumeIdentityDigest}
	return protocol.Object{"id": reg.Binding["archiveId"], "version": strconv.FormatInt(revision, 10), "digest": protocol.MustDigest(record)}
}
func toAny(xs []string) []any {
	a := make([]any, len(xs))
	for i, x := range xs {
		a[i] = x
	}
	return a
}
func number(n int) string { return strconv.Itoa(n) }
func strconvCount(o protocol.Object, k string) (int, error) {
	n, e := strconv.ParseInt(protocol.Text(o, k), 10, 32)
	if e != nil || n < 0 || n > 15 {
		return 0, errors.New("inventory count")
	}
	return int(n), nil
}

// Health never trusts a cached REDUNDANT label. It derives health from one
// linearizable snapshot of all current archive generations and bundle receipts.
func (c *Catalog) Health(ctx context.Context, bundle string, archiveIDs []string) (string, error) {
	_, count, e := c.CopySnapshot(ctx, bundle, archiveIDs)
	if e != nil {
		return "", e
	}
	if count >= 2 {
		return "REDUNDANT", nil
	}
	if count == 1 {
		return "DEGRADED", nil
	}
	return "UNAVAILABLE", nil
}
