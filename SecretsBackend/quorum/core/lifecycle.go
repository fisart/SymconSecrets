package core

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"sort"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/archive"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/consensus"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
)

func (c *Controller) Reserve(ctx context.Context, commandID string, a ApprovedIntent, actor protocol.Object) (Reservation, error) {
	var r Reservation
	var err error
	a, err = ownApproved(a)
	if err != nil {
		return r, err
	}
	actor, err = ownObject(actor, "NodeBinding")
	if err != nil {
		return r, err
	}
	i := a.Intent
	id := protocol.Text(i.CandidateHead, "commitId")
	cmd := attempt(commandID, "reserve", map[string]any{"approved": object(a), "actor": actor})
	if e := c.history(ctx, cmd); e != nil {
		return r, e
	}
	v, m, coordinator, e := c.live(ctx, a, actor, reservationKey(id), "core/review-audit/"+i.UserOperationID, "bundles/"+id)
	if e != nil {
		return r, e
	}
	if len(v.Values[originalKey(i.UserOperationID)].Bytes) > 0 || len(v.Values["bundles/"+id].Bytes) > 0 || len(v.Values[pendingKey()].Bytes) > 0 || len(v.Values[reservationKey(id)].Bytes) > 0 || len(v.Values[consumedKey(a)].Bytes) > 0 || len(v.Values["core/review-audit/"+i.UserOperationID].Bytes) > 0 {
		return r, consensus.ErrConflict
	}
	catalog, _ := archive.NewCatalog(c.Store)
	copies, count, e := catalog.CopySnapshot(ctx, protocol.Text(i.ExpectedHead, "commitId"), m.Archives)
	if e != nil {
		return r, e
	}
	if count < 2 {
		return r, errors.New("predecessor requires two current copies")
	}
	v, e = merge(v, copies)
	if e != nil {
		return r, e
	}
	review := map[string]any{"userOperationId": i.UserOperationID, "intentDigest": Digest(i), "permittedDiffDigest": i.PermittedDiffDigest}
	auditRef := Ref(i.UserOperationID, "1", review)
	r = Reservation{Approved: a, Bundle: i.Bundle, Record: protocol.Object{"id": id, "version": "1", "purpose": "CORE", "state": "PREPARING", "userOperationId": i.UserOperationID, "originalActionDigest": Digest(i), "predecessor": i.ExpectedHead, "candidate": i.CandidateHead, "bundleDigest": i.Bundle.Descriptor["bundleDigest"], "manifestDigest": i.Bundle.Descriptor["manifestDigest"], "bundleLength": i.Bundle.Descriptor["bundleLength"], "initiator": i.Owner, "coordinator": coordinator, "scope": i.Scope, "policyRef": i.PolicyRef, "membershipRef": i.MembershipRef, "approvalRef": a.ApprovalRef, "receiptRefs": []any{}, "auditRef": auditRef}}
	if e = c.profile.Validate(r.Record, "Reservation", ""); e != nil {
		return r, e
	}
	writes := []consensus.Write{{Key: originalKey(i.UserOperationID), Bytes: consensus.JSON(original(i))}, {Key: reservationKey(id), Bytes: consensus.JSON(r)}, {Key: pendingKey(), Bytes: consensus.JSON(map[string]string{"id": id})}, {Key: consumedKey(a), Bytes: consensus.JSON(map[string]string{"reservationId": id, "intentDigest": Digest(i)})}, {Key: "core/review-audit/" + i.UserOperationID, Bytes: consensus.JSON(review)}}
	e = c.finish(ctx, cmd, v, writes, "APPLIED", ReservationRef(r))
	return r, e
}
func (c *Controller) stage(ctx context.Context, id string, ref, actor protocol.Object, extra ...string) (Reservation, consensus.Snapshot, Membership, error) {
	r, e := c.readReservation(ctx, id, ref)
	if e != nil {
		return r, consensus.Snapshot{}, Membership{}, e
	}
	keys := addKeys(extra, reservationKey(id), "core/review-audit/"+r.Approved.Intent.UserOperationID)
	v, m, coordinator, e := c.live(ctx, r.Approved, actor, keys...)
	if e != nil {
		return r, v, m, e
	}
	if len(v.Values[originalKey(r.Approved.Intent.UserOperationID)].Bytes) == 0 {
		return r, v, m, ErrAuthorization
	}
	var current Reservation
	var pending, consumed, review protocol.Object
	for _, x := range []struct {
		k      string
		target any
	}{{reservationKey(id), &current}, {pendingKey(), &pending}, {consumedKey(r.Approved), &consumed}, {"core/review-audit/" + r.Approved.Intent.UserOperationID, &review}} {
		if e = load(v, x.k, x.target); e != nil {
			return r, v, m, e
		}
	}
	if !protocol.Equal(ref, ReservationRef(current)) || !protocol.Equal(r.Record["coordinator"], coordinator) || pending["id"] != id || consumed["reservationId"] != id || consumed["intentDigest"] != Digest(r.Approved.Intent) || !protocol.Equal(Ref(r.Approved.Intent.UserOperationID, "1", review), r.Record["auditRef"]) {
		return r, v, m, consensus.ErrConflict
	}
	return current, v, m, nil
}
func (c *Controller) verifyReceipt(v consensus.Snapshot, r Reservation, receipt protocol.Object) (string, error) {
	if e := c.profile.Validate(receipt, "ArchiveReceipt", ""); e != nil {
		return "", e
	}
	id := protocol.Text(protocol.Obj(receipt, "archive"), "archiveId")
	reg, e := currentArchive(v, id)
	if e != nil {
		return "", e
	}
	i := r.Approved.Intent
	var admission protocol.Object
	if e = load(v, "admissions/"+id, &admission); e != nil {
		return "", e
	}
	if admission["nativeClusterId"] != c.Store.NativeID() || admission["volumeIdentityDigest"] != reg.VolumeIdentityDigest || admission["targetIdentityDigest"] != archive.IdentityDigest(reg) {
		return "", ErrAuthorization
	}
	for _, k := range []string{"clusterId", "realmId", "incarnation"} {
		if admission[k] != i.ExpectedHead[k] {
			return "", ErrAuthorization
		}
	}
	if !protocol.Equal(receipt["archive"], reg.Binding) || receipt["reservationId"] != r.Record["id"] || receipt["candidateCommitId"] != i.CandidateHead["commitId"] || receipt["bundleDigest"] != i.Bundle.Descriptor["bundleDigest"] || receipt["manifestDigest"] != i.Bundle.Descriptor["manifestDigest"] || receipt["bundleLength"] != i.Bundle.Descriptor["bundleLength"] || receipt["keyId"] != reg.KeyID {
		return "", ErrAuthorization
	}
	for _, k := range []string{"clusterId", "realmId", "incarnation"} {
		if receipt[k] != i.ExpectedHead[k] {
			return "", ErrAuthorization
		}
	}
	pub, e := protocol.Unbase(reg.PublicKey, 32)
	if e != nil {
		return "", e
	}
	if e = c.profile.Verify("archiveReceipt", protocol.Unsigned(receipt), protocol.Text(receipt, "signature"), ed25519.PublicKey(pub)); e != nil {
		return "", e
	}
	return protocol.Text(reg.Binding, "failureDomainId"), nil
}
func (c *Controller) RegisterReceipt(ctx context.Context, commandID, id string, ref, receipt, actor protocol.Object) (Reservation, error) {
	var inputErr error
	ref, inputErr = ownObject(ref, "RecordRef")
	if inputErr != nil {
		return Reservation{}, inputErr
	}
	actor, inputErr = ownObject(actor, "NodeBinding")
	if inputErr != nil {
		return Reservation{}, inputErr
	}
	receipt, inputErr = ownObject(receipt, "ArchiveReceipt")
	if inputErr != nil {
		return Reservation{}, inputErr
	}

	cmd := attempt(commandID, "receipt", map[string]any{"reservationId": id, "reservation": ref, "receipt": receipt, "actor": actor})
	if e := c.history(ctx, cmd); e != nil {
		return Reservation{}, e
	}
	first, e := c.readReservation(ctx, id, ref)
	if e != nil {
		return first, e
	}
	memberID := protocol.Text(protocol.Obj(receipt, "archive"), "archiveId")
	var m Membership
	view, e := c.Store.Read(ctx, "membership")
	if e != nil {
		return first, e
	}
	if e = load(view, "membership", &m); e != nil {
		return first, e
	}
	if !has(m.Archives, memberID) {
		return first, ErrAuthorization
	}
	key := candidateReceiptKey(id, memberID)
	r, v, currentMembership, e := c.stage(ctx, id, ref, actor, append(archiveKeys(m.Archives), key)...)
	if e != nil {
		return r, e
	}
	if !has(currentMembership.Archives, memberID) {
		return r, ErrAuthorization
	}
	if r.Record["state"] != "PREPARING" {
		return r, errors.New("receipt cannot revive/modify ready or terminal candidate")
	}
	if _, e = c.verifyReceipt(v, r, receipt); e != nil {
		return r, e
	}
	if len(v.Values[key].Bytes) > 0 {
		return r, consensus.ErrConflict
	}
	e = c.finish(ctx, cmd, v, []consensus.Write{{Key: key, Bytes: consensus.JSON(receipt)}}, "APPLIED", Ref(memberID, "1", receipt))
	return r, e
}
func (c *Controller) candidateCopies(ctx context.Context, r Reservation, v consensus.Snapshot, m Membership) (consensus.Snapshot, []any, error) {
	keys := archiveKeys(m.Archives)
	id := protocol.Text(r.Record, "id")
	for _, aid := range m.Archives {
		keys = append(keys, candidateReceiptKey(id, aid))
	}
	fresh, e := c.Store.Read(ctx, keys...)
	if e != nil {
		return v, nil, e
	}
	v, e = merge(v, fresh)
	if e != nil {
		return v, nil, e
	}
	refs := []any{}
	domains := map[string]bool{}
	for _, aid := range m.Archives {
		key := candidateReceiptKey(id, aid)
		if len(v.Values[key].Bytes) == 0 {
			continue
		}
		var receipt protocol.Object
		if e = load(v, key, &receipt); e != nil {
			return v, nil, e
		}
		domain, err := c.verifyReceipt(v, r, receipt)
		if err != nil {
			return v, nil, err
		}
		domains[domain] = true
		refs = append(refs, Ref(aid, "1", receipt))
	}
	sort.Slice(refs, func(i, j int) bool {
		return protocol.Text(refs[i].(map[string]any), "id") < protocol.Text(refs[j].(map[string]any), "id")
	})
	if len(domains) < 2 {
		return v, nil, errors.New("candidate requires two current independent copies")
	}
	return v, refs, nil
}
func (c *Controller) Ready(ctx context.Context, commandID, id string, ref, actor protocol.Object) (Reservation, error) {
	var inputErr error
	ref, inputErr = ownObject(ref, "RecordRef")
	if inputErr != nil {
		return Reservation{}, inputErr
	}
	actor, inputErr = ownObject(actor, "NodeBinding")
	if inputErr != nil {
		return Reservation{}, inputErr
	}

	cmd := attempt(commandID, "ready", map[string]any{"reservationId": id, "reservation": ref, "actor": actor})
	if e := c.history(ctx, cmd); e != nil {
		return Reservation{}, e
	}
	r, v, m, e := c.stage(ctx, id, ref, actor)
	if e != nil {
		return r, e
	}
	if r.Record["state"] != "PREPARING" {
		return r, consensus.ErrConflict
	}
	v, refs, e := c.candidateCopies(ctx, r, v, m)
	if e != nil {
		return r, e
	}
	version, e := increment(protocol.Text(r.Record, "version"))
	if e != nil {
		return r, e
	}
	r.Record["state"] = "READY"
	r.Record["version"] = version
	r.Record["receiptRefs"] = refs
	e = c.finish(ctx, cmd, v, []consensus.Write{{Key: reservationKey(id), Bytes: consensus.JSON(r)}}, "APPLIED", ReservationRef(r))
	return r, e
}
func (c *Controller) Commit(ctx context.Context, commandID, id string, ref, actor protocol.Object) (UserOutcome, error) {
	var inputErr error
	ref, inputErr = ownObject(ref, "RecordRef")
	if inputErr != nil {
		return UserOutcome{}, inputErr
	}
	actor, inputErr = ownObject(actor, "NodeBinding")
	if inputErr != nil {
		return UserOutcome{}, inputErr
	}

	var out UserOutcome
	cmd := attempt(commandID, "commit", map[string]any{"reservationId": id, "reservation": ref, "actor": actor})
	if e := c.history(ctx, cmd); e != nil {
		return out, e
	}
	r, v, m, e := c.stage(ctx, id, ref, actor, "reference-index", "core/revision", "core/head-pin", auditKey(id), "bundles/"+id)
	if e != nil {
		return out, e
	}
	if r.Record["state"] != "READY" {
		return out, consensus.ErrConflict
	}
	v, refs, e := c.candidateCopies(ctx, r, v, m)
	if e != nil {
		return out, e
	}
	if !protocol.Equal(refs, r.Record["receiptRefs"]) {
		return out, consensus.ErrConflict
	}
	catalog, _ := archive.NewCatalog(c.Store)
	i := r.Approved.Intent
	predecessor, count, e := catalog.CopySnapshot(ctx, protocol.Text(i.ExpectedHead, "commitId"), m.Archives)
	if e != nil {
		return out, e
	}
	if count < 2 {
		return out, errors.New("predecessor copies lost before commit")
	}
	v, e = merge(v, predecessor)
	if e != nil {
		return out, e
	}
	extra := []string{}
	for _, aid := range m.Archives {
		extra = append(extra, "inventory/"+aid, "receipts/"+aid+"/"+id, "deletions/"+aid+"/"+id)
	}
	for _, d := range i.Outbox {
		extra = append(extra, "core/pairings/"+protocol.Text(d.PairingRef, "id"))
	}
	extra = addKeys(extra, "core/outbox/"+i.UserOperationID, "core/sequences")
	more, e := c.Store.Read(ctx, extra...)
	if e != nil {
		return out, e
	}
	v, e = merge(v, more)
	if e != nil {
		return out, e
	}
	if len(v.Values["bundles/"+id].Bytes) > 0 || len(v.Values[auditKey(id)].Bytes) > 0 || string(v.Values["core/revision"].Bytes) != protocol.Text(i.ExpectedHead, "index") {
		return out, consensus.ErrConflict
	}
	var oldPin, oldIndex protocol.Object
	if e = load(v, "core/head-pin", &oldPin); e != nil {
		return out, e
	}
	if oldPin["id"] != i.ExpectedHead["commitId"] {
		return out, consensus.ErrConflict
	}
	if e = load(v, "reference-index", &oldIndex); e != nil {
		return out, e
	}
	version, e := increment(protocol.Text(r.Record, "version"))
	if e != nil {
		return out, e
	}
	r.Record["state"] = "COMMITTED"
	r.Record["version"] = version
	out = UserOutcome{Version: "1", UserOperationID: i.UserOperationID, IntentDigest: Digest(i), Result: "COMMITTED", Head: i.CandidateHead, Reason: "NONE"}
	b := i.Bundle
	b.Protected = true
	b.ReservationID = id
	nextScope := protocol.Obj(object(i), "scope")
	nextScope["revision"] = i.NewRevision
	nextScope["objectDigest"] = i.NewScopeDigest
	indexVersion, e := increment(protocol.Text(oldIndex, "version"))
	if e != nil {
		return out, e
	}
	index := Ref(protocol.Text(oldIndex, "id"), indexVersion, map[string]any{"previous": oldIndex, "retained": oldPin, "current": b.Ref})
	audit := map[string]any{"original": object(out), "reviewRef": r.Record["auditRef"], "approvalRef": r.Record["approvalRef"], "coordinator": r.Record["coordinator"], "scope": i.Scope, "changeClass": i.ChangeClass}
	writes := []consensus.Write{{Key: "head", Bytes: consensus.JSON(i.CandidateHead)}, {Key: reservationKey(id), Bytes: consensus.JSON(r)}, {Key: outcomeKey(i.UserOperationID), Bytes: consensus.JSON(out)}, {Key: pendingKey(), Delete: true}, {Key: "core/revision", Bytes: []byte(protocol.Text(i.CandidateHead, "index"))}, {Key: "core/head-pin", Bytes: consensus.JSON(b.Ref)}, {Key: scopeKey(i), Bytes: consensus.JSON(nextScope)}, {Key: "bundles/" + id, Bytes: consensus.JSON(b)}, {Key: "reference-index", Bytes: consensus.JSON(index)}, {Key: auditKey(id), Bytes: consensus.JSON(audit)}}
	for _, aid := range m.Archives {
		key := "inventory/" + aid
		var inv archive.Inventory
		if e = load(v, key, &inv); e != nil {
			return out, e
		}
		if !slices.Equal(inv.ArchiveIDs, m.Archives) || len(inv.BundleIDs) >= 15 || has(inv.BundleIDs, id) || len(v.Values["receipts/"+aid+"/"+id].Bytes) > 0 || len(v.Values["deletions/"+aid+"/"+id].Bytes) > 0 {
			return out, errors.New("inventory/deletion capacity conflict")
		}
		inv.BundleIDs = append(inv.BundleIDs, id)
		sort.Strings(inv.BundleIDs)
		n, e := increment(protocol.Text(inv.Ref, "version"))
		if e != nil {
			return out, e
		}
		inv.Ref = Ref(protocol.Text(inv.Ref, "id"), n, map[string]any{"bundles": toAny(inv.BundleIDs), "archives": toAny(inv.ArchiveIDs)})
		writes = append(writes, consensus.Write{Key: key, Bytes: consensus.JSON(inv)})
		receipt := v.Values[candidateReceiptKey(id, aid)].Bytes
		if len(receipt) > 0 {
			writes = append(writes, consensus.Write{Key: "receipts/" + aid + "/" + id, Bytes: receipt})
		}
	}
	batch := JobBatch{Jobs: []Job{}}
	cursors := SequenceState{Entries: []Sequence{}}
	if len(v.Values["core/sequences"].Bytes) > 0 {
		if e = load(v, "core/sequences", &cursors); e != nil {
			return out, e
		}
		if cursors.Entries == nil {
			return out, errors.New("invalid sequence registry")
		}
	}
	high := map[string]string{}
	for _, entry := range cursors.Entries {
		if c.profile.Validate(entry.RecipientID, "UUID", "") != nil || c.profile.Validate(entry.Value, "Q_POS", "") != nil || high[entry.RecipientID] != "" {
			return out, errors.New("invalid sequence high water")
		}
		high[entry.RecipientID] = entry.Value
	}

	jobKey := "core/outbox/" + i.UserOperationID
	if len(v.Values[jobKey].Bytes) > 0 {
		return out, consensus.ErrIDReuse
	}
	for _, d := range i.Outbox {
		key := "core/pairings/" + protocol.Text(d.PairingRef, "id")
		var pairing Pairing
		if e = load(v, key, &pairing); e != nil {
			return out, e
		}
		if !pairing.Active || pairing.RecipientID != d.RecipientID || !protocol.Equal(Ref(pairing.ID, pairing.Version, pairing), d.PairingRef) {
			return out, ErrAuthorization
		}
		seq := high[d.RecipientID]
		if seq == "" {
			seq = "0"
		}
		seq, e = increment(seq)
		if e != nil {
			return out, e
		}
		job := Job{UserOperationID: i.UserOperationID, IntentDigest: Digest(i), RecipientID: d.RecipientID, PairingRef: d.PairingRef, SourceRevision: protocol.Text(i.CandidateHead, "index"), Sequence: seq, BundleRef: b.Ref, PayloadDigest: protocol.Text(b.Descriptor, "bundleDigest")}
		batch.Jobs = append(batch.Jobs, job)
		high[d.RecipientID] = seq
	}
	if len(high) > 100 {
		return out, errors.New("sequence registry capacity gate")
	}
	cursors.Entries = []Sequence{}
	for recipient, value := range high {
		cursors.Entries = append(cursors.Entries, Sequence{RecipientID: recipient, Value: value})
	}
	sort.Slice(cursors.Entries, func(i, j int) bool { return cursors.Entries[i].RecipientID < cursors.Entries[j].RecipientID })
	writes = append(writes, consensus.Write{Key: "core/sequences", Bytes: consensus.JSON(cursors)}, consensus.Write{Key: jobKey, Bytes: consensus.JSON(batch)})
	e = c.finish(ctx, cmd, v, writes, "COMMITTED", out)
	return out, e
}
func toAny(xs []string) []any {
	a := make([]any, len(xs))
	for i, s := range xs {
		a[i] = s
	}
	return a
}
