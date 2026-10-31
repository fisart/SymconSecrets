package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/archive"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/consensus"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
)

var ErrTerminal = errors.New("original user operation is terminal; query its exact outcome")
var ErrAuthorization = errors.New("current core authorization does not match the approved change")

type Controller struct {
	Store   *consensus.Store
	profile *protocol.Profile
	Fault   func(string) error
}

func New(s *consensus.Store) (*Controller, error) {
	if s == nil {
		return nil, errors.New("authority required")
	}
	p, e := protocol.Load()
	if e != nil {
		return nil, e
	}
	return &Controller{Store: s, profile: p}, nil
}
func (c *Controller) trip(point string) error {
	if c.Fault != nil {
		return c.Fault(point)
	}
	return nil
}
func reservationKey(id string) string { return "core/reservations/" + id }
func originalKey(id string) string    { return "core/originals/" + id }
func original(i Intent) Original {
	return Original{UserOperationID: i.UserOperationID, IntentDigest: Digest(i), ReservationID: protocol.Text(i.CandidateHead, "commitId")}
}
func checkOriginal(v consensus.Snapshot, i Intent) error {
	key := originalKey(i.UserOperationID)
	if len(v.Values[key].Bytes) == 0 {
		return nil
	}
	var old Original
	if e := load(v, key, &old); e != nil {
		return e
	}
	if !protocol.Equal(object(old), object(original(i))) {
		return consensus.ErrIDReuse
	}
	return nil
}

func outcomeKey(id string) string                     { return "core/outcomes/" + id }
func candidateReceiptKey(id, archiveID string) string { return "core/receipts/" + id + "/" + archiveID }
func pendingKey() string                              { return "core/pending" }
func scopeKey(i Intent) string                        { return "core/scopes/" + protocol.Text(i.Scope, "scopeId") }
func approvalKey(a ApprovedIntent) string {
	return "core/approvals/" + protocol.Text(a.ApprovalRef, "id")
}
func consumedKey(a ApprovedIntent) string {
	return "core/consumed-approvals/" + protocol.Text(a.ApprovalRef, "id")
}
func auditKey(id string) string { return "core/audit/" + id }
func attempt(id, op string, body any) consensus.Attempt {
	return consensus.Attempt{ID: id, Digest: hash(map[string]any{"domain": "SymconSecrets/CoreCommand/v1", "operation": op, "body": body})}
}
func (c *Controller) history(ctx context.Context, a consensus.Attempt) error {
	out, e := c.Store.Resolve(ctx, a)
	if e != nil {
		return e
	}
	if out != nil {
		return &consensus.AlreadyDecided{Outcome: *out}
	}
	return nil
}
func (c *Controller) ResolveUser(ctx context.Context, id, digest string) (*UserOutcome, error) {
	if e := c.profile.Validate(id, "UUID", ""); e != nil {
		return nil, e
	}
	if e := c.profile.Validate(digest, "DIGEST", ""); e != nil {
		return nil, e
	}
	v, e := c.Store.Read(ctx, outcomeKey(id))
	if e != nil {
		return nil, e
	}
	if len(v.Values[outcomeKey(id)].Bytes) == 0 {
		return nil, nil
	}
	var o UserOutcome
	if e = load(v, outcomeKey(id), &o); e != nil {
		return nil, e
	}
	if o.UserOperationID != id || o.IntentDigest != digest {
		return nil, consensus.ErrIDReuse
	}
	return &o, nil
}
func addKeys(xs []string, keys ...string) []string {
	for _, k := range keys {
		if !has(xs, k) {
			xs = append(xs, k)
		}
	}
	return xs
}
func merge(a, b consensus.Snapshot) (consensus.Snapshot, error) {
	for k, v := range b.Values {
		if old, ok := a.Values[k]; ok && (old.Revision != v.Revision || old.Lease != v.Lease || string(old.Bytes) != string(v.Bytes)) {
			return a, consensus.ErrConflict
		}
		a.Values[k] = v
	}
	return a, nil
}
func coordinatorKey(actor protocol.Object) string { return "nodes/" + protocol.Text(actor, "nodeId") }
func (c *Controller) base(ctx context.Context, a ApprovedIntent, actor protocol.Object, extra ...string) (consensus.Snapshot, Membership, protocol.Object, error) {
	i := a.Intent
	empty := consensus.Snapshot{}
	var m Membership
	var coordinator protocol.Object
	if e := validateIntent(a); e != nil {
		return empty, m, nil, e
	}
	if e := c.profile.Validate(actor, "NodeBinding", ""); e != nil {
		return empty, m, nil, e
	}
	keys := []string{"head", "policy", "membership", "coordinator", coordinatorKey(actor), coordinatorKey(i.Owner)}
	keys = addKeys(keys, extra...)
	v, e := c.Store.Read(ctx, keys...)
	if e != nil {
		return v, m, nil, e
	}
	var currentHead protocol.Object
	if e = load(v, "head", &currentHead); e != nil {
		return v, m, nil, e
	}
	for _, k := range []string{"clusterId", "realmId", "incarnation"} {
		if currentHead[k] != i.ExpectedHead[k] {
			return v, m, nil, consensus.ErrLineage
		}
	}
	var owner, node Node
	if e = load(v, "membership", &m); e != nil {
		return v, m, nil, e
	}
	if len(m.Archives) != 3 {
		return v, m, nil, ErrAuthorization
	}
	seen := map[string]bool{}
	for _, id := range m.Archives {
		if e = c.profile.Validate(id, "UUID", ""); e != nil || seen[id] {
			return v, m, nil, ErrAuthorization
		}
		seen[id] = true
	}
	if !has(m.Nodes, protocol.Text(actor, "nodeId")) || !has(m.Nodes, protocol.Text(i.Owner, "nodeId")) {
		return v, m, nil, ErrAuthorization
	}
	if e = load(v, coordinatorKey(i.Owner), &owner); e != nil {
		return v, m, nil, e
	}
	if e = load(v, coordinatorKey(actor), &node); e != nil {
		return v, m, nil, e
	}
	scopeID := protocol.Text(i.Scope, "scopeId")
	if !owner.Active || !node.Active || !protocol.Equal(owner.Binding, i.Owner) || !protocol.Equal(node.Binding, actor) || !has(owner.Scopes, scopeID) || !has(node.Scopes, scopeID) || owner.KeyID != a.KeyID {
		return v, m, nil, ErrAuthorization
	}
	if e = verify(a, owner.PublicKey); e != nil {
		return v, m, nil, e
	}
	if e = load(v, "coordinator", &coordinator); e != nil {
		return v, m, nil, e
	}
	if e = c.profile.Validate(coordinator, "Coordinator", ""); e != nil {
		return v, m, nil, e
	}
	if v.Values["coordinator"].Lease == 0 || coordinator["leaseId"] != fmt.Sprintf("%016x", uint64(v.Values["coordinator"].Lease)) {
		return v, m, nil, ErrAuthorization
	}
	for _, k := range []string{"nodeId", "bootId", "nodeFence"} {
		if coordinator[k] != actor[k] {
			return v, m, nil, ErrAuthorization
		}
	}
	return v, m, coordinator, nil
}
func (c *Controller) live(ctx context.Context, a ApprovedIntent, actor protocol.Object, extra ...string) (consensus.Snapshot, Membership, protocol.Object, error) {
	i := a.Intent
	keys := []string{scopeKey(i), "core/permissions/" + protocol.Text(i.PermissionRef, "id"), "core/sessions/" + protocol.Text(i.SessionRef, "id"), "core/credentials/" + protocol.Text(i.CredentialRef, "id"), approvalKey(a), consumedKey(a), outcomeKey(i.UserOperationID), pendingKey()}
	keys = addKeys(keys, extra...)
	keys = addKeys(keys, originalKey(i.UserOperationID))
	v, m, coordinator, e := c.base(ctx, a, actor, keys...)
	if e != nil {
		return v, m, nil, e
	}
	if e = checkOriginal(v, i); e != nil {
		return v, m, nil, e
	}
	var policy Policy
	var permission Permission
	var session Session
	var credential Credential
	var approval Approval
	var scope protocol.Object
	for _, x := range []struct {
		k      string
		target any
	}{{"policy", &policy}, {scopeKey(i), &scope}, {keys[1], &permission}, {keys[2], &session}, {keys[3], &credential}, {approvalKey(a), &approval}} {
		if e = load(v, x.k, x.target); e != nil {
			return v, m, nil, e
		}
	}
	if !protocol.Equal(object(scope), i.Scope) || !protocol.Equal(Ref(policy.ID, policy.Version, policy), i.PolicyRef) || !protocol.Equal(Ref(m.ID, m.Version, m), i.MembershipRef) || !protocol.Equal(Ref(permission.ID, permission.Version, permission), i.PermissionRef) || !protocol.Equal(Ref(session.ID, session.Version, session), i.SessionRef) || !protocol.Equal(Ref(credential.ID, credential.Version, credential), i.CredentialRef) || !protocol.Equal(Ref(approval.ID, approval.Version, approval), a.ApprovalRef) {
		return v, m, nil, ErrAuthorization
	}
	if string(v.Values["head"].Bytes) != string(consensus.JSON(i.ExpectedHead)) || !permission.Active || !session.Active || !credential.Active || permission.AdministratorID != session.AdministratorID || permission.AdministratorID != credential.AdministratorID || !has(permission.Classes, i.ChangeClass) || !has(permission.Scopes, protocol.Text(i.Scope, "scopeId")) {
		return v, m, nil, ErrAuthorization
	}
	if v.Values[keys[2]].Lease == 0 || v.Values[approvalKey(a)].Lease == 0 || approval.IntentDigest != Digest(i) || !approval.UserPresence || !approval.UserVerification || !approval.DiffVerified || !protocol.Equal(approval.PermissionRef, i.PermissionRef) || !protocol.Equal(approval.SessionRef, i.SessionRef) || !protocol.Equal(approval.CredentialRef, i.CredentialRef) {
		return v, m, nil, ErrAuthorization
	}
	if has(policy.HardwareClasses, i.ChangeClass) && !credential.HardwareVerified {
		return v, m, nil, ErrAuthorization
	}
	if len(v.Values[outcomeKey(i.UserOperationID)].Bytes) > 0 {
		var out UserOutcome
		if e = load(v, outcomeKey(i.UserOperationID), &out); e != nil {
			return v, m, nil, e
		}
		if out.IntentDigest != Digest(i) {
			return v, m, nil, consensus.ErrIDReuse
		}
		return v, m, nil, ErrTerminal
	}
	return v, m, coordinator, nil
}
func (c *Controller) readReservation(ctx context.Context, id string, expected protocol.Object) (Reservation, error) {
	var r Reservation
	if e := c.profile.Validate(id, "UUID", ""); e != nil {
		return r, e
	}
	if e := c.profile.Validate(expected, "RecordRef", ""); e != nil {
		return r, e
	}
	v, e := c.Store.Read(ctx, reservationKey(id))
	if e != nil {
		return r, e
	}
	if e = load(v, reservationKey(id), &r); e != nil {
		return r, e
	}
	if !protocol.Equal(expected, ReservationRef(r)) {
		return r, consensus.ErrConflict
	}
	return r, nil
}
func archiveKeys(ids []string) []string {
	keys := []string{}
	for _, id := range ids {
		keys = append(keys, "archives/"+id, "admissions/"+id)
	}
	return keys
}
func currentArchive(v consensus.Snapshot, id string) (archive.Registration, error) {
	var reg archive.Registration
	var admission protocol.Object
	if e := load(v, "archives/"+id, &reg); e != nil {
		return reg, e
	}
	if e := load(v, "admissions/"+id, &admission); e != nil {
		return reg, e
	}
	p, _ := protocol.Load()
	if p.Validate(reg.Binding, "ArchiveBinding", "") != nil || p.Validate(admission, "HostAdmission", "") != nil {
		return reg, ErrAuthorization
	}
	if reg.State != "ACTIVE" || reg.Binding["archiveId"] != id || reg.AdmissionDigest != protocol.MustDigest(admission) || admission["componentKind"] != "ARCHIVE" || admission["componentId"] != id || admission["bootId"] != reg.Binding["bootId"] || admission["storageGeneration"] != reg.Binding["storageGeneration"] {
		return reg, ErrAuthorization
	}
	return reg, nil
}
func (c *Controller) finish(ctx context.Context, a consensus.Attempt, v consensus.Snapshot, writes []consensus.Write, kind string, result any) error {
	if e := c.trip("before-final-cas"); e != nil {
		return e
	}
	if _, e := c.Store.Apply(ctx, a, v, writes, kind, result); e != nil {
		return e
	}
	return c.trip("after-commit-before-ack")
}
