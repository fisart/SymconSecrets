package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/consensus"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
)

// Abort is restricted to the currently registered coordinator. It may close an
// abandoned old-coordinator candidate, but cannot adopt its approval to commit.
// This internal maintenance authority must never be exposed as a browser claim.
func (c *Controller) Abort(ctx context.Context, commandID, id string, ref, actor protocol.Object, reason string) (UserOutcome, error) {
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
	if e := c.profile.Validate(reason, "AbortReason", ""); e != nil {
		return out, e
	}
	cmd := attempt(commandID, "abort", map[string]any{"reservationId": id, "reservation": ref, "actor": actor, "reason": reason})
	if e := c.history(ctx, cmd); e != nil {
		return out, e
	}
	r, e := c.readReservation(ctx, id, ref)
	if e != nil {
		return out, e
	}
	i := r.Approved.Intent
	v, e := c.abortContext(ctx, actor, protocol.Text(i.Scope, "scopeId"), reservationKey(id), originalKey(i.UserOperationID), outcomeKey(i.UserOperationID), pendingKey(), auditKey(id))
	if e != nil {
		return out, e
	}
	if e = checkOriginal(v, i); e != nil {
		return out, e
	}
	if len(v.Values[originalKey(i.UserOperationID)].Bytes) == 0 {
		return out, ErrAuthorization
	}
	var current Reservation
	var head, pending protocol.Object
	for _, x := range []struct {
		k      string
		target any
	}{{reservationKey(id), &current}, {"head", &head}, {pendingKey(), &pending}} {
		if e = load(v, x.k, x.target); e != nil {
			return out, e
		}
	}
	if !protocol.Equal(ReservationRef(current), ref) || pending["id"] != id {
		return out, consensus.ErrConflict
	}
	if !has([]string{"PREPARING", "READY"}, protocol.Text(current.Record, "state")) || len(v.Values[outcomeKey(i.UserOperationID)].Bytes) > 0 {
		return out, ErrTerminal
	}
	if head["commitId"] == i.CandidateHead["commitId"] || len(v.Values[auditKey(id)].Bytes) > 0 {
		return out, errors.New("published/terminal candidate cannot be aborted")
	}
	version, e := increment(protocol.Text(current.Record, "version"))
	if e != nil {
		return out, e
	}
	current.Record["state"] = "ABORTED"
	current.Record["version"] = version
	out = UserOutcome{Version: "1", UserOperationID: i.UserOperationID, IntentDigest: Digest(i), Result: "ABORTED", Head: nil, Reason: reason}
	audit := map[string]any{"original": object(out), "coordinator": actor, "reviewRef": r.Record["auditRef"]}
	writes := []consensus.Write{{Key: reservationKey(id), Bytes: consensus.JSON(current)}, {Key: outcomeKey(i.UserOperationID), Bytes: consensus.JSON(out)}, {Key: pendingKey(), Delete: true}, {Key: auditKey(id), Bytes: consensus.JSON(audit)}}
	e = c.finish(ctx, cmd, v, writes, "ABORTED", out)
	return out, e
}

// CancelUnknown writes a terminal tombstone when no reservation exists. UNKNOWN
// alone did not prevent a delayed Reserve; this transaction does. It never clears
// another pending operation or grants the requested change.
func (c *Controller) CancelUnknown(ctx context.Context, commandID string, a ApprovedIntent, actor protocol.Object) (UserOutcome, error) {
	var inputErr error
	a, inputErr = ownApproved(a)
	if inputErr != nil {
		return UserOutcome{}, inputErr
	}
	actor, inputErr = ownObject(actor, "NodeBinding")
	if inputErr != nil {
		return UserOutcome{}, inputErr
	}

	var out UserOutcome
	cmd := attempt(commandID, "cancel-unknown", map[string]any{"approved": object(a), "actor": actor})
	if e := c.history(ctx, cmd); e != nil {
		return out, e
	}
	i := a.Intent
	id := protocol.Text(i.CandidateHead, "commitId")
	v, _, _, e := c.base(ctx, a, actor, reservationKey(id), originalKey(i.UserOperationID), outcomeKey(i.UserOperationID), auditKey(i.UserOperationID))
	if e != nil {
		return out, e
	}
	if e = checkOriginal(v, i); e != nil {
		return out, e
	}
	if len(v.Values[originalKey(i.UserOperationID)].Bytes) > 0 {
		return out, ErrTerminal
	}
	if len(v.Values[outcomeKey(i.UserOperationID)].Bytes) > 0 {
		return out, ErrTerminal
	}
	if len(v.Values[reservationKey(id)].Bytes) > 0 || len(v.Values[auditKey(i.UserOperationID)].Bytes) > 0 {
		return out, consensus.ErrConflict
	}
	out = UserOutcome{Version: "1", UserOperationID: i.UserOperationID, IntentDigest: Digest(i), Result: "ABORTED", Head: nil, Reason: "USER_CANCEL"}
	e = c.finish(ctx, cmd, v, []consensus.Write{{Key: originalKey(i.UserOperationID), Bytes: consensus.JSON(original(i))}, {Key: outcomeKey(i.UserOperationID), Bytes: consensus.JSON(out)}, {Key: auditKey(i.UserOperationID), Bytes: consensus.JSON(map[string]any{"original": object(out), "coordinator": actor})}}, "ABORTED", out)
	return out, e
}
func (c *Controller) abortContext(ctx context.Context, actor protocol.Object, scope string, extra ...string) (consensus.Snapshot, error) {
	if e := c.profile.Validate(actor, "NodeBinding", ""); e != nil {
		return consensus.Snapshot{}, e
	}
	keys := []string{"head", "policy", "membership", "coordinator", coordinatorKey(actor)}
	keys = addKeys(keys, extra...)
	v, e := c.Store.Read(ctx, keys...)
	if e != nil {
		return v, e
	}
	var m Membership
	var n Node
	var coordinator protocol.Object
	if e = load(v, "membership", &m); e != nil {
		return v, e
	}
	if e = load(v, coordinatorKey(actor), &n); e != nil {
		return v, e
	}
	if e = load(v, "coordinator", &coordinator); e != nil {
		return v, e
	}
	if !has(m.Nodes, protocol.Text(actor, "nodeId")) || !n.Active || !has(n.Scopes, scope) || !protocol.Equal(n.Binding, actor) || v.Values["coordinator"].Lease == 0 || coordinator["leaseId"] != fmt.Sprintf("%016x", uint64(v.Values["coordinator"].Lease)) {
		return v, ErrAuthorization
	}
	for _, k := range []string{"nodeId", "bootId", "nodeFence"} {
		if coordinator[k] != actor[k] {
			return v, ErrAuthorization
		}
	}
	return v, nil
}
