package protocol

import (
	"errors"
	"strconv"
)

func headDigest(h any) any {
	if h == nil {
		return nil
	}
	return MustDigest(h)
}
func counterCompare(a, b string) int {
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
func nextCounter(s string) (string, error) {
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || n == 9223372036854775807 {
		return "", errors.New("counter exhausted")
	}
	return strconv.FormatInt(n+1, 10), nil
}
func (p *Profile) decisionBinding(d, request Object) error {
	action := Obj(request, "action")
	op := Text(action, "operation")
	ad, e := p.ActionDigest(request)
	if e != nil {
		return e
	}
	if d["operationId"] != action["operationId"] || d["operation"] != op || d["actionDigest"] != ad || d["incarnation"] != request["incarnation"] || d["actorDigest"] != MustDigest(request["actor"]) || !Equal(d["expectedHeadDigest"], headDigest(action["expectedHead"])) {
		return errors.New("decision predecessor/action binding")
	}
	coordinator := Obj(action, "requiredCoordinator")
	var epoch any
	if coordinator != nil {
		epoch = coordinator["epoch"]
	}
	if !Equal(d["coordinatorEpoch"], epoch) {
		return errors.New("decision coordinator binding")
	}
	return p.decisionSemantics(d, request)
}

// Apply the same operation lifecycle to immediate, historical and nested
// decisions. No generic enum value is authority to reinterpret an operation as
// a different user lifecycle. Any future original-user operation needs an
// explicit reviewed contract, not a blanket COMMITTED/ABORTED exception.
func (p *Profile) decisionSemantics(d, request Object) error {
	action := Obj(request, "action")
	op := Text(action, "operation")
	if d["result"] == "REJECTED" {
		if d["reason"] == "NONE" || d["resultHeadDigest"] != nil {
			return errors.New("rejection decision semantics")
		}
		return nil
	}
	if !contains(p.ResponseDecisionContract.SuccessResults[op], Text(d, "result")) || d["reason"] != "NONE" {
		return errors.New("operation decision outcome/reason")
	}
	head := d["resultHeadDigest"]
	if op == "commitCandidate" {
		if head == nil || Equal(head, headDigest(action["expectedHead"])) {
			return errors.New("committed decision requires a new head")
		}
	} else if op == "abortCandidate" {
		if head != nil {
			return errors.New("aborted decision cannot publish a head")
		}
	} else if head != nil && !Equal(head, headDigest(action["expectedHead"])) {
		return errors.New("non-commit decision result head")
	}
	return nil
}
func (p *Profile) requestRole(request Object) error {
	a := Obj(request, "action")
	op := p.Operations[Text(a, "operation")]
	c := Obj(a, "requiredCoordinator")
	actor := Obj(request, "actor")
	kind := Text(actor, "kind")
	if !contains(op.AllowedActors, kind) {
		return errors.New("operation actor role binding")
	}
	require := op.Coordinator == "EXACT_OWNED_CURRENT" || (Text(a, "operation") == "abortCandidate" && kind == "NODE") || (Text(a, "operation") == "replacementStep" && kind == "NODE")
	forbid := op.Coordinator == "MUST_BE_NULL" || kind == "ARCHIVE" || (kind == "GATEWAY" && (Text(a, "operation") == "abortCandidate" || Text(a, "operation") == "replacementStep"))
	if require && c == nil || forbid && c != nil {
		return errors.New("request coordinator role/null binding")
	}
	if c != nil {
		if kind != "NODE" {
			return errors.New("coordinator requires node actor")
		}
		node := Obj(actor, "binding")
		for _, k := range []string{"nodeId", "bootId", "nodeFence"} {
			if node[k] != c[k] {
				return errors.New("coordinator actor binding")
			}
		}
	}
	if op.ExpectedHead == "EXACT_CURRENT" || op.ExpectedHead == "EXACT_RESERVED" {
		if a["expectedHead"] == nil {
			return errors.New("required predecessor missing")
		}
	}
	return nil
}
func headAtLeast(current, earlier Object) error {
	for _, k := range []string{"clusterId", "realmId", "incarnation"} {
		if current[k] != earlier[k] {
			return errors.New("head lineage binding")
		}
	}
	cmp := counterCompare(Text(current, "index"), Text(earlier, "index"))
	if cmp < 0 || cmp == 0 && !Equal(current, earlier) {
		return errors.New("head precedes/contradicts accepted predecessor")
	}
	return nil
}
func coordinatorAtLeast(current, earlier Object) error {
	if current == nil || earlier == nil {
		return nil
	}
	cmp := counterCompare(Text(current, "epoch"), Text(earlier, "epoch"))
	if cmp < 0 || cmp == 0 && !Equal(current, earlier) {
		return errors.New("coordinator precedes/contradicts request")
	}
	return nil
}
func refSuccessor(result, prior Object) error {
	if result == nil || prior == nil || result["id"] != prior["id"] {
		return errors.New("result reference identity")
	}
	cmp := counterCompare(Text(result, "version"), Text(prior, "version"))
	if cmp < 0 || cmp == 0 && !Equal(result, prior) {
		return errors.New("result reference version")
	}
	return nil
}
func sameFields(result, prior Object, fields ...string) error {
	for _, k := range fields {
		if !Equal(result[k], prior[k]) {
			return errors.New("result field binding: " + k)
		}
	}
	return nil
}

// These comparisons use only information actually retained in the request. A
// digest is not permission to reconstruct an unknown historical request context.
func (p *Profile) resultBinding(r, request Object, originals []Object) error {
	a := Obj(request, "action")
	body := Obj(a, "body")
	result := Obj(r, "result")
	op := Text(a, "operation")
	d := Obj(r, "decision")
	expected := Obj(a, "expectedHead")
	switch op {
	case "readHead":
		if !Equal(r["currentHead"], result["head"]) {
			return errors.New("read result head binding")
		}
	case "registerBoot":
		node := Obj(result, "node")
		admission := Obj(body, "admission")
		actor := Obj(request, "actor")
		next, e := nextCounter(Text(body, "previousNodeFence"))
		if e != nil {
			return e
		}
		if node["nodeId"] != actor["nodeId"] || node["bootId"] != actor["candidateBootId"] || node["bootId"] != admission["bootId"] || node["nodeFence"] != next {
			return errors.New("registered node binding")
		}
		return refSuccessor(Obj(result, "nodeRecord"), Obj(body, "expectedNodeRecord"))
	case "acquireCoordinator":
		c := Obj(result, "coordinator")
		next, e := nextCounter(Text(body, "expectedEpoch"))
		if e != nil {
			return e
		}
		if c["epoch"] != next || c["leaseId"] != body["leaseId"] {
			return errors.New("election result binding")
		}
		if e = sameFields(c, Obj(Obj(request, "actor"), "binding"), "nodeId", "bootId", "nodeFence"); e != nil {
			return e
		}
		return coordinatorAtLeast(Obj(r, "currentCoordinator"), c)
	case "uploadBundle":
		receipt := Obj(result, "receipt")
		if receipt["reservationId"] != Obj(body, "reservationRef")["id"] {
			return errors.New("receipt reservation binding")
		}
		return sameFields(receipt, body, "bundleDigest", "bundleLength")
	case "registerReceipt", "markReady", "commitCandidate", "abortCandidate":
		if e := refSuccessor(Obj(result, "reservationRef"), Obj(body, "reservationRef")); e != nil {
			return e
		}
		if op == "registerReceipt" && Obj(result, "receiptRef")["digest"] != MustDigest(body["receipt"]) {
			return errors.New("receipt reference digest")
		}
		if op == "commitCandidate" || op == "abortCandidate" {
			user := Obj(result, "userDecision")
			if user["operationId"] != body["userOperationId"] || len(originals) != 1 {
				return errors.New("original user context required")
			}
			if e := p.validateOriginal(user, originals[0], request); e != nil {
				return e
			}
			if !Equal(user["expectedHeadDigest"], headDigest(a["expectedHead"])) {
				return errors.New("original user predecessor")
			}
			if op == "abortCandidate" {
				if user["result"] != "ABORTED" || user["actionDigest"] != body["originalActionDigest"] || user["resultHeadDigest"] != nil {
					return errors.New("abort original outcome")
				}
			} else {
				head := Obj(result, "head")
				next, e := nextCounter(Text(expected, "index"))
				if e != nil {
					return e
				}
				if head["index"] != next || d["resultHeadDigest"] != MustDigest(head) || user["result"] != "COMMITTED" || user["resultHeadDigest"] != MustDigest(head) {
					return errors.New("commit result head")
				}
				if e = headAtLeast(Obj(r, "currentHead"), head); e != nil {
					return e
				}
			}
		}
	case "status":
		target := Obj(result, "targetDecision")
		if target != nil {
			if len(originals) != 1 {
				return errors.New("historical original request context required")
			}
			if e := p.validateOriginal(target, originals[0], request); e != nil {
				return e
			}
			if target["result"] != "REJECTED" {
				expected := Obj(Obj(originals[0], "action"), "expectedHead")
				current := Obj(r, "currentHead")
				if expected != nil {
					if e := headAtLeast(current, expected); e != nil {
						return e
					}
				}
				if target["result"] == "COMMITTED" {
					next, e := nextCounter(Text(expected, "index"))
					if e != nil {
						return e
					}
					cmp := counterCompare(Text(current, "index"), next)
					if cmp < 0 || (cmp == 0 && target["resultHeadDigest"] != MustDigest(current)) {
						return errors.New("historical committed head contradicts current head")
					}
				}
			}
		}
	case "pinBundleBegin":
		return sameFields(Obj(result, "pin"), body, "purpose", "ownerRef", "bundle", "leaseId")
	case "pinBundleRelease":
		if Obj(result, "pin")["id"] != Obj(body, "pinRef")["id"] || Obj(result, "pin")["state"] != "RELEASED" {
			return errors.New("pin release binding")
		}
	case "repairOpen":
		ticket := Obj(result, "repairTicket")
		if e := sameFields(ticket, body, "bundleRef", "source", "target"); e != nil {
			return e
		}
		if !Equal(ticket["requiredHead"], a["expectedHead"]) {
			return errors.New("repair head binding")
		}
	case "repairRegister":
		if Obj(result, "repairTicket")["id"] != Obj(body, "repairTicketRef")["id"] || !Equal(Obj(result, "repairTicket")["target"], Obj(body, "receipt")["archive"]) {
			return errors.New("repair result binding")
		}
	case "deletePermit":
		return sameFields(Obj(result, "permit"), body, "bundleRef", "reservationId", "archive", "referenceIndexRef")
	case "archiveBoot":
		archive := Obj(result, "archive")
		old := Obj(Obj(request, "actor"), "archive")
		ad := Obj(body, "admission")
		version, e := nextCounter(Text(old, "registrationVersion"))
		if e != nil {
			return e
		}
		if archive["storageGeneration"] != body["newStorageGeneration"] || archive["bootId"] != ad["bootId"] || archive["archiveId"] != old["archiveId"] || archive["failureDomainId"] != old["failureDomainId"] || archive["registrationVersion"] != version {
			return errors.New("archive boot result binding")
		}
	case "replacementBegin":
		return sameFields(Obj(result, "plan"), Obj(body, "plan"), "id", "kind", "oldIdentityDigest", "newIdentityDigest", "routingDigest", "scopeSetDigest", "approvalRef", "expectedHead")
	case "replacementStep":
		if Obj(result, "plan")["id"] != Obj(body, "planRef")["id"] {
			return errors.New("replacement result identity")
		}
	case "reattestCommitted":
		if Obj(result, "receiptRef")["id"] != a["operationId"] || Obj(result, "receiptRef")["digest"] != MustDigest(body["receipt"]) {
			return errors.New("reattestation result reference")
		}
	case "activateArchive":
		if !Equal(result["archive"], Obj(request, "actor")["archive"]) || result["state"] != "ACTIVE" {
			return errors.New("activation result runtime binding")
		}
	}
	return nil
}
func (p *Profile) validateOriginal(d, original, query Object) error {
	if e := p.Validate(original, "Request", Text(Obj(original, "action"), "operation")); e != nil {
		return e
	}
	if d["result"] != "REJECTED" {
		if e := p.requestRole(original); e != nil {
			return e
		}
	}
	for _, k := range []string{"clusterId", "realmId", "incarnation"} {
		if original[k] != query[k] {
			return errors.New("historical request lineage")
		}
	}
	return p.decisionBinding(d, original)
}
