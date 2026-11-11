// Package core implements the internal, human secret-change state machine.
// It has no listener, enrollment, WebAuthn verifier or generic write endpoint.
package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/archive"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/consensus"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
)

const IntentDomain = "SymconSecrets/DC01/CoreUserIntent/v1\x00"
const IntentSignatureDomain = "SymconSecrets/DC01/CoreUserSignature/v1\x00"

// Intent is separate from a wire Request or Decision. Only these two human
// change classes are implemented. SECURITY/machine/counter operations fail closed.
// Authorization facts bind Digest(Intent); the owner signs the complete ApprovedIntent.
type Intent struct {
	NewScopeDigest      string          `json:"newScopeDigest"`
	Version             string          `json:"version"`
	UserOperationID     string          `json:"userOperationId"`
	ExpectedHead        protocol.Object `json:"expectedHead"`
	Owner               protocol.Object `json:"owner"`
	PolicyRef           protocol.Object `json:"policyRef"`
	MembershipRef       protocol.Object `json:"membershipRef"`
	PermissionRef       protocol.Object `json:"permissionRef"`
	SessionRef          protocol.Object `json:"sessionRef"`
	CredentialRef       protocol.Object `json:"credentialRef"`
	Scope               protocol.Object `json:"scope"`
	NewRevision         string          `json:"newRevision"`
	ChangeClass         string          `json:"changeClass"`
	PermittedDiffDigest string          `json:"permittedDiffDigest"`
	CandidateHead       protocol.Object `json:"candidateHead"`
	Bundle              archive.Bundle  `json:"bundle"`
	Outbox              []Delivery      `json:"outbox"`
}
type Delivery struct {
	RecipientID string          `json:"recipientId"`
	PairingRef  protocol.Object `json:"pairingRef"`
}
type ApprovedIntent struct {
	Intent      Intent          `json:"intent"`
	ApprovalRef protocol.Object `json:"approvalRef"`
	KeyID       string          `json:"keyId"`
	Signature   string          `json:"signature"`
}

// These records are produced only by independently authorized provisioning and
// the future V2 authorization service. Core cannot issue or weaken any of them.
type Policy struct {
	ID              string   `json:"id"`
	Version         string   `json:"version"`
	HardwareClasses []string `json:"hardwareClasses"`
}
type Membership struct {
	ID       string   `json:"id"`
	Version  string   `json:"version"`
	Nodes    []string `json:"nodes"`
	Archives []string `json:"archives"`
}
type Node struct {
	Binding   protocol.Object `json:"binding"`
	KeyID     string          `json:"keyId"`
	PublicKey string          `json:"publicKey"`
	Active    bool            `json:"active"`
	Scopes    []string        `json:"scopes"`
}
type Permission struct {
	ID              string   `json:"id"`
	Version         string   `json:"version"`
	AdministratorID string   `json:"administratorId"`
	Active          bool     `json:"active"`
	Classes         []string `json:"classes"`
	Scopes          []string `json:"scopes"`
}
type Session struct {
	ID              string `json:"id"`
	Version         string `json:"version"`
	AdministratorID string `json:"administratorId"`
	Active          bool   `json:"active"`
}
type Credential struct {
	ID               string `json:"id"`
	Version          string `json:"version"`
	AdministratorID  string `json:"administratorId"`
	Active           bool   `json:"active"`
	HardwareVerified bool   `json:"hardwareVerified"`
}
type Approval struct {
	ID               string          `json:"id"`
	Version          string          `json:"version"`
	IntentDigest     string          `json:"intentDigest"`
	PermissionRef    protocol.Object `json:"permissionRef"`
	SessionRef       protocol.Object `json:"sessionRef"`
	CredentialRef    protocol.Object `json:"credentialRef"`
	UserPresence     bool            `json:"userPresence"`
	UserVerification bool            `json:"userVerification"`
	// The authorizer must verify the exact permitted encrypted-object diff and
	// assertion/hardware policy, not copy these booleans from a browser request.
	DiffVerified bool `json:"diffVerified"`
}
type Pairing struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	RecipientID string `json:"recipientId"`
	Active      bool   `json:"active"`
}
type Reservation struct {
	Record   protocol.Object `json:"record"`
	Approved ApprovedIntent  `json:"approved"`
	Bundle   archive.Bundle  `json:"bundle"`
}
type Original struct {
	UserOperationID string `json:"userOperationId"`
	IntentDigest    string `json:"intentDigest"`
	ReservationID   string `json:"reservationId"`
}

type UserOutcome struct {
	Version         string          `json:"version"`
	UserOperationID string          `json:"userOperationId"`
	IntentDigest    string          `json:"intentDigest"`
	Result          string          `json:"result"`
	Head            protocol.Object `json:"head"`
	Reason          string          `json:"reason"`
}
type Sequence struct {
	RecipientID string `json:"recipientId"`
	Value       string `json:"value"`
}
type SequenceState struct {
	Entries []Sequence `json:"entries"`
}
type JobBatch struct {
	Jobs []Job `json:"jobs"`
}

type Job struct {
	UserOperationID string          `json:"userOperationId"`
	IntentDigest    string          `json:"intentDigest"`
	RecipientID     string          `json:"recipientId"`
	PairingRef      protocol.Object `json:"pairingRef"`
	SourceRevision  string          `json:"sourceRevision"`
	Sequence        string          `json:"sequence"`
	BundleRef       protocol.Object `json:"bundleRef"`
	PayloadDigest   string          `json:"payloadDigest"`
}

func object(v any) protocol.Object {
	b := consensus.JSON(v)
	var o protocol.Object
	if e := json.Unmarshal(b, &o); e != nil {
		panic(e)
	}
	return o
}
func hash(v any) string { return protocol.MustDigest(object(v)) }
func Digest(i Intent) string {
	b, e := protocol.Canonical(object(i))
	if e != nil {
		return ""
	}
	s := sha256.Sum256(append([]byte(IntentDomain), b...))
	return hex.EncodeToString(s[:])
}
func Ref(id, version string, record any) protocol.Object {
	return protocol.Object{"id": id, "version": version, "digest": hash(record)}
}
func ReservationRef(r Reservation) protocol.Object {
	return Ref(protocol.Text(r.Record, "id"), protocol.Text(r.Record, "version"), r)
}
func Signed(a ApprovedIntent, key ed25519.PrivateKey) (ApprovedIntent, error) {
	a.Signature = ""
	b, e := protocol.Canonical(object(a))
	if e != nil {
		return a, e
	}
	if len(key) != ed25519.PrivateKeySize {
		return a, errors.New("owner signing key")
	}
	a.Signature = protocol.Base(ed25519.Sign(key, append([]byte(IntentSignatureDomain), b...)))
	return a, nil
}
func verify(a ApprovedIntent, key string) error {
	sig, e := protocol.Unbase(a.Signature, 64)
	if e != nil {
		return e
	}
	pub, e := protocol.Unbase(key, 32)
	if e != nil {
		return e
	}
	a.Signature = ""
	b, e := protocol.Canonical(object(a))
	if e != nil {
		return e
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), append([]byte(IntentSignatureDomain), b...), sig) {
		return errors.New("original owner signature")
	}
	return nil
}
func decode(b []byte, v any) error {
	if _, e := protocol.Decode(b); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
func load(v consensus.Snapshot, key string, target any) error {
	return decode(v.Values[key].Bytes, target)
}
func has(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}
func increment(s string) (string, error) {
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || n < 0 || n == 9223372036854775807 {
		return "", errors.New("counter exhausted")
	}
	return strconv.FormatInt(n+1, 10), nil
}
func validateIntent(a ApprovedIntent) error {
	p, _ := protocol.Load()
	i := a.Intent
	if i.Version != "1" || !has([]string{"GLOBAL_EDIT", "LOCAL_EDIT"}, i.ChangeClass) || i.Outbox == nil || len(i.Outbox) > 4 || i.Bundle.ReservationID != "" {
		return errors.New("unsupported core user contract")
	}
	for _, x := range []struct {
		v any
		t string
	}{{i.UserOperationID, "UUID"}, {i.ExpectedHead, "Head"}, {i.Owner, "NodeBinding"}, {i.Scope, "ScopeBinding"}, {i.NewRevision, "Q_POS"}, {i.PermittedDiffDigest, "DIGEST"}, {i.NewScopeDigest, "DIGEST"}, {i.CandidateHead, "Head"}, {i.Bundle.Ref, "RecordRef"}, {i.Bundle.Descriptor, "BundleDescriptor"}, {i.Bundle.IndexDigest, "DIGEST"}, {a.KeyID, "B64_32"}, {a.ApprovalRef, "RecordRef"}} {
		if e := p.Validate(x.v, x.t, ""); e != nil {
			return e
		}
	}
	for _, r := range []protocol.Object{i.PolicyRef, i.MembershipRef, i.PermissionRef, i.SessionRef, i.CredentialRef} {
		if e := p.Validate(r, "RecordRef", ""); e != nil {
			return e
		}
	}
	next, e := increment(protocol.Text(i.ExpectedHead, "index"))
	if e != nil {
		return e
	}
	rev, e := increment(protocol.Text(i.Scope, "revision"))
	if e != nil {
		return e
	}
	for _, k := range []string{"clusterId", "realmId", "incarnation", "keyEpoch"} {
		if i.CandidateHead[k] != i.ExpectedHead[k] {
			return errors.New("candidate lineage/key change forbidden")
		}
	}
	if i.NewRevision != rev || i.CandidateHead["index"] != next || i.CandidateHead["commitId"] == i.ExpectedHead["commitId"] || i.Bundle.Ref["id"] != i.CandidateHead["commitId"] || i.Bundle.Ref["version"] != "1" || i.Bundle.Ref["digest"] != hash(i.Bundle.Descriptor) || i.Bundle.Descriptor["commitId"] != i.CandidateHead["commitId"] || i.Bundle.Descriptor["manifestDigest"] != i.CandidateHead["manifestDigest"] || i.Bundle.Protected {
		return errors.New("candidate descriptor/revision")
	}
	if i.ChangeClass == "LOCAL_EDIT" {
		if i.Scope["kind"] != "LOCAL" || i.Scope["ownerNodeId"] != i.Owner["nodeId"] {
			return errors.New("local owner scope")
		}
	} else if i.Scope["kind"] != "GLOBAL" || i.Scope["ownerNodeId"] != nil {
		return errors.New("global scope")
	}
	seen := map[string]bool{}
	for _, d := range i.Outbox {
		if e = p.Validate(d.RecipientID, "UUID", ""); e != nil {
			return e
		}
		if e = p.Validate(d.PairingRef, "RecordRef", ""); e != nil {
			return e
		}
		if seen[d.RecipientID] {
			return errors.New("duplicate recipient")
		}
		seen[d.RecipientID] = true
	}
	// Closed canonical round trip enforces size, depth, ASCII and duplicate rules.
	var copy ApprovedIntent
	return decode(consensus.JSON(a), &copy)
}

func ownApproved(a ApprovedIntent) (ApprovedIntent, error) {
	var copy ApprovedIntent
	if e := decode(consensus.JSON(a), &copy); e != nil {
		return copy, e
	}
	return copy, validateIntent(copy)
}
func ownObject(o protocol.Object, typ string) (protocol.Object, error) {
	copy, e := protocol.Decode(consensus.JSON(o))
	if e != nil {
		return nil, e
	}
	p, _ := protocol.Load()
	if e = p.Validate(copy, typ, ""); e != nil {
		return nil, e
	}
	return copy, nil
}
