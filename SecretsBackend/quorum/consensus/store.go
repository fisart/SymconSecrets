// Package consensus supplies linearizable, lineage-bound, atomic operations.
// It is internal service infrastructure, not a generic remotely writable API.
package consensus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
	clientv3 "go.etcd.io/etcd/client/v3"
)

var ErrConflict = errors.New("current authority changed")
var ErrLineage = errors.New("native cluster lineage mismatch")
var ErrIDReuse = errors.New("operation identity reused with different digest")

type Store struct {
	client *clientv3.Client
	prefix string
	native uint64
}
type Value struct {
	Bytes    []byte
	Revision int64
	Lease    clientv3.LeaseID
}
type Snapshot struct {
	Values   map[string]Value
	Revision int64
}
type Write struct {
	Key    string
	Bytes  []byte
	Delete bool
	Lease  clientv3.LeaseID
}

// Attempt represents one durable application operation, independent of transport retry.
type Attempt struct {
	ID     string
	Digest string
}
type Outcome struct {
	Digest  string          `json:"digest"`
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}
type AlreadyDecided struct{ Outcome Outcome }

func (e *AlreadyDecided) Error() string {
	return "operation already has a durable outcome; query status"
}

func New(client *clientv3.Client, cluster, realm, native string) (*Store, error) {
	p, e := protocol.Load()
	if e != nil {
		return nil, e
	}
	for _, x := range []string{cluster, realm} {
		if e = p.Validate(x, "UUID", ""); e != nil {
			return nil, e
		}
	}
	if e = p.Validate(native, "NATIVE_ID", ""); e != nil {
		return nil, e
	}
	id, e := strconv.ParseUint(native, 16, 64)
	if e != nil {
		return nil, e
	}
	if client == nil {
		return nil, errors.New("etcd client required")
	}
	return &Store{client: client, prefix: "/symcon-secrets/v2/" + cluster + "/" + realm + "/", native: id}, nil
}
func (s *Store) key(k string) (string, error) {
	if k == "" || strings.HasPrefix(k, "/") || strings.Contains(k, "..") || strings.ContainsRune(k, 0) {
		return "", errors.New("invalid internal key")
	}
	return s.prefix + k, nil
}
func (s *Store) Read(ctx context.Context, keys ...string) (Snapshot, error) {
	if len(keys) == 0 || len(keys) > 100 {
		return Snapshot{}, errors.New("bounded read required")
	}
	ops := make([]clientv3.Op, 0, len(keys))
	for _, k := range keys {
		full, e := s.key(k)
		if e != nil {
			return Snapshot{}, e
		}
		ops = append(ops, clientv3.OpGet(full))
	}
	// A Txn containing only exact reads is linearizable unless explicitly made serializable.
	r, e := s.client.Txn(ctx).Then(ops...).Commit()
	if e != nil {
		return Snapshot{}, e
	}
	if r.Header.ClusterId != s.native {
		return Snapshot{}, ErrLineage
	}
	v := Snapshot{Values: map[string]Value{}, Revision: r.Header.Revision}
	for i, res := range r.Responses {
		kv := res.GetResponseRange().Kvs
		if len(kv) > 0 {
			v.Values[keys[i]] = Value{Bytes: append([]byte(nil), kv[0].Value...), Revision: kv[0].ModRevision, Lease: clientv3.LeaseID(kv[0].Lease)}
		} else {
			v.Values[keys[i]] = Value{}
		}
	}
	return v, nil
}
func (s *Store) Resolve(ctx context.Context, a Attempt) (*Outcome, error) {
	if e := validAttempt(a); e != nil {
		return nil, e
	}
	v, e := s.Read(ctx, "decisions/"+a.ID)
	if e != nil {
		return nil, e
	}
	b := v.Values["decisions/"+a.ID].Bytes
	if len(b) == 0 {
		return nil, nil
	}
	var o Outcome
	if e = json.Unmarshal(b, &o); e != nil {
		return nil, e
	}
	if o.Digest != a.Digest {
		return nil, ErrIDReuse
	}
	return &o, nil
}
func validAttempt(a Attempt) error {
	p, e := protocol.Load()
	if e != nil {
		return e
	}
	if e = p.Validate(a.ID, "UUID", ""); e != nil {
		return e
	}
	return p.Validate(a.Digest, "DIGEST", "")
}

// Apply requires the exact read set used during validation. The original outcome
// CAS competes with every success, rejection and cancellation for that attempt.
// This method is never an HTTP endpoint and does not perform user authorization.
func (s *Store) Apply(ctx context.Context, a Attempt, validated Snapshot, writes []Write, kind string, payload any) (Outcome, error) {
	if e := validAttempt(a); e != nil {
		return Outcome{}, e
	}
	if len(validated.Values) == 0 || len(validated.Values)+len(writes) > 90 {
		return Outcome{}, errors.New("bounded nonempty validation set required")
	}
	o := Outcome{Digest: a.Digest, Kind: kind}
	b, e := json.Marshal(payload)
	if e != nil {
		return o, e
	}
	o.Payload = b
	decision, e := json.Marshal(o)
	if e != nil {
		return o, e
	}
	if len(decision) > 65536 {
		return o, errors.New("decision size limit")
	}
	dk, _ := s.key("decisions/" + a.ID)
	compares := []clientv3.Cmp{clientv3.Compare(clientv3.CreateRevision(dk), "=", 0)}
	ops := []clientv3.Op{}
	seen := map[string]bool{}
	for k, v := range validated.Values {
		full, e := s.key(k)
		if e != nil {
			return o, e
		}
		compares = append(compares, clientv3.Compare(clientv3.ModRevision(full), "=", v.Revision))
		if v.Revision > 0 {
			compares = append(compares, clientv3.Compare(clientv3.Value(full), "=", string(v.Bytes)))
			if v.Lease != 0 {
				compares = append(compares, clientv3.Compare(clientv3.LeaseValue(full), "=", int64(v.Lease)))
			}
		}
	}
	for _, w := range writes {
		if seen[w.Key] || strings.HasPrefix(w.Key, "decisions/") {
			return o, errors.New("duplicate or reserved write")
		}
		seen[w.Key] = true
		if _, ok := validated.Values[w.Key]; !ok {
			return o, errors.New("write lacks predecessor comparison")
		}
		full, e := s.key(w.Key)
		if e != nil {
			return o, e
		}
		if len(w.Bytes) > 65536 {
			return o, errors.New("control record size limit")
		}
		if w.Delete {
			ops = append(ops, clientv3.OpDelete(full))
		} else {
			opts := []clientv3.OpOption{}
			if w.Lease != 0 {
				opts = append(opts, clientv3.WithLease(w.Lease))
			}
			ops = append(ops, clientv3.OpPut(full, string(w.Bytes), opts...))
		}
	}
	ops = append(ops, clientv3.OpPut(dk, string(decision)))
	// Native lineage is verified through a fresh read before invoking a mutation;
	// TLS pins must also prevent endpoint reassignment during this client lifetime.
	lineage, lineageErr := s.Read(ctx, "lineage")
	if lineageErr != nil {
		return o, lineageErr
	}
	lv := lineage.Values["lineage"]
	if lv.Revision > 0 && string(lv.Bytes) != fmt.Sprintf("%016x", s.native) {
		return o, ErrLineage
	}
	if lv.Revision == 0 {
		found := false
		for _, w := range writes {
			if w.Key == "lineage" && !w.Delete && string(w.Bytes) == fmt.Sprintf("%016x", s.native) {
				found = true
			}
		}
		if !found {
			return o, errors.New("explicit initial lineage provisioning required")
		}
	}
	if existing, ok := validated.Values["lineage"]; ok && existing.Revision != lv.Revision {
		return o, ErrConflict
	}
	fullLineage, _ := s.key("lineage")
	compares = append(compares, clientv3.Compare(clientv3.ModRevision(fullLineage), "=", lv.Revision))
	if lv.Revision > 0 {
		compares = append(compares, clientv3.Compare(clientv3.Value(fullLineage), "=", string(lv.Bytes)))
	}
	if len(compares)+len(ops) > 120 {
		return o, errors.New("authority transaction capacity gate")
	}
	r, e := s.client.Txn(ctx).If(compares...).Then(ops...).Commit()
	if e != nil {
		return o, e
	}
	if r.Header.ClusterId != s.native {
		return o, ErrLineage
	}
	if !r.Succeeded {
		old, e := s.Resolve(ctx, a)
		if e != nil {
			return o, e
		}
		if old != nil {
			return o, &AlreadyDecided{Outcome: *old}
		}
		return o, ErrConflict
	}
	return o, nil
}
func JSON(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func (s *Store) Client() *clientv3.Client { return s.client }
func (s *Store) NativeID() string         { return fmt.Sprintf("%016x", s.native) }

// Initialize is an independent provisioning primitive, not a runtime fallback.
// Calling it against existing state cannot erase membership, heads or outcomes.
func (s *Store) Initialize(ctx context.Context, a Attempt, records map[string][]byte) error {
	keys := []string{}
	for k := range records {
		keys = append(keys, k)
	}
	v, e := s.Read(ctx, keys...)
	if e != nil {
		return e
	}
	writes := []Write{}
	for k, b := range records {
		if v.Values[k].Revision != 0 {
			return errors.New("authority already initialized")
		}
		writes = append(writes, Write{Key: k, Bytes: b})
	}
	_, e = s.Apply(ctx, a, v, writes, "APPLIED", map[string]string{"provisioning": "initial-only"})
	return e
}

type Guard struct {
	Head        []byte
	Policy      []byte
	Membership  []byte
	NodeID      string
	Node        []byte
	Coordinator []byte
}

func (g Guard) Keys(extra ...string) []string {
	k := []string{"head", "policy", "membership", "nodes/" + g.NodeID}
	if g.Coordinator != nil {
		k = append(k, "coordinator")
	}
	return append(k, extra...)
}
func (g Guard) Check(v Snapshot) error {
	if g.NodeID == "" || len(g.Head) == 0 || len(g.Policy) == 0 || len(g.Membership) == 0 || len(g.Node) == 0 {
		return errors.New("complete current guard required")
	}
	for k, b := range map[string][]byte{"head": g.Head, "policy": g.Policy, "membership": g.Membership, "nodes/" + g.NodeID: g.Node} {
		if !bytesEqual(v.Values[k].Bytes, b) {
			return ErrConflict
		}
	}
	if g.Coordinator != nil {
		c := v.Values["coordinator"]
		if c.Revision == 0 || c.Lease == 0 || !bytesEqual(c.Bytes, g.Coordinator) {
			return ErrConflict
		}
	}
	return nil
}
func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

// Guarded records a single exact decision only after rechecking all security
// predecessors at the final transaction. afterRead is a fault-test hook; runtime
// construction must leave it nil. It cannot replace the transaction comparisons.
func (s *Store) Guarded(ctx context.Context, a Attempt, g Guard, kind string, result any, afterRead func()) (Outcome, error) {
	v, e := s.Read(ctx, g.Keys()...)
	if e != nil {
		return Outcome{}, e
	}
	if e = g.Check(v); e != nil {
		return Outcome{}, e
	}
	if afterRead != nil {
		afterRead()
	}
	return s.Apply(ctx, a, v, nil, kind, result)
}

// Elect keeps epoch outside the expiring coordinator key. Losing an ACK never
// permits a new attempt to masquerade as the original successful election.
func (s *Store) Elect(ctx context.Context, a Attempt, g Guard, lease clientv3.LeaseID, binding protocol.Object) (Outcome, error) {
	if lease == 0 || g.Coordinator != nil {
		return Outcome{}, errors.New("election prerequisites")
	}
	v, e := s.Read(ctx, g.Keys("epoch", "coordinator")...)
	if e != nil {
		return Outcome{}, e
	}
	if e = g.Check(v); e != nil {
		return Outcome{}, e
	}
	if v.Values["coordinator"].Revision != 0 {
		return Outcome{}, ErrConflict
	}
	epoch := string(v.Values["epoch"].Bytes)
	n, e := strconv.ParseInt(epoch, 10, 64)
	if e != nil || n < 0 || n == 9223372036854775807 {
		return Outcome{}, errors.New("invalid durable epoch")
	}
	next := strconv.FormatInt(n+1, 10)
	c := protocol.Object{}
	for k, x := range binding {
		c[k] = x
	}
	c["epoch"] = next
	c["leaseId"] = fmt.Sprintf("%016x", uint64(lease))
	p, _ := protocol.Load()
	if e = p.Validate(c, "Coordinator", ""); e != nil {
		return Outcome{}, e
	}
	var node protocol.Object
	if e = json.Unmarshal(g.Node, &node); e != nil {
		return Outcome{}, e
	}
	for _, k := range []string{"nodeId", "bootId", "nodeFence"} {
		if c[k] != node[k] {
			return Outcome{}, errors.New("election node binding")
		}
	}
	return s.Apply(ctx, a, v, []Write{{Key: "epoch", Bytes: []byte(next)}, {Key: "coordinator", Bytes: JSON(c), Lease: lease}}, "APPLIED", c)
}
