package consensus

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/internal/testcluster"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestEtcdMemberProcess(t *testing.T) { testcluster.MemberProcess(t) }
func attempt() Attempt {
	id := testcluster.UUID()
	return Attempt{ID: id, Digest: protocol.MustDigest(protocol.Object{"operationId": id})}
}
func fixture(t *testing.T, c *testcluster.Cluster) (*Store, Guard) {
	t.Helper()
	s, e := New(c.Client, testcluster.UUID(), testcluster.UUID(), c.NativeID)
	if e != nil {
		t.Fatal(e)
	}
	node := protocol.Object{"nodeId": testcluster.UUID(), "bootId": protocol.Base(make([]byte, 32)), "nodeFence": "1"}
	g := Guard{Head: []byte("head-0"), Policy: []byte("policy-0"), Membership: []byte("membership-0"), NodeID: protocol.Text(node, "nodeId"), Node: JSON(node)}
	records := map[string][]byte{"lineage": []byte(c.NativeID), "head": g.Head, "policy": g.Policy, "membership": g.Membership, "epoch": []byte("0"), "nodes/" + g.NodeID: g.Node}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e = s.Initialize(ctx, attempt(), records); e != nil {
		t.Fatal(e)
	}
	return s, g
}
func TestFinalTransactionFencesPausedWorkers(t *testing.T) {
	c := testcluster.New(t)
	s, g := fixture(t, c)
	ctx := context.Background()
	checked := make(chan struct{})
	resume := make(chan struct{})
	done := make(chan error, 1)
	a := attempt()
	go func() {
		_, e := s.Guarded(ctx, a, g, "AUTHORIZED", map[string]string{"exactResponse": "record-1"}, func() { close(checked); <-resume })
		done <- e
	}()
	<-checked
	v, e := s.Read(ctx, "policy")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Apply(ctx, attempt(), v, []Write{{Key: "policy", Bytes: []byte("policy-revoked")}}, "COMMITTED", nil); e != nil {
		t.Fatal(e)
	}
	close(resume)
	if e = <-done; !errors.Is(e, ErrConflict) {
		t.Fatal("paused stale validation committed", e)
	}
	out, e := s.Resolve(ctx, a)
	if e != nil || out != nil {
		t.Fatal("stale grant exists", out, e)
	}
}
func TestImmutableOutcomesAndAllowedCompletion(t *testing.T) {
	c := testcluster.New(t)
	s, g := fixture(t, c)
	ctx := context.Background()
	a := attempt()
	out, e := s.Guarded(ctx, a, g, "AUTHORIZED", map[string]string{"exactResponse": "record-1"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	v, _ := s.Read(ctx, "policy")
	s.Apply(ctx, attempt(), v, []Write{{Key: "policy", Bytes: []byte("revoked")}}, "COMMITTED", nil)
	historical, e := s.Resolve(ctx, a)
	if e != nil || historical == nil || string(historical.Payload) != string(out.Payload) {
		t.Fatal("already authorized exact completion lost", e)
	}
	bad := a
	bad.Digest = protocol.MustDigest(protocol.Object{"changed": "request"})
	if _, e = s.Resolve(ctx, bad); !errors.Is(e, ErrIDReuse) {
		t.Fatal("ID reuse accepted", e)
	}
	fresh, _ := s.Read(ctx, "policy")
	if _, e = s.Apply(ctx, a, fresh, nil, "REJECTED", nil); e == nil {
		t.Fatal("success replaced by rejection")
	}
	historical, _ = s.Resolve(ctx, a)
	if historical.Kind != "AUTHORIZED" {
		t.Fatal("original outcome changed")
	}
}
func TestElectionLeaseAndOrdinaryPeerRights(t *testing.T) {
	c := testcluster.New(t)
	s, g := fixture(t, c)
	ctx := context.Background()
	lease, e := c.Client.Grant(ctx, 10)
	if e != nil {
		t.Fatal(e)
	}
	var binding protocol.Object
	json.Unmarshal(g.Node, &binding)
	a := attempt()
	win, e := s.Elect(ctx, a, g, lease.ID, binding)
	if e != nil {
		t.Fatal(e)
	}
	var coordinator protocol.Object
	json.Unmarshal(win.Payload, &coordinator)
	old := g
	old.Coordinator = JSON(coordinator)
	checked := make(chan struct{})
	resume := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, e := s.Guarded(ctx, attempt(), old, "COMMITTED", nil, func() { close(checked); <-resume })
		done <- e
	}()
	<-checked
	if _, e = c.Client.Revoke(ctx, lease.ID); e != nil {
		t.Fatal(e)
	}
	lease2, e := c.Client.Grant(ctx, 10)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Elect(ctx, attempt(), g, lease2.ID, binding); e != nil {
		t.Fatal(e)
	}
	close(resume)
	if e = <-done; !errors.Is(e, ErrConflict) {
		t.Fatal("former coordinator committed", e)
	}
	if _, e = s.Guarded(ctx, attempt(), g, "AUTHORIZED", map[string]string{"ordinaryPeer": "fresh exact response"}, nil); e != nil {
		t.Fatal("leadership loss wrongly revoked ordinary peer", e)
	}
	v, _ := s.Read(ctx, "epoch")
	if string(v.Values["epoch"].Bytes) != "2" {
		t.Fatal("epoch not monotonic")
	}
	if historical, e := s.Resolve(ctx, a); e != nil || historical == nil {
		t.Fatal("election lost ACK unresolved", e)
	}
}
func TestConcurrentElectionAndCrashRecovery(t *testing.T) {
	c := testcluster.New(t)
	s, g := fixture(t, c)
	ctx := context.Background()
	var binding protocol.Object
	json.Unmarshal(g.Node, &binding)
	start := make(chan struct{})
	out := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		l, e := c.Client.Grant(ctx, 15)
		if e != nil {
			t.Fatal(e)
		}
		wg.Add(1)
		go func(id clientv3.LeaseID) {
			defer wg.Done()
			<-start
			_, e := s.Elect(ctx, attempt(), g, id, binding)
			out <- e
		}(l.ID)
	}
	close(start)
	wg.Wait()
	close(out)
	wins := 0
	for e := range out {
		if e == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatal("election winners", wins)
	}
	// SIGKILL and ordinary intact-volume restart, not a simulated in-memory store.
	leader := c.Leader(t)
	other := (leader + 1) % 3
	c.Kill(leader)
	// A leader change may return an uncertain transport error. Preserve the same
	// attempt and resolve it; do not pretend failover is instantaneous or mint IDs.
	survivor := attempt()
	confirmed := false
	deadlineMajority := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadlineMajority) {
		call, cancelCall := context.WithTimeout(ctx, 2*time.Second)
		_, e := s.Guarded(call, survivor, g, "AUTHORIZED", nil, nil)
		cancelCall()
		if e == nil {
			confirmed = true
			break
		}
		query, cancelQuery := context.WithTimeout(ctx, time.Second)
		known, qe := s.Resolve(query, survivor)
		cancelQuery()
		if qe == nil && known != nil {
			confirmed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !confirmed {
		t.Fatal("majority did not recover after one process crash")
	}
	c.Kill(other)
	deadline, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	defer cancel()
	if _, e := s.Guarded(deadline, attempt(), g, "AUTHORIZED", nil, nil); e == nil {
		t.Fatal("minority authorized")
	}
	c.Start(t, leader)
	c.Start(t, other)
	deadline2, cancel2 := context.WithTimeout(ctx, 12*time.Second)
	defer cancel2()
	v, e := s.Read(deadline2, "head", "epoch")
	if e != nil || string(v.Values["head"].Bytes) != "head-0" || string(v.Values["epoch"].Bytes) != "1" {
		t.Fatal("restart lost acknowledged state", e)
	}
	if o, e := s.Resolve(deadline2, survivor); e != nil || o == nil || o.Kind != "AUTHORIZED" {
		t.Fatal("SIGKILL restart lost acknowledged decision", e)
	}
}
func TestWrongNativeClusterCannotWrite(t *testing.T) {
	c := testcluster.New(t)
	s, g := fixture(t, c)
	wrong, e := New(c.Client, testcluster.UUID(), testcluster.UUID(), "0000000000000001")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = wrong.Read(context.Background(), "head"); !errors.Is(e, ErrLineage) {
		t.Fatal("foreign native lineage accepted", e)
	}
	v, _ := s.Read(context.Background(), "head")
	if string(v.Values["head"].Bytes) != string(g.Head) {
		t.Fatal("lineage failure changed data")
	}
}
