package core

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/consensus"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type worker struct {
	Endpoints                                         []string
	Cluster, Realm, Native, ID, Command, Point, Ready string
	Ref, Actor                                        protocol.Object
}

func TestCoreCommitWorker(t *testing.T) {
	raw := os.Getenv("SYMCON_CORE_TEST_WORKER")
	if raw == "" {
		t.Skip("child helper")
	}
	var input worker
	must(t, json.Unmarshal([]byte(raw), &input))
	client, e := clientv3.New(clientv3.Config{Endpoints: input.Endpoints, DialTimeout: 5 * time.Second})
	must(t, e)
	defer client.Close()
	store, e := consensus.New(client, input.Cluster, input.Realm, input.Native)
	must(t, e)
	controller, e := New(store)
	must(t, e)
	controller.Fault = func(point string) error {
		if point == input.Point {
			must(t, os.WriteFile(input.Ready, []byte("paused"), 0600))
			select {}
		}
		return nil
	}
	_, e = controller.Commit(context.Background(), input.Command, input.ID, input.Ref, input.Actor)
	t.Fatal("worker should pause", e)
}
func TestCoreProcessDeathBeforeAndAfterCommit(t *testing.T) {
	for _, point := range []string{"before-final-cas", "after-commit-before-ack"} {
		t.Run(point, func(t *testing.T) {
			f := fixture(t)
			ctx := context.Background()
			a, _, r := f.ready(t)
			id := protocol.Text(r.Record, "id")
			ready := filepath.Join(t.TempDir(), "ready")
			input := worker{Endpoints: f.cluster.Endpoints, Cluster: protocol.Text(f.head, "clusterId"), Realm: protocol.Text(f.head, "realmId"), Native: f.cluster.NativeID, ID: id, Command: uid(), Ref: ReservationRef(r), Actor: f.actor, Point: point, Ready: ready}
			raw, _ := json.Marshal(input)
			p := exec.Command(os.Args[0], "-test.run=^TestCoreCommitWorker$")
			p.Env = append(os.Environ(), "SYMCON_CORE_TEST_WORKER="+string(raw))
			logfile, e := os.Create(filepath.Join(t.TempDir(), "worker.log"))
			must(t, e)
			defer logfile.Close()
			p.Stdout = logfile
			p.Stderr = logfile
			must(t, p.Start())
			t.Cleanup(func() {
				if p.ProcessState == nil {
					p.Process.Kill()
					p.Wait()
				}
			})
			deadline := time.Now().Add(15 * time.Second)
			for {
				if _, e = os.Stat(ready); e == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("child did not reach boundary; see worker log")
				}
				time.Sleep(10 * time.Millisecond)
			}
			must(t, p.Process.Kill())
			if e = p.Wait(); e == nil {
				t.Fatal("expected killed process")
			}
			fresh, e := New(f.store)
			must(t, e)
			out, e := fresh.ResolveUser(ctx, a.Intent.UserOperationID, Digest(a.Intent))
			must(t, e)
			if point == "before-final-cas" {
				if out != nil {
					t.Fatal("uncommitted prepare appeared committed", out)
				}
				_, e = fresh.Abort(ctx, uid(), id, ReservationRef(r), f.actor, "USER_CANCEL")
				must(t, e)
				if _, e = fresh.Commit(ctx, input.Command, id, input.Ref, input.Actor); e == nil {
					t.Fatal("delayed killed command executed after abort")
				}
			} else {
				if out == nil || out.Result != "COMMITTED" {
					t.Fatal("acknowledged authority state lost", out)
				}
				var historical *consensus.AlreadyDecided
				_, e = fresh.Commit(ctx, input.Command, id, input.Ref, input.Actor)
				if !errors.As(e, &historical) {
					t.Fatal("exact lost reply not resolved", e)
				}
				// Restarting an actual killed Raft leader preserves this specific commit.
				leader := f.cluster.Leader(t)
				f.cluster.Kill(leader)
				f.cluster.Start(t, leader)
				timeout, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				for {
					out, e = fresh.ResolveUser(timeout, a.Intent.UserOperationID, Digest(a.Intent))
					if e == nil {
						break
					}
					if timeout.Err() != nil {
						t.Fatal("majority did not recover status", e)
					}
					time.Sleep(20 * time.Millisecond)
				}
				if out == nil || out.Result != "COMMITTED" {
					t.Fatal("leader restart lost core outcome")
				}
			}
		})
	}
}
