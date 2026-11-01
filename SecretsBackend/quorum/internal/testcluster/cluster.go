// Package testcluster runs actual etcd members in separately killable processes.
// Its loopback plaintext transport is TEST ONLY and never a deployment template.
package testcluster

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"
)

type config struct{ Name, Dir, Client, Peer, Initial, Token string }
type member struct {
	config  string
	command *exec.Cmd
	log     *os.File
}
type Cluster struct {
	Client    *clientv3.Client
	Endpoints []string
	NativeID  string
	members   []member
}

func UUID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	s := hex.EncodeToString(b)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}
func endpoint(t *testing.T) (string, net.Listener) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := l.Addr().String()
	return "http://" + addr, l
}
func New(t *testing.T) *Cluster {
	t.Helper()
	root := t.TempDir()
	c := &Cluster{}
	cfgs := make([]config, 3)
	initial := []string{}
	token := UUID()
	// Keep all six addresses reserved while constructing the member roster.
	// Closing every probe immediately can hand the same port to two voters.
	reservations := make([][2]net.Listener, len(cfgs))
	defer func() {
		for _, pair := range reservations {
			for _, listener := range pair {
				if listener != nil {
					listener.Close()
				}
			}
		}
	}()
	for i := range cfgs {
		clientURL, clientListener := endpoint(t)
		peerURL, peerListener := endpoint(t)
		reservations[i] = [2]net.Listener{clientListener, peerListener}
		cfgs[i] = config{Name: fmt.Sprintf("voter-%d", i), Dir: filepath.Join(root, fmt.Sprintf("member-%d", i)), Client: clientURL, Peer: peerURL, Token: token}
		initial = append(initial, cfgs[i].Name+"="+cfgs[i].Peer)
		c.Endpoints = append(c.Endpoints, cfgs[i].Client)
	}
	for i := range cfgs {
		cfgs[i].Initial = strings.Join(initial, ",")
		b, _ := json.Marshal(cfgs[i])
		path := filepath.Join(root, fmt.Sprintf("config-%d.json", i))
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		log, e := os.OpenFile(filepath.Join(root, fmt.Sprintf("log-%d.txt", i)), os.O_CREATE|os.O_RDWR, 0600)
		if e != nil {
			t.Fatal(e)
		}
		c.members = append(c.members, member{config: path, log: log})
	}
	t.Cleanup(func() {
		if c.Client != nil {
			c.Client.Close()
		}
		for i := range c.members {
			c.Kill(i)
			c.members[i].log.Close()
		}
	})
	for i := range c.members {
		reservations[i][0].Close()
		reservations[i][1].Close()
		c.Start(t, i)
	}
	cli, e := clientv3.New(clientv3.Config{Endpoints: c.Endpoints, DialTimeout: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	c.Client = cli
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		r, e := cli.Get(ctx, "readiness-check")
		cancel()
		if e == nil {
			c.NativeID = fmt.Sprintf("%016x", r.Header.ClusterId)
			return c
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, m := range c.members {
		b, _ := os.ReadFile(m.log.Name())
		t.Log(string(b))
	}
	t.Fatal("three-process etcd cluster failed readiness")
	return nil
}
func (c *Cluster) Start(t *testing.T, i int) {
	t.Helper()
	m := &c.members[i]
	if m.command != nil {
		t.Fatal("member already running")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestEtcdMemberProcess$", "-test.timeout=10m")
	cmd.Env = append(os.Environ(), "SYMCON_TEST_ETCD_CONFIG="+m.config)
	cmd.Stdout = m.log
	cmd.Stderr = m.log
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	m.command = cmd
}
func (c *Cluster) Kill(i int) {
	m := &c.members[i]
	if m.command != nil {
		m.command.Process.Kill()
		m.command.Wait()
		m.command = nil
	}
}
func (c *Cluster) Leader(t *testing.T) int {
	t.Helper()
	for i, endpoint := range c.Endpoints {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		status, e := c.Client.Status(ctx, endpoint)
		cancel()
		if e == nil && status.Header.MemberId == status.Leader {
			return i
		}
	}
	t.Fatal("no current Raft leader observed")
	return -1
}
func MemberProcess(t *testing.T) {
	t.Helper()
	path := os.Getenv("SYMCON_TEST_ETCD_CONFIG")
	if path == "" {
		t.Skip("etcd child only")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var input config
	if e = json.Unmarshal(b, &input); e != nil {
		t.Fatal(e)
	}
	cfg := embed.NewConfig()
	cfg.Name = input.Name
	cfg.Dir = input.Dir
	cfg.InitialCluster = input.Initial
	cfg.InitialClusterToken = input.Token
	cfg.Logger = "zap"
	cfg.LogLevel = "error"
	cfg.LogOutputs = []string{"stderr"}
	cfg.TickMs = 100
	cfg.ElectionMs = 1000
	peer, _ := url.Parse(input.Peer)
	client, _ := url.Parse(input.Client)
	cfg.ListenPeerUrls = []url.URL{*peer}
	cfg.AdvertisePeerUrls = []url.URL{*peer}
	cfg.ListenClientUrls = []url.URL{*client}
	cfg.AdvertiseClientUrls = []url.URL{*client}
	server, e := embed.StartEtcd(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	select {
	case <-server.Server.ReadyNotify():
	case e := <-server.Err():
		t.Fatal(e)
	case <-time.After(30 * time.Second):
		t.Fatal("member readiness")
	}
	select {}
}
