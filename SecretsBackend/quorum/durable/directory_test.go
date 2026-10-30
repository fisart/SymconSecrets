package durable

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func root(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "private")
	if e := os.Mkdir(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestImmutableAndPrivateStorage(t *testing.T) {
	path := root(t)
	d, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if e = d.Locked(func() error { return d.PutImmutable("one", []byte("durable bytes")) }); e != nil {
		t.Fatal(e)
	}
	if e = d.Locked(func() error { return d.PutImmutable("one", []byte("changed")) }); e == nil {
		t.Fatal("immutable content overwritten")
	}
	st, e := os.Stat(filepath.Join(path, "one"))
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("permissions")
	}
	if e = os.Symlink("one", filepath.Join(path, "alias")); e != nil {
		t.Fatal(e)
	}
	if _, e = d.Read("alias"); e == nil {
		t.Fatal("symlink accepted")
	}
	if e = d.Replace("../escape", []byte("bad")); e == nil {
		t.Fatal("path traversal accepted")
	}
}
func TestLockChildProcess(t *testing.T) {
	path := os.Getenv("SYMCON_DURABLE_LOCK_CHILD")
	if path == "" {
		t.Skip("lock child only")
	}
	d, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if e = d.Locked(func() error { return nil }); e == nil {
		t.Fatal("competing process obtained lock")
	}
}
func TestRealProcessLockExclusion(t *testing.T) {
	path := root(t)
	d, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if e = d.Locked(func() error {
		cmd := exec.Command(os.Args[0], "-test.run=^TestLockChildProcess$", "-test.timeout=10s")
		cmd.Env = append(os.Environ(), "SYMCON_DURABLE_LOCK_CHILD="+path)
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("child lock test: %s %v", b, e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
