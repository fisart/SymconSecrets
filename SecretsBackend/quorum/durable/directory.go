// Package durable provides private, locked, fsync-before-acknowledgement storage.
// Host guards must place it outside the protected component's restore domain.
package durable

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type Directory struct{ root *os.Root }

func Open(path string) (*Directory, error) {
	clean, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	resolved, e := filepath.EvalSymlinks(clean)
	if e != nil || resolved != clean {
		return nil, errors.New("private canonical directory required")
	}
	st, e := os.Lstat(clean)
	if e != nil {
		return nil, e
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 {
		return nil, errors.New("directory must be private 0700")
	}
	r, e := os.OpenRoot(clean)
	if e != nil {
		return nil, e
	}
	parent, e := os.Open(filepath.Dir(clean))
	if e != nil {
		r.Close()
		return nil, e
	}
	e = parent.Sync()
	parent.Close()
	if e != nil {
		r.Close()
		return nil, e
	}
	return &Directory{root: r}, nil
}
func (d *Directory) Close() error { return d.root.Close() }
func nameOK(name string) bool {
	return name != "" && !strings.ContainsAny(name, "/\\\x00") && name != "." && name != ".."
}
func (d *Directory) Read(name string) ([]byte, error) {
	if !nameOK(name) {
		return nil, errors.New("invalid file name")
	}
	st, e := d.root.Lstat(name)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return nil, errors.New("private regular file required")
	}
	f, e := d.root.Open(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 67108865))
}
func (d *Directory) Sync() error {
	f, e := d.root.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (d *Directory) Locked(fn func() error) error {
	f, e := d.root.OpenFile("control.lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	ls, e := d.root.Lstat("control.lock")
	if e != nil || !ls.Mode().IsRegular() || !os.SameFile(st, ls) || st.Mode().Perm() != 0600 {
		return errors.New("unsafe lock")
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("storage transition busy")
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
func (d *Directory) Replace(name string, b []byte) error {
	if !nameOK(name) || len(b) > 67108864 {
		return errors.New("invalid write")
	}
	if st, e := d.root.Lstat(name); e == nil && (!st.Mode().IsRegular() || st.Mode().Perm() != 0600) {
		return errors.New("unsafe destination")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	nonce := make([]byte, 16)
	if _, e := rand.Read(nonce); e != nil {
		return e
	}
	temp := "prepare-" + hex.EncodeToString(nonce)
	f, e := d.root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer d.root.Remove(temp)
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = d.root.Rename(temp, name); e != nil {
		return e
	}
	return d.Sync()
}

// PutImmutable is idempotent only for exactly identical bytes. The caller holds Locked.
func (d *Directory) PutImmutable(name string, b []byte) error {
	old, e := d.Read(name)
	if e == nil {
		if !bytes.Equal(old, b) {
			return errors.New("immutable file collision")
		}
		return nil
	}
	if !os.IsNotExist(e) {
		return e
	}
	return d.Replace(name, b)
}

// Remove requires a previously durable authority deletion fence, checked by caller.
func (d *Directory) Remove(name string) error {
	if !nameOK(name) {
		return errors.New("invalid file name")
	}
	if e := d.root.Remove(name); e != nil && !os.IsNotExist(e) {
		return e
	}
	return d.Sync()
}
