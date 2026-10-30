package trust

import (
	"crypto/ed25519"
	"errors"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/durable"
	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
	"testing"
)

func TestAdmittedRuntimeRequiresIndependentVolumeAndImmutableContext(t *testing.T) {
	path := privateDir(t)
	d, e := durable.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	identity, e := d.Identity()
	if e != nil {
		t.Fatal(e)
	}
	j, e := OpenAdmission(privateDir(t))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	if e = j.Initialize(); e != nil {
		t.Fatal(e)
	}
	record, c := admission(t)
	record["volumeIdentityDigest"] = identity
	c.Expected["volumeIdentityDigest"] = identity
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(96 + i)
	}
	p, _ := protocol.Load()
	record["signature"], _ = p.Sign("hostAdmission", protocol.Unsigned(record), ed25519.NewKeyFromSeed(seed))
	if _, e = j.AdmitDirectory(record, c, path, nil); e == nil {
		t.Fatal("missing volume verifier admitted runtime")
	}
	if _, e = j.AdmitDirectory(record, c, path, func(string, string) error { return errors.New("not an approved volume") }); e == nil {
		t.Fatal("rejected inventory admitted runtime")
	}
	token, e := j.AdmitDirectory(record, c, path, func(got, digest string) error {
		if got != path || digest != identity {
			return errors.New("wrong volume")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = token.MatchesDirectory(d); e != nil {
		t.Fatal(e)
	}
	other, e := durable.Open(privateDir(t))
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if e = token.MatchesDirectory(other); e == nil {
		t.Fatal("admission transferred to another directory")
	}
	boot := token.Record()["bootId"]
	record["bootId"] = "changed caller map"
	copy := token.Record()
	copy["bootId"] = "changed returned map"
	if token.Record()["bootId"] != boot {
		t.Fatal("admitted runtime context was mutable")
	}
}
