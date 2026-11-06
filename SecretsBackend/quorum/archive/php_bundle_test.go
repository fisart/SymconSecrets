package archive

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/fisart/SymconSecrets/SecretsBackend/quorum/protocol"
)

func TestPHPBundleInteroperability(t *testing.T) {
	raw, e := os.ReadFile("php-bundle-vector.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Manifest string `json:"manifest"`
		Objects  []struct {
			Reference protocol.Object `json:"reference"`
			Bytes     string          `json:"bytes"`
		} `json:"objects"`
		Bundle Bundle `json:"bundle"`
		Bytes  string `json:"bytes"`
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	payload, e := base64.RawURLEncoding.Strict().DecodeString(v.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyBundle(payload, v.Bundle); e != nil {
		t.Fatal(e)
	}
	refs := []protocol.Object{}
	data := [][]byte{}
	for _, o := range v.Objects {
		b, e := base64.RawURLEncoding.Strict().DecodeString(o.Bytes)
		if e != nil {
			t.Fatal(e)
		}
		refs = append(refs, o.Reference)
		data = append(data, b)
	}
	actual, index, e := BuildBundle([]byte(v.Manifest), refs, data)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(actual, payload) || index != v.Bundle.IndexDigest {
		t.Fatal("PHP/Go bundle bytes differ")
	}
	for _, bad := range [][]byte{payload[:len(payload)-1], append(append([]byte{}, payload...), 0)} {
		if VerifyBundle(bad, v.Bundle) == nil {
			t.Fatal("altered PHP bundle accepted")
		}
	}
}
