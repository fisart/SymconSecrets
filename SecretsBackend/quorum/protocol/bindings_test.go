package protocol

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
)

func TestIR03SharedSignedBindings(t *testing.T) {
	raw, e := os.ReadFile("../tests/response-bindings.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors struct {
		Profile string `json:"profileSha256"`
		Gateway Object `json:"gateway"`
		Cases   []struct {
			Name     string `json:"name"`
			Accept   bool   `json:"accept"`
			Request  Object `json:"request"`
			Wire     Object `json:"wire"`
			Original Object `json:"original"`
		} `json:"cases"`
	}
	if e = json.Unmarshal(raw, &vectors); e != nil {
		t.Fatal(e)
	}
	if vectors.Profile != ProfileSHA256 {
		t.Fatal("wrong baseline")
	}
	p, _ := Load()
	pub, e := Unbase(Text(vectors.Gateway, "publicKey"), 32)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range vectors.Cases {
		t.Run(v.Name, func(t *testing.T) {
			if e := p.Verify("response", Obj(v.Wire, "response"), Text(v.Wire, "signature"), ed25519.PublicKey(pub)); e != nil {
				t.Fatal("negative must be validly signed", e)
			}
			var originals []Object
			if v.Original != nil {
				originals = []Object{v.Original}
			}
			e := p.ValidateResponse(v.Wire, v.Request, originals...)
			if (e == nil) != v.Accept {
				t.Fatalf("accept=%v error=%v", v.Accept, e)
			}
		})
	}
}
