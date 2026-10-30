package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

func Fixtures(t *testing.T) Object {
	t.Helper()
	var all Object
	if e := json.Unmarshal(ProfileBytes(), &all); e != nil {
		t.Fatal(e)
	}
	return Obj(all, "illustrativeVectors")
}
func clone(o Object) Object { b, _ := json.Marshal(o); var v Object; json.Unmarshal(b, &v); return v }
func TestFrozenFixtures(t *testing.T) {
	p, e := Load()
	if e != nil {
		t.Fatal(e)
	}
	v := Fixtures(t)
	for name, raw := range Obj(v, "wireOutcomes") {
		t.Run(name, func(t *testing.T) {
			x := raw.(map[string]any)
			wr := Obj(x, "wireRequest")
			req := Obj(wr, "request")
			ws := Obj(x, "wireResponse")
			r := Obj(ws, "response")
			op := Text(Obj(req, "action"), "operation")
			if e = p.Validate(wr, "WireRequest", op); e != nil {
				t.Fatal(e)
			}
			var originals []Object
			if name == "historicalStatus" {
				originals = []Object{Obj(Obj(Obj(Obj(v, "wireOutcomes"), "authorized"), "wireRequest"), "request")}
			}
			if name == "rejectedReservation" {
				if e = p.ValidateResponse(ws, req); e == nil {
					t.Fatal("frozen contradictory null coordinator epoch accepted")
				}
				r["decision"].(map[string]any)["coordinatorEpoch"] = Obj(Obj(req, "action"), "requiredCoordinator")["epoch"]
				seed := make([]byte, 32)
				for i := range seed {
					seed[i] = byte(64 + i)
				}
				ws["signature"], _ = p.Sign("response", r, ed25519.NewKeyFromSeed(seed))
				x["canonicalResponseUtf8"], _ = func() (string, error) { b, e := Canonical(r); return string(b), e }()
			}
			if e = p.ValidateResponse(ws, req, originals...); e != nil {
				t.Fatal(e)
			}
			pub, _ := Unbase(Text(x, "requestPublicKey"), 32)
			if e = p.Verify("request", req, Text(wr, "signature"), ed25519.PublicKey(pub)); e != nil {
				t.Fatal(e)
			}
			pub, _ = Unbase(Text(x, "gatewayPublicKey"), 32)
			if e = p.Verify("response", r, Text(ws, "signature"), ed25519.PublicKey(pub)); e != nil {
				t.Fatal(e)
			}
			b, e := Canonical(r)
			if e != nil || string(b) != x["canonicalResponseUtf8"] {
				t.Fatal("canonical fixture")
			}
			raw, _ := Canonical(ws)
			if _, e = Decode(raw); e != nil {
				t.Fatal(e)
			}
		})
	}
	for name, domain := range map[string]string{"hostAdmission": "hostAdmission", "recoveryManifest": "recoveryManifest", "committedCopyReceipt": "archiveReattestation"} {
		t.Run(name, func(t *testing.T) {
			x := Obj(v, name)
			r := Obj(x, "record")
			pub, _ := Unbase(Text(x, "publicKey"), 32)
			if e = p.Verify(domain, Unsigned(r), Text(r, "signature"), ed25519.PublicKey(pub)); e != nil {
				t.Fatal(e)
			}
			b, _ := Canonical(Unsigned(r))
			if string(b) != x["canonicalUnsignedUtf8"] {
				t.Fatal("canonical artifact")
			}
		})
	}
	for _, raw := range v["signedArtifactNegatives"].([]any) {
		x := raw.(map[string]any)
		t.Run(Text(x, "name"), func(t *testing.T) {
			r := Obj(x, "record")
			pub, _ := Unbase(Text(x, "publicKey"), 32)
			e := p.Verify(Text(x, "verifyDomain"), Unsigned(r), Text(r, "signature"), ed25519.PublicKey(pub))
			if x["requiredResult"] == "SIGNATURE_REJECT" && e == nil {
				t.Fatal("bad signature accepted")
			}
			if x["requiredResult"] != "SIGNATURE_REJECT" && e != nil {
				t.Fatal("context negative should have a valid signature", e)
			}
		})
	}
}
func TestParserRejectsAmbiguity(t *testing.T) {
	for name, b := range map[string]string{
		"duplicate": `{"a":"x","a":"y"}`, "nestedDuplicate": `{"a":{"x":"1","x":"2"}}`, "number": `{"a":1}`, "unicode": `{"a":"\u00e4"}`, "trailing": `{} {}`, "deep": `{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{}}}}}}}}`, "array": `{"a":[` + strings.Repeat(`"x",`, 100) + `"x"]}`, "size": `{"a":"` + strings.Repeat("x", 65536) + `""}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := Decode([]byte(b)); e == nil {
				t.Fatal("ambiguous input accepted")
			}
		})
	}
}
func TestResponseRejectsInconsistentSignedResults(t *testing.T) {
	p, _ := Load()
	v := Fixtures(t)
	cases := Obj(v, "wireOutcomes")
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(64 + i)
	}
	key := ed25519.NewKeyFromSeed(seed)
	mutations := []struct {
		name, fixture string
		mutate        func(Object)
	}{
		{"grantOnRejection", "rejectedAuthorize", func(r Object) {
			r["result"] = Obj(Obj(cases["authorized"].(map[string]any), "wireResponse"), "response")["result"]
		}},
		{"missingSuccess", "authorized", func(r Object) { r["result"] = nil }},
		{"unknownWithDecision", "unknownStatus", func(r Object) {
			Obj(r, "result")["targetDecision"] = Obj(Obj(Obj(cases["historicalStatus"].(map[string]any), "wireResponse"), "response"), "result")["targetDecision"]
		}},
		{"wrongAction", "authorized", func(r Object) { Obj(r, "decision")["actionDigest"] = strings.Repeat("f", 64) }},
		{"unknownField", "authorized", func(r Object) { r["extra"] = "bad" }},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			x := clone(cases[m.fixture].(map[string]any))
			w := Obj(x, "wireResponse")
			r := Obj(w, "response")
			m.mutate(r)
			signature, e := p.Sign("response", r, key)
			if e != nil {
				t.Fatal(e)
			}
			w["signature"] = signature
			if e = p.Verify("response", r, signature, key.Public().(ed25519.PublicKey)); e != nil {
				t.Fatal(e)
			}
			if e = p.ValidateResponse(w, Obj(Obj(x, "wireRequest"), "request")); e == nil {
				t.Fatal("signed inconsistent result accepted")
			}
		})
	}
}
func TestCanonicalASCII(t *testing.T) {
	o := Object{"z": "<&>", "a": []any{"\\", "\"", nil}}
	b, e := Canonical(o)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(b, []byte(`{"a":["\\","\"",null],"z":"<&>"}`)) {
		t.Fatal(string(b))
	}
}
