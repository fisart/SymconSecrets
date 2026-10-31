// Package protocol implements the closed, hash-pinned DC-01 v1.2 wire contract.
// It conveys no authority by itself: callers must perform current quorum checks.
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const ProfileSHA256 = "d406bb26320866f390b4d2222f6307516ff0edadcdd2ef166277f9ec739176fc"
const MaxMetadataBytes = 65536

//go:embed profile.json
var profileBytes []byte

type Object = map[string]any
type FieldSet struct {
	Fields map[string]string `json:"fields"`
}
type Operation struct {
	AllowedActors []string `json:"allowedActors"`
	Coordinator   string   `json:"coordinator"`
	ExpectedHead  string   `json:"expectedHead"`
	Body          FieldSet `json:"body"`
	Result        FieldSet `json:"result"`
}
type Profile struct {
	Domains                  map[string]string          `json:"domains"`
	Primitives               map[string]string          `json:"primitives"`
	Enums                    map[string][]string        `json:"enums"`
	Records                  map[string]FieldSet        `json:"records"`
	Operations               map[string]Operation       `json:"operations"`
	Unions                   map[string]json.RawMessage `json:"unions"`
	ResponseDecisionContract struct {
		SuccessResults map[string][]string `json:"successResultsByOperation"`
	} `json:"responseDecisionContract"`
}

func Load() (*Profile, error) {
	sum := sha256.Sum256(profileBytes)
	if hex.EncodeToString(sum[:]) != ProfileSHA256 {
		return nil, errors.New("protocol profile integrity failure")
	}
	p := new(Profile)
	err := json.Unmarshal(profileBytes, p)
	return p, err
}
func ProfileBytes() []byte { return append([]byte(nil), profileBytes...) }
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func Text(o Object, k string) string { v, _ := o[k].(string); return v }
func Obj(o Object, k string) Object  { v, _ := o[k].(map[string]any); return v }

// Decode rejects duplicate keys, excessive nesting, trailing JSON and numeric values.
// Ordinary encoding/json decoding alone would silently accept duplicate keys.
func Decode(raw []byte) (Object, error) {
	if len(raw) > MaxMetadataBytes {
		return nil, errors.New("metadata limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var read func(int) (any, error)
	read = func(level int) (any, error) {
		t, err := d.Token()
		if err != nil {
			return nil, err
		}
		switch x := t.(type) {
		case json.Delim:
			if level > 8 {
				return nil, errors.New("metadata depth")
			}
			if x == '{' {
				o := Object{}
				for d.More() {
					t, e := d.Token()
					if e != nil {
						return nil, e
					}
					k, ok := t.(string)
					if !ok || !ascii(k) {
						return nil, errors.New("invalid key")
					}
					if _, exists := o[k]; exists {
						return nil, errors.New("duplicate key")
					}
					v, e := read(level + 1)
					if e != nil {
						return nil, e
					}
					o[k] = v
				}
				_, err = d.Token()
				return o, err
			}
			if x == '[' {
				a := []any{}
				for d.More() {
					if len(a) >= 100 {
						return nil, errors.New("array limit")
					}
					v, e := read(level + 1)
					if e != nil {
						return nil, e
					}
					a = append(a, v)
				}
				_, err = d.Token()
				return a, err
			}
			return nil, errors.New("unexpected delimiter")
		case string:
			if !ascii(x) {
				return nil, errors.New("non ASCII metadata")
			}
			return x, nil
		case json.Number:
			return nil, errors.New("numeric metadata forbidden")
		case nil, bool:
			return x, nil
		default:
			return nil, errors.New("invalid JSON token")
		}
	}
	v, err := read(1)
	if err != nil {
		return nil, err
	}
	if _, e := d.Token(); e != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("root must be object")
	}
	return o, nil
}
func ascii(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}

// Canonical is the declared ASCII subset of JCS. Never use it for arbitrary
// application objects containing floats, non-ASCII keys or plaintext secrets.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	var write func(any) error
	write = func(x any) error {
		switch y := x.(type) {
		case nil:
			b.WriteString("null")
		case bool:
			if y {
				b.WriteString("true")
			} else {
				b.WriteString("false")
			}
		case string:
			if !ascii(y) {
				return errors.New("non ASCII canonical input")
			}
			b.WriteString(strconv.Quote(y))
		case []any:
			b.WriteByte('[')
			for i, e := range y {
				if i > 0 {
					b.WriteByte(',')
				}
				if err := write(e); err != nil {
					return err
				}
			}
			b.WriteByte(']')
		case map[string]any:
			keys := make([]string, 0, len(y))
			for k := range y {
				if !ascii(k) {
					return errors.New("non ASCII key")
				}
				keys = append(keys, k)
			}
			sort.Strings(keys)
			b.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteString(strconv.Quote(k))
				b.WriteByte(':')
				if err := write(y[k]); err != nil {
					return err
				}
			}
			b.WriteByte('}')
		default:
			return fmt.Errorf("unsupported canonical type %T", x)
		}
		return nil
	}
	err := write(v)
	return b.Bytes(), err
}
func Digest(v any) (string, error) {
	b, e := Canonical(v)
	if e != nil {
		return "", e
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}
func MustDigest(v any) string {
	s, e := Digest(v)
	if e != nil {
		panic(e)
	}
	return s
}
func Equal(a, b any) bool {
	x, e := Canonical(a)
	if e != nil {
		return false
	}
	y, e := Canonical(b)
	return e == nil && bytes.Equal(x, y)
}

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var native = regexp.MustCompile(`^[0-9a-f]{16}$`)
var decimal = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

func Unbase(s string, n int) ([]byte, error) {
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || len(b) != n || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, errors.New("base64url binding")
	}
	return b, nil
}
func Base(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func (p *Profile) Fields(v any, f FieldSet, operation string) error {
	o, ok := v.(map[string]any)
	if !ok || len(o) != len(f.Fields) {
		return errors.New("closed field set")
	}
	for k, t := range f.Fields {
		x, exists := o[k]
		if !exists {
			return fmt.Errorf("missing %s", k)
		}
		if e := p.Validate(x, t, operation); e != nil {
			return fmt.Errorf("%s: %w", k, e)
		}
	}
	return nil
}
func (p *Profile) Validate(v any, t, operation string) error {
	if strings.HasSuffix(t, "?") {
		if v == nil {
			return nil
		}
		t = strings.TrimSuffix(t, "?")
	}
	if strings.HasSuffix(t, "[]") {
		a, ok := v.([]any)
		if !ok || len(a) > 100 {
			return errors.New("typed array")
		}
		for _, e := range a {
			if err := p.Validate(e, strings.TrimSuffix(t, "[]"), operation); err != nil {
				return err
			}
		}
		return nil
	}
	if r, ok := p.Records[t]; ok {
		return p.Fields(v, r, operation)
	}
	if en, ok := p.Enums[t]; ok {
		s, ok := v.(string)
		if !ok || !contains(en, s) {
			return fmt.Errorf("enum %s", t)
		}
		return nil
	}
	if t == "Operation" {
		s, ok := v.(string)
		if !ok {
			return errors.New("operation")
		}
		if _, ok = p.Operations[s]; !ok {
			return errors.New("unknown operation")
		}
		return nil
	}
	if t == "OperationBody" || t == "OperationResult" {
		op, ok := p.Operations[operation]
		if !ok {
			return errors.New("missing dispatch context")
		}
		if t == "OperationBody" {
			return p.Fields(v, op.Body, operation)
		}
		return p.Fields(v, op.Result, operation)
	}
	if t == "Actor" || t == "AuthorizationEvidence" {
		o, ok := v.(map[string]any)
		if !ok {
			return errors.New("union object")
		}
		var choices []string
		if e := json.Unmarshal(p.Unions[t], &choices); e != nil {
			return e
		}
		for _, name := range choices {
			tag := p.Records[name].Fields["kind"]
			if contains(p.Enums[tag], Text(o, "kind")) {
				return p.Validate(v, name, operation)
			}
		}
		return errors.New("unknown union tag")
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("primitive %s", t)
	}
	valid := false
	switch t {
	case "UUID":
		valid = uuid.MatchString(s)
	case "DIGEST":
		valid = digest.MatchString(s)
	case "Q", "Q_POS":
		valid = decimal.MatchString(s) && (len(s) < 19 || (len(s) == 19 && s <= "9223372036854775807")) && (t != "Q_POS" || s != "0")
	case "NATIVE_ID":
		valid = native.MatchString(s) && s != "0000000000000000"
	case "B64_16", "B64_32", "B64_64":
		n, _ := strconv.Atoi(strings.TrimPrefix(t, "B64_"))
		_, e := Unbase(s, n)
		valid = e == nil
	case "B64_VAR":
		b, e := base64.RawURLEncoding.Strict().DecodeString(s)
		valid = e == nil && len(s) > 0 && len(s) <= 16384 && Base(b) == s
	case "ASCII_2048", "ASCII_253":
		n, _ := strconv.Atoi(strings.TrimPrefix(t, "ASCII_"))
		valid = len(s) > 0 && len(s) <= n && ascii(s)
	default:
		return fmt.Errorf("undefined type %s", t)
	}
	if !valid {
		return fmt.Errorf("invalid %s", t)
	}
	return nil
}
func (p *Profile) ActionDigest(r Object) (string, error) {
	o := Object{}
	for _, k := range []string{"version", "clusterId", "realmId", "incarnation", "trustRevision", "actor", "action"} {
		o[k] = r[k]
	}
	b, e := Canonical(o)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256(append([]byte(p.Domains["action"]), b...))
	return hex.EncodeToString(sum[:]), nil
}
func (p *Profile) Sign(domain string, v Object, key ed25519.PrivateKey) (string, error) {
	d, ok := p.Domains[domain]
	if !ok || len(key) != ed25519.PrivateKeySize {
		return "", errors.New("signature parameters")
	}
	b, e := Canonical(v)
	if e != nil {
		return "", e
	}
	return Base(ed25519.Sign(key, append([]byte(d), b...))), nil
}
func (p *Profile) Verify(domain string, v Object, signature string, key ed25519.PublicKey) error {
	d, ok := p.Domains[domain]
	if !ok || len(key) != ed25519.PublicKeySize {
		return errors.New("signature parameters")
	}
	s, e := Unbase(signature, 64)
	if e != nil {
		return e
	}
	b, e := Canonical(v)
	if e != nil {
		return e
	}
	if !ed25519.Verify(key, append([]byte(d), b...), s) {
		return errors.New("signature verification")
	}
	return nil
}
func Unsigned(v Object) Object {
	r := Object{}
	for k, x := range v {
		if k != "signature" {
			r[k] = x
		}
	}
	return r
}

// ValidateResponse is required even after verifying the gateway signature.
func (p *Profile) ValidateResponse(wire, request Object, originals ...Object) error {
	r := Obj(wire, "response")
	op := Text(Obj(request, "action"), "operation")
	if e := p.Validate(request, "Request", op); e != nil {
		return e
	}
	if e := p.Validate(wire, "WireResponse", op); e != nil {
		return e
	}
	if r["outcome"] == "SUCCESS" {
		if e := p.requestRole(request); e != nil {
			return e
		}
	}
	for _, k := range []string{"version", "clusterId", "realmId", "incarnation", "trustRevision", "requestId", "nonce"} {
		if r[k] != request[k] {
			return errors.New("response request binding")
		}
	}
	for _, k := range []string{"clusterId", "realmId", "incarnation"} {
		if Obj(r, "currentHead")[k] != request[k] {
			return errors.New("response head lineage")
		}
	}
	ad, e := p.ActionDigest(request)
	if e != nil {
		return e
	}
	if r["actionDigest"] != ad || r["operation"] != op {
		return errors.New("response action binding")
	}
	dec := Obj(r, "decision")
	action := Obj(request, "action")
	if expected := Obj(action, "expectedHead"); expected != nil && r["outcome"] == "SUCCESS" {
		if e := headAtLeast(Obj(r, "currentHead"), expected); e != nil {
			return e
		}
	}
	if e := coordinatorAtLeast(Obj(r, "currentCoordinator"), Obj(action, "requiredCoordinator")); e != nil && r["outcome"] == "SUCCESS" {
		return e
	}
	if dec != nil {
		if dec["operationId"] != action["operationId"] || dec["operation"] != op || dec["actionDigest"] != ad || dec["incarnation"] != request["incarnation"] || dec["actorDigest"] != MustDigest(request["actor"]) {
			return errors.New("decision action binding")
		}
		if e := p.decisionBinding(dec, request); e != nil {
			return e
		}
	}
	if r["outcome"] == "REJECTED" {
		if r["result"] != nil || dec == nil || dec["result"] != "REJECTED" || dec["reason"] == "NONE" || dec["resultHeadDigest"] != nil {
			return errors.New("inconsistent rejection")
		}
		return nil
	}
	result := Obj(r, "result")
	if result == nil {
		return errors.New("success result missing")
	}
	if op == "readHead" || op == "status" {
		if dec != nil {
			return errors.New("read decision")
		}
	} else if dec == nil || dec["result"] == "REJECTED" {
		return errors.New("inconsistent success")
	}
	if op == "status" {
		target := Obj(result, "targetDecision")
		body := Obj(action, "body")
		if result["resolution"] == "UNKNOWN" {
			if target != nil {
				return errors.New("unknown with decision")
			}
		} else if target == nil || target["operationId"] != body["targetOperationId"] || target["actionDigest"] != body["targetActionDigest"] {
			return errors.New("historical target binding")
		}
	}
	return p.resultBinding(r, request, originals)
}
