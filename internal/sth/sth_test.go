package sth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/christiaan839-beep/receipts-log/internal/merkle"
	"github.com/christiaan839-beep/receipts-log/internal/testutil"
)

func testKey(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestCanonicalMatchesReferenceShape(t *testing.T) {
	root := merkle.LeafHash([]byte("x"))
	s := New("test-log", 3, root, time.Date(2026, 10, 23, 12, 0, 0, 5e6, time.UTC))
	got, err := s.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"logId":"test-log","rootHash":"` + root.String() + `","timestamp":"2026-10-23T12:00:00.005Z","treeSize":3,"v":1}`
	if string(got) != want {
		t.Fatalf("canonical\n got %s\nwant %s", got, want)
	}
}

func TestJSStringEscapes(t *testing.T) {
	cases := map[string]string{
		"plain":        `"plain"`,
		"q\"b\\":       `"q\"b\\"`,
		"\b\f\n\r\t":   `"\b\f\n\r\t"`,
		"\x00\x1f\x7f": `"\u0000\u001f` + "\x7f" + `"`,
		"<&>":          `"<&>"`,
		"é    ":        "\"é    \"",
		"😀":            `"😀"`,
	}
	for in, want := range cases {
		var b bytes.Buffer
		if err := writeJSString(&b, in); err != nil {
			t.Fatal(err)
		}
		if b.String() != want {
			t.Errorf("%q -> %s, want %s", in, b.String(), want)
		}
	}
	var b bytes.Buffer
	if err := writeJSString(&b, "\xff"); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestSignVerify(t *testing.T) {
	key := testKey(t)
	pub := key.Public().(ed25519.PublicKey)
	s, err := Sign(New("log", 0, merkle.EmptyRoot(), time.Now()), key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.Signature, "v2=") {
		t.Fatal("not a v2 signature")
	}
	if err := Verify(s, pub); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*STH){
		func(x *STH) { x.TreeSize++ },
		func(x *STH) { x.LogID = "other" },
		func(x *STH) { x.Timestamp = FormatTime(time.Unix(0, 0)) },
		func(x *STH) { x.RootHash = merkle.LeafHash(nil).String() },
		func(x *STH) { x.Signature = "v2=AAAA" },
		func(x *STH) { x.Signature = x.Signature[:7] + "\n" + x.Signature[7:] },
		func(x *STH) { x.Signature += "\r\n" },
		func(x *STH) { x.Signature = "v3=" + x.Signature[3:] },
		func(x *STH) { x.V = 2 },
	} {
		c := s
		mutate(&c)
		if Verify(c, pub) == nil {
			t.Fatalf("mutated STH verified: %+v", c)
		}
	}
	other := testKey(t).Public().(ed25519.PublicKey)
	if Verify(s, other) == nil {
		t.Fatal("verified under the wrong key")
	}
}

func TestValidate(t *testing.T) {
	good := New("log", 1, merkle.EmptyRoot(), time.Now())
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []STH{
		{V: 1, LogID: "", TreeSize: 1, RootHash: good.RootHash, Timestamp: good.Timestamp},
		{V: 1, LogID: "a\nb", TreeSize: 1, RootHash: good.RootHash, Timestamp: good.Timestamp},
		{V: 1, LogID: "log", TreeSize: MaxTreeSize + 1, RootHash: good.RootHash, Timestamp: good.Timestamp},
		{V: 1, LogID: "log", TreeSize: 1, RootHash: strings.ToUpper(good.RootHash), Timestamp: good.Timestamp},
		{V: 1, LogID: "log", TreeSize: 1, RootHash: "00", Timestamp: good.Timestamp},
		{V: 1, LogID: "log", TreeSize: 1, RootHash: good.RootHash, Timestamp: "yesterday"},
	}
	for i, s := range bad {
		if s.Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestParseCanonical(t *testing.T) {
	s := New("log/ä", 7, merkle.EmptyRoot(), time.Now())
	c, err := s.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseCanonical(c)
	if err != nil || back != s {
		t.Fatalf("round trip: %v %+v", err, back)
	}
	for _, bad := range []string{
		string(c) + " ",
		strings.Replace(string(c), `"logId"`, `"LOGID"`, 1),
		strings.Replace(string(c), `{`, `{ `, 1),
		`{"logId":"log","rootHash":"` + s.RootHash + `","timestamp":"` + s.Timestamp + `","treeSize":7,"v":1,"x":1}`,
		`{"v":1,"logId":"log","rootHash":"` + s.RootHash + `","timestamp":"` + s.Timestamp + `","treeSize":7}`,
		`null`, `[]`, ``,
	} {
		if _, err := ParseCanonical([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestResponseShape(t *testing.T) {
	s, err := Sign(New("log", 1, merkle.EmptyRoot(), time.Now()), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewResponse(s)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"v", "logId", "treeSize", "rootHash", "timestamp", "signature", "canonical"} {
		if _, ok := m[k]; !ok {
			t.Errorf("response lacks %q: %s", k, raw)
		}
	}
}

// FuzzCanonicalString: whatever valid UTF-8 the log ID holds, the
// canonical string is valid JSON that decodes back to the same values,
// and ParseCanonical accepts it.
func FuzzCanonicalString(f *testing.F) {
	f.Add("test-log", "2026-10-23T12:00:00.000Z", uint64(3))
	f.Add(" \"\\\x01", "2026-01-01T00:00:00Z", uint64(0))
	f.Fuzz(func(t *testing.T, logID, ts string, size uint64) {
		s := STH{V: 1, LogID: logID, TreeSize: size, RootHash: merkle.EmptyRoot().String(), Timestamp: ts}
		c, err := s.Canonical()
		if err != nil {
			return
		}
		var back STH
		if err := json.Unmarshal(c, &back); err != nil {
			t.Fatalf("canonical is not JSON: %v: %s", err, c)
		}
		if back.LogID != logID || back.Timestamp != ts || back.TreeSize != size {
			t.Fatalf("canonical does not round-trip: %s", c)
		}
		if s.Validate() == nil {
			if _, err := ParseCanonical(c); err != nil {
				t.Fatalf("ParseCanonical rejects a valid canonical: %v", err)
			}
		}
	})
}

// FuzzParseCanonical: arbitrary bytes never panic, and anything accepted
// re-encodes to exactly the input.
func FuzzParseCanonical(f *testing.F) {
	s := New("log", 7, merkle.EmptyRoot(), time.Unix(0, 0))
	c, _ := s.Canonical()
	f.Add(c)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseCanonical(data)
		if err != nil {
			return
		}
		re, err := got.Canonical()
		if err != nil || !bytes.Equal(re, data) {
			t.Fatal("accepted a non-canonical input")
		}
	})
}

// FuzzVerify: arbitrary STH fields and signatures never panic.
func FuzzVerify(f *testing.F) {
	key := testKey(f)
	pub := key.Public().(ed25519.PublicKey)
	s, _ := Sign(New("log", 1, merkle.EmptyRoot(), time.Unix(0, 0)), key)
	f.Add(s.LogID, s.TreeSize, s.RootHash, s.Timestamp, s.Signature)
	f.Fuzz(func(t *testing.T, logID string, size uint64, root, ts, sig string) {
		_ = Verify(STH{V: 1, LogID: logID, TreeSize: size, RootHash: root, Timestamp: ts, Signature: sig}, pub)
	})
}

// Every Ed25519 vector of the verifiable-receipts conformance corpus
// (ed25519-*.json) through VerifyBytes, with the fixture's key as it is,
// weak or not: tree heads and cosignatures are checked under the strict
// profile of VAOS 2.0 section 7.3, with the verifiers' reasons.
func TestVerifyBytesStrictEd25519Fixtures(t *testing.T) {
	files, _ := filepath.Glob("../../testdata/conformance/fixtures/ed25519-*.json")
	if len(files) < 20 {
		t.Fatalf("found %d ed25519 fixtures", len(files))
	}
	for _, f := range files {
		name := filepath.Base(f)
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var fx struct {
			PublicKeyPem string `json:"publicKeyPem"`
			Receipt      struct {
				Canonical string `json:"canonical"`
				Signature string `json:"signature"`
			} `json:"receipt"`
			Ed25519 struct {
				PublicKey, Message, Signature string
			} `json:"ed25519"`
			Expected struct {
				OK             bool   `json:"ok"`
				ReasonContains string `json:"reasonContains"`
			} `json:"expected"`
		}
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		var pub ed25519.PublicKey
		var msg []byte
		var wire string
		if fx.PublicKeyPem != "" {
			block, _ := pem.Decode([]byte(fx.PublicKeyPem))
			k, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			pub, msg, wire = k.(ed25519.PublicKey), []byte(fx.Receipt.Canonical), fx.Receipt.Signature
		} else {
			p, _ := hex.DecodeString(fx.Ed25519.PublicKey)
			m, _ := hex.DecodeString(fx.Ed25519.Message)
			sig, _ := hex.DecodeString(fx.Ed25519.Signature)
			pub, msg, wire = p, m, EncodeSignature(sig)
		}
		err = VerifyBytes(msg, wire, pub)
		if (err == nil) != fx.Expected.OK {
			t.Errorf("%s: %v, want ok=%v", name, err, fx.Expected.OK)
			continue
		}
		if err != nil && (!errors.Is(err, ErrSignature) || !strings.Contains(err.Error(), fx.Expected.ReasonContains)) {
			t.Errorf("%s: %v, want ErrSignature with %q", name, err, fx.Expected.ReasonContains)
		}
	}
}

// R = identity with S = k*a: crypto/ed25519 accepts it, VerifyBytes does
// not, so neither does Verify for a tree head.
func TestVerifyRefusesIdentityR(t *testing.T) {
	key := testKey(t)
	pub := key.Public().(ed25519.PublicKey)
	s := New("log", 1, merkle.EmptyRoot(), time.Now())
	c, _ := s.Canonical()
	sig := testutil.IdentityRSignature(key, c)
	if !ed25519.Verify(pub, c, sig) {
		t.Fatal("crypto/ed25519 rejects the identity-R signature; the test is broken")
	}
	s.Signature = EncodeSignature(sig)
	if err := Verify(s, pub); !errors.Is(err, ErrSignature) || !strings.Contains(err.Error(), "signature R is a small-order point") {
		t.Fatalf("Verify: %v", err)
	}
}

// SignBytes, and so Sign, refuse a key whose public half does not match
// its seed or is not a point of order L.
func TestSignRefusesInconsistentOrWeakKeys(t *testing.T) {
	good := testKey(t)
	other := testKey(t)
	mismatched := append(append(ed25519.PrivateKey{}, good.Seed()...), other.Public().(ed25519.PublicKey)...)
	identity := append(append(ed25519.PrivateKey{}, good.Seed()...), append([]byte{1}, make([]byte, 31)...)...)
	for name, c := range map[string]struct {
		key    ed25519.PrivateKey
		reason string
	}{
		"mismatched public half": {mismatched, "signature does not verify under the supplied public key"},
		"identity public half":   {identity, "public key is a small-order point"},
		"short":                  {good[:10], "not an Ed25519 private key"},
	} {
		if _, err := SignBytes([]byte("m"), c.key); !errors.Is(err, ErrSignature) || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: SignBytes: %v, want %q", name, err, c.reason)
		}
		if _, err := Sign(New("log", 0, merkle.EmptyRoot(), time.Now()), c.key); err == nil {
			t.Errorf("%s: Sign accepted the key", name)
		}
	}
	if _, err := SignBytes([]byte("m"), good); err != nil {
		t.Fatal(err)
	}
}
