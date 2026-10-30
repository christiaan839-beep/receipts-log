package translog

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/christiaan839-beep/receipts-log/internal/sth"
	"github.com/christiaan839-beep/receipts-log/internal/testutil"
)

// VAOS 2.0 section 7.3: an Ed25519 public key that is not a canonical
// encoding of a point of order L is refused: of small order, a
// non-canonical encoding, off the curve, or of mixed order. Under the
// identity key one signature verifies every message, so a log configured
// with it would admit anything; under a key of mixed order verifiers
// disagree.

// weakKey returns the 32-byte key whose first byte is first, whose last
// is last and whose other bytes are fill.
func weakKey(first, fill, last byte) ed25519.PublicKey {
	k := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range k {
		k[i] = fill
	}
	k[0], k[31] = first, last
	return k
}

var weakKeys = map[string]struct {
	key    ed25519.PublicKey
	reason string
}{
	"identity":       {weakKey(0x01, 0x00, 0x00), "public key is a small-order point"},
	"identity, sign": {weakKey(0x01, 0x00, 0x80), "public key is a small-order point"},
	"y = p + 3":      {weakKey(0xf0, 0xff, 0x7f), "public key is not a canonical encoding"},
	// The keys of ed25519-key-off-curve.json and ed25519-key-mixed-order-8.json.
	"y = 2, off the curve": {weakKey(0x02, 0x00, 0x00), "public key is not a point on the curve"},
	"mixed order":          {mustHexKey("1fbeffcfb79db7951f9b8741c150f5d3e944455794cda3e7c5b81a99ecec3c85"), "public key is not in the prime-order subgroup"},
}

func mustHexKey(h string) ed25519.PublicKey {
	k, err := hex.DecodeString(h)
	if err != nil || len(k) != ed25519.PublicKeySize {
		panic("bad key " + h)
	}
	return k
}

func TestOpenRefusesWeakIssuerKeys(t *testing.T) {
	for name, w := range weakKeys {
		e := newEnv(t)
		c := e.cfg()
		c.IssuerKeys = append(c.IssuerKeys, w.key)
		if l, err := Open(c); err == nil {
			l.Close()
			t.Errorf("%s: Open accepted the issuer key", name)
		} else if !strings.Contains(err.Error(), w.reason) {
			t.Errorf("%s: %v, want %q", name, err, w.reason)
		}
	}
}

func TestOpenRefusesWeakWitnessKeys(t *testing.T) {
	for name, w := range weakKeys {
		e := newEnv(t)
		c := e.cfg()
		c.WitnessKeys["weak"] = w.key
		if l, err := Open(c); err == nil {
			l.Close()
			t.Errorf("%s: Open accepted the witness key", name)
		} else if !strings.Contains(err.Error(), w.reason) {
			t.Errorf("%s: %v, want %q", name, err, w.reason)
		}
	}
}

func TestCheckRefusesWeakIssuerKeys(t *testing.T) {
	e := newEnv(t)
	e.open(t).Close()
	for name, w := range weakKeys {
		if _, err := Check(e.dir, "test-log", e.logKey.Public().(ed25519.PublicKey),
			CheckOptions{IssuerKeys: []ed25519.PublicKey{w.key}}); err == nil || !strings.Contains(err.Error(), w.reason) {
			t.Errorf("%s: Check: %v, want %q", name, err, w.reason)
		}
	}
}

// The identity key with the signature R = identity, S = 0: Ed25519
// verification accepts it for every message.
func TestNoReceiptIsAdmittedUnderTheIdentityKey(t *testing.T) {
	identity := weakKeys["identity"].key
	universal := "v2=" + base64.StdEncoding.EncodeToString(append(append([]byte{}, identity...), make([]byte, 32)...))
	if !ed25519.Verify(identity, []byte("anything"), mustDecode(t, universal[3:])) {
		t.Fatal("the universal signature does not verify under the identity key; the test is broken")
	}
	body := []byte(`{"canonical":"{\"overall\":\"pass\"}","overall":"pass","signature":"` + universal + `"}`)

	e := newEnv(t)
	c := e.cfg()
	c.IssuerKeys = []ed25519.PublicKey{identity}
	if l, err := Open(c); err == nil {
		defer l.Close()
		if _, err := l.Append(body); err == nil {
			t.Error("the log admitted a receipt signed for every message under the identity key")
		}
	}
	// Admission's own check, below Open, refuses the key too.
	if _, _, err := verifyReceipt(body, []ed25519.PublicKey{identity}); err == nil ||
		!strings.Contains(err.Error(), "public key is a small-order point") {
		t.Errorf("verifyReceipt under the identity key: %v", err)
	}
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The log signing key's public half must match its seed and be a point
// of order L; strict verifiers would reject every tree head otherwise.
func TestOpenRefusesInconsistentOrWeakLogKey(t *testing.T) {
	e := newEnv(t)
	seed := e.logKey.Seed()
	for name, c := range map[string]struct {
		pub    ed25519.PublicKey
		reason string
	}{
		"another key's public half": {testutil.Key(t).Public().(ed25519.PublicKey), "does not match the seed"},
		"identity public half":      {weakKeys["identity"].key, "does not match the seed"},
	} {
		cfg := e.cfg()
		cfg.Key = append(append(ed25519.PrivateKey{}, seed...), c.pub...)
		if l, err := Open(cfg); err == nil {
			l.Close()
			t.Errorf("%s: Open accepted the log key", name)
		} else if !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: %v, want %q", name, err, c.reason)
		}
	}
}

// Check refuses a weak log public key as LoadPublicKey does.
func TestCheckRefusesWeakLogKey(t *testing.T) {
	e := newEnv(t)
	e.open(t).Close()
	for name, w := range weakKeys {
		if _, err := Check(e.dir, "test-log", w.key, CheckOptions{}); err == nil || !strings.Contains(err.Error(), w.reason) {
			t.Errorf("%s: Check: %v, want %q", name, err, w.reason)
		}
	}
}

// A cosignature whose R is the identity (S = k*a) passes crypto/ed25519
// but not the strict profile: 422 with the verifier's reason.
func TestCosignatureWithIdentityRIsRefused(t *testing.T) {
	e := newEnv(t)
	l := e.open(t)
	defer l.Close()
	l.Append(e.receipt(t, 0))
	c, _ := l.STH().Canonical()
	sig := testutil.IdentityRSignature(e.witness, c)
	if !ed25519.Verify(e.witness.Public().(ed25519.PublicKey), c, sig) {
		t.Fatal("crypto/ed25519 rejects the identity-R signature; the test is broken")
	}
	_, _, err := l.AddCosignature("w1", string(c), sth.EncodeSignature(sig), "")
	if !errors.Is(err, ErrWitnessSignature) || err.Error() != "witness signature does not verify: signature R is a small-order point" {
		t.Fatalf("AddCosignature: %v", err)
	}
	if got := l.Cosignatures(0, true); len(got) != 0 {
		t.Fatalf("recorded %+v", got)
	}
}

// A receipt whose R is the identity, signed by the configured issuer, is
// refused with the strict profile's reason.
func TestAppendRefusesIdentityR(t *testing.T) {
	e := newEnv(t)
	l := e.open(t)
	defer l.Close()
	canonical := `{"overall":"pass"}`
	sig := testutil.IdentityRSignature(e.issuer, []byte(canonical))
	body := []byte(`{"canonical":"{\"overall\":\"pass\"}","overall":"pass","signature":"v2=` +
		base64.StdEncoding.EncodeToString(sig) + `"}`)
	_, err := l.Append(body)
	if !errors.Is(err, ErrUnverified) || !strings.Contains(err.Error(), "signature R is a small-order point") {
		t.Fatalf("Append: %v", err)
	}
	if l.STH().TreeSize != 0 {
		t.Fatal("appended")
	}
}
