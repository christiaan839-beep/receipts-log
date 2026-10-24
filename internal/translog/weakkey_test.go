package translog

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

// VAOS 2.0 section 7.3: an Ed25519 public key that is a point of small
// order, or a non-canonical encoding, is refused. Under the identity key
// one signature verifies every message, so a log configured with it would
// admit anything.

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
