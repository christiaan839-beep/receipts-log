// Copied from github.com/christiaan839-beep/verifiable-receipts,
// packages/verifiable-receipts-go/key_test.go at commit
// f41348eac297c81e1c2a0dca91b7bd49dd2a5d9a (Apache-2.0, Copyright 2026
// Christiaan de Wet / Sovereign Matrix). Changed: this notice added; the
// code below is otherwise unchanged. See internal/vaos/README.md.

package vaos

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
)

// VAOS 2.0 section 7.3: a public key that is a point of small order, or
// a non-canonical encoding, is refused when it is loaded and when it is
// used.

// keyFromY is the little-endian encoding of y, sign bit clear.
func keyFromY(y *big.Int) []byte {
	be := y.FillBytes(make([]byte, 32))
	out := make([]byte, 32)
	for i := range be {
		out[i] = be[31-i]
	}
	return out
}

func weakKeys() map[string]struct {
	raw    []byte
	reason string
} {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	identity := keyFromY(big.NewInt(1))
	signBit := append([]byte(nil), identity...)
	signBit[31] |= 0x80
	return map[string]struct {
		raw    []byte
		reason string
	}{
		"identity":          {identity, "public key is a small-order point"},
		"identity-sign-bit": {signBit, "public key is a small-order point"},
		"y=p+1":             {keyFromY(new(big.Int).Add(p, big.NewInt(1))), "public key is a small-order point"},
		"y=p+3":             {keyFromY(new(big.Int).Add(p, big.NewInt(3))), "public key is not a canonical encoding"},
	}
}

func pemOf(t *testing.T, raw []byte) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(raw))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestWeakKeys_RefusedWhenLoadedAndWhenUsed(t *testing.T) {
	// Under the identity key this signature verifies every message.
	universal := "v2=" + base64.StdEncoding.EncodeToString(append(keyFromY(big.NewInt(1)), make([]byte, 32)...))
	for name, k := range weakKeys() {
		if _, err := LoadEd25519PublicKeyFromPEM(pemOf(t, k.raw)); err == nil || err.Error() != "vaos: "+k.reason {
			t.Fatalf("%s: load: got %v", name, err)
		}
		got := VerifyV2Receipt(Receipt{Canonical: `{"a":1}`, Signature: universal}, ed25519.PublicKey(k.raw))
		if got.OK || got.Reason != k.reason {
			t.Fatalf("%s: verify: got %+v", name, got)
		}
	}
}

func TestWeakKeys_AcceptsAValidKey(t *testing.T) {
	pub, priv, pemBytes := makeKeyPair(t)
	if _, err := LoadEd25519PublicKeyFromPEM(pemBytes); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := VerifyV2Receipt(Receipt{Canonical: `{"a":1}`, Signature: signV2(priv, `{"a":1}`)}, pub); !got.OK {
		t.Fatalf("verify: %+v", got)
	}
}
