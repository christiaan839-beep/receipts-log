// Package testutil signs VAOS 2.0 receipts for tests, with keys made at
// run time. It mirrors sign_v2_receipt in the verifiable-receipts
// Python package: the canonical is compact JSON with keys sorted, the
// receipt is the body plus canonical, contentHash and signature.
package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// Key returns a fresh Ed25519 key.
func Key(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Receipt signs body (whose keys must be ASCII) and returns the receipt
// JSON: the body's fields, canonical, contentHash and signature.
func Receipt(t testing.TB, key ed25519.PrivateKey, body map[string]any) []byte {
	t.Helper()
	canonical, err := json.Marshal(body) // map keys are sorted
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	out := map[string]any{}
	for k, v := range body {
		out[k] = v
	}
	out["canonical"] = string(canonical)
	out["contentHash"] = "sha256:" + hex.EncodeToString(sum[:])
	out["signature"] = "v2=" + base64.StdEncoding.EncodeToString(ed25519.Sign(key, canonical))
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
