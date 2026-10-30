// Package testutil signs VAOS 2.0 receipts for tests, with keys made at
// run time. It mirrors sign_v2_receipt in the verifiable-receipts
// Python package: the canonical is compact JSON with keys sorted, the
// receipt is the body plus canonical, contentHash and signature.
package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
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

// IdentityRSignature returns a signature over msg under key whose R is
// the identity point (01 00 … 00) and whose S is k*a mod L, with a the
// key's secret scalar and k = SHA-512(R || A || msg) mod L. Then
// [S]B = R + [k]A, so crypto/ed25519's cofactorless check accepts it;
// the strict profile of VAOS 2.0 section 7.3 refuses it with "signature
// R is a small-order point".
func IdentityRSignature(key ed25519.PrivateKey, msg []byte) []byte {
	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	h := sha512.Sum512(key.Seed())
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	a := littleEndian(h[:32])
	r := make([]byte, 32)
	r[0] = 1
	kh := sha512.New()
	kh.Write(r)
	kh.Write(key.Public().(ed25519.PublicKey))
	kh.Write(msg)
	k := littleEndian(kh.Sum(nil))
	s := new(big.Int).Mul(k.Mod(k, l), a)
	s.Mod(s, l)
	be := s.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		be[i], be[j] = be[j], be[i]
	}
	return append(r, be...)
}

func littleEndian(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}
