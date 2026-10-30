// Copied from github.com/christiaan839-beep/verifiable-receipts,
// packages/verifiable-receipts-go/strict_ed25519_test.go at commit
// 4d9943a99376527f742dcfdf93652ed040a51b43 (Apache-2.0, Copyright 2026
// Christiaan de Wet / Sovereign Matrix). Changed: this notice added; the
// code below is otherwise unchanged. See internal/vaos/README.md.

package vaos

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// VAOS 2.0 section 7.3, the strict profile: before the signature reaches
// crypto/ed25519, R must be a canonical encoding of a point of order L
// (not of small order, the identity included, and in the prime-order
// subgroup), S must be below L, and the key must be a point of order L.
// Each rejection has its reason, the same in the TypeScript and Python
// verifiers.

const genericReason = "signature does not verify under the supplied public key"

var (
	aScalar = new(big.Int).Mod(mustInt("1234567890abcdef1234567890abcdef"), edL)
	rScalar = new(big.Int).Mod(mustInt("fedcba0987654321fedcba0987654321"), edL)
)

func mustInt(h string) *big.Int {
	n, _ := new(big.Int).SetString(h, 16)
	return n
}

func le32(n *big.Int) []byte {
	return keyFromY(new(big.Int).Set(n)) // little-endian, 32 bytes
}

func kOf(r, pub, msg []byte) *big.Int {
	h := sha512.New()
	h.Write(r)
	h.Write(pub)
	h.Write(msg)
	k := littleEndianInt(h.Sum(nil))
	return k.Mod(k, edL)
}

// sigWithR is (R, S = r + k*a) for a chosen R.
func sigWithR(rPoint edPoint, msg, pub []byte, r *big.Int) []byte {
	rEnc := edEncode(rPoint)
	s := new(big.Int).Mul(kOf(rEnc, pub, msg), aScalar)
	s.Add(s, r).Mod(s, edL)
	return append(rEnc, le32(s)...)
}

func strictPub() []byte { return edEncode(edScalarMult(aScalar, edBase)) }

func mixedPub(t *testing.T, torsionHex string) []byte {
	return edEncode(edAdd(edScalarMult(aScalar, edBase), mustPoint(t, torsionHex)))
}

// reasons is every Go entry point's reason for (pub, msg, sig).
func reasons(pub, msg, sig []byte) [2]string {
	r := Receipt{Canonical: string(msg), Signature: "v2=" + base64.StdEncoding.EncodeToString(sig)}
	return [2]string{VerifyEd25519(pub, msg, sig).Reason, VerifyV2Receipt(r, ed25519.PublicKey(pub)).Reason}
}

func both(s string) [2]string { return [2]string{s, s} }

var strictMsg = []byte(`{"a":1}`)

func TestStrict_AcceptsAnHonestSignature(t *testing.T) {
	pub := strictPub()
	sig := sigWithR(edScalarMult(rScalar, edBase), strictMsg, pub, rScalar)
	if got := VerifyEd25519(pub, strictMsg, sig); !got.OK {
		t.Fatalf("%+v", got)
	}
	if got := reasons(pub, strictMsg, sig); got != both("") {
		t.Fatalf("%q", got)
	}
}

func TestStrict_RejectsSmallAndMixedOrderR(t *testing.T) {
	pub := strictPub()
	zero := big.NewInt(0)
	for name, c := range map[string]struct {
		r      edPoint
		secret *big.Int
		reason string
	}{
		"identity": {edIdentity(), zero, "signature R is a small-order point"},
		"order 2":  {mustPoint(t, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), zero, "signature R is a small-order point"},
		"order 8":  {mustPoint(t, t8Hex), zero, "signature R is a small-order point"},
		"mixed":    {edAdd(edScalarMult(rScalar, edBase), mustPoint(t, t8Hex)), rScalar, "signature R is not in the prime-order subgroup"},
	} {
		sig := sigWithR(c.r, strictMsg, pub, c.secret)
		if got := Ed25519SignatureProblem(sig); got != c.reason {
			t.Fatalf("%s: problem %q", name, got)
		}
		if got := reasons(pub, strictMsg, sig); got != both(c.reason) {
			t.Fatalf("%s: %q", name, got)
		}
	}
}

func TestStrict_RejectsRIdentityThatTheLibraryAccepts(t *testing.T) {
	pub := strictPub()
	sig := sigWithR(edIdentity(), strictMsg, pub, big.NewInt(0))
	if !ed25519.Verify(pub, strictMsg, sig) {
		t.Fatal("crypto/ed25519 alone was expected to accept R = identity, S = k*a")
	}
	if got := reasons(pub, strictMsg, sig); got != both("signature R is a small-order point") {
		t.Fatalf("%q", got)
	}
}

func TestStrict_REncodingProblems(t *testing.T) {
	pub := strictPub()
	rEnc := fromY(new(big.Int).Add(edP, big.NewInt(1)), 0)
	s := new(big.Int).Mul(kOf(rEnc, pub, strictMsg), aScalar)
	nonCanonical := append(rEnc, le32(s.Mod(s, edL))...)
	if got := reasons(pub, strictMsg, nonCanonical); got != both("signature R is not a canonical encoding") {
		t.Fatalf("non-canonical: %q", got)
	}
	signBit := append(fromY(big.NewInt(1), 1), make([]byte, 32)...)
	if got := Ed25519SignatureProblem(signBit); got != "signature R is not a canonical encoding" {
		t.Fatalf("sign bit: %q", got)
	}
	offCurve := append(fromY(big.NewInt(2), 0), le32(rScalar)...)
	if got := reasons(pub, strictMsg, offCurve); got != both("signature R is not a point on the curve") {
		t.Fatalf("off curve: %q", got)
	}
}

func TestStrict_RejectsSOfLOrMore(t *testing.T) {
	pub := strictPub()
	sig := sigWithR(edScalarMult(rScalar, edBase), strictMsg, pub, rScalar)
	s := littleEndianInt(sig[32:])
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	for _, bad := range []*big.Int{new(big.Int).Add(s, edL), edL, max} {
		be := bad.FillBytes(make([]byte, 32))
		le := make([]byte, 32)
		for i := range be {
			le[i] = be[31-i]
		}
		tampered := append(append([]byte(nil), sig[:32]...), le...)
		if got := Ed25519SignatureProblem(tampered); got != genericReason {
			t.Fatalf("S = %v: %q", bad, got)
		}
		if got := reasons(pub, strictMsg, tampered); got != both(genericReason) {
			t.Fatalf("S = %v: %q", bad, got)
		}
	}
	if got := Ed25519SignatureProblem(sig); got != "" {
		t.Fatalf("honest: %q", got)
	}
	for _, n := range []int{0, 63, 65} {
		if got := Ed25519SignatureProblem(make([]byte, n)); got != genericReason {
			t.Fatalf("length %d: %q", n, got)
		}
		if got := VerifyEd25519(pub, strictMsg, make([]byte, n)).Reason; got != genericReason {
			t.Fatalf("length %d: %q", n, got)
		}
	}
}

func TestStrict_MixedOrderRWithTheCofactorlessEquationHolding(t *testing.T) {
	pub := mixedPub(t, t8Hex)
	t8 := mustPoint(t, t8Hex)
	for nonce := 0; nonce < 400; nonce++ {
		msg := []byte(fmt.Sprintf(`{"n":%d}`, nonce))
		for tt := int64(1); tt < 8; tt++ {
			rEnc := edEncode(edAdd(edScalarMult(rScalar, edBase), edScalarMult(big.NewInt(tt), t8)))
			k := kOf(rEnc, pub, msg)
			if new(big.Int).Mod(new(big.Int).Add(k, big.NewInt(tt)), big.NewInt(8)).Sign() != 0 {
				continue
			}
			s := new(big.Int).Mul(k, aScalar)
			s.Add(s, rScalar).Mod(s, edL)
			sig := append(rEnc, le32(s)...)
			if !ed25519.Verify(pub, msg, sig) {
				t.Fatal("crypto/ed25519 alone was expected to accept it")
			}
			if got := reasons(pub, msg, sig); got != both("public key is not in the prime-order subgroup") {
				t.Fatalf("%q", got)
			}
			if got := Ed25519SignatureProblem(sig); got != "signature R is not in the prime-order subgroup" {
				t.Fatalf("R alone: %q", got)
			}
			return
		}
	}
	t.Fatal("no message found")
}

func TestStrict_RefusesMixedOrderAndOffCurveKeys(t *testing.T) {
	for name, c := range map[string]struct {
		raw    []byte
		reason string
	}{
		"mixed T8":  {mixedPub(t, t8Hex), "public key is not in the prime-order subgroup"},
		"mixed T2":  {mixedPub(t, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), "public key is not in the prime-order subgroup"},
		"off curve": {fromY(big.NewInt(2), 0), "public key is not a point on the curve"},
	} {
		if got := Ed25519PublicKeyProblem(c.raw); got != c.reason {
			t.Fatalf("%s: %q", name, got)
		}
		if _, err := LoadEd25519PublicKeyFromPEM(pemOf(t, c.raw)); err == nil || err.Error() != "vaos: "+c.reason {
			t.Fatalf("%s: load: %v", name, err)
		}
		sig := sigWithR(edScalarMult(rScalar, edBase), strictMsg, c.raw, rScalar)
		if got := reasons(c.raw, strictMsg, sig); got != both(c.reason) {
			t.Fatalf("%s: %q", name, got)
		}
	}
}

func TestStrict_KeepsTheExistingKeyReasons(t *testing.T) {
	one := big.NewInt(1)
	for _, c := range []struct {
		raw    []byte
		reason string
	}{
		{fromY(one, 0), "public key is a small-order point"},
		{fromY(new(big.Int).Add(edP, one), 0), "public key is a small-order point"},
		{fromY(new(big.Int).Add(edP, big.NewInt(3)), 0), "public key is not a canonical encoding"},
		{mustHex(t, t8Hex), "public key is a small-order point"},
		{strictPub(), ""},
	} {
		if got := Ed25519PublicKeyProblem(c.raw); got != c.reason {
			t.Fatalf("%x: %q", c.raw, got)
		}
	}
	if got := VerifyEd25519(strictPub()[:31], strictMsg, make([]byte, 64)).Reason; got != "public key is not 32 bytes" {
		t.Fatalf("short key: %q", got)
	}
}

// Go's arguments are byte slices, so only nil and empty slices stand for
// the bad inputs the TypeScript and Python tests try: they fail without
// a panic, with the reasons of any wrong length.
func TestStrict_NilAndEmptyInputs(t *testing.T) {
	pub := strictPub()
	sig := sigWithR(edScalarMult(rScalar, edBase), strictMsg, pub, rScalar)
	for name, c := range map[string]struct {
		pub, msg, sig []byte
		reason        string
	}{
		"nil key":       {nil, strictMsg, sig, "public key is not 32 bytes"},
		"empty key":     {[]byte{}, strictMsg, sig, "public key is not 32 bytes"},
		"nil signature": {pub, strictMsg, nil, genericReason},
		"nil message":   {pub, nil, sig, genericReason},
	} {
		if got := VerifyEd25519(c.pub, c.msg, c.sig); got.OK || got.Reason != c.reason {
			t.Fatalf("%s: %+v", name, got)
		}
	}
}

// fixtureKeyAndSignature is an Ed25519 fixture's raw public key and
// signature: from its "ed25519" vector, or from its publicKeyPem (the
// last 32 bytes of the SPKI) and its receipt's v2 signature.
func fixtureKeyAndSignature(t *testing.T, path string) (pub, sig []byte, expected v2Expected) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Ed25519 *struct {
			PublicKey string `json:"publicKey"`
			Signature string `json:"signature"`
		} `json:"ed25519"`
		PublicKeyPem string `json:"publicKeyPem"`
		Receipt      struct {
			Signature string `json:"signature"`
		} `json:"receipt"`
		Expected v2Expected `json:"expected"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if f.Ed25519 != nil {
		return mustHex(t, f.Ed25519.PublicKey), mustHex(t, f.Ed25519.Signature), f.Expected
	}
	block, _ := pem.Decode([]byte(f.PublicKeyPem))
	if block == nil || len(block.Bytes) < 32 {
		t.Fatalf("%s: no public key", path)
	}
	sig, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(f.Receipt.Signature, "v2="))
	if err != nil {
		t.Fatal(err)
	}
	return block.Bytes[len(block.Bytes)-32:], sig, f.Expected
}

// The shared corpus through the two exported pre-checks: a fixture that
// fails on its key expects the key's reason; any other expects no key
// problem and, when it fails, the signature's reason. The TypeScript and
// Python tests check the same, and the round trip
// (conformance/roundtrip/) checks that the three languages give the same
// pair of answers on every fixture.
func TestStrict_ExportedPreChecksOnTheFixtures(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(fixturesDir, "ed25519-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 20 {
		t.Fatalf("want 20 Ed25519 fixtures, have %d", len(paths))
	}
	for _, path := range paths {
		t.Run(strings.TrimSuffix(filepath.Base(path), ".json"), func(t *testing.T) {
			pub, sig, expected := fixtureKeyAndSignature(t, path)
			want := expected.ReasonContains
			if expected.OK != (want == "") {
				t.Fatalf("fixture: ok %v with reason %q", expected.OK, want)
			}
			key := Ed25519PublicKeyProblem(pub)
			if strings.HasPrefix(want, "public key ") {
				if key != want {
					t.Fatalf("key: %q, want %q", key, want)
				}
			} else {
				if key != "" {
					t.Fatalf("key: %q, want none", key)
				}
				if got := Ed25519SignatureProblem(sig); got != want {
					t.Fatalf("signature: %q, want %q", got, want)
				}
			}
			// The same answers as VerifyEd25519, which calls them.
			first := key
			if first == "" {
				first = Ed25519SignatureProblem(sig)
			}
			if first != "" {
				if got := VerifyEd25519(pub, nil, sig).Reason; got != first {
					t.Fatalf("VerifyEd25519: %q, want %q", got, first)
				}
			}
		})
	}
}

// A key of the wrong length has its own reason, as in TypeScript and
// Python; nil and empty slices fail without a panic.
func TestStrict_ExportedPreChecksOnWrongLengths(t *testing.T) {
	pub := strictPub()
	sig := sigWithR(edScalarMult(rScalar, edBase), strictMsg, pub, rScalar)
	for _, k := range [][]byte{nil, ed25519.PublicKey(nil), {}, pub[:31], append(append([]byte(nil), pub...), 0)} {
		if got := Ed25519PublicKeyProblem(k); got != "public key is not 32 bytes" {
			t.Fatalf("key of %d bytes: %q", len(k), got)
		}
	}
	for _, s := range [][]byte{nil, {}, sig[:63], append(append([]byte(nil), sig...), 0)} {
		if got := Ed25519SignatureProblem(s); got != genericReason {
			t.Fatalf("signature of %d bytes: %q", len(s), got)
		}
	}
	if Ed25519PublicKeyProblem(pub) != "" || Ed25519SignatureProblem(sig) != "" {
		t.Fatal("an honest key and signature are refused")
	}
}
