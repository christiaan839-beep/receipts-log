// Copied from github.com/christiaan839-beep/verifiable-receipts,
// packages/verifiable-receipts-go/edwards25519_test.go at commit
// 4d9943a99376527f742dcfdf93652ed040a51b43 (Apache-2.0, Copyright 2026
// Christiaan de Wet / Sovereign Matrix). Changed: this notice added; the
// code below is otherwise unchanged. See internal/vaos/README.md.

package vaos

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

// The pure edwards25519 arithmetic behind the strict Ed25519 checks of
// VAOS 2.0 section 7.3: its constants against RFC 8032, decoding and
// encoding, and the order of points.

const (
	baseHex = "5866666666666666666666666666666666666666666666666666666666666666"
	t8Hex   = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
)

// torsion maps the encodings of the points of small order (sign bit
// clear) to their order.
var torsion = map[string]int{
	"0100000000000000000000000000000000000000000000000000000000000000": 1,
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": 2,
	"0000000000000000000000000000000000000000000000000000000000000000": 4,
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05": 8,
	t8Hex: 8,
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustPoint(t *testing.T, s string) edPoint {
	t.Helper()
	p, problem := edDecode(mustHex(t, s))
	if problem != "" {
		t.Fatalf("decode %s: %s", s, problem)
	}
	return p
}

// fromY is the little-endian encoding of y, with the sign bit set when sign is 1.
func fromY(y *big.Int, sign uint) []byte {
	out := keyFromY(new(big.Int).Mod(y, new(big.Int).Lsh(big.NewInt(1), 255)))
	out[31] |= byte(sign << 7)
	return out
}

func smallOrder(p edPoint) int {
	for _, n := range []int64{1, 2, 4, 8} {
		if edIsIdentity(edScalarMult(big.NewInt(n), p)) {
			return int(n)
		}
	}
	return 0
}

// scalarStream is a deterministic stream of scalars in [1, L).
func scalarStream(seed string, count int) []*big.Int {
	out := make([]*big.Int, count)
	lm1 := new(big.Int).Sub(edL, big.NewInt(1))
	for i := range out {
		h := sha512.Sum512([]byte(fmt.Sprintf("%s %d", seed, i)))
		k := new(big.Int).SetBytes(h[:])
		out[i] = k.Mod(k, lm1).Add(k, big.NewInt(1))
	}
	return out
}

func TestEdwards25519_ConstantsMatchRFC8032(t *testing.T) {
	wantP := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	if edP.Cmp(wantP) != 0 {
		t.Fatalf("p = %v", edP)
	}
	wantL, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	if edL.Cmp(wantL) != 0 {
		t.Fatalf("L = %v", edL)
	}
	wantD, _ := new(big.Int).SetString("37095705934669439343138083508754565189542113879843219016388785533085940283555", 10)
	if edD.Cmp(wantD) != 0 {
		t.Fatalf("d = %v", edD)
	}
	// d = -121665 / 121666.
	check := new(big.Int).Mul(edD, big.NewInt(121666))
	check.Add(check, big.NewInt(121665)).Mod(check, edP)
	if check.Sign() != 0 {
		t.Fatal("d * 121666 != -121665")
	}
	sq := new(big.Int).Mul(edSqrtM1, edSqrtM1)
	if sq.Mod(sq, edP).Cmp(new(big.Int).Sub(edP, big.NewInt(1))) != 0 {
		t.Fatal("sqrt(-1)^2 != -1")
	}
	// y of B = 4/5.
	y := new(big.Int).Mul(edBaseY, big.NewInt(5))
	if y.Mod(y, edP).Cmp(big.NewInt(4)) != 0 {
		t.Fatal("5 * y(B) != 4")
	}
	if got := hex.EncodeToString(edEncode(edBase)); got != baseHex {
		t.Fatalf("encode(B) = %s", got)
	}
}

func TestEdwards25519_BaseHasOrderL(t *testing.T) {
	if !edIsOnCurve(edBase) || edIsIdentity(edBase) {
		t.Fatal("B")
	}
	if !edIsIdentity(edScalarMult(edL, edBase)) {
		t.Fatal("[L]B != O")
	}
	if edIsIdentity(edScalarMult(new(big.Int).Sub(edL, big.NewInt(1)), edBase)) {
		t.Fatal("[L-1]B == O")
	}
	if got := hex.EncodeToString(edEncode(edScalarMult(new(big.Int).Add(edL, big.NewInt(1)), edBase))); got != baseHex {
		t.Fatalf("[L+1]B = %s", got)
	}
}

func TestEdwards25519_RFC8032Test1PublicKey(t *testing.T) {
	h := sha512.Sum512(mustHex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
	a := littleEndianInt(h[:32])
	a.And(a, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 254), big.NewInt(8)))
	a.SetBit(a, 254, 1)
	if got := hex.EncodeToString(edEncode(edScalarMult(a, edBase))); got != "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" {
		t.Fatalf("public key = %s", got)
	}
}

func TestEdwards25519_TorsionPoints(t *testing.T) {
	for h, n := range torsion {
		p := mustPoint(t, h)
		if got := smallOrder(p); got != n {
			t.Fatalf("%s: order %d, want %d", h, got, n)
		}
		if !edIsIdentity(edScalarMult(big.NewInt(8), p)) || !edHasSmallOrder(p) {
			t.Fatalf("%s: [8]T != O", h)
		}
		if edInPrimeOrderSubgroup(p) != (n == 1) {
			t.Fatalf("%s: subgroup", h)
		}
		if got := edPointProblem(mustHex(t, h)); got != edSmallOrder {
			t.Fatalf("%s: problem %q", h, got)
		}
	}
}

func TestEdwards25519_EncodeDecodeRoundTrip(t *testing.T) {
	for _, k := range scalarStream("round trip", 48) {
		p := edScalarMult(k, edBase)
		data := edEncode(p)
		back, problem := edDecode(data)
		if problem != "" {
			t.Fatalf("decode: %s", problem)
		}
		if !bytes.Equal(edEncode(back), data) || !edPointsEqual(back, p) {
			t.Fatal("round trip")
		}
		if !edInPrimeOrderSubgroup(back) || edHasSmallOrder(back) || edPointProblem(data) != "" {
			t.Fatal("order")
		}
	}
}

func TestEdwards25519_MixedOrder(t *testing.T) {
	mixed := edAdd(edScalarMult(big.NewInt(12345), edBase), mustPoint(t, t8Hex))
	if edHasSmallOrder(mixed) || edInPrimeOrderSubgroup(mixed) {
		t.Fatal("mixed-order point")
	}
	if !edInPrimeOrderSubgroup(edScalarMult(big.NewInt(8), mixed)) {
		t.Fatal("[8] does not clear the small-order component")
	}
	if got := edPointProblem(edEncode(mixed)); got != edNotInSubgroup {
		t.Fatalf("problem %q", got)
	}
}

func TestEdwards25519_DecodeRefusesNonCanonical(t *testing.T) {
	one := big.NewInt(1)
	pm1 := new(big.Int).Sub(edP, one)
	for name, data := range map[string][]byte{
		"y=p":        fromY(edP, 0),
		"y=p+1":      fromY(new(big.Int).Add(edP, one), 0),
		"y=2^255-1":  fromY(new(big.Int).Sub(new(big.Int).Lsh(one, 255), one), 0),
		"y=1,sign":   fromY(one, 1),
		"y=p-1,sign": fromY(pm1, 1),
		"length 0":   {},
		"length 31":  make([]byte, 31),
		"length 33":  make([]byte, 33),
		"length 64":  make([]byte, 64),
	} {
		if _, problem := edDecode(data); problem != edNotCanonical {
			t.Fatalf("%s: %q", name, problem)
		}
	}
	for _, y := range []*big.Int{one, pm1} {
		if _, problem := edDecode(fromY(y, 0)); problem != "" {
			t.Fatalf("y=%v: %q", y, problem)
		}
	}
}

func TestEdwards25519_DecodeRefusesPointsOffTheCurve(t *testing.T) {
	if _, problem := edDecode(fromY(big.NewInt(2), 0)); problem != edNotOnCurve {
		t.Fatalf("y=2: %q", problem)
	}
	if got := edPointProblem(fromY(big.NewInt(2), 0)); got != edNotOnCurve {
		t.Fatalf("y=2 problem: %q", got)
	}
	off := 0
	for _, y := range scalarStream("off curve", 200) {
		p, problem := edDecode(fromY(y, 0))
		if problem == edNotOnCurve {
			off++
		} else if problem != "" || !edIsOnCurve(p) {
			t.Fatalf("y=%v: %q", y, problem)
		}
	}
	if off <= 60 || off >= 140 {
		t.Fatalf("%d of 200 off the curve", off)
	}
}
