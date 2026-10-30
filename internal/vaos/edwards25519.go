// Copied from github.com/christiaan839-beep/verifiable-receipts,
// packages/verifiable-receipts-go/edwards25519.go at commit
// f41348eac297c81e1c2a0dca91b7bd49dd2a5d9a (Apache-2.0, Copyright 2026
// Christiaan de Wet / Sovereign Matrix). Changed: this notice added; the
// code below is otherwise unchanged. See internal/vaos/README.md.

package vaos

import (
	"math/big"
)

// Point arithmetic on edwards25519 (RFC 8032), for the strict Ed25519
// checks of VAOS 2.0 section 7.3.
//
// math/big, written for correctness, not speed or constant time: every
// input it sees (a public key, a signature's R) is public. The
// TypeScript (src/edwards25519.ts, conformance/verify-v2.mjs) and
// Python (edwards25519.py) verifiers carry the same code with the same
// constants. The standard library's crypto/internal/edwards25519 is not
// importable, and the module takes no dependencies.
//
// Points are in extended coordinates (X, Y, Z, T), with x = X/Z,
// y = Y/Z and x*y = T/Z, and are added with the formulas of RFC 8032
// section 5.1.4, which are complete on this curve: they also double,
// and they take the identity and points of small order.

var (
	// edP is the field prime 2^255 - 19.
	edP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	// edL is the order of the base point, 2^252 + 27742317777372353535851937790883648493.
	edL = func() *big.Int {
		c, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
		return c.Add(c, new(big.Int).Lsh(big.NewInt(1), 252))
	}()
	// edD is the curve constant -121665/121666.
	edD = edMod(new(big.Int).Mul(big.NewInt(-121665), edInv(big.NewInt(121666))))
	// edSqrtM1 is a square root of -1 mod p.
	edSqrtM1 = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(edP, big.NewInt(1)), 2), edP)
	// edBaseY is 4/5, the y of the base point.
	edBaseY = edMod(new(big.Int).Mul(big.NewInt(4), edInv(big.NewInt(5))))
	// edBase is the base point B.
	edBase = func() edPoint {
		x, _ := edRecoverX(edXSquared(edBaseY), 0)
		return edPoint{x, new(big.Int).Set(edBaseY), big.NewInt(1), edMod(new(big.Int).Mul(x, edBaseY))}
	}()
)

// Why an encoding is refused; the verifiers prefix "public key is " or
// "signature R is ".
const (
	edNotCanonical  = "not a canonical encoding"
	edNotOnCurve    = "not a point on the curve"
	edSmallOrder    = "a small-order point"
	edNotInSubgroup = "not in the prime-order subgroup"
)

// edPoint is a point in extended coordinates. Its values are never
// modified once made.
type edPoint struct{ X, Y, Z, T *big.Int }

func edIdentity() edPoint {
	return edPoint{big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)}
}

// edMod reduces a into [0, p), in place, and returns it.
func edMod(a *big.Int) *big.Int { return a.Mod(a, edP) }

func edMul(a, b *big.Int) *big.Int { return edMod(new(big.Int).Mul(a, b)) }

func edInv(a *big.Int) *big.Int {
	return new(big.Int).Exp(edMod(new(big.Int).Set(a)), new(big.Int).Sub(edP, big.NewInt(2)), edP)
}

// edAdd is p + q (RFC 8032 section 5.1.4); also p + p.
func edAdd(p, q edPoint) edPoint {
	a := edMul(new(big.Int).Sub(p.Y, p.X), new(big.Int).Sub(q.Y, q.X))
	b := edMul(new(big.Int).Add(p.Y, p.X), new(big.Int).Add(q.Y, q.X))
	c := edMul(edMul(new(big.Int).Lsh(p.T, 1), q.T), edD)
	d := edMul(new(big.Int).Lsh(p.Z, 1), q.Z)
	e := new(big.Int).Sub(b, a)
	f := new(big.Int).Sub(d, c)
	g := new(big.Int).Add(d, c)
	h := new(big.Int).Add(b, a)
	return edPoint{edMul(e, f), edMul(g, h), edMul(f, g), edMul(e, h)}
}

// edScalarMult is [k]p for k >= 0, by double-and-add from the top bit.
func edScalarMult(k *big.Int, p edPoint) edPoint {
	q := edIdentity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		q = edAdd(q, q)
		if k.Bit(i) == 1 {
			q = edAdd(q, p)
		}
	}
	return q
}

// edIsIdentity reports whether p is the identity (0, 1).
func edIsIdentity(p edPoint) bool {
	return edMod(new(big.Int).Set(p.X)).Sign() == 0 && edMod(new(big.Int).Sub(p.Y, p.Z)).Sign() == 0
}

// edPointsEqual reports whether p and q are the same point.
func edPointsEqual(p, q edPoint) bool {
	return edMod(new(big.Int).Sub(new(big.Int).Mul(p.X, q.Z), new(big.Int).Mul(q.X, p.Z))).Sign() == 0 &&
		edMod(new(big.Int).Sub(new(big.Int).Mul(p.Y, q.Z), new(big.Int).Mul(q.Y, p.Z))).Sign() == 0
}

// edIsOnCurve reports whether p satisfies -x^2 + y^2 = 1 + d x^2 y^2,
// with x*y = T/Z.
func edIsOnCurve(p edPoint) bool {
	x2, y2, z2 := edMul(p.X, p.X), edMul(p.Y, p.Y), edMul(p.Z, p.Z)
	lhs := new(big.Int).Sub(y2, x2)
	lhs.Sub(lhs, z2).Sub(lhs, edMul(edD, edMul(p.T, p.T)))
	return edMod(lhs).Sign() == 0 &&
		edMod(new(big.Int).Sub(new(big.Int).Mul(p.X, p.Y), new(big.Int).Mul(p.Z, p.T))).Sign() == 0
}

// edXSquared is (y^2 - 1) / (d y^2 + 1).
func edXSquared(y *big.Int) *big.Int {
	y2 := edMul(y, y)
	return edMul(new(big.Int).Sub(y2, big.NewInt(1)), edInv(new(big.Int).Add(edMul(edD, y2), big.NewInt(1))))
}

// edRecoverX is the x with x^2 = x2 = edXSquared(y) and this sign (RFC
// 8032 section 5.1.3); ok is false when there is none.
func edRecoverX(x2 *big.Int, sign uint) (x *big.Int, ok bool) {
	if x2.Sign() == 0 {
		return big.NewInt(0), sign == 0
	}
	exp := new(big.Int).Rsh(new(big.Int).Add(edP, big.NewInt(3)), 3)
	x = new(big.Int).Exp(x2, exp, edP)
	if edMul(x, x).Cmp(x2) != 0 {
		x = edMul(x, edSqrtM1)
	}
	if edMul(x, x).Cmp(x2) != 0 {
		return nil, false
	}
	if x.Bit(0) != sign {
		x = new(big.Int).Sub(edP, x)
	}
	return x, true
}

// littleEndianInt reads b as a little-endian unsigned integer.
func littleEndianInt(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}

// edDecode decodes a 32-byte encoding (RFC 8032 section 5.1.3). The
// problem is edNotCanonical for a y of p or more, x = 0 with the sign
// bit set or a length other than 32, edNotOnCurve for a y with no x on
// the curve, and "" when the point decodes.
func edDecode(data []byte) (edPoint, string) {
	if len(data) != 32 {
		return edPoint{}, edNotCanonical
	}
	n := littleEndianInt(data)
	sign := n.Bit(255)
	y := n.SetBit(n, 255, 0)
	if y.Cmp(edP) >= 0 {
		return edPoint{}, edNotCanonical
	}
	x2 := edXSquared(y)
	if x2.Sign() == 0 && sign == 1 {
		return edPoint{}, edNotCanonical
	}
	x, ok := edRecoverX(x2, sign)
	if !ok {
		return edPoint{}, edNotOnCurve
	}
	return edPoint{x, y, big.NewInt(1), edMul(x, y)}, ""
}

// edEncode is the canonical 32-byte encoding of p (RFC 8032 section 5.1.2).
func edEncode(p edPoint) []byte {
	zi := edInv(p.Z)
	x, y := edMul(p.X, zi), edMul(p.Y, zi)
	be := y.FillBytes(make([]byte, 32))
	out := make([]byte, 32)
	for i := range be {
		out[i] = be[31-i]
	}
	out[31] |= byte(x.Bit(0) << 7)
	return out
}

// edHasSmallOrder reports whether [8]p is the identity: p is one of the
// 8 points of small order.
func edHasSmallOrder(p edPoint) bool { return edIsIdentity(edScalarMult(big.NewInt(8), p)) }

// edInPrimeOrderSubgroup reports whether [L]p is the identity: p has no
// small-order component.
func edInPrimeOrderSubgroup(p edPoint) bool { return edIsIdentity(edScalarMult(edL, p)) }

// edPointProblem says why an encoding is not a point of order L, or
// returns "". In order: edNotCanonical, edNotOnCurve, edSmallOrder (the
// identity included), edNotInSubgroup (a mixed-order point).
func edPointProblem(data []byte) string {
	p, problem := edDecode(data)
	if problem != "" {
		return problem
	}
	if edHasSmallOrder(p) {
		return edSmallOrder
	}
	if !edInPrimeOrderSubgroup(p) {
		return edNotInSubgroup
	}
	return ""
}
