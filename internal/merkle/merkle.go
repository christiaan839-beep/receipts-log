// Package merkle implements the RFC 6962 / RFC 9162 Merkle tree used by
// the verifiable-receipts transparency log: leaf and node hashing with
// the 0x00 / 0x01 domain separators, tree heads, inclusion proofs and
// consistency proofs, and their verifiers.
//
// The proof shapes are the ones the verifiable-receipts TypeScript,
// Go and Python packages produce and verify: an inclusion proof is the
// RFC 9162 §2.1.3 audit path, ordered from the leaf up, and a
// consistency proof is the RFC 9162 §2.1.4 path.
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"strings"
)

// HashSize is the size of every hash in the tree.
const HashSize = sha256.Size

// Hash is a SHA-256 digest: a leaf hash, a node hash or a tree root.
type Hash [HashSize]byte

// String returns the lowercase hex encoding of h.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// ParseHash decodes a hash written as exactly 64 lowercase hex digits,
// the one spelling every verifier accepts (transparency-log spec §3.6).
func ParseHash(s string) (Hash, error) {
	var h Hash
	if len(s) != 2*HashSize {
		return h, fmt.Errorf("merkle: hash must be %d hex characters, got %d", 2*HashSize, len(s))
	}
	if strings.ToLower(s) != s {
		return h, errors.New("merkle: hash must be lowercase hex")
	}
	if _, err := hex.Decode(h[:], []byte(s)); err != nil {
		return h, errors.New("merkle: hash is not valid hex")
	}
	return h, nil
}

// ParseHashes decodes a list of hex hashes.
func ParseHashes(list []string) ([]Hash, error) {
	out := make([]Hash, len(list))
	for i, s := range list {
		h, err := ParseHash(s)
		if err != nil {
			return nil, fmt.Errorf("element %d: %w", i, err)
		}
		out[i] = h
	}
	return out, nil
}

// HexHashes encodes a list of hashes as lowercase hex strings. A nil or
// empty list encodes as an empty, non-nil slice so it marshals as [].
func HexHashes(list []Hash) []string {
	out := make([]string, len(list))
	for i, h := range list {
		out[i] = h.String()
	}
	return out
}

// LeafHash returns SHA-256(0x00 || data) (RFC 6962 §2.1).
func LeafHash(data []byte) Hash {
	d := sha256.New()
	d.Write([]byte{0x00})
	d.Write(data)
	var h Hash
	d.Sum(h[:0])
	return h
}

// NodeHash returns SHA-256(0x01 || left || right) (RFC 6962 §2.1).
func NodeHash(left, right Hash) Hash {
	var buf [1 + 2*HashSize]byte
	buf[0] = 0x01
	copy(buf[1:], left[:])
	copy(buf[1+HashSize:], right[:])
	return sha256.Sum256(buf[:])
}

// EmptyRoot is the root of the empty tree: SHA-256 of the empty string.
func EmptyRoot() Hash { return sha256.Sum256(nil) }

// splitPoint returns the largest power of two strictly less than n.
// It requires n >= 2.
func splitPoint(n uint64) uint64 {
	return uint64(1) << (bits.Len64(n-1) - 1)
}

// ErrSize is returned when a requested index or size is outside the tree.
var ErrSize = errors.New("merkle: index or size out of range")

// Tree is an append-only Merkle tree held in memory. It stores every
// complete, aligned subtree hash (about 2n hashes for n leaves), so a
// root or proof at any size costs O(log² n) node hashes at most.
//
// A Tree is not safe for concurrent use; callers hold their own lock.
type Tree struct {
	// levels[k][i] is the hash of leaves [i·2^k, (i+1)·2^k).
	levels [][]Hash
}

// Size returns the number of leaves.
func (t *Tree) Size() uint64 {
	if len(t.levels) == 0 {
		return 0
	}
	return uint64(len(t.levels[0]))
}

// Append adds a leaf hash and returns its index.
func (t *Tree) Append(leaf Hash) uint64 {
	if len(t.levels) == 0 {
		t.levels = append(t.levels, nil)
	}
	t.levels[0] = append(t.levels[0], leaf)
	for k := 0; len(t.levels[k])%2 == 0; k++ {
		if k+1 == len(t.levels) {
			t.levels = append(t.levels, nil)
		}
		n := len(t.levels[k])
		t.levels[k+1] = append(t.levels[k+1], NodeHash(t.levels[k][n-2], t.levels[k][n-1]))
	}
	return uint64(len(t.levels[0])) - 1
}

// Leaf returns the leaf hash at index i.
func (t *Tree) Leaf(i uint64) (Hash, error) {
	if i >= t.Size() {
		return Hash{}, ErrSize
	}
	return t.levels[0][i], nil
}

// subtree returns MTH(D[lo:hi]) for 0 <= lo < hi <= Size().
func (t *Tree) subtree(lo, hi uint64) Hash {
	n := hi - lo
	if n&(n-1) == 0 {
		k := bits.TrailingZeros64(n)
		if lo%n == 0 && k < len(t.levels) && lo>>k < uint64(len(t.levels[k])) {
			return t.levels[k][lo>>k]
		}
	}
	k := splitPoint(n)
	return NodeHash(t.subtree(lo, lo+k), t.subtree(lo+k, hi))
}

// Root returns the root of the tree at its current size.
func (t *Tree) Root() Hash {
	r, _ := t.RootAt(t.Size())
	return r
}

// RootAt returns the root of the tree formed by the first n leaves.
func (t *Tree) RootAt(n uint64) (Hash, error) {
	if n > t.Size() {
		return Hash{}, ErrSize
	}
	if n == 0 {
		return EmptyRoot(), nil
	}
	return t.subtree(0, n), nil
}

// InclusionProof returns the audit path for leaf index in the tree of
// the given size (RFC 9162 §2.1.3.1).
func (t *Tree) InclusionProof(index, size uint64) ([]Hash, error) {
	if size > t.Size() || index >= size {
		return nil, ErrSize
	}
	return t.path(index, 0, size, make([]Hash, 0, bits.Len64(size))), nil
}

func (t *Tree) path(m, lo, hi uint64, out []Hash) []Hash {
	n := hi - lo
	if n == 1 {
		return out
	}
	k := splitPoint(n)
	if m < k {
		out = t.path(m, lo, lo+k, out)
		return append(out, t.subtree(lo+k, hi))
	}
	out = t.path(m-k, lo+k, hi, out)
	return append(out, t.subtree(lo, lo+k))
}

// ConsistencyProof returns the proof that the tree of size second
// extends the tree of size first (RFC 9162 §2.1.4.1). The proof is
// empty when first is 0 or first equals second.
func (t *Tree) ConsistencyProof(first, second uint64) ([]Hash, error) {
	if second > t.Size() || first > second {
		return nil, ErrSize
	}
	if first == 0 || first == second {
		return []Hash{}, nil
	}
	return t.subproof(first, 0, second, true, make([]Hash, 0, 2*bits.Len64(second))), nil
}

func (t *Tree) subproof(m, lo, hi uint64, whole bool, out []Hash) []Hash {
	n := hi - lo
	if m == n {
		if whole {
			return out
		}
		return append(out, t.subtree(lo, hi))
	}
	k := splitPoint(n)
	if m <= k {
		out = t.subproof(m, lo, lo+k, whole, out)
		return append(out, t.subtree(lo+k, hi))
	}
	out = t.subproof(m-k, lo+k, hi, false, out)
	return append(out, t.subtree(lo, lo+k))
}
