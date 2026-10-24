// Copied from github.com/christiaan839-beep/verifiable-receipts,
// packages/verifiable-receipts-go/transparency.go at commit
// fd2390b5cd30fb3c31c41810195ab7ec5ed51702 (Apache-2.0, Copyright 2026
// Christiaan de Wet / Sovereign Matrix). Changed: this notice added; the
// code below is otherwise unchanged. See internal/vaos/README.md.

package vaos

import (
	"crypto/sha256"
	"encoding/hex"
	"math/bits"
	"strings"
)

// RFC 9162 / RFC 6962 transparency-log primitives. Byte-for-byte
// compatible with the TypeScript canonical implementation in
// `transparency.ts` — same domain separators (0x00 for leaves,
// 0x01 for inner nodes), same hex encoding throughout.

const (
	leafPrefix  byte = 0x00
	innerPrefix byte = 0x01
)

// LeafHash computes sha256(0x00 || data) per RFC 9162 §2. Returns
// the hex-encoded digest.
func LeafHash(data []byte) string {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// InnerHash combines two child hashes (both hex-encoded) into the
// parent hash sha256(0x01 || left || right) per RFC 9162 §2.
func InnerHash(leftHex, rightHex string) (string, error) {
	left, err := hex.DecodeString(strings.TrimPrefix(leftHex, "0x"))
	if err != nil {
		return "", err
	}
	right, err := hex.DecodeString(strings.TrimPrefix(rightHex, "0x"))
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte{innerPrefix})
	h.Write(left)
	h.Write(right)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// maxCount is the largest leaf index or tree size a verifier accepts,
// 2^53 - 1: the integers a double holds exactly, so every verifier,
// including JavaScript's, reads the same value.
const maxCount = 1<<53 - 1

// isHashHex reports whether s is a wire hash: 32 bytes written as
// exactly 64 lowercase hex digits.
func isHashHex(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// InclusionProof is the wire shape of an RFC 9162 audit path.
type InclusionProof struct {
	// LeafIndex is the 0-based position of the leaf in the tree.
	LeafIndex int

	// TreeSize is the total number of leaves in the tree.
	TreeSize int

	// AuditPath is the sequence of sibling hashes (hex-encoded)
	// needed to walk from the leaf up to the root.
	AuditPath []string
}

// VerifyInclusionProof returns true iff hashing the leaf with the
// audit path siblings (per RFC 9162 §2.1.1) yields rootHashHex.
//
// Uses the inner/border decomposition that handles every tree shape
// — including odd-tree right-edge carry-up cases like idx=6 in a
// 7-leaf tree. Byte-identical with the TypeScript canonical verifier.
//
// Returns false (not error) for all routine failure modes — wrong
// root, wrong index, malformed audit path entry, leaf-index out of
// range, zero tree size — so callers can use it as a predicate
// without exception-handling. Every hash must be 64 lowercase hex
// digits (32 bytes): a hash has one spelling, and a longer "leaf"
// cannot stand in for two hashes.
func VerifyInclusionProof(proof InclusionProof, leafHashHex, rootHashHex string) bool {
	if proof.TreeSize <= 0 || proof.TreeSize > maxCount {
		return false
	}
	if proof.LeafIndex < 0 || proof.LeafIndex >= proof.TreeSize {
		return false
	}
	if !isHashHex(leafHashHex) || !isHashHex(rootHashHex) {
		return false
	}
	for _, h := range proof.AuditPath {
		if !isHashHex(h) {
			return false
		}
	}
	// Single-leaf tree: root equals leaf, no audit path.
	if proof.TreeSize == 1 {
		return len(proof.AuditPath) == 0 && leafHashHex == rootHashHex
	}

	// RFC 9162 §2.1.1 inner/border decomposition.
	// Both operands are non-negative here, so the uint conversions are exact.
	inner := bits.Len(uint(proof.LeafIndex ^ (proof.TreeSize - 1)))
	border := bits.OnesCount(uint(proof.LeafIndex >> inner))
	if len(proof.AuditPath) != inner+border {
		return false
	}

	current := leafHashHex

	// Inner segment: walk the bits of leafIndex.
	// Bit=0 → sibling on the right; bit=1 → sibling on the left.
	for i := 0; i < inner; i++ {
		sibling := proof.AuditPath[i]
		var h string
		var err error
		if (proof.LeafIndex>>i)&1 == 0 {
			h, err = InnerHash(current, sibling)
		} else {
			h, err = InnerHash(sibling, current)
		}
		if err != nil {
			return false
		}
		current = h
	}

	// Border segment: every remaining sibling combines on the LEFT
	// (these are left-children we skipped while walking up the right edge).
	for i := 0; i < border; i++ {
		h, err := InnerHash(proof.AuditPath[inner+i], current)
		if err != nil {
			return false
		}
		current = h
	}

	return current == rootHashHex
}
