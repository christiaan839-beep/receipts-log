package merkle

import (
	"errors"
	"math/bits"
)

// Verification errors. Every verifier returns nil or one of these, and
// never panics, whatever its input.
var (
	ErrProofSize = errors.New("merkle: proof has the wrong number of hashes")
	ErrRoot      = errors.New("merkle: proof does not lead to the expected root")
	ErrRange     = errors.New("merkle: index or sizes out of range")
)

// RootFromInclusion folds leaf with an audit path for index in a tree of
// the given size and returns the root it leads to (RFC 9162 §2.1.3.2).
func RootFromInclusion(leaf Hash, index, size uint64, proof []Hash) (Hash, error) {
	if index >= size {
		return Hash{}, ErrRange
	}
	// The proof length is fixed by (index, size): the bits where index
	// and size-1 differ, plus the set bits of index above them. Checking
	// it first rejects padded and truncated proofs early.
	inner := bits.Len64(index ^ (size - 1))
	border := bits.OnesCount64(index >> inner)
	if len(proof) != inner+border {
		return Hash{}, ErrProofSize
	}
	r := leaf
	for i, p := range proof {
		if i < inner && (index>>i)&1 == 0 {
			r = NodeHash(r, p)
		} else {
			r = NodeHash(p, r)
		}
	}
	return r, nil
}

// VerifyInclusion checks that leaf is at index in the tree of the given
// size whose root is root.
func VerifyInclusion(leaf Hash, index, size uint64, proof []Hash, root Hash) error {
	got, err := RootFromInclusion(leaf, index, size, proof)
	if err != nil {
		return err
	}
	if got != root {
		return ErrRoot
	}
	return nil
}

// VerifyConsistency checks that the tree of size second with root
// secondRoot is an append-only extension of the tree of size first with
// root firstRoot (RFC 9162 §2.1.4.2).
//
// The edge cases follow the verifiable-receipts reference verifier: a
// first size of 0 is consistent with any tree when the proof is empty,
// and equal sizes are consistent when the proof is empty and the roots
// are equal.
func VerifyConsistency(first, second uint64, firstRoot, secondRoot Hash, proof []Hash) error {
	switch {
	case first > second:
		return ErrRange
	case first == second:
		if len(proof) != 0 {
			return ErrProofSize
		}
		if firstRoot != secondRoot {
			return ErrRoot
		}
		return nil
	case first == 0:
		if len(proof) != 0 {
			return ErrProofSize
		}
		return nil
	}

	// A proof between two different non-zero sizes is never empty and
	// never longer than two hashes per tree level. The walk below then
	// rejects any length the sizes do not produce.
	if len(proof) == 0 || len(proof) > 2*64 {
		return ErrProofSize
	}

	path := proof
	if first&(first-1) == 0 {
		// first is a power of two: the old root is a complete subtree
		// and is not part of the proof.
		path = make([]Hash, 0, len(proof)+1)
		path = append(path, firstRoot)
		path = append(path, proof...)
	}

	fn := first - 1
	sn := second - 1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return ErrProofSize
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return ErrProofSize
	}
	if fr != firstRoot || sr != secondRoot {
		return ErrRoot
	}
	return nil
}
