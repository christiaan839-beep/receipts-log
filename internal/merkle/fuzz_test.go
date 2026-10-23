package merkle

import (
	"testing"
)

func splitHashes(b []byte) []Hash {
	out := make([]Hash, 0, len(b)/HashSize)
	for len(b) >= HashSize {
		var h Hash
		copy(h[:], b)
		out = append(out, h)
		b = b[HashSize:]
	}
	return out
}

// FuzzVerifyInclusion feeds arbitrary indices, sizes and proof bytes to
// the inclusion verifier. It must never panic, and whatever it accepts
// must fold to the root it was given.
func FuzzVerifyInclusion(f *testing.F) {
	tr := treeOf(leavesN(13))
	p, _ := tr.InclusionProof(6, 13)
	var seed []byte
	for _, h := range p {
		seed = append(seed, h[:]...)
	}
	root, _ := tr.RootAt(13)
	leaf, _ := tr.Leaf(6)
	f.Add(leaf[:], uint64(6), uint64(13), seed, root[:])
	f.Add([]byte{}, uint64(0), uint64(0), []byte{}, []byte{})
	f.Add([]byte{1}, ^uint64(0), ^uint64(0), seed, root[:])
	f.Fuzz(func(t *testing.T, leafB []byte, index, size uint64, proofB, rootB []byte) {
		var lh, rh Hash
		copy(lh[:], leafB)
		copy(rh[:], rootB)
		proof := splitHashes(proofB)
		err := VerifyInclusion(lh, index, size, proof, rh)
		if err == nil {
			got, err2 := RootFromInclusion(lh, index, size, proof)
			if err2 != nil || got != rh {
				t.Fatal("accepted a proof that does not fold to the root")
			}
		}
	})
}

// FuzzVerifyConsistency feeds arbitrary sizes, roots and proof bytes to
// the consistency verifier. It must never panic, and it must accept the
// honest proof for any pair of sizes taken from the input.
func FuzzVerifyConsistency(f *testing.F) {
	tr := treeOf(leavesN(64))
	f.Add(uint64(3), uint64(7), []byte{}, []byte{}, []byte{})
	f.Add(uint64(0), uint64(0), []byte{}, []byte{}, []byte{})
	f.Add(^uint64(0), ^uint64(0), []byte{1}, []byte{2}, make([]byte, 64))
	f.Fuzz(func(t *testing.T, first, second uint64, oldB, newB, proofB []byte) {
		var o, n Hash
		copy(o[:], oldB)
		copy(n[:], newB)
		_ = VerifyConsistency(first, second, o, n, splitHashes(proofB))

		a, b := first%65, second%65
		if a > b {
			a, b = b, a
		}
		ra, _ := tr.RootAt(a)
		rb, _ := tr.RootAt(b)
		p, err := tr.ConsistencyProof(a, b)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyConsistency(a, b, ra, rb, p); err != nil {
			t.Fatalf("honest proof %d->%d rejected: %v", a, b, err)
		}
	})
}

// FuzzParseHashes checks the hex decoder never panics and round-trips.
func FuzzParseHashes(f *testing.F) {
	f.Add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	f.Add("")
	f.Add("ZZ")
	f.Fuzz(func(t *testing.T, s string) {
		h, err := ParseHash(s)
		if err == nil {
			back, err := ParseHash(h.String())
			if err != nil || back != h {
				t.Fatal("round trip failed")
			}
		}
	})
}
