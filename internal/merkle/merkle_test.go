package merkle

import (
	"encoding/binary"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"testing/quick"

	"github.com/christiaan839-beep/receipts-log/internal/vaos"
)

// ── Reference implementation: RFC 9162 §2.1 written over slices ──────

func refRoot(leaves []Hash) Hash {
	switch len(leaves) {
	case 0:
		return EmptyRoot()
	case 1:
		return leaves[0]
	}
	k := splitPoint(uint64(len(leaves)))
	return NodeHash(refRoot(leaves[:k]), refRoot(leaves[k:]))
}

func refPath(m int, leaves []Hash) []Hash {
	if len(leaves) <= 1 {
		return nil
	}
	k := int(splitPoint(uint64(len(leaves))))
	if m < k {
		return append(refPath(m, leaves[:k]), refRoot(leaves[k:]))
	}
	return append(refPath(m-k, leaves[k:]), refRoot(leaves[:k]))
}

func refSubproof(m int, leaves []Hash, whole bool) []Hash {
	n := len(leaves)
	if m == n {
		if whole {
			return nil
		}
		return []Hash{refRoot(leaves)}
	}
	k := int(splitPoint(uint64(n)))
	if m <= k {
		return append(refSubproof(m, leaves[:k], whole), refRoot(leaves[k:]))
	}
	return append(refSubproof(m-k, leaves[k:], false), refRoot(leaves[:k]))
}

func leavesN(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(i))
		out[i] = LeafHash(b[:])
	}
	return out
}

func treeOf(leaves []Hash) *Tree {
	t := &Tree{}
	for _, l := range leaves {
		t.Append(l)
	}
	return t
}

func equalHashes(a, b []Hash) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── Known answers ─────────────────────────────────────────────────────

// The roots of the first n leaves of the Certificate Transparency test
// corpus. The same values come out of the verifiable-receipts TypeScript
// treeRoot.
func TestKnownRoots(t *testing.T) {
	data := []string{"", "\x00", "\x10", "\x20\x21", "\x30\x31", "\x40\x41\x42\x43",
		"\x50\x51\x52\x53\x54\x55\x56\x57",
		"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"}
	want := []string{
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
		"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
		"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
		"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	}
	tr := &Tree{}
	if got := tr.Root().String(); got != want[0] {
		t.Fatalf("empty root = %s", got)
	}
	for i, d := range data {
		tr.Append(LeafHash([]byte(d)))
		if got := tr.Root().String(); got != want[i+1] {
			t.Fatalf("root at size %d = %s, want %s", i+1, got, want[i+1])
		}
	}
}

type inclusionFixture struct {
	Description string   `json:"description"`
	LeafHashHex string   `json:"leafHashHex"`
	LeafIndex   uint64   `json:"leafIndex"`
	TreeSize    uint64   `json:"treeSize"`
	AuditPath   []string `json:"auditPath"`
	RootHashHex string   `json:"rootHashHex"`
	Expected    struct {
		OK bool `json:"ok"`
	} `json:"expected"`
}

// The verifiable-receipts conformance corpus: every inclusion fixture
// gets the expected verdict from VerifyInclusion.
func TestConformanceInclusionFixtures(t *testing.T) {
	files, err := filepath.Glob("../../testdata/conformance/fixtures/inclusion-*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var fx inclusionFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		leaf, err1 := ParseHash(fx.LeafHashHex)
		root, err2 := ParseHash(fx.RootHashHex)
		proof, err3 := ParseHashes(fx.AuditPath)
		if err1 != nil || err2 != nil || err3 != nil {
			t.Fatalf("%s: bad fixture", f)
		}
		got := VerifyInclusion(leaf, fx.LeafIndex, fx.TreeSize, proof, root) == nil
		if got != fx.Expected.OK {
			t.Errorf("%s (%s): got ok=%v, want %v", filepath.Base(f), fx.Description, got, fx.Expected.OK)
		}
	}
}

// The 4-leaf fixtures are the tree over "alpha".."delta"; this tree
// must produce byte-identical proofs.
func TestConformanceFixtureReproduced(t *testing.T) {
	tr := &Tree{}
	for _, s := range []string{"alpha", "beta", "gamma", "delta"} {
		tr.Append(LeafHash([]byte(s)))
	}
	raw, err := os.ReadFile("../../testdata/conformance/fixtures/inclusion-4leaf-idx1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx inclusionFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	proof, err := tr.InclusionProof(1, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got := HexHashes(proof); len(got) != len(fx.AuditPath) || got[0] != fx.AuditPath[0] || got[1] != fx.AuditPath[1] {
		t.Fatalf("audit path %v, want %v", got, fx.AuditPath)
	}
	if tr.Root().String() != fx.RootHashHex {
		t.Fatalf("root %s, want %s", tr.Root(), fx.RootHashHex)
	}
}

// ── Exhaustive agreement with the reference, small trees ──────────────

func TestAgainstReferenceExhaustive(t *testing.T) {
	const maxN = 70
	all := leavesN(maxN)
	tr := &Tree{}
	for n := 0; n <= maxN; n++ {
		if n > 0 {
			tr.Append(all[n-1])
		}
		leaves := all[:n]
		root := refRoot(leaves)
		got, err := tr.RootAt(uint64(n))
		if err != nil || got != root {
			t.Fatalf("RootAt(%d) mismatch", n)
		}
		for m := 0; m < n; m++ {
			p, err := tr.InclusionProof(uint64(m), uint64(n))
			if err != nil {
				t.Fatal(err)
			}
			if !equalHashes(p, refPath(m, leaves)) {
				t.Fatalf("inclusion(%d,%d) differs from reference", m, n)
			}
			if err := VerifyInclusion(leaves[m], uint64(m), uint64(n), p, root); err != nil {
				t.Fatalf("inclusion(%d,%d) rejected: %v", m, n, err)
			}
			// The published Go verifier agrees.
			vp := vaos.InclusionProof{LeafIndex: m, TreeSize: n, AuditPath: HexHashes(p)}
			if !vaos.VerifyInclusionProof(vp, leaves[m].String(), root.String()) {
				t.Fatalf("vaos rejects inclusion(%d,%d)", m, n)
			}
		}
		for m := 0; m <= n; m++ {
			p, err := tr.ConsistencyProof(uint64(m), uint64(n))
			if err != nil {
				t.Fatal(err)
			}
			var want []Hash
			if m > 0 && m < n {
				want = refSubproof(m, leaves, true)
			}
			if !equalHashes(p, want) {
				t.Fatalf("consistency(%d,%d) differs from reference", m, n)
			}
			old := refRoot(all[:m])
			if err := VerifyConsistency(uint64(m), uint64(n), old, root, p); err != nil {
				t.Fatalf("consistency(%d,%d) rejected: %v", m, n, err)
			}
		}
	}
}

// ── Property tests ───────────────────────────────────────────────────

// Every honest proof verifies; every single-bit change to a proof hash,
// a dropped or extra hash, or a different index or size is rejected.
func TestPropertyInclusionTamper(t *testing.T) {
	all := leavesN(600)
	tr := treeOf(all)
	prop := func(a, b uint16, flip uint16) bool {
		n := uint64(a)%uint64(len(all)) + 1
		m := uint64(b) % n
		root, _ := tr.RootAt(n)
		p, err := tr.InclusionProof(m, n)
		if err != nil || VerifyInclusion(all[m], m, n, p, root) != nil {
			return false
		}
		if len(p) > 0 {
			q := append([]Hash(nil), p...)
			i := int(flip) % (len(q) * HashSize * 8)
			q[i/(HashSize*8)][(i/8)%HashSize] ^= 1 << (i % 8)
			if VerifyInclusion(all[m], m, n, q, root) == nil {
				return false
			}
			if VerifyInclusion(all[m], m, n, p[:len(p)-1], root) == nil {
				return false
			}
		}
		if VerifyInclusion(all[m], m, n, append(append([]Hash(nil), p...), root), root) == nil {
			return false
		}
		if m+1 < n && VerifyInclusion(all[m], m+1, n, p, root) == nil && all[m] != all[m+1] {
			return false
		}
		// A different tree size is not checked here: the audit path for
		// (m, n) can also fit (m, n+1), so the size is bound by the
		// signed tree head, not by the proof.
		// Wrong leaf.
		other := all[(m+1)%uint64(len(all))]
		return other == all[m] || VerifyInclusion(other, m, n, p, root) != nil
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 3000}); err != nil {
		t.Fatal(err)
	}
}

func TestPropertyConsistencyTamper(t *testing.T) {
	all := leavesN(600)
	tr := treeOf(all)
	prop := func(a, b uint16, flip uint16) bool {
		n := uint64(a)%uint64(len(all)) + 1
		m := uint64(b)%n + 1 // 1..n
		oldRoot, _ := tr.RootAt(m)
		newRoot, _ := tr.RootAt(n)
		p, err := tr.ConsistencyProof(m, n)
		if err != nil || VerifyConsistency(m, n, oldRoot, newRoot, p) != nil {
			return false
		}
		if m == n {
			return VerifyConsistency(m, n, oldRoot, NodeHash(oldRoot, oldRoot), p) != nil
		}
		q := append([]Hash(nil), p...)
		i := int(flip) % (len(q) * HashSize * 8)
		q[i/(HashSize*8)][(i/8)%HashSize] ^= 1 << (i % 8)
		if VerifyConsistency(m, n, oldRoot, newRoot, q) == nil {
			return false
		}
		if VerifyConsistency(m, n, oldRoot, newRoot, p[:len(p)-1]) == nil {
			return false
		}
		if VerifyConsistency(m, n, oldRoot, newRoot, append(append([]Hash(nil), p...), newRoot)) == nil {
			return false
		}
		// A different history: change one old leaf.
		forked := append([]Hash(nil), all[:n]...)
		forked[int(flip)%int(m)][0] ^= 0xff
		ft := treeOf(forked)
		fNew, _ := ft.RootAt(n)
		if VerifyConsistency(m, n, oldRoot, fNew, p) == nil {
			return false
		}
		fp, _ := ft.ConsistencyProof(m, n)
		if VerifyConsistency(m, n, oldRoot, fNew, fp) == nil {
			return false
		}
		// The old size must match the proof. (The new size is bound by
		// the signed tree head: a proof for (m, n) can also fit (m, n+1).)
		return m+1 >= n || VerifyConsistency(m+1, n, oldRoot, newRoot, p) != nil
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 3000}); err != nil {
		t.Fatal(err)
	}
}

// Roots at every size of a large random tree agree with the reference
// at sampled sizes, and the incremental tree never rebuilds history.
func TestPropertyRandomLarge(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	all := make([]Hash, 5000)
	for i := range all {
		rng.Read(all[i][:])
	}
	tr := treeOf(all)
	for i := 0; i < 200; i++ {
		n := uint64(rng.Intn(len(all))) + 1
		r, _ := tr.RootAt(n)
		if r != refRoot(all[:n]) {
			t.Fatalf("root at %d mismatch", n)
		}
		m := uint64(rng.Intn(int(n)))
		p, _ := tr.InclusionProof(m, n)
		if VerifyInclusion(all[m], m, n, p, r) != nil {
			t.Fatalf("inclusion %d/%d", m, n)
		}
		o := uint64(rng.Intn(int(n))) + 1
		or, _ := tr.RootAt(o)
		cp, _ := tr.ConsistencyProof(o, n)
		if VerifyConsistency(o, n, or, r, cp) != nil {
			t.Fatalf("consistency %d/%d", o, n)
		}
	}
}

func TestRangeErrors(t *testing.T) {
	tr := treeOf(leavesN(5))
	if _, err := tr.InclusionProof(5, 5); err == nil {
		t.Fatal("index == size accepted")
	}
	if _, err := tr.InclusionProof(0, 6); err == nil {
		t.Fatal("size > tree accepted")
	}
	if _, err := tr.ConsistencyProof(3, 2); err == nil {
		t.Fatal("first > second accepted")
	}
	if _, err := tr.RootAt(6); err == nil {
		t.Fatal("RootAt beyond size accepted")
	}
	if _, err := tr.Leaf(5); err == nil {
		t.Fatal("Leaf beyond size accepted")
	}
	if VerifyInclusion(Hash{}, 0, 0, nil, Hash{}) == nil {
		t.Fatal("size 0 accepted")
	}
	if VerifyConsistency(0, 5, Hash{}, Hash{}, nil) != nil {
		t.Fatal("empty old tree should be consistent with an empty proof")
	}
	if VerifyConsistency(0, 5, Hash{}, Hash{}, []Hash{{}}) == nil {
		t.Fatal("non-empty proof from size 0 accepted")
	}
	if VerifyConsistency(4, 5, Hash{}, Hash{}, nil) == nil {
		t.Fatal("empty proof between different sizes accepted")
	}
}

func TestParseHash(t *testing.T) {
	h := LeafHash([]byte("x"))
	got, err := ParseHash(h.String())
	if err != nil || got != h {
		t.Fatal("round trip failed")
	}
	for _, bad := range []string{"", "00", h.String() + "0", "zz" + h.String()[2:]} {
		if _, err := ParseHash(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if hs := HexHashes(nil); hs == nil || len(hs) != 0 {
		t.Fatal("HexHashes(nil) must be an empty, non-nil slice")
	}
}
