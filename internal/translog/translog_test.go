package translog

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/christiaan839-beep/receipts-log/internal/keys"
	"github.com/christiaan839-beep/receipts-log/internal/merkle"
	"github.com/christiaan839-beep/receipts-log/internal/sth"
	"github.com/christiaan839-beep/receipts-log/internal/store"
	"github.com/christiaan839-beep/receipts-log/internal/testutil"
)

type env struct {
	dir     string
	logKey  ed25519.PrivateKey
	issuer  ed25519.PrivateKey
	witness ed25519.PrivateKey
}

func newEnv(t testing.TB) *env {
	return &env{dir: t.TempDir(), logKey: testutil.Key(t), issuer: testutil.Key(t), witness: testutil.Key(t)}
}

func (e *env) cfg() Config {
	return Config{
		Dir: e.dir, LogID: "test-log", Key: e.logKey,
		IssuerKeys:  []ed25519.PublicKey{e.issuer.Public().(ed25519.PublicKey)},
		WitnessKeys: map[string]ed25519.PublicKey{"w1": e.witness.Public().(ed25519.PublicKey)},
	}
}

func (e *env) open(t *testing.T) *Log {
	t.Helper()
	l, err := Open(e.cfg())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (e *env) receipt(t *testing.T, i int) []byte {
	return testutil.Receipt(t, e.issuer, map[string]any{"runId": fmt.Sprintf("run_%04d", i), "overall": "pass", "n": i})
}

func TestAppendProveReopen(t *testing.T) {
	e := newEnv(t)
	l := e.open(t)
	pub := l.PublicKey()
	if err := sth.Verify(l.STH(), pub); err != nil || l.STH().TreeSize != 0 {
		t.Fatalf("initial STH: %v", err)
	}
	var heads []sth.STH
	for i := 0; i < 20; i++ {
		r, err := l.Append(e.receipt(t, i))
		if err != nil {
			t.Fatal(err)
		}
		if r.Index != uint64(i) || r.Duplicate || r.STH.TreeSize != uint64(i+1) {
			t.Fatalf("append %d: %+v", i, r)
		}
		if err := sth.Verify(r.STH, pub); err != nil {
			t.Fatal(err)
		}
		heads = append(heads, r.STH)
	}
	// Re-submitting returns the existing entry.
	r, err := l.Append(e.receipt(t, 3))
	if err != nil || !r.Duplicate || r.Index != 3 || r.STH.TreeSize != 20 {
		t.Fatalf("duplicate: %+v %v", r, err)
	}
	head := l.STH()
	root, _ := head.Root()
	for i := uint64(0); i < 20; i++ {
		p, err := l.ProveInclusion(i, 0)
		if err != nil {
			t.Fatal(err)
		}
		ent, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := LeafForReceipt(ent.Receipt)
		if err != nil || leaf != ent.Leaf {
			t.Fatalf("entry %d leaf", i)
		}
		if err := merkle.VerifyInclusion(leaf, i, head.TreeSize, p.Path, root); err != nil {
			t.Fatalf("inclusion %d: %v", i, err)
		}
		if idx, err := l.IndexOf(leaf); err != nil || idx != i {
			t.Fatalf("IndexOf %d", i)
		}
	}
	for _, old := range heads {
		c, err := l.ProveConsistency(old.TreeSize, 0)
		if err != nil {
			t.Fatal(err)
		}
		oldRoot, _ := old.Root()
		if err := merkle.VerifyConsistency(old.TreeSize, head.TreeSize, oldRoot, root, c.Path); err != nil {
			t.Fatalf("consistency %d: %v", old.TreeSize, err)
		}
	}
	if _, err := l.Entry(20); !errors.Is(err, ErrNotFound) {
		t.Fatal("entry past end")
	}
	if _, err := l.ProveInclusion(0, 21); !errors.Is(err, ErrRange) {
		t.Fatal("proof past end")
	}
	if _, err := l.ProveConsistency(5, 3); !errors.Is(err, ErrRange) {
		t.Fatal("first > second")
	}
	l.Close()

	l = e.open(t)
	defer l.Close()
	if l.STH() != head {
		t.Fatalf("reopened STH %+v, want %+v", l.STH(), head)
	}
	if _, err := l.Append(e.receipt(t, 99)); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsBadReceipts(t *testing.T) {
	e := newEnv(t)
	l := e.open(t)
	defer l.Close()
	good := e.receipt(t, 1)
	other := testutil.Receipt(t, testutil.Key(t), map[string]any{"runId": "x"})
	var m map[string]any
	json.Unmarshal(good, &m)
	m["overall"] = "fail"
	tampered, _ := json.Marshal(m)
	cases := map[string]struct {
		body []byte
		want error
	}{
		"not json":     {[]byte("{"), ErrInvalidReceipt},
		"array":        {[]byte("[]"), ErrInvalidReceipt},
		"no canonical": {[]byte(`{"signature":"v2=AA=="}`), ErrInvalidReceipt},
		"wrong key":    {other, ErrUnverified},
		"envelope":     {tampered, ErrUnverified},
		"v3":           {[]byte(`{"canonical":"{}","signature":"v3=AA==.AA=="}`), ErrUnverified},
		"too large":    {[]byte(`{"canonical":"` + strings.Repeat("a", 2<<20) + `"}`), ErrTooLarge},
	}
	for name, c := range cases {
		if _, err := l.Append(c.body); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	if l.STH().TreeSize != 0 {
		t.Fatal("a rejected receipt was appended")
	}
}

type fixture struct {
	Receipt json.RawMessage `json:"receipt"`
	// ReceiptText is a receipt given as JSON text, admitted as sent.
	ReceiptText string `json:"receiptText"`
	// PublicKeyPem is the fixture's own issuer key, used instead of
	// public-key.pem. It is parsed without keys.ParsePublicKeyPEM, which
	// refuses weak keys, so the log itself meets the key.
	PublicKeyPem string `json:"publicKeyPem"`
	Expected     struct {
		OK             bool   `json:"ok"`
		ReasonContains string `json:"reasonContains"`
	} `json:"expected"`
}

// fixtureKey parses a fixture's publicKeyPem as it is, weak or not.
func fixtureKey(t testing.TB, text string) ed25519.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		t.Fatal("publicKeyPem: no PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("publicKeyPem: %v", err)
	}
	return k.(ed25519.PublicKey)
}

// The v2 and Ed25519 receipt fixtures of the verifiable-receipts conformance corpus: the
// valid ones are admitted, the invalid ones refused, for the reason the
// fixture names. A receipt given as text is posted as that text; a
// fixture with its own key is checked by a log configured with that key,
// which refuses a weak key when it opens and when it verifies.
func TestConformanceReceipts(t *testing.T) {
	pub, err := keys.LoadPublicKey("../../testdata/conformance/public-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	cfg := e.cfg()
	cfg.IssuerKeys = []ed25519.PublicKey{pub}
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	files, _ := filepath.Glob("../../testdata/conformance/fixtures/v2-*.json")
	if len(files) < 8 {
		t.Fatalf("found %d v2 fixtures", len(files))
	}
	// The Ed25519 fixtures given as receipts (the strict profile of VAOS
	// 2.0 section 7.3), each with its own key; those given as raw
	// signatures are sth's (TestVerifyBytesStrictEd25519Fixtures).
	edFiles, _ := filepath.Glob("../../testdata/conformance/fixtures/ed25519-*.json")
	var edReceipts int
	for _, f := range edFiles {
		raw, _ := os.ReadFile(f)
		if strings.Contains(string(raw), `"receipt"`) {
			files = append(files, f)
			edReceipts++
		}
	}
	if edReceipts < 15 {
		t.Fatalf("found %d ed25519 receipt fixtures", edReceipts)
	}
	var withText, withKey int
	for _, f := range files {
		name := filepath.Base(f)
		raw, _ := os.ReadFile(f)
		var fx fixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		body := []byte(fx.Receipt)
		if fx.ReceiptText != "" {
			body = []byte(fx.ReceiptText)
			withText++
		}
		if len(body) == 0 {
			t.Fatalf("%s: no receipt or receiptText", name)
		}
		var errs []error
		if fx.PublicKeyPem != "" {
			withKey++
			key := fixtureKey(t, fx.PublicKeyPem)
			c := newEnv(t).cfg()
			c.IssuerKeys = []ed25519.PublicKey{key}
			if own, err := Open(c); err != nil {
				errs = append(errs, err)
			} else {
				_, err := own.Append(body)
				own.Close()
				errs = append(errs, err)
			}
			// Below Open, admission's own check meets the key too.
			_, _, err := verifyReceipt(body, []ed25519.PublicKey{key})
			errs = append(errs, err)
		} else {
			_, err := l.Append(body)
			errs = append(errs, err)
		}
		for _, err := range errs {
			if (err == nil) != fx.Expected.OK {
				t.Errorf("%s: err=%v, expected ok=%v", name, err, fx.Expected.OK)
			} else if err != nil && fx.Expected.ReasonContains != "" &&
				!regexp.MustCompile("(?i)"+fx.Expected.ReasonContains).MatchString(err.Error()) {
				t.Errorf("%s: err=%v, want a reason containing %q", name, err, fx.Expected.ReasonContains)
			}
		}
	}
	if withText == 0 || withKey == 0 {
		t.Fatalf("%d receiptText and %d publicKeyPem fixtures; the corpus has both", withText, withKey)
	}
	// The valid fixtures share one canonical, so they are one entry.
	if l.STH().TreeSize != 1 {
		t.Fatalf("tree size %d", l.STH().TreeSize)
	}
}

func TestCosignatures(t *testing.T) {
	e := newEnv(t)
	l := e.open(t)
	for i := 0; i < 3; i++ {
		l.Append(e.receipt(t, i))
	}
	head := l.STH()
	c, _ := head.Canonical()
	sig := sth.EncodeSignature(ed25519.Sign(e.witness, c))
	n, rec, err := l.AddCosignature("w1", string(c), sig, "https://w.example/key.pem")
	if err != nil || n != 1 || !rec {
		t.Fatalf("cosign: %d %v %v", n, rec, err)
	}
	if n, rec, err := l.AddCosignature("w1", string(c), sig, ""); err != nil || n != 1 || rec {
		t.Fatalf("duplicate cosign: %d %v %v", n, rec, err)
	}
	if _, _, err := l.AddCosignature("w2", string(c), sig, ""); !errors.Is(err, ErrUnknownWitness) {
		t.Fatalf("unknown witness: %v", err)
	}
	bad := sth.EncodeSignature(ed25519.Sign(testutil.Key(t), c))
	if _, _, err := l.AddCosignature("w1", string(c), bad, ""); !errors.Is(err, ErrWitnessSignature) {
		t.Fatalf("bad signature: %v", err)
	}
	forged := head
	forged.RootHash = merkle.LeafHash([]byte("x")).String()
	fc, _ := forged.Canonical()
	if _, _, err := l.AddCosignature("w1", string(fc), sth.EncodeSignature(ed25519.Sign(e.witness, fc)), ""); !errors.Is(err, ErrForeignSTH) {
		t.Fatalf("foreign STH: %v", err)
	}
	if _, _, err := l.AddCosignature("w1", string(c)+" ", sig, ""); !errors.Is(err, ErrInvalidCosig) {
		t.Fatalf("non-canonical: %v", err)
	}
	if got := l.Cosignatures(head.TreeSize, false); len(got) != 1 || got[0].WitnessID != "w1" {
		t.Fatalf("list: %+v", got)
	}
	l.Close()
	l = e.open(t)
	defer l.Close()
	if got := l.Cosignatures(0, true); len(got) != 1 {
		t.Fatalf("after reopen: %+v", got)
	}
}

func TestOpenVerifiesCheckpoint(t *testing.T) {
	e := newEnv(t)
	l := e.open(t)
	for i := 0; i < 4; i++ {
		l.Append(e.receipt(t, i))
	}
	l.Close()

	// Another log key cannot open the directory.
	cfg := e.cfg()
	cfg.Key = testutil.Key(t)
	if _, err := Open(cfg); !errors.Is(err, store.ErrCorrupt) {
		t.Fatalf("wrong log key: %v", err)
	}
	// Another log ID cannot open it.
	cfg = e.cfg()
	cfg.LogID = "other"
	if _, err := Open(cfg); err == nil {
		t.Fatal("wrong log ID accepted")
	}
	// A checkpoint signed by the right key over a different root fails.
	ckPath := filepath.Join(e.dir, store.CheckpointFile)
	orig, _ := os.ReadFile(ckPath)
	var head sth.STH
	json.Unmarshal(orig, &head)
	head.RootHash = merkle.LeafHash([]byte("forged")).String()
	forged, _ := sth.Sign(head, e.logKey)
	raw, _ := json.Marshal(forged)
	os.WriteFile(ckPath, raw, 0o600)
	if _, err := Open(e.cfg()); !errors.Is(err, store.ErrCorrupt) {
		t.Fatalf("forged root: %v", err)
	}
	// Deleting the checkpoint is detected.
	os.Remove(ckPath)
	if _, err := Open(e.cfg()); !errors.Is(err, store.ErrCorrupt) {
		t.Fatalf("missing checkpoint: %v", err)
	}
	os.WriteFile(ckPath, orig, 0o600)
	l = e.open(t)
	l.Close()
}

// An entry that reached the disk without its checkpoint (a crash
// between the two writes) is kept and covered by a new tree head.
func TestEntryPastCheckpointIsSigned(t *testing.T) {
	e := newEnv(t)
	l := e.open(t)
	l.Append(e.receipt(t, 0))
	ckPath := filepath.Join(e.dir, store.CheckpointFile)
	ck1, _ := os.ReadFile(ckPath)
	l.Append(e.receipt(t, 1))
	l.Close()
	os.WriteFile(ckPath, ck1, 0o600) // roll the checkpoint back one append
	l = e.open(t)
	defer l.Close()
	if l.STH().TreeSize != 2 {
		t.Fatalf("tree size %d", l.STH().TreeSize)
	}
	if err := sth.Verify(l.STH(), l.PublicKey()); err != nil {
		t.Fatal(err)
	}
}

func TestTimestampsNeverGoBackwards(t *testing.T) {
	e := newEnv(t)
	clock := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	cfg := e.cfg()
	cfg.Now = func() time.Time { return clock }
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	clock = clock.Add(-time.Hour)
	r, err := l.Append(e.receipt(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	if r.STH.Timestamp != "2026-10-23T12:00:00.000Z" {
		t.Fatalf("timestamp went backwards: %s", r.STH.Timestamp)
	}
}

func TestConcurrentAppendsAndReads(t *testing.T) {
	e := newEnv(t)
	l := e.open(t)
	defer l.Close()
	bodies := make([][]byte, 64)
	for i := range bodies {
		bodies[i] = e.receipt(t, i)
	}
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < len(bodies); i += 8 {
				if _, err := l.Append(bodies[i]); err != nil {
					t.Error(err)
				}
				head := l.STH()
				if head.TreeSize > 0 {
					if _, err := l.ProveInclusion(head.TreeSize-1, head.TreeSize); err != nil {
						t.Error(err)
					}
					if _, err := l.ProveConsistency(1, head.TreeSize); err != nil {
						t.Error(err)
					}
				}
			}
		}(w)
	}
	wg.Wait()
	if l.STH().TreeSize != 64 {
		t.Fatalf("size %d", l.STH().TreeSize)
	}
}

func TestRefreshSTH(t *testing.T) {
	e := newEnv(t)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := e.cfg()
	cfg.Now = func() time.Time { return clock }
	l, _ := Open(cfg)
	defer l.Close()
	clock = clock.Add(time.Minute)
	h, err := l.RefreshSTH()
	if err != nil || h.Timestamp != "2026-01-01T00:01:00.000Z" {
		t.Fatalf("%+v %v", h, err)
	}
}

func TestOpenValidatesConfig(t *testing.T) {
	e := newEnv(t)
	for name, mut := range map[string]func(*Config){
		"no log id":  func(c *Config) { c.LogID = "" },
		"no key":     func(c *Config) { c.Key = nil },
		"no issuers": func(c *Config) { c.IssuerKeys = nil },
		"bad issuer": func(c *Config) { c.IssuerKeys = []ed25519.PublicKey{{1, 2}} },
	} {
		c := e.cfg()
		mut(&c)
		if _, err := Open(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// FuzzAppend submits arbitrary bodies; nothing panics and nothing
// unsigned is admitted.
func FuzzAppend(f *testing.F) {
	e := &env{dir: f.TempDir(), logKey: testutil.Key(f), issuer: testutil.Key(f), witness: testutil.Key(f)}
	l, err := Open(e.cfg())
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { l.Close() })
	f.Add([]byte(`{"canonical":"{}","signature":"v2=AA=="}`))
	f.Add([]byte(`{"canonical":"{\"a\":1}","a":1,"contentHash":"sha256:00","signature":"v2="}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if _, err := l.Append(body); err == nil {
			t.Fatalf("admitted an unsigned body: %q", body)
		}
	})
}

func TestCheck(t *testing.T) {
	e := newEnv(t)
	l := e.open(t)
	for i := 0; i < 5; i++ {
		l.Append(e.receipt(t, i))
	}
	l.Close()
	pub := e.logKey.Public().(ed25519.PublicKey)
	rep, err := Check(e.dir, "test-log", pub, CheckOptions{})
	if err != nil || rep.Entries != 5 || rep.CheckpointSize != 5 {
		t.Fatalf("%+v %v", rep, err)
	}
	if _, err := Check(e.dir, "test-log", testutil.Key(t).Public().(ed25519.PublicKey), CheckOptions{}); err == nil {
		t.Fatal("wrong key accepted")
	}
	path := filepath.Join(e.dir, store.EntriesFile)
	data, _ := os.ReadFile(path)
	data[len(data)-10] ^= 1
	os.WriteFile(path, data, 0o600)
	if _, err := Check(e.dir, "test-log", pub, CheckOptions{}); !errors.Is(err, store.ErrCorrupt) {
		t.Fatalf("corruption: %v", err)
	}
}

// appendRaw appends bodies to the store without verifying them and
// without opening the log, so no checkpoint covers them.
func appendRaw(t *testing.T, e *env, bodies ...[]byte) {
	t.Helper()
	st, err := store.Open(store.Options{Dir: e.dir}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bodies {
		leaf, err := LeafForReceipt(b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Append(leaf, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
}

// writeUnverified stores bodies the way a log built before an admission
// rule existed could have: straight into the store, without verifying
// them. Opening the log afterwards signs a checkpoint over them.
func writeUnverified(t *testing.T, e *env, bodies ...[]byte) {
	t.Helper()
	appendRaw(t, e, bodies...)
	e.open(t).Close()
}

// withField returns receipt with one top-level field set.
func withField(t *testing.T, receipt []byte, key string, value any) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(receipt, &m); err != nil {
		t.Fatal(err)
	}
	m[key] = value
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// count returns the report's nonconforming count, which must be set.
func count(t *testing.T, rep CheckReport) uint64 {
	t.Helper()
	if rep.NonconformingCount == nil {
		t.Fatalf("nonconformingCount missing: %+v", rep)
	}
	return *rep.NonconformingCount
}

// Check with issuer keys reports the stored receipts that admission
// would now refuse; without them it does not look at payloads.
func TestCheckReverifiesReceipts(t *testing.T) {
	e := newEnv(t)
	l := e.open(t)
	for i := 0; i < 2; i++ {
		if _, err := l.Append(e.receipt(t, i)); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	otherKey := testutil.Key(t)
	emptyHash := withField(t, e.receipt(t, 2), "contentHash", "")
	otherIssuer := testutil.Receipt(t, otherKey, map[string]any{"runId": "other"})
	// Admission refuses both today.
	l = e.open(t)
	for _, b := range [][]byte{emptyHash, otherIssuer} {
		if _, err := l.Append(b); !errors.Is(err, ErrUnverified) {
			t.Fatalf("admitted: %v", err)
		}
	}
	l.Close()
	writeUnverified(t, e, emptyHash, otherIssuer)

	pub := e.logKey.Public().(ed25519.PublicKey)
	rep, err := Check(e.dir, "test-log", pub, CheckOptions{})
	if err != nil || rep.Entries != 4 || rep.Nonconforming != nil || rep.NonconformingCount != nil || rep.IssuerKeys != 0 {
		t.Fatalf("without issuer keys: %+v %v", rep, err)
	}
	if out, _ := json.Marshal(rep); strings.Contains(string(out), "onconforming") || strings.Contains(string(out), "issuerKeys") {
		t.Fatalf("default report changed: %s", out)
	}

	issuer := e.issuer.Public().(ed25519.PublicKey)
	rep, err = Check(e.dir, "test-log", pub, CheckOptions{IssuerKeys: []ed25519.PublicKey{issuer}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Entries != 4 || rep.IssuerKeys != 1 || count(t, rep) != 2 || len(rep.Nonconforming) != 2 {
		t.Fatalf("with the issuer key: %+v", rep)
	}
	for i, want := range []struct {
		index  uint64
		body   []byte
		reason string
	}{
		{2, emptyHash, "contentHash mismatch"},
		{3, otherIssuer, "signature does not verify"},
	} {
		got := rep.Nonconforming[i]
		leaf, _ := LeafForReceipt(want.body)
		if got.Index != want.index || got.LeafHash != leaf.String() || got.PastCheckpoint ||
			!strings.Contains(got.Reason, want.reason) || !strings.HasPrefix(got.Reason, ErrUnverified.Error()) {
			t.Errorf("entry %d: %+v", i, got)
		}
	}
	out, _ := json.Marshal(rep)
	if !strings.Contains(string(out), `"nonconformingCount":2,"nonconforming":[{"index":2,"leafHash":"`) ||
		strings.Contains(string(out), "pastCheckpoint") {
		t.Fatalf("JSON: %s", out)
	}

	// Every key counts, whichever position it has: with the other
	// issuer's key too, only the empty contentHash is left.
	for _, ks := range [][]ed25519.PublicKey{
		{otherKey.Public().(ed25519.PublicKey), issuer},
		{issuer, otherKey.Public().(ed25519.PublicKey)},
	} {
		rep, err = Check(e.dir, "test-log", pub, CheckOptions{IssuerKeys: ks})
		if err != nil || rep.IssuerKeys != 2 || count(t, rep) != 1 || len(rep.Nonconforming) != 1 ||
			rep.Nonconforming[0].Index != 2 || !strings.Contains(rep.Nonconforming[0].Reason, "contentHash mismatch") {
			t.Fatalf("two keys: %+v %v", rep, err)
		}
	}

	if _, err := Check(e.dir, "test-log", pub, CheckOptions{IssuerKeys: []ed25519.PublicKey{{1, 2, 3}}}); err == nil {
		t.Fatal("a malformed issuer key was accepted")
	}
}

func TestCheckReverifyAllValid(t *testing.T) {
	e := newEnv(t)
	l := e.open(t)
	for i := 0; i < 3; i++ {
		l.Append(e.receipt(t, i))
	}
	l.Close()
	rep, err := Check(e.dir, "test-log", e.logKey.Public().(ed25519.PublicKey),
		CheckOptions{IssuerKeys: []ed25519.PublicKey{e.issuer.Public().(ed25519.PublicKey)}})
	if err != nil || rep.Entries != 3 || rep.IssuerKeys != 1 || count(t, rep) != 0 || len(rep.Nonconforming) != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	// Scripts can read the count: it is present, and 0, when clean.
	out, _ := json.Marshal(rep)
	if !strings.Contains(string(out), `"nonconformingCount":0`) || strings.Contains(string(out), `"nonconforming":`) {
		t.Fatalf("JSON: %s", out)
	}
}

// The list is capped per call; the count is not.
func TestCheckReverifyCap(t *testing.T) {
	e := newEnv(t)
	e.open(t).Close()
	var bad [][]byte
	for i := 0; i < 5; i++ {
		bad = append(bad, withField(t, e.receipt(t, i), "contentHash", ""))
	}
	writeUnverified(t, e, bad...)
	pub := e.logKey.Public().(ed25519.PublicKey)
	issuers := []ed25519.PublicKey{e.issuer.Public().(ed25519.PublicKey)}
	rep, err := Check(e.dir, "test-log", pub, CheckOptions{IssuerKeys: issuers, NonconformingLimit: 2})
	if err != nil || count(t, rep) != 5 || len(rep.Nonconforming) != 2 ||
		rep.Nonconforming[0].Index != 0 || rep.Nonconforming[1].Index != 1 {
		t.Fatalf("limit 2: %+v %v", rep, err)
	}
	// A zero limit is the default.
	rep, err = Check(e.dir, "test-log", pub, CheckOptions{IssuerKeys: issuers})
	if err != nil || count(t, rep) != 5 || len(rep.Nonconforming) != 5 {
		t.Fatalf("default limit: %+v %v", rep, err)
	}
	if DefaultNonconformingLimit != 1000 {
		t.Fatalf("default limit %d", DefaultNonconformingLimit)
	}
}

// Entries past the checkpoint (an append interrupted before its
// checkpoint) are verified too, and marked.
func TestCheckReverifyPastCheckpoint(t *testing.T) {
	e := newEnv(t)
	l := e.open(t)
	for i := 0; i < 2; i++ {
		l.Append(e.receipt(t, i))
	}
	l.Close()
	bad := withField(t, e.receipt(t, 2), "contentHash", "")
	appendRaw(t, e, bad)
	rep, err := Check(e.dir, "test-log", e.logKey.Public().(ed25519.PublicKey),
		CheckOptions{IssuerKeys: []ed25519.PublicKey{e.issuer.Public().(ed25519.PublicKey)}})
	if err != nil || rep.Entries != 3 || rep.CheckpointSize != 2 || count(t, rep) != 1 || len(rep.Nonconforming) != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := rep.Nonconforming[0]; got.Index != 2 || !got.PastCheckpoint || !strings.Contains(got.Reason, "contentHash mismatch") {
		t.Fatalf("%+v", got)
	}
	if out, _ := json.Marshal(rep); !strings.Contains(string(out), `"pastCheckpoint":true`) {
		t.Fatalf("JSON: %s", out)
	}
}

// Corruption is still reported as corruption when issuer keys are given.
func TestCheckReverifyCorrupt(t *testing.T) {
	e := newEnv(t)
	e.open(t).Close()
	writeUnverified(t, e, withField(t, e.receipt(t, 0), "contentHash", ""), e.receipt(t, 1))
	path := filepath.Join(e.dir, store.EntriesFile)
	data, _ := os.ReadFile(path)
	data[len(data)-10] ^= 1
	os.WriteFile(path, data, 0o600)
	if _, err := Check(e.dir, "test-log", e.logKey.Public().(ed25519.PublicKey),
		CheckOptions{IssuerKeys: []ed25519.PublicKey{e.issuer.Public().(ed25519.PublicKey)}}); !errors.Is(err, store.ErrCorrupt) {
		t.Fatalf("corruption: %v", err)
	}
}
