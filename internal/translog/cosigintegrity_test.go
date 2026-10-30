package translog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/christiaan839-beep/receipts-log/internal/sth"
	"github.com/christiaan839-beep/receipts-log/internal/testutil"
)

// foreignCosigStore writes, through store, four cosignatures by the
// configured witness w1 whose signatures verify but whose tree heads are
// not evidence of this log, between two honest ones:
//
//	1 (a) another log's head
//	2 (b) a fork: this log's ID and a real size, another root
//	3 (c) a tree size this log never reached
//	4 (d) record fields saying size 3 while sthCanonical is the size-1 head
//
// Lines 0 and 5 are honest cosignatures of the size-1 and size-3 heads.
type foreignCosigStore struct {
	e     *env
	heads []sth.STH
	recs  []Cosignature
}

func newForeignCosigStore(t *testing.T) *foreignCosigStore {
	t.Helper()
	e := newEnv(t)
	l := e.open(t)
	var heads []sth.STH
	for i := 0; i < 3; i++ {
		l.Append(e.receipt(t, i))
		heads = append(heads, l.STH())
	}
	l.Close()
	canon := func(h sth.STH) string {
		h.Signature = ""
		c, err := h.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		return string(c)
	}
	foreign := heads[1]
	foreign.LogID = "other-log"
	fork := heads[1]
	fork.RootHash = heads[2].RootHash
	future := heads[2]
	future.TreeSize = 99
	rec := func(h sth.STH, fieldSize uint64, fieldRoot string) Cosignature {
		c := canon(h)
		return Cosignature{WitnessID: "w1", TreeSize: fieldSize, RootHash: fieldRoot, Timestamp: h.Timestamp,
			STHCanonical: c, Signature: sth.EncodeSignature(ed25519.Sign(e.witness, []byte(c))), ReceivedAt: h.Timestamp}
	}
	honest := func(h sth.STH) Cosignature { return rec(h, h.TreeSize, h.RootHash) }
	recs := []Cosignature{
		honest(heads[0]),
		rec(foreign, foreign.TreeSize, foreign.RootHash),
		rec(fork, fork.TreeSize, fork.RootHash),
		rec(future, future.TreeSize, future.RootHash),
		rec(heads[0], heads[2].TreeSize, heads[2].RootHash),
		honest(heads[2]),
	}
	// (d) shares (witness, canonical) with line 0, which Open would keep
	// first anyway; give it its own witness so the test sees it.
	recs[4].WitnessID = "w2"
	recs[4].Signature = sth.EncodeSignature(ed25519.Sign(e.witness2(t), []byte(recs[4].STHCanonical)))
	writeCosignatures(t, e.dir, recs...)
	return &foreignCosigStore{e: e, heads: heads, recs: recs}
}

// witness2 is a second configured witness, made on first use.
func (e *env) witness2(t *testing.T) ed25519.PrivateKey {
	if e.second == nil {
		e.second = testutil.Key(t)
	}
	return e.second
}

func (f *foreignCosigStore) witnesses() map[string]ed25519.PublicKey {
	w := f.e.cfg().WitnessKeys
	w["w2"] = f.e.second.Public().(ed25519.PublicKey)
	return w
}

// Check reports (a), (b) and (c) as heads this log did not produce and
// (d) as a record that disagrees with its signed head; the honest ones
// pass.
func TestCheckReportsForeignCosignatures(t *testing.T) {
	f := newForeignCosigStore(t)
	rep, err := Check(f.e.dir, "test-log", f.e.logKey.Public().(ed25519.PublicKey), CheckOptions{WitnessKeys: f.witnesses()})
	if err != nil {
		t.Fatal(err)
	}
	want := []NonconformingCosignature{
		{Index: 1, WitnessID: "w1", TreeSize: 2, Reason: "tree head was not produced by this log"},
		{Index: 2, WitnessID: "w1", TreeSize: 2, Reason: "tree head was not produced by this log"},
		{Index: 3, WitnessID: "w1", TreeSize: 99, Reason: "tree head was not produced by this log"},
		{Index: 4, WitnessID: "w2", TreeSize: 3, Reason: "cosignature record disagrees with its signed tree head: treeSize, rootHash"},
	}
	if rep.Cosignatures != 6 || *rep.NonconformingCosignatureCount != 4 || len(rep.NonconformingCosignatures) != 4 {
		t.Fatalf("report: %+v", rep)
	}
	for i, w := range want {
		if rep.NonconformingCosignatures[i] != w {
			t.Errorf("nonconforming %d: %+v, want %+v", i, rep.NonconformingCosignatures[i], w)
		}
	}
	// AddCosignature refuses (a), (b) and (c) with the same reason.
	l, err := Open(f.cfg())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, c := range f.recs[1:4] {
		if _, _, err := l.AddCosignature(c.WitnessID, c.STHCanonical, c.Signature, ""); !errors.Is(err, ErrForeignSTH) {
			t.Errorf("AddCosignature(%s): %v", c.STHCanonical, err)
		}
	}
}

func (f *foreignCosigStore) cfg() Config {
	c := f.e.cfg()
	c.WitnessKeys = f.witnesses()
	return c
}

// Open skips (a) to (d), with a warning, and still opens; it serves
// only the honest ones, each under the size its signed head names.
func TestOpenSkipsForeignCosignatures(t *testing.T) {
	f := newForeignCosigStore(t)
	var logs bytes.Buffer
	c := f.cfg()
	c.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	l, err := Open(c)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()
	if !strings.Contains(logs.String(), "skipping stored cosignatures that are not evidence of this log") ||
		!strings.Contains(logs.String(), "skipped=4") {
		t.Errorf("no warning: %s", logs.String())
	}
	all := l.Cosignatures(0, true)
	if len(all) != 2 || all[0] != f.recs[0] || all[1] != f.recs[5] {
		t.Fatalf("served: %+v", all)
	}
	for size, want := range map[uint64][]Cosignature{1: {f.recs[0]}, 2: {}, 3: {f.recs[5]}, 99: {}} {
		got := l.Cosignatures(size, false)
		if len(got) != len(want) || (len(want) == 1 && got[0] != want[0]) {
			t.Errorf("treeSize=%d: %+v, want %+v", size, got, want)
		}
	}
	// w2 can still record an honest cosignature of the head (d) named.
	canonical := f.recs[4].STHCanonical
	sig := sth.EncodeSignature(ed25519.Sign(f.e.second, []byte(canonical)))
	if n, rec, err := l.AddCosignature("w2", canonical, sig, ""); err != nil || !rec || n != 2 {
		t.Fatalf("honest w2 cosignature: %d %v %v", n, rec, err)
	}
	if got := l.Cosignatures(1, false); len(got) != 2 {
		t.Fatalf("treeSize=1 after: %+v", got)
	}
}

// An honest store's cosignatures are served exactly as before, after a
// reopen too.
func TestHonestCosignaturesServedAsBefore(t *testing.T) {
	e := newEnv(t)
	c := e.cfg()
	second := e.witness2(t)
	c.WitnessKeys["w2"] = second.Public().(ed25519.PublicKey)
	l, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		l.Append(e.receipt(t, i))
		head := l.STH()
		canonical, _ := head.Canonical()
		for id, k := range map[string]ed25519.PrivateKey{"w1": e.witness, "w2": second} {
			if i == 2 && id == "w2" {
				continue
			}
			if _, _, err := l.AddCosignature(id, string(canonical), sth.EncodeSignature(ed25519.Sign(k, canonical)), "https://"+id+".example/key.pem"); err != nil {
				t.Fatal(err)
			}
		}
	}
	snapshot := func(l *Log) string {
		var parts []any
		parts = append(parts, l.Cosignatures(0, true))
		for size := uint64(0); size <= 5; size++ {
			parts = append(parts, l.Cosignatures(size, false))
		}
		out, _ := json.Marshal(parts)
		return string(out)
	}
	before := snapshot(l)
	if n := len(l.Cosignatures(0, true)); n != 7 {
		t.Fatalf("%d cosignatures", n)
	}
	l.Close()
	if l, err = Open(c); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if after := snapshot(l); after != before {
		t.Fatalf("after reopen:\n%s\nbefore:\n%s", after, before)
	}
	rep, err := Check(e.dir, "test-log", e.logKey.Public().(ed25519.PublicKey), CheckOptions{WitnessKeys: c.WitnessKeys})
	if err != nil || rep.Cosignatures != 7 || *rep.NonconformingCosignatureCount != 0 {
		t.Fatalf("Check: %+v %v", rep, err)
	}
}

// AddCosignature's order: labels (400), the witness (403), the
// canonical form (400), whether the head is this log's (409), and only
// then the signature (422). A foreign head with a bad signature is a
// foreign head.
func TestAddCosignatureReasonOrder(t *testing.T) {
	e := newEnv(t)
	l := e.open(t)
	defer l.Close()
	l.Append(e.receipt(t, 0))
	head := l.STH()
	foreign := head
	foreign.LogID = "other-log"
	fc, _ := foreign.Canonical()
	badSig := sth.EncodeSignature(ed25519.Sign(testutil.Key(t), fc))
	cases := []struct {
		name               string
		witness, canonical string
		sig, url           string
		want               error
	}{
		{"bad witness label and unknown", "bad\nlabel", string(fc), badSig, "", ErrInvalidCosig},
		{"bad url and unknown witness", "w9", string(fc), badSig, "bad\nurl", ErrInvalidCosig},
		{"unknown witness, foreign head", "w9", string(fc), badSig, "", ErrUnknownWitness},
		{"non-canonical, bad signature", "w1", string(fc) + " ", badSig, "", ErrInvalidCosig},
		{"foreign head, bad signature", "w1", string(fc), badSig, "", ErrForeignSTH},
		{"foreign head, good signature", "w1", string(fc), sth.EncodeSignature(ed25519.Sign(e.witness, fc)), "", ErrForeignSTH},
	}
	for _, c := range cases {
		if _, _, err := l.AddCosignature(c.witness, c.canonical, c.sig, c.url); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	own, _ := head.Canonical()
	if _, _, err := l.AddCosignature("w1", string(own), sth.EncodeSignature(ed25519.Sign(testutil.Key(t), own)), ""); !errors.Is(err, ErrWitnessSignature) {
		t.Errorf("own head, bad signature: %v", err)
	}
}
