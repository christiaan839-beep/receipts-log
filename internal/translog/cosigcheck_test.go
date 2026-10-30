package translog

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/christiaan839-beep/receipts-log/internal/sth"
	"github.com/christiaan839-beep/receipts-log/internal/store"
	"github.com/christiaan839-beep/receipts-log/internal/testutil"
)

// writeCosignatures appends cosignature lines to the store without the
// log, as an older build that did not verify them as strictly would
// have recorded them.
func writeCosignatures(t *testing.T, dir string, cs ...Cosignature) {
	t.Helper()
	st, err := store.Open(store.Options{Dir: dir}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		line, _ := json.Marshal(c)
		if err := st.AppendCosignature(line); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
}

// Check with witness keys reports each stored cosignature the log would
// refuse today; Open still loads them; without witness keys Check does
// not look at them.
func TestCheckReverifiesCosignatures(t *testing.T) {
	e := newEnv(t)
	l := e.open(t)
	var heads []sth.STH
	for i := 0; i < 3; i++ {
		l.Append(e.receipt(t, i))
		heads = append(heads, l.STH())
	}
	canonical := func(h sth.STH) []byte { c, _ := h.Canonical(); return c }
	c1 := canonical(heads[0])
	if _, _, err := l.AddCosignature("w1", string(c1), sth.EncodeSignature(ed25519.Sign(e.witness, c1)), ""); err != nil {
		t.Fatal(err)
	}
	l.Close()
	rec := func(id string, h sth.STH, sig []byte) Cosignature {
		return Cosignature{WitnessID: id, TreeSize: h.TreeSize, RootHash: h.RootHash,
			Timestamp: h.Timestamp, STHCanonical: string(canonical(h)), Signature: sth.EncodeSignature(sig), ReceivedAt: h.Timestamp}
	}
	writeCosignatures(t, e.dir,
		rec("w1", heads[1], testutil.IdentityRSignature(e.witness, canonical(heads[1]))),
		rec("w2", heads[1], ed25519.Sign(testutil.Key(t), canonical(heads[1]))),
		rec("w1", heads[2], ed25519.Sign(testutil.Key(t), canonical(heads[2]))),
	)
	l = e.open(t)
	if got := l.Cosignatures(0, true); len(got) != 4 {
		t.Fatalf("Open loaded %d cosignatures", len(got))
	}
	l.Close()

	pub := e.logKey.Public().(ed25519.PublicKey)
	witnesses := e.cfg().WitnessKeys
	rep, err := Check(e.dir, "test-log", pub, CheckOptions{WitnessKeys: witnesses})
	if err != nil {
		t.Fatal(err)
	}
	if rep.WitnessKeys != 1 || rep.Cosignatures != 4 || rep.NonconformingCosignatureCount == nil ||
		*rep.NonconformingCosignatureCount != 3 || rep.NonconformingCount != nil {
		t.Fatalf("report: %+v", rep)
	}
	want := []NonconformingCosignature{
		{Index: 1, WitnessID: "w1", TreeSize: 2, Reason: "witness signature does not verify: signature R is a small-order point"},
		{Index: 2, WitnessID: "w2", TreeSize: 2, Reason: "witness is not configured on this log"},
		{Index: 3, WitnessID: "w1", TreeSize: 3, Reason: "witness signature does not verify: signature does not verify under the supplied public key"},
	}
	for i, w := range want {
		if rep.NonconformingCosignatures[i] != w {
			t.Errorf("nonconforming cosignature %d: %+v, want %+v", i, rep.NonconformingCosignatures[i], w)
		}
	}
	// The same reasons as a submission of each gets today.
	l = e.open(t)
	lines := splitLines(mustRead(t, filepath.Join(e.dir, store.CosignaturesFile)))
	for _, w := range want {
		var stored Cosignature
		json.Unmarshal(lines[w.Index], &stored)
		if _, _, err := l.AddCosignature(stored.WitnessID, stored.STHCanonical, stored.Signature, ""); err == nil || err.Error() != w.Reason {
			t.Errorf("AddCosignature of cosignature %d: %v, want %q", w.Index, err, w.Reason)
		}
	}
	l.Close()

	rep, err = Check(e.dir, "test-log", pub, CheckOptions{WitnessKeys: witnesses, NonconformingLimit: 1})
	if err != nil || *rep.NonconformingCosignatureCount != 3 || len(rep.NonconformingCosignatures) != 1 {
		t.Fatalf("capped: %+v %v", rep, err)
	}
	rep, err = Check(e.dir, "test-log", pub, CheckOptions{})
	if err != nil || rep.WitnessKeys != 0 || rep.NonconformingCosignatureCount != nil || rep.NonconformingCosignatures != nil {
		t.Fatalf("without witness keys: %+v %v", rep, err)
	}
	out, _ := json.Marshal(rep)
	var fields map[string]any
	json.Unmarshal(out, &fields)
	for _, k := range []string{"witnessKeys", "cosignatures", "nonconformingCosignatureCount", "nonconformingCosignatures"} {
		if _, ok := fields[k]; ok {
			t.Errorf("without witness keys the report has %q", k)
		}
	}

	// A weak witness key is refused, as Open refuses it.
	if _, err := Check(e.dir, "test-log", pub, CheckOptions{
		WitnessKeys: map[string]ed25519.PublicKey{"w1": make(ed25519.PublicKey, 32)}}); err == nil {
		t.Fatal("Check accepted a small-order witness key")
	}
}

// Every cosignature passing gives a count of 0; a torn last line is
// skipped, not repaired; a line that is not JSON is corruption.
func TestCheckCosignaturesIntactAndCorrupt(t *testing.T) {
	e := newEnv(t)
	l := e.open(t)
	l.Append(e.receipt(t, 0))
	c, _ := l.STH().Canonical()
	if _, _, err := l.AddCosignature("w1", string(c), sth.EncodeSignature(ed25519.Sign(e.witness, c)), ""); err != nil {
		t.Fatal(err)
	}
	l.Close()
	pub := e.logKey.Public().(ed25519.PublicKey)
	opts := CheckOptions{WitnessKeys: e.cfg().WitnessKeys}
	path := filepath.Join(e.dir, store.CosignaturesFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"witnessId":"w1","tree`)
	f.Close()
	before, _ := os.ReadFile(path)
	rep, err := Check(e.dir, "test-log", pub, opts)
	if err != nil || rep.Cosignatures != 1 || *rep.NonconformingCosignatureCount != 0 || len(rep.NonconformingCosignatures) != 0 {
		t.Fatalf("intact: %+v %v", rep, err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("Check changed the cosignature file")
	}
	os.WriteFile(path, append(before[:len(before)-len(`{"witnessId":"w1","tree`)], "not json\n"...), 0o600)
	if _, err := Check(e.dir, "test-log", pub, opts); !errors.Is(err, store.ErrCorrupt) {
		t.Fatalf("corrupt line: %v", err)
	}
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	for len(data) > 0 {
		i := 0
		for i < len(data) && data[i] != '\n' {
			i++
		}
		out = append(out, data[:i])
		if i < len(data) {
			i++
		}
		data = data[i:]
	}
	return out
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
