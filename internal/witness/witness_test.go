package witness

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/christiaan839-beep/receipts-log/internal/server"
	"github.com/christiaan839-beep/receipts-log/internal/testutil"
	"github.com/christiaan839-beep/receipts-log/internal/translog"
)

type logEnv struct {
	log    *translog.Log
	issuer ed25519.PrivateKey
}

// newLog starts a log server whose handler can be swapped, so a test can
// replace the log behind one URL (a fork).
func newLog(t *testing.T, logKey ed25519.PrivateKey, witness ed25519.PublicKey, handler *atomic.Value) *logEnv {
	t.Helper()
	issuer := testutil.Key(t)
	l, err := translog.Open(translog.Config{
		Dir: t.TempDir(), LogID: "test-log", Key: logKey,
		IssuerKeys:  []ed25519.PublicKey{issuer.Public().(ed25519.PublicKey)},
		WitnessKeys: map[string]ed25519.PublicKey{"w1": witness},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.New(l, server.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	handler.Store(s.Handler())
	return &logEnv{log: l, issuer: issuer}
}

func (e *logEnv) add(t *testing.T, tag string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := e.log.Append(testutil.Receipt(t, e.issuer, map[string]any{"id": fmt.Sprintf("%s-%d-%d", tag, e.log.STH().TreeSize, i)})); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWitnessFlow(t *testing.T) {
	logKey, wKey := testutil.Key(t), testutil.Key(t)
	var h atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Load().(http.Handler).ServeHTTP(w, r)
	}))
	defer srv.Close()
	a := newLog(t, logKey, wKey.Public().(ed25519.PublicKey), &h)
	a.add(t, "a", 3)

	cfg := Config{BaseURL: srv.URL, WitnessID: "w1", Key: wKey, LogKey: logKey.Public().(ed25519.PublicKey),
		StatePath: filepath.Join(t.TempDir(), "state", "w1.json")}
	ctx := context.Background()
	run := func(want string) Result {
		t.Helper()
		r, err := RunOnce(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if r.Verdict != want {
			t.Fatalf("verdict %q (%s), want %q", r.Verdict, r.Reason, want)
		}
		return r
	}
	if r := run(Witnessed); r.WitnessCount != 1 || r.TreeSize != 3 {
		t.Fatalf("%+v", r)
	}
	if st, _ := os.Stat(cfg.StatePath); st.Mode().Perm() != 0o600 {
		t.Fatal("state file mode")
	}
	run(NoChange)
	a.add(t, "a", 5)
	if r := run(Witnessed); r.OldSize != 3 || r.TreeSize != 8 {
		t.Fatalf("%+v", r)
	}
	if got := a.log.Cosignatures(8, false); len(got) != 1 {
		t.Fatalf("cosignatures at 8: %d", len(got))
	}

	// Fork: the same key and log ID serve a different history.
	b := newLog(t, logKey, wKey.Public().(ed25519.PublicKey), &h)
	b.add(t, "b", 8)
	run(Fork) // same size, different root
	b.add(t, "b", 4)
	run(Fork) // bigger, but not an extension
	b2 := newLog(t, logKey, wKey.Public().(ed25519.PublicKey), &h)
	b2.add(t, "c", 2)
	run(Fork) // smaller

	// Back to the honest log: still consistent with the saved state.
	h.Store(mustHandler(t, a.log))
	a.add(t, "a", 1)
	run(Witnessed)
}

func mustHandler(t *testing.T, l *translog.Log) http.Handler {
	s, err := server.New(l, server.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

func TestWitnessRejectsBadInput(t *testing.T) {
	logKey, wKey := testutil.Key(t), testutil.Key(t)
	var h atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Load().(http.Handler).ServeHTTP(w, r)
	}))
	defer srv.Close()
	a := newLog(t, logKey, wKey.Public().(ed25519.PublicKey), &h)
	a.add(t, "a", 2)
	dir := t.TempDir()
	cfg := Config{BaseURL: srv.URL, WitnessID: "w1", Key: wKey, LogKey: testutil.Key(t).Public().(ed25519.PublicKey),
		StatePath: filepath.Join(dir, "s.json")}
	if _, err := RunOnce(context.Background(), cfg); err == nil {
		t.Fatal("tree head under the wrong log key accepted")
	}
	// A log key of mixed order (ed25519-key-mixed-order-8.json) is refused
	// before anything is fetched (VAOS 2.0 section 7.3).
	mixed, _ := hex.DecodeString("1fbeffcfb79db7951f9b8741c150f5d3e944455794cda3e7c5b81a99ecec3c85")
	cfg.LogKey = mixed
	if _, err := RunOnce(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "public key is not in the prime-order subgroup") {
		t.Fatalf("mixed-order log key: %v", err)
	}
	// A witness key whose public half does not match its seed: its
	// cosignature would not verify, so the witness does not send it.
	cfg.LogKey = logKey.Public().(ed25519.PublicKey)
	cfg.Key = append(append(ed25519.PrivateKey{}, wKey.Seed()...), testutil.Key(t).Public().(ed25519.PublicKey)...)
	if _, err := RunOnce(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("inconsistent witness key: %v", err)
	}
	if _, err := os.Stat(cfg.StatePath); err == nil {
		t.Fatal("state saved although nothing was cosigned")
	}
	cfg.Key = wKey
	cfg.LogKey = logKey.Public().(ed25519.PublicKey)
	os.WriteFile(cfg.StatePath, []byte("{not json"), 0o600)
	if _, err := RunOnce(context.Background(), cfg); err == nil {
		t.Fatal("corrupt state treated as first run")
	}
	os.Remove(cfg.StatePath)
	cfg.WitnessID = "unknown"
	if _, err := RunOnce(context.Background(), cfg); err == nil {
		t.Fatal("submission refused by the log was reported as success")
	}
	if _, err := os.Stat(cfg.StatePath); err == nil {
		t.Fatal("state saved although the submission failed")
	}
	cfg.BaseURL = "ftp://x"
	if _, err := RunOnce(context.Background(), cfg); err == nil {
		t.Fatal("non-http URL accepted")
	}
	// A server that returns garbage.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"v":1,"logId":"x","treeSize":"many"}`))
	}))
	defer bad.Close()
	cfg.BaseURL, cfg.WitnessID = bad.URL, "w1"
	if _, err := RunOnce(context.Background(), cfg); err == nil {
		t.Fatal("malformed tree head accepted")
	}
	// State for another log.
	cfg.BaseURL = srv.URL
	SaveState(cfg.StatePath, State{LogID: "other", LastSize: 1, LastRoot: a.log.STH().RootHash})
	if _, err := RunOnce(context.Background(), cfg); err == nil {
		t.Fatal("state for another log accepted")
	}
}

// A consistency proof the server tampers with is a fork.
func TestWitnessDetectsBadProof(t *testing.T) {
	logKey, wKey := testutil.Key(t), testutil.Key(t)
	var h atomic.Value
	a := newLog(t, logKey, wKey.Public().(ed25519.PublicKey), &h)
	a.add(t, "a", 3)
	tamper := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tamper.Load() && r.URL.Path == "/api/transparency/proof" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"proof":["` + a.log.STH().RootHash + `"]}`))
			return
		}
		h.Load().(http.Handler).ServeHTTP(w, r)
	}))
	defer srv.Close()
	cfg := Config{BaseURL: srv.URL, WitnessID: "w1", Key: wKey, LogKey: logKey.Public().(ed25519.PublicKey),
		StatePath: filepath.Join(t.TempDir(), "s.json")}
	if r, err := RunOnce(context.Background(), cfg); err != nil || r.Verdict != Witnessed {
		t.Fatal(r, err)
	}
	a.add(t, "a", 2)
	tamper.Store(true)
	if r, err := RunOnce(context.Background(), cfg); err != nil || r.Verdict != Fork {
		t.Fatalf("%+v %v", r, err)
	}
}
