package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/christiaan839-beep/receipts-log/internal/keys"
	"github.com/christiaan839-beep/receipts-log/internal/store"
	"github.com/christiaan839-beep/receipts-log/internal/testutil"
	"github.com/christiaan839-beep/receipts-log/internal/translog"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// TestCLIEndToEnd generates keys with the CLI, serves a log, appends a
// receipt, proves it, witnesses the log twice and checks the data
// directory offline.
func TestCLIEndToEnd(t *testing.T) {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	for _, k := range []string{"log", "witness", "issuer"} {
		if code, _, e := runCLI(t, "keygen", "-out", p(k+".key"), "-pub", p(k+".pub")); code != 0 {
			t.Fatalf("keygen %s: %s", k, e)
		}
	}
	if code, out, _ := runCLI(t, "pubkey", "-key", p("log.key")); code != 0 || !strings.Contains(out, "PUBLIC KEY") {
		t.Fatal("pubkey")
	}
	issuer, _, err := keys.LoadPrivateKey(p("issuer.key"))
	if err != nil {
		t.Fatal(err)
	}
	receipt := testutil.Receipt(t, issuer, map[string]any{"runId": "cli-1", "overall": "pass"})
	os.WriteFile(p("r1.json"), receipt, 0o600)
	os.WriteFile(p("r2.json"), testutil.Receipt(t, issuer, map[string]any{"runId": "cli-2"}), 0o600)
	os.WriteFile(p("bad.json"), testutil.Receipt(t, testutil.Key(t), map[string]any{"runId": "x"}), 0o600)

	addr := freeAddr(t)
	base := "http://" + addr
	done := make(chan int, 1)
	var serveErr bytes.Buffer
	go func() {
		done <- run([]string{"serve", "-addr", addr, "-data", p("data"), "-log-id", "cli-log",
			"-log-key", p("log.key"), "-issuer-key", p("issuer.pub"),
			"-witness-key", "w1=" + p("witness.pub"), "-sth-interval", "0"}, &bytes.Buffer{}, &serveErr)
	}()
	for i := 0; ; i++ {
		resp, err := http.Get(base + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		if i > 100 {
			t.Fatalf("server did not start: %s", serveErr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	if code, out, e := runCLI(t, "append", "-url", base, "-file", p("r1.json")); code != 0 || !strings.Contains(out, `"index":0`) {
		t.Fatalf("append: %d %s %s", code, out, e)
	}
	if code, _, _ := runCLI(t, "append", "-url", base, "-file", p("bad.json")); code != 1 {
		t.Fatalf("append of an unsigned receipt: exit %d", code)
	}
	if code, out, e := runCLI(t, "sth", "-url", base, "-log-public-key", p("log.pub")); code != 0 || !strings.Contains(out, `"treeSize": 1`) {
		t.Fatalf("sth: %d %s %s", code, out, e)
	}
	if code, _, _ := runCLI(t, "sth", "-url", base, "-log-public-key", p("issuer.pub")); code != 1 {
		t.Fatal("sth verified under the wrong key")
	}
	if code, out, e := runCLI(t, "prove", "-url", base, "-file", p("r1.json"), "-log-public-key", p("log.pub")); code != 0 || !strings.Contains(out, `"included": true`) {
		t.Fatalf("prove: %d %s %s", code, out, e)
	}
	if code, _, _ := runCLI(t, "prove", "-url", base, "-file", p("r2.json"), "-log-public-key", p("log.pub")); code != 1 {
		t.Fatal("prove of an absent receipt did not fail")
	}
	if code, _, _ := runCLI(t, "prove", "-url", base, "-file", p("r1.json"), "-log-public-key", p("issuer.pub")); code != 1 {
		t.Fatalf("prove under the wrong log key: exit %d, want 1", code)
	}

	wargs := []string{"witness", "-url", base, "-key", p("witness.key"), "-witness-id", "w1",
		"-log-public-key", p("log.pub"), "-state", p("wstate.json"), "-once", "-json"}
	code, out, e := runCLI(t, wargs...)
	if code != 0 || !strings.Contains(out, `"verdict":"witnessed"`) {
		t.Fatalf("witness: %d %s %s", code, out, e)
	}
	runCLI(t, "append", "-url", base, "-file", p("r2.json"))
	code, out, _ = runCLI(t, wargs...)
	var res map[string]any
	json.Unmarshal([]byte(out), &res)
	if code != 0 || res["verdict"] != "witnessed" || res["oldSize"] != float64(1) || res["treeSize"] != float64(2) {
		t.Fatalf("second witness: %d %s", code, out)
	}
	code, out, _ = runCLI(t, wargs...)
	if code != 0 || !strings.Contains(out, "no-change") {
		t.Fatalf("third witness: %d %s", code, out)
	}

	// Stop the server and check the directory offline.
	syscall.Kill(os.Getpid(), syscall.SIGTERM)
	select {
	case c := <-done:
		if c != 0 {
			t.Fatalf("serve exited %d: %s", c, serveErr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
	if !strings.Contains(serveErr.String(), `"msg":"entry appended"`) {
		t.Fatalf("no structured log lines: %s", serveErr.String())
	}
	checkArgs := []string{"check", "-data", p("data"), "-log-id", "cli-log", "-log-public-key", p("log.pub")}
	code, out, e = runCLI(t, checkArgs...)
	if code != 0 || !strings.Contains(out, `"entries": 2`) {
		t.Fatalf("check: %d %s %s", code, out, e)
	}
	if strings.Contains(out, "issuerKeys") || strings.Contains(out, "onconforming") {
		t.Fatalf("check without -issuer-key re-verified receipts: %s", out)
	}
	withKey := append(append([]string{}, checkArgs...), "-issuer-key", p("issuer.pub"))
	code, out, e = runCLI(t, withKey...)
	if code != 0 || !strings.Contains(out, `"issuerKeys": 1`) || strings.Contains(out, "onconforming") {
		t.Fatalf("check -issuer-key of valid receipts: %d %s %s", code, out, e)
	}

	// A receipt with "contentHash": "" that an older build admitted.
	var m map[string]any
	json.Unmarshal(testutil.Receipt(t, issuer, map[string]any{"runId": "cli-3"}), &m)
	m["contentHash"] = ""
	old, _ := json.Marshal(m)
	writeUnverified(t, p("data"), "cli-log", p("log.key"), old)

	code, out, e = runCLI(t, checkArgs...)
	if code != 0 || !strings.Contains(out, `"entries": 3`) || strings.Contains(out, "onconforming") {
		t.Fatalf("check without -issuer-key after an old admission: %d %s %s", code, out, e)
	}
	code, out, e = runCLI(t, withKey...)
	if code != 3 || !strings.Contains(out, `"nonconformingCount": 1`) ||
		!strings.Contains(out, `"index": 2`) || !strings.Contains(out, "contentHash mismatch") {
		t.Fatalf("check -issuer-key after an old admission: %d %s %s", code, out, e)
	}
	// Corruption comes first: it is exit 1 even with nonconforming entries.
	path := filepath.Join(p("data"), store.EntriesFile)
	raw, _ := os.ReadFile(path)
	raw[len(raw)-10] ^= 1
	os.WriteFile(path, raw, 0o600)
	if code, out, e = runCLI(t, withKey...); code != 1 {
		t.Fatalf("check -issuer-key of a corrupt store: %d %s %s", code, out, e)
	}
}

// writeUnverified appends bodies to the store in dir without verifying
// them, as a build with older admission rules could have, and opens the
// log once so it signs a checkpoint over them.
func writeUnverified(t *testing.T, dir, logID, logKey string, bodies ...[]byte) {
	t.Helper()
	st, err := store.Open(store.Options{Dir: dir}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bodies {
		leaf, err := translog.LeafForReceipt(b)
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
	key, _, err := keys.LoadPrivateKey(logKey)
	if err != nil {
		t.Fatal(err)
	}
	l, err := translog.Open(translog.Config{Dir: dir, LogID: logID, Key: key,
		IssuerKeys: []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
}

func TestCLIUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"nope"},
		{"serve"},
		{"witness"},
		{"keygen"},
		{"prove"},
		{"check"},
		{"serve", "-data", "x", "-log-id", "y", "-log-key", "/does/not/exist", "-issuer-key", "z"},
		{"check", "-data", "x", "-log-id", "y", "-log-public-key", "../../testdata/conformance/public-key.pem", "-issuer-key", "/does/not/exist"},
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code, _, _ := runCLI(t, "version"); code != 0 {
		t.Fatal("version")
	}
	if code, out, _ := runCLI(t, "help"); code != 0 || !strings.Contains(out, "-issuer-key FILE") ||
		!strings.Contains(out, "3 check found") {
		t.Fatalf("help does not document check -issuer-key and exit 3: %s", out)
	}
	if code, _, _ := runCLI(t, "serve", "-h"); code != 0 {
		t.Fatal("serve -h")
	}
}

func TestDefaultStatePath(t *testing.T) {
	for _, id := range []string{"EU Witness · Berlin/../x", "..", "../../etc/passwd"} {
		p := defaultStatePath(id)
		if filepath.Base(filepath.Dir(p)) != ".sovereign-witness" || !strings.HasSuffix(p, ".json") {
			t.Fatalf("state path %q escapes its directory", p)
		}
	}
}
