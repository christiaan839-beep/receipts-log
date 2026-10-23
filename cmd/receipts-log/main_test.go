package main

import (
	"bytes"
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
	"github.com/christiaan839-beep/receipts-log/internal/testutil"
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
	code, out, e = runCLI(t, "check", "-data", p("data"), "-log-id", "cli-log", "-log-public-key", p("log.pub"))
	if code != 0 || !strings.Contains(out, `"entries": 2`) {
		t.Fatalf("check: %d %s %s", code, out, e)
	}
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
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code, _, _ := runCLI(t, "version"); code != 0 {
		t.Fatal("version")
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
