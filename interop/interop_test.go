// Package interop checks this log against a checkout of
// verifiable-receipts: its TypeScript, Python and Go verifiers, its
// Python signer, its witness CLI and its TypeScript log.
//
// Set VERIFIABLE_RECEIPTS_DIR to the checkout and have node (22.6 or
// later, for type stripping), python3 with the cryptography package, and
// go on PATH. Without VERIFIABLE_RECEIPTS_DIR the tests are skipped.
package interop

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/christiaan839-beep/receipts-log/internal/keys"
	"github.com/christiaan839-beep/receipts-log/internal/merkle"
	"github.com/christiaan839-beep/receipts-log/internal/server"
	"github.com/christiaan839-beep/receipts-log/internal/sth"
	"github.com/christiaan839-beep/receipts-log/internal/testutil"
	"github.com/christiaan839-beep/receipts-log/internal/translog"
	"github.com/christiaan839-beep/receipts-log/internal/witness"
)

func checkout(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("VERIFIABLE_RECEIPTS_DIR")
	if dir == "" {
		t.Skip("VERIFIABLE_RECEIPTS_DIR is not set")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"node", "python3", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required for the interop tests", tool)
		}
	}
	return abs
}

func runTool(t *testing.T, stdin []byte, name string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(name, args...)
	// The tool's temporary files go in a directory the test removes.
	cmd.Env = append(os.Environ(), "TMPDIR="+t.TempDir())
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, stderr.String())
	}
	return out
}

type keySet struct {
	dir                   string
	log, issuer, wGo, wTS ed25519.PrivateKey
	logPEM, issuerPEM     string
	issuerPath, wTSPath   string
	logPath               string
}

func makeKeys(t *testing.T) *keySet {
	ks := &keySet{dir: t.TempDir()}
	gen := func(name string) (ed25519.PrivateKey, string) {
		p := filepath.Join(ks.dir, name+".pem")
		k, err := keys.Generate(p)
		if err != nil {
			t.Fatal(err)
		}
		return k, p
	}
	ks.log, ks.logPath = gen("log")
	ks.issuer, ks.issuerPath = gen("issuer")
	ks.wGo, _ = gen("w-go")
	ks.wTS, ks.wTSPath = gen("w-ts")
	lp, _ := keys.PublicKeyPEM(ks.log.Public().(ed25519.PublicKey))
	ip, _ := keys.PublicKeyPEM(ks.issuer.Public().(ed25519.PublicKey))
	ks.logPEM, ks.issuerPEM = string(lp), string(ip)
	return ks
}

func openLog(t *testing.T, ks *keySet, logID string) *translog.Log {
	l, err := translog.Open(translog.Config{
		Dir: t.TempDir(), LogID: logID, Key: ks.log,
		IssuerKeys: []ed25519.PublicKey{ks.issuer.Public().(ed25519.PublicKey)},
		WitnessKeys: map[string]ed25519.PublicKey{
			"w-go": ks.wGo.Public().(ed25519.PublicKey),
			"w-ts": ks.wTS.Public().(ed25519.PublicKey),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func handlerFor(t *testing.T, l *translog.Log) http.Handler {
	s, err := server.New(l, server.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

func getJSON(t *testing.T, url string, out any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

type inclusion struct {
	LeafHashHex string   `json:"leafHashHex"`
	LeafIndex   int      `json:"leafIndex"`
	TreeSize    int      `json:"treeSize"`
	AuditPath   []string `json:"auditPath"`
	RootHashHex string   `json:"rootHashHex"`
}

type consistency struct {
	OldSize    int      `json:"oldSize"`
	NewSize    int      `json:"newSize"`
	OldRootHex string   `json:"oldRootHex"`
	NewRootHex string   `json:"newRootHex"`
	Proof      []string `json:"proof"`
}

func flipHex(s string) string {
	b := []byte(s)
	if b[0] == '0' {
		b[0] = '1'
	} else {
		b[0] = '0'
	}
	return string(b)
}

// TestProofsAcrossLanguages: receipts signed by the Python signer are
// admitted; every inclusion proof this server serves verifies in the
// TypeScript, Python and Go verifiers, and every consistency proof in the
// TypeScript verifier; tampered proofs fail in all of them; the
// TypeScript implementation builds the same roots and proofs from the
// same leaves; and the TypeScript canonicalizeSth and node's Ed25519
// verify accept this server's tree heads.
func TestProofsAcrossLanguages(t *testing.T) {
	repo := checkout(t)
	ks := makeKeys(t)
	const n = 13
	signed := runTool(t, nil, "python3", "-I", "py-tool.py", repo, "sign", ks.issuerPath, fmt.Sprint(n))
	var receipts []json.RawMessage
	sc := bufio.NewScanner(bytes.NewReader(signed))
	for sc.Scan() {
		receipts = append(receipts, json.RawMessage(append([]byte(nil), sc.Bytes()...)))
	}
	if len(receipts) != n {
		t.Fatalf("python signed %d receipts", len(receipts))
	}

	l := openLog(t, ks, "interop-log")
	srv := httptest.NewServer(handlerFor(t, l))
	defer srv.Close()
	var heads []sth.Response
	for i, r := range receipts {
		resp, err := http.Post(srv.URL+"/v1/entries", "application/json", bytes.NewReader(r))
		if err != nil {
			t.Fatal(err)
		}
		var ar struct {
			Index uint64       `json:"index"`
			STH   sth.Response `json:"sth"`
		}
		json.NewDecoder(resp.Body).Decode(&ar)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated || ar.Index != uint64(i) {
			t.Fatalf("python-signed receipt %d refused: HTTP %d", i, resp.StatusCode)
		}
		heads = append(heads, ar.STH)
	}

	var leaves []string
	var stored []json.RawMessage
	for i := 0; i < n; i++ {
		var e struct {
			LeafHash string          `json:"leafHash"`
			Receipt  json.RawMessage `json:"receipt"`
		}
		getJSON(t, fmt.Sprintf("%s/v1/entries/%d", srv.URL, i), &e)
		leaves = append(leaves, e.LeafHash)
		stored = append(stored, e.Receipt)
	}

	var good, bad []inclusion
	for size := 1; size <= n; size++ {
		for i := 0; i < size; i++ {
			var p inclusion
			getJSON(t, fmt.Sprintf("%s/v1/proof/inclusion?index=%d&treeSize=%d", srv.URL, i, size), &p)
			good = append(good, p)
			q := p
			q.RootHashHex = flipHex(p.RootHashHex)
			bad = append(bad, q)
			if len(p.AuditPath) > 0 {
				q = p
				q.AuditPath = append([]string(nil), p.AuditPath...)
				q.AuditPath[len(q.AuditPath)-1] = flipHex(q.AuditPath[len(q.AuditPath)-1])
				bad = append(bad, q)
			}
		}
	}
	var cGood, cBad []consistency
	for size := 1; size <= n; size++ {
		for old := 0; old <= size; old++ {
			var c consistency
			getJSON(t, fmt.Sprintf("%s/v1/proof/consistency?old=%d&new=%d", srv.URL, old, size), &c)
			cGood = append(cGood, c)
			if len(c.Proof) > 0 {
				d := c
				d.Proof = append([]string(nil), c.Proof...)
				d.Proof[0] = flipHex(d.Proof[0])
				cBad = append(cBad, d)
			}
			if old > 0 && old < size {
				d := c
				d.NewRootHex = flipHex(c.NewRootHex)
				cBad = append(cBad, d)
			}
		}
	}
	allIncl := append(append([]inclusion(nil), good...), bad...)
	allCons := append(append([]consistency(nil), cGood...), cBad...)
	var sths []sth.STH
	for _, h := range heads {
		sths = append(sths, h.STH)
	}

	expectAll := func(who string, got []bool, nGood int) {
		t.Helper()
		if len(got) != len(allIncl) && len(got) != len(allCons) {
			t.Fatalf("%s: %d results", who, len(got))
		}
		for i, ok := range got {
			if want := i < nGood; ok != want {
				t.Errorf("%s: result %d = %v, want %v", who, i, ok, want)
			}
		}
	}

	// TypeScript.
	job, _ := json.Marshal(map[string]any{"leaves": leaves, "inclusion": allIncl, "consistency": allCons,
		"sths": sths, "logPublicKeyPem": ks.logPEM})
	var ts struct {
		Roots           []string `json:"roots"`
		InclusionProofs []struct {
			I, N  int
			Proof []string
		} `json:"inclusionProofs"`
		ConsistencyProofs []struct {
			M, N  int
			Proof []string
		} `json:"consistencyProofs"`
		Inclusion   []bool `json:"inclusion"`
		Consistency []bool `json:"consistency"`
		STHs        []struct {
			Canonical   string `json:"canonical"`
			SignatureOK *bool  `json:"signatureOk"`
		} `json:"sths"`
	}
	if err := json.Unmarshal(runTool(t, job, "node", "ts-tool.mjs", repo), &ts); err != nil {
		t.Fatal(err)
	}
	expectAll("TypeScript verifyInclusionProof", ts.Inclusion, len(good))
	expectAll("TypeScript verifyConsistencyProof", ts.Consistency, len(cGood))
	for i, h := range heads {
		if ts.STHs[i].Canonical != h.Canonical {
			t.Errorf("STH %d: TypeScript canonical %s, server %s", i, ts.STHs[i].Canonical, h.Canonical)
		}
		if ts.STHs[i].SignatureOK == nil || !*ts.STHs[i].SignatureOK {
			t.Errorf("STH %d: node's Ed25519 verify rejects the signature", i)
		}
		if ts.Roots[i+1] != h.RootHash {
			t.Errorf("TypeScript treeRoot at %d = %s, server %s", i+1, ts.Roots[i+1], h.RootHash)
		}
	}
	if ts.Roots[0] != merkle.EmptyRoot().String() {
		t.Error("empty root differs")
	}
	k := 0
	for _, p := range ts.InclusionProofs {
		if strings.Join(p.Proof, ",") != strings.Join(good[k].AuditPath, ",") {
			t.Errorf("TypeScript inclusionProof(%d, %d) differs from the server's", p.I, p.N)
		}
		k++
	}
	for k, p := range ts.ConsistencyProofs {
		if strings.Join(p.Proof, ",") != strings.Join(cGood[k].Proof, ",") {
			t.Errorf("TypeScript consistencyProof(%d, %d) differs from the server's", p.M, p.N)
		}
		// And this repository's verifier accepts the TypeScript proof.
		proof, _ := merkle.ParseHashes(p.Proof)
		o, _ := merkle.ParseHash(ts.Roots[p.M])
		nr, _ := merkle.ParseHash(ts.Roots[p.N])
		if err := merkle.VerifyConsistency(uint64(p.M), uint64(p.N), o, nr, proof); err != nil {
			t.Errorf("Go rejects TypeScript consistencyProof(%d, %d): %v", p.M, p.N, err)
		}
	}
	t.Logf("TypeScript: %d inclusion and %d consistency verdicts, %d tree heads, %d roots and %d+%d proofs compared",
		len(ts.Inclusion), len(ts.Consistency), len(ts.STHs), len(ts.Roots), len(ts.InclusionProofs), len(ts.ConsistencyProofs))

	// Python.
	pyJob, _ := json.Marshal(map[string]any{"inclusion": allIncl, "receipts": stored, "issuerPublicKeyPem": ks.issuerPEM})
	var py struct {
		Inclusion []bool `json:"inclusion"`
		Receipts  []bool `json:"receipts"`
	}
	if err := json.Unmarshal(runTool(t, pyJob, "python3", "-I", "py-tool.py", repo, "verify"), &py); err != nil {
		t.Fatal(err)
	}
	expectAll("Python verify_inclusion_proof", py.Inclusion, len(good))
	for i, ok := range py.Receipts {
		if !ok {
			t.Errorf("Python rejects stored entry %d", i)
		}
	}
	t.Logf("Python: %d inclusion verdicts, %d stored receipts verified", len(py.Inclusion), len(py.Receipts))

	// Go (the published package, through a replace directive).
	goDir := t.TempDir()
	src, _ := os.ReadFile("go-vaos/main.go.txt")
	os.WriteFile(filepath.Join(goDir, "main.go"), src, 0o600)
	mod := "module interop/govaos\n\ngo 1.22\n\nrequire github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go v0.0.0\n\n" +
		"replace github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go => " +
		filepath.Join(repo, "packages/verifiable-receipts-go") + "\n"
	os.WriteFile(filepath.Join(goDir, "go.mod"), []byte(mod), 0o600)
	build := exec.Command("go", "build", "-o", filepath.Join(goDir, "govaos"), ".")
	build.Dir = goDir
	build.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build go-vaos: %v\n%s", err, out)
	}
	var gv struct {
		Inclusion []bool `json:"inclusion"`
		Receipts  []bool `json:"receipts"`
	}
	if err := json.Unmarshal(runTool(t, pyJob, filepath.Join(goDir, "govaos")), &gv); err != nil {
		t.Fatal(err)
	}
	expectAll("Go VerifyInclusionProof", gv.Inclusion, len(good))
	for i, ok := range gv.Receipts {
		if !ok {
			t.Errorf("Go VerifyV2Receipt rejects stored entry %d", i)
		}
	}
	t.Logf("Go: %d inclusion verdicts, %d stored receipts verified", len(gv.Inclusion), len(gv.Receipts))
}

// TestTypeScriptWitnessAgainstThisLog runs bin/witness.mjs against this
// server, with --log-id and --log-public-key: it witnesses the empty tree
// (whose root must be SHA-256 of no bytes) and every STH field passes its
// shape check, it sees growth as consistent, it refuses another logId,
// and it exits 1 on a fork.
func TestTypeScriptWitnessAgainstThisLog(t *testing.T) {
	repo := checkout(t)
	ks := makeKeys(t)
	honest := openLog(t, ks, "interop-log")
	var h atomic.Value
	h.Store(handlerFor(t, honest))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Load().(http.Handler).ServeHTTP(w, r)
	}))
	defer srv.Close()
	add := func(l *translog.Log, tag string, count int) {
		for i := 0; i < count; i++ {
			body := map[string]any{"id": fmt.Sprintf("%s-%d-%d", tag, l.STH().TreeSize, i)}
			if _, err := l.Append(testutil.Receipt(t, ks.issuer, body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	logPub := filepath.Join(ks.dir, "log.pub")
	if err := os.WriteFile(logPub, []byte(ks.logPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "ts-witness.json")
	// witnessRun returns the exit code, the last JSON line on stdout, and
	// stdout and stderr for a failure message.
	witnessRun := func(extra ...string) (int, map[string]any, string) {
		args := []string{"run-ts-witness.sh", repo, "--url", srv.URL, "--key", ks.wTSPath,
			"--witness-id", "w-ts", "--state", state, "--log-public-key", logPub,
			"--timeout", "20", "--once", "--json"}
		if len(extra) == 0 {
			extra = []string{"--log-id", "interop-log"}
		}
		cmd := exec.Command("bash", append(args, extra...)...)
		cmd.Env = append(os.Environ(), "TMPDIR="+t.TempDir())
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		var res map[string]any
		lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
		json.Unmarshal([]byte(lines[len(lines)-1]), &res)
		out := "stdout: " + stdout.String() + "stderr: " + stderr.String()
		if code == 2 {
			t.Fatalf("witness.mjs usage/network error: %s", out)
		}
		return code, res, out
	}
	if code, res, out := witnessRun(); code != 0 || res["verdict"] != "witnessed" || res["treeSize"] != float64(0) {
		t.Fatalf("empty tree: %d %v\n%s", code, res, out)
	}
	add(honest, "a", 4)
	if code, res, out := witnessRun(); code != 0 || res["verdict"] != "witnessed" || res["treeSize"] != float64(4) {
		t.Fatalf("first entries: %d %v\n%s", code, res, out)
	}
	if code, res, out := witnessRun("--log-id", "other-log"); code != 1 || res["verdict"] != "log-id-mismatch" {
		t.Fatalf("--log-id other-log: %d %v\n%s", code, res, out)
	}
	add(honest, "a", 5)
	if code, res, out := witnessRun(); code != 0 || res["verdict"] != "witnessed" || res["treeSize"] != float64(9) {
		t.Fatalf("after growth: %d %v\n%s", code, res, out)
	}
	if code, res, out := witnessRun(); code != 0 || res["verdict"] != "no-change" {
		t.Fatalf("no change: %d %v\n%s", code, res, out)
	}
	if got := honest.Cosignatures(0, true); len(got) != 3 {
		t.Fatalf("server recorded %d cosignatures from witness.mjs", len(got))
	}
	for _, c := range honest.Cosignatures(0, true) {
		if err := sth.VerifyBytes([]byte(c.STHCanonical), c.Signature, ks.wTS.Public().(ed25519.PublicKey)); err != nil {
			t.Fatalf("stored cosignature does not verify: %v", err)
		}
	}
	// A fork: same key and log ID, different history, larger tree.
	forked := openLog(t, ks, "interop-log")
	add(forked, "b", 12)
	h.Store(handlerFor(t, forked))
	if code, res, out := witnessRun(); code != 1 || res["verdict"] != "fork-detected" {
		t.Fatalf("fork: %d %v\n%s", code, res, out)
	}
}

// syncBuffer is a bytes.Buffer that a running command's output goroutine
// can write while the test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestGoWitnessAgainstTypeScriptLog runs this repository's witness
// against a log served by the TypeScript TransparencyLog.
func TestGoWitnessAgainstTypeScriptLog(t *testing.T) {
	repo := checkout(t)
	ks := makeKeys(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "ts-log-server.mjs", repo, ks.logPath, "ts-log")
	// Cancelling kills the server, so its exit hook cannot remove its
	// temporary files; they go in a directory the test removes.
	cmd.Env = append(os.Environ(), "TMPDIR="+t.TempDir())
	stdout, _ := cmd.StdoutPipe()
	var stderr syncBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
	}()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("ts-log-server did not start: %v %s", err, stderr.String())
	}
	base := "http://127.0.0.1:" + strings.TrimSpace(strings.TrimPrefix(line, "listening "))
	post := func(path string, body any) {
		raw, _ := json.Marshal(body)
		resp, err := http.Post(base+path, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("POST %s: %d (%s)", path, resp.StatusCode, stderr.String())
		}
	}
	cfg := witness.Config{BaseURL: base, WitnessID: "w-go", Key: ks.wGo, LogKey: ks.log.Public().(ed25519.PublicKey),
		StatePath: filepath.Join(t.TempDir(), "go-witness.json"), Client: &http.Client{Timeout: 10 * time.Second}}
	expect := func(want string) witness.Result {
		t.Helper()
		r, err := witness.RunOnce(ctx, cfg)
		if err != nil {
			t.Fatalf("RunOnce: %v (%s)", err, stderr.String())
		}
		if r.Verdict != want {
			t.Fatalf("verdict %s (%s), want %s", r.Verdict, r.Reason, want)
		}
		return r
	}
	// A request the harness cannot handle gets a fixed message, not the error.
	resp, err := http.Post(base+"/test/append", "application/json", strings.NewReader("{not json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 500 || string(raw) != `{"error":"internal error"}` {
		t.Fatalf("malformed body: %d %s (%s)", resp.StatusCode, raw, stderr.String())
	}
	expect(witness.Witnessed) // the empty tree
	for size := 1; size <= 17; size++ {
		post("/test/append", map[string]string{"data": fmt.Sprintf("leaf-%d", size)})
		if size%4 == 1 || size == 17 {
			expect(witness.Witnessed)
		}
	}
	expect(witness.NoChange)
	var cos []map[string]string
	getJSON(t, base+"/test/cosignatures", &cos)
	if len(cos) != 6 {
		t.Fatalf("TypeScript log received %d cosignatures", len(cos))
	}
	for _, c := range cos {
		if err := sth.VerifyBytes([]byte(c["sthCanonical"]), c["signature"], ks.wGo.Public().(ed25519.PublicKey)); err != nil {
			t.Fatal("cosignature from the Go witness does not verify")
		}
	}
	leaves := []string{}
	for i := 0; i < 20; i++ {
		leaves = append(leaves, fmt.Sprintf("other-%d", i))
	}
	post("/test/reset", map[string]any{"leaves": leaves})
	expect(witness.Fork)
}

// TestFixturesAndVerifierCopiesMatchCheckout: the conformance fixtures in
// testdata/ and the verifier and tests copied into internal/vaos are
// byte-identical to the checkout's.
func TestFixturesAndVerifierCopiesMatchCheckout(t *testing.T) {
	repo := checkout(t)
	src := filepath.Join(repo, "packages/verifiable-receipts/conformance/fixtures")
	files, _ := filepath.Glob(filepath.Join(src, "*.json"))
	if len(files) == 0 {
		t.Fatal("no fixtures in the checkout")
	}
	for _, f := range files {
		a, _ := os.ReadFile(f)
		b, err := os.ReadFile(filepath.Join("../testdata/conformance/fixtures", filepath.Base(f)))
		if err != nil || !bytes.Equal(a, b) {
			t.Errorf("fixture %s differs from the checkout (or is missing)", filepath.Base(f))
		}
	}
	a, _ := os.ReadFile(filepath.Join(repo, "packages/verifiable-receipts/conformance/public-key.pem"))
	b, _ := os.ReadFile("../testdata/conformance/public-key.pem")
	if !bytes.Equal(a, b) {
		t.Error("public-key.pem differs")
	}
	copied := []string{
		"verify.go", "transparency.go", "edwards25519.go",
		"contenthash_test.go", "nesting_test.go", "edwards25519_test.go", "strict_ed25519_test.go",
		"key_test.go",
	}
	for _, name := range copied {
		orig, _ := os.ReadFile(filepath.Join(repo, "packages/verifiable-receipts-go", name))
		copied, _ := os.ReadFile(filepath.Join("../internal/vaos", name))
		i := bytes.Index(copied, []byte("\n\n"))
		if i < 0 {
			t.Fatalf("internal/vaos/%s has no notice", name)
		}
		if !bytes.Equal(copied[i+2:], orig) {
			t.Errorf("internal/vaos/%s differs from the checkout beyond its notice", name)
		}
	}
}

// TestCanonicalTreeHeadEscaping: for log IDs with quotes, backslashes,
// control characters, U+2028 and non-ASCII text, the TypeScript
// canonicalizeSth (JSON.stringify) and this repository's canonical
// string are byte-identical.
func TestCanonicalTreeHeadEscaping(t *testing.T) {
	repo := checkout(t)
	ids := []string{"plain", `q"uote`, `back\slash`, "tab\tnew\nline\x01\x1f\x7f", "line\u2028sep\u2029", "Zürich ✓ 😀", "<script>&"}
	var heads []sth.STH
	for i, id := range ids {
		heads = append(heads, sth.New(id, uint64(i)*1000003, merkle.LeafHash([]byte(id)), time.Unix(1_800_000_000+int64(i), 123e6)))
	}
	job, _ := json.Marshal(map[string]any{"sths": heads})
	var ts struct {
		STHs []struct {
			Canonical string `json:"canonical"`
		} `json:"sths"`
	}
	if err := json.Unmarshal(runTool(t, job, "node", "ts-tool.mjs", repo), &ts); err != nil {
		t.Fatal(err)
	}
	for i, h := range heads {
		c, err := h.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if ts.STHs[i].Canonical != string(c) {
			t.Errorf("logId %q:\n TypeScript %s\n Go         %s", ids[i], ts.STHs[i].Canonical, c)
		}
	}
}
