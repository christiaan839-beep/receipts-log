package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/christiaan839-beep/receipts-log/internal/keys"
	"github.com/christiaan839-beep/receipts-log/internal/merkle"
	"github.com/christiaan839-beep/receipts-log/internal/sth"
	"github.com/christiaan839-beep/receipts-log/internal/testutil"
	"github.com/christiaan839-beep/receipts-log/internal/translog"
)

type fixture struct {
	srv     *httptest.Server
	log     *translog.Log
	issuer  ed25519.PrivateKey
	witness ed25519.PrivateKey
}

func setup(t *testing.T) *fixture {
	t.Helper()
	issuer, witness := testutil.Key(t), testutil.Key(t)
	l, err := translog.Open(translog.Config{
		Dir: t.TempDir(), LogID: "test-log", Key: testutil.Key(t),
		IssuerKeys:  []ed25519.PublicKey{issuer.Public().(ed25519.PublicKey)},
		WitnessKeys: map[string]ed25519.PublicKey{"w1": witness.Public().(ed25519.PublicKey)},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(l, Options{MaxEntryBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(func() { srv.Close(); l.Close() })
	return &fixture{srv: srv, log: l, issuer: issuer, witness: witness}
}

func (f *fixture) do(t *testing.T, method, path string, body []byte) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, f.srv.URL+path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if ct := resp.Header.Get("Content-Type"); resp.StatusCode != 200 && !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("%s %s: content type %q", method, path, ct)
	}
	return resp.StatusCode, out
}

func decode[T any](t *testing.T, b []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return v
}

func TestEndToEnd(t *testing.T) {
	f := setup(t)
	pub := f.log.PublicKey()
	var receipts [][]byte
	for i := 0; i < 9; i++ {
		rc := testutil.Receipt(t, f.issuer, map[string]any{"runId": fmt.Sprintf("r%d", i)})
		receipts = append(receipts, rc)
		code, body := f.do(t, "POST", "/v1/entries", rc)
		if code != http.StatusCreated {
			t.Fatalf("append %d: %d %s", i, code, body)
		}
		res := decode[appendResponse](t, body)
		if res.Index != uint64(i) || res.STH.TreeSize != uint64(i+1) {
			t.Fatalf("append %d: %+v", i, res)
		}
		if err := sth.Verify(res.STH.STH, pub); err != nil {
			t.Fatal(err)
		}
		if c, _ := res.STH.STH.Canonical(); string(c) != res.STH.Canonical {
			t.Fatal("canonical field disagrees")
		}
	}
	code, body := f.do(t, "POST", "/v1/entries", receipts[2])
	if code != http.StatusOK || !decode[appendResponse](t, body).Duplicate {
		t.Fatalf("duplicate: %d %s", code, body)
	}

	code, body = f.do(t, "GET", "/v1/sth", nil)
	head := decode[sth.Response](t, body)
	if code != 200 || head.TreeSize != 9 || sth.Verify(head.STH, pub) != nil {
		t.Fatalf("sth: %d %s", code, body)
	}
	root, _ := head.Root()

	for i, rc := range receipts {
		code, body = f.do(t, "GET", fmt.Sprintf("/v1/entries/%d", i), nil)
		ent := decode[struct {
			Index    uint64          `json:"index"`
			LeafHash string          `json:"leafHash"`
			Receipt  json.RawMessage `json:"receipt"`
		}](t, body)
		var compact bytes.Buffer
		json.Compact(&compact, rc)
		if code != 200 || !bytes.Equal(ent.Receipt, compact.Bytes()) {
			t.Fatalf("entry %d: %d %s", i, code, body)
		}
		leaf, _ := translog.LeafForReceipt(rc)
		for _, q := range []string{fmt.Sprintf("index=%d", i), "leafHash=" + leaf.String()} {
			code, body = f.do(t, "GET", "/v1/proof/inclusion?"+q+"&treeSize=9", nil)
			p := decode[inclusionResponse](t, body)
			path, err := merkle.ParseHashes(p.AuditPath)
			if code != 200 || err != nil || p.LeafHashHex != leaf.String() || p.RootHashHex != head.RootHash {
				t.Fatalf("inclusion %s: %d %s", q, code, body)
			}
			if err := merkle.VerifyInclusion(leaf, uint64(i), 9, path, root); err != nil {
				t.Fatal(err)
			}
		}
	}
	for old := 0; old <= 9; old++ {
		for _, path := range []string{
			fmt.Sprintf("/v1/proof/consistency?old=%d&new=9", old),
			fmt.Sprintf("/api/transparency/proof?kind=consistency&old=%d&new=9", old),
		} {
			code, body = f.do(t, "GET", path, nil)
			p := decode[consistencyResponse](t, body)
			proof, _ := merkle.ParseHashes(p.Proof)
			oldRoot, _ := merkle.ParseHash(p.OldRootHex)
			if code != 200 || merkle.VerifyConsistency(uint64(old), 9, oldRoot, root, proof) != nil {
				t.Fatalf("%s: %d %s", path, code, body)
			}
		}
	}

	// Witness cosignature through the compat route.
	c, _ := head.STH.Canonical()
	req, _ := json.Marshal(map[string]string{"witnessId": "w1", "sthCanonical": string(c),
		"signature": sth.EncodeSignature(ed25519.Sign(f.witness, c))})
	code, body = f.do(t, "POST", "/api/transparency/witness", req)
	if code != 200 || decode[map[string]any](t, body)["witnessCount"] != float64(1) {
		t.Fatalf("cosign: %d %s", code, body)
	}
	code, body = f.do(t, "GET", "/v1/cosignatures?treeSize=9", nil)
	if code != 200 || !strings.Contains(string(body), `"witnessId":"w1"`) {
		t.Fatalf("cosignatures: %d %s", code, body)
	}

	resp, err := http.Get(f.srv.URL + "/v1/public-key")
	if err != nil {
		t.Fatal(err)
	}
	pem, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if k, err := keys.ParsePublicKeyPEM(pem); err != nil || !k.Equal(pub) {
		t.Fatal("public key endpoint")
	}
	if code, _ := f.do(t, "GET", "/healthz", nil); code != 200 {
		t.Fatal("healthz")
	}
}

func TestBadRequests(t *testing.T) {
	f := setup(t)
	good := testutil.Receipt(t, f.issuer, map[string]any{"runId": "a"})
	f.do(t, "POST", "/v1/entries", good)
	unsigned := testutil.Receipt(t, testutil.Key(t), map[string]any{"runId": "b"})
	cases := []struct {
		method, path string
		body         []byte
		want         int
	}{
		{"POST", "/v1/entries", []byte("{"), 400},
		{"POST", "/v1/entries", []byte("[1]"), 400},
		{"POST", "/v1/entries", unsigned, 422},
		{"POST", "/v1/entries", bytes.Repeat([]byte("a"), 65<<10), 413},
		{"GET", "/v1/entries/1", nil, 404},
		{"GET", "/v1/entries/-1", nil, 400},
		{"GET", "/v1/entries/abc", nil, 400},
		{"GET", "/v1/entries/99999999999999999999", nil, 400},
		{"GET", "/v1/proof/inclusion?index=0&treeSize=2", nil, 400},
		{"GET", "/v1/proof/inclusion?index=1", nil, 400},
		{"GET", "/v1/proof/inclusion", nil, 400},
		{"GET", "/v1/proof/inclusion?index=0&leafHash=00", nil, 400},
		{"GET", "/v1/proof/inclusion?leafHash=zz", nil, 400},
		{"GET", "/v1/proof/inclusion?leafHash=" + merkle.LeafHash(nil).String(), nil, 404},
		{"GET", "/v1/proof/inclusion?index=0&treeSize=0", nil, 400},
		{"GET", "/v1/proof/consistency?old=2&new=1", nil, 400},
		{"GET", "/v1/proof/consistency?old=x", nil, 400},
		{"GET", "/v1/proof/consistency", nil, 400},
		{"GET", "/api/transparency/proof?kind=nope", nil, 400},
		{"POST", "/v1/cosignatures", []byte(`{"witnessId":"zz","sthCanonical":"{}","signature":"v2=AA=="}`), 403},
		{"POST", "/v1/cosignatures", []byte(`{"witnessId":"w1","sthCanonical":"{}","signature":"v2=AA=="}`), 400},
		{"POST", "/v1/cosignatures", []byte(`nope`), 400},
		{"GET", "/v1/cosignatures", nil, 400},
		{"DELETE", "/v1/sth", nil, 405},
		{"GET", "/v1/nothing", nil, 404},
		{"GET", "/v1/sth?" + strings.Repeat("a", 3000), nil, 414},
	}
	for _, c := range cases {
		if code, body := f.do(t, c.method, c.path, c.body); code != c.want {
			t.Errorf("%s %s: got %d, want %d (%s)", c.method, c.path, code, c.want, body)
		}
	}
	req, _ := http.NewRequest("POST", f.srv.URL+"/v1/entries", bytes.NewReader(good))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain: %d", resp.StatusCode)
	}
}

func TestPanicIsContained(t *testing.T) {
	f := setup(t)
	s, _ := New(f.log, Options{})
	h := s.middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "internal error") {
		t.Fatalf("panic: %d %s", rec.Code, rec.Body.String())
	}
}

func TestBusy(t *testing.T) {
	f := setup(t)
	s, _ := New(f.log, Options{MaxInFlight: 1})
	s.sem <- struct{}{}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/v1/sth", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("busy: %d", rec.Code)
	}
}

// FuzzHandler sends arbitrary paths, queries and bodies through the
// whole handler: it must never panic and never answer 500.
func FuzzHandler(f *testing.F) {
	issuer := testutil.Key(f)
	l, err := translog.Open(translog.Config{Dir: f.TempDir(), LogID: "fuzz", Key: testutil.Key(f),
		IssuerKeys: []ed25519.PublicKey{issuer.Public().(ed25519.PublicKey)}})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { l.Close() })
	l.Append(testutil.Receipt(f, issuer, map[string]any{"a": "b"}))
	l.Append(testutil.Receipt(f, issuer, map[string]any{"a": "c"}))
	s, _ := New(l, Options{MaxEntryBytes: 4096})
	h := s.Handler()
	f.Add("GET", "/v1/proof/inclusion", "index=1&treeSize=2", []byte(nil))
	f.Add("GET", "/v1/proof/consistency", "old=1&new=2", []byte(nil))
	f.Add("POST", "/v1/entries", "", []byte(`{"canonical":"{}"}`))
	f.Add("POST", "/api/transparency/witness", "", []byte(`{"witnessId":"w"}`))
	f.Add("GET", "/v1/entries/1", "", []byte(nil))
	f.Fuzz(func(t *testing.T, method, path, query string, body []byte) {
		if method != "GET" && method != "POST" {
			method = "GET"
		}
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " ?#%\x00\r\n\t") {
			return
		}
		req, err := http.NewRequest(method, "http://x"+path, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.URL.RawQuery = query
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code >= 500 && rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s?%s: %d %s", method, path, query, rec.Code, rec.Body.String())
		}
	})
}
