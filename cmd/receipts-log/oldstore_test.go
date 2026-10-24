package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/christiaan839-beep/receipts-log/internal/keys"
	"github.com/christiaan839-beep/receipts-log/internal/merkle"
	"github.com/christiaan839-beep/receipts-log/internal/server"
	"github.com/christiaan839-beep/receipts-log/internal/sth"
	"github.com/christiaan839-beep/receipts-log/internal/store"
	"github.com/christiaan839-beep/receipts-log/internal/testutil"
	"github.com/christiaan839-beep/receipts-log/internal/translog"
)

// Builds before the sync with verifiable-receipts 24f5c47 admitted
// receipts nested deeper than 64. A store holding them must still open,
// serve and prove them, and check must report them as nonconforming
// (exit 3), not as corruption: a receipt's leaf never depends on the
// admission rules.

type oldStore struct {
	dir               string
	logKey            ed25519.PrivateKey
	logPub, issuerPub string
	bodies            [][]byte
	leaves            []merkle.Hash
	deepFrom          int // bodies[deepFrom:] are nested too deep
	receiptFiles      []string
	issuer            ed25519.PrivateKey
}

func nestedArrays(levels int) string {
	return strings.Repeat("[", levels) + strings.Repeat("]", levels)
}

// signedDeep is a receipt whose canonical is {"d":<d>,"runId":id} and
// whose envelope carries both fields, signed by issuer.
func signedDeep(issuer ed25519.PrivateKey, id, d string) []byte {
	canonical := `{"d":` + d + `,"runId":"` + id + `"}`
	sum := sha256.Sum256([]byte(canonical))
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(issuer, []byte(canonical)))
	return []byte(`{"canonical":"` + strings.ReplaceAll(canonical, `"`, `\"`) + `","contentHash":"sha256:` +
		hex.EncodeToString(sum[:]) + `","d":` + d + `,"runId":"` + id + `","signature":"v2=` + sig + `"}`)
}

// oldLeaf is the leaf rule of the builds that stored these receipts: the
// last "canonical" key of the object, as a non-empty string.
func oldLeaf(t *testing.T, body []byte) merkle.Hash {
	t.Helper()
	var fields map[string]json.RawMessage
	var canonical string
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fields["canonical"], &canonical); err != nil || canonical == "" {
		t.Fatalf("no canonical: %v", err)
	}
	return merkle.LeafHash([]byte(canonical))
}

// newOldStore writes, through store and without the log, what an older
// build would have left: a valid receipt, then a receipt 65 deep, one
// whose duplicate key is 65 deep and one 5000 deep, and a checkpoint
// signed over all four.
func newOldStore(t *testing.T) *oldStore {
	t.Helper()
	dir := t.TempDir()
	o := &oldStore{dir: filepath.Join(dir, "data"), logKey: testutil.Key(t), issuer: testutil.Key(t), deepFrom: 1}
	valid := testutil.Receipt(t, o.issuer, map[string]any{"runId": "old-valid"})
	dupBase := testutil.Receipt(t, o.issuer, map[string]any{"overall": "pass", "runId": "old-dup"})
	o.bodies = [][]byte{
		valid,
		signedDeep(o.issuer, "old-65", nestedArrays(64)),
		[]byte(`{"overall":` + nestedArrays(64) + `,` + string(dupBase[1:])),
		signedDeep(o.issuer, "old-5000", nestedArrays(5000)),
	}
	st, err := store.Open(store.Options{Dir: o.dir}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var tree merkle.Tree
	for i, b := range o.bodies {
		leaf := oldLeaf(t, b)
		if _, err := st.Append(leaf, b); err != nil {
			t.Fatal(err)
		}
		tree.Append(leaf)
		o.leaves = append(o.leaves, leaf)
		f := filepath.Join(dir, fmt.Sprintf("r%d.json", i))
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
		o.receiptFiles = append(o.receiptFiles, f)
	}
	head, err := sth.Sign(sth.New("old-log", tree.Size(), tree.Root(), time.Now()), o.logKey)
	if err != nil {
		t.Fatal(err)
	}
	ck, _ := json.Marshal(head)
	if err := st.WriteCheckpoint(ck); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	write := func(name string, pub ed25519.PublicKey) string {
		data, _ := keys.PublicKeyPEM(pub)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	o.logPub = write("log.pub", o.logKey.Public().(ed25519.PublicKey))
	o.issuerPub = write("issuer.pub", o.issuer.Public().(ed25519.PublicKey))
	return o
}

func (o *oldStore) open(t *testing.T) (*translog.Log, *httptest.Server) {
	t.Helper()
	l, err := translog.Open(translog.Config{Dir: o.dir, LogID: "old-log", Key: o.logKey,
		IssuerKeys: []ed25519.PublicKey{o.issuer.Public().(ed25519.PublicKey)}})
	if err != nil {
		t.Fatalf("Open refuses a store an older build wrote: %v", err)
	}
	s, err := server.New(l, server.Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(func() { srv.Close(); l.Close() })
	return l, srv
}

func TestOldDeepReceiptsOpenAndServe(t *testing.T) {
	o := newOldStore(t)
	l, srv := o.open(t)
	if l.STH().TreeSize != uint64(len(o.bodies)) {
		t.Fatalf("tree size %d", l.STH().TreeSize)
	}
	for i, leaf := range o.leaves {
		for _, path := range []string{
			fmt.Sprintf("/v1/entries/%d", i),
			"/v1/proof/inclusion?leafHash=" + leaf.String(),
		} {
			resp, err := http.Get(srv.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), leaf.String()) {
				t.Errorf("GET %s: %d %.120s", path, resp.StatusCode, body)
			}
		}
	}
}

func TestOldDeepReceiptsCheckNonconforming(t *testing.T) {
	o := newOldStore(t)
	code, out, e := runCLI(t, "check", "-data", o.dir, "-log-id", "old-log", "-log-public-key", o.logPub,
		"-issuer-key", o.issuerPub)
	if code != exitNonconforming {
		t.Fatalf("check -issuer-key: exit %d, want %d: %s %s", code, exitNonconforming, out, e)
	}
	var rep translog.CheckReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("report: %v: %s", err, out)
	}
	if rep.Entries != 4 || rep.NonconformingCount == nil || *rep.NonconformingCount != 3 || len(rep.Nonconforming) != 3 {
		t.Fatalf("report: %s", out)
	}
	for k, n := range rep.Nonconforming {
		if n.Index != uint64(o.deepFrom+k) || n.LeafHash != o.leaves[n.Index].String() ||
			!strings.Contains(n.Reason, "receipt nesting deeper than 64") {
			t.Errorf("nonconforming %d: %+v", k, n)
		}
	}
	// Without issuer keys the store is simply intact.
	if code, out, e := runCLI(t, "check", "-data", o.dir, "-log-id", "old-log", "-log-public-key", o.logPub); code != 0 {
		t.Fatalf("check: exit %d: %s %s", code, out, e)
	}
}

func TestOldDeepReceiptsProve(t *testing.T) {
	o := newOldStore(t)
	for i, b := range o.bodies {
		if leaf, err := translog.LeafForReceipt(b); err != nil || leaf != o.leaves[i] {
			t.Errorf("LeafForReceipt of stored receipt %d: %v", i, err)
		}
	}
	_, srv := o.open(t)
	for i, f := range o.receiptFiles {
		code, out, e := runCLI(t, "prove", "-url", srv.URL, "-file", f, "-log-public-key", o.logPub)
		if code != 0 || !strings.Contains(out, `"included": true`) {
			t.Errorf("prove -file r%d: exit %d %s %s", i, code, out, e)
		}
	}
}
