package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

// Builds before the sync with verifiable-receipts f41348e checked an
// Ed25519 signature with crypto/ed25519 alone, and refused only issuer
// keys of small order or with a non-canonical encoding. They admitted a
// signature whose R is the identity (S = k*a under an ordinary key), and
// receipts under an issuer key of mixed order (with k = 0 mod 8). The
// strict profile of VAOS 2.0 section 7.3 refuses both. A store holding
// them must still open, serve and prove them, and check must report them
// as nonconforming (exit 3), not as corruption.
//
// Those builds recorded a witness's cosignature after the same check, so
// they recorded one whose R is the identity too. The log loads stored
// cosignatures without verifying them: the store must still open and
// serve it, and check -witness-key must report it (exit 4).

// The conformance fixtures the stored receipts are, in store order.
var strictOldFixtures = []string{
	"ed25519-honest.json",               // conforming, under the honest key
	"ed25519-r-identity.json",           // R = identity, under the honest key
	"ed25519-key-mixed-order-8-k0.json", // under a key of mixed order
}

type strictOldStore struct {
	dir                 string
	logKey              ed25519.PrivateKey
	logPub              string
	honestPub, mixedPub string // PEM files
	honestKey           ed25519.PublicKey
	bodies              [][]byte
	leaves              []merkle.Hash
	receiptFiles        []string
	// Two pinned witnesses: w1 cosigned the checkpoint honestly, w2 with
	// an R that is the identity.
	witnessKeys       map[string]ed25519.PublicKey
	witnessFlags      []string // -witness-key NAME=FILE values
	headSize          uint64
	identityRCosigSig string
}

// rawPublicKey parses an SPKI PEM Ed25519 key without the key rule, as
// an older build loaded a mixed-order key.
func rawPublicKey(t *testing.T, data string) ed25519.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		t.Fatal("no PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(ed25519.PublicKey)
}

// newStrictOldStore writes, through store and without the log, what an
// older build configured with the honest and the mixed-order issuer keys
// would have left: the three fixture receipts, and a checkpoint signed
// over them.
func newStrictOldStore(t *testing.T) *strictOldStore {
	t.Helper()
	dir := t.TempDir()
	o := &strictOldStore{dir: filepath.Join(dir, "data"), logKey: testutil.Key(t)}
	st, err := store.Open(store.Options{Dir: o.dir}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var tree merkle.Tree
	for i, name := range strictOldFixtures {
		raw, err := os.ReadFile(filepath.Join("../../testdata/conformance/fixtures", name))
		if err != nil {
			t.Fatal(err)
		}
		var fx struct {
			PublicKeyPem string          `json:"publicKeyPem"`
			Receipt      json.RawMessage `json:"receipt"`
		}
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		key := rawPublicKey(t, fx.PublicKeyPem)
		var r struct{ Canonical, Signature string }
		if err := json.Unmarshal(fx.Receipt, &r); err != nil {
			t.Fatal(err)
		}
		sig, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Signature, "v2="))
		// What older builds checked: crypto/ed25519 accepts each one.
		if !ed25519.Verify(key, []byte(r.Canonical), sig) {
			t.Fatalf("%s: crypto/ed25519 rejects it, so no older build admitted it", name)
		}
		pemFile := filepath.Join(dir, fmt.Sprintf("issuer%d.pub", i))
		if err := os.WriteFile(pemFile, []byte(fx.PublicKeyPem), 0o600); err != nil {
			t.Fatal(err)
		}
		switch i {
		case 0:
			o.honestKey, o.honestPub = key, pemFile
		case 2:
			o.mixedPub = pemFile
		}
		body := []byte(fx.Receipt)
		leaf := oldLeaf(t, body)
		if _, err := st.Append(leaf, body); err != nil {
			t.Fatal(err)
		}
		tree.Append(leaf)
		o.bodies = append(o.bodies, body)
		o.leaves = append(o.leaves, leaf)
		f := filepath.Join(dir, fmt.Sprintf("r%d.json", i))
		if err := os.WriteFile(f, body, 0o600); err != nil {
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
	canonical, err := head.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	o.witnessKeys = map[string]ed25519.PublicKey{}
	o.headSize = head.TreeSize
	for _, id := range []string{"w1", "w2"} {
		wk := testutil.Key(t)
		pub := wk.Public().(ed25519.PublicKey)
		sig := ed25519.Sign(wk, canonical)
		if id == "w2" {
			sig = testutil.IdentityRSignature(wk, canonical)
			// What older builds checked: crypto/ed25519 accepts it.
			if !ed25519.Verify(pub, canonical, sig) {
				t.Fatal("crypto/ed25519 rejects the identity-R cosignature, so no older build recorded it")
			}
			o.identityRCosigSig = sth.EncodeSignature(sig)
		}
		line, _ := json.Marshal(translog.Cosignature{WitnessID: id, TreeSize: head.TreeSize, RootHash: head.RootHash,
			Timestamp: head.Timestamp, STHCanonical: string(canonical), Signature: sth.EncodeSignature(sig),
			ReceivedAt: head.Timestamp})
		if err := st.AppendCosignature(line); err != nil {
			t.Fatal(err)
		}
		pemData, err := keys.PublicKeyPEM(pub)
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(dir, id+".pub")
		if err := os.WriteFile(f, pemData, 0o600); err != nil {
			t.Fatal(err)
		}
		o.witnessKeys[id] = pub
		o.witnessFlags = append(o.witnessFlags, id+"="+f)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	logPEM, err := keys.PublicKeyPEM(o.logKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	o.logPub = filepath.Join(dir, "log.pub")
	if err := os.WriteFile(o.logPub, logPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return o
}

// open opens the store with the honest issuer key (the mixed-order key
// can no longer be configured) and both witnesses pinned.
func (o *strictOldStore) open(t *testing.T) (*translog.Log, *httptest.Server) {
	t.Helper()
	l, err := translog.Open(translog.Config{Dir: o.dir, LogID: "old-log", Key: o.logKey,
		IssuerKeys: []ed25519.PublicKey{o.honestKey}, WitnessKeys: o.witnessKeys})
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

func TestOldStrictReceiptsOpenAndServe(t *testing.T) {
	o := newStrictOldStore(t)
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
	// Both stored cosignatures are served, the identity-R one included.
	resp, err := http.Get(fmt.Sprintf("%s/v1/cosignatures?treeSize=%d", srv.URL, o.headSize))
	if err != nil {
		t.Fatal(err)
	}
	var cos struct {
		Cosignatures []translog.Cosignature `json:"cosignatures"`
	}
	err = json.NewDecoder(resp.Body).Decode(&cos)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || len(cos.Cosignatures) != 2 ||
		cos.Cosignatures[1].WitnessID != "w2" || cos.Cosignatures[1].Signature != o.identityRCosigSig {
		t.Errorf("GET /v1/cosignatures: %d %+v %v", resp.StatusCode, cos, err)
	}
	// Submitted again, the conforming receipt is a duplicate (200); the
	// others are refused today, with 422 and the strict profile's reason.
	for i, want := range []struct {
		code   int
		reason string
	}{
		{http.StatusOK, `"duplicate":true`},
		{http.StatusUnprocessableEntity, "signature R is a small-order point"},
		{http.StatusUnprocessableEntity, "signature does not verify under the supplied public key"},
	} {
		resp, err := http.Post(srv.URL+"/v1/entries", "application/json", strings.NewReader(string(o.bodies[i])))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want.code || !strings.Contains(string(body), want.reason) {
			t.Errorf("resubmit %d: %d %s, want %d %q", i, resp.StatusCode, body, want.code, want.reason)
		}
	}
}

func TestOldStrictReceiptsCheckNonconforming(t *testing.T) {
	o := newStrictOldStore(t)
	base := []string{"check", "-data", o.dir, "-log-id", "old-log", "-log-public-key", o.logPub}
	code, out, e := runCLI(t, append(base, "-issuer-key", o.honestPub)...)
	if code != exitNonconforming {
		t.Fatalf("check -issuer-key: exit %d, want %d: %s %s", code, exitNonconforming, out, e)
	}
	var rep translog.CheckReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("report: %v: %s", err, out)
	}
	if rep.Entries != 3 || rep.NonconformingCount == nil || *rep.NonconformingCount != 2 || len(rep.Nonconforming) != 2 {
		t.Fatalf("report: %s", out)
	}
	for k, want := range []string{
		"receipt signature does not verify under any configured issuer key: signature R is a small-order point",
		// Under the honest key, the one that can be configured now, a
		// receipt the mixed-order key signed does not verify.
		"receipt signature does not verify under any configured issuer key: signature does not verify under the supplied public key",
	} {
		n := rep.Nonconforming[k]
		if n.Index != uint64(k+1) || n.LeafHash != o.leaves[n.Index].String() || n.Reason != want {
			t.Errorf("nonconforming %d: %+v, want reason %q", k, n, want)
		}
	}
	// The mixed-order key itself is refused when check loads it, as serve
	// refuses it, with the strict profile's reason.
	code, out, e = runCLI(t, append(base, "-issuer-key", o.mixedPub)...)
	if code != exitUsage || !strings.Contains(e, "public key is not in the prime-order subgroup") {
		t.Fatalf("check -issuer-key mixed: exit %d, want %d naming the subgroup: %s %s", code, exitUsage, out, e)
	}
	// Without issuer keys the store is simply intact.
	if code, out, e := runCLI(t, base...); code != 0 {
		t.Fatalf("check: exit %d: %s %s", code, out, e)
	}
}

func TestOldStrictReceiptsProve(t *testing.T) {
	o := newStrictOldStore(t)
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

// serve and check load -issuer-key files with loadIssuerKeys, which
// refuses the mixed-order key an older build accepted.
func TestOldStrictLoadIssuerKeysRefusesMixedOrderKey(t *testing.T) {
	o := newStrictOldStore(t)
	if _, err := loadIssuerKeys([]string{o.mixedPub}); err == nil ||
		!strings.Contains(err.Error(), "public key is not in the prime-order subgroup") {
		t.Fatalf("loadIssuerKeys: %v", err)
	}
}

// check -witness-key reports the identity-R cosignature an older build
// recorded (exit 4), and with -issuer-key too the receipts as well (exit
// 3, which comes first).
func TestOldStrictCosignatureCheckNonconforming(t *testing.T) {
	o := newStrictOldStore(t)
	base := []string{"check", "-data", o.dir, "-log-id", "old-log", "-log-public-key", o.logPub}
	var witnessArgs []string
	for _, f := range o.witnessFlags {
		witnessArgs = append(witnessArgs, "-witness-key", f)
	}
	const reason = "witness signature does not verify: signature R is a small-order point"
	code, out, e := runCLI(t, append(base, witnessArgs...)...)
	if code != exitNonconformingCosig || !strings.Contains(e, "1 stored cosignature(s) the log now refuses") {
		t.Fatalf("check -witness-key: exit %d, want %d: %s %s", code, exitNonconformingCosig, out, e)
	}
	var rep translog.CheckReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("report: %v: %s", err, out)
	}
	want := translog.NonconformingCosignature{Index: 1, WitnessID: "w2", TreeSize: o.headSize, Reason: reason}
	if rep.WitnessKeys != 2 || rep.Cosignatures != 2 || rep.NonconformingCosignatureCount == nil ||
		*rep.NonconformingCosignatureCount != 1 || len(rep.NonconformingCosignatures) != 1 ||
		rep.NonconformingCosignatures[0] != want || rep.NonconformingCount != nil {
		t.Fatalf("report: %s", out)
	}

	code, out, e = runCLI(t, append(append(base, "-issuer-key", o.honestPub), witnessArgs...)...)
	if code != exitNonconforming || !strings.Contains(e, "2 stored receipt(s) fail the current admission rules; "+
		"1 stored cosignature(s) the log now refuses") {
		t.Fatalf("check -issuer-key -witness-key: exit %d, want %d: %s %s", code, exitNonconforming, out, e)
	}
	rep = translog.CheckReport{}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || *rep.NonconformingCount != 2 ||
		*rep.NonconformingCosignatureCount != 1 {
		t.Fatalf("report: %v: %s", err, out)
	}

	// Only the honest witness pinned: the other is no longer configured.
	code, out, e = runCLI(t, append(base, "-witness-key", o.witnessFlags[0])...)
	if code != exitNonconformingCosig || !strings.Contains(out, "witness is not configured on this log") {
		t.Fatalf("check -witness-key w1: exit %d: %s %s", code, out, e)
	}
	if code, out, e := runCLI(t, append(base, "-witness-key", "w1")...); code != exitUsage {
		t.Fatalf("check -witness-key without a file: exit %d: %s %s", code, out, e)
	}
}
