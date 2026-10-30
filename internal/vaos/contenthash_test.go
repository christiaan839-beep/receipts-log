// Copied from github.com/christiaan839-beep/verifiable-receipts,
// packages/verifiable-receipts-go/contenthash_test.go at commit
// f41348eac297c81e1c2a0dca91b7bd49dd2a5d9a (Apache-2.0, Copyright 2026
// Christiaan de Wet / Sovereign Matrix). Changed: this notice added; the
// code below is otherwise unchanged. See internal/vaos/README.md.

package vaos

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A contentHash that is present must be a hash, even when it is "";
// absent or null means no hash (VAOS 2.0 section 7, step 3). These
// tests check that a JSON round trip through Receipt keeps that
// distinction in both directions.

func loadFixtureReceipt(t *testing.T, name string) (Receipt, ed25519.PublicKey) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixturesDir, name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture v2Fixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	pemBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	pub, err := LoadEd25519PublicKeyFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("load public key: %v", err)
	}
	return fixture.Receipt, pub
}

func roundTrip(t *testing.T, r Receipt) (Receipt, []byte) {
	t.Helper()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Receipt
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal %s: %v", data, err)
	}
	return back, data
}

func TestReceipt_JSONRoundTripKeepsAHandBuiltReceiptWithNoHashValid(t *testing.T) {
	parsed, pub := loadFixtureReceipt(t, "v2-valid-001.json")
	r := Receipt{Canonical: parsed.Canonical, Signature: parsed.Signature}
	if res := VerifyV2Receipt(r, pub); !res.OK {
		t.Fatalf("hand-built receipt rejected: %s", res.Reason)
	}
	back, data := roundTrip(t, r)
	if bytes.Contains(data, []byte(`"contentHash"`)) {
		t.Fatalf("marshal wrote a contentHash the receipt does not have: %s", data)
	}
	if res := VerifyV2Receipt(back, pub); !res.OK {
		t.Fatalf("rejected after a JSON round trip: %s (%s)", res.Reason, data)
	}
}

func TestReceipt_JSONRoundTripKeepsAParsedEmptyContentHashRejected(t *testing.T) {
	r, pub := loadFixtureReceipt(t, "v2-invalid-empty-contenthash.json")
	for i := 0; i < 2; i++ {
		for name, res := range map[string]VerifyResult{
			"VerifyV2Receipt":           VerifyV2Receipt(r, pub),
			"VerifyGuardianAttestation": VerifyGuardianAttestation(r, pub),
		} {
			if res.OK || !strings.Contains(res.Reason, "contentHash mismatch") {
				t.Fatalf("round trip %d: %s = %+v, want a contentHash mismatch", i, name, res)
			}
		}
		var data []byte
		r, data = roundTrip(t, r)
		if !bytes.Contains(data, []byte(`"contentHash":""`)) {
			t.Fatalf("marshal dropped the empty contentHash: %s", data)
		}
	}
}

func TestReceipt_JSONRoundTripKeepsANullContentHashValid(t *testing.T) {
	r, pub := loadFixtureReceipt(t, "v2-valid-null-contenthash.json")
	for i := 0; i < 2; i++ {
		if res := VerifyV2Receipt(r, pub); !res.OK {
			t.Fatalf("round trip %d: rejected: %s", i, res.Reason)
		}
		r, _ = roundTrip(t, r)
	}
}
