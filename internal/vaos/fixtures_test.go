package vaos

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

// What the tests copied from verifiable-receipts (contenthash_test.go,
// nesting_test.go, key_test.go and strict_ed25519_test.go) expect from the rest of that package's
// tests. There they come from its conformance_test.go and verify_test.go;
// here the fixture paths name this repository's copies.

const fixturesDir = "../../testdata/conformance/fixtures"
const publicKeyPath = "../../testdata/conformance/public-key.pem"

// v2Expected is a fixture's expected verdict.
type v2Expected struct {
	OK             bool   `json:"ok"`
	ReasonContains string `json:"reasonContains,omitempty"`
}

type v2Fixture struct {
	Receipt Receipt `json:"receipt"`
}

// makeKeyPair returns an Ed25519 key pair and the public key as PEM.
func makeKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return pub, priv, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// signV2 returns the v2= signature over canonical.
func signV2(priv ed25519.PrivateKey, canonical string) string {
	return "v2=" + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(canonical)))
}
