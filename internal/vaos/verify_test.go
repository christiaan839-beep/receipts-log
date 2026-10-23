package vaos

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// The log admits receipts through VerifyV2Receipt, so a second spelling
// of a valid signature must not pass: Go's decoder skips CR and LF even
// in strict mode, and each of these decodes to the signature's bytes.
func TestVerifyV2ReceiptRejectsLineBreaksInSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonical := `{"overall":"pass","verdictId":"v_test"}`
	sum := sha256.Sum256([]byte(canonical))
	hash := "sha256:" + hex.EncodeToString(sum[:])
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(canonical)))

	ok := VerifyV2Receipt(Receipt{Canonical: canonical, ContentHash: hash, Signature: "v2=" + sig}, pub)
	if !ok.OK {
		t.Fatalf("the canonical spelling must verify: %s", ok.Reason)
	}
	for _, s := range []string{
		sig[:4] + "\n" + sig[4:],
		sig[:4] + "\r" + sig[4:],
		sig + "\r\n",
		"\n" + sig,
	} {
		if VerifyV2Receipt(Receipt{Canonical: canonical, ContentHash: hash, Signature: "v2=" + s}, pub).OK {
			t.Errorf("accepted %q", s)
		}
	}
}
