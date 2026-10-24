package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/christiaan839-beep/receipts-log/internal/testutil"
)

// VAOS 2.0 section 7.2: a receipt or a canonical nested deeper than 64 is
// refused. These receipts are correctly signed by the log's issuer, so
// only the depth limit refuses them.

func nested(levels int) string {
	return strings.Repeat("[", levels) + strings.Repeat("]", levels)
}

// deepEntry is a receipt whose canonical is {"d":<d>} and whose envelope
// carries d too when inEnvelope is set.
func deepEntry(t *testing.T, issuer ed25519.PrivateKey, d string, inEnvelope bool) []byte {
	t.Helper()
	canonical := `{"d":` + d + `}`
	sum := sha256.Sum256([]byte(canonical))
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(issuer, []byte(canonical)))
	quoted := strings.ReplaceAll(canonical, `"`, `\"`)
	body := `{"canonical":"` + quoted + `","contentHash":"sha256:` + hex.EncodeToString(sum[:]) +
		`","signature":"v2=` + sig + `"`
	if inEnvelope {
		body += `,"d":` + d
	}
	return []byte(body + "}")
}

func TestEntriesAdmitAReceiptExactly64Deep(t *testing.T) {
	f := setup(t)
	// The receipt object is one level and d 63 more; the same in the canonical.
	if code, body := f.do(t, "POST", "/v1/entries", deepEntry(t, f.issuer, nested(63), true)); code != http.StatusCreated {
		t.Fatalf("64 deep: got %d, want 201 (%s)", code, body)
	}
}

func TestEntriesRefuseAReceiptNestedDeeperThan64(t *testing.T) {
	for _, levels := range []int{64, 5000, 12000} {
		f := setup(t)
		code, body := f.do(t, "POST", "/v1/entries", deepEntry(t, f.issuer, nested(levels), true))
		if code != http.StatusBadRequest || !strings.Contains(string(body), "receipt nesting deeper than 64") {
			t.Errorf("d %d deep: got %d %.200s, want 400 naming the depth limit", levels, code, body)
		}
		if f.log.STH().TreeSize != 0 {
			t.Errorf("d %d deep: the receipt was appended", levels)
		}
	}
}

func TestEntriesRefuseACanonicalNestedDeeperThan64(t *testing.T) {
	f := setup(t)
	// The receipt itself is shallow; only its canonical text is 65 deep.
	code, body := f.do(t, "POST", "/v1/entries", deepEntry(t, f.issuer, nested(64), false))
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "canonical nesting deeper than 64") {
		t.Fatalf("got %d %.200s, want 422 naming the canonical's depth", code, body)
	}
	if f.log.STH().TreeSize != 0 {
		t.Fatal("the receipt was appended")
	}
}

// The text repeats a key, first nested 64 deep and then with the signed
// value. encoding/json keeps the last, so the depth is counted on the text.
func TestEntriesRefuseADuplicateKeyNestedDeeperThan64(t *testing.T) {
	f := setup(t)
	signed := testutil.Receipt(t, f.issuer, map[string]any{"overall": "pass", "runId": "dup-1"})
	text := `{"overall":` + nested(64) + `,` + string(signed[1:])
	code, body := f.do(t, "POST", "/v1/entries", []byte(text))
	if code != http.StatusBadRequest || !strings.Contains(string(body), "receipt nesting deeper than 64") {
		t.Fatalf("got %d %.200s, want 400 naming the depth limit", code, body)
	}
	if f.log.STH().TreeSize != 0 {
		t.Fatal("the receipt was appended")
	}
}

// A signature or contentHash that is not a string is a verdict, with the
// TypeScript and Python verifiers' reason; a canonical that is not a
// string reads as no canonical. The values replace those of a receipt
// that verifies.
func TestEntriesFieldsThatAreNotStrings(t *testing.T) {
	for _, c := range []struct {
		key, value string
		code       int
		reason     string
	}{
		{"canonical", `5`, http.StatusBadRequest, "missing canonical"},
		{"signature", `["v2="]`, http.StatusUnprocessableEntity, "missing signature"},
		{"contentHash", `5`, http.StatusUnprocessableEntity, "contentHash must be a string"},
		{"contentHash", `null`, http.StatusCreated, ""},
	} {
		f := setup(t)
		var m map[string]json.RawMessage
		if err := json.Unmarshal(testutil.Receipt(t, f.issuer, map[string]any{"runId": "s-1"}), &m); err != nil {
			t.Fatal(err)
		}
		m[c.key] = json.RawMessage(c.value)
		body, _ := json.Marshal(m)
		code, out := f.do(t, "POST", "/v1/entries", body)
		if code != c.code || !strings.Contains(string(out), c.reason) {
			t.Errorf("%s %s: got %d %s, want %d %q", c.key, c.value, code, out, c.code, c.reason)
		}
	}
}

// The signature's base64 reasons are the TypeScript and Python verifiers'.
func TestEntriesSignatureBase64Reasons(t *testing.T) {
	for _, c := range []struct{ name, edit, reason string }{
		{"line break", "\n", "signature base64 invalid"},
		{"padding bits", "", "signature base64 invalid: not canonical"},
	} {
		f := setup(t)
		var m map[string]any
		if err := json.Unmarshal(testutil.Receipt(t, f.issuer, map[string]any{"runId": "b-1"}), &m); err != nil {
			t.Fatal(err)
		}
		sig := m["signature"].(string)
		if c.edit != "" {
			sig = sig[:7] + c.edit + sig[7:]
		} else {
			// The last character before "==" carries 4 padding bits.
			b := []byte(sig)
			i := len(b) - 3 // its 4 padding bits are 0, so setting bit 0 changes it
			b[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[strings.IndexByte(
				"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", b[i])|1]
			sig = string(b)
		}
		m["signature"] = sig
		body, _ := json.Marshal(m)
		code, out := f.do(t, "POST", "/v1/entries", body)
		if code != http.StatusUnprocessableEntity || !strings.Contains(string(out), c.reason) {
			t.Errorf("%s: got %d %s, want 422 %q", c.name, code, out, c.reason)
		}
	}
}
