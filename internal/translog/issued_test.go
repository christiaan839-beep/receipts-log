package translog

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/christiaan839-beep/receipts-log/internal/keys"
	"github.com/christiaan839-beep/receipts-log/internal/testutil"
	"github.com/christiaan839-beep/receipts-log/internal/vaos"
)

// legacyKeyReason is what admission checked under one key before the
// R and S checks were made once per request: VerifyV2Receipt, then
// VerifyGuardianAttestation, each in full. ok reports that either
// verified; reason is VerifyV2Receipt's.
func legacyKeyReason(r vaos.Receipt, k ed25519.PublicKey) (ok bool, reason string) {
	res := vaos.VerifyV2Receipt(r, k)
	if res.OK {
		return true, ""
	}
	return vaos.VerifyGuardianAttestation(r, k).OK, res.Reason
}

// legacyVerifyIssued is verifyIssued as it was at 66bb8c6: every key in
// full, and the first key's reason.
func legacyVerifyIssued(r vaos.Receipt, issuers []ed25519.PublicKey) (string, error) {
	reason := ""
	for _, k := range issuers {
		ok, why := legacyKeyReason(r, k)
		if ok {
			return keys.ID(k), nil
		}
		if reason == "" {
			reason = why
		}
	}
	return "", fmt.Errorf("%w: %s", ErrUnverified, reason)
}

// oracleVerifyIssued applies the reason rule of verify-receipts-action
// (verifyUnderKeys) to the legacy per-key answers: a receipt-level
// reason wins, then a problem with R, then one key's own reason or, with
// several, that the signature verifies under none of them.
func oracleVerifyIssued(r vaos.Receipt, issuers []ed25519.PublicKey) (string, error) {
	var first, receiptProblem, rProblem string
	for i, k := range issuers {
		ok, why := legacyKeyReason(r, k)
		if ok {
			return keys.ID(k), nil
		}
		if i == 0 {
			first = why
		}
		switch {
		case !isSignatureFailure(why):
			if receiptProblem == "" {
				receiptProblem = why
			}
		case strings.HasPrefix(why, rProblemPrefix):
			if rProblem == "" {
				rProblem = why
			}
		}
	}
	reason := first
	switch {
	case receiptProblem != "":
		reason = receiptProblem
	case rProblem != "":
		reason = rProblem
	case len(issuers) > 1:
		reason = fmt.Sprintf("signature does not verify under any of the %d issuer keys", len(issuers))
	}
	return "", fmt.Errorf("%w: %s", ErrUnverified, reason)
}

// reasonCase is a receipt and the key it was made for.
type reasonCase struct {
	name string
	r    vaos.Receipt
	key  ed25519.PublicKey
}

// reasonCases returns every ed25519-*.json fixture as a receipt with its
// key (the three RFC 8032 vectors as a receipt whose canonical is the
// message), and receipts with malformed or non-canonical base64, a wrong
// or non-string contentHash, or an R that is the identity, under the
// conformance key.
func reasonCases(t *testing.T) []reasonCase {
	t.Helper()
	files, _ := filepath.Glob("../../testdata/conformance/fixtures/ed25519-*.json")
	if len(files) != 20 {
		t.Fatalf("found %d ed25519 fixtures, want 20", len(files))
	}
	var out []reasonCase
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var fx struct {
			fixture
			Ed25519 *struct{ PublicKey, Message, Signature string } `json:"ed25519"`
		}
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		c := reasonCase{name: filepath.Base(f)}
		if fx.Ed25519 != nil {
			pub, _ := hex.DecodeString(fx.Ed25519.PublicKey)
			msg, _ := hex.DecodeString(fx.Ed25519.Message)
			sig, _ := hex.DecodeString(fx.Ed25519.Signature)
			c.key = pub
			c.r = vaos.Receipt{Canonical: string(msg), Signature: "v2=" + base64.StdEncoding.EncodeToString(sig)}
		} else {
			c.key = fixtureKey(t, fx.PublicKeyPem)
			if c.r, err = vaos.ParseReceipt(fx.Receipt); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
		}
		out = append(out, c)
	}
	pub, err := keys.LoadPublicKey("../../testdata/conformance/public-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	v2 := func(name string, edit func(map[string]any)) {
		raw, err := os.ReadFile("../../testdata/conformance/fixtures/v2-valid-001.json")
		if err != nil {
			t.Fatal(err)
		}
		var fx struct {
			Receipt map[string]any `json:"receipt"`
		}
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		edit(fx.Receipt)
		body, _ := json.Marshal(fx.Receipt)
		r, err := vaos.ParseReceipt(body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out = append(out, reasonCase{name: name, r: r, key: pub})
	}
	identityR := "v2=" + base64.StdEncoding.EncodeToString(append([]byte{1}, make([]byte, 63)...))
	v2("v2-valid-001.json", func(map[string]any) {})
	v2("malformed base64", func(m map[string]any) { m["signature"] = "v2=@@not base64@@" })
	v2("non-canonical base64", func(m map[string]any) {
		s := m["signature"].(string)
		m["signature"] = s[:len(s)-3] + "B=="
	})
	v2("bad contentHash", func(m map[string]any) { m["contentHash"] = "sha256:" + strings.Repeat("0", 64) })
	v2("contentHash not a string", func(m map[string]any) { m["contentHash"] = 7 })
	v2("R identity", func(m map[string]any) { m["signature"] = identityR })
	// VerifyV2Receipt checks base64 and contentHash before R: so must
	// admission, with an R that is the identity too.
	v2("malformed base64, R identity", func(m map[string]any) { m["signature"] = identityR[:len(identityR)-2] + "!!" })
	v2("bad contentHash, R identity", func(m map[string]any) {
		m["contentHash"] = "sha256:" + strings.Repeat("0", 64)
		m["signature"] = identityR
	})
	v2("empty contentHash present", func(m map[string]any) { m["contentHash"] = "" })
	v2("missing canonical", func(m map[string]any) { delete(m, "canonical") })
	v2("missing signature", func(m map[string]any) { delete(m, "signature") })
	v2("no v2= prefix", func(m map[string]any) { m["signature"] = strings.TrimPrefix(m["signature"].(string), "v2=") })
	v2("tampered envelope field", func(m map[string]any) { m["overall"] = "tampered" })
	v2("absent envelope field", func(m map[string]any) { m["unsigned"] = 1 })
	// The receipt nests deeper than 64 (its object is one level), which
	// ParseReceipt would refuse first; the verifier refuses it too.
	{
		last := out[len(out)-1]
		r := last.r
		r.Envelope = map[string]json.RawMessage{}
		for k, v := range last.r.Envelope {
			r.Envelope[k] = v
		}
		delete(r.Envelope, "unsigned")
		r.Envelope["deep"] = json.RawMessage(strings.Repeat("[", 64) + strings.Repeat("]", 64))
		out = append(out, reasonCase{name: "receipt nesting over 64", r: r, key: last.key})
	}

	// Receipts signed here, with a key made for the test.
	signer := testutil.Key(t)
	signerPub := signer.Public().(ed25519.PublicKey)
	signed := func(name, canonical string, sig []byte, envelope map[string]any) {
		if sig == nil {
			sig = ed25519.Sign(signer, []byte(canonical))
		}
		m := map[string]any{"canonical": canonical, "signature": "v2=" + base64.StdEncoding.EncodeToString(sig)}
		for k, v := range envelope {
			m[k] = v
		}
		body, _ := json.Marshal(m)
		r, err := vaos.ParseReceipt(body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out = append(out, reasonCase{name: name, r: r, key: signerPub})
	}
	signed("canonical not JSON", `{"overall":`, nil, nil)
	signed("canonical nested too deep", `{"d":`+strings.Repeat("[", 70)+strings.Repeat("]", 70)+`}`, nil, nil)
	good := `{"overall":"pass"}`
	full := ed25519.Sign(signer, []byte(good))
	signed("63-byte signature", good, full[:63], map[string]any{"overall": "pass"})
	signed("65-byte signature", good, append(append([]byte(nil), full...), 0), map[string]any{"overall": "pass"})
	rules := `{"rules":[{"reason":"no","ruleId":"r2","verdict":"fail"},{"reason":"ok","ruleId":"r1","verdict":"pass"}]}`
	envRules := func(verdict string) map[string]any {
		return map[string]any{"totalMs": 3, "rules": []any{
			map[string]any{"ruleId": "r1", "verdict": "pass", "reason": "ok", "ms": 1},
			map[string]any{"ruleId": "r2", "verdict": verdict, "reason": "no", "ms": 2},
		}}
	}
	signed("Guardian attestation", rules, nil, envRules("fail"))
	signed("Guardian attestation, tampered rule", rules, nil, envRules("pass"))
	signed("Guardian attestation, wrong key", rules, ed25519.Sign(testutil.Key(t), []byte(rules)), envRules("fail"))
	return out
}

// Under the key a receipt was made for, admission refuses every case
// with the reason it gave before (legacyVerifyIssued), and admits the
// ones it admitted.
func TestVerifyIssuedReasonsUnchangedUnderOneKey(t *testing.T) {
	for _, c := range reasonCases(t) {
		issuers := []ed25519.PublicKey{c.key}
		gotID, gotErr := verifyIssued(c.r, issuers)
		wantID, wantErr := legacyVerifyIssued(c.r, issuers)
		if gotID != wantID || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
			t.Errorf("%s: got %q %v, want %q %v", c.name, gotID, gotErr, wantID, wantErr)
		}
		t.Logf("%-38s %v", c.name, gotErr)
	}
}

// Under several keys, the reason follows verify-receipts-action's rule
// (oracleVerifyIssued, over the legacy per-key answers), with the
// receipt's own key first, last or missing.
func TestVerifyIssuedReasonsUnderSeveralKeys(t *testing.T) {
	a, b := testutil.Key(t).Public().(ed25519.PublicKey), testutil.Key(t).Public().(ed25519.PublicKey)
	for _, c := range reasonCases(t) {
		for _, issuers := range [][]ed25519.PublicKey{{c.key, a}, {a, b, c.key}, {a, b}} {
			gotID, gotErr := verifyIssued(c.r, issuers)
			wantID, wantErr := oracleVerifyIssued(c.r, issuers)
			if gotID != wantID || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
				t.Errorf("%s under %d keys: got %q %v, want %q %v", c.name, len(issuers), gotID, gotErr, wantID, wantErr)
			}
		}
	}
}

// The reason rule with several issuer keys, case by case.
func TestVerifyIssuedReasonRule(t *testing.T) {
	signer, other, third := testutil.Key(t), testutil.Key(t), testutil.Key(t)
	pk := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	good := testutil.Receipt(t, signer, map[string]any{"overall": "pass"})
	tampered := withField(t, good, "overall", "fail")
	badHash := withField(t, good, "contentHash", "sha256:"+strings.Repeat("0", 64))
	identityR := []byte(`{"canonical":"{\"overall\":\"pass\"}","overall":"pass","signature":"v2=` +
		base64.StdEncoding.EncodeToString(testutil.IdentityRSignature(signer, []byte(`{"overall":"pass"}`))) + `"}`)
	// The signer's signature with S + L in place of S: R is fine, S is
	// not below L.
	var m map[string]any
	json.Unmarshal(good, &m)
	sig, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(m["signature"].(string), "v2="))
	addL(sig[32:])
	sPlusL := withField(t, good, "signature", "v2="+base64.StdEncoding.EncodeToString(sig))

	const mismatch = "signature does not verify under the supplied public key"
	const none2 = "signature does not verify under any of the 2 issuer keys"
	cases := []struct {
		name    string
		body    []byte
		issuers []ed25519.PublicKey
		reason  string // "" means admitted
	}{
		{"admitted under the second key", good, []ed25519.PublicKey{pk(other), pk(signer)}, ""},
		{"one wrong key: its own reason", good, []ed25519.PublicKey{pk(other)}, mismatch},
		{"two wrong keys", good, []ed25519.PublicKey{pk(other), pk(third)}, none2},
		{"three wrong keys", good, []ed25519.PublicKey{pk(other), pk(third), pk(other)},
			"signature does not verify under any of the 3 issuer keys"},
		{"tampered envelope: its reason wins over a wrong key first", tampered,
			[]ed25519.PublicKey{pk(other), pk(signer)}, `envelope field "overall" disagrees with the signed canonical`},
		{"tampered envelope under wrong keys only", tampered, []ed25519.PublicKey{pk(other), pk(third)}, none2},
		{"bad contentHash: the receipt's reason", badHash, []ed25519.PublicKey{pk(other), pk(third)},
			"contentHash mismatch with canonical bytes"},
		{"R identity: R's reason", identityR, []ed25519.PublicKey{pk(other), pk(signer)}, "signature R is a small-order point"},
		{"S of L or more, one key", sPlusL, []ed25519.PublicKey{pk(signer)}, mismatch},
		{"S of L or more, two keys", sPlusL, []ed25519.PublicKey{pk(other), pk(signer)}, none2},
	}
	for _, c := range cases {
		r, err := vaos.ParseReceipt(c.body)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		id, err := verifyIssued(r, c.issuers)
		if c.reason == "" {
			if err != nil || id != keys.ID(pk(signer)) {
				t.Errorf("%s: %q %v", c.name, id, err)
			}
			continue
		}
		if !errors.Is(err, ErrUnverified) || err.Error() != ErrUnverified.Error()+": "+c.reason {
			t.Errorf("%s: got %v, want reason %q", c.name, err, c.reason)
		}
	}
}

// addL adds L to the 32-byte little-endian scalar s, in place.
func addL(s []byte) {
	l := [32]byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		31: 0x10}
	carry := 0
	for i := range s {
		v := int(s[i]) + int(l[i]) + carry
		s[i], carry = byte(v), v>>8
	}
}

// A Guardian attestation is admitted under the second of two keys: its
// signature verifies, VerifyV2Receipt fails at the envelope, and only
// then is VerifyGuardianAttestation tried.
func TestVerifyIssuedAdmitsGuardianUnderSecondKey(t *testing.T) {
	signer := testutil.Key(t)
	canonical := `{"rules":[{"reason":"ok","ruleId":"r1","verdict":"pass"}]}`
	body, _ := json.Marshal(map[string]any{
		"canonical": canonical,
		"signature": "v2=" + base64.StdEncoding.EncodeToString(ed25519.Sign(signer, []byte(canonical))),
		"rules":     []any{map[string]any{"ruleId": "r1", "verdict": "pass", "reason": "ok", "ms": 3}},
		"totalMs":   3,
	})
	r, err := vaos.ParseReceipt(body)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.Public().(ed25519.PublicKey)
	if vaos.VerifyV2Receipt(r, pub).OK || !vaos.VerifyGuardianAttestation(r, pub).OK {
		t.Fatal("not an attestation only VerifyGuardianAttestation admits; the test is broken")
	}
	other := testutil.Key(t).Public().(ed25519.PublicKey)
	if id, err := verifyIssued(r, []ed25519.PublicKey{other, pub}); err != nil || id != keys.ID(pub) {
		t.Fatalf("verifyIssued: %q %v", id, err)
	}
}

func benchIssuers(b *testing.B, n int) []ed25519.PublicKey {
	out := make([]ed25519.PublicKey, n)
	for i := range out {
		out[i] = testutil.Key(b).Public().(ed25519.PublicKey)
	}
	return out
}

// forgedSignatureReceipt is a ~150-byte receipt whose signature has a
// valid R and S but verifies under none of the configured keys: what a
// client without a key can send.
func forgedSignatureReceipt(b *testing.B) []byte {
	body := testutil.Receipt(b, testutil.Key(b), map[string]any{"overall": "pass"})
	b.Logf("body: %d bytes", len(body))
	return body
}

// benchmarkAdmissionForgedSig measures Append refusing a forged
// signature under n issuer keys.
func benchmarkAdmissionForgedSig(b *testing.B, n int) {
	e := newEnv(b)
	c := e.cfg()
	c.IssuerKeys = benchIssuers(b, n)
	l, err := Open(c)
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	body := forgedSignatureReceipt(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := l.Append(body); !errors.Is(err, ErrUnverified) {
			b.Fatal(err)
		}
	}
}

func BenchmarkAdmissionForgedSig_1Key(b *testing.B)  { benchmarkAdmissionForgedSig(b, 1) }
func BenchmarkAdmissionForgedSig_8Keys(b *testing.B) { benchmarkAdmissionForgedSig(b, 8) }

// The same refusal by the check admission made before (legacyVerifyIssued).
func benchmarkLegacyAdmissionForgedSig(b *testing.B, n int) {
	issuers := benchIssuers(b, n)
	body := forgedSignatureReceipt(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := parseReceipt(body)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := legacyVerifyIssued(r, issuers); !errors.Is(err, ErrUnverified) {
			b.Fatal(err)
		}
	}
}

func BenchmarkLegacyAdmissionForgedSig_1Key(b *testing.B)  { benchmarkLegacyAdmissionForgedSig(b, 1) }
func BenchmarkLegacyAdmissionForgedSig_8Keys(b *testing.B) { benchmarkLegacyAdmissionForgedSig(b, 8) }
