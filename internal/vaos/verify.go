// Copied from github.com/christiaan839-beep/verifiable-receipts,
// packages/verifiable-receipts-go/verify.go at commit
// 732fce9d4d050a0acdaa2c004a08f57af4c5ec5c (Apache-2.0, Copyright 2026
// Christiaan de Wet / Sovereign Matrix). Changed: this notice added; the
// code below is otherwise unchanged. See internal/vaos/README.md.

// Package vaos verifies VAOS 2.0 receipts (Ed25519) and RFC 9162
// transparency-log inclusion proofs, using only the Go standard library.
//
// It verifies v2 (Ed25519) receipts only; v3 (Ed25519 + ML-DSA-65)
// needs a post-quantum signature library and is not verified here.
//
// VerifyV2Receipt checks the receipt's Canonical string as given: its
// contentHash, its Ed25519 signature, and that every other top-level
// field of the receipt equals the same field in the parsed canonical.
// It does not re-derive the canonical from the other fields, so it
// accepts receipts from any issuer that signs the canonical string it
// ships, whatever key order that issuer used.
package vaos

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Receipt is the verifier-facing shape of a VAOS 2.0 receipt.
//
// Unmarshal a receipt's JSON into a Receipt to fill all four fields:
// Canonical, ContentHash and Signature from their keys, and Envelope
// from every other top-level key.
type Receipt struct {
	// Canonical is the exact UTF-8 byte string the issuer signed.
	Canonical string `json:"canonical"`

	// ContentHash, when non-empty, MUST equal "sha256:" + hex(sha256(canonical))
	// (the "sha256:" prefix is optional).
	ContentHash string `json:"contentHash"`

	// Signature is the v2= wire-format signature: "v2=" + base64(ed25519_sig).
	Signature string `json:"signature"`

	// Envelope holds every other top-level field of the receipt, as raw
	// JSON keyed by field name. VerifyV2Receipt requires each of them to
	// equal the same field in the parsed canonical. UnmarshalJSON fills
	// it; a Receipt built by hand with no Envelope has no fields to check.
	Envelope map[string]json.RawMessage `json:"-"`
}

// UnmarshalJSON reads a receipt object: canonical, contentHash and
// signature into their fields (each must be a string or null), and
// every other key into Envelope. Keys match exactly, case included.
func (r *Receipt) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if fields == nil {
		return errors.New("vaos: receipt is not a JSON object")
	}
	out := Receipt{}
	for key, raw := range fields {
		var target *string
		switch key {
		case "canonical":
			target = &out.Canonical
		case "contentHash":
			target = &out.ContentHash
		case "signature":
			target = &out.Signature
		default:
			if out.Envelope == nil {
				out.Envelope = make(map[string]json.RawMessage)
			}
			out.Envelope[key] = raw
			continue
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return errors.New("vaos: receipt field " + strconv.Quote(key) + " is not a string")
		}
	}
	*r = out
	return nil
}

// VerifyResult is the outcome of a verification attempt. OK reports
// success; Reason is non-empty on failure.
type VerifyResult struct {
	OK     bool
	Reason string
}

// LoadEd25519PublicKeyFromPEM parses a PEM-encoded Ed25519 public key
// (the same format served at /.well-known/sovereign-receipts/ed25519.pem).
//
// Returns an error if the PEM is not Ed25519 or is malformed.
func LoadEd25519PublicKeyFromPEM(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("vaos: PEM block not found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("vaos: PEM is not an Ed25519 public key")
	}
	return ed, nil
}

// VerifyV2Receipt verifies a single VAOS 2.0 receipt under the
// supplied Ed25519 public key.
//
// Returns OK=true only when, checked in this order:
//   - Receipt has a non-empty Canonical
//   - Receipt has a non-empty Signature starting with "v2=" and
//     followed by standard base64
//   - ContentHash (if present) equals "sha256:" + hex(sha256(canonical))
//   - The Ed25519 signature verifies over the canonical UTF-8 bytes,
//     exactly as given
//   - Canonical parses as a JSON object
//   - Every field in Envelope is present in that object with an equal
//     JSON value (numbers by numeric value, objects regardless of key
//     order); a field that disagrees, or that the canonical does not
//     contain, is an unsigned claim and the receipt is rejected
//
// Never panics on adversarial input. Returns a short Reason string
// on any failure.
func VerifyV2Receipt(r Receipt, pub ed25519.PublicKey) VerifyResult {
	if r.Canonical == "" {
		return VerifyResult{OK: false, Reason: "missing canonical projection"}
	}
	if r.Signature == "" {
		return VerifyResult{OK: false, Reason: "missing signature"}
	}
	if !strings.HasPrefix(r.Signature, "v2=") {
		return VerifyResult{OK: false, Reason: "signature is not v2 (expected 'v2=<base64>')"}
	}
	// One signature has exactly one valid string form: Strict rejects
	// non-zero padding bits, and the re-encoding check rejects what the
	// decoder skips even in strict mode (CR and LF anywhere in the input).
	sigText := r.Signature[3:]
	sigBytes, err := base64.StdEncoding.Strict().DecodeString(sigText)
	if err != nil {
		return VerifyResult{OK: false, Reason: "signature base64 invalid: " + err.Error()}
	}
	if base64.StdEncoding.EncodeToString(sigBytes) != sigText {
		return VerifyResult{OK: false, Reason: "signature base64 invalid: not canonical padded standard base64"}
	}

	canonicalBytes := []byte(r.Canonical)

	if r.ContentHash != "" {
		actual := sha256.Sum256(canonicalBytes)
		expected := strings.TrimPrefix(r.ContentHash, "sha256:")
		actualHex := hex.EncodeToString(actual[:])
		if actualHex != expected {
			return VerifyResult{OK: false, Reason: "contentHash mismatch with canonical bytes"}
		}
	}

	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, canonicalBytes, sigBytes) {
		return VerifyResult{
			OK:     false,
			Reason: "signature does not verify under the supplied public key",
		}
	}

	// Only now parse the canonical: these bytes are authenticated.
	if reason := checkEnvelope(r); reason != "" {
		return VerifyResult{OK: false, Reason: reason}
	}

	return VerifyResult{OK: true}
}

// decodeJSON parses one JSON value, keeping numbers as json.Number,
// and rejects trailing data.
func decodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return v, nil
}

// checkEnvelope returns a reason when an Envelope field disagrees with,
// or is absent from, the parsed canonical, or "" when all agree.
func checkEnvelope(r Receipt) string {
	parsed, err := decodeJSON([]byte(r.Canonical))
	if err != nil {
		return "canonical is not valid JSON"
	}
	signed, ok := parsed.(map[string]any)
	if !ok {
		return "canonical is not a JSON object"
	}
	keys := make([]string, 0, len(r.Envelope))
	for key := range r.Envelope {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key == "canonical" || key == "contentHash" || key == "signature" {
			continue
		}
		want, present := signed[key]
		if !present {
			return `envelope field "` + key + `" is not in the signed canonical`
		}
		have, err := decodeJSON(r.Envelope[key])
		if err != nil {
			return `envelope field "` + key + `" is not valid JSON`
		}
		if !jsonEqual(have, want) {
			return `envelope field "` + key + `" disagrees with the signed canonical`
		}
	}
	return ""
}

// jsonEqual reports deep JSON-value equality: the same JSON type and
// the same value, with numbers compared by numeric value (1 equals
// 1.0), arrays element by element and objects key by key regardless of
// key order. Both values come from decodeJSON.
func jsonEqual(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case json.Number:
		y, ok := b.(json.Number)
		return ok && numbersEqual(x, y)
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !jsonEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, present := y[k]
			if !present || !jsonEqual(v, w) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// numbersEqual compares two JSON number literals by value (1 equals
// 1.0). A number of magnitude 2^53 or more equals nothing: a double, the
// only number type JavaScript's JSON.parse has, cannot tell 2^53 from
// 2^53 + 1, so every verifier rejects such a number in a repeated field
// rather than disagree about it. Below 2^53 every integer is exact as a
// double, and comparing the doubles is exact comparison.
func numbersEqual(a, b json.Number) bool {
	x, okA := numberValue(a)
	y, okB := numberValue(b)
	if !okA || !okB {
		return false
	}
	return math.Abs(x) < 1<<53 && math.Abs(y) < 1<<53 && x == y
}

// numberValue reads n as the nearest double; a literal out of range
// reads as an infinity, as JSON.parse reads it.
func numberValue(n json.Number) (float64, bool) {
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return 0, false
	}
	return f, true
}

// VerifyGuardianAttestation verifies a signed Guardian attestation from
// the TypeScript runGuardian. It applies the checks of VerifyV2Receipt
// to the part of the attestation that its canonical signs, as the
// TypeScript verifyGuardianAttestation does:
//
//   - totalMs is not signed and is not checked.
//   - Each rule in rules is compared as {ruleId, verdict, reason} (a
//     missing reason reads as null); its durationMs and evidence are not
//     signed and are not checked. The order of rules does not matter.
//   - Every other Envelope field must equal the canonical's, as in
//     VerifyV2Receipt.
//
// Do not rely on totalMs, durationMs or evidence: no signature covers
// them.
func VerifyGuardianAttestation(r Receipt, pub ed25519.PublicKey) VerifyResult {
	return VerifyV2Receipt(guardianSignedView(r), pub)
}

// guardianSignedView returns a copy of r without the Guardian fields
// that the canonical does not sign.
func guardianSignedView(r Receipt) Receipt {
	if len(r.Envelope) == 0 {
		return r
	}
	view := r
	view.Envelope = make(map[string]json.RawMessage, len(r.Envelope))
	for key, raw := range r.Envelope {
		if key != "totalMs" {
			view.Envelope[key] = raw
		}
	}
	if raw, ok := view.Envelope["rules"]; ok {
		if projected, ok := guardianRules(raw, r.Canonical); ok {
			view.Envelope["rules"] = projected
		}
	}
	return view
}

// guardianRules projects each envelope rule to the {ruleId, verdict,
// reason} the Guardian canonical signs. When the projected rules are
// the same multiset as the canonical's rules, it returns them in the
// canonical's order (the canonical sorts them by ruleId); otherwise in
// their own order, so the envelope check rejects them.
func guardianRules(raw json.RawMessage, canonical string) (json.RawMessage, bool) {
	decoded, err := decodeJSON(raw)
	if err != nil {
		return nil, false
	}
	rules, ok := decoded.([]any)
	if !ok {
		return nil, false
	}
	projected := make([]any, len(rules))
	for i, rule := range rules {
		m, isObject := rule.(map[string]any)
		if !isObject {
			projected[i] = rule
			continue
		}
		p := map[string]any{"reason": m["reason"]}
		for _, key := range []string{"ruleId", "verdict"} {
			if v, present := m[key]; present {
				p[key] = v
			}
		}
		projected[i] = p
	}

	ordered := projected
	if parsed, err := decodeJSON([]byte(canonical)); err == nil {
		if signed, ok := parsed.(map[string]any); ok {
			if signedRules, ok := signed["rules"].([]any); ok {
				if matched, ok := matchOrder(projected, signedRules); ok {
					ordered = matched
				}
			}
		}
	}
	out, err := json.Marshal(ordered)
	if err != nil {
		return nil, false
	}
	return out, true
}

// matchOrder returns have reordered to the order of want, when the two
// hold equal values the same number of times.
func matchOrder(have, want []any) ([]any, bool) {
	if len(have) != len(want) {
		return nil, false
	}
	remaining := append([]any(nil), have...)
	out := make([]any, 0, len(want))
	for _, w := range want {
		found := -1
		for i, h := range remaining {
			if jsonEqual(h, w) {
				found = i
				break
			}
		}
		if found < 0 {
			return nil, false
		}
		out = append(out, remaining[found])
		remaining = append(remaining[:found], remaining[found+1:]...)
	}
	return out, true
}
