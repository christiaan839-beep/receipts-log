// Copied from github.com/christiaan839-beep/verifiable-receipts,
// packages/verifiable-receipts-go/verify.go at commit
// 24f5c4780dba7c4f76b159b7f7844e17d0226cd6 (Apache-2.0, Copyright 2026
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
// ships, whatever key order that issuer used. A receipt or a canonical
// nested deeper than 64 is rejected before it is decoded or compared
// (VAOS 2.0 section 7.2).
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
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Receipt is the verifier-facing shape of a VAOS 2.0 receipt.
//
// Unmarshal a receipt's JSON into a Receipt to fill all four fields:
// Canonical, ContentHash and Signature from their keys, and Envelope
// from every other top-level key. Use it as a named field, not an
// embedded one: its MarshalJSON and UnmarshalJSON would be promoted
// and hide the outer struct's own fields.
type Receipt struct {
	// Canonical is the exact UTF-8 byte string the issuer signed.
	Canonical string `json:"canonical"`

	// ContentHash, when present, MUST equal "sha256:" + hex(sha256(canonical))
	// (the "sha256:" prefix is optional). A receipt read by UnmarshalJSON
	// with a contentHash key that is a string, even "", has one; a
	// Receipt built by hand has one when ContentHash is non-empty.
	ContentHash string `json:"contentHash"`

	// Signature is the v2= wire-format signature: "v2=" + base64(ed25519_sig).
	Signature string `json:"signature"`

	// Envelope holds every other top-level field of the receipt, as raw
	// JSON keyed by field name. VerifyV2Receipt requires each of them to
	// equal the same field in the parsed canonical. UnmarshalJSON fills
	// it; a Receipt built by hand with no Envelope has no fields to check.
	Envelope map[string]json.RawMessage `json:"-"`

	// hasContentHash is set by UnmarshalJSON when the contentHash key
	// holds a string, so an empty one is checked rather than skipped.
	hasContentHash bool

	// contentHashNotString is set by UnmarshalJSON when the contentHash
	// key holds a value that is neither a string nor null.
	contentHashNotString bool
}

// errReceiptTooDeep is the error for a receipt nested deeper than
// maxNesting, with the reason the verifiers give (VAOS 2.0 section 7.2).
var errReceiptTooDeep = errors.New("vaos: receipt nesting deeper than 64")

// ParseReceipt reads a receipt from JSON text as UnmarshalJSON does, but
// counts the text's depth before encoding/json sees it. json.Unmarshal
// first validates the whole input, and refuses text nested deeper than
// 10,000 with its own error before UnmarshalJSON runs; ParseReceipt gives
// "vaos: receipt nesting deeper than 64" at any depth. Like UnmarshalJSON
// it counts the text, so a duplicate key the parser discards still counts
// (VAOS 2.0 section 7.2).
func ParseReceipt(data []byte) (Receipt, error) {
	if textNestsDeeper(string(data), maxNesting) {
		return Receipt{}, errReceiptTooDeep
	}
	var r Receipt
	err := json.Unmarshal(data, &r)
	return r, err
}

// UnmarshalJSON reads a receipt object: canonical, contentHash and
// signature into their fields, and every other key into Envelope. Keys
// match exactly, case included. A canonical or signature that is not a
// string reads as empty, and a contentHash that is not a string or null
// is marked, so VerifyV2Receipt rejects them with the reasons the
// TypeScript and Python verifiers give ("missing canonical projection",
// "missing signature", "contentHash must be a string"), at the same
// step. A receipt nested deeper than 64 is an error, checked first.
func (r *Receipt) UnmarshalJSON(data []byte) error {
	if textNestsDeeper(string(data), maxNesting) {
		return errReceiptTooDeep
	}
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
			// Not a string (null reads as "" without an error).
			*target = ""
			if key == "contentHash" {
				out.contentHashNotString = true
			}
			continue
		}
		if key == "contentHash" && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			out.hasContentHash = true
		}
	}
	*r = out
	return nil
}

// MarshalJSON writes canonical, contentHash and signature, as the
// default encoding did, but writes contentHash only when the receipt
// has one: ContentHash is non-empty, or UnmarshalJSON read a string
// contentHash (even ""). So a receipt with no hash stays without one
// after a round trip, and a parsed "" stays a defect. Envelope is not
// written, as before, so a receipt read back from this output has no
// envelope fields to check against its canonical: keep the original
// bytes to verify a receipt later, not a re-marshalled copy.
func (r Receipt) MarshalJSON() ([]byte, error) {
	type wire struct {
		Canonical   string  `json:"canonical"`
		ContentHash *string `json:"contentHash,omitempty"`
		Signature   string  `json:"signature"`
	}
	w := wire{Canonical: r.Canonical, Signature: r.Signature}
	if r.ContentHash != "" || r.hasContentHash {
		hash := r.ContentHash
		w.ContentHash = &hash
	}
	return json.Marshal(w)
}

// VerifyResult is the outcome of a verification attempt. OK reports
// success; Reason is non-empty on failure.
type VerifyResult struct {
	OK     bool
	Reason string
}

// LoadEd25519PublicKeyFromPEM parses a PEM-encoded Ed25519 public key
// (the format VAOS 2.0 §6.3 publishes at
// /.well-known/sovereign-receipts/ed25519.pem).
//
// Returns an error if the PEM is not Ed25519 or is malformed, or if the
// key is a point of small order or a non-canonical encoding (VAOS 2.0
// section 7.3).
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
	if problem := ed25519KeyProblem(ed); problem != "" {
		return nil, errors.New("vaos: " + problem)
	}
	return ed, nil
}

// smallOrderKeys are the encodings of the points of small order, with the
// sign bit cleared: the libsodium blocklist ("Taming the many EdDSAs",
// Chalkias et al.). The last two are the non-canonical y = p and y = p + 1.
var smallOrderKeys = [...]string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
}

// ed25519KeyProblem says why a 32-byte Ed25519 public key is refused
// (VAOS 2.0 section 7.3), or returns "".
func ed25519KeyProblem(pub []byte) string {
	if len(pub) != ed25519.PublicKeySize {
		return ""
	}
	cleared := append([]byte(nil), pub...)
	cleared[31] &= 0x7f
	clearedHex := hex.EncodeToString(cleared)
	for _, k := range smallOrderKeys {
		if clearedHex == k {
			return "public key is a small-order point"
		}
	}
	// y >= p = 2^255 - 19: the top byte is 0x7f, the next 30 are 0xff and
	// the first is 0xed or more.
	if cleared[31] == 0x7f && cleared[0] >= 0xed && bytes.Count(cleared[1:31], []byte{0xff}) == 30 {
		return "public key is not a canonical encoding"
	}
	return ""
}

// VerifyV2Receipt verifies a single VAOS 2.0 receipt under the
// supplied Ed25519 public key.
//
// Returns OK=true only when, checked in this order:
//   - The receipt nests at most 64 deep: the receipt object is one
//     level, and each array or object in an Envelope field one more
//   - Receipt has a non-empty Canonical
//   - Receipt has a non-empty Signature starting with "v2=" and
//     followed by standard base64
//   - ContentHash (if present, even empty) equals "sha256:" + hex(sha256(canonical))
//   - The Ed25519 signature verifies over the canonical UTF-8 bytes,
//     exactly as given
//   - Canonical nests at most 64 deep, counted on its text before it
//     is decoded, and parses as a JSON object
//   - Every field in Envelope is present in that object with an equal
//     JSON value (numbers by numeric value, objects regardless of key
//     order); a field that disagrees, or that the canonical does not
//     contain, is an unsigned claim and the receipt is rejected
//
// Never panics on adversarial input. Returns a short Reason string
// on any failure.
func VerifyV2Receipt(r Receipt, pub ed25519.PublicKey) VerifyResult {
	if receiptNestsTooDeep(r) {
		return VerifyResult{OK: false, Reason: "receipt nesting deeper than 64"}
	}
	if r.Canonical == "" {
		return VerifyResult{OK: false, Reason: "missing canonical projection"}
	}
	if r.Signature == "" {
		return VerifyResult{OK: false, Reason: "missing signature"}
	}
	if !strings.HasPrefix(r.Signature, "v2=") {
		return VerifyResult{OK: false, Reason: "signature is not v2 (expected 'v2=<base64>')"}
	}
	// One signature has exactly one valid string form. The same two steps,
	// with the same reasons, as the TypeScript and Python verifiers: the
	// shape of padded standard base64 (no CR, LF or other characters),
	// then the re-encoding check, which rejects non-zero padding bits.
	sigText := r.Signature[3:]
	if !standardBase64.MatchString(sigText) {
		return VerifyResult{OK: false, Reason: "signature base64 invalid"}
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigText)
	if err != nil || base64.StdEncoding.EncodeToString(sigBytes) != sigText {
		return VerifyResult{OK: false, Reason: "signature base64 invalid: not canonical"}
	}
	if problem := ed25519KeyProblem(pub); problem != "" {
		return VerifyResult{OK: false, Reason: problem}
	}

	canonicalBytes := []byte(r.Canonical)

	if r.contentHashNotString {
		return VerifyResult{OK: false, Reason: "contentHash must be a string"}
	}

	if r.ContentHash != "" || r.hasContentHash {
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

// standardBase64 is the shape of padded standard base64 (RFC 4648 section 4).
var standardBase64 = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)

// maxNesting is the nesting limit of VAOS 2.0 section 7.2.
const maxNesting = 64

// textNestsDeeper reports whether JSON text opens more than limit arrays
// and objects at once, read from the start, valid JSON or not: outside
// strings '[' and '{' open one and ']' and '}' close one (when one is
// open); a string runs from '"' to the next '"' not escaped by '\\'.
func textNestsDeeper(text string, limit int) bool {
	open := 0
	inString := false
	for i := 0; i < len(text); i++ {
		switch c := text[i]; {
		case inString:
			if c == '\\' {
				i++
			} else if c == '"' {
				inString = false
			}
		case c == '"':
			inString = true
		case c == '[' || c == '{':
			open++
			if open > limit {
				return true
			}
		case (c == ']' || c == '}') && open > 0:
			open--
		}
	}
	return false
}

// receiptNestsTooDeep reports whether the receipt nests deeper than
// maxNesting: its object is one level, so each Envelope field may nest
// maxNesting - 1 deep. Canonical, ContentHash and Signature are strings.
func receiptNestsTooDeep(r Receipt) bool {
	for _, raw := range r.Envelope {
		if textNestsDeeper(string(raw), maxNesting-1) {
			return true
		}
	}
	return false
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

// decodeShallowJSON is decodeJSON for text that nests at most maxNesting
// deep; deeper text is an error.
func decodeShallowJSON(text string) (any, error) {
	if textNestsDeeper(text, maxNesting) {
		return nil, errors.New("nesting deeper than 64")
	}
	return decodeJSON([]byte(text))
}

// checkEnvelope returns a reason when an Envelope field disagrees with,
// or is absent from, the parsed canonical, or "" when all agree.
func checkEnvelope(r Receipt) string {
	if textNestsDeeper(r.Canonical, maxNesting) {
		return "canonical nesting deeper than 64"
	}
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
// key order. Arrays and objects deeper than maxNesting equal nothing,
// so it recurses at most maxNesting deep on any input.
func jsonEqual(a, b any) bool {
	return jsonEqualAt(a, b, 1)
}

// jsonEqualAt is jsonEqual for values at level depth (1 at the top).
func jsonEqualAt(a, b any, depth int) bool {
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
		if !ok || len(x) != len(y) || depth > maxNesting {
			return false
		}
		for i := range x {
			if !jsonEqualAt(x[i], y[i], depth+1) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) || depth > maxNesting {
			return false
		}
		for k, v := range x {
			w, present := y[k]
			if !present || !jsonEqualAt(v, w, depth+1) {
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
	// Before the rules are projected and compared: the attestation as
	// given, fields that are not signed included, nests at most 64 deep.
	if receiptNestsTooDeep(r) {
		return VerifyResult{OK: false, Reason: "receipt nesting deeper than 64"}
	}
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
	// A canonical nested too deep is not decoded here: VerifyV2Receipt
	// rejects it.
	if parsed, err := decodeShallowJSON(canonical); err == nil {
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
