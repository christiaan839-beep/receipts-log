// Package sth implements the Signed Tree Head of the verifiable-receipts
// transparency log (docs/specs/transparency-log.md §3.3).
//
// An STH is the object
//
//	{"v":1,"logId":…,"treeSize":…,"rootHash":"<hex>","timestamp":"<ISO 8601>","signature":"v2=<base64>"}
//
// and its signing input is the canonical string
//
//	{"logId":…,"rootHash":…,"timestamp":…,"treeSize":…,"v":1}
//
// with the keys in that order and no whitespace, exactly as JavaScript's
// JSON.stringify writes it. The signature is "v2=" followed by the
// standard base64 of the Ed25519 signature over the canonical's UTF-8
// bytes.
package sth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/christiaan839-beep/receipts-log/internal/merkle"
)

// Version is the only STH version defined by the specification.
const Version = 1

// MaxTreeSize is the largest tree size an STH may carry: 2^53 - 1, the
// largest integer a JavaScript number holds exactly. Beyond it the
// TypeScript verifier could not reproduce the canonical string.
const MaxTreeSize = 1<<53 - 1

// MaxLogIDLen bounds the log identifier.
const MaxLogIDLen = 256

// TimeLayout is the layout of JavaScript's Date.prototype.toISOString.
const TimeLayout = "2006-01-02T15:04:05.000Z"

// STH is a signed tree head.
type STH struct {
	V         int    `json:"v"`
	LogID     string `json:"logId"`
	TreeSize  uint64 `json:"treeSize"`
	RootHash  string `json:"rootHash"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature,omitempty"`
}

// Errors returned by Validate and Verify.
var (
	ErrInvalid   = errors.New("sth: invalid tree head")
	ErrSignature = errors.New("sth: signature does not verify")
)

// New builds an unsigned STH.
func New(logID string, size uint64, root merkle.Hash, at time.Time) STH {
	return STH{
		V:         Version,
		LogID:     logID,
		TreeSize:  size,
		RootHash:  root.String(),
		Timestamp: FormatTime(at),
	}
}

// FormatTime formats t as JavaScript's toISOString does.
func FormatTime(t time.Time) string { return t.UTC().Format(TimeLayout) }

// ValidateLogID checks a log identifier: non-empty, at most MaxLogIDLen
// bytes, valid UTF-8 and free of control characters.
func ValidateLogID(id string) error {
	if id == "" || len(id) > MaxLogIDLen || !utf8.ValidString(id) {
		return fmt.Errorf("%w: logId must be 1-%d bytes of UTF-8", ErrInvalid, MaxLogIDLen)
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: logId contains a control character", ErrInvalid)
		}
	}
	return nil
}

// Validate checks every field except the signature.
func (s STH) Validate() error {
	if s.V != Version {
		return fmt.Errorf("%w: v must be %d", ErrInvalid, Version)
	}
	if err := ValidateLogID(s.LogID); err != nil {
		return err
	}
	if s.TreeSize > MaxTreeSize {
		return fmt.Errorf("%w: treeSize exceeds 2^53-1", ErrInvalid)
	}
	if _, err := s.Root(); err != nil {
		return fmt.Errorf("%w: rootHash: %v", ErrInvalid, err)
	}
	if len(s.Timestamp) > 64 || !utf8.ValidString(s.Timestamp) {
		return fmt.Errorf("%w: timestamp", ErrInvalid)
	}
	if _, err := time.Parse(time.RFC3339Nano, s.Timestamp); err != nil {
		return fmt.Errorf("%w: timestamp is not ISO 8601", ErrInvalid)
	}
	return nil
}

// Root decodes the root hash. It requires lowercase hex, the form every
// reference implementation emits and compares.
func (s STH) Root() (merkle.Hash, error) {
	if strings.ToLower(s.RootHash) != s.RootHash {
		return merkle.Hash{}, errors.New("rootHash must be lowercase hex")
	}
	return merkle.ParseHash(s.RootHash)
}

// Canonical returns the signing input. It fails when a string field is
// not valid UTF-8 (JavaScript could not produce the same bytes).
func (s STH) Canonical() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`{"logId":`)
	if err := writeJSString(&b, s.LogID); err != nil {
		return nil, err
	}
	b.WriteString(`,"rootHash":`)
	if err := writeJSString(&b, s.RootHash); err != nil {
		return nil, err
	}
	b.WriteString(`,"timestamp":`)
	if err := writeJSString(&b, s.Timestamp); err != nil {
		return nil, err
	}
	b.WriteString(`,"treeSize":`)
	b.WriteString(strconv.FormatUint(s.TreeSize, 10))
	b.WriteString(`,"v":`)
	b.WriteString(strconv.Itoa(s.V))
	b.WriteByte('}')
	return b.Bytes(), nil
}

// writeJSString writes s as JSON.stringify does: quote, backslash and
// the C0 controls escaped (\b \f \n \r \t, otherwise \u00xx in lowercase
// hex), every other character as UTF-8.
func writeJSString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: string is not valid UTF-8", ErrInvalid)
	}
	const hexDigits = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[c>>4])
				b.WriteByte(hexDigits[c&0xf])
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return nil
}

// Sign validates s, signs its canonical string and returns s with the
// signature set.
func Sign(s STH, key ed25519.PrivateKey) (STH, error) {
	if err := s.Validate(); err != nil {
		return STH{}, err
	}
	c, err := s.Canonical()
	if err != nil {
		return STH{}, err
	}
	s.Signature = EncodeSignature(ed25519.Sign(key, c))
	return s, nil
}

// EncodeSignature returns the v2 wire form of an Ed25519 signature.
func EncodeSignature(sig []byte) string {
	return "v2=" + base64.StdEncoding.EncodeToString(sig)
}

// DecodeSignature parses a v2 wire signature.
func DecodeSignature(wire string) ([]byte, error) {
	if !strings.HasPrefix(wire, "v2=") {
		return nil, fmt.Errorf("%w: signature is not v2", ErrSignature)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(wire[3:])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signature is not base64 of 64 bytes", ErrSignature)
	}
	// Strict still skips CR and LF; one signature has one spelling.
	if base64.StdEncoding.EncodeToString(sig) != wire[3:] {
		return nil, fmt.Errorf("%w: signature is not canonical base64", ErrSignature)
	}
	return sig, nil
}

// Verify validates s and checks its signature under pub.
func Verify(s STH, pub ed25519.PublicKey) error {
	if err := s.Validate(); err != nil {
		return err
	}
	c, err := s.Canonical()
	if err != nil {
		return err
	}
	return VerifyBytes(c, s.Signature, pub)
}

// VerifyBytes checks a v2 wire signature over msg under pub.
func VerifyBytes(msg []byte, wire string, pub ed25519.PublicKey) error {
	sig, err := DecodeSignature(wire)
	if err != nil {
		return err
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, msg, sig) {
		return ErrSignature
	}
	return nil
}

// ParseCanonical parses a canonical STH string and returns the STH it
// encodes (without a signature). It accepts only the exact canonical
// form: the input must equal the canonical re-encoding of its parse.
func ParseCanonical(data []byte) (STH, error) {
	var s STH
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return STH{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return STH{}, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	if s.Signature != "" {
		return STH{}, fmt.Errorf("%w: canonical form has no signature", ErrInvalid)
	}
	if err := s.Validate(); err != nil {
		return STH{}, err
	}
	c, err := s.Canonical()
	if err != nil {
		return STH{}, err
	}
	if !bytes.Equal(c, data) {
		return STH{}, fmt.Errorf("%w: not in canonical form", ErrInvalid)
	}
	return s, nil
}

// Response is the wire shape served at GET /v1/sth and
// GET /api/transparency/sth: the STH with its canonical string, as the
// verifiable-receipts witness CLI expects.
type Response struct {
	STH
	Canonical string `json:"canonical"`
}

// NewResponse returns the wire shape of a signed STH.
func NewResponse(s STH) (Response, error) {
	c, err := s.Canonical()
	if err != nil {
		return Response{}, err
	}
	return Response{STH: s, Canonical: string(c)}, nil
}
