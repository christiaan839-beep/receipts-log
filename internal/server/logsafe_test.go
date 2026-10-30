package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"

	"github.com/christiaan839-beep/receipts-log/internal/sth"
	"github.com/christiaan839-beep/receipts-log/internal/testutil"
	"github.com/christiaan839-beep/receipts-log/internal/translog"
)

func TestLogSafe(t *testing.T) {
	for in, want := range map[string]string{
		"/v1/sth":             "/v1/sth",
		"a\nb":                `a\nb`,
		"a\r\nb":              `a\r\nb`,
		`a\nb`:                `a\\nb`,
		"a\x00b\x1bc\x7f":     `a\u0000b\u001bc\u007f`,
		"a\u0085b\u2028c":     `a\u0085b\u2028c`,
		"tab\there":           `tab\u0009here`,
		"ünïcödé ✓":           "ünïcödé ✓",
		"\xff":                `\xff`,
		"\ufffd":              "\ufffd",
		"a\xffb\xc3":          `a\xffb\xc3`,
		"a\u2029b":            `a\u2029b`,
		"x\n{\"level\":\"E\"": `x\n{"level":"E"`,
	} {
		got := logSafe(in)
		if got != want {
			t.Errorf("logSafe(%q) = %q, want %q", in, got, want)
		}
		for _, r := range got {
			if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
				t.Errorf("logSafe(%q) = %q keeps control character %U", in, got, r)
			}
		}
	}
}

// A real U+FFFD and an invalid byte log differently.
func TestLogSafeKeepsInvalidUTF8Distinct(t *testing.T) {
	if a, b := logSafe("\ufffd"), logSafe("\xff"); a == b {
		t.Fatalf("U+FFFD and 0xff both log as %q", a)
	}
}

// logLines decodes buf as JSON lines and fails if any value holds a CR or
// LF: such a value, written by a line-oriented sink, would start a new line.
func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line %q is not JSON: %v", line, err)
		}
		for k, v := range m {
			if s, ok := v.(string); ok && strings.ContainsAny(s, "\r\n") {
				t.Errorf("log field %s = %q holds CR or LF", k, s)
			}
		}
		out = append(out, m)
	}
	return out
}

// A CR or LF in a request path cannot forge a log line.
func TestRequestLogCannotBeForged(t *testing.T) {
	f := setup(t)
	var buf bytes.Buffer
	s, err := New(f.log, Options{Logger: slog.New(slog.NewJSONHandler(&buf, nil))})
	if err != nil {
		t.Fatal(err)
	}
	forged := `/v1/entries/x%0D%0A{"level":"ERROR","msg":"forged"}`
	s.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", forged, nil))
	lines := logLines(t, &buf)
	if len(lines) != 1 || lines[0]["msg"] != "request" {
		t.Fatalf("want one request line, got %v", lines)
	}
	if p, _ := lines[0]["path"].(string); p != `/v1/entries/x\r\n{"level":"ERROR","msg":"forged"}` {
		t.Fatalf("path logged as %q", p)
	}
}

// A configured witness ID may hold a backslash or a C1 control character
// (sth.ValidLabel allows both); the cosignature line logs it escaped. An ID
// with LF is refused before anything logs it.
func TestCosignatureLogEscapesWitnessID(t *testing.T) {
	witness := testutil.Key(t)
	ids := map[string]string{`w\1`: `w\\1`, "w\u00852": `w\u00852`}
	wk := map[string]ed25519.PublicKey{}
	for id := range ids {
		wk[id] = witness.Public().(ed25519.PublicKey)
	}
	l, err := translog.Open(translog.Config{
		Dir: t.TempDir(), LogID: "test-log", Key: testutil.Key(t),
		IssuerKeys:  []ed25519.PublicKey{testutil.Key(t).Public().(ed25519.PublicKey)},
		WitnessKeys: wk,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var buf bytes.Buffer
	s, err := New(l, Options{Logger: slog.New(slog.NewJSONHandler(&buf, nil))})
	if err != nil {
		t.Fatal(err)
	}
	c, err := l.STH().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	cosign := func(id string) int {
		body, _ := json.Marshal(map[string]string{"witnessId": id, "sthCanonical": string(c),
			"signature": sth.EncodeSignature(ed25519.Sign(witness, c))})
		req := httptest.NewRequest("POST", "/v1/cosignatures", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	if code := cosign("w1\n{\"level\":\"ERROR\",\"msg\":\"forged\"}"); code != http.StatusBadRequest {
		t.Fatalf("witnessId with LF: %d", code)
	}
	want := map[any]bool{}
	for id, esc := range ids {
		if code := cosign(id); code != http.StatusOK {
			t.Fatalf("cosign %q: %d", id, code)
		}
		want[esc] = true
	}
	var n int
	for _, m := range logLines(t, &buf) {
		if m["msg"] == "cosignature recorded" {
			n++
			if !want[m["witnessId"]] {
				t.Errorf("witnessId logged as %q", m["witnessId"])
			}
		}
	}
	if n != len(ids) {
		t.Fatalf("want %d cosignature lines, got %d in %s", len(ids), n, buf.String())
	}
}
