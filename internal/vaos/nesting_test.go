// Copied from github.com/christiaan839-beep/verifiable-receipts,
// packages/verifiable-receipts-go/nesting_test.go at commit
// 24f5c4780dba7c4f76b159b7f7844e17d0226cd6 (Apache-2.0, Copyright 2026
// Christiaan de Wet / Sovereign Matrix). Changed: this notice added; the
// code below is otherwise unchanged. See internal/vaos/README.md.

package vaos

import (
	"encoding/json"
	"strings"
	"testing"
)

// VAOS 2.0 section 7.2: a receipt or a canonical nested deeper than 64 is
// rejected with a verdict; nothing deeper is decoded or compared.

func nestedText(levels int) string {
	return strings.Repeat("[", levels) + strings.Repeat("]", levels)
}

// deepReceipt is a receipt signed over canonical, with the field d set to
// the raw JSON value field (no field when it is empty).
func deepReceipt(t *testing.T, canonical, field string) (Receipt, VerifyResult) {
	t.Helper()
	pub, priv, _ := makeKeyPair(t)
	r := Receipt{Canonical: canonical, Signature: signV2(priv, canonical)}
	if field != "" {
		r.Envelope = map[string]json.RawMessage{"d": json.RawMessage(field)}
	}
	return r, VerifyV2Receipt(r, pub)
}

func TestNesting_AcceptsExactly64Deep(t *testing.T) {
	// The canonical's object and the receipt object are one level each;
	// the field d adds 63 more to each.
	if _, got := deepReceipt(t, `{"d":`+nestedText(63)+`}`, nestedText(63)); !got.OK {
		t.Fatalf("expected ok at depth 64, got %+v", got)
	}
}

func TestNesting_RejectsAReceipt65DeepFirst(t *testing.T) {
	_, got := deepReceipt(t, `{"a":1}`, nestedText(64))
	if got.OK || got.Reason != "receipt nesting deeper than 64" {
		t.Fatalf("got %+v", got)
	}
}

func TestNesting_RejectsACanonical65DeepValidJSONOrNot(t *testing.T) {
	for _, canonical := range []string{
		`{"d":` + nestedText(64) + `}`,
		`{"d":` + strings.Repeat("[", 64),
		`x` + strings.Repeat("{", 65),
	} {
		_, got := deepReceipt(t, canonical, "")
		if got.OK || got.Reason != "canonical nesting deeper than 64" {
			t.Fatalf("%.8s: got %+v", canonical, got)
		}
	}
}

func TestNesting_DoesNotCountBracketsInsideStrings(t *testing.T) {
	canonical := `{"s":"` + strings.Repeat("[", 100) + `\\\"` + strings.Repeat("{", 100) + `"}`
	if _, got := deepReceipt(t, canonical, ""); !got.OK {
		t.Fatalf("got %+v", got)
	}
}

func TestNesting_ReturnsAVerdictAtDepth5000And20000(t *testing.T) {
	for _, depth := range []int{5000, 20000} {
		canonical := `{"d":` + nestedText(depth) + `}`
		r, got := deepReceipt(t, canonical, nestedText(depth))
		if got.OK || got.Reason != "receipt nesting deeper than 64" {
			t.Fatalf("depth %d, deep field: got %+v", depth, got)
		}
		pub, priv, _ := makeKeyPair(t)
		r.Signature = signV2(priv, canonical)
		r.Envelope = map[string]json.RawMessage{
			"rules": json.RawMessage(`[{"ruleId":"r","verdict":"pass","reason":` + nestedText(depth) + `}]`),
		}
		if got := VerifyGuardianAttestation(r, pub); got.OK || got.Reason != "receipt nesting deeper than 64" {
			t.Fatalf("depth %d, Guardian: got %+v", depth, got)
		}
		r.Envelope = nil
		if got := VerifyV2Receipt(r, pub); got.OK || got.Reason != "canonical nesting deeper than 64" {
			t.Fatalf("depth %d, deep canonical: got %+v", depth, got)
		}
	}
}

func TestNesting_GuardianCountsUnsignedEvidence(t *testing.T) {
	// The attestation, rules and the rule are three levels; the unsigned
	// evidence adds the rest: 64 deep is accepted, 65 deep rejected.
	canonical := `{"overall":"pass","rules":[{"ruleId":"r","verdict":"pass","reason":null}]}`
	for _, c := range []struct {
		levels int
		ok     bool
	}{{61, true}, {62, false}} {
		pub, priv, _ := makeKeyPair(t)
		r := Receipt{Canonical: canonical, Signature: signV2(priv, canonical), Envelope: map[string]json.RawMessage{
			"overall": json.RawMessage(`"pass"`),
			"rules":   json.RawMessage(`[{"ruleId":"r","verdict":"pass","evidence":` + nestedText(c.levels) + `}]`),
		}}
		got := VerifyGuardianAttestation(r, pub)
		if got.OK != c.ok || (!c.ok && got.Reason != "receipt nesting deeper than 64") {
			t.Fatalf("evidence %d deep: got %+v", c.levels, got)
		}
	}
}

func TestNesting_JSONEqualIsBoundedAt64(t *testing.T) {
	for _, c := range []struct {
		levels int
		want   bool
	}{{64, true}, {65, false}, {20000, false}} {
		v, err := decodeJSON([]byte(nestedText(c.levels)))
		if c.levels > 10000 {
			// encoding/json refuses this depth; build the value directly.
			var deep any = []any{}
			for i := 1; i < c.levels; i++ {
				deep = []any{deep}
			}
			v, err = deep, nil
		}
		if err != nil {
			t.Fatalf("decode %d: %v", c.levels, err)
		}
		if got := jsonEqual(v, v); got != c.want {
			t.Fatalf("jsonEqual at %d levels = %v, want %v", c.levels, got, c.want)
		}
		if c.levels > 100 {
			continue
		}
		objects := strings.Repeat(`{"k":`, c.levels-1) + `{}` + strings.Repeat(`}`, c.levels-1)
		o, err := decodeJSON([]byte(objects))
		if err != nil {
			t.Fatalf("decode objects %d: %v", c.levels, err)
		}
		if got := jsonEqual(o, o); got != c.want {
			t.Fatalf("jsonEqual on objects at %d levels = %v, want %v", c.levels, got, c.want)
		}
	}
}

func TestNesting_ParsingRejectsAReceipt65DeepWithTheSameReason(t *testing.T) {
	const reason = "vaos: receipt nesting deeper than 64"
	for _, text := range []string{
		`{"canonical":"{}","signature":"v2=AA==","d":` + nestedText(64) + `}`,
		`{"canonical":` + nestedText(64) + `,"signature":"v2=AA=="}`,
		`{"d":` + nestedText(20000) + `}`,
	} {
		var r Receipt
		if err := json.Unmarshal([]byte(text), &r); err == nil || (len(text) < 1000 && err.Error() != reason) {
			t.Fatalf("Unmarshal %.30s: got %v", text, err)
		}
		if _, err := ParseReceipt([]byte(text)); err == nil || err.Error() != reason {
			t.Fatalf("ParseReceipt %.30s: got %v", text, err)
		}
	}
	at := `{"canonical":"{}","signature":"v2=AA==","d":` + nestedText(63) + `}`
	if r, err := ParseReceipt([]byte(at)); err != nil || len(r.Envelope) != 1 {
		t.Fatalf("ParseReceipt at 64 deep: %v", err)
	}
}
