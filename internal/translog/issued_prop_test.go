package translog

// A property test and fuzz target for verifyIssued: random receipts
// (canonical, envelope, Guardian rules, signature, base64 and
// contentHash each varied) under random sets of good and refused issuer
// keys. Each verdict must equal the previous code's (legacyVerifyIssued)
// and the documented reason rule, written here independently
// (independentRule); with one key the reason must equal the previous
// code's too.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/christiaan839-beep/receipts-log/internal/keys"
	"github.com/christiaan839-beep/receipts-log/internal/testutil"
	"github.com/christiaan839-beep/receipts-log/internal/vaos"
)

type propWorld struct {
	priv  []ed25519.PrivateKey
	good  []ed25519.PublicKey
	weak  []ed25519.PublicKey
	rPool [][]byte
	fx    []reasonCase
}

func newPropWorld(t *testing.T) *propWorld {
	w := &propWorld{}
	for i := 0; i < 3; i++ {
		w.priv = append(w.priv, testutil.Key(t))
	}
	w.good = []ed25519.PublicKey{
		w.priv[0].Public().(ed25519.PublicKey), w.priv[1].Public().(ed25519.PublicKey),
		testutil.Key(t).Public().(ed25519.PublicKey), testutil.Key(t).Public().(ed25519.PublicKey),
	}
	w.fx = reasonCases(t)
	for _, c := range w.fx {
		sig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(c.r.Signature, "v2="))
		if err == nil && len(sig) == 64 {
			w.rPool = append(w.rPool, append([]byte(nil), sig[:32]...))
		}
		if vaos.Ed25519PublicKeyProblem(c.key) != "" {
			w.weak = append(w.weak, c.key)
		}
	}
	w.weak = append(w.weak, make([]byte, 31))
	if len(w.weak) < 5 {
		t.Fatalf("weak key pool too small: %d", len(w.weak))
	}
	return w
}

func deepJSON(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }

func (w *propWorld) randomReceipt(rng *rand.Rand) (vaos.Receipt, string) {
	var desc []string
	var canonical string
	switch rng.Intn(9) {
	case 0, 1, 2:
		canonical = `{"n":1,"overall":"pass"}`
	case 3, 4:
		canonical = `{"rules":[{"reason":"ok","ruleId":"r1","verdict":"pass"},{"reason":"no","ruleId":"r2","verdict":"fail"}]}`
	case 5:
		canonical = `{"overall":`
		desc = append(desc, "canon-notjson")
	case 6:
		canonical = `[1,2]`
		desc = append(desc, "canon-array")
	case 7:
		canonical = `{"overall":"pass","d":` + deepJSON(70) + `}`
		desc = append(desc, "canon-deep")
	case 8:
		canonical = ""
		desc = append(desc, "canon-empty")
	}
	m := map[string]any{}
	if canonical != "" || rng.Intn(2) == 0 {
		m["canonical"] = canonical
	}
	switch rng.Intn(8) {
	case 0, 1:
	case 2:
		m["overall"] = "pass"
	case 3:
		m["overall"] = "fail"
		desc = append(desc, "env-disagree")
	case 4:
		m["unsigned"] = 1
		desc = append(desc, "env-absent")
	case 5:
		var deep any = []any{}
		for i := 0; i < 70; i++ {
			deep = []any{deep}
		}
		m["overall"] = deep
		desc = append(desc, "env-deep")
	case 6, 7:
		rules := []any{
			map[string]any{"ruleId": "r2", "verdict": "fail", "reason": "no", "ms": 1},
			map[string]any{"ruleId": "r1", "verdict": "pass", "reason": "ok", "ms": 2},
		}
		if rng.Intn(3) == 0 {
			rules[0].(map[string]any)["verdict"] = "pass"
			desc = append(desc, "rules-tampered")
		}
		m["rules"] = rules
		if rng.Intn(2) == 0 {
			m["totalMs"] = 3
		}
		desc = append(desc, "guardian-env")
	}
	signer := w.priv[rng.Intn(3)]
	msg := []byte(canonical)
	if rng.Intn(10) == 0 {
		msg = []byte("other")
		desc = append(desc, "sig-othermsg")
	}
	sig := ed25519.Sign(signer, msg)
	switch rng.Intn(14) {
	case 0, 1, 2, 3, 4:
	case 5:
		sig = testutil.IdentityRSignature(signer, msg)
		desc = append(desc, "sig-identityR")
	case 6:
		copy(sig[:32], w.rPool[rng.Intn(len(w.rPool))])
		desc = append(desc, "sig-poolR")
	case 7:
		addL(sig[32:])
		desc = append(desc, "sig-S+L")
	case 8:
		rng.Read(sig)
		desc = append(desc, "sig-random")
	case 9:
		sig = sig[:63]
		desc = append(desc, "sig-63")
	case 10:
		sig = append(sig, 0)
		desc = append(desc, "sig-65")
	case 11:
		sig[63] |= 0x80
		desc = append(desc, "sig-highS")
	case 12:
		sig[0] ^= 1
		desc = append(desc, "sig-flipR")
	case 13:
		sig[40] ^= 1
		desc = append(desc, "sig-flipS")
	}
	sigText := "v2=" + base64.StdEncoding.EncodeToString(sig)
	switch rng.Intn(14) {
	case 0:
		sigText = "v2=@@bad@@"
		desc = append(desc, "b64-bad")
	case 1:
		if strings.HasSuffix(sigText, "==") {
			sigText = sigText[:len(sigText)-3] + "B=="
			desc = append(desc, "b64-noncanon")
		}
	case 2:
		sigText = strings.TrimPrefix(sigText, "v2=")
		desc = append(desc, "sig-nov2")
	case 3:
		sigText = ""
		desc = append(desc, "sig-empty")
	}
	if sigText != "" || rng.Intn(2) == 0 {
		m["signature"] = sigText
	}
	sum := sha256.Sum256([]byte(canonical))
	switch rng.Intn(7) {
	case 0, 1:
	case 2, 3:
		m["contentHash"] = "sha256:" + hex.EncodeToString(sum[:])
	case 4:
		m["contentHash"] = "sha256:" + strings.Repeat("0", 64)
		desc = append(desc, "ch-wrong")
	case 5:
		m["contentHash"] = ""
		desc = append(desc, "ch-empty")
	case 6:
		m["contentHash"] = 7
		desc = append(desc, "ch-nonstring")
	}
	body, _ := json.Marshal(m)
	r, err := vaos.ParseReceipt(body)
	if err != nil {
		return vaos.Receipt{}, "unparseable"
	}
	if rng.Intn(15) == 0 {
		if r.Envelope == nil {
			r.Envelope = map[string]json.RawMessage{}
		}
		r.Envelope["deep"] = json.RawMessage(deepJSON(64))
		desc = append(desc, "env-deep-direct")
	}
	return r, strings.Join(desc, ",")
}

func (w *propWorld) randomIssuers(rng *rand.Rand, includeWeak bool, extra ed25519.PublicKey) []ed25519.PublicKey {
	n := 1 + rng.Intn(4)
	out := make([]ed25519.PublicKey, 0, n+1)
	for i := 0; i < n; i++ {
		if includeWeak && rng.Intn(3) == 0 {
			out = append(out, w.weak[rng.Intn(len(w.weak))])
		} else {
			out = append(out, w.good[rng.Intn(len(w.good))])
		}
	}
	if extra != nil {
		pos := rng.Intn(len(out) + 1)
		out = append(out[:pos], append([]ed25519.PublicKey{extra}, out[pos:]...)...)
	}
	return out
}

// independentRule is the documented reason rule over full verification
// under each key, written without verifyIssued's shortcuts.
func independentRule(r vaos.Receipt, issuers []ed25519.PublicKey) (string, string) {
	var reasons []string
	for _, k := range issuers {
		res := vaos.VerifyV2Receipt(r, k)
		if res.OK || vaos.VerifyGuardianAttestation(r, k).OK {
			return keys.ID(k), ""
		}
		reasons = append(reasons, res.Reason)
	}
	sigFail := func(s string) bool {
		return s == "signature does not verify under the supplied public key" ||
			strings.HasPrefix(s, "signature R is ") || strings.HasPrefix(s, "public key is ")
	}
	for _, s := range reasons {
		if !sigFail(s) {
			return "", s
		}
	}
	for _, s := range reasons {
		if strings.HasPrefix(s, "signature R is ") {
			return "", s
		}
	}
	if len(issuers) == 1 {
		return "", reasons[0]
	}
	return "", fmt.Sprintf("signature does not verify under any of the %d issuer keys", len(issuers))
}

// TestVerifyIssuedProperty runs VERIFY_ISSUED_ITERS random receipts
// (1500 by default; 40000 makes a thorough run), then 300 fixtures
// under random key sets.
func TestVerifyIssuedProperty(t *testing.T) {
	w := newPropWorld(t)
	iters := 1500
	if s := os.Getenv("VERIFY_ISSUED_ITERS"); s != "" {
		fmt.Sscan(s, &iters)
	}
	stats := map[string]int{}
	tags := map[string]int{}
	check := func(name string, r vaos.Receipt, issuers []ed25519.PublicKey) {
		gotID, gotErr := verifyIssued(r, issuers)
		oldID, oldErr := legacyVerifyIssued(r, issuers)
		wantID, wantReason := independentRule(r, issuers)
		if gotID != oldID {
			t.Fatalf("%s: VERDICT differs: new %q old %q (%v)", name, gotID, oldID, gotErr)
		}
		if wantID != gotID {
			t.Fatalf("%s: verdict differs from rule oracle", name)
		}
		if gotID == "" {
			want := ErrUnverified.Error() + ": " + wantReason
			if gotErr == nil || gotErr.Error() != want {
				t.Fatalf("%s (%d keys): reason %v, want %q", name, len(issuers), gotErr, want)
			}
			if len(issuers) == 1 && fmt.Sprint(oldErr) != fmt.Sprint(gotErr) {
				t.Fatalf("%s: one key: reason %v, legacy %v", name, gotErr, oldErr)
			}
			stats["refused"]++
			tags[strings.TrimPrefix(gotErr.Error(), ErrUnverified.Error()+": ")]++
		} else {
			stats["admitted"]++
		}
	}
	rng := rand.New(rand.NewSource(22))
	for i := 0; i < iters; i++ {
		r, desc := w.randomReceipt(rng)
		if desc == "unparseable" {
			stats["unparseable"]++
			continue
		}
		check(fmt.Sprintf("random #%d [%s]", i, desc), r, w.randomIssuers(rng, i%2 == 0, nil))
	}
	for i := 0; i < 300; i++ {
		c := w.fx[rng.Intn(len(w.fx))]
		check("fixture "+c.name, c.r, w.randomIssuers(rng, i%2 == 0, c.key))
	}
	t.Logf("stats: %v", stats)
	for k, v := range tags {
		t.Logf("%6d  %s", v, k)
	}
}

// Every refused key in the pool is refused as an issuer or witness key
// when the log loads it, so verifyIssued meets one only in tests.
func TestRefusedKeysRefusedAtLoad(t *testing.T) {
	w := newPropWorld(t)
	for _, k := range w.weak {
		if err := validateIssuerKeys([]ed25519.PublicKey{w.good[0], k}); err == nil {
			t.Errorf("validateIssuerKeys accepted %x", k)
		}
		if err := validateWitnessKeys(map[string]ed25519.PublicKey{"w": k}); err == nil {
			t.Errorf("validateWitnessKeys accepted %x", k)
		}
		e := newEnv(t)
		c := e.cfg()
		c.IssuerKeys = []ed25519.PublicKey{w.good[0], k}
		if l, err := Open(c); err == nil {
			l.Close()
			t.Errorf("Open accepted weak issuer key %x", k)
		}
	}
	t.Logf("%d weak keys refused", len(w.weak))
}

func FuzzVerifyIssued(f *testing.F) {
	f.Add(int64(1), uint8(0))
	var w *propWorld
	f.Fuzz(func(t *testing.T, seed int64, mode uint8) {
		if w == nil {
			w = newPropWorld(t)
		}
		rng := rand.New(rand.NewSource(seed))
		r, desc := w.randomReceipt(rng)
		if desc == "unparseable" {
			return
		}
		issuers := w.randomIssuers(rng, mode%2 == 0, nil)
		gotID, gotErr := verifyIssued(r, issuers)
		oldID, _ := legacyVerifyIssued(r, issuers)
		_, want := independentRule(r, issuers)
		if gotID != oldID {
			t.Fatalf("verdict differs [%s]", desc)
		}
		if gotID == "" && gotErr.Error() != ErrUnverified.Error()+": "+want {
			t.Fatalf("reason differs [%s]: %v vs %q", desc, gotErr, want)
		}
	})
}
