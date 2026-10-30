package keys

import (
	"strings"
	"testing"
)

// VAOS 2.0 section 7.3: a public key that is not a canonical encoding of
// a point of order L (small order, non-canonical, off the curve, mixed
// order) is refused when it is loaded. Issuer and witness
// keys are loaded with ParsePublicKeyPEM; under the identity key one
// signature verifies every message.
var weakPEMs = map[string]struct{ pem, reason string }{
	"identity": {"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END PUBLIC KEY-----\n",
		"public key is a small-order point"},
	"y = p + 3": {"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA8P///////////////////////////////////////38=\n-----END PUBLIC KEY-----\n",
		"public key is not a canonical encoding"},
	// The keys of ed25519-key-off-curve.json and ed25519-key-mixed-order-8.json.
	"off the curve": {"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END PUBLIC KEY-----\n",
		"public key is not a point on the curve"},
	"mixed order": {"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAH77/z7edt5Ufm4dBwVD10+lERVeUzaPnxbgamezsPIU=\n-----END PUBLIC KEY-----\n",
		"public key is not in the prime-order subgroup"},
}

func TestParsePublicKeyPEMRefusesWeakKeys(t *testing.T) {
	for name, w := range weakPEMs {
		if _, err := ParsePublicKeyPEM([]byte(w.pem)); err == nil || !strings.Contains(err.Error(), w.reason) {
			t.Errorf("%s: %v, want %q", name, err, w.reason)
		}
	}
}
