package keys

import (
	"strings"
	"testing"
)

// VAOS 2.0 section 7.3: a public key that is a point of small order or a
// non-canonical encoding is refused when it is loaded. Issuer and witness
// keys are loaded with ParsePublicKeyPEM; under the identity key one
// signature verifies every message.
var weakPEMs = map[string]struct{ pem, reason string }{
	"identity": {"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END PUBLIC KEY-----\n",
		"public key is a small-order point"},
	"y = p + 3": {"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA8P///////////////////////////////////////38=\n-----END PUBLIC KEY-----\n",
		"public key is not a canonical encoding"},
}

func TestParsePublicKeyPEMRefusesWeakKeys(t *testing.T) {
	for name, w := range weakPEMs {
		if _, err := ParsePublicKeyPEM([]byte(w.pem)); err == nil || !strings.Contains(err.Error(), w.reason) {
			t.Errorf("%s: %v, want %q", name, err, w.reason)
		}
	}
}
