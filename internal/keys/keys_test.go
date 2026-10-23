package keys

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.pem")
	key, err := Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(path); err == nil {
		t.Fatal("Generate overwrote an existing key")
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, err %v", st.Mode(), err)
	}
	got, insecure, err := LoadPrivateKey(path)
	if err != nil || insecure || !got.Equal(key) {
		t.Fatalf("load: %v insecure=%v", err, insecure)
	}
	pubPEM, err := PublicKeyPEM(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKey(pubPath)
	if err != nil || !pub.Equal(key.Public()) {
		t.Fatalf("public key: %v", err)
	}
	if len(ID(pub)) != 16 {
		t.Fatal("ID length")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, insecure, _ := LoadPrivateKey(path); !insecure {
		t.Fatal("world-readable key not reported")
	}
}

func TestParseRejects(t *testing.T) {
	if _, err := ParsePrivateKeyPEM([]byte("nope")); err == nil {
		t.Fatal("accepted non-PEM")
	}
	pub, err := os.ReadFile("../../testdata/conformance/public-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicKeyPEM(pub); err != nil {
		t.Fatalf("conformance key rejected: %v", err)
	}
	if _, err := ParsePrivateKeyPEM(pub); err == nil {
		t.Fatal("public key accepted as private")
	}
}

func FuzzParsePEM(f *testing.F) {
	pub, _ := os.ReadFile("../../testdata/conformance/public-key.pem")
	f.Add(pub)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePublicKeyPEM(data)
		_, _ = ParsePrivateKeyPEM(data)
	})
}
