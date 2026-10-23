// Package keys loads and writes Ed25519 keys in the PEM forms the
// verifiable-receipts tools use: PKCS #8 ("PRIVATE KEY") for private
// keys, as Node's KeyObject.export({format: "pem", type: "pkcs8"})
// writes them, and SPKI ("PUBLIC KEY") for public keys, as served at
// /.well-known/sovereign-receipts/ed25519.pem.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// MaxPEMSize bounds every key file read.
const MaxPEMSize = 64 << 10

func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxPEMSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxPEMSize {
		return nil, fmt.Errorf("keys: %s is larger than %d bytes", path, MaxPEMSize)
	}
	return data, nil
}

// ParsePrivateKeyPEM parses a PKCS #8 PEM Ed25519 private key.
func ParsePrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("keys: no PKCS #8 \"PRIVATE KEY\" PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	ed, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("keys: private key is not Ed25519")
	}
	return ed, nil
}

// ParsePublicKeyPEM parses an SPKI PEM Ed25519 public key.
func ParsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("keys: no \"PUBLIC KEY\" PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	ed, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("keys: public key is not Ed25519")
	}
	return ed, nil
}

// LoadPrivateKey reads a PKCS #8 PEM Ed25519 private key from path. It
// reports in insecure whether the file is readable by group or others.
func LoadPrivateKey(path string) (key ed25519.PrivateKey, insecure bool, err error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, false, err
	}
	data, err := readSmall(path)
	if err != nil {
		return nil, false, err
	}
	key, err = ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", path, err)
	}
	return key, st.Mode().Perm()&0o077 != 0, nil
}

// LoadPublicKey reads an SPKI PEM Ed25519 public key from path.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := readSmall(path)
	if err != nil {
		return nil, err
	}
	k, err := ParsePublicKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

// PrivateKeyPEM encodes key as PKCS #8 PEM.
func PrivateKeyPEM(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// PublicKeyPEM encodes pub as SPKI PEM.
func PublicKeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ID returns a short stable identifier for pub: the first 16 hex
// characters of SHA-256 over its SPKI DER encoding.
func ID(pub ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "invalid"
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}

// Generate creates a new Ed25519 key and writes it to path as PKCS #8
// PEM with mode 0600. It refuses to overwrite an existing file.
func Generate(path string) (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	data, err := PrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return key, nil
}
