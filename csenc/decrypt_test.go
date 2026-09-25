package csenc_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/yeyu/cloudsync-decrypt/csenc"
)

// vectorsRoot is the local path to a clone of marnix/synology-decrypt.
// Its `tests/` folder ships publicly-known test vectors (encrypted files
// with matching plaintext and a fixed password / private key pair) that we
// use as ground truth.  If the directory is not present the tests are
// skipped rather than failed, so the package still `go test`'s cleanly in
// isolation.
const vectorsRoot = "/tmp/synology-decrypt/tests"

type vector struct {
	name      string
	cipherRel string
	plainRel  string
}

func loadPassword(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorsRoot, "testfiles-secrets", "password.txt"))
	if err != nil {
		t.Skipf("missing password file: %v", err)
	}
	return bytes.TrimRight(b, "\r\n")
}

func loadPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsRoot, "testfiles-secrets", "private.pem"))
	if err != nil {
		t.Skipf("missing private key: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("private.pem: no PEM block")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("parse RSA private key: %v", err)
		}
		return k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("parse PKCS#8 private key: %v", err)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			t.Fatal("PKCS#8 private key is not RSA")
		}
		return rk
	default:
		t.Fatalf("unsupported PEM type %q", block.Type)
		return nil
	}
}

var samples = []vector{
	{"v3-42bytes", "testfiles-v3/csenc/42-bytes.txt", "testfiles-v3/plain/42-bytes.txt"},
	{"v3-ssingle", "testfiles-v3/csenc/ssingle-line.txt", "testfiles-v3/plain/ssingle-line.txt"},
	{"v31-ssingle", "testfiles-v3/csenc/ssingle-line-3.1.txt", "testfiles-v3/plain/ssingle-line.txt"},
	{"v31-5000words", "testfiles-v3/csenc/5000words-3.1.txt", "testfiles-v3/plain/5000words-3.1.txt"},
	{"v1-single", "testfiles-v1/csenc/single-line.txt", "testfiles-v1/plain/single-line.txt"},
}

func runVector(t *testing.T, v vector, opts csenc.Options) {
	t.Helper()
	inPath := filepath.Join(vectorsRoot, v.cipherRel)
	wantPath := filepath.Join(vectorsRoot, v.plainRel)

	src, err := os.Open(inPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("test vector missing: %v", err)
		}
		t.Fatal(err)
	}
	defer src.Close()

	var out bytes.Buffer
	if err := csenc.Decrypt(src, &out, opts); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	want, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read expected plaintext: %v", err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("plaintext mismatch: got %d bytes, want %d bytes", out.Len(), len(want))
	}
}

func TestDecrypt_Password(t *testing.T) {
	password := loadPassword(t)
	for _, v := range samples {
		v := v
		t.Run(v.name, func(t *testing.T) {
			runVector(t, v, csenc.Options{Password: password})
		})
	}
}

func TestDecrypt_PrivateKey(t *testing.T) {
	key := loadPrivateKey(t)
	for _, v := range samples {
		v := v
		t.Run(v.name, func(t *testing.T) {
			runVector(t, v, csenc.Options{PrivateKey: key})
		})
	}
}

func TestDecrypt_WrongPassword(t *testing.T) {
	loadPassword(t) // skip if vectors absent
	v := samples[0]
	inPath := filepath.Join(vectorsRoot, v.cipherRel)
	src, err := os.Open(inPath)
	if err != nil {
		t.Skip(err)
	}
	defer src.Close()

	var out bytes.Buffer
	err = csenc.Decrypt(src, &out, csenc.Options{Password: []byte("not-the-password")})
	if err == nil {
		t.Fatal("expected error with wrong password, got nil")
	}
}
