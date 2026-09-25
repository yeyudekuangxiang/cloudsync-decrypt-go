package csenc_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/yeyu/cloudsync-decrypt/csenc"
)

// roundtrip encrypts plaintext, decrypts what came out, and returns the
// recovered bytes together with any error along the way.
func roundtrip(t *testing.T, plaintext []byte, encOpts csenc.EncryptOptions, decOpts csenc.Options) []byte {
	t.Helper()

	var encoded bytes.Buffer
	if err := csenc.Encrypt(bytes.NewReader(plaintext), &encoded, encOpts); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Sanity: header starts with the magic + magic hash.
	if !bytes.HasPrefix(encoded.Bytes(), []byte(csenc.FileMagic)) {
		t.Fatalf("encoded stream missing magic prefix")
	}

	var out bytes.Buffer
	if err := csenc.Decrypt(&encoded, &out, decOpts); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	return out.Bytes()
}

func mustLoadPrivate(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsRoot, "testfiles-secrets", "private.pem"))
	if err != nil {
		t.Skipf("private key not available: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no PEM block in private.pem")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return k.(*rsa.PrivateKey)
	}
	t.Fatalf("unexpected PEM type %q", block.Type)
	return nil
}

func mustLoadPublic(t *testing.T) *rsa.PublicKey {
	t.Helper()
	k, err := csenc.LoadRSAPublicKey(filepath.Join(vectorsRoot, "testfiles-secrets", "public.pem"))
	if err != nil {
		t.Skipf("public key not available: %v", err)
	}
	return k
}

var (
	pwSample     = []byte("s0me-pass-w0rd!!")
	textSample   = []byte("The quick brown fox jumps over the lazy dog. 中文测试。\n")
	longSample   = bytes.Repeat([]byte("plaintext line #123 padding padding padding padding\n"), 5000) // ~250 KB
	binarySample = func() []byte {
		b := make([]byte, 200*1024)
		_, _ = rand.Read(b)
		return b
	}()
)

func TestEncrypt_Roundtrip_V31_Password(t *testing.T) {
	for _, plain := range [][]byte{textSample, longSample, binarySample} {
		got := roundtrip(t, plain,
			csenc.EncryptOptions{Password: pwSample},
			csenc.Options{Password: pwSample})
		if !bytes.Equal(got, plain) {
			t.Fatalf("roundtrip mismatch (len=%d)", len(plain))
		}
	}
}

func TestEncrypt_Roundtrip_V31_PublicPrivate(t *testing.T) {
	pub := mustLoadPublic(t)
	priv := mustLoadPrivate(t)
	got := roundtrip(t, textSample,
		csenc.EncryptOptions{PublicKey: pub},
		csenc.Options{PrivateKey: priv})
	if !bytes.Equal(got, textSample) {
		t.Fatalf("public/private roundtrip mismatch")
	}
}

func TestEncrypt_Roundtrip_V31_BothRecoveryPaths(t *testing.T) {
	// Encrypt with both a password and a public key.  Both recovery
	// paths must yield the exact plaintext.
	pub := mustLoadPublic(t)
	priv := mustLoadPrivate(t)

	var encoded bytes.Buffer
	if err := csenc.Encrypt(bytes.NewReader(longSample), &encoded,
		csenc.EncryptOptions{Password: pwSample, PublicKey: pub}); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	frozen := encoded.Bytes()

	byPassword := &bytes.Buffer{}
	if err := csenc.Decrypt(bytes.NewReader(frozen), byPassword, csenc.Options{Password: pwSample}); err != nil {
		t.Fatalf("Decrypt via password: %v", err)
	}
	if !bytes.Equal(byPassword.Bytes(), longSample) {
		t.Fatal("password recovery mismatch")
	}

	byKey := &bytes.Buffer{}
	if err := csenc.Decrypt(bytes.NewReader(frozen), byKey, csenc.Options{PrivateKey: priv}); err != nil {
		t.Fatalf("Decrypt via private key: %v", err)
	}
	if !bytes.Equal(byKey.Bytes(), longSample) {
		t.Fatal("private-key recovery mismatch")
	}
}

func TestEncrypt_Roundtrip_V30(t *testing.T) {
	got := roundtrip(t, textSample,
		csenc.EncryptOptions{Password: pwSample, Major: 3, Minor: 0},
		csenc.Options{Password: pwSample})
	if !bytes.Equal(got, textSample) {
		t.Fatal("v3.0 roundtrip mismatch")
	}
}

func TestEncrypt_Roundtrip_V1(t *testing.T) {
	got := roundtrip(t, textSample,
		csenc.EncryptOptions{Password: pwSample, Major: 1, Minor: 0},
		csenc.Options{Password: pwSample})
	if !bytes.Equal(got, textSample) {
		t.Fatal("v1 roundtrip mismatch")
	}
}

func TestEncrypt_Roundtrip_NoCompress(t *testing.T) {
	off := false
	got := roundtrip(t, binarySample,
		csenc.EncryptOptions{Password: pwSample, Compress: &off},
		csenc.Options{Password: pwSample})
	if !bytes.Equal(got, binarySample) {
		t.Fatal("no-compress roundtrip mismatch")
	}
}

func TestEncrypt_Roundtrip_Empty(t *testing.T) {
	got := roundtrip(t, nil,
		csenc.EncryptOptions{Password: pwSample},
		csenc.Options{Password: pwSample})
	if len(got) != 0 {
		t.Fatalf("empty plaintext roundtrip got %d bytes", len(got))
	}
}

func TestEncrypt_FilenameMetadata(t *testing.T) {
	var encoded bytes.Buffer
	if err := csenc.Encrypt(bytes.NewReader(textSample), &encoded,
		csenc.EncryptOptions{Password: pwSample, Filename: "note.txt"}); err != nil {
		t.Fatal(err)
	}
	m, err := csenc.Inspect(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if m.Filename != "note.txt" {
		t.Fatalf("expected filename metadata to be preserved, got %q", m.Filename)
	}
	if m.Major != 3 || m.Minor != 1 {
		t.Fatalf("expected default version 3.1, got %d.%d", m.Major, m.Minor)
	}
}

func TestEncrypt_RejectsNoSecret(t *testing.T) {
	_, err := csenc.NewWriter(&bytes.Buffer{}, csenc.EncryptOptions{})
	if err == nil {
		t.Fatal("expected error when neither Password nor PublicKey is provided")
	}
}

func TestEncryptFile_Roundtrip(t *testing.T) {
	tmp := t.TempDir()
	plainPath := filepath.Join(tmp, "src.bin")
	if err := os.WriteFile(plainPath, longSample, 0o644); err != nil {
		t.Fatal(err)
	}
	encPath := filepath.Join(tmp, "src.bin.enc")
	if err := csenc.EncryptFile(plainPath, encPath, csenc.EncryptOptions{Password: pwSample}); err != nil {
		t.Fatal(err)
	}
	// Confirm on disk it starts with the magic.
	ok, err := csenc.IsCsencFile(encPath)
	if err != nil || !ok {
		t.Fatalf("encrypted file not recognised as csenc: ok=%v err=%v", ok, err)
	}
	recPath := filepath.Join(tmp, "src.bin.recovered")
	if err := csenc.DecryptFile(encPath, recPath, csenc.Options{Password: pwSample}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, longSample) {
		t.Fatal("EncryptFile -> DecryptFile mismatch")
	}
}
