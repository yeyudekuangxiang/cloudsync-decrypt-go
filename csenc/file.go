package csenc

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// IsCsencFile reports whether path refers to a file that starts with the
// csenc magic bytes.  It reads only the header - it does not attempt to
// decrypt anything or validate the checksum.
//
// The returned error is only non-nil when the file cannot be opened or
// its header cannot be read; a well-formed non-csenc file returns
// (false, nil).
func IsCsencFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	head := make([]byte, len(FileMagic))
	n, err := io.ReadFull(f, head)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return n == len(FileMagic) && bytes.Equal(head, []byte(FileMagic)), nil
}

// InspectFile reads only the leading metadata of the file at path.  See
// Inspect for the exact semantics.
func InspectFile(path string) (*Metadata, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Inspect(f)
}

// DecryptFile decrypts inPath and writes the plaintext to outPath.  It
// writes to a sibling temporary file first, atomically renames it to
// outPath on success, and removes it on failure.  Missing directories in
// outPath's prefix are created with mode 0o755.
func DecryptFile(inPath, outPath string, opts Options) error {
	src, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer src.Close()

	if dir := filepath.Dir(outPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(outPath), ".csenc-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup on any error path.
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if err := Decrypt(src, tmp, opts); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		return err
	}
	return nil
}

// OpenFile returns a Reader that yields the plaintext of the csenc file
// at path.  Callers MUST Close the returned Reader (which also closes the
// underlying file handle).
//
// This is the recommended entry point for callers that want to feed the
// plaintext into another stream consumer without touching a temp file.
func OpenFile(path string, opts Options) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return NewReaderWithCloser(f, f, opts), nil
}

// NewReaderWithCloser is like NewReader but arranges for extra to be
// closed alongside the Reader.  It is useful when the caller wraps a
// resource-owning value (an os.File, an http.Response.Body, a
// io.PipeReader) and wants a single Close on the returned Reader to tear
// everything down.
func NewReaderWithCloser(in io.Reader, extra io.Closer, opts Options) *Reader {
	r := NewReader(in, opts)
	r.extraClose = extra
	return r
}

// LoadRSAPrivateKey parses a PEM-encoded RSA private key from path.  It
// supports both the traditional "RSA PRIVATE KEY" (PKCS#1) and the
// newer "PRIVATE KEY" (PKCS#8) block types, with optional legacy
// passphrase decryption.
//
// passphrase may be empty when the key is not encrypted.
func LoadRSAPrivateKey(path, passphrase string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("csenc: no PEM block found")
	}
	der := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		if passphrase == "" {
			return nil, errors.New("csenc: private key is encrypted, passphrase required")
		}
		der, err = x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("csenc: decrypt PEM block: %w", err)
		}
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(der)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, err
		}
		rk, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("csenc: PKCS#8 key is not RSA")
		}
		return rk, nil
	default:
		return nil, fmt.Errorf("csenc: unsupported PEM block type %q", block.Type)
	}
}
