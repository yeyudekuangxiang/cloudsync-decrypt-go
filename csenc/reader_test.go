package csenc_test

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yeyu/cloudsync-decrypt/csenc"
)

// TestReader_StreamsPlaintext confirms the io.Reader entry point yields
// bytes equal to the reference plaintext for every published test vector.
func TestReader_StreamsPlaintext(t *testing.T) {
	pw := loadPassword(t)
	for _, v := range samples {
		v := v
		t.Run(v.name, func(t *testing.T) {
			src, err := os.Open(filepath.Join(vectorsRoot, v.cipherRel))
			if err != nil {
				if os.IsNotExist(err) {
					t.Skip(err)
				}
				t.Fatal(err)
			}
			defer src.Close()

			r := csenc.NewReader(src, csenc.Options{Password: pw})
			defer r.Close()

			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if err := r.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			want, err := os.ReadFile(filepath.Join(vectorsRoot, v.plainRel))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("plaintext mismatch: got %d bytes, want %d", len(got), len(want))
			}
		})
	}
}

// TestReader_MetadataCallback verifies OnMetadata fires before payload
// bytes are emitted and reports the same view as Reader.Metadata().
func TestReader_MetadataCallback(t *testing.T) {
	pw := loadPassword(t)
	src, err := os.Open(filepath.Join(vectorsRoot, "testfiles-v3/csenc/5000words-3.1.txt"))
	if err != nil {
		t.Skip(err)
	}
	defer src.Close()

	var seen *csenc.Metadata
	r := csenc.NewReader(src, csenc.Options{
		Password: pw,
		OnMetadata: func(m *csenc.Metadata) {
			seen = m
		},
	})
	defer r.Close()

	// Trigger the goroutine to enter the payload phase.
	buf := make([]byte, 1024)
	if _, err := r.Read(buf); err != nil && err != io.EOF {
		t.Fatalf("Read: %v", err)
	}
	if seen == nil {
		t.Fatal("OnMetadata was not invoked before first byte")
	}
	if got := r.Metadata(); got == nil || got.Compress != seen.Compress || got.Major != seen.Major {
		t.Fatalf("Reader.Metadata() does not match callback view: %+v vs %+v", got, seen)
	}
}

// TestReader_EarlyCloseSuppresses ensures that bailing out mid-stream
// does not surface a pipe-closed error from Close().
func TestReader_EarlyCloseSuppresses(t *testing.T) {
	pw := loadPassword(t)
	src, err := os.Open(filepath.Join(vectorsRoot, "testfiles-v3/csenc/5000words-3.1.txt"))
	if err != nil {
		t.Skip(err)
	}
	defer src.Close()

	r := csenc.NewReader(src, csenc.Options{Password: pw})
	if _, err := io.CopyN(io.Discard, r, 32); err != nil {
		t.Fatalf("CopyN: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("early Close returned error: %v", err)
	}
}

// TestOpenFile_TieClose verifies OpenFile ties the underlying os.File so
// that a single Close on the Reader is enough.
func TestOpenFile_TieClose(t *testing.T) {
	pw := loadPassword(t)
	r, err := csenc.OpenFile(filepath.Join(vectorsRoot, "testfiles-v1/csenc/single-line.txt"),
		csenc.Options{Password: pw})
	if err != nil {
		t.Skip(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	want, err := os.ReadFile(filepath.Join(vectorsRoot, "testfiles-v1/plain/single-line.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("plaintext mismatch via OpenFile")
	}
}

// TestIsCsencFile spot-checks the magic sniffer.
func TestIsCsencFile(t *testing.T) {
	yes := filepath.Join(vectorsRoot, "testfiles-v1/csenc/single-line.txt")
	no := filepath.Join(vectorsRoot, "testfiles-v1/plain/single-line.txt")

	if _, err := os.Stat(yes); os.IsNotExist(err) {
		t.Skip(err)
	}
	ok, err := csenc.IsCsencFile(yes)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("csenc file not recognized")
	}
	ok, err = csenc.IsCsencFile(no)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("plaintext file falsely recognized as csenc")
	}
}

// TestInspectFile confirms the metadata-only helper stops before payload.
func TestInspectFile(t *testing.T) {
	m, err := csenc.InspectFile(filepath.Join(vectorsRoot, "testfiles-v3/csenc/5000words-3.1.txt"))
	if err != nil {
		t.Skip(err)
	}
	if m.Major != 3 || m.Minor != 1 {
		t.Fatalf("expected version 3.1, got %d.%d", m.Major, m.Minor)
	}
	if m.Encrypt != 1 || m.Compress != 1 {
		t.Fatalf("expected encrypt=1 compress=1, got encrypt=%d compress=%d", m.Encrypt, m.Compress)
	}
}

// TestReader_UsableWithChainedConsumer wires the Reader into a hash
// pipeline as the sort of downstream consumer a real caller might use.
func TestReader_UsableWithChainedConsumer(t *testing.T) {
	pw := loadPassword(t)
	src, err := os.Open(filepath.Join(vectorsRoot, "testfiles-v3/csenc/5000words-3.1.txt"))
	if err != nil {
		t.Skip(err)
	}
	defer src.Close()

	r := csenc.NewReader(src, csenc.Options{Password: pw})
	defer r.Close()

	h := md5.New()
	if _, err := io.Copy(h, r); err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(h.Sum(nil))

	want, err := os.ReadFile(filepath.Join(vectorsRoot, "testfiles-v3/plain/5000words-3.1.txt"))
	if err != nil {
		t.Fatal(err)
	}
	wantSum := md5.Sum(want)
	if got != hex.EncodeToString(wantSum[:]) {
		t.Fatalf("md5 mismatch")
	}
	// Sanity: r.Metadata() should be populated by now.
	if m := r.Metadata(); m == nil || !strings.EqualFold(m.Digest, "md5") {
		t.Fatalf("metadata not captured or unexpected digest: %+v", m)
	}
}
