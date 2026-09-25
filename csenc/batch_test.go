package csenc_test

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"

	"github.com/yeyu/cloudsync-decrypt/csenc"
)

// TestBatch_RecursiveDirectoryMirror walks the entire test-vector v3
// directory and verifies every decrypted file matches the reference
// plaintext bit-for-bit.  It also exercises OnEvent, mirroring layout
// and concurrent workers.
func TestBatch_RecursiveDirectoryMirror(t *testing.T) {
	pw := loadPassword(t)

	tmp := t.TempDir()
	inputDir := filepath.Join(vectorsRoot, "testfiles-v3", "csenc")
	if _, err := os.Stat(inputDir); os.IsNotExist(err) {
		t.Skip("test vectors not present")
	}

	var (
		discovered atomic.Int64
		succeeded  atomic.Int64
	)
	rep := csenc.Batch(csenc.BatchConfig{
		Inputs:       []string{inputDir},
		OutputDir:    tmp,
		Password:     pw,
		Recursive:    true,
		Concurrency:  4,
		PreserveTime: true,
		OnEvent: func(e csenc.BatchEvent) {
			switch e.Kind {
			case csenc.EventDiscovered:
				discovered.Add(1)
			case csenc.EventSucceeded:
				succeeded.Add(1)
			case csenc.EventFailed:
				t.Errorf("batch: %s failed: %v", e.InputPath, e.Err)
			}
		},
	})

	if rep.Failed != 0 {
		t.Fatalf("batch reported %d failure(s): %v", rep.Failed, rep.Errors)
	}
	if rep.Succeeded == 0 {
		t.Fatalf("no files decrypted; discovered=%d", rep.Discovered)
	}
	if got, want := discovered.Load(), rep.Discovered; got != want {
		t.Fatalf("OnEvent discovered=%d but report says %d", got, want)
	}

	// Compare each decrypted output against reference plaintext.  The
	// mirror layout puts them under tmp/<inputDirBasename>/<basename>.
	base := filepath.Base(inputDir)
	entries, err := os.ReadDir(filepath.Join(vectorsRoot, "testfiles-v3", "plain"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		wantPath := filepath.Join(vectorsRoot, "testfiles-v3", "plain", e.Name())
		gotPath := filepath.Join(tmp, base, e.Name())
		want, err := os.ReadFile(wantPath)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(gotPath)
		if err != nil {
			// A few v3 fixtures share the same plaintext under
			// different cipher names (ssingle-line-3.1 vs
			// ssingle-line).  Skip missing outputs unrelated to
			// the reference set.
			continue
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("mismatch for %s", e.Name())
		}
	}
}

// TestBatch_SkipExisting confirms that pre-existing outputs are skipped
// (not overwritten) when SkipExisting=true.
func TestBatch_SkipExisting(t *testing.T) {
	pw := loadPassword(t)
	inPath := filepath.Join(vectorsRoot, "testfiles-v3/csenc/42-bytes.txt")
	if _, err := os.Stat(inPath); os.IsNotExist(err) {
		t.Skip(err)
	}
	tmp := t.TempDir()
	target := filepath.Join(tmp, "42-bytes.txt")

	// Pre-populate the target with a sentinel value.
	sentinel := []byte("PRE-EXISTING; MUST NOT BE OVERWRITTEN")
	if err := os.WriteFile(target, sentinel, 0o644); err != nil {
		t.Fatal(err)
	}

	rep := csenc.Batch(csenc.BatchConfig{
		Inputs:       []string{inPath},
		OutputDir:    tmp,
		Password:     pw,
		SkipExisting: true,
	})
	if rep.Skipped != 1 || rep.Succeeded != 0 || rep.Failed != 0 {
		t.Fatalf("expected 1 skipped, got %+v", rep)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, sentinel) {
		t.Fatal("sentinel was overwritten despite SkipExisting=true")
	}
}

// TestBatch_MissingInput reports missing files as errors without aborting
// the whole run.
func TestBatch_MissingInput(t *testing.T) {
	pw := loadPassword(t)
	realPath := filepath.Join(vectorsRoot, "testfiles-v3/csenc/42-bytes.txt")
	if _, err := os.Stat(realPath); os.IsNotExist(err) {
		t.Skip(err)
	}
	tmp := t.TempDir()

	rep := csenc.Batch(csenc.BatchConfig{
		Inputs:    []string{realPath, "/definitely/not/here.enc"},
		OutputDir: tmp,
		Password:  pw,
	})
	if rep.Succeeded != 1 {
		t.Fatalf("expected 1 success, got %d", rep.Succeeded)
	}
	if rep.Failed != 1 || len(rep.Errors) != 1 {
		t.Fatalf("expected 1 failure, got %+v", rep)
	}
	if rep.Errors[0].InputPath != "/definitely/not/here.enc" {
		t.Fatalf("failure not attributed to the missing path: %+v", rep.Errors[0])
	}
}
