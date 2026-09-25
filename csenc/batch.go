package csenc

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// BatchConfig drives Batch.  It bundles the discovery rules (Inputs +
// Recursive + Filter), the output layout (OutputDir), the secret material
// used to unwrap each file (Password / PrivateKey), the parallelism and
// idempotency knobs, and observability hooks.
type BatchConfig struct {
	// Inputs list files and/or directories to process.  Duplicate paths
	// are deduplicated.  A missing path is recorded as an error and does
	// not abort the run.
	Inputs []string

	// OutputDir is the root under which decrypted files are placed.
	// When an input is a file, its basename is joined here.  When an
	// input is a directory (with Recursive=true), each contained file's
	// path relative to that input directory is joined here, so the
	// original hierarchy is mirrored under OutputDir.
	OutputDir string

	// Password and PrivateKey match Options; at least one must be set.
	Password   []byte
	PrivateKey *rsa.PrivateKey

	// Recursive enables walking directories in Inputs.  Directories
	// found while Recursive=false are recorded as errors.
	Recursive bool

	// Concurrency caps the number of files being decrypted in parallel.
	// Zero or negative defaults to runtime.GOMAXPROCS(0).
	Concurrency int

	// SkipExisting causes a file whose target already exists to be
	// reported as skipped rather than overwritten.
	SkipExisting bool

	// PreserveTime copies each source's mtime onto its decrypted target
	// after the atomic rename completes.
	PreserveTime bool

	// Filter, if non-nil, is consulted for every discovered file.  A
	// false return skips the file entirely (no event is emitted).  When
	// nil, files that do not begin with the csenc magic are silently
	// skipped.
	Filter func(path string, info fs.FileInfo) bool

	// OnEvent, if non-nil, is invoked for every file that reaches a
	// terminal state (succeeded, skipped or failed) as well as for
	// every file that is queued after discovery.  It is called from
	// worker goroutines and must be safe for concurrent use.
	OnEvent func(BatchEvent)

	// Logger receives non-fatal diagnostics from Batch itself.
	Logger func(format string, args ...interface{})
}

// BatchEventKind enumerates the terminal states reported by OnEvent.
type BatchEventKind int

const (
	// EventDiscovered fires once per file at enumeration time, before
	// any worker touches it.
	EventDiscovered BatchEventKind = iota
	// EventSucceeded fires after a file is decrypted and renamed into
	// place.
	EventSucceeded
	// EventSkipped fires when SkipExisting=true and the target already
	// exists.
	EventSkipped
	// EventFailed fires when decryption errored.  Err is set.
	EventFailed
)

// BatchEvent carries the observable state of one file in a batch.
type BatchEvent struct {
	Kind       BatchEventKind
	InputPath  string
	OutputPath string
	InputSize  int64
	OutputSize int64 // set on Succeeded
	Duration   time.Duration
	Err        error
}

// BatchError captures the input path that failed alongside its cause.
type BatchError struct {
	InputPath string
	Err       error
}

func (e BatchError) Error() string { return e.InputPath + ": " + e.Err.Error() }
func (e BatchError) Unwrap() error { return e.Err }

// BatchReport is the aggregate outcome of one Batch call.  Counters are
// safe to read after Batch returns.
type BatchReport struct {
	Discovered int64
	Succeeded  int64
	Skipped    int64
	Failed     int64
	BytesIn    int64
	BytesOut   int64
	Duration   time.Duration
	Errors     []BatchError
}

// Batch decrypts every csenc file reachable from cfg.Inputs, mirroring
// directory structure under cfg.OutputDir.  It never returns an error at
// the top level even when individual files fail; per-file failures are
// aggregated in the returned report.  Only unrecoverable configuration
// problems (missing OutputDir combined with missing OutputRoot resolution)
// surface via panic during argument checking is intentionally NOT done -
// callers are expected to provide a valid OutputDir.
func Batch(cfg BatchConfig) *BatchReport {
	if cfg.OutputDir == "" {
		return &BatchReport{
			Errors: []BatchError{{Err: errors.New("csenc: BatchConfig.OutputDir is required")}},
			Failed: 1,
		}
	}
	if cfg.Password == nil && cfg.PrivateKey == nil {
		return &BatchReport{
			Errors: []BatchError{{Err: errors.New("csenc: BatchConfig needs Password or PrivateKey")}},
			Failed: 1,
		}
	}

	workers := cfg.Concurrency
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}

	rep := &BatchReport{}
	startedAt := time.Now()

	// 1) Discover.  Walk inputs, emit units, count discoveries.
	units, discoverErrs := discover(cfg)
	rep.Errors = append(rep.Errors, discoverErrs...)
	rep.Failed += int64(len(discoverErrs))

	// Announce discovery through OnEvent.
	for _, u := range units {
		if cfg.OnEvent != nil {
			cfg.OnEvent(BatchEvent{
				Kind:      EventDiscovered,
				InputPath: u.inPath,
				OutputPath: u.outPath,
				InputSize: u.size,
			})
		}
	}
	atomic.AddInt64(&rep.Discovered, int64(len(units)))

	// 2) Process in parallel.
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var errMu sync.Mutex

	optTemplate := Options{
		Password:   cfg.Password,
		PrivateKey: cfg.PrivateKey,
		Logger:     cfg.Logger,
	}

	for _, u := range units {
		u := u
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()
			ev := runOne(u, cfg, optTemplate)
			switch ev.Kind {
			case EventSucceeded:
				atomic.AddInt64(&rep.Succeeded, 1)
				atomic.AddInt64(&rep.BytesIn, ev.InputSize)
				atomic.AddInt64(&rep.BytesOut, ev.OutputSize)
			case EventSkipped:
				atomic.AddInt64(&rep.Skipped, 1)
			case EventFailed:
				atomic.AddInt64(&rep.Failed, 1)
				errMu.Lock()
				rep.Errors = append(rep.Errors, BatchError{InputPath: u.inPath, Err: ev.Err})
				errMu.Unlock()
			}
			if cfg.OnEvent != nil {
				cfg.OnEvent(ev)
			}
		}()
	}
	wg.Wait()

	rep.Duration = time.Since(startedAt)
	return rep
}

// unit describes a single planned decryption job.
type unit struct {
	inPath  string
	outPath string
	size    int64
}

// discover walks the configured Inputs, resolves the mirrored output
// paths and returns the plan.
func discover(cfg BatchConfig) ([]unit, []BatchError) {
	var (
		units []unit
		errs  []BatchError
		seen  = map[string]struct{}{}
	)
	push := func(inPath, outPath string, size int64) {
		if _, dup := seen[inPath]; dup {
			return
		}
		seen[inPath] = struct{}{}
		units = append(units, unit{inPath: inPath, outPath: outPath, size: size})
	}

	filter := cfg.Filter
	if filter == nil {
		filter = defaultCsencFilter
	}

	for _, in := range cfg.Inputs {
		info, err := os.Stat(in)
		if err != nil {
			errs = append(errs, BatchError{InputPath: in, Err: err})
			continue
		}
		if info.IsDir() {
			if !cfg.Recursive {
				errs = append(errs, BatchError{InputPath: in, Err: errors.New("is a directory; pass Recursive=true to walk it")})
				continue
			}
			root := filepath.Clean(in)
			werr := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					errs = append(errs, BatchError{InputPath: p, Err: walkErr})
					return nil
				}
				if d.IsDir() {
					return nil
				}
				fi, err := d.Info()
				if err != nil {
					errs = append(errs, BatchError{InputPath: p, Err: err})
					return nil
				}
				if !filter(p, fi) {
					return nil
				}
				rel, err := filepath.Rel(root, p)
				if err != nil {
					errs = append(errs, BatchError{InputPath: p, Err: err})
					return nil
				}
				push(p, filepath.Join(cfg.OutputDir, filepath.Base(root), rel), fi.Size())
				return nil
			})
			if werr != nil {
				errs = append(errs, BatchError{InputPath: in, Err: werr})
			}
			continue
		}
		// Regular file input.
		if !filter(in, info) {
			continue
		}
		push(in, filepath.Join(cfg.OutputDir, filepath.Base(in)), info.Size())
	}
	return units, errs
}

// defaultCsencFilter accepts files whose magic bytes match FileMagic.
// The check reads only the first 17 bytes and does not touch the payload.
func defaultCsencFilter(path string, _ fs.FileInfo) bool {
	ok, err := IsCsencFile(path)
	return err == nil && ok
}

// runOne executes exactly one job and returns the terminal event.
func runOne(u unit, cfg BatchConfig, opt Options) BatchEvent {
	ev := BatchEvent{InputPath: u.inPath, OutputPath: u.outPath, InputSize: u.size}
	start := time.Now()

	if cfg.SkipExisting {
		if st, err := os.Stat(u.outPath); err == nil && !st.IsDir() {
			ev.Kind = EventSkipped
			ev.Duration = time.Since(start)
			return ev
		}
	}

	if err := DecryptFile(u.inPath, u.outPath, opt); err != nil {
		ev.Kind = EventFailed
		ev.Err = err
		ev.Duration = time.Since(start)
		return ev
	}

	if st, err := os.Stat(u.outPath); err == nil {
		ev.OutputSize = st.Size()
	}

	if cfg.PreserveTime {
		if src, err := os.Stat(u.inPath); err == nil {
			_ = os.Chtimes(u.outPath, time.Now(), src.ModTime())
		} else if cfg.Logger != nil {
			cfg.Logger("csenc/batch: cannot stat source for mtime preservation: %v", err)
		}
	}

	ev.Kind = EventSucceeded
	ev.Duration = time.Since(start)
	return ev
}

// Format returns a compact human-readable summary of the report.
func (r *BatchReport) Format() string {
	return fmt.Sprintf("discovered=%d succeeded=%d skipped=%d failed=%d bytes_in=%d bytes_out=%d elapsed=%s",
		r.Discovered, r.Succeeded, r.Skipped, r.Failed, r.BytesIn, r.BytesOut, r.Duration.Round(time.Millisecond))
}
