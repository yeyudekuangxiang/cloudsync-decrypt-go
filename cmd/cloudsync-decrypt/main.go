// Command cloudsync-decrypt is a thin CLI wrapper around the csenc
// library.  It supports both directions: decryption (the default) and
// encryption (with -encrypt).  Every real code path lives in csenc.
package main

import (
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yeyu/cloudsync-decrypt/csenc"
)

func main() {
	fs := flag.NewFlagSet("cloudsync-decrypt", flag.ExitOnError)

	var (
		encryptMode = fs.Bool("encrypt", false, "encrypt inputs instead of decrypting them")
		inspectMode = fs.Bool("inspect", false, "print each input's metadata as JSON and exit")

		pwFile   = fs.String("password-file", "", "path to a file whose contents (trailing newline stripped) form the password")
		pwInline = fs.String("password", "", "password on the command line (leaks via /proc); prefer -password-file")
		pkPEM    = fs.String("private-key", "", "path to a PEM-encoded RSA private key (decrypt only)")
		pkPass   = fs.String("private-key-password", "", "passphrase protecting the private key, if any")
		pubPEM   = fs.String("public-key", "", "path to a PEM-encoded RSA public key (encrypt only)")

		outDir    = fs.String("outdir", "", "directory to write outputs under, mirroring input directory structure")
		outFile   = fs.String("o", "", "write output to this exact path (single input only)")
		recursive = fs.Bool("r", false, "recurse into input directories")
		jobs      = fs.Int("j", 0, "maximum concurrent files (default: GOMAXPROCS)")
		skipExist = fs.Bool("skip-existing", false, "skip inputs whose target file already exists")
		keepMTime = fs.Bool("preserve-time", true, "copy each source's mtime onto the target")
		verbose   = fs.Bool("v", false, "log worker warnings and unknown metadata fields")

		version  = fs.String("version", "3.1", "csenc version to write when encrypting: 1.0, 3.0 or 3.1")
		compress = fs.Bool("compress", true, "LZ4-frame the payload when encrypting")
	)

	fs.Usage = func() {
		w := fs.Output()
		fmt.Fprintln(w, "usage: cloudsync-decrypt [flags] input [input ...]")
		fmt.Fprintln(w, "       cloudsync-decrypt -encrypt [flags] input [input ...]")
		fmt.Fprintln(w, "       cloudsync-decrypt -inspect [flags] input [input ...]")
		fmt.Fprintln(w, "Flags:")
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])

	inputs := fs.Args()
	if len(inputs) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	logger := func(string, ...interface{}) {}
	if *verbose {
		logger = func(f string, a ...interface{}) { log.Printf(f, a...) }
	}

	// -inspect is a metadata-only utility; it does not care about the
	// direction flags.
	if *inspectMode {
		runInspect(inputs, *recursive)
		return
	}

	// Common output validation.
	if *outFile == "" && *outDir == "" {
		fail("specify either -o (single file) or -outdir (batch/mirror)")
	}
	if *outFile != "" && len(inputs) != 1 {
		fail("-o accepts a single input; use -outdir for multiple inputs")
	}
	if *outFile != "" && *recursive {
		fail("-o cannot be combined with -r; use -outdir for directory inputs")
	}

	if *encryptMode {
		runEncrypt(inputs, *outFile, *outDir, *recursive, *jobs,
			*skipExist, *keepMTime, *pwFile, *pwInline, *pubPEM,
			*version, *compress, logger)
		return
	}
	runDecrypt(inputs, *outFile, *outDir, *recursive, *jobs,
		*skipExist, *keepMTime, *pwFile, *pwInline, *pkPEM, *pkPass, logger)
}

// ------------------------------------------------------------------
// Decryption paths
// ------------------------------------------------------------------

func runDecrypt(inputs []string, outFile, outDir string, recursive bool, jobs int,
	skipExist, keepMTime bool, pwFile, pwInline, pkPEM, pkPass string,
	logger csencLogger) {

	pw, key := loadDecryptSecrets(pwFile, pwInline, pkPEM, pkPass)
	if pw == nil && key == nil {
		fail("supply at least one of -password-file / -password / -private-key")
	}

	if outFile != "" {
		if err := csenc.DecryptFile(inputs[0], outFile, csenc.Options{
			Password:   pw,
			PrivateKey: key,
			Logger:     logger,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", inputs[0], err)
			os.Exit(1)
		}
		fmt.Printf("%s -> %s\n", inputs[0], outFile)
		return
	}

	rep := csenc.Batch(csenc.BatchConfig{
		Inputs:       inputs,
		OutputDir:    outDir,
		Password:     pw,
		PrivateKey:   key,
		Recursive:    recursive,
		Concurrency:  jobs,
		SkipExisting: skipExist,
		PreserveTime: keepMTime,
		Logger:       logger,
		OnEvent:      makeProgressReporter("decrypt"),
	})
	printReport(rep)
	if rep.Failed > 0 {
		os.Exit(1)
	}
}

// ------------------------------------------------------------------
// Encryption paths
// ------------------------------------------------------------------

func runEncrypt(inputs []string, outFile, outDir string, recursive bool, jobs int,
	skipExist, keepMTime bool, pwFile, pwInline, pubPEM, versionStr string,
	compress bool, logger csencLogger) {

	pw, pubKey := loadEncryptSecrets(pwFile, pwInline, pubPEM)
	if pw == nil && pubKey == nil {
		fail("supply at least one of -password-file / -password / -public-key")
	}

	major, minor, err := parseVersion(versionStr)
	if err != nil {
		fail("%v", err)
	}

	buildOpts := func(inPath string) csenc.EncryptOptions {
		return csenc.EncryptOptions{
			Password:  pw,
			PublicKey: pubKey,
			Major:     major,
			Minor:     minor,
			Compress:  &compress,
			Filename:  filepath.Base(inPath),
			Logger:    logger,
		}
	}

	if outFile != "" {
		if err := csenc.EncryptFile(inputs[0], outFile, buildOpts(inputs[0])); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", inputs[0], err)
			os.Exit(1)
		}
		fmt.Printf("%s -> %s\n", inputs[0], outFile)
		return
	}

	rep := runEncryptBatch(inputs, outDir, recursive, jobs, skipExist, keepMTime, buildOpts, logger)
	printReport(rep)
	if rep.Failed > 0 {
		os.Exit(1)
	}
}

// runEncryptBatch mirrors csenc.Batch semantics but for the encryption
// direction.  It discovers files (recursively when asked), respects
// SkipExisting and PreserveTime, and prints per-file progress through the
// same reporter used by the decrypt path.
func runEncryptBatch(inputs []string, outDir string, recursive bool, jobs int,
	skipExist, keepMTime bool, buildOpts func(string) csenc.EncryptOptions,
	logger csencLogger) *csenc.BatchReport {

	report := &csenc.BatchReport{}
	started := time.Now()

	units, discErrs := discoverEncryptUnits(inputs, outDir, recursive)
	report.Errors = append(report.Errors, discErrs...)
	report.Failed += int64(len(discErrs))
	atomic.AddInt64(&report.Discovered, int64(len(units)))

	reporter := makeProgressReporter("encrypt")
	// Announce discoveries first (matches decrypt-path behavior).
	for _, u := range units {
		reporter(csenc.BatchEvent{
			Kind:      csenc.EventDiscovered,
			InputPath: u.in, OutputPath: u.out, InputSize: u.size,
		})
	}

	if jobs <= 0 {
		jobs = runtime.GOMAXPROCS(0)
	}
	sem := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	var errMu sync.Mutex

	for _, u := range units {
		u := u
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()
			ev := runEncryptOne(u, skipExist, keepMTime, buildOpts, logger)
			switch ev.Kind {
			case csenc.EventSucceeded:
				atomic.AddInt64(&report.Succeeded, 1)
				atomic.AddInt64(&report.BytesIn, ev.InputSize)
				atomic.AddInt64(&report.BytesOut, ev.OutputSize)
			case csenc.EventSkipped:
				atomic.AddInt64(&report.Skipped, 1)
			case csenc.EventFailed:
				atomic.AddInt64(&report.Failed, 1)
				errMu.Lock()
				report.Errors = append(report.Errors,
					csenc.BatchError{InputPath: u.in, Err: ev.Err})
				errMu.Unlock()
			}
			reporter(ev)
		}()
	}
	wg.Wait()
	report.Duration = time.Since(started)
	return report
}

type encryptUnit struct {
	in, out string
	size    int64
}

func discoverEncryptUnits(inputs []string, outDir string, recursive bool) ([]encryptUnit, []csenc.BatchError) {
	var (
		units []encryptUnit
		errs  []csenc.BatchError
		seen  = map[string]struct{}{}
	)
	for _, in := range inputs {
		info, err := os.Stat(in)
		if err != nil {
			errs = append(errs, csenc.BatchError{InputPath: in, Err: err})
			continue
		}
		if !info.IsDir() {
			if _, dup := seen[in]; !dup {
				units = append(units, encryptUnit{
					in:   in,
					out:  filepath.Join(outDir, filepath.Base(in)),
					size: info.Size(),
				})
				seen[in] = struct{}{}
			}
			continue
		}
		if !recursive {
			errs = append(errs, csenc.BatchError{
				InputPath: in,
				Err:       fmt.Errorf("is a directory; pass -r to walk it"),
			})
			continue
		}
		root := filepath.Clean(in)
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				errs = append(errs, csenc.BatchError{InputPath: p, Err: walkErr})
				return nil
			}
			if d.IsDir() {
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				errs = append(errs, csenc.BatchError{InputPath: p, Err: err})
				return nil
			}
			if _, dup := seen[p]; dup {
				return nil
			}
			seen[p] = struct{}{}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				errs = append(errs, csenc.BatchError{InputPath: p, Err: err})
				return nil
			}
			units = append(units, encryptUnit{
				in:   p,
				out:  filepath.Join(outDir, filepath.Base(root), rel),
				size: fi.Size(),
			})
			return nil
		})
	}
	return units, errs
}

func runEncryptOne(u encryptUnit, skipExist, keepMTime bool,
	buildOpts func(string) csenc.EncryptOptions, logger csencLogger) csenc.BatchEvent {

	ev := csenc.BatchEvent{InputPath: u.in, OutputPath: u.out, InputSize: u.size}
	start := time.Now()

	if skipExist {
		if st, err := os.Stat(u.out); err == nil && !st.IsDir() {
			ev.Kind = csenc.EventSkipped
			ev.Duration = time.Since(start)
			return ev
		}
	}

	if err := csenc.EncryptFile(u.in, u.out, buildOpts(u.in)); err != nil {
		ev.Kind = csenc.EventFailed
		ev.Err = err
		ev.Duration = time.Since(start)
		return ev
	}
	if st, err := os.Stat(u.out); err == nil {
		ev.OutputSize = st.Size()
	}
	if keepMTime {
		if src, err := os.Stat(u.in); err == nil {
			_ = os.Chtimes(u.out, time.Now(), src.ModTime())
		} else if logger != nil {
			logger("csenc/encrypt-batch: cannot stat source for mtime preservation: %v", err)
		}
	}
	ev.Kind = csenc.EventSucceeded
	ev.Duration = time.Since(start)
	return ev
}

// ------------------------------------------------------------------
// Shared helpers
// ------------------------------------------------------------------

// makeProgressReporter returns an OnEvent function that prints one line
// per completed unit.  label is used in the log lines to distinguish
// decrypt vs encrypt runs.
func makeProgressReporter(label string) func(csenc.BatchEvent) {
	var (
		discovered atomic.Int64
		done       atomic.Int64
	)
	return func(e csenc.BatchEvent) {
		switch e.Kind {
		case csenc.EventDiscovered:
			discovered.Add(1)
		case csenc.EventSucceeded:
			n := done.Add(1)
			fmt.Fprintf(os.Stderr, "[%s %d/%d] OK  %s (%s -> %s, %s)\n",
				label, n, discovered.Load(), e.InputPath,
				humanBytes(e.InputSize), humanBytes(e.OutputSize),
				e.Duration.Round(time.Millisecond))
		case csenc.EventSkipped:
			n := done.Add(1)
			fmt.Fprintf(os.Stderr, "[%s %d/%d] --  %s (skip, output exists)\n",
				label, n, discovered.Load(), e.InputPath)
		case csenc.EventFailed:
			n := done.Add(1)
			fmt.Fprintf(os.Stderr, "[%s %d/%d] ERR %s: %v\n",
				label, n, discovered.Load(), e.InputPath, e.Err)
		}
	}
}

func printReport(rep *csenc.BatchReport) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "==========================================")
	fmt.Fprintln(os.Stderr, rep.Format())
	if len(rep.Errors) > 0 {
		fmt.Fprintln(os.Stderr, "errors:")
		for _, e := range rep.Errors {
			fmt.Fprintf(os.Stderr, "  %s\n", e.Error())
		}
	}
}

// runInspect prints metadata JSON for every csenc input.
func runInspect(inputs []string, recursive bool) {
	visit := func(path string) {
		m, err := csenc.InspectFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			return
		}
		out := map[string]interface{}{
			"path":     path,
			"version":  fmt.Sprintf("%d.%d", m.Major, m.Minor),
			"encrypt":  m.Encrypt,
			"compress": m.Compress,
			"digest":   m.Digest,
			"filename": m.Filename,
			"has_pw":   len(m.EncKey1) > 0,
			"has_key":  len(m.EncKey2) > 0,
			"salt":     string(m.Salt),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	}
	for _, in := range inputs {
		info, err := os.Stat(in)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", in, err)
			continue
		}
		if !info.IsDir() {
			visit(in)
			continue
		}
		if !recursive {
			fmt.Fprintf(os.Stderr, "%s: is a directory; pass -r to recurse\n", in)
			continue
		}
		_ = filepath.Walk(in, func(p string, i os.FileInfo, werr error) error {
			if werr != nil || i.IsDir() {
				return nil
			}
			if ok, _ := csenc.IsCsencFile(p); ok {
				visit(p)
			}
			return nil
		})
	}
}

// loadDecryptSecrets loads password and/or private key for the decrypt path.
func loadDecryptSecrets(pwFile, pwInline, pkPEM, pkPass string) ([]byte, *rsa.PrivateKey) {
	var pw []byte
	if pwFile != "" {
		b, err := os.ReadFile(pwFile)
		if err != nil {
			fail("read password file: %v", err)
		}
		pw = trimEOL(b)
	} else if pwInline != "" {
		pw = []byte(pwInline)
	}
	var key *rsa.PrivateKey
	if pkPEM != "" {
		k, err := csenc.LoadRSAPrivateKey(pkPEM, pkPass)
		if err != nil {
			fail("load private key: %v", err)
		}
		key = k
	}
	return pw, key
}

// loadEncryptSecrets loads password and/or public key for the encrypt path.
func loadEncryptSecrets(pwFile, pwInline, pubPEM string) ([]byte, *rsa.PublicKey) {
	var pw []byte
	if pwFile != "" {
		b, err := os.ReadFile(pwFile)
		if err != nil {
			fail("read password file: %v", err)
		}
		pw = trimEOL(b)
	} else if pwInline != "" {
		pw = []byte(pwInline)
	}
	var pub *rsa.PublicKey
	if pubPEM != "" {
		k, err := csenc.LoadRSAPublicKey(pubPEM)
		if err != nil {
			fail("load public key: %v", err)
		}
		pub = k
	}
	return pw, pub
}

func parseVersion(s string) (int64, int64, error) {
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid -version %q; expected N.M", s)
	}
	maj, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid major in -version %q: %w", s, err)
	}
	min, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid minor in -version %q: %w", s, err)
	}
	if maj != 1 && maj != 3 {
		return 0, 0, fmt.Errorf("-version major must be 1 or 3, got %d", maj)
	}
	return maj, min, nil
}

func trimEOL(b []byte) []byte { return []byte(strings.TrimRight(string(b), "\r\n")) }

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func fail(format string, args ...interface{}) {
	fmt.Fprintln(os.Stderr, "error: "+fmt.Sprintf(format, args...))
	os.Exit(2)
}

type csencLogger = func(format string, args ...interface{})
