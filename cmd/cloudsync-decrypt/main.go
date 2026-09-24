// Command cloudsync-decrypt is a CLI wrapper around the csenc package.
// It accepts one or more encrypted files and writes the recovered
// plaintext either to a single file (-o) or to a directory (-outdir).
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"cloudsync-decrypt-go/csenc"
)

func main() {
	var (
		pwFile       string
		pwInline     string
		pkPEM        string
		pkPass       string
		outDir       string
		outFile      string
		verbose      bool
	)
	flag.StringVar(&pwFile, "password-file", "", "path to a file whose contents (trailing newline stripped) form the password")
	flag.StringVar(&pwInline, "password", "", "password on the command line (leaks to /proc; prefer -password-file)")
	flag.StringVar(&pkPEM, "private-key", "", "path to a PEM-encoded RSA private key")
	flag.StringVar(&pkPass, "private-key-password", "", "passphrase protecting the private key, if any")
	flag.StringVar(&outDir, "outdir", "", "write decrypted files under this directory, preserving basenames")
	flag.StringVar(&outFile, "o", "", "write decrypted output to this exact path (single input only)")
	flag.BoolVar(&verbose, "v", false, "log unrecognized metadata fields and other diagnostics")
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "usage: cloudsync-decrypt [flags] input.enc [input2.enc ...]")
		fmt.Fprintln(flag.CommandLine.Output(), "Flags:")
		flag.PrintDefaults()
	}
	flag.Parse()

	inputs := flag.Args()
	if len(inputs) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if outFile == "" && outDir == "" {
		fail("specify either -o (single) or -outdir (batch)")
	}
	if outFile != "" && len(inputs) != 1 {
		fail("-o accepts a single input; use -outdir for multiple inputs")
	}

	opts := csenc.Options{}
	if verbose {
		opts.Logger = func(f string, a ...interface{}) { log.Printf(f, a...) }
	}
	if pwFile != "" {
		b, err := os.ReadFile(pwFile)
		if err != nil {
			fail("read password file: %v", err)
		}
		opts.Password = trimEndOfLine(b)
	} else if pwInline != "" {
		opts.Password = []byte(pwInline)
	}
	if pkPEM != "" {
		key, err := loadRSAPrivateKey(pkPEM, pkPass)
		if err != nil {
			fail("load private key: %v", err)
		}
		opts.PrivateKey = key
	}
	if opts.Password == nil && opts.PrivateKey == nil {
		fail("need at least one of -password-file / -password / -private-key")
	}

	for _, in := range inputs {
		var dest string
		if outFile != "" {
			dest = outFile
		} else {
			dest = filepath.Join(outDir, filepath.Base(in))
		}
		if err := runOne(in, dest, opts); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", in, err)
			os.Exit(1)
		}
		fmt.Printf("%s -> %s\n", in, dest)
	}
}

func runOne(inPath, outPath string, opts csenc.Options) error {
	src, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer src.Close()

	if dir := filepath.Dir(outPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := outPath + ".partial"
	dst, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := csenc.Decrypt(src, dst, opts); err != nil {
		dst.Close()
		os.Remove(tmp)
		return err
	}
	if err := dst.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, outPath)
}

func trimEndOfLine(b []byte) []byte {
	return []byte(strings.TrimRight(string(b), "\r\n"))
}

func loadRSAPrivateKey(path, pass string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	der := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		if pass == "" {
			return nil, errors.New("private key is encrypted; supply -private-key-password")
		}
		der, err = x509.DecryptPEMBlock(block, []byte(pass))
		if err != nil {
			return nil, err
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
			return nil, errors.New("PKCS#8 key is not RSA")
		}
		return rk, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

func fail(format string, args ...interface{}) {
	fmt.Fprintln(os.Stderr, "error: "+fmt.Sprintf(format, args...))
	os.Exit(2)
}
