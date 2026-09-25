package csenc

import (
	"crypto/aes"
	"crypto/cipher"
	stdmd5 "crypto/md5"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"

	"github.com/pierrec/lz4/v4"
)

// EncryptOptions controls one encryption run.  At least one of Password
// or PublicKey must be supplied; when both are, the produced file has
// both recovery paths available.
type EncryptOptions struct {
	// Password, when non-empty, causes an enc_key1 entry to be written so
	// the recipient can recover the session key from just the password.
	Password []byte

	// PublicKey, when non-nil, causes an enc_key2 entry to be written so
	// the recipient can recover the session key from the matching
	// private key (RSA-OAEP with SHA-1).
	PublicKey *rsa.PublicKey

	// Major/Minor selects the wire version.  Zero values default to
	// {3, 1} which is what modern Cloud Sync writes.  Setting Major=1
	// (any Minor) produces a v1 stream (no salt, raw session key on
	// wire).
	Major, Minor int64

	// Filename, if non-empty, is stored in the metadata as file_name.
	Filename string

	// Compress selects whether to LZ4-frame the plaintext before AES.
	// Nil pointer -> true (matches what Cloud Sync always emits).
	Compress *bool

	// Rand is the entropy source used for the session key, salt and
	// hash-prefix generation.  Defaults to crypto/rand.Reader.
	Rand io.Reader

	// Logger receives non-fatal diagnostics.  May be nil.
	Logger func(format string, args ...interface{})
}

func (o EncryptOptions) major() int64 {
	if o.Major == 0 {
		return 3
	}
	return o.Major
}
func (o EncryptOptions) minor() int64 {
	if o.Major == 0 && o.Minor == 0 {
		return 1
	}
	return o.Minor
}
func (o EncryptOptions) rand() io.Reader {
	if o.Rand != nil {
		return o.Rand
	}
	return crand.Reader
}
func (o EncryptOptions) compressOn() bool {
	if o.Compress == nil {
		return true
	}
	return *o.Compress
}

// Encrypt reads plaintext from in and writes a csenc-encoded stream to
// out.  It is a thin wrapper over Writer and does not close either side.
func Encrypt(in io.Reader, out io.Writer, opts EncryptOptions) error {
	w, err := NewWriter(out, opts)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, in); err != nil {
		_ = w.abort()
		return err
	}
	return w.Close()
}

// EncryptFile encrypts inPath and writes the ciphertext to outPath using
// the same atomic-rename dance as DecryptFile.
func EncryptFile(inPath, outPath string, opts EncryptOptions) error {
	src, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dir := filepath.Dir(outPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".csenc-enc-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if opts.Filename == "" {
		opts.Filename = filepath.Base(inPath)
	}
	if err := Encrypt(src, tmp, opts); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, outPath)
}

// LoadRSAPublicKey parses a PEM-encoded RSA public key.  It accepts both
// "PUBLIC KEY" (PKIX) and "RSA PUBLIC KEY" (PKCS#1) block types.
func LoadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseRSAPublicKeyPEM(raw)
}

// -- Streaming Writer -------------------------------------------------

// dataChunkSize bounds the size of each on-wire "data" dict.  The wire
// format limits blob length to a u16, so this must stay below 65535.
// We keep it comfortably lower and 16-aligned so AES output slots into
// exactly one chunk boundary.
const dataChunkSize = 32 * 1024

// Writer wraps an io.Writer and turns plaintext bytes written to it into
// a csenc-encoded stream.  It is the encoding counterpart of Reader.
//
// After the last Write, callers MUST Close the Writer so the tail
// metadata (file_md5) is emitted and any pending partial block is padded
// and flushed.  Close is idempotent.
type Writer struct {
	out  io.Writer
	opts EncryptOptions

	md5  hash.Hash    // plaintext md5 accumulator
	lz4W *lz4.Writer  // nil when compress=false
	aes  *aesFeeder   // AES-CBC-encrypter with staging buffer
	sink *pendingSink // ciphertext -> data dicts

	started bool
	closed  bool
	failed  error
}

// NewWriter returns a Writer that will emit a csenc stream on out when
// bytes are written to it.  The header (magic + leading metadata dict) is
// deferred to the first Write / Close so that any error in preparing the
// header - including missing secret material - surfaces from there.
func NewWriter(out io.Writer, opts EncryptOptions) (*Writer, error) {
	if len(opts.Password) == 0 && opts.PublicKey == nil {
		return nil, errors.New("csenc: EncryptOptions needs Password and/or PublicKey")
	}
	if maj := opts.major(); maj != 1 && maj != 3 {
		return nil, fmt.Errorf("csenc: unsupported major version %d (want 1 or 3)", maj)
	}
	return &Writer{
		out:  out,
		opts: opts,
		md5:  stdmd5.New(),
	}, nil
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("csenc: write on closed Writer")
	}
	if w.failed != nil {
		return 0, w.failed
	}
	if !w.started {
		if err := w.start(); err != nil {
			w.failed = err
			return 0, err
		}
	}
	w.md5.Write(p)
	var dst io.Writer = w.aes
	if w.lz4W != nil {
		dst = w.lz4W
	}
	return dst.Write(p)
}

func (w *Writer) Close() error {
	if w.closed {
		return w.failed
	}
	w.closed = true
	if w.failed != nil {
		return w.failed
	}
	if !w.started {
		// Empty content still needs a well-formed stream.
		if err := w.start(); err != nil {
			w.failed = err
			return err
		}
	}
	if w.lz4W != nil {
		if err := w.lz4W.Close(); err != nil {
			w.failed = err
			return err
		}
	}
	if err := w.aes.finish(); err != nil {
		w.failed = err
		return err
	}
	if err := w.sink.flush(); err != nil {
		w.failed = err
		return err
	}
	// Trailing metadata: file_md5.
	if err := writeFinalMetadata(w.out, hex.EncodeToString(w.md5.Sum(nil))); err != nil {
		w.failed = err
		return err
	}
	return nil
}

// abort discards the current pipeline without emitting the trailing
// metadata.  Used when the copy that feeds the writer errors out.
func (w *Writer) abort() error {
	if !w.closed {
		w.closed = true
	}
	return nil
}

// start emits the magic + leading metadata dict and wires the pipeline.
func (w *Writer) start() error {
	w.started = true
	rnd := w.opts.rand()
	major := w.opts.major()

	// 1) Session key material.
	rawSess := make([]byte, 32)
	if _, err := io.ReadFull(rnd, rawSess); err != nil {
		return fmt.Errorf("csenc: read random session key: %w", err)
	}
	var sessionKeyOnWire []byte
	var dataKDFInput []byte
	if major >= 3 {
		sessionKeyOnWire = []byte(hex.EncodeToString(rawSess)) // 64 ASCII
		dataKDFInput = rawSess                                 // 32 raw
	} else {
		sessionKeyOnWire = rawSess
		dataKDFInput = rawSess
	}

	// 2) Salt (v3+ only).
	var salt []byte
	if major >= 3 {
		s, err := randomAlnum(rnd, 8)
		if err != nil {
			return err
		}
		salt = s
	}

	// 3) Wrap the session key with password / public key as applicable.
	var encKey1, encKey2 []byte
	if len(w.opts.Password) > 0 {
		iters := 1
		if len(salt) > 0 {
			iters = 1000
		}
		key, iv := evpKDF(w.opts.Password, salt, iters, 32, aes.BlockSize)
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		padded := pkcs7Pad(sessionKeyOnWire, aes.BlockSize)
		encKey1 = make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(encKey1, padded)
	}
	if w.opts.PublicKey != nil {
		ct, err := rsa.EncryptOAEP(sha1.New(), rnd, w.opts.PublicKey, sessionKeyOnWire, nil)
		if err != nil {
			return fmt.Errorf("csenc: rsa-oaep(session_key): %w", err)
		}
		encKey2 = ct
	}

	// 4) Salted-md5 envelopes over the password and the session key.
	//    Each carries its own 10-char ASCII prefix used as md5 seed.
	var key1Hash string
	if len(w.opts.Password) > 0 {
		prefix, err := randomHex(rnd, 10)
		if err != nil {
			return err
		}
		key1Hash = saltedDigest(prefix, w.opts.Password)
	}
	prefix, err := randomHex(rnd, 10)
	if err != nil {
		return err
	}
	sessKeyHash := saltedDigest(prefix, sessionKeyOnWire)

	// 5) Emit magic + leading metadata dict.
	if err := writeMagic(w.out); err != nil {
		return err
	}
	if err := writeLeadingMetadata(w.out, leadingMetadata{
		major:       major,
		minor:       w.opts.minor(),
		salt:        salt,
		encKey1:     encKey1,
		encKey2:     encKey2,
		key1Hash:    key1Hash,
		sessKeyHash: sessKeyHash,
		compress:    boolAsInt(w.opts.compressOn()),
		encrypt:     1,
		filename:    w.opts.Filename,
	}); err != nil {
		return err
	}

	// 6) Derive data cipher key/iv and wire the streaming pipeline.
	dataKey, dataIV := evpKDF(dataKDFInput, nil, 1, 32, aes.BlockSize)
	dataBlock, err := aes.NewCipher(dataKey)
	if err != nil {
		return err
	}
	w.sink = &pendingSink{out: w.out, chunkSize: dataChunkSize}
	w.aes = &aesFeeder{enc: cipher.NewCBCEncrypter(dataBlock, dataIV), sink: w.sink}
	if w.opts.compressOn() {
		w.lz4W = lz4.NewWriter(w.aes)
	}
	return nil
}

// -- Streaming pipeline stages ---------------------------------------

// aesFeeder implements io.Writer.  It accumulates incoming bytes, encrypts
// them in AES-CBC mode 16 bytes at a time (chained across writes) and
// forwards ciphertext to sink.  Callers finish the stream by calling
// finish(), which appends PKCS7 padding to the residual and flushes the
// last block(s).
type aesFeeder struct {
	enc  cipher.BlockMode
	buf  []byte
	sink io.Writer
}

func (a *aesFeeder) Write(p []byte) (int, error) {
	n := len(p)
	a.buf = append(a.buf, p...)
	full := len(a.buf) / aes.BlockSize * aes.BlockSize
	if full == 0 {
		return n, nil
	}
	cipherBuf := make([]byte, full)
	a.enc.CryptBlocks(cipherBuf, a.buf[:full])
	if _, err := a.sink.Write(cipherBuf); err != nil {
		return 0, err
	}
	// Retain leftover bytes.
	if leftover := len(a.buf) - full; leftover > 0 {
		copy(a.buf, a.buf[full:])
		a.buf = a.buf[:leftover]
	} else {
		a.buf = a.buf[:0]
	}
	return n, nil
}

// finish appends PKCS7 padding (always 1-16 bytes; never zero) and
// encrypts the final block(s).
func (a *aesFeeder) finish() error {
	padLen := aes.BlockSize - (len(a.buf) % aes.BlockSize)
	for i := 0; i < padLen; i++ {
		a.buf = append(a.buf, byte(padLen))
	}
	cipherBuf := make([]byte, len(a.buf))
	a.enc.CryptBlocks(cipherBuf, a.buf)
	if _, err := a.sink.Write(cipherBuf); err != nil {
		return err
	}
	a.buf = a.buf[:0]
	return nil
}

// pendingSink accepts ciphertext and emits it as consecutive "data"
// dicts, each no larger than chunkSize.
type pendingSink struct {
	out       io.Writer
	buf       []byte
	chunkSize int
}

func (s *pendingSink) Write(p []byte) (int, error) {
	s.buf = append(s.buf, p...)
	for len(s.buf) >= s.chunkSize {
		if err := writeDataDict(s.out, s.buf[:s.chunkSize]); err != nil {
			return 0, err
		}
		copy(s.buf, s.buf[s.chunkSize:])
		s.buf = s.buf[:len(s.buf)-s.chunkSize]
	}
	return len(p), nil
}

func (s *pendingSink) flush() error {
	if len(s.buf) == 0 {
		return nil
	}
	if err := writeDataDict(s.out, s.buf); err != nil {
		return err
	}
	s.buf = s.buf[:0]
	return nil
}

// -- Wire encoders ---------------------------------------------------

type leadingMetadata struct {
	major, minor int64
	salt         []byte
	encKey1      []byte
	encKey2      []byte
	key1Hash     string
	sessKeyHash  string
	compress     int64
	encrypt      int64
	filename     string
}

func writeMagic(w io.Writer) error {
	if _, err := w.Write([]byte(FileMagic)); err != nil {
		return err
	}
	sum := stdmd5.Sum([]byte(FileMagic))
	_, err := w.Write([]byte(hex.EncodeToString(sum[:])))
	return err
}

func writeLeadingMetadata(w io.Writer, m leadingMetadata) error {
	e := &wireEnc{w: w}
	e.dictStart()
	e.strPair("type", "metadata")

	e.key("version")
	e.dictStart()
	e.intPair("major", m.major)
	e.intPair("minor", m.minor)
	e.dictEnd()

	if len(m.salt) > 0 {
		e.strPair("salt", string(m.salt))
	}
	e.strPair("digest", "md5")
	if len(m.encKey1) > 0 {
		e.strPair("enc_key1", base64.StdEncoding.EncodeToString(m.encKey1))
	}
	if m.key1Hash != "" {
		e.strPair("key1_hash", m.key1Hash)
	}
	if len(m.encKey2) > 0 {
		e.strPair("enc_key2", base64.StdEncoding.EncodeToString(m.encKey2))
	}
	e.strPair("session_key_hash", m.sessKeyHash)
	e.intPair("compress", m.compress)
	e.intPair("encrypt", m.encrypt)
	if m.filename != "" {
		e.strPair("file_name", m.filename)
	}
	e.dictEnd()
	return e.err
}

func writeDataDict(w io.Writer, data []byte) error {
	e := &wireEnc{w: w}
	e.dictStart()
	e.strPair("type", "data")
	e.key("data")
	e.bytesValue(data)
	e.dictEnd()
	return e.err
}

func writeFinalMetadata(w io.Writer, md5hex string) error {
	e := &wireEnc{w: w}
	e.dictStart()
	e.strPair("type", "metadata")
	e.strPair("file_md5", md5hex)
	e.dictEnd()
	return e.err
}

// wireEnc is a tiny sticky-error encoder for the on-disk representation.
type wireEnc struct {
	w   io.Writer
	err error
}

func (e *wireEnc) writeAll(b []byte) {
	if e.err != nil {
		return
	}
	_, e.err = e.w.Write(b)
}

func (e *wireEnc) dictStart() { e.writeAll([]byte{tagDict}) }
func (e *wireEnc) dictEnd()   { e.writeAll([]byte{tagEnd}) }

func (e *wireEnc) key(s string) {
	e.writeAll([]byte{tagString})
	e.writeShortBlob([]byte(s))
}
func (e *wireEnc) strPair(k, v string) {
	e.key(k)
	e.writeAll([]byte{tagString})
	e.writeShortBlob([]byte(v))
}
func (e *wireEnc) intPair(k string, v int64) {
	e.key(k)
	e.writeAll([]byte{tagInt})
	e.writeIntBody(v)
}
func (e *wireEnc) bytesValue(b []byte) {
	e.writeAll([]byte{tagBytes})
	e.writeShortBlob(b)
}

func (e *wireEnc) writeShortBlob(b []byte) {
	if len(b) > 0xFFFF {
		if e.err == nil {
			e.err = fmt.Errorf("csenc: value length %d exceeds u16 wire limit", len(b))
		}
		return
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(b)))
	e.writeAll(hdr[:])
	e.writeAll(b)
}

// writeIntBody writes a length-prefixed big-endian integer using the
// minimum number of bytes.  Positive-only; matches what the samples use.
func (e *wireEnc) writeIntBody(n int64) {
	if n < 0 {
		if e.err == nil {
			e.err = fmt.Errorf("csenc: negative integer %d not representable", n)
		}
		return
	}
	if n == 0 {
		e.writeAll([]byte{1, 0})
		return
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	start := 0
	for start < 7 && b[start] == 0 {
		start++
	}
	length := 8 - start
	e.writeAll([]byte{byte(length)})
	e.writeAll(b[start:])
}

// -- Utilities -------------------------------------------------------

func pkcs7Pad(b []byte, blockSize int) []byte {
	padLen := blockSize - (len(b) % blockSize)
	out := make([]byte, 0, len(b)+padLen)
	out = append(out, b...)
	for i := 0; i < padLen; i++ {
		out = append(out, byte(padLen))
	}
	return out
}

func boolAsInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// randomAlnum returns n bytes from the [A-Za-z0-9] alphabet.  Modulo bias
// is negligible for salt use.
func randomAlnum(r io.Reader, n int) ([]byte, error) {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, n)
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	for i, b := range buf {
		out[i] = a[int(b)%len(a)]
	}
	return out, nil
}

// randomHex returns n hex characters ([0-9a-f]).
func randomHex(r io.Reader, n int) ([]byte, error) {
	rawLen := (n + 1) / 2
	raw := make([]byte, rawLen)
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, err
	}
	s := hex.EncodeToString(raw)
	return []byte(s[:n]), nil
}

// parseRSAPublicKeyPEM accepts either "PUBLIC KEY" (PKIX / SubjectPublicKeyInfo)
// or "RSA PUBLIC KEY" (PKCS#1) blocks.
func parseRSAPublicKeyPEM(raw []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("csenc: no PEM block found")
	}
	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rk, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("csenc: PKIX public key is not RSA")
		}
		return rk, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("csenc: unsupported PEM block type %q", block.Type)
	}
}
