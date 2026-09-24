package csenc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/pierrec/lz4/v4"
)

// Options controls one Decrypt call.  At least one of Password or
// PrivateKey must be supplied.  When both are, Password takes precedence.
type Options struct {
	// Password is the recovery secret required to unwrap enc_key1.  Must
	// be the raw bytes as supplied by the user (no trailing newline).
	Password []byte

	// PrivateKey is used to unwrap enc_key2 via RSA-OAEP(SHA-1).
	PrivateKey *rsa.PrivateKey

	// Logger receives non-fatal diagnostics such as unknown metadata
	// fields or algorithm mismatches that are not treated as errors.
	Logger func(format string, args ...interface{})
}

func (o Options) logf(format string, args ...interface{}) {
	if o.Logger != nil {
		o.Logger(format, args...)
	}
}

// Decrypt streams a csenc-encoded blob from in, writing the recovered
// plaintext to out.  When present, key1_hash / session_key_hash / file_md5
// are validated; any mismatch is returned as an error.
func Decrypt(in io.Reader, out io.Writer, opt Options) error {
	if err := consumeMagic(in); err != nil {
		return err
	}

	sr := NewStreamReader(in)

	// meta accumulates metadata as the stream progresses.  Metadata
	// dicts may appear before, between or after data dicts (file_md5,
	// for instance, is written after the payload).
	meta := newMetadata()

	plaintextMD5 := md5.New()
	var pipe *decryptPipe

	for {
		obj, more, err := sr.Next()
		if err != nil {
			if pipe != nil {
				pipe.abort(err)
			}
			return err
		}
		if !more {
			break
		}
		if obj.Kind != KindDict {
			return fmt.Errorf("csenc: top-level value is not a dict (kind=%d)", obj.Kind)
		}
		kindField, ok := obj.Lookup("type")
		if !ok || kindField.Kind != KindString {
			return errors.New("csenc: top-level dict missing string 'type'")
		}

		switch kindField.Str {
		case "metadata":
			for _, mp := range obj.Members {
				if mp.Key.Kind != KindString || mp.Key.Str == "type" {
					continue
				}
				if err := meta.absorb(mp, opt); err != nil {
					return err
				}
			}

		case "data":
			if pipe == nil {
				if err := meta.checkModes(); err != nil {
					return err
				}
				sessionKey, err := recoverSessionKey(opt, meta.EncKey1, meta.EncKey2,
					meta.Salt, meta.Key1Hash, meta.SessionKeyHash, meta.Major)
				if err != nil {
					return err
				}
				pipe, err = newDecryptPipe(sessionKey, out, plaintextMD5, meta.Compress == 1)
				if err != nil {
					return err
				}
			}
			ct, ok := obj.Lookup("data")
			if !ok || ct.Kind != KindBytes {
				pipe.abort(errors.New("bad data dict"))
				return errors.New("csenc: 'data' dict missing bytes payload")
			}
			if err := pipe.feed(ct.Bytes); err != nil {
				pipe.abort(err)
				return err
			}

		default:
			return fmt.Errorf("csenc: unknown top-level type %q", kindField.Str)
		}
	}

	if pipe == nil {
		return errors.New("csenc: stream contained no data blocks")
	}
	if err := pipe.finish(); err != nil {
		return err
	}

	if meta.PlaintextMD5 != "" {
		got := hex.EncodeToString(plaintextMD5.Sum(nil))
		if got != meta.PlaintextMD5 {
			return fmt.Errorf("csenc: plaintext md5 mismatch (got %s, want %s)", got, meta.PlaintextMD5)
		}
	}
	if meta.Digest != "" && meta.Digest != "md5" {
		opt.logf("csenc: file_md5 was not verified: digest=%q", meta.Digest)
	}
	return nil
}

// Metadata is the union of every metadata field observed in one csenc
// stream.  Values are populated as the stream is parsed; unknown fields
// are ignored (or logged via Options.Logger).
type Metadata struct {
	Major          int64
	Minor          int64
	Salt           []byte // ASCII bytes as they appear on the wire
	Digest         string // e.g. "md5"
	EncKey1        []byte // decoded base64
	EncKey2        []byte // decoded base64
	Key1Hash       string
	SessionKeyHash string
	PlaintextMD5   string // hex string as recorded by the writer
	Filename       string
	Compress       int64
	Encrypt        int64
}

// newMetadata returns a Metadata pre-populated with the defaults the writer
// assumes when the corresponding fields are omitted from the stream.
func newMetadata() *Metadata {
	return &Metadata{Compress: 1, Encrypt: 1}
}

// absorb merges one metadata field into the running state.
func (m *Metadata) absorb(p Pair, opt Options) error {
	switch p.Key.Str {
	case "version":
		if maj, ok := p.Value.Lookup("major"); ok && maj.Int != nil {
			m.Major = maj.Int.Int64()
		}
		if min, ok := p.Value.Lookup("minor"); ok && min.Int != nil {
			m.Minor = min.Int.Int64()
		}
	case "salt":
		if p.Value.Kind == KindString {
			m.Salt = []byte(p.Value.Str)
		}
	case "digest":
		if p.Value.Kind == KindString {
			m.Digest = p.Value.Str
		}
	case "enc_key1":
		b, err := decodeB64(p.Value)
		if err != nil {
			return fmt.Errorf("csenc: enc_key1: %w", err)
		}
		m.EncKey1 = b
	case "enc_key2":
		b, err := decodeB64(p.Value)
		if err != nil {
			return fmt.Errorf("csenc: enc_key2: %w", err)
		}
		m.EncKey2 = b
	case "key1_hash":
		if p.Value.Kind == KindString {
			m.Key1Hash = p.Value.Str
		}
	case "session_key_hash":
		if p.Value.Kind == KindString {
			m.SessionKeyHash = p.Value.Str
		}
	case "file_md5":
		if p.Value.Kind == KindString {
			m.PlaintextMD5 = p.Value.Str
		}
	case "file_name":
		if p.Value.Kind == KindString {
			m.Filename = p.Value.Str
		}
	case "compress":
		if p.Value.Kind == KindInt && p.Value.Int != nil {
			m.Compress = p.Value.Int.Int64()
		}
	case "encrypt":
		if p.Value.Kind == KindInt && p.Value.Int != nil {
			m.Encrypt = p.Value.Int.Int64()
		}
	case "key2_hash":
		// Present but not verified: the exact preimage is not fixed by
		// any public specification, and the official tool treats it as
		// informational as well.
	default:
		opt.logf("csenc: unrecognized metadata field %q", p.Key.Str)
	}
	return nil
}

// checkModes rejects streams whose payload was not written through the
// pipeline this decoder supports.
func (m *Metadata) checkModes() error {
	if m.Encrypt != 1 {
		return fmt.Errorf("csenc: encrypt=%d streams are not implemented", m.Encrypt)
	}
	if m.Compress != 0 && m.Compress != 1 {
		return fmt.Errorf("csenc: unexpected compress=%d", m.Compress)
	}
	return nil
}

// Inspect reads only the metadata region of an encrypted stream, stopping
// as soon as it reaches the first "data" chunk.  It does not attempt to
// unwrap the session key or touch the payload, so passwords / private keys
// are not required.  Note that some fields (notably file_md5) may only be
// emitted after the payload and will therefore be empty in the returned
// value; call Decrypt for the fully consumed view.
func Inspect(r io.Reader) (*Metadata, error) {
	if err := consumeMagic(r); err != nil {
		return nil, err
	}
	sr := NewStreamReader(r)
	meta := newMetadata()
	for {
		obj, more, err := sr.Next()
		if err != nil {
			return nil, err
		}
		if !more {
			return meta, nil
		}
		if obj.Kind != KindDict {
			return nil, errors.New("csenc: top-level value is not a dict")
		}
		typ, ok := obj.Lookup("type")
		if !ok || typ.Kind != KindString {
			return nil, errors.New("csenc: top-level dict missing string 'type'")
		}
		switch typ.Str {
		case "metadata":
			for _, pair := range obj.Members {
				if pair.Key.Kind != KindString || pair.Key.Str == "type" {
					continue
				}
				if err := meta.absorb(pair, Options{}); err != nil {
					return nil, err
				}
			}
		case "data":
			return meta, nil
		default:
			return nil, fmt.Errorf("csenc: unknown top-level type %q", typ.Str)
		}
	}
}

func consumeMagic(r io.Reader) error {
	head := make([]byte, len(FileMagic))
	if _, err := io.ReadFull(r, head); err != nil {
		return fmt.Errorf("csenc: read magic: %w", err)
	}
	if !bytes.Equal(head, []byte(FileMagic)) {
		return errors.New("csenc: not a csenc stream (bad magic)")
	}
	tail := make([]byte, magicChecksumLen)
	if _, err := io.ReadFull(r, tail); err != nil {
		return fmt.Errorf("csenc: read magic checksum: %w", err)
	}
	sum := md5.Sum([]byte(FileMagic))
	if hex.EncodeToString(sum[:]) != string(tail) {
		return errors.New("csenc: magic checksum mismatch")
	}
	return nil
}

func decodeB64(v Value) ([]byte, error) {
	switch v.Kind {
	case KindString:
		return base64.StdEncoding.DecodeString(v.Str)
	case KindBytes:
		return base64.StdEncoding.DecodeString(string(v.Bytes))
	default:
		return nil, fmt.Errorf("cannot base64-decode kind=%d", v.Kind)
	}
}

func recoverSessionKey(opt Options, encKey1, encKey2, salt []byte,
	key1Hash, sessKeyHash string, majorVer int64) ([]byte, error) {

	var sk []byte
	switch {
	case opt.Password != nil && encKey1 != nil:
		if err := verifyKeyHash(key1Hash, opt.Password, "password"); err != nil {
			return nil, err
		}
		iters := 1
		if len(salt) > 0 {
			iters = 1000
		}
		key, iv := evpKDF(opt.Password, salt, iters, 32, aes.BlockSize)
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		if len(encKey1) == 0 || len(encKey1)%aes.BlockSize != 0 {
			return nil, fmt.Errorf("csenc: enc_key1 length %d not aes-aligned", len(encKey1))
		}
		out := make([]byte, len(encKey1))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, encKey1)
		unpadded, err := unpadPKCS7(out)
		if err != nil {
			return nil, fmt.Errorf("csenc: enc_key1 padding: %w", err)
		}
		sk = unpadded

	case opt.PrivateKey != nil && encKey2 != nil:
		pt, err := rsa.DecryptOAEP(sha1.New(), nil, opt.PrivateKey, encKey2, nil)
		if err != nil {
			return nil, fmt.Errorf("csenc: rsa-oaep(enc_key2): %w", err)
		}
		sk = pt

	default:
		return nil, errors.New("csenc: no recovery secret; supply Password with enc_key1 or PrivateKey with enc_key2")
	}

	if err := verifyKeyHash(sessKeyHash, sk, "session_key"); err != nil {
		return nil, err
	}

	// v3+ streams (salt present) record the session key as ASCII hex.
	// Convert once before it becomes the KDF password for payload cipher.
	if len(salt) > 0 {
		decoded, err := hex.DecodeString(string(sk))
		if err != nil {
			return nil, fmt.Errorf("csenc: session key not ascii-hex as expected for v%d: %w", majorVer, err)
		}
		sk = decoded
	}
	return sk, nil
}

func verifyKeyHash(saltedHash string, secret []byte, label string) error {
	if saltedHash == "" || len(saltedHash) < 10 {
		return nil // nothing to check against
	}
	prefix := []byte(saltedHash[:10])
	if saltedDigest(prefix, secret) != saltedHash {
		return fmt.Errorf("csenc: %s hash mismatch", label)
	}
	return nil
}

func unpadPKCS7(buf []byte) ([]byte, error) {
	if len(buf) == 0 || len(buf)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("length %d is not aes-aligned", len(buf))
	}
	pad := int(buf[len(buf)-1])
	if pad < 1 || pad > aes.BlockSize {
		return nil, fmt.Errorf("pad byte %d out of range", pad)
	}
	for i := len(buf) - pad; i < len(buf); i++ {
		if int(buf[i]) != pad {
			return nil, errors.New("pkcs7 tail bytes inconsistent")
		}
	}
	return buf[:len(buf)-pad], nil
}

// decryptPipe applies the two payload-side stages once the session key is
// known:
//
//	ciphertext block --> AES-CBC decrypter --> (optional LZ4 frame reader)
//	                 --> MultiWriter(out, plaintextMD5)
//
// When the metadata reports compress=1 the LZ4 stage runs in a goroutine
// fed through io.Pipe.  When compress=0 (high-entropy payloads such as
// H.264 video, JPEG, already-compressed archives) the LZ4 stage is
// bypassed entirely and the AES output is written straight to the sink -
// no goroutine, no extra copy.
//
// A one-block lookahead buffer holds the most recently decrypted plaintext
// so that PKCS7 padding can be stripped exactly from the last block when
// the stream is known to be over.
type decryptPipe struct {
	dec     cipher.BlockMode
	pending []byte

	// Exactly one of the following is non-nil.
	pipeW  *io.PipeWriter // compress=1 path
	direct io.Writer      // compress=0 path (MultiWriter over out + md5)

	doneCh chan error // buffered; receives the LZ4 goroutine's result
}

func newDecryptPipe(sessionKey []byte, out io.Writer, plaintextMD5 hash.Hash, useLZ4 bool) (*decryptPipe, error) {
	key, iv := evpKDF(sessionKey, nil, 1, 32, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	p := &decryptPipe{
		dec:    cipher.NewCBCDecrypter(block, iv),
		doneCh: make(chan error, 1),
	}

	if !useLZ4 {
		// Fast path: no compression stage.  We can write straight to
		// the final sink from the AES thread and skip io.Pipe entirely.
		p.direct = io.MultiWriter(out, plaintextMD5)
		p.doneCh <- nil // finish/abort still expect one drain
		return p, nil
	}

	pr, pw := io.Pipe()
	p.pipeW = pw
	go func() {
		lzr := lz4.NewReader(pr)
		_, cpErr := io.Copy(io.MultiWriter(out, plaintextMD5), lzr)
		if cpErr != nil {
			pr.CloseWithError(cpErr)
		} else {
			pr.Close()
		}
		p.doneCh <- cpErr
	}()
	return p, nil
}

// writeSink writes one buffer to whichever sink is active.
func (p *decryptPipe) writeSink(b []byte) error {
	if p.pipeW != nil {
		_, err := p.pipeW.Write(b)
		return err
	}
	_, err := p.direct.Write(b)
	return err
}

func (p *decryptPipe) feed(cipherBlock []byte) error {
	if len(cipherBlock) == 0 || len(cipherBlock)%aes.BlockSize != 0 {
		return fmt.Errorf("csenc: data block length %d not aes-aligned", len(cipherBlock))
	}
	plain := make([]byte, len(cipherBlock))
	p.dec.CryptBlocks(plain, cipherBlock)

	// Flush the previously buffered block (which we now know is not the
	// stream's tail) verbatim, then hold this one.
	if p.pending != nil {
		if err := p.writeSink(p.pending); err != nil {
			return err
		}
	}
	p.pending = plain
	return nil
}

func (p *decryptPipe) finish() error {
	if p.pending != nil {
		tail, err := unpadPKCS7(p.pending)
		if err != nil {
			p.abort(err)
			return fmt.Errorf("csenc: final block padding: %w", err)
		}
		if err := p.writeSink(tail); err != nil {
			if p.pipeW != nil {
				<-p.doneCh
			}
			return err
		}
	}
	if p.pipeW != nil {
		if err := p.pipeW.Close(); err != nil {
			<-p.doneCh
			return err
		}
		return <-p.doneCh
	}
	// Fast path: doneCh was pre-populated with nil.
	return <-p.doneCh
}

func (p *decryptPipe) abort(err error) {
	if p.pipeW != nil {
		p.pipeW.CloseWithError(err)
		<-p.doneCh
	}
}
