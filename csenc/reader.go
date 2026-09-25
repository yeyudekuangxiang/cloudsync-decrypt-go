package csenc

import (
	"errors"
	"io"
	"sync"
)

// Reader is a streaming decryptor that turns a csenc-encoded byte stream
// into an io.ReadCloser yielding plaintext bytes.  It is the natural
// building block for callers that want to feed the plaintext directly into
// another consumer (an image decoder, a video player, a hash function, a
// multipart uploader, etc.) without going through a temporary file.
//
// A Reader always drives one background goroutine that runs the underlying
// Decrypt pipeline; consequently callers MUST Close the Reader when they
// are done, both to release that goroutine and to surface any error that
// only becomes visible after the payload is fully consumed (for example a
// plaintext MD5 mismatch reported by the writer at the end of the stream).
//
// Close is idempotent.  Reading further after Close returns io.EOF or the
// error that terminated the underlying decryption.
type Reader struct {
	pr     *io.PipeReader
	doneCh chan error

	// extraClose is closed alongside the Reader.  Set by NewReaderWithCloser
	// / OpenFile so that callers can hand off an os.File / http.Response.Body
	// and rely on Reader.Close cleaning everything up.
	extraClose io.Closer

	closeOnce sync.Once
	closeErr  error

	metaMu sync.RWMutex
	meta   *Metadata
}

// NewReader wraps an encrypted stream and returns a Reader that yields
// the recovered plaintext.  NewReader is infallible: any real error - bad
// magic, wrong password, malformed metadata - surfaces from the first
// Read that reaches the failing point, or from Close.
//
// The passed opts is copied; the caller's OnMetadata hook, if any, is
// still invoked after the Reader captures its own snapshot.
func NewReader(in io.Reader, opts Options) *Reader {
	pr, pw := io.Pipe()
	r := &Reader{
		pr:     pr,
		doneCh: make(chan error, 1),
	}

	userHook := opts.OnMetadata
	opts.OnMetadata = func(m *Metadata) {
		r.metaMu.Lock()
		r.meta = m
		r.metaMu.Unlock()
		if userHook != nil {
			userHook(m)
		}
	}

	go func() {
		err := Decrypt(in, pw, opts)
		// Propagate the terminal state to the pipe reader: nil -> EOF,
		// non-nil -> that exact error surfaces from Read.
		_ = pw.CloseWithError(err)
		r.doneCh <- err
	}()
	return r
}

// Read implements io.Reader.
func (r *Reader) Read(p []byte) (int, error) {
	return r.pr.Read(p)
}

// Metadata returns a copy of the header metadata that has been parsed so
// far, or nil if no metadata has been observed yet (either because Read
// has not been called or because the stream is malformed).
//
// The returned value is a stable snapshot; the caller is free to retain
// or mutate it without affecting the Reader.
func (r *Reader) Metadata() *Metadata {
	r.metaMu.RLock()
	defer r.metaMu.RUnlock()
	if r.meta == nil {
		return nil
	}
	cp := *r.meta
	return &cp
}

// Close terminates the underlying decryption pipeline.  If the caller has
// already read to io.EOF the returned error is nil (or the error already
// surfaced from Read).  If Close is called before the stream is fully
// consumed, an in-flight decryption is aborted and any resulting error
// (typically "io: read/write on closed pipe") is suppressed - a caller
// that Closes early is deliberately walking away from the remainder.
func (r *Reader) Close() error {
	r.closeOnce.Do(func() {
		// Wake up any goroutine waiting on Write with a benign signal.
		_ = r.pr.Close()
		err := <-r.doneCh
		if r.extraClose != nil {
			if cerr := r.extraClose.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}
		if err == nil {
			return
		}
		if errors.Is(err, io.ErrClosedPipe) {
			// User bailed out; not a real error.
			return
		}
		r.closeErr = err
	})
	return r.closeErr
}
