package csenc

import (
	"crypto/md5"
	"encoding/hex"
)

// saltedDigest returns saltASCII || hex(md5(saltASCII || data)).
//
// The metadata layer stores password / session-key integrity envelopes in
// this shape; the leading 10 bytes of the recorded value carry the salt
// prefix used as MD5 seed.
func saltedDigest(saltASCII, data []byte) string {
	h := md5.New()
	h.Write(saltASCII)
	h.Write(data)
	return string(saltASCII) + hex.EncodeToString(h.Sum(nil))
}
