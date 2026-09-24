package csenc

import "crypto/md5"

// evpKDF mirrors OpenSSL's EVP_BytesToKey used with EVP_md5().  It emits
// keyLen bytes of key material followed by ivLen bytes of IV material.
//
// Each round produces one MD5 digest of (previous || password || salt) and
// then re-hashes that digest count-1 additional times before appending it
// to the output buffer.  count == 1 is used when no salt is present; the
// csenc metadata layer uses count == 1000 whenever a salt is included.
// salt may be nil.
func evpKDF(password, salt []byte, count, keyLen, ivLen int) (key, iv []byte) {
	if count < 1 {
		count = 1
	}
	need := keyLen + ivLen
	buf := make([]byte, 0, need+md5.Size)
	var prev []byte

	for len(buf) < need {
		h := md5.New()
		h.Write(prev)
		h.Write(password)
		h.Write(salt)
		digest := h.Sum(nil)

		for i := 1; i < count; i++ {
			s := md5.Sum(digest)
			digest = s[:]
		}
		prev = digest
		buf = append(buf, digest...)
	}

	key = append([]byte(nil), buf[:keyLen]...)
	iv = append([]byte(nil), buf[keyLen:keyLen+ivLen]...)
	return
}
