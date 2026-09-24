package csenc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// Kind enumerates the wire-level types encountered in a csenc object stream.
type Kind uint8

const (
	KindNil Kind = iota
	KindDict
	KindBytes
	KindString
	KindInt
)

// Tag bytes as they appear on the wire.  These are protocol constants.
const (
	tagEnd    byte = 0x40 // terminates a dict; also acts as top-level EOS
	tagDict   byte = 0x42
	tagBytes  byte = 0x11
	tagString byte = 0x10
	tagInt    byte = 0x01
)

// Value is one deserialized node from a csenc object stream.
// Only fields matching Kind are meaningful.
type Value struct {
	Kind    Kind
	Bytes   []byte
	Str     string
	Int     *big.Int
	Members []Pair // ordered; used when Kind == KindDict
}

// Pair is one entry of a KindDict Value.
type Pair struct {
	Key, Value Value
}

// Lookup returns the first value whose key is a string equal to name.
func (v Value) Lookup(name string) (Value, bool) {
	if v.Kind != KindDict {
		return Value{}, false
	}
	for i := range v.Members {
		k := v.Members[i].Key
		if k.Kind == KindString && k.Str == name {
			return v.Members[i].Value, true
		}
	}
	return Value{}, false
}

// StreamReader yields one top-level Value at a time from a byte stream.
type StreamReader struct {
	src io.Reader
}

// NewStreamReader wraps src for iterative decoding.
func NewStreamReader(src io.Reader) *StreamReader {
	return &StreamReader{src: src}
}

// Next returns the next top-level Value.  It returns ok=false, err=nil
// when the underlying stream has been fully and cleanly consumed.
func (sr *StreamReader) Next() (Value, bool, error) {
	v, term, err := readOne(sr.src)
	if err == io.EOF {
		return Value{}, false, nil
	}
	if err != nil {
		return Value{}, false, err
	}
	if term {
		// A bare terminator at the top level is treated as end-of-stream.
		return Value{}, false, nil
	}
	return v, true, nil
}

func readOne(r io.Reader) (Value, bool, error) {
	var head [1]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Value{}, false, err
	}
	switch head[0] {
	case tagEnd:
		return Value{Kind: KindNil}, true, nil

	case tagDict:
		var members []Pair
		for {
			key, term, err := readOne(r)
			if err != nil {
				return Value{}, false, err
			}
			if term {
				return Value{Kind: KindDict, Members: members}, false, nil
			}
			val, termV, err := readOne(r)
			if err != nil {
				return Value{}, false, err
			}
			if termV {
				return Value{}, false, errors.New("csenc/wire: dict key with no value")
			}
			members = append(members, Pair{Key: key, Value: val})
		}

	case tagBytes:
		b, err := readShortBlob(r)
		if err != nil {
			return Value{}, false, err
		}
		return Value{Kind: KindBytes, Bytes: b}, false, nil

	case tagString:
		b, err := readShortBlob(r)
		if err != nil {
			return Value{}, false, err
		}
		return Value{Kind: KindString, Str: string(b)}, false, nil

	case tagInt:
		var szBuf [1]byte
		if _, err := io.ReadFull(r, szBuf[:]); err != nil {
			return Value{}, false, err
		}
		digits := make([]byte, int(szBuf[0]))
		if _, err := io.ReadFull(r, digits); err != nil {
			return Value{}, false, err
		}
		return Value{Kind: KindInt, Int: new(big.Int).SetBytes(digits)}, false, nil

	default:
		return Value{}, false, fmt.Errorf("csenc/wire: unknown tag 0x%02x", head[0])
	}
}

func readShortBlob(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	buf := make([]byte, int(n))
	if n == 0 {
		return buf, nil
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
