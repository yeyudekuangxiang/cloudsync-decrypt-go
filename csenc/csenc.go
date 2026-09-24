// Package csenc decodes the "__CLOUDSYNC_ENC__" stream format produced by
// Synology Cloud Sync when per-file encryption is enabled.
//
// This is an independent Go implementation.  The wire format, algorithm
// choices and metadata field names are protocol-level facts derived from:
//   - The Synology Cloud Sync white paper and knowledge base article about
//     the closed-source decryption utility.
//   - Symbol table, DWARF debug info and rodata inspection of the official
//     tool binary (class layouts, magic bytes, cipher/handler names).
//     No decompiled source code was copied.
//   - Cross-verification against https://github.com/marnix/synology-decrypt
//     (GPL-3.0), used only as an oracle for protocol facts.  No source
//     code from that project is reproduced or translated here.
package csenc

// FileMagic is the leading identifier at offset 0 of every csenc stream.
const FileMagic = "__CLOUDSYNC_ENC__"

// magicChecksumLen is the size of the ASCII-hex MD5 of FileMagic that
// immediately follows the magic bytes.  32 hex chars == 16 raw bytes.
const magicChecksumLen = 32
