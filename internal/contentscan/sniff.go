package contentscan

import (
	"bytes"
	"strings"
)

// container is a container or compression format the walker recognizes from
// the first bytes of a stream.
type container int

const (
	containerNone container = iota
	// Compression layers: one stream in, one stream out.
	containerGzip
	containerBzip2
	containerXz
	containerZstd
	containerLzma
	// Archives: many members.
	containerZip
	containerTar
	containerAr
	containerDeb // an ar whose first member is "debian-binary"; never sniffed, set by walkAr
	containerCpio
	containerRPM
	containerNAR
)

// compression reports whether the format is a compression layer rather than an
// archive.
func (c container) compression() bool {
	switch c {
	case containerGzip, containerBzip2, containerXz, containerZstd, containerLzma:
		return true
	}
	return false
}

// suffix is the conventional file-name suffix of a compression layer, used to
// name the detected format ("tar.gz", "cpio.zst").
func (c container) suffix() string {
	switch c {
	case containerGzip:
		return "gz"
	case containerBzip2:
		return "bz2"
	case containerXz:
		return "xz"
	case containerZstd:
		return "zst"
	case containerLzma:
		return "lzma"
	}
	return ""
}

// narMagic is how every Nix archive starts: the length-prefixed, zero-padded
// string "nix-archive-1".
var narMagic = []byte("\x0d\x00\x00\x00\x00\x00\x00\x00nix-archive-1\x00\x00\x00")

// sniffContainer recognizes a stream's format from its first bytes (up to one
// tar block). It returns containerNone for anything else — which is not an
// error: most members of an archive are ordinary files.
//
// Recognition is by signature only. A signature is a claim the content makes,
// so every decoder behind it still validates what it reads; what the signature
// decides is which decoder gets to try.
func sniffContainer(head []byte) container {
	at := func(off int, sig string) bool {
		return len(head) >= off+len(sig) && string(head[off:off+len(sig)]) == sig
	}
	switch {
	case at(0, "\x1f\x8b"):
		return containerGzip
	case at(0, "BZh") && len(head) >= 4 && head[3] >= '1' && head[3] <= '9':
		return containerBzip2
	case at(0, "\xfd7zXZ\x00"):
		return containerXz
	case at(0, "\x28\xb5\x2f\xfd"):
		return containerZstd
	case len(head) >= 4 && head[0]&0xf0 == 0x50 && head[1] == 0x2a && head[2] == 0x4d && head[3] == 0x18:
		// A zstd skippable frame (magic 0x184D2A50..5F, little-endian): a zstd
		// stream may legally begin with one.
		return containerZstd
	case at(0, "PK\x03\x04"), at(0, "PK\x05\x06"), at(0, "PK\x07\x08"):
		return containerZip
	case at(0, "!<arch>\n"):
		return containerAr
	case at(0, "\xed\xab\xee\xdb"):
		return containerRPM
	case at(0, "070701"), at(0, "070702"), at(0, "070707"), at(0, "07070X"):
		return containerCpio
	case bytes.HasPrefix(head, narMagic):
		return containerNAR
	case looksLikeTarBlock(head):
		return containerTar
	case looksLikeLzmaAlone(head):
		return containerLzma
	}
	return containerNone
}

// looksLikeTarBlock reports whether head starts with a tar header block: 512
// bytes whose checksum field holds the sum of the block (the one invariant
// every tar dialect — v7, ustar, GNU, pax — shares), or 512 zero bytes, which
// is how an empty archive starts.
func looksLikeTarBlock(head []byte) bool {
	const block = 512
	if len(head) < block {
		return false
	}
	blk := head[:block]
	want, ok := parseTarOctal(blk[148:156])
	if !ok {
		// An all-zero block is the end-of-archive marker: an empty tar.
		for _, c := range blk {
			if c != 0 {
				return false
			}
		}
		return true
	}
	var unsigned, signed int64
	for i, c := range blk {
		if i >= 148 && i < 156 {
			c = ' '
		}
		unsigned += int64(c)
		signed += int64(int8(c))
	}
	// Historic tars summed the block as signed chars; both are accepted, as every
	// tar implementation does.
	return want == unsigned || want == signed
}

// parseTarOctal parses a tar numeric field: octal digits, optionally padded
// with spaces or NULs. It reports false for an empty or non-octal field.
func parseTarOctal(field []byte) (int64, bool) {
	s := strings.Trim(string(field), " \x00")
	if s == "" {
		return 0, false
	}
	var v int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '7' {
			return 0, false
		}
		v = v<<3 | int64(c-'0')
	}
	return v, true
}

// looksLikeLzmaAlone recognizes the legacy ".lzma" container, which has no
// magic: a 13-byte header of one properties byte, a little-endian dictionary
// size and a little-endian uncompressed size. The test is the one xz-utils and
// file(1) use: the common properties byte, a dictionary size that is a power
// of two (or 2^n + 2^(n-1)) of at least 4 KiB, and an uncompressed size that is
// either "unknown" or plausible.
func looksLikeLzmaAlone(head []byte) bool {
	if len(head) < 13 || head[0] != 0x5d {
		return false
	}
	dict := uint32(head[1]) | uint32(head[2])<<8 | uint32(head[3])<<16 | uint32(head[4])<<24
	if dict < 1<<12 {
		return false
	}
	// 2^n or 2^n + 2^(n-1).
	if d := dict; d&(d-1) != 0 {
		top := uint32(1)
		for top<<1 <= d && top<<1 != 0 {
			top <<= 1
		}
		if d != top|top>>1 {
			return false
		}
	}
	var size uint64
	for i := 0; i < 8; i++ {
		size |= uint64(head[5+i]) << (8 * i)
	}
	return size == ^uint64(0) || size < 1<<40
}

// compressionSuffixes are the file-name endings a compression layer adds.
var compressionSuffixes = []string{".gz", ".bz2", ".xz", ".zst", ".zstd", ".lzma", ".z"}

// stripCompressionSuffix removes one compression suffix from a file name, so a
// decompressed single file is reported under the name it has once unpacked
// ("install.sh.gz" -> "install.sh"). A name without one is returned unchanged.
func stripCompressionSuffix(name string) string {
	lower := strings.ToLower(name)
	for _, suf := range compressionSuffixes {
		if strings.HasSuffix(lower, suf) && len(name) > len(suf) {
			return name[:len(name)-len(suf)]
		}
	}
	return name
}
