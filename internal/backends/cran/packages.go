package cran

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// A CRAN PACKAGES index is a DCF (Debian-control) file: one control stanza per
// package, separated by blank lines. Each stanza carries at least a Package and
// Version field and an MD5sum field (the hex MD5 of the package tarball in the
// same directory). The proxy parses the PACKAGES index siblng to a requested
// tarball to recover the expected MD5, then verifies the fetched tarball against
// it. Schematic of a single stanza:
//
//	Package: jsonlite
//	Version: 1.8.8
//	Depends: methods
//	License: MIT + file LICENSE
//	MD5sum: 8d7b6f2e...e3
//	NeedsCompilation: yes
//
// PACKAGES does not record a Filename field; the tarball is addressed as
// "<Package>_<Version>" plus the area's native extension, so the parser keys its
// digest map by the "<Package>_<Version>" stem and the backend looks it up by
// the stem of the requested filename.

// maxPackagesBytes bounds how much of a PACKAGES index the parser reads. The
// full CRAN source index is a few MiB; the cap is generous while bounding memory
// against a hostile upstream.
const maxPackagesBytes = 64 << 20 // 64 MiB

const md5HexLen = 32

// Index maps each package's "<Package>_<Version>" stem to its lowercase MD5 hex
// digest, recovered from a PACKAGES DCF document.
type Index struct {
	md5 map[string]string
}

// ParsePackages decodes a (already-decompressed) PACKAGES DCF document into the
// digest index the backend verifies tarballs against. Stanzas without a
// Package, a Version, and a well-formed MD5sum are skipped (they cannot anchor a
// verification) rather than failing the whole parse, so a single malformed entry
// does not deny service for the rest of the index.
func ParsePackages(data []byte) (*Index, error) {
	if len(data) > maxPackagesBytes {
		return nil, fmt.Errorf("cran: PACKAGES index exceeds %d bytes", maxPackagesBytes)
	}
	idx := &Index{md5: map[string]string{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var pkg, version, sum string
	flush := func() {
		if pkg != "" && version != "" {
			if hex, ok := normalizeMD5(sum); ok {
				idx.md5[pkg+"_"+version] = hex
			}
		}
		pkg, version, sum = "", "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		// Continuation lines (leading space/tab) belong to multi-line fields we do
		// not use (Depends, Description, ...); skip them.
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, val, ok := splitField(line)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "package":
			pkg = strings.TrimSpace(val)
		case "version":
			version = strings.TrimSpace(val)
		case "md5sum":
			sum = strings.TrimSpace(val)
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cran: reading PACKAGES index: %w", err)
	}
	return idx, nil
}

// md5For returns the recorded MD5 for a package stem "<Package>_<Version>".
func (i *Index) md5For(stem string) (string, bool) {
	if i == nil || stem == "" {
		return "", false
	}
	d, ok := i.md5[stem]
	return d, ok
}

// splitField splits a "Key: value" DCF line into its key and value.
func splitField(line string) (key, val string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// normalizeMD5 lowercases s and returns it only if it is exactly 32 hex
// characters; otherwise it returns ok=false (a malformed digest is treated as no
// digest rather than trusted).
func normalizeMD5(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) != md5HexLen || !isHex(s) {
		return "", false
	}
	return strings.ToLower(s), true
}

// isHex reports whether s is composed solely of hexadecimal digits.
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
