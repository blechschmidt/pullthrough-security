package apt

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

// A binary Packages index is a Deb822 file: one control paragraph per binary
// package, separated by blank lines. Each paragraph carries a Filename field
// (the package's repository-root-relative pool path) and a SHA256 field (its
// digest). The proxy parses every Packages index it serves to record those
// (pool-path -> SHA-256) pairs, then verifies the corresponding .deb against the
// recorded digest when it is fetched. The index itself is SHA-256-verified
// against the (optionally GPG-signed) Release before it is parsed, so the digests
// it yields are trusted.
//
// Schematic of a single stanza:
//
//	Package: foo
//	Version: 1.2.3-1
//	Architecture: amd64
//	Filename: pool/main/f/foo/foo_1.2.3-1_amd64.deb
//	Size: 12345
//	SHA256: <hex>

// maxPackagesBytes bounds how much of a (decompressed) Packages index the parser
// reads. Large suites publish indices of a few hundred MiB decompressed; the cap
// is generous while still bounding memory against a hostile upstream.
const maxPackagesBytes = 512 << 20 // 512 MiB

// PackageEntry is the parsed coordinate of one binary package in an index: just
// the pool path and digest the backend needs to verify the corresponding .deb.
type PackageEntry struct {
	Filename string
	SHA256   string
}

// ParsePackages decodes a (already-decompressed) binary Packages index into the
// list of (Filename, SHA256) pairs the backend records. Stanzas without both a
// Filename and a well-formed SHA256 are skipped (they cannot anchor a
// verification) rather than failing the whole parse, so a single malformed entry
// does not deny service for the rest of the index.
func ParsePackages(data []byte) ([]PackageEntry, error) {
	if len(data) > maxPackagesBytes {
		return nil, fmt.Errorf("apt: Packages index exceeds %d bytes", maxPackagesBytes)
	}
	var out []PackageEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var filename, sha string
	flush := func() {
		if filename != "" {
			if hex, ok := normalizeSHA256(sha); ok {
				out = append(out, PackageEntry{Filename: strings.TrimLeft(filename, "/"), SHA256: hex})
			}
		}
		filename, sha = "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		// Stanza fields used here are single-line; continuation lines (leading
		// space) belong to fields we ignore, so skip them.
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, val, ok := splitField(line)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "filename":
			filename = strings.TrimSpace(val)
		case "sha256":
			sha = strings.TrimSpace(val)
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("apt: reading Packages index: %w", err)
	}
	return out, nil
}

// decompressPackages returns the decompressed bytes of a Packages index given
// the index filename (which encodes the compression). It supports the
// stdlib-decodable encodings APT publishes (plain, gzip, bzip2); xz and lz4
// require an external decoder and are reported unsupported so the caller serves
// the index live without populating the digest store (a documented limitation —
// gzip is what every APT client fetches by default).
func decompressPackages(filename string, data []byte) ([]byte, error) {
	switch {
	case strings.HasSuffix(filename, ".gz"):
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("apt: gzip Packages: %w", err)
		}
		defer zr.Close()
		return io.ReadAll(io.LimitReader(zr, maxPackagesBytes+1))
	case strings.HasSuffix(filename, ".bz2"):
		return io.ReadAll(io.LimitReader(bzip2.NewReader(bytes.NewReader(data)), maxPackagesBytes+1))
	case strings.HasSuffix(filename, ".xz"), strings.HasSuffix(filename, ".lz4"):
		return nil, fmt.Errorf("apt: %w: unsupported Packages compression for %q", errUnsupportedCompression, filename)
	default:
		// Plain, uncompressed Packages.
		return data, nil
	}
}

// errUnsupportedCompression flags a compression encoding the backend cannot
// decode in-process; it is handled by serving the index live and skipping digest
// extraction, not by failing the request.
var errUnsupportedCompression = fmt.Errorf("unsupported compression")
