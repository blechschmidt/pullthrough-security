package yum

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// primary.xml (usually served gzip-compressed as <hash>-primary.xml.gz) is the
// package list of an RPM repository. Each <package> entry carries the .rpm's
// repository-root-relative location and the checksum that anchors its
// verification. The proxy parses it to record every (rpm-path -> checksum) pair
// into the digest store, then verifies a fetched .rpm against the recorded digest.
//
// Schematic of a single package entry:
//
//	<package type="rpm">
//	  <name>foo</name>
//	  <version epoch="0" ver="1.0" rel="1"/>
//	  <checksum type="sha256" pkgid="YES"><hex></checksum>
//	  <location href="Packages/foo-1.0-1.x86_64.rpm"/>
//	</package>

// maxPrimaryBytes bounds how much of a (decompressed) primary.xml the parser
// reads. Large repositories publish primary.xml of a few hundred MiB
// decompressed; the cap is generous while still bounding memory.
const maxPrimaryBytes = 512 << 20 // 512 MiB

// PackageEntry is the parsed locator + digest of one package in primary.xml.
type PackageEntry struct {
	Name     string
	Location string
	Checksum expectedChecksum
}

// ParsePrimary decodes a (already-decompressed) primary.xml into the list of
// (location, checksum) pairs the backend records. It streams the document with a
// token decoder so a large package list does not require materializing a full
// DOM. Entries without a usable location or a supported checksum are skipped
// rather than failing the whole parse.
func ParsePrimary(data []byte) ([]PackageEntry, error) {
	if len(data) > maxPrimaryBytes {
		return nil, fmt.Errorf("yum: primary.xml exceeds %d bytes", maxPrimaryBytes)
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	var out []PackageEntry
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("yum: parsing primary.xml: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "package" {
			continue
		}
		var pkg rawPackage
		if err := dec.DecodeElement(&pkg, &se); err != nil {
			return nil, fmt.Errorf("yum: parsing primary.xml package: %w", err)
		}
		href := strings.TrimLeft(strings.TrimSpace(pkg.Location.Href), "/")
		if href == "" || strings.Contains(href, "..") {
			continue
		}
		c, ok := parseChecksum(pkg.Checksum.Type, pkg.Checksum.Value)
		if !ok {
			continue
		}
		out = append(out, PackageEntry{
			Name:     strings.TrimSpace(pkg.Name),
			Location: href,
			Checksum: c,
		})
	}
	return out, nil
}

type rawPackage struct {
	Name     string `xml:"name"`
	Checksum struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"checksum"`
	Location struct {
		Href string `xml:"href,attr"`
	} `xml:"location"`
}

// decompressPrimary returns the decompressed bytes of a primary.xml given its
// filename (which encodes the compression). It supports gzip (the createrepo
// default) and plain XML; xz/zstd primaries require an external decoder and are
// reported unsupported so the caller serves the file live without populating the
// digest store (a documented limitation — gzip is the overwhelming default).
func decompressPrimary(filename string, data []byte) ([]byte, error) {
	switch {
	case strings.HasSuffix(filename, ".gz"):
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("yum: gzip primary.xml: %w", err)
		}
		defer zr.Close()
		return io.ReadAll(io.LimitReader(zr, maxPrimaryBytes+1))
	case strings.HasSuffix(filename, ".xz"), strings.HasSuffix(filename, ".zst"), strings.HasSuffix(filename, ".zck"):
		return nil, fmt.Errorf("yum: %w: unsupported primary.xml compression for %q", errUnsupportedCompression, filename)
	default:
		return data, nil
	}
}

// errUnsupportedCompression flags a compression encoding the backend cannot
// decode in-process; it is handled by serving the file live and skipping digest
// extraction, not by failing the request.
var errUnsupportedCompression = fmt.Errorf("unsupported compression")
