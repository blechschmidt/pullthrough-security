package apt

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// Release (and its inline-clearsigned twin InRelease) is the trust anchor of an
// APT repository. It is a single RFC822/Deb822 control paragraph whose SHA256
// field enumerates every index file published under the suite, each as a
// "<hex> <size> <relative-path>" line. The proxy parses it to recover the
// expected SHA-256 of a requested Packages index and verifies the fetched index
// against it; when a trusted GPG keyring is configured the Release's own
// signature is checked first (see gpg.go), so the whole SHA-256 chain descends
// from a cryptographically verified root.
//
// Schematic of the document the parser accepts (Release form shown; InRelease is
// the same content wrapped in a PGP clearsign envelope, which the parser strips):
//
//	Origin: Debian
//	Suite: bookworm
//	Components: main contrib non-free
//	SHA256:
//	 <hex> 1234 main/binary-amd64/Packages
//	 <hex>  567 main/binary-amd64/Packages.gz
//	MD5Sum:
//	 <hex> 1234 main/binary-amd64/Packages

// maxReleaseBytes bounds how much of a Release document the parser reads. Release
// files enumerate every index in a suite and run to a few MiB on the largest
// archives; the cap stops a hostile upstream exhausting memory.
const maxReleaseBytes = 32 << 20 // 32 MiB

// Release is the parsed, validated form of a Release/InRelease document, reduced
// to what the backend needs: the SHA-256 of each published index file, keyed by
// its suite-relative path.
type Release struct {
	// Suite/Codename are advisory provenance fields surfaced for diagnostics.
	Suite    string
	Codename string
	// digests maps a suite-relative index path (e.g. "main/binary-amd64/Packages.gz")
	// to its declared lowercase SHA-256 hex.
	digests map[string]string
}

// Digest returns the SHA-256 declared for a suite-relative index path.
func (r *Release) Digest(relPath string) (expectedChecksum, bool) {
	hex, ok := r.digests[strings.TrimLeft(relPath, "/")]
	if !ok {
		return expectedChecksum{}, false
	}
	return expectedChecksum{hex: hex}, true
}

// ParseRelease decodes a Release or InRelease document and extracts the SHA256
// file table. It transparently unwraps a PGP clearsign envelope (InRelease) so
// the same parser serves both forms. A document with no parseable SHA256 table
// is an error so the backend fails closed rather than treating an unsigned or
// malformed Release as an empty (and therefore unverifiable) one.
func ParseRelease(data []byte) (*Release, error) {
	if len(data) > maxReleaseBytes {
		return nil, fmt.Errorf("apt: Release exceeds %d bytes", maxReleaseBytes)
	}
	body := stripClearsign(data)

	rel := &Release{digests: make(map[string]string)}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	inSHA256 := false
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		// Continuation lines (digest entries) begin with a space or tab.
		if line[0] == ' ' || line[0] == '\t' {
			if inSHA256 {
				if hex, rel2, ok := parseDigestLine(line); ok {
					rel.digests[rel2] = hex
				}
			}
			continue
		}
		// A new field header ends any in-progress digest block.
		key, val, ok := splitField(line)
		if !ok {
			inSHA256 = false
			continue
		}
		switch strings.ToLower(key) {
		case "sha256":
			inSHA256 = true
		case "suite":
			rel.Suite = strings.TrimSpace(val)
			inSHA256 = false
		case "codename":
			rel.Codename = strings.TrimSpace(val)
			inSHA256 = false
		default:
			inSHA256 = false
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("apt: reading Release: %w", err)
	}
	if len(rel.digests) == 0 {
		return nil, fmt.Errorf("apt: Release carries no SHA256 file table")
	}
	return rel, nil
}

// parseDigestLine parses a "<hex> <size> <path>" digest entry, returning the
// normalized SHA-256 and the suite-relative path. A malformed or non-SHA256 line
// is rejected (ok=false) so it is skipped rather than poisoning the table.
func parseDigestLine(line string) (hex, relPath string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return "", "", false
	}
	h, ok := normalizeSHA256(fields[0])
	if !ok {
		return "", "", false
	}
	if _, err := strconv.ParseInt(fields[1], 10, 64); err != nil {
		return "", "", false
	}
	p := strings.TrimLeft(fields[2], "/")
	if p == "" || strings.Contains(p, "..") {
		return "", "", false
	}
	return h, p, true
}

// splitField splits a Deb822 "Key: value" header line.
func splitField(line string) (key, val string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// stripClearsign returns the signed content of a PGP clearsigned document (the
// bytes between the armor header block and the signature), or the input
// unchanged when it is not clearsigned. It is a parsing convenience only — actual
// signature verification is performed in gpg.go against a trusted keyring.
func stripClearsign(data []byte) []byte {
	const beginMsg = "-----BEGIN PGP SIGNED MESSAGE-----"
	const beginSig = "-----BEGIN PGP SIGNATURE-----"
	s := string(data)
	idx := strings.Index(s, beginMsg)
	if idx < 0 {
		return data
	}
	// Skip the armor header line and the following "Hash:" headers, which end at
	// the first blank line.
	rest := s[idx+len(beginMsg):]
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[nl+1:]
	}
	if blank := strings.Index(rest, "\n\n"); blank >= 0 {
		rest = rest[blank+2:]
	} else if blank := strings.Index(rest, "\r\n\r\n"); blank >= 0 {
		rest = rest[blank+4:]
	}
	if end := strings.Index(rest, beginSig); end >= 0 {
		rest = rest[:end]
	}
	// Reverse the clearsign dash-escaping ("- " prefix on lines).
	rest = strings.ReplaceAll(rest, "\n- ", "\n")
	rest = strings.TrimPrefix(rest, "- ")
	return []byte(rest)
}
