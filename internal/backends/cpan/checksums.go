package cpan

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// A CPAN per-author CHECKSUMS file is a PGP-clearsigned document whose body is a
// single Perl data structure assigning a digest record to every file in the same
// author directory. It is emitted by CPAN::Checksums as Data::Dumper output, one
// key or field per line:
//
//	0&&<<''; # this PGP-signed message is also valid perl
//	-----BEGIN PGP SIGNED MESSAGE-----
//	Hash: SHA256
//
//	$cksum = {
//	  'Acme-CPANAuthors-Canadian-0.0108.tar.gz' => {
//	    'md5' => 'ab4b1f23abf8dc9cdd26fca1dc09be9c',
//	    'mtime' => '2022-01-04',
//	    'sha256' => '7ad62d525bf89a1541cbfc50b85c18b70bdb3c4c3593cb51fb722e4f6817e1f5',
//	    'size' => 26874
//	  },
//	  ...
//	};
//	-----BEGIN PGP SIGNATURE-----
//	...
//	-----END PGP SIGNATURE-----
//
// The proxy parses this to recover the SHA-256 the author's own tooling recorded
// for a requested distribution tarball, then verifies the fetched tarball against
// it before the bytes are cached or streamed to a client — so a tampered or
// corrupt mirror can neither poison the cache nor reach a client. This mirrors the
// checksum verification the CRAN backend performs against the PACKAGES index and
// the Hex backend performs against the signed /packages/<name> resource.
//
// The parser is line-oriented and tolerant: it does not evaluate Perl, nor does it
// verify the enclosing PGP signature (the digests in the body are the integrity
// anchor used here, and the file is fetched over the same authenticated egress as
// the tarball). It tracks the current filename entry and captures that entry's
// sha256 field, which is exactly the shape CPAN::Checksums emits.

// maxChecksumsBytes bounds how much of a CHECKSUMS file the parser reads. A
// prolific author's directory lists many releases, but the file is still well
// under this cap, which bounds memory against a hostile upstream.
const maxChecksumsBytes = 64 << 20 // 64 MiB

const sha256HexLen = 64

// Checksums maps each filename in an author directory to its lowercase SHA-256
// hex digest, recovered from a CHECKSUMS document.
type Checksums struct {
	sha256 map[string]string
}

// ParseChecksums decodes a CHECKSUMS document into the digest index the backend
// verifies distributions against. Entries without a well-formed SHA-256 are
// skipped (they cannot anchor a verification) rather than failing the whole parse,
// so a single malformed or sha256-less entry does not deny service for the rest of
// the directory.
func ParseChecksums(data []byte) (*Checksums, error) {
	if len(data) > maxChecksumsBytes {
		return nil, fmt.Errorf("cpan: CHECKSUMS file exceeds %d bytes", maxChecksumsBytes)
	}
	cs := &Checksums{sha256: map[string]string{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var current string // filename of the entry currently being parsed
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// A new entry opens with "'<filename>' => {". The filename is the key; the
		// opening brace begins its digest record.
		if name, ok := entryKey(line); ok {
			current = name
			continue
		}
		// A "'<field>' => '<value>'" line within the current entry. Capture sha256.
		if current != "" {
			if key, val, ok := quotedField(line); ok && strings.EqualFold(key, "sha256") {
				if hex, ok := normalizeSHA256(val); ok {
					cs.sha256[current] = hex
				}
			}
		}
		// A closing "}," ends the current entry.
		if strings.HasPrefix(line, "}") {
			current = ""
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cpan: reading CHECKSUMS file: %w", err)
	}
	return cs, nil
}

// sha256For returns the recorded SHA-256 for a filename.
func (c *Checksums) sha256For(filename string) (string, bool) {
	if c == nil || filename == "" {
		return "", false
	}
	d, ok := c.sha256[filename]
	return d, ok
}

// entryKey reports whether line opens a new file entry of the form
// "'<filename>' => {" and returns the (unquoted) filename. The value side must be
// an opening brace, distinguishing an entry key from an ordinary "'k' => 'v'"
// field.
func entryKey(line string) (string, bool) {
	key, rest, ok := quotedKey(line)
	if !ok {
		return "", false
	}
	if !strings.HasPrefix(strings.TrimSpace(rest), "{") {
		return "", false
	}
	return key, true
}

// quotedField parses a "'<key>' => '<value>'" line into its unquoted key and
// value. It returns ok=false for lines whose value is not a single-quoted scalar
// (e.g. an entry-opening brace or a bare numeric like 'size' => 26874).
func quotedField(line string) (key, val string, ok bool) {
	key, rest, ok := quotedKey(line)
	if !ok {
		return "", "", false
	}
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, "'") {
		return "", "", false
	}
	rest = rest[1:]
	end := strings.IndexByte(rest, '\'')
	if end < 0 {
		return "", "", false
	}
	return key, rest[:end], true
}

// quotedKey parses a leading "'<key>' =>" from line, returning the unquoted key
// and the remainder after the fat comma. It returns ok=false when the line does
// not begin with a single-quoted key followed by "=>".
func quotedKey(line string) (key, rest string, ok bool) {
	if !strings.HasPrefix(line, "'") {
		return "", "", false
	}
	body := line[1:]
	end := strings.IndexByte(body, '\'')
	if end < 0 {
		return "", "", false
	}
	key = body[:end]
	after := strings.TrimSpace(body[end+1:])
	if !strings.HasPrefix(after, "=>") {
		return "", "", false
	}
	return key, strings.TrimSpace(after[len("=>"):]), true
}

// normalizeSHA256 lowercases s and returns it only if it is exactly 64 hex
// characters; otherwise it returns ok=false (a malformed digest is treated as no
// digest rather than trusted).
func normalizeSHA256(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) != sha256HexLen || !isHex(s) {
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
