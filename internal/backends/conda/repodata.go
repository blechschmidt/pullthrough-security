package conda

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// repodata.json is a Conda subdir's integrity record and catalog. It is a JSON
// object with two package sections — "packages" (legacy .tar.bz2 archives) and
// "packages.conda" (the v2 .conda format) — each mapping a package filename to a
// record carrying the archive's "sha256" and "md5" digests:
//
//	{
//	  "info": {"subdir": "linux-64"},
//	  "packages": {
//	    "numpy-1.26.0-py312h0_0.tar.bz2": {"sha256": "<hex>", "md5": "<hex>", "size": 1}
//	  },
//	  "packages.conda": {
//	    "numpy-1.26.0-py312h0_0.conda": {"sha256": "<hex>", "md5": "<hex>", "size": 1}
//	  }
//	}
//
// conda-forge's per-subdir repodata.json runs to hundreds of megabytes, so the
// backend never buffers the whole document. repodataChecksum streams the body
// with a token-level decoder, descends only into the one section that could hold
// the requested filename, and stops as soon as the entry is found — memory stays
// bounded regardless of index size.

// maxRepodataBytes bounds how much of a repodata.json the parser will read. The
// largest published per-subdir indices are a few hundred MiB; the cap is
// generous while still bounding memory against a hostile upstream.
const maxRepodataBytes = 768 << 20 // 768 MiB

const (
	sha256HexLen = 64
	md5HexLen    = 32
)

// pkgRecord is the subset of a repodata package record the backend needs: the
// integrity digests. Other fields (size, depends, build, ...) are ignored.
type pkgRecord struct {
	SHA256 string `json:"sha256"`
	MD5    string `json:"md5"`
}

// repodataChecksum streams a repodata.json body and returns the SHA-256 and MD5
// digests recorded for want. It inspects only the section that matches want's
// archive format ("packages.conda" for a .conda filename, "packages" otherwise)
// and returns found=false if the file is absent (the caller then serves it
// unverified). A truncated or non-JSON body yields an error.
func repodataChecksum(r io.Reader, want string) (sha256hex, md5hex string, found bool, err error) {
	section := "packages"
	if strings.HasSuffix(want, ".conda") {
		section = "packages.conda"
	}
	dec := json.NewDecoder(io.LimitReader(r, maxRepodataBytes+1))

	tok, err := dec.Token()
	if err != nil {
		return "", "", false, fmt.Errorf("conda: reading repodata.json: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return "", "", false, fmt.Errorf("conda: repodata.json is not a JSON object")
	}
	for dec.More() {
		keyTok, kerr := dec.Token()
		if kerr != nil {
			return "", "", false, fmt.Errorf("conda: reading repodata.json: %w", kerr)
		}
		key, _ := keyTok.(string)
		if key == section {
			return scanSection(dec, want)
		}
		if serr := skipValue(dec); serr != nil {
			return "", "", false, fmt.Errorf("conda: reading repodata.json: %w", serr)
		}
	}
	return "", "", false, nil
}

// scanSection iterates the entries of a repodata package section, decoding only
// the record for want and skipping every other (potentially huge) entry.
func scanSection(dec *json.Decoder, want string) (sha256hex, md5hex string, found bool, err error) {
	tok, err := dec.Token()
	if err != nil {
		return "", "", false, fmt.Errorf("conda: reading repodata section: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return "", "", false, fmt.Errorf("conda: repodata section is not a JSON object")
	}
	for dec.More() {
		keyTok, kerr := dec.Token()
		if kerr != nil {
			return "", "", false, fmt.Errorf("conda: reading repodata section: %w", kerr)
		}
		name, _ := keyTok.(string)
		if name == want {
			var rec pkgRecord
			if derr := dec.Decode(&rec); derr != nil {
				return "", "", false, fmt.Errorf("conda: decoding repodata entry %q: %w", want, derr)
			}
			sha := normalizeHex(rec.SHA256, sha256HexLen)
			m := normalizeHex(rec.MD5, md5HexLen)
			if sha == "" && m == "" {
				return "", "", false, nil
			}
			return sha, m, true, nil
		}
		if serr := skipValue(dec); serr != nil {
			return "", "", false, fmt.Errorf("conda: reading repodata section: %w", serr)
		}
	}
	return "", "", false, nil
}

// skipValue consumes the next JSON value from the decoder without materializing
// it, tracking container depth so an arbitrarily nested object/array is skipped
// in a single pass. Scalars are consumed by their single opening token.
func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok || (d != '{' && d != '[') {
		return nil
	}
	depth := 1
	for depth > 0 {
		t, terr := dec.Token()
		if terr != nil {
			return terr
		}
		if dd, ok := t.(json.Delim); ok {
			switch dd {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

// normalizeHex lowercases s and returns it only if it is exactly wantLen
// hexadecimal characters; otherwise it returns "" (a malformed or absent digest
// is treated as no digest rather than trusted).
func normalizeHex(s string, wantLen int) string {
	s = strings.TrimSpace(s)
	if len(s) != wantLen || !isHex(s) {
		return ""
	}
	return strings.ToLower(s)
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
