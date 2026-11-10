package conan

import "strings"

// conanmanifest.txt is Conan's per-revision integrity record. Its wire format is
// a leading timestamp line followed by one "relative/path: md5hex" line per file
// in the revision:
//
//	1700000000
//	conanfile.py: 5d41402abc4b2a76b9719d911017c592
//	conan_sources.tgz: 7d793037a0760186574b0282f2f435e7
//
// The digest is a 32-character hex MD5 and always appears last on the line; the
// path may itself contain spaces or colons (unusual, but possible for recipe
// exports), so the value is recovered from the end of the line rather than by
// naive field splitting.

const md5HexLen = 32

// Manifest maps each file's path (as recorded in conanmanifest.txt) to its
// lowercase MD5 hex digest.
type Manifest struct {
	Digests map[string]string
}

// ParseManifest parses a conanmanifest.txt body. Lines that do not carry a
// trailing MD5 hex digest (the timestamp line, blank lines, malformed entries)
// are skipped rather than treated as an error, so a partially understood
// manifest still yields the digests it does declare. A nil or empty body yields
// an empty, non-nil manifest.
func ParseManifest(body []byte) *Manifest {
	m := &Manifest{Digests: map[string]string{}}
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimRight(raw, "\r")
		colon := strings.LastIndex(line, ":")
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		value := strings.TrimSpace(line[colon+1:])
		if name == "" || len(value) != md5HexLen || !isHex(value) {
			continue
		}
		m.Digests[name] = strings.ToLower(value)
	}
	return m
}

// digestFor returns the recorded MD5 for a requested file path. It tries the
// exact path first, then the bare basename, since recipe-export manifests record
// relative paths while a client requests a flat filename.
func (m *Manifest) digestFor(filename string) (string, bool) {
	if m == nil || filename == "" {
		return "", false
	}
	if d, ok := m.Digests[filename]; ok {
		return d, true
	}
	base := filename
	if i := strings.LastIndex(filename, "/"); i >= 0 {
		base = filename[i+1:]
	}
	if base != filename {
		if d, ok := m.Digests[base]; ok {
			return d, true
		}
	}
	return "", false
}

// isHex reports whether s is composed solely of hexadecimal digits.
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
