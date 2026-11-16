package cpan

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The full mirror (Task 190) lists a CPAN distribution's releases from its
// author directory's CHECKSUMS file and names them the way this backend does.
// These helpers expose the backend's own parsers for that, so the mirror
// fetches exactly the files Resolve classifies as distributions.

// ParseDistFilename splits a distribution archive's file name into the
// distribution's name and version with the backend's own rule (parseDistFilename,
// over its archive extension list): "Try-Tiny-0.31.tar.gz" is "Try-Tiny" at
// "0.31". ok reports a recognized archive extension; dist and version are
// empty for an archive whose name has no version boundary — Resolve serves
// such a file without a coordinate.
func ParseDistFilename(file string) (dist, version string, ok bool) {
	return parseDistFilename(file)
}

// maxChecksumsEntries bounds the files ListChecksums returns.
const maxChecksumsEntries = 1 << 20

// ChecksumsEntry is one file a CHECKSUMS document lists.
type ChecksumsEntry struct {
	// File is the file's name in the author directory.
	File string
	// Size is its size in bytes; zero when the entry states none.
	Size int64
	// Mtime is the day the file was written ("mtime" => "2022-01-04"), at
	// midnight UTC; zero when the entry states none or another form.
	Mtime time.Time
	// SHA256 is its lower-case hex SHA-256; empty when the entry has none
	// well-formed.
	SHA256 string
	// IsDir marks a subdirectory ("isdir" => 1): it has no digest, and its
	// files are listed by its own CHECKSUMS.
	IsDir bool
}

// ListChecksums reads every file a CHECKSUMS document lists, in the
// document's order, with its size and mtime as well as its digest — what
// ParseChecksums reads, it keeps only the digests. It reads the same
// CPAN::Checksums layout with the same line helpers and tolerance: a field it
// does not know is skipped, and an entry whose name is repeated keeps its
// first record.
func ListChecksums(data []byte) ([]ChecksumsEntry, error) {
	if len(data) > maxChecksumsBytes {
		return nil, fmt.Errorf("cpan: CHECKSUMS file exceeds %d bytes", maxChecksumsBytes)
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var out []ChecksumsEntry
	seen := map[string]bool{}
	cur := -1 // index in out of the entry being read; -1 outside one
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if name, ok := entryKey(line); ok {
			cur = -1
			if name == "" || seen[name] {
				continue
			}
			if len(out) >= maxChecksumsEntries {
				return nil, fmt.Errorf("cpan: CHECKSUMS file lists more than %d files", maxChecksumsEntries)
			}
			seen[name] = true
			out = append(out, ChecksumsEntry{File: name})
			cur = len(out) - 1
			continue
		}
		if cur >= 0 {
			e := &out[cur]
			if key, val, ok := quotedField(line); ok {
				switch strings.ToLower(key) {
				case "sha256":
					if hex, ok := normalizeSHA256(val); ok {
						e.SHA256 = hex
					}
				case "mtime":
					if t, err := time.Parse("2006-01-02", strings.TrimSpace(val)); err == nil {
						e.Mtime = t.UTC()
					}
				case "size":
					e.Size = checksumsSize(val)
				case "isdir":
					e.IsDir = strings.TrimSpace(val) == "1"
				}
			} else if key, val, ok := bareField(line); ok {
				switch strings.ToLower(key) {
				case "size":
					e.Size = checksumsSize(val)
				case "isdir":
					e.IsDir = val == "1"
				}
			}
		}
		if strings.HasPrefix(line, "}") {
			cur = -1
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cpan: reading CHECKSUMS file: %w", err)
	}
	return out, nil
}

// bareField parses a "'<key>' => <value>," line whose value is not quoted
// (CPAN::Checksums writes sizes as bare numbers), returning the value without
// its trailing comma.
func bareField(line string) (key, val string, ok bool) {
	key, rest, ok := quotedKey(line)
	if !ok {
		return "", "", false
	}
	val = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), ","))
	if val == "" || strings.ContainsAny(val, "'\"{}") {
		return "", "", false
	}
	return key, val, true
}

// checksumsSize reads a size field: decimal digits, no sign; anything else is
// no size.
func checksumsSize(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 18 {
		return 0
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return 0
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
