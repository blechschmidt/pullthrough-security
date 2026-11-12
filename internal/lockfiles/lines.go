package lockfiles

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// lineIter walks the lines of a text without building a slice of them: a file
// of a million empty lines must not cost a million slice entries. Lines come
// as strings.Split(s, "\n") would give them, numbered from 1.
type lineIter struct {
	s   string
	pos int
	n   int
}

func newLineIter(s string) *lineIter { return &lineIter{s: s} }

// next returns the next line and its number, or ok false after the last.
func (l *lineIter) next() (line string, n int, ok bool) {
	if l.pos > len(l.s) {
		return "", 0, false
	}
	rest := l.s[l.pos:]
	if i := strings.IndexByte(rest, '\n'); i >= 0 {
		line = rest[:i]
		l.pos += i + 1
	} else {
		line = rest
		l.pos = len(l.s) + 1
	}
	l.n++
	return line, l.n, true
}

// Bounds of the formats read into a tree (YAML, TOML), whose memory grows
// with the number of values rather than the number of bytes.
const (
	// maxTreeInput is the largest YAML or TOML lock file read.
	maxTreeInput = 16 << 20
	// minBytesPerYAMLMark is the fewest bytes per YAML structure mark (":",
	// ",", "- ", "{", "[") a document may have. Real lock files have 21 to
	// 31 (pnpm-lock.yaml from pnpm 7 to 12, Yarn 3 and 4, compose files, the
	// lock files of vite and jest measured); a document denser than this is
	// all structure, and the parser's tree of it would be a hundred times its
	// size.
	minBytesPerYAMLMark = 12
)

var errTreeInputTooLarge = fmt.Errorf("larger than %d bytes, the limit for formats read into a tree", maxTreeInput)

// checkYAMLInput refuses YAML too large or too dense to read into a tree.
func checkYAMLInput(data []byte) error {
	if len(data) > maxTreeInput {
		return errTreeInputTooLarge
	}
	marks := bytes.Count(data, []byte(":")) + bytes.Count(data, []byte(",")) +
		bytes.Count(data, []byte("- ")) + bytes.Count(data, []byte("{")) + bytes.Count(data, []byte("["))
	if marks > len(data)/minBytesPerYAMLMark+1024 {
		return errors.New("YAML document too dense to be a lock file (a value every few bytes)")
	}
	return nil
}
