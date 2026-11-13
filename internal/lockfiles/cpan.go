package lockfiles

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// cpanfileSnapshot reads Carton's cpanfile.snapshot:
//
//	# carton snapshot format: version 1.0
//	DISTRIBUTIONS
//	  Try-Tiny-0.31
//	    pathname: E/ET/ETHER/Try-Tiny-0.31.tar.gz
//	    provides:
//	      Try::Tiny 0.31
//	    requirements:
//	      Carp 0
//
// Every distribution is one dependency, named and versioned as its archive
// is ("Try-Tiny" 0.31), with its path under authors/id/ — what a client
// fetches — as its ID. The snapshot records no hash: the CHECKSUMS file of
// the author's directory on CPAN has one, the snapshot does not. Nor does it
// say which distributions only tests need.
type cpanfileSnapshot struct{}

func (cpanfileSnapshot) Type() string            { return "cpan" }
func (cpanfileSnapshot) Format() string          { return "cpanfile.snapshot" }
func (cpanfileSnapshot) Detect(path string) bool { return baseName(path) == "cpanfile.snapshot" }

func (cpanfileSnapshot) Parse(data []byte) (*Result, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("cpanfile.snapshot is not valid UTF-8")
	}
	res := &Result{}
	inDists := false
	sawSection := false
	var cur *Dependency
	flush := func() {
		if cur == nil {
			return
		}
		d := *cur
		cur = nil
		if d.ID == "" {
			res.warnf("line %d: %s has no pathname", d.Line, d.Name)
			return
		}
		name, version, ok := cpanDistNameVersion(fileNameOf(d.ID))
		if !ok {
			name, version, ok = cpanDistNameVersion(d.Name)
		}
		if !ok || !validPackageName(name) || !validVersion(version) {
			res.warnf("line %d: the name and version of %s cannot be told from its archive", d.Line, d.Name)
			return
		}
		d.Name, d.Version = name, version
		res.Dependencies = append(res.Dependencies, d)
	}
	for it := newLineIter(string(data)); ; {
		raw, lineNo, more := it.next()
		if !more {
			break
		}
		line := strings.TrimRight(raw, "\r")
		if lineNo == 1 {
			if v, ok := strings.CutPrefix(line, "# carton snapshot format: version "); ok {
				res.FormatVersion = strings.TrimSpace(v)
				continue
			}
		}
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		text := strings.TrimSpace(line)
		switch {
		case indent == 0:
			flush()
			inDists = text == "DISTRIBUTIONS"
			sawSection = true
		case !inDists:
		case indent == 2:
			flush()
			cur = &Dependency{Name: text, Line: lineNo}
		case indent == 4 && cur != nil:
			if p, ok := strings.CutPrefix(text, "pathname:"); ok {
				cur.ID = strings.TrimSpace(p)
			}
		}
	}
	flush()
	if !sawSection {
		return nil, errNotFormat("cpanfile.snapshot", "no DISTRIBUTIONS section")
	}
	return res, nil
}

// cpanArchiveExts are the archive extensions of CPAN distributions.
var cpanArchiveExts = []string{".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar.xz", ".zip", ".tar"}

// cpanDistNameVersion splits "Try-Tiny-0.31" (or its archive's file name)
// at the last hyphen followed by a version: a digit, or "v" and a digit.
func cpanDistNameVersion(s string) (name, version string, ok bool) {
	for _, ext := range cpanArchiveExts {
		if base, cut := strings.CutSuffix(s, ext); cut {
			s = base
			break
		}
	}
	for i := len(s) - 1; i > 0; i-- {
		if s[i] != '-' || i+1 >= len(s) {
			continue
		}
		rest := s[i+1:]
		if rest[0] >= '0' && rest[0] <= '9' || len(rest) > 1 && rest[0] == 'v' && rest[1] >= '0' && rest[1] <= '9' {
			return s[:i], rest, true
		}
	}
	return "", "", false
}
