package update

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// The native updaters rewrite a lock file in place: the targeted entries'
// versions, download URLs and digests are replaced where they stand, and
// every other byte of the file — formatting, key order, indentation, line
// endings, the final newline — is kept. A rewrite they cannot make exactly
// (an entry in a shape they do not know, a version pinned elsewhere too) is an
// error, never a best effort: the caller then falls back to the package
// manager, and Verify holds whatever was written to what was intended.

// nativeUpdaters are the updaters NativeUpdater hands out, by format key.
// go.mod and go.sum are one pair, rewritten together by one updater.
var nativeUpdaters = map[string]Updater{
	"npm/package-lock.json":   npmUpdater{file: "package-lock.json"},
	"npm/npm-shrinkwrap.json": npmUpdater{file: "npm-shrinkwrap.json"},
	"pip/requirements.txt":    requirementsUpdater{},
	"cargo/Cargo.lock":        cargoUpdater{},
	"go/go.mod":               goUpdater{},
	"go/go.sum":               goUpdater{},
}

// NativeUpdater returns the updater that rewrites the lock-file format key
// ("<type>/<format>", as internal/lockfiles names its parsers) in place, or
// nil when the format is not updated natively.
func NativeUpdater(key string) Updater { return nativeUpdaters[key] }

// Bounds of what a change may name. Names and versions are written into the
// lock file as they are given; they must be plain tokens of the ecosystem's
// alphabet.
const (
	maxNameLen    = 512
	maxVersionLen = 256
)

// checkChanges holds the changes for an updater of the upstream type typ to
// what every native rewrite assumes: each names a package of that type and
// two different versions, spelled in the ecosystem's alphabet; no two change
// the same version of a package; and no change starts from a version another
// change moves the package to, whose outcome would depend on their order.
func checkChanges(typ string, changes []Change, nameOK, versionOK func(string) bool) error {
	if len(changes) == 0 {
		return errors.New("no changes to write")
	}
	from := map[[2]string]bool{}
	to := map[[2]string]bool{}
	for _, c := range changes {
		if c.Type != typ {
			return fmt.Errorf("a change of type %q for a %s lock file", c.Type, typ)
		}
		if len(c.Name) > maxNameLen || !nameOK(c.Name) {
			return fmt.Errorf("%q is not a %s package name", c.Name, typ)
		}
		if len(c.From) > maxVersionLen || len(c.To) > maxVersionLen || !versionOK(c.From) || !versionOK(c.To) {
			return fmt.Errorf("%s: %q or %q is not a %s version", c.Name, c.From, c.To, typ)
		}
		if c.From == c.To {
			return fmt.Errorf("%s: the change keeps version %s", c.Name, c.From)
		}
		k := [2]string{c.Name, c.From}
		if from[k] {
			return fmt.Errorf("two changes of %s %s", c.Name, c.From)
		}
		from[k] = true
		to[[2]string{c.Name, c.To}] = true
	}
	for _, c := range changes {
		if to[[2]string{c.Name, c.From}] {
			return fmt.Errorf("%s %s is changed and is what another change moves %s to", c.Name, c.From, c.Name)
		}
	}
	return nil
}

// tokenOf reports whether s is non-empty and made of ASCII letters, digits
// and the bytes of extra.
func tokenOf(s, extra string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.IndexByte(extra, c) >= 0 {
			continue
		}
		return false
	}
	return true
}

// semverToken reports whether s is spelled like a semantic version (npm,
// Cargo): digits, letters, ".", "-", "+".
func semverToken(s string) bool { return tokenOf(s, ".-+") && s[0] >= '0' && s[0] <= '9' }

// onlyArtifact returns the one artifact of a role. A change with none, or
// with several, names no single object whose digest the lock file can hold.
func onlyArtifact(c Change, role string) (Artifact, error) {
	arts := c.ArtifactsOf(role)
	switch len(arts) {
	case 1:
		return arts[0], nil
	case 0:
		return Artifact{}, fmt.Errorf("%s %s: the change carries no %q artifact", c.Name, c.To, role)
	default:
		return Artifact{}, fmt.Errorf("%s %s: the change carries %d %q artifacts, one was expected", c.Name, c.To, len(arts), role)
	}
}

// hexDigest returns v in lower case if it is the hex of an n-byte digest.
func hexDigest(v string, n int) (string, bool) {
	v = strings.ToLower(v)
	if len(v) != 2*n {
		return "", false
	}
	if _, err := hex.DecodeString(v); err != nil {
		return "", false
	}
	return v, true
}

// digestBytes are the lengths of the hashes internal/lockfiles reads from a
// lock file.
var digestBytes = map[string]int{"md5": 16, "sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}

// readableHash reports whether internal/lockfiles reads a digest from the
// value of a --hash option ("<alg>:<hex>", or "<alg>=<hex>"). A rewrite of an
// entry whose old digests the parser did not read would come out with digests
// where the scan saw none: the updaters refuse such entries.
func readableHash(v string) bool {
	v = strings.TrimSpace(v)
	i := strings.IndexAny(v, ":=")
	if i <= 0 {
		return false
	}
	n, ok := digestBytes[strings.ToLower(strings.TrimSpace(v[:i]))]
	if !ok {
		return false
	}
	_, ok = hexDigest(strings.TrimSpace(v[i+1:]), n)
	return ok
}

// readableIntegrity reports whether internal/lockfiles reads a digest from a
// Subresource Integrity value ("sha512-<base64> …").
func readableIntegrity(sri string) bool {
	for _, part := range strings.Fields(sri) {
		alg, value, ok := strings.Cut(part, "-")
		if !ok {
			continue
		}
		value, _, _ = strings.Cut(value, "?")
		n, ok := digestBytes[strings.ToLower(strings.TrimSpace(alg))]
		if !ok {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(value, "="))
		}
		if err == nil && len(raw) == n {
			return true
		}
	}
	return false
}

// sha256Of returns an artifact's SHA-256 as lower-case hex.
func sha256Of(c Change, a Artifact) (string, error) {
	v, ok := hexDigest(a.SHA256, 32)
	if !ok {
		return "", fmt.Errorf("%s %s: the %q artifact has no SHA-256", c.Name, c.To, a.Role)
	}
	return v, nil
}

// goH1 returns a Go module hash (the base64 text after "h1:") in the form
// go.sum writes and internal/lockfiles reports: standard base64 of a SHA-256,
// padded.
func goH1(v string) (string, bool) {
	v = strings.TrimPrefix(v, "h1:")
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(v, "="))
	}
	if err != nil || len(raw) != 32 {
		return "", false
	}
	return base64.StdEncoding.EncodeToString(raw), true
}

// edit replaces data[start:end] with text.
type edit struct {
	start, end int
	text       string
}

// splice applies edits that do not overlap to data, in one pass: the cost is
// the size of the file, whatever the number of edits.
func splice(data []byte, edits []edit) ([]byte, error) {
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	size := len(data)
	prev := 0
	for _, e := range edits {
		if e.start < prev || e.end < e.start || e.end > len(data) {
			return nil, errors.New("internal error: overlapping edits")
		}
		prev = e.end
		size += len(e.text) - (e.end - e.start)
	}
	out := make([]byte, 0, size)
	pos := 0
	for _, e := range edits {
		out = append(out, data[pos:e.start]...)
		out = append(out, e.text...)
		pos = e.end
	}
	return append(out, data[pos:]...), nil
}

// textLine is one line of a text file: its content is data[start:end], with
// any carriage returns before the newline left out, and the line ending runs
// from end to next (empty for a last line without a newline).
type textLine struct {
	start, end, next int
}

// nextLine returns the line starting at off, as strings.Split(data, "\n")
// would cut it. ok is false past the end.
func nextLine(data []byte, off int) (l textLine, ok bool) {
	if off > len(data) {
		return textLine{}, false
	}
	l.start = off
	nl := off
	for nl < len(data) && data[nl] != '\n' {
		nl++
	}
	l.end = nl
	for l.end > l.start && data[l.end-1] == '\r' {
		l.end--
	}
	l.next = nl + 1
	if nl == len(data) {
		l.next = len(data) + 1 // past the end: a last line without a newline
	}
	return l, true
}

// eol returns the line ending of l ("" for a last line without one).
func (l textLine) eol(data []byte) string {
	if l.next > len(data) {
		return string(data[l.end:])
	}
	return string(data[l.end:l.next])
}
