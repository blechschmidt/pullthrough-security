package fullmirror

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/cran"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// cran follows a CRAN-like repository's source index (Task 191).
//
// A CRAN mirror (cloud.r-project.org; Posit Package Manager, Bioconductor,
// miniCRAN, Artifactory and Nexus repositories alike) lists every current
// source package in src/contrib/PACKAGES, a DCF file of one stanza per
// package: Package, Version, MD5sum and, on CRAN, Published. Changes reads
// PACKAGES.gz (PACKAGES where there is none) conditionally, with the ETag and
// Last-Modified of the copy read last — an unchanged index costs a 304 — and
// diffs it against the stored copy, as a stream; a new version is reported as
// package@version, the version it supersedes as deleted. Bootstrap lists
// every package of the index.
//
// A version moves to src/contrib/Archive/<package>/ when the next one is
// published, and is listed from then on only in Meta/archive.rds (an R
// serialised object), which the feed does not read: archived versions are not
// followed. A version is current when it is published, so following PACKAGES
// catches every upload; one the mirror has not fetched before it is archived
// (a version superseded within one poll interval, or during a long
// enumeration) is not mirrored. Windows and macOS binaries (bin/…/PACKAGES,
// one per R version) are not followed.
//
// Releases comes from the stored copy: a package's current version, with its
// source tarball at "/src/contrib/<package>_<version>.tar.gz" (repos/locate's
// cran locator, the path R downloads while the version is current) and the
// time it was published. A stanza whose Path field names a subdirectory is
// served beneath it (cran.SourcePackagePath); CRAN lists its recommended
// packages a second time under "<R version>/Recommended", and R installs the
// top-level copy, so a version listed at the top level is mirrored from there
// only.
//
// Any upstream serves src/contrib/PACKAGES beneath its URL; the feed option
// "url" names another repository root to read it from. A document refused
// (401, 403, 407: S3, and CloudFront in front of it, answers 403 for a key
// that does not exist) is passed over for the next one, like one not found;
// when neither answers, the upstream is held (the poll fails and is retried)
// if one was refused, and the repository is not a CRAN-like one if both are
// not found. While the plain PACKAGES answers, PACKAGES.gz is asked for again
// at every poll.
//
// A version is reported once it has been listed for the settle period (feed
// option "settle", default 45m; see feed_firstseen.go): the backend verifies a
// tarball against the plain PACKAGES, which CRAN's CloudFront caches for 30
// minutes apart from the PACKAGES.gz the feed reads, and serves a tarball it
// finds no MD5 for unverified. The period counts from the poll that first saw
// the version (on a first read, from its Published time, or from PACKAGES'
// Last-Modified for a version published less than a day before it).

// Bounds of the cran feed.
const (
	// cranMaxIndex bounds PACKAGES, compressed and not (CRAN's is 7.5 MB;
	// the backend verifies tarballs against at most 64 MiB of it).
	cranMaxIndex = 64 << 20
)

// cranFiles are the index documents, preferred first.
var cranFiles = []string{"src/contrib/PACKAGES.gz", "src/contrib/PACKAGES"}

// Settling.
const (
	// cranDefaultSettle is how long a version is listed before it is
	// reported: CRAN's CloudFront caches PACKAGES for 30 minutes.
	cranDefaultSettle = 45 * time.Minute
	// cranFirstSeenFile keeps when the feed first saw each version.
	cranFirstSeenFile = "cran-firstseen.bin"
)

type cranFeed struct {
	*indexFeed
	src *cranSource
}

func newCRANFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "settle")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	settle, err := gitSettleOption(opts, cranDefaultSettle)
	if err != nil {
		return nil, err
	}
	root := k.upstream
	if raw := opts["url"]; raw != "" {
		if root, err = parseBaseURL("the feed option url", raw); err != nil {
			return nil, err
		}
	}
	src := &cranSource{k: k, files: files{dir: env.Dir}, root: root, settle: settle, now: time.Now}
	return &cranFeed{indexFeed: newIndexFeed("cran", env, src), src: src}, nil
}

func init() { Register("cran", newCRANFeed) }

// Releases lists a package's version from the stored copy (normally its one
// current version), with the source tarball R downloads.
func (f *cranFeed) Releases(_ context.Context, name string) ([]Release, error) {
	recs, err := f.lookup(name)
	if err != nil {
		return nil, err
	}
	rels := snapReleases(recs)
	for i := range rels {
		rels[i].Artifacts = cranPreferTopLevel(rels[i].Artifacts)
	}
	// internal/versions has no R scheme (orderReleases would keep the copy's
	// order, which is by version string).
	sort.SliceStable(rels, func(i, j int) bool { return cranCompareVersions(rels[i].Version, rels[j].Version) < 0 })
	return rels, nil
}

// cranPreferTopLevel keeps a version's tarball at the top of src/contrib
// when it has one there: R installs that copy of a version listed twice.
func cranPreferTopLevel(arts []Artifact) []Artifact {
	var top []Artifact
	for _, a := range arts {
		if rest := strings.TrimPrefix(a.Path, "/src/contrib/"); rest != a.Path && !strings.Contains(rest, "/") {
			top = append(top, a)
		}
	}
	if len(top) == 0 {
		return arts
	}
	return top
}

// cranSource reads a repository's PACKAGES.
type cranSource struct {
	k     kit
	files files
	root  *url.URL
	// settle is how long a version is listed before it is reported.
	settle time.Duration
	// now is this host's clock.
	now func() time.Time
}

// cranState is what the next read is conditioned on.
type cranState struct {
	URL  string `json:"url"`
	File string `json:"file,omitempty"`
	httpValidators
	// Pending is when (Unix seconds, this host's clock) the earliest version
	// held back settles: the index is then read even if unchanged.
	Pending int64 `json:"pending,omitempty"`
}

func (s *cranSource) readIndex(ctx context.Context, prev json.RawMessage, old *snapHeader, b *snapBuilder) (indexRead, error) {
	var st cranState
	if prev != nil && json.Unmarshal(prev, &st) != nil {
		st = cranState{}
	}
	if st.URL != s.root.String() {
		// A copy of another repository (or none the state tells of): its
		// records are not carried forward.
		old = nil
	}
	known := old != nil && st.File != ""
	// The documents found missing or refused by this read.
	absent := map[string]bool{}
	var refusal error
	isAbsent := func(file string, err error) bool {
		switch {
		case cranRefused(err):
			refusal = err
		case !cranNotFound(err):
			return false
		}
		absent[file] = true
		return true
	}
	if known && st.File != cranFiles[0] {
		// The plain PACKAGES answered last: PACKAGES.gz is asked for again
		// (a CDN's 404 passed, the repository started serving it). While it
		// does not answer, the plain one is read as before.
		next, read, err := s.fetch(ctx, cranFiles[0], nil, old, b)
		switch {
		case err == nil:
			return next, nil
		case isAbsent(cranFiles[0], err), !read:
		default:
			return next, err
		}
	}
	if known {
		// Conditionally, unless a version held back is due.
		var hdr http.Header
		if st.Pending == 0 || s.now().Unix() < st.Pending {
			hdr = http.Header{}
			st.httpValidators.set(hdr)
		}
		next, _, err := s.fetch(ctx, st.File, hdr, old, b)
		switch {
		case err == nil:
			return next, nil
		case errors.Is(err, errNotModified):
			if len(hdr) == 0 {
				return indexRead{}, fmt.Errorf("%s answered an unconditional request with 304", join(s.root, st.File))
			}
			return indexRead{Unchanged: true}, nil
		case !isAbsent(st.File, err):
			return next, err
		}
	}
	for _, file := range cranFiles {
		if absent[file] {
			continue
		}
		next, _, err := s.fetch(ctx, file, nil, old, b)
		switch {
		case err == nil:
			return next, nil
		case !isAbsent(file, err):
			return next, err
		}
	}
	if refusal != nil {
		// Nothing answered and the repository refused a document: not a
		// verdict on it (an expired token, an access rule); the upstream is
		// held.
		return indexRead{}, refusal
	}
	return indexRead{}, Permanent(fmt.Errorf("%s serves no src/contrib/PACKAGES: is it a CRAN-like repository?", s.root.Redacted()))
}

// cranMissing marks an index document the repository does not serve.
type cranMissing struct{ err error }

func (e *cranMissing) Error() string { return e.err.Error() }
func (e *cranMissing) Unwrap() error { return e.err }

func cranNotFound(err error) bool {
	var m *cranMissing
	return errors.As(err, &m)
}

// cranRefusal marks an index document the repository refused (401, 403, 407:
// S3, and CloudFront in front of it, answers 403 for a key that does not
// exist).
type cranRefusal struct{ err error }

func (e *cranRefusal) Error() string { return e.err.Error() }
func (e *cranRefusal) Unwrap() error { return e.err }

func cranRefused(err error) bool {
	var r *cranRefusal
	return errors.As(err, &r)
}

// fetch reads one index document into b: the versions listed for the settle
// period. PACKAGES lists a package's current version only: a package whose
// listed versions are all held back keeps the records the stored copy old
// has of it (its previous version) until they settle, rather than vanish
// from the copy meanwhile. read reports whether it began to read the
// document into b; an error before that (the document's status, the
// connection's) leaves b as it was.
func (s *cranSource) fetch(ctx context.Context, file string, hdr http.Header, old *snapHeader, b *snapBuilder) (rd indexRead, read bool, err error) {
	raw := join(s.root, file)
	resp, body, err := s.k.getStream(ctx, raw, hdr, cranMaxIndex)
	if err != nil {
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusNotFound, http.StatusGone:
				return indexRead{}, false, &cranMissing{err: err}
			case http.StatusUnauthorized, http.StatusForbidden, http.StatusProxyAuthRequired:
				return indexRead{}, false, &cranRefusal{err: err}
			}
		}
		return indexRead{}, false, err
	}
	defer body.Close()
	content, release, err := openContent(body, raw, cranMaxIndex)
	if err != nil {
		return indexRead{}, false, err
	}
	defer release()
	local := s.now()
	table := firstSeenOpen(s.files, cranFirstSeenFile, s.root.String(), s.settle, resp, local)
	kept := 0
	// The packages with a version held back, and those with one admitted.
	held, admitted := map[string]bool{}, map[string]bool{}
	malformed, err := cranParsePackages(content, func(st cranStanza) {
		rec, ok := s.record(ctx, st)
		if !ok || !rec.valid() {
			return
		}
		kept++
		if table.admit(&rec, rec.Time) {
			b.Add(rec)
			admitted[rec.Name] = true
		} else {
			held[rec.Name] = true
		}
	})
	if err != nil {
		return indexRead{}, true, fmt.Errorf("%s: %w", raw, err)
	}
	if kept == 0 && malformed > 0 {
		// Not an empty repository: something else (an error page) answered.
		return indexRead{}, true, Permanent(fmt.Errorf("%s is not a PACKAGES index: %d stanzas, none of them one", raw, malformed))
	}
	for name := range admitted {
		delete(held, name)
	}
	if len(held) > 0 && old != nil {
		if err := b.CopyFrom(old, func(r *snapRecord) bool { return held[r.Name] }); err != nil {
			return indexRead{}, true, err
		}
	}
	if err := table.save(); err != nil {
		return indexRead{}, true, err
	}
	v := validatorsOf(resp)
	state, _ := json.Marshal(cranState{URL: s.root.String(), File: file, httpValidators: v, Pending: table.due(local)})
	rd = indexRead{State: state}
	if t, err := http.ParseTime(v.LastModified); err == nil {
		rd.HeadTime = t.UTC()
	}
	return rd, true, nil
}

// record makes a stanza's record: its source tarball where R downloads it.
// ok is false for a stanza the backend does not serve as that version.
func (s *cranSource) record(ctx context.Context, st cranStanza) (snapRecord, bool) {
	if !cranValidName(st.Package) || !cranValidVersion(st.Version) {
		return snapRecord{}, false
	}
	if st.File != "" && st.File != st.Package+"_"+st.Version+".tar.gz" {
		return snapRecord{}, false // R downloads a file of another name
	}
	var p string
	if st.Path == "" {
		arts, err := s.k.locate(ctx, lockfiles.Dependency{Name: st.Package, Version: st.Version}, nil)
		if err != nil || len(arts) != 1 {
			return snapRecord{}, false
		}
		p = arts[0].Path
	} else {
		var ok bool
		if p, ok = cran.SourcePackagePath(st.Path, st.Package, st.Version); !ok {
			return snapRecord{}, false
		}
	}
	rec := snapRecord{Name: st.Package, Version: st.Version, Path: p}
	if sum := strings.ToLower(st.MD5sum); condaHex(sum, 32) {
		rec.Digest = sum
	}
	for _, layout := range []string{"2006-01-02 15:04:05 MST", "2006-01-02 15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, st.Published); err == nil && t.Unix() > 0 {
			rec.Time = t.Unix()
			break
		}
	}
	return rec, true
}

// cranValidName reports an R package name: letters, digits and dots,
// starting with a letter, not ending with a dot.
func cranValidName(s string) bool {
	if len(s) < 2 || len(s) > 256 || s[len(s)-1] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// cranValidVersion reports an R package version: non-negative integers
// separated by single dots or dashes.
func cranValidVersion(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' }) {
		if strings.Trim(part, "0123456789") != "" {
			return false
		}
	}
	return s[0] != '.' && s[0] != '-' && s[len(s)-1] != '.' && s[len(s)-1] != '-' &&
		!strings.Contains(s, "..") && !strings.Contains(s, "--") && !strings.Contains(s, ".-") && !strings.Contains(s, "-.")
}

// cranStanza is what the feed reads of one PACKAGES stanza.
type cranStanza struct {
	Package, Version, MD5sum, Path, File, Published string
}

// cranParsePackages reads a PACKAGES (DCF) document as a stream, calling emit
// for every stanza and returning how many it left out. Field names are
// matched as R's read.dcf matches them (exactly); a stanza that repeats or
// continues one of the fields read, or holds a line that is neither a field
// nor a continuation, is left out.
func cranParsePackages(r io.Reader, emit func(cranStanza)) (int, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var st cranStanza
	bad, open := false, false
	var last string
	seen := map[string]bool{}
	malformed := 0
	flush := func() {
		if open && !bad {
			emit(st)
		} else if open {
			malformed++
		}
		st, bad, open, last = cranStanza{}, false, false, ""
		clear(seen)
	}
	for {
		line, long, err := cranReadLine(br)
		if err != nil && err != io.EOF {
			return malformed, err
		}
		if line == nil && err == io.EOF {
			flush()
			return malformed, nil
		}
		text := strings.TrimSuffix(string(line), "\r")
		switch {
		case long:
			open, bad = true, true
		case strings.TrimSpace(text) == "":
			flush()
		case text[0] == ' ' || text[0] == '\t':
			// A continuation of the field before it: the fields read are
			// one-line values.
			if !open || cranRead(last) {
				bad = true
			}
			open = true
		default:
			open = true
			key, val, ok := strings.Cut(text, ":")
			if !ok || key == "" || strings.ContainsAny(key, " \t") {
				bad = true
				last = ""
				continue
			}
			last = key
			if !cranRead(key) {
				continue
			}
			if seen[key] {
				bad = true
			}
			seen[key] = true
			val = strings.TrimSpace(val)
			switch key {
			case "Package":
				st.Package = val
			case "Version":
				st.Version = val
			case "MD5sum":
				st.MD5sum = val
			case "Path":
				st.Path = val
			case "File":
				st.File = val
			case "Published":
				st.Published = val
			}
		}
		if err == io.EOF {
			flush()
			return malformed, nil
		}
	}
}

// cranRead reports a field the feed reads.
func cranRead(key string) bool {
	switch key {
	case "Package", "Version", "MD5sum", "Path", "File", "Published":
		return true
	}
	return false
}

// cranReadLine reads a line without its line break. A line longer than the
// reader's buffer (64 KiB) is read past and reported long: its stanza is
// malformed.
func cranReadLine(br *bufio.Reader) (line []byte, long bool, err error) {
	line, err = br.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		for err == bufio.ErrBufferFull {
			_, err = br.ReadSlice('\n')
		}
		if err != nil && err != io.EOF {
			return nil, false, err
		}
		return []byte{}, true, err
	}
	if err == io.EOF && len(line) == 0 {
		return nil, false, io.EOF
	}
	if err != nil && err != io.EOF {
		return nil, false, err
	}
	return []byte(strings.TrimSuffix(string(line), "\n")), false, err
}

// --- version order ----------------------------------------------------------------

// cranCompareVersions orders R package versions as package_version does:
// numerically, component by component, a version that is a prefix of another
// first; versions that do not parse sort first, and equal ones fall back to
// the text, so that the order is total.
func cranCompareVersions(a, b string) int {
	okA, okB := cranValidVersion(a), cranValidVersion(b)
	switch {
	case !okA && !okB:
		return strings.Compare(a, b)
	case !okA:
		return -1
	case !okB:
		return 1
	}
	split := func(r rune) bool { return r == '.' || r == '-' }
	pa, pb := strings.FieldsFunc(a, split), strings.FieldsFunc(b, split)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, y := strings.TrimLeft(pa[i], "0"), strings.TrimLeft(pb[i], "0")
		if len(x) != len(y) {
			if len(x) < len(y) {
				return -1
			}
			return 1
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	if c := len(pa) - len(pb); c != 0 {
		if c < 0 {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}
