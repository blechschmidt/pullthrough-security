package fullmirror

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/conda"
)

// conda follows a channel's repodata, subdir by subdir (Task 191).
//
// A conda channel (conda.anaconda.org/<channel>, repo.anaconda.com/pkgs/<x>,
// an Artifactory, Nexus, Quetz or prefix.dev channel) publishes, per platform
// subdir, a repodata.json listing every package file of the subdir with its
// size, SHA-256 and time stamp (when it was built). Changes reads each
// followed subdir's repodata.json.zst (repodata.json where there is none)
// conditionally, with the ETag and Last-Modified of the copy read last: an
// unchanged subdir costs a 304 and its records are copied from the stored
// copy; a changed one is read whole, as a stream — decompressed with the
// decoder's memory bounded, walked to its "packages" and "packages.conda"
// objects, each package record decoded on its own — and the new copy is
// diffed against the stored one: a version with a file added or changed is
// reported as name@version. Bootstrap lists every package of the copy.
//
// Releases comes from the stored copy: each version with every file of it
// the followed subdirs list — every build, both formats (.conda and
// .tar.bz2) — at "/<subdir>/<filename>", the path the backend serves
// (conda.PackagePath), with its size and time stamp. A file whose name does
// not parse back to the name and version its record states is left out, so
// that the coordinate the backend derives is the one the feed reports.
//
// Options: "subdirs" (comma-separated; default noarch, linux-64,
// linux-aarch64, osx-64, osx-arm64, win-64 — conda clients read noarch as
// well as their platform's subdir, so list it), "index" (repodata, the
// default: every package file; current: current_repodata.json, the latest
// version of each package only), "settle" (default 30m) and "url" (another
// channel URL). A subdir the channel does not serve contributes nothing
// (conda-forge answers an empty repodata for one); a channel serving none of
// the subdirs is an error. A document refused (401, 403, 407: S3, and
// CloudFront in front of it, answers 403 for a key that does not exist) is
// passed over for the next one, like one not found; a subdir none of whose
// documents answers is not served — the channel is held (the poll fails and is
// retried) only when no subdir answered and one was refused. A subdir that was
// served and stops answering keeps its packages for condaMissingPolls polls in
// a row (a CDN's hiccup must not report every one of them deleted, and again
// when it is back). While the plain repodata.json answers, the .zst is asked
// for again at every poll (a 404 costs little; the .zst is an eighth of the
// plain document).
//
// A package file is reported once it has been listed for the settle period
// (option "settle"; feed_firstseen.go): the backend verifies a package
// against the subdir's plain repodata.json, which conda-forge's CDN caches for
// 20 minutes apart from the .zst the feed reads, and serves a file it finds
// no digest for unverified. The period counts from the poll that first saw
// the file — conda's timestamp is when the package was built, typically an
// hour or more before it is indexed. On a first read the timestamp stands in,
// or the subdir's Last-Modified for a package built less than a day before it.

// Bounds of the conda feed.
const (
	// condaMaxRepodata bounds a subdir's repodata, compressed and not: the
	// backend verifies packages against at most 768 MiB of it.
	condaMaxRepodata = 768 << 20
	// condaMaxSubdirs bounds the subdirs followed.
	condaMaxSubdirs = 32
	// condaMaxRecord bounds one package record of a repodata (real ones are a
	// few KB): the decoder holds a record whole.
	condaMaxRecord = 1 << 20
	// condaMaxDepth bounds the nesting of a value the parser skips (the
	// decoder keeps a frame per level; real repodata nests a few levels).
	condaMaxDepth = 64
	// condaMissingPolls is how many polls in a row a subdir that was served
	// may answer no document (404, 403) before its packages are dropped.
	condaMissingPolls = 3
	// condaDefaultSettle is how long a file is listed before it is reported:
	// conda-forge's CDN caches repodata.json for 20 minutes.
	condaDefaultSettle = 30 * time.Minute
)

// condaFirstSeenPrefix names the files that keep when the feed first saw each
// file of a subdir (feed_firstseen.go).
const condaFirstSeenPrefix = "conda-firstseen-"

func condaFirstSeenFile(subdir string) string { return condaFirstSeenPrefix + subdir + ".bin" }

// condaDefaultSubdirs are the subdirs followed by default: noarch and the
// platforms conda-forge builds for that clients mostly run on.
const condaDefaultSubdirs = "noarch,linux-64,linux-aarch64,osx-64,osx-arm64,win-64"

type condaFeed struct {
	*indexFeed
	src *condaSource
}

func newCondaFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "subdirs", "index", "settle")
	if err != nil {
		return nil, err
	}
	settle, err := gitSettleOption(opts, condaDefaultSettle)
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	channel := k.upstream
	if raw := opts["url"]; raw != "" {
		if channel, err = parseBaseURL("the feed option url", raw); err != nil {
			return nil, err
		}
	}
	subdirs, err := condaParseSubdirs(opts.get("subdirs", condaDefaultSubdirs))
	if err != nil {
		return nil, err
	}
	index, err := opts.oneOf("index", "repodata", "current")
	if err != nil {
		return nil, err
	}
	src := &condaSource{k: k, files: files{dir: env.Dir}, channel: channel, subdirs: subdirs, index: index, settle: settle, now: time.Now}
	return &condaFeed{indexFeed: newIndexFeed("conda", env, src), src: src}, nil
}

func init() { Register("conda", newCondaFeed) }

// condaParseSubdirs reads the "subdirs" option: subdirs the backend serves
// packages from, separated by commas.
func condaParseSubdirs(v string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if !conda.IsSubdir(s) || s != strings.ToLower(s) || len(s) > 64 {
			return nil, fmt.Errorf("option subdirs: %q is not a conda subdir (like noarch, linux-64 or osx-arm64)", s)
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) > condaMaxSubdirs {
		return nil, fmt.Errorf("option subdirs lists %d subdirs; at most %d are followed", len(out), condaMaxSubdirs)
	}
	sort.Strings(out)
	return out, nil
}

// Releases lists a package's versions from the stored copy, in conda's
// version order, each with every file of it in the subdirs followed.
func (f *condaFeed) Releases(_ context.Context, name string) ([]Release, error) {
	recs, err := f.lookup(name)
	if err != nil {
		return nil, err
	}
	rels := snapReleases(recs)
	// internal/versions has no conda scheme (orderReleases would keep the
	// copy's order, which is by version string).
	sort.SliceStable(rels, func(i, j int) bool { return condaCompareVersions(rels[i].Version, rels[j].Version) < 0 })
	return rels, nil
}

// condaSource reads a channel's repodata.
type condaSource struct {
	k       kit
	files   files
	channel *url.URL
	subdirs []string
	// index is "repodata" or "current".
	index string
	// settle is how long a file is listed before it is reported.
	settle time.Duration
	// now is this host's clock.
	now func() time.Time
}

// condaState is what the next read is conditioned on: per subdir, the
// document that answered and its validators.
type condaState struct {
	URL     string                      `json:"url"`
	Index   string                      `json:"index"`
	Subdirs map[string]condaSubdirState `json:"subdirs,omitempty"`
}

type condaSubdirState struct {
	// File is the document that answered; "" when the channel serves none.
	File string `json:"file,omitempty"`
	httpValidators
	// Pending is when (Unix seconds, this host's clock) the earliest file
	// held back settles: the document is then read even if unchanged.
	Pending int64 `json:"pending,omitempty"`
	// Missing counts the polls in a row the subdir, served before, answered
	// no document (404, 403): its packages are kept until condaMissingPolls.
	Missing int `json:"missing,omitempty"`
}

// documents are the documents a subdir's index is read from, preferred first.
func (s *condaSource) documents() []string {
	if s.index == "current" {
		return []string{"current_repodata.json.zst", "current_repodata.json"}
	}
	return []string{"repodata.json.zst", "repodata.json"}
}

func (s *condaSource) readIndex(ctx context.Context, prev json.RawMessage, old *snapHeader, b *snapBuilder) (indexRead, error) {
	var st condaState
	if prev != nil && json.Unmarshal(prev, &st) != nil {
		st = condaState{}
	}
	usable := old != nil && st.URL == s.channel.String() && st.Index == s.index
	next := condaState{URL: s.channel.String(), Index: s.index, Subdirs: map[string]condaSubdirState{}}
	keep := map[string]bool{}
	changed, served, present := false, 0, 0
	var refusal error
	for _, sd := range s.subdirs {
		var was condaSubdirState
		had := false
		if usable {
			was, had = st.Subdirs[sd]
		}
		r, err := s.readSubdir(ctx, sd, was, had, b)
		if err != nil {
			return indexRead{}, err
		}
		next.Subdirs[sd] = r.state
		if r.served {
			served++
		}
		if r.state.File != "" {
			present++
		}
		if r.refusal != nil {
			refusal = r.refusal
		}
		if r.same {
			keep[sd] = true
		} else {
			changed = true
		}
	}
	if served == 0 && refusal != nil {
		// No subdir answered and the channel refused some: not a verdict on
		// the channel (an expired token, an access rule); the upstream is
		// held.
		return indexRead{}, refusal
	}
	if present == 0 {
		return indexRead{}, Permanent(fmt.Errorf("%s serves no %s for any subdir followed (%s): is it a conda channel?", s.channel.Redacted(), s.documents()[1], strings.Join(s.subdirs, ", ")))
	}
	// The tables of subdirs no longer followed go.
	tables := make([]string, len(s.subdirs))
	for i, sd := range s.subdirs {
		tables[i] = condaFirstSeenFile(sd)
	}
	s.files.prune(condaFirstSeenPrefix, tables...)
	state, _ := json.Marshal(next)
	if usable && !changed && len(st.Subdirs) == len(next.Subdirs) {
		return indexRead{Unchanged: true, State: state}, nil
	}
	rd := indexRead{State: state}
	// The channel last changed when its newest subdir did.
	for _, sub := range next.Subdirs {
		if t, err := http.ParseTime(sub.LastModified); err == nil && t.After(rd.HeadTime) {
			rd.HeadTime = t.UTC()
		}
	}
	if len(keep) > 0 {
		// One pass over the stored copy for every part kept (a damaged copy
		// is the toolkit's to report and heal).
		if err := b.CopyFrom(old, func(r *snapRecord) bool { return keep[r.Index] }); err != nil {
			return indexRead{}, err
		}
	}
	return rd, nil
}

// condaSubdirRead is what a read of one subdir found.
type condaSubdirRead struct {
	// state is what the next read of the subdir is conditioned on.
	state condaSubdirState
	// same reports that the subdir's records are copied from the stored
	// copy: it did not change, or it is kept while it does not answer.
	same bool
	// served reports that one of its documents answered (200 or 304).
	served bool
	// refusal is a refusal of one of its documents when none answered.
	refusal error
}

// readSubdir reads one subdir's repodata into b, conditionally on what was
// read last (when had).
func (s *condaSource) readSubdir(ctx context.Context, sd string, was condaSubdirState, had bool, b *snapBuilder) (condaSubdirRead, error) {
	docs := s.documents()
	// The documents found missing or refused by this read, and how.
	absent := map[string]bool{}
	var refusal error
	isAbsent := func(file string, err error) bool {
		switch {
		case condaRefused(err):
			refusal = err
		case !condaNotFound(err):
			return false
		}
		absent[file] = true
		return true
	}
	if had && was.File != "" && was.File != docs[0] {
		// The plain document answered last: the compressed one is asked for
		// again (a CDN's 404 passed, the channel started serving it). While
		// it does not answer, the plain one is read as before.
		now, read, err := s.fetch(ctx, sd, docs[0], nil, b)
		switch {
		case err == nil:
			return condaSubdirRead{state: now, served: true}, nil
		case isAbsent(docs[0], err), !read:
		default:
			return condaSubdirRead{}, err
		}
	}
	if had && was.File != "" {
		// Conditionally, unless a file held back is due.
		var hdr http.Header
		if was.Pending == 0 || s.now().Unix() < was.Pending {
			hdr = http.Header{}
			was.httpValidators.set(hdr)
		}
		now, _, err := s.fetch(ctx, sd, was.File, hdr, b)
		switch {
		case err == nil:
			return condaSubdirRead{state: now, served: true}, nil
		case errors.Is(err, errNotModified):
			if len(hdr) == 0 {
				return condaSubdirRead{}, fmt.Errorf("%s answered an unconditional request with 304", join(s.channel, sd+"/"+was.File))
			}
			was.Missing = 0
			return condaSubdirRead{state: was, same: true, served: true}, nil
		case !isAbsent(was.File, err):
			return condaSubdirRead{}, err
		}
	}
	for _, file := range docs {
		if absent[file] {
			continue
		}
		now, _, err := s.fetch(ctx, sd, file, nil, b)
		switch {
		case err == nil:
			return condaSubdirRead{state: now, served: true}, nil
		case !isAbsent(file, err):
			return condaSubdirRead{}, err
		}
	}
	// Every document is gone or refused.
	if had && was.File != "" && was.Missing+1 < condaMissingPolls {
		// Served until now: its packages are kept, and it is asked for
		// again at the next poll.
		was.Missing++
		return condaSubdirRead{state: was, same: true, refusal: refusal}, nil
	}
	return condaSubdirRead{same: had && was.File == "", refusal: refusal}, nil
}

// condaNotFound reports the 404 or 410 of a document the channel does not
// serve.
func condaNotFound(err error) bool {
	var nf *condaMissing
	return errors.As(err, &nf)
}

// condaMissing marks a document the channel does not serve.
type condaMissing struct{ err error }

func (e *condaMissing) Error() string { return e.err.Error() }
func (e *condaMissing) Unwrap() error { return e.err }

// condaRefused reports a 401, 403 or 407 for a document: S3 (and CloudFront
// in front of it) answers 403 for a key that does not exist.
func condaRefused(err error) bool {
	var r *condaRefusal
	return errors.As(err, &r)
}

// condaRefusal marks a document the channel refused.
type condaRefusal struct{ err error }

func (e *condaRefusal) Error() string { return e.err.Error() }
func (e *condaRefusal) Unwrap() error { return e.err }

// fetch reads one repodata document of a subdir into b: the files listed for
// the settle period. read reports whether it began to read the document into
// b; an error before that (the document's status, the connection's) leaves b
// as it was.
func (s *condaSource) fetch(ctx context.Context, sd, file string, hdr http.Header, b *snapBuilder) (st condaSubdirState, read bool, err error) {
	raw := join(s.channel, sd+"/"+file)
	resp, body, err := s.k.getStream(ctx, raw, hdr, condaMaxRepodata)
	if err != nil {
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusNotFound, http.StatusGone:
				return condaSubdirState{}, false, &condaMissing{err: err}
			case http.StatusUnauthorized, http.StatusForbidden, http.StatusProxyAuthRequired:
				return condaSubdirState{}, false, &condaRefusal{err: err}
			}
		}
		return condaSubdirState{}, false, err
	}
	defer body.Close()
	content, release, err := openContent(body, raw, condaMaxRepodata)
	if err != nil {
		return condaSubdirState{}, false, err
	}
	defer release()
	local := s.now()
	table := firstSeenOpen(s.files, condaFirstSeenFile(sd), s.channel.String()+"\x00"+s.index+"\x00"+sd, s.settle, resp, local)
	info, err := condaParseRepodata(content, func(section, filename string, rec *condaRecord) {
		if r, ok := condaRecordOf(sd, section, filename, rec); ok && table.admit(&r, r.Time) {
			b.Add(r)
		}
	})
	if err != nil {
		return condaSubdirState{}, true, fmt.Errorf("%s: %w", raw, err)
	}
	if info.version >= 2 {
		if err := condaCheckBaseURL(raw, info.BaseURL); err != nil {
			return condaSubdirState{}, true, err
		}
	}
	if err := table.save(); err != nil {
		return condaSubdirState{}, true, err
	}
	return condaSubdirState{File: file, httpValidators: validatorsOf(resp), Pending: table.due(local)}, true, nil
}

// condaCheckBaseURL refuses a repodata (CEP-15, repodata_version 2) that
// places its packages elsewhere than beside it: the backend serves a
// subdir's packages beneath the channel only.
func condaCheckBaseURL(repodata, base string) error {
	if strings.TrimSpace(base) == "" {
		return nil
	}
	ru, err1 := url.Parse(repodata)
	bu, err2 := url.Parse(strings.TrimSpace(base))
	if err1 == nil && err2 == nil {
		got := ru.ResolveReference(bu)
		dir := ru.ResolveReference(&url.URL{Path: "./"})
		if strings.TrimRight(got.String(), "/") == strings.TrimRight(dir.String(), "/") {
			return nil
		}
	}
	return Permanent(fmt.Errorf("%s places its packages at %q (base_url), not beside it: the proxy's conda backend serves packages beneath the channel only", repodata, truncate(base, 200)))
}

// condaRecord is what the feed reads of a repodata package record.
type condaRecord struct {
	Name      string      `json:"name"`
	Version   string      `json:"version"`
	Size      json.Number `json:"size"`
	SHA256    string      `json:"sha256"`
	MD5       string      `json:"md5"`
	Timestamp json.Number `json:"timestamp"`
}

// condaRecordOf makes a package file's record; ok is false for a file the
// backend does not serve as the package its record names.
func condaRecordOf(subdir, section, filename string, rec *condaRecord) (snapRecord, bool) {
	if (section == "packages.conda") != strings.HasSuffix(filename, ".conda") {
		return snapRecord{}, false
	}
	p, name, version, ok := conda.PackagePath(subdir, filename)
	if !ok || rec.Name != name || rec.Version != version || !condaValidName(name) {
		return snapRecord{}, false
	}
	if _, ok := condaParseVersion(version); !ok {
		return snapRecord{}, false // a version conda cannot install
	}
	r := snapRecord{Name: name, Version: version, Path: p, Index: subdir}
	if n, err := strconv.ParseInt(rec.Size.String(), 10, 64); err == nil && n > 0 {
		r.Size = n
	}
	if f, err := strconv.ParseFloat(rec.Timestamp.String(), 64); err == nil && f > 0 && f < 1e15 {
		// conda's rule: a time stamp past the year 9999 in seconds is in
		// milliseconds.
		if f > 253402300799 {
			f /= 1000
		}
		r.Time = int64(f)
	}
	switch {
	case condaHex(rec.SHA256, 64):
		r.Digest = strings.ToLower(rec.SHA256[:16])
	case condaHex(rec.MD5, 32):
		r.Digest = "md5:" + strings.ToLower(rec.MD5[:16])
	}
	return r, true
}

// condaValidName reports a package name a channel can hold: letters, digits
// and "._+-", not starting with a dot or a dash.
func condaValidName(s string) bool {
	if s == "" || len(s) > 256 || s[0] == '.' || s[0] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._+-", c) >= 0) {
			return false
		}
	}
	return true
}

// condaHex reports a hex string of n characters.
func condaHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < n; i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// condaInfo is what the feed reads of a repodata's "info", and its
// repodata_version.
type condaInfo struct {
	Subdir  string `json:"subdir"`
	BaseURL string `json:"base_url"`
	version int
}

// condaParseRepodata reads a repodata document as a stream: it walks the
// top-level object to the "packages" and "packages.conda" objects and decodes
// each package record on its own, calling emit with it; everything else is
// skipped token by token, without being held. The decoder may read at most
// condaMaxRecord past the token it is at, so a record (or a key, or a string)
// larger than that is refused rather than held. A record of the wrong shape
// is left out (emit gets those that state a name and a version); a document
// that is not a JSON object of objects is a permanent error, a stream that
// failed (a connection cut, a decompression error) the stream's error.
func condaParseRepodata(r io.Reader, emit func(section, filename string, rec *condaRecord)) (condaInfo, error) {
	g := &condaGuard{r: r}
	p := &condaParser{dec: json.NewDecoder(g), g: g}
	var info condaInfo
	if err := p.delim('{'); err != nil {
		return info, err
	}
	for p.more() {
		key, err := p.key()
		if err != nil {
			return info, err
		}
		switch key {
		case "packages", "packages.conda":
			if err := p.section(key, emit); err != nil {
				return info, err
			}
		case "info":
			var in condaInfo
			if err := p.decode(&in); err != nil {
				return info, err
			}
			in.version = info.version
			info = in
		case "repodata_version":
			var n json.Number
			if err := p.decode(&n); err != nil {
				return info, err
			}
			if v, err := strconv.Atoi(n.String()); err == nil {
				info.version = v
			}
		default:
			if err := p.skip(); err != nil {
				return info, err
			}
		}
	}
	if err := p.delim('}'); err != nil {
		return info, err
	}
	if _, err := p.token(); err != io.EOF {
		if err != nil && !IsPermanent(err) {
			return info, err
		}
		return info, condaMalformed("data after the document")
	}
	return info, nil
}

// condaGuard is what a repodata's decoder reads from: it lets the decoder
// read at most condaMaxRecord past the token it is at, and keeps the error the
// stream itself failed with.
type condaGuard struct {
	r     io.Reader
	read  int64
	limit int64
	err   error
}

// errCondaTooLarge is a record, key or value past condaMaxRecord.
var errCondaTooLarge = fmt.Errorf("a record larger than %d bytes", condaMaxRecord)

func (g *condaGuard) Read(p []byte) (int, error) {
	if g.read >= g.limit {
		return 0, errCondaTooLarge
	}
	if room := g.limit - g.read; int64(len(p)) > room {
		p = p[:room]
	}
	n, err := g.r.Read(p)
	g.read += int64(n)
	if err != nil && err != io.EOF {
		g.err = err
	}
	return n, err
}

// condaParser walks a repodata document.
type condaParser struct {
	dec *json.Decoder
	g   *condaGuard
}

// bound lets the decoder read condaMaxRecord past where it is.
func (p *condaParser) bound() { p.g.limit = p.dec.InputOffset() + condaMaxRecord }

// fail classifies an error the decoder met: the stream's own failure (it is
// what the decoder's "unexpected EOF" means then), a record past its bound, a
// document that is not JSON.
func (p *condaParser) fail(err error) error {
	switch {
	case errors.Is(err, errCondaTooLarge):
		return condaMalformed(err.Error())
	case p.g.err != nil:
		return p.g.err
	}
	var se *json.SyntaxError
	if errors.As(err, &se) || errors.Is(err, io.ErrUnexpectedEOF) || err == io.EOF {
		return Permanent(fmt.Errorf("not a repodata document: %w", err))
	}
	return err
}

func (p *condaParser) more() bool {
	p.bound()
	return p.dec.More()
}

// token reads the next token; io.EOF at the document's end.
func (p *condaParser) token() (json.Token, error) {
	p.bound()
	tok, err := p.dec.Token()
	if err == io.EOF && p.g.err == nil {
		return nil, io.EOF
	}
	if err != nil {
		return nil, p.fail(err)
	}
	return tok, nil
}

// section reads one package object: filename -> record.
func (p *condaParser) section(section string, emit func(section, filename string, rec *condaRecord)) error {
	tok, err := p.token()
	if err != nil {
		return p.eof(err)
	}
	if tok == nil {
		return nil // null: no packages
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return condaMalformed(fmt.Sprintf("%q is not an object", section))
	}
	for p.more() {
		filename, err := p.key()
		if err != nil {
			return err
		}
		var rec condaRecord
		if err := p.decode(&rec); err != nil {
			return err
		}
		if rec.Name != "" && rec.Version != "" {
			emit(section, filename, &rec)
		}
	}
	return p.delim('}')
}

// decode decodes the next value into v. A value of the wrong type (a record
// that is not an object, a size that is a string) leaves the fields it could
// not fill empty: the value was read whole, and the decoder goes on after it.
func (p *condaParser) decode(v any) error {
	p.bound()
	err := p.dec.Decode(v)
	var te *json.UnmarshalTypeError
	if err == nil || errors.As(err, &te) || (p.g.err == nil && strings.HasPrefix(err.Error(), "json: invalid number literal")) {
		return nil
	}
	return p.eof(p.fail(err))
}

// key reads an object key.
func (p *condaParser) key() (string, error) {
	tok, err := p.token()
	if err != nil {
		return "", p.eof(err)
	}
	s, ok := tok.(string)
	if !ok {
		return "", condaMalformed(fmt.Sprintf("%v where a key belongs", tok))
	}
	return s, nil
}

// delim reads the delimiter want.
func (p *condaParser) delim(want json.Delim) error {
	tok, err := p.token()
	if err != nil {
		return p.eof(err)
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return condaMalformed(fmt.Sprintf("%v where %q belongs", tok, want))
	}
	return nil
}

// skip consumes the next value, token by token; one nested deeper than
// condaMaxDepth is refused.
func (p *condaParser) skip() error {
	depth := 0
	for {
		tok, err := p.token()
		if err != nil {
			return p.eof(err)
		}
		if d, ok := tok.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
				if depth > condaMaxDepth {
					return condaMalformed(fmt.Sprintf("a value nested deeper than %d levels", condaMaxDepth))
				}
			} else {
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

// eof turns the end of the document where more was expected into a
// permanent error.
func (p *condaParser) eof(err error) error {
	if err == io.EOF {
		return Permanent(fmt.Errorf("not a repodata document: %w", io.ErrUnexpectedEOF))
	}
	return err
}

// condaMalformed is a document of the wrong shape: permanent.
func condaMalformed(what string) error {
	return Permanent(fmt.Errorf("not a repodata document: %s", what))
}

// --- version order ----------------------------------------------------------------

// condaItem is one item of a version component as conda's VersionOrder
// splits it (conda.models.version): a number (its digits, without leading
// zeros), "post" (a number larger than every other) or a string ("dev"
// upper-cased, so that it sorts before every other string).
type condaItem struct {
	kind int // condaNumber, condaInfinity or condaString
	text string
}

const (
	condaNumber = iota
	condaInfinity
	condaString
)

// condaParseVersion splits a version as conda's VersionOrder does: into its
// components (the epoch first, 0 when it states none) and its local
// version's, each a list of items. ok is false for a version conda refuses.
func condaParseVersion(s string) ([2][][]condaItem, bool) {
	var out [2][][]condaItem
	v := strings.ToLower(strings.TrimSpace(s))
	valid := func(x string) bool {
		for i := 0; i < len(x); i++ {
			if c := x[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || strings.IndexByte("*.+!_", c) >= 0) {
				return false
			}
		}
		return x != ""
	}
	if !valid(v) {
		// Dashes stand for underscores when there are none.
		if !strings.Contains(v, "-") || strings.Contains(v, "_") {
			return out, false
		}
		if v = strings.ReplaceAll(v, "-", "_"); !valid(v) {
			return out, false
		}
	}
	epoch, rest, hasEpoch := strings.Cut(v, "!")
	if !hasEpoch {
		epoch, rest = "0", v
	} else if epoch == "" || strings.Trim(epoch, "0123456789") != "" || strings.Contains(rest, "!") {
		return out, false
	}
	main, local, hasLocal := strings.Cut(rest, "+")
	if main == "" || strings.Contains(local, "+") {
		return out, false
	}
	var comps []string
	if strings.HasSuffix(main, "_") {
		// openssl's "1.0.1_": the trailing underscore stays with the last
		// component.
		comps = strings.Split(strings.ReplaceAll(main[:len(main)-1], "_", "."), ".")
		comps[len(comps)-1] += "_"
	} else {
		comps = strings.Split(strings.ReplaceAll(main, "_", "."), ".")
	}
	lists := [2][]string{append([]string{epoch}, comps...), nil}
	if hasLocal {
		lists[1] = strings.Split(strings.ReplaceAll(local, "_", "."), ".")
	}
	for k, list := range lists {
		for _, comp := range list {
			items := condaItems(comp)
			if items == nil {
				return out, false
			}
			out[k] = append(out[k], items)
		}
	}
	return out, true
}

// condaItems splits a component into runs of digits, of '*' and of other
// characters, with a 0 before a component that does not start with a digit
// (so that 1.1.a1 == 1.1.0a1); nil for an empty component.
func condaItems(comp string) []condaItem {
	var out []condaItem
	class := func(c byte) int {
		switch {
		case c >= '0' && c <= '9':
			return 0
		case c == '*':
			return 1
		}
		return 2
	}
	for i := 0; i < len(comp); {
		j := i
		for j < len(comp) && class(comp[j]) == class(comp[i]) {
			j++
		}
		run := comp[i:j]
		switch {
		case class(comp[i]) == 0:
			if run = strings.TrimLeft(run, "0"); run == "" {
				run = "0"
			}
			out = append(out, condaItem{kind: condaNumber, text: run})
		case run == "post":
			out = append(out, condaItem{kind: condaInfinity})
		case run == "dev":
			out = append(out, condaItem{kind: condaString, text: "DEV"})
		default:
			out = append(out, condaItem{kind: condaString, text: run})
		}
		i = j
	}
	if len(out) > 0 && class(comp[0]) != 0 {
		out = append([]condaItem{{kind: condaNumber, text: "0"}}, out...)
	}
	return out
}

// condaCompareItems orders two items: strings before numbers, numbers by
// value ("post" above all), strings by text.
func condaCompareItems(a, b condaItem) int {
	switch {
	case a.kind == condaString && b.kind == condaString:
		return strings.Compare(a.text, b.text)
	case a.kind == condaString:
		return -1
	case b.kind == condaString:
		return 1
	case a.kind == condaInfinity || b.kind == condaInfinity:
		return a.kind - b.kind
	case len(a.text) != len(b.text):
		if len(a.text) < len(b.text) {
			return -1
		}
		return 1
	}
	return strings.Compare(a.text, b.text)
}

// condaCompareVersions orders versions as conda does (missing components and
// items count as 0); versions conda refuses sort first, and equal ones fall
// back to the text, so that the order is total.
func condaCompareVersions(a, b string) int {
	va, okA := condaParseVersion(a)
	vb, okB := condaParseVersion(b)
	switch {
	case !okA && !okB:
		return strings.Compare(a, b)
	case !okA:
		return -1
	case !okB:
		return 1
	}
	zero := condaItem{kind: condaNumber, text: "0"}
	for k := 0; k < 2; k++ {
		pa, pb := va[k], vb[k]
		for i := 0; i < len(pa) || i < len(pb); i++ {
			var ca, cb []condaItem
			if i < len(pa) {
				ca = pa[i]
			}
			if i < len(pb) {
				cb = pb[i]
			}
			for j := 0; j < len(ca) || j < len(cb); j++ {
				x, y := zero, zero
				if j < len(ca) {
					x = ca[j]
				}
				if j < len(cb) {
					y = cb[j]
				}
				if c := condaCompareItems(x, y); c != 0 {
					return c
				}
			}
		}
	}
	return strings.Compare(a, b)
}
