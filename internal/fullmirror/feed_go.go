package fullmirror

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
	"github.com/blechschmidt/pullthrough-security/internal/versions"
)

// go follows the Go module index.
//
// The index (index.golang.org for proxy.golang.org) lists every module version
// the mirror has fetched, as JSON lines {Path, Version, Timestamp} in
// chronological order: `index?since=<RFC 3339>&limit=2000` returns the
// versions from since on, at most 2000 (the cap). Since is inclusive, so the
// cursor keeps the last timestamp read together with the versions already
// reported at exactly that instant, which the next page repeats and the feed
// drops. A full page whose versions all share the cursor's timestamp would be
// returned again and again; the feed steps one microsecond past that instant
// instead — the versions beyond the first 2000 of a single instant (the
// index's resolution is a microsecond) are not reported, which the index has
// not been seen to hold. A full page asks for more right away.
//
// The index is the complete enumeration, so Bootstrap replays it from its
// beginning (2019) until a page is not full, and continues from where the
// replay ended: nothing published during it is missed, since the replay reads
// up to the newest entry. Every change carries its version.
//
// Pseudo-versions (v0.0.0-20261116023036-3ccb34e7df57: a commit, not a tag)
// are listed by the index but not by a module's @v/list, so the engine would
// find each "gone"; they are dropped, and an untagged commit is mirrored when a
// client first asks for it. Tagged versions are kept, "+incompatible" and
// pre-releases included.
//
// Releases reads the module's @v/list through the gated pipeline (the module
// path case-escaped as the protocol wants it) and names each version's .info,
// .mod and .zip with repos/locate's Go locator — the paths the backend serves
// and the go command fetches. A version the feed announced in its last two
// batches is listed even while the module's @v/list does not show it yet
// (proxy.golang.org says a new version can take up to 30 minutes to appear
// in its lists), so a fresh version is not lost as "gone". Retractions in a
// module's go.mod are not read: a retracted version is mirrored like any
// other, and the go command still honours the retraction.
//
// The public mirror's index is https://index.golang.org/index. Athens serves
// the same format at <upstream>/index (covering what it has stored), which is
// assumed for any other upstream; the feed option "url" names another index
// (the index endpoint itself; a URL without a path gets "/index"). A GOPROXY
// without an index — Artifactory, Nexus, goproxy.io, goproxy.cn — cannot be
// followed by itself; one that mirrors proxy.golang.org can be followed with
// url set to index.golang.org's.

const goIndexFeedVersion = 1

// goIndexPublicHosts are the public mirror's names.
var goIndexPublicHosts = []string{"proxy.golang.org"}

// goIndexPublic is the public mirror's index.
const goIndexPublic = "https://index.golang.org/index"

// goIndexWithoutIndex are public GOPROXYs known to serve no index.
var goIndexWithoutIndex = []string{"goproxy.io", "goproxy.cn", "mirrors.aliyun.com", "mirrors.tencent.com"}

const (
	// goIndexLimit is the most versions one page asks for (the cap).
	goIndexLimit = 2000
	// goIndexMaxSeen bounds the versions a cursor remembers at its timestamp.
	goIndexMaxSeen = goIndexLimit
	// goIndexMaxLines bounds the lines one page may have.
	goIndexMaxLines = 100_000
	// goIndexMaxList bounds a module's @v/list.
	goIndexMaxList = 16 << 20
	// goIndexMaxVersions bounds the versions one @v/list may name.
	goIndexMaxVersions = 100_000
	// goIndexMaxPath bounds a module path.
	goIndexMaxPath = 512
	// goIndexMaxVersion bounds a version.
	goIndexMaxVersion = 256
	// goIndexFuture is how far ahead of the clock a cursor may stand.
	goIndexFuture = 24 * time.Hour
)

type goIndexFeed struct {
	k kit
	// index is the index endpoint.
	index *url.URL
	// limit is how many versions one page asks for.
	limit int
	now   func() time.Time
	files files
	// recent and older are the versions the last two batches announced, by
	// module. They are kept in Env.Dir as well (goIndexAnnounced): the engine
	// resumes a stored batch after a restart before it polls again, and a
	// version its Releases no longer knew of would be taken for gone.
	mu            sync.Mutex
	loaded        bool
	recent, older map[string][]string
}

// goIndexAnnounced names the file the announcements are kept in.
const goIndexAnnounced = "go-announced.json"

// goIndexAnnouncements is that file's content.
type goIndexAnnouncements struct {
	Recent map[string][]string `json:"recent"`
	Older  map[string][]string `json:"older"`
}

func newGoIndexFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	var index *url.URL
	switch {
	case opts["url"] != "":
		if index, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
		if index.Path == "" {
			index.Path = "/index"
		}
	case hostIs(k.upstream, goIndexPublicHosts...):
		index, _ = url.Parse(goIndexPublic)
	case hostIs(k.upstream, goIndexWithoutIndex...):
		return nil, fmt.Errorf("upstream %s is a GOPROXY without a module index: set fullMirror.feed.url to an index of what it serves (https://index.golang.org/index for a mirror of proxy.golang.org)", k.upstream.Redacted())
	default:
		u := *k.upstream
		u.Path = strings.TrimRight(u.Path, "/") + "/index"
		index = &u
	}
	return &goIndexFeed{k: k, index: index, limit: goIndexLimit, now: time.Now, files: files{dir: env.Dir}}, nil
}

func init() { Register("go", newGoIndexFeed) }

// goIndexCursor is the Go feed's position.
type goIndexCursor struct {
	Format string `json:"format"`
	// Since is the timestamp of the last version read (RFC 3339); empty at
	// the index's beginning.
	Since string `json:"since,omitempty"`
	// Seen are the versions already reported at exactly Since, as
	// goIndexKey hashes: the next page, which starts at Since, repeats them.
	Seen []string `json:"seen,omitempty"`
	// Replay is set while Bootstrap replays the index.
	Replay bool `json:"replay,omitempty"`
}

func (c *goIndexCursor) cursorFormat() string { return c.Format }

func (f *goIndexFeed) format() string { return cursorFormat("go", goIndexFeedVersion) }

// decode reads and checks a cursor and its timestamp.
func (f *goIndexFeed) decode(cursor string) (goIndexCursor, time.Time, error) {
	var c goIndexCursor
	if err := decodeCursor(cursor, f.format(), &c); err != nil {
		return c, time.Time{}, err
	}
	var since time.Time
	if c.Since != "" {
		t, err := time.Parse(time.RFC3339Nano, c.Since)
		if err != nil {
			return c, time.Time{}, fmt.Errorf("%w: the go cursor's timestamp %q does not read", ErrCursorInvalid, truncate(c.Since, 64))
		}
		since = t.UTC()
	}
	if len(c.Seen) > goIndexMaxSeen || (c.Since == "" && len(c.Seen) > 0) {
		return c, time.Time{}, fmt.Errorf("%w: the go cursor remembers %d versions", ErrCursorInvalid, len(c.Seen))
	}
	for _, s := range c.Seen {
		if !goIndexIsKey(s) {
			return c, time.Time{}, fmt.Errorf("%w: the go cursor remembers %q", ErrCursorInvalid, truncate(s, 32))
		}
	}
	if since.After(f.now().Add(goIndexFuture)) {
		return c, time.Time{}, fmt.Errorf("%w: the go cursor stands at %s, in the future", ErrCursorInvalid, c.Since)
	}
	return c, since, nil
}

// Bootstrap replays the index from its beginning.
func (f *goIndexFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	c, since := goIndexCursor{Format: f.format(), Replay: true}, time.Time{}
	if cursor != "" {
		var err error
		if c, since, err = f.decode(cursor); err != nil {
			return Batch{}, err
		}
		if !c.Replay {
			return Batch{}, fmt.Errorf("%w: the go cursor does not continue a replay of the index", ErrCursorInvalid)
		}
	}
	return f.read(ctx, c, since)
}

// Changes reads the index after the cursor.
func (f *goIndexFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	c, since, err := f.decode(cursor)
	if err != nil {
		return Batch{}, err
	}
	if c.Replay {
		return Batch{}, fmt.Errorf("%w: the go cursor continues a replay of the index", ErrCursorInvalid)
	}
	return f.read(ctx, c, since)
}

// read reads the page at the cursor.
func (f *goIndexFeed) read(ctx context.Context, c goIndexCursor, since time.Time) (Batch, error) {
	q := url.Values{"limit": {strconv.Itoa(f.limit)}}
	if c.Since != "" {
		q.Set("since", since.Format(time.RFC3339Nano))
	}
	u := *f.index
	u.RawQuery = q.Encode()
	body, resp, err := f.k.get(ctx, u.String(), nil, maxFeedPage)
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone) {
			return Batch{}, Permanent(fmt.Errorf("%s serves no module index (%v): a GOPROXY without one (Artifactory, Nexus, goproxy.io) cannot be followed; set fullMirror.feed.url to an index of what it serves, such as https://index.golang.org/index for a mirror of proxy.golang.org", f.index.Redacted(), err))
		}
		return Batch{}, fmt.Errorf("reading the module index: %w", err)
	}
	entries, lines, err := goIndexParsePage(body)
	if err != nil {
		return Batch{}, Permanent(fmt.Errorf("the module index page at %s: %w", u.Redacted(), err))
	}
	full := lines >= f.limit
	items, next, newest, err := goIndexAdvance(c, since, f.now().Add(goIndexFuture), entries, full)
	if err != nil {
		return Batch{}, Permanent(fmt.Errorf("the module index page at %s: %w", u.Redacted(), err))
	}
	if c.Replay && !full {
		next.Replay = false // the replay reached the newest entry: follow from here
	}
	b := Batch{Items: items, Next: encodeCursor(&next), More: full}
	if !newest.IsZero() {
		b.CursorTime = newest
		if !full {
			b.Head, b.HeadTime, b.LagKnown = newest.Format(time.RFC3339Nano), newest, true
		}
	}
	f.remember(items)
	return b, nil
}

// goIndexEntry is one record of the index.
type goIndexEntry struct {
	path, version string
	time          time.Time
}

// goIndexParsePage reads an index page: one JSON record per line. Records of
// another shape are left out; lines counts every non-empty line (a page with
// as many as the limit is full), and a page none of whose lines is a record
// is an error.
func goIndexParsePage(body []byte) ([]goIndexEntry, int, error) {
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(nil, 1<<20) // a record is a line of a few hundred bytes
	var out []goIndexEntry
	lines := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if lines++; lines > goIndexMaxLines {
			return nil, 0, fmt.Errorf("more than %d lines", goIndexMaxLines)
		}
		var r struct {
			Path      string `json:"Path"`
			Version   string `json:"Version"`
			Timestamp string `json:"Timestamp"`
		}
		if json.Unmarshal(line, &r) != nil || r.Path == "" || r.Version == "" || len(r.Path) > goIndexMaxPath || len(r.Version) > goIndexMaxVersion {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, r.Timestamp)
		if err != nil || t.Year() < 2000 {
			continue
		}
		out = append(out, goIndexEntry{path: r.Path, version: r.Version, time: t.UTC()})
	}
	if err := sc.Err(); err != nil {
		return nil, 0, err
	}
	if lines > 0 && len(out) == 0 {
		return nil, 0, fmt.Errorf("none of its %d lines is an index record", lines)
	}
	return out, lines, nil
}

// goIndexAdvance works out a page's changes and the cursor after it: the
// records from the cursor's timestamp on, less those the cursor remembers,
// as tagged versions of valid module paths (each once); and the newest
// timestamp read. Records dated after horizon (the clock and a day) are
// left out: a cursor moved into the future would be refused at the next
// poll and have the index replayed from its beginning, again and again.
func goIndexAdvance(c goIndexCursor, since, horizon time.Time, entries []goIndexEntry, full bool) ([]Coordinate, goIndexCursor, time.Time, error) {
	seen := make(map[string]bool, len(c.Seen))
	for _, k := range c.Seen {
		seen[k] = true
	}
	current := entries[:0:0]
	newest := since
	for _, e := range entries {
		if !since.IsZero() && e.time.Before(since) {
			continue // before the cursor: not asked for
		}
		if e.time.After(horizon) {
			continue // dated in the future
		}
		current = append(current, e)
		if e.time.After(newest) {
			newest = e.time
		}
	}
	next := goIndexCursor{Format: c.Format, Replay: c.Replay, Since: c.Since, Seen: c.Seen}
	if len(current) == 0 {
		if full {
			// A full page of records older than since: an index that ignores
			// since would have the feed read the same page forever.
			return nil, next, since, errors.New("a full page without a record between the since asked for and now")
		}
		return nil, next, since, nil
	}
	var items []Coordinate
	dup := map[Coordinate]bool{}
	for _, e := range current {
		if e.time.Equal(since) && seen[goIndexKey(e)] {
			continue // reported with the page before
		}
		if co, ok := goIndexCoordinate(e); ok && !dup[co] {
			dup[co] = true
			items = append(items, co)
		}
	}
	keys := map[string]bool{}
	if newest.Equal(since) {
		for k := range seen {
			keys[k] = true
		}
	}
	for _, e := range current {
		if e.time.Equal(newest) {
			keys[goIndexKey(e)] = true
		}
	}
	if (full && newest.Equal(since)) || len(keys) > goIndexMaxSeen {
		// The page is one instant's records and full: the index cannot show
		// what follows them at that instant. Step past it.
		next.Since, next.Seen = newest.Add(time.Microsecond).Format(time.RFC3339Nano), nil
		return items, next, newest, nil
	}
	next.Since, next.Seen = newest.Format(time.RFC3339Nano), make([]string, 0, len(keys))
	for k := range keys {
		next.Seen = append(next.Seen, k)
	}
	sort.Strings(next.Seen)
	return items, next, newest, nil
}

// goIndexKey identifies a record in a cursor: 64 bits of the SHA-256 of
// "path@version", in hex.
func goIndexKey(e goIndexEntry) string {
	sum := sha256.Sum256([]byte(e.path + "@" + e.version))
	return hex.EncodeToString(sum[:8])
}

func goIndexIsKey(s string) bool {
	if len(s) != 16 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

// goIndexCoordinate maps a record to a change: a valid module path at a
// tagged version.
func goIndexCoordinate(e goIndexEntry) (Coordinate, bool) {
	if !goIndexModulePath(e.path) || !goIndexTagged(e.version) {
		return Coordinate{}, false
	}
	return Coordinate{Name: e.path, Version: e.version}, true
}

// goIndexTagged reports whether v is a module version a module's @v/list
// names: a valid version that is not a pseudo-version, case-escapable.
func goIndexTagged(v string) bool {
	scheme, _ := versions.For("go")
	parsed, err := scheme.Parse(v)
	if err != nil || versions.IsPseudoVersion(parsed) || len(v) > goIndexMaxVersion {
		return false
	}
	_, err = locate.GoEscapePath(v)
	return err == nil
}

// goIndexModulePath reports whether p is a module path the protocol can
// carry (golang.org/x/mod's CheckPath, less its reserved-name rules):
// slash-separated elements of ASCII letters, digits and "-._~", none empty,
// none starting or ending with a dot; the first a lower-case domain-like
// name with a dot, not starting with a dash.
func goIndexModulePath(p string) bool {
	if p == "" || len(p) > goIndexMaxPath {
		return false
	}
	for i, el := range strings.Split(p, "/") {
		if el == "" || el[0] == '.' || el[len(el)-1] == '.' {
			return false
		}
		for j := 0; j < len(el); j++ {
			c := el[j]
			lower := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.'
			if i == 0 && !lower {
				return false
			}
			if !lower && !(c >= 'A' && c <= 'Z' || c == '_' || c == '~') {
				return false
			}
		}
		if i == 0 && (!strings.Contains(el, ".") || el[0] == '-') {
			return false
		}
	}
	_, err := locate.GoEscapePath(p)
	return err == nil
}

// remember keeps the versions a batch announced, for Releases, and stores
// them (best effort: a lost file costs only the versions @v/list does not
// list yet, as it would have without it).
func (f *goIndexFeed) remember(items []Coordinate) {
	m := make(map[string][]string, len(items))
	for _, c := range items {
		m[c.Name] = append(m[c.Name], c.Version)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loadLocked()
	f.older, f.recent = f.recent, m
	_ = f.files.writeJSON(goIndexAnnounced, goIndexAnnouncements{Recent: f.recent, Older: f.older})
}

// loadLocked reads the stored announcements once, after a restart. Entries
// that are not module paths and versions are left out.
func (f *goIndexFeed) loadLocked() {
	if f.loaded || f.files.dir == "" {
		return
	}
	f.loaded = true
	var a goIndexAnnouncements
	if f.files.readJSON(goIndexAnnounced, 4<<20, &a) != nil {
		return
	}
	clean := func(m map[string][]string) map[string][]string {
		out := map[string][]string{}
		for mod, vs := range m {
			if !goIndexModulePath(mod) {
				continue
			}
			for _, v := range vs {
				if cleanName(v) && len(v) <= 256 && !strings.ContainsAny(v, "/ ") {
					out[mod] = append(out[mod], v)
				}
			}
		}
		return out
	}
	f.recent, f.older = clean(a.Recent), clean(a.Older)
}

// announced returns the versions the last two batches announced for a module.
func (f *goIndexFeed) announced(module string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loadLocked()
	return append(append([]string(nil), f.recent[module]...), f.older[module]...)
}

// Releases reads the module's version list through the gated pipeline.
func (f *goIndexFeed) Releases(ctx context.Context, module string) ([]Release, error) {
	if !goIndexModulePath(module) {
		return nil, Permanent(fmt.Errorf("%q is not a module path", truncate(module, 600)))
	}
	esc, err := locate.GoEscapePath(module)
	if err != nil {
		return nil, Permanent(err)
	}
	body, err := f.k.read(ctx, "/"+esc+"/@v/list", "", goIndexMaxList)
	if err != nil {
		return nil, err
	}
	listed, err := goIndexParseList(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the version list of %s: %w", module, err))
	}
	have := make(map[string]bool, len(listed))
	for _, v := range listed {
		have[v] = true
	}
	for _, v := range f.announced(module) {
		if !have[v] {
			have[v] = true
			listed = append(listed, v)
		}
	}
	rels := make([]Release, 0, len(listed))
	for _, v := range listed {
		arts, err := f.k.locate(ctx, lockfiles.Dependency{Name: module, Version: v}, nil)
		if err != nil {
			continue // the Go locator reads nothing: an error is the version's own
		}
		rels = append(rels, Release{Version: v, Artifacts: arts})
	}
	orderReleases("go", rels)
	return rels, nil
}

// goIndexParseList reads a module's @v/list: one version per line (the go
// command reads the first field of each). Pseudo-versions and lines that are
// not versions are left out, each version once; a list none of whose lines
// is a version is an error, an empty list is none.
func goIndexParseList(body []byte) ([]string, error) {
	scheme, _ := versions.For("go")
	var out []string
	seen := map[string]bool{}
	lines, valid := 0, 0
	for _, line := range bytes.Split(body, []byte("\n")) {
		fields := strings.Fields(string(line))
		if len(fields) == 0 {
			continue
		}
		if lines++; lines > goIndexMaxVersions {
			return nil, fmt.Errorf("more than %d lines", goIndexMaxVersions)
		}
		v := fields[0]
		if _, err := scheme.Parse(v); err != nil {
			continue
		}
		valid++
		if goIndexTagged(v) && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if lines > 0 && valid == 0 {
		return nil, fmt.Errorf("none of its %d lines is a version", lines)
	}
	return out, nil
}
