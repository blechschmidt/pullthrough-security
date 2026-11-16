package fullmirror

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/cpan"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// cpan follows a CPAN mirror's RECENT files (File::Rsync::Mirror::Recent).
//
// RECENT-1h.json lists the mirror's events of the last hour — {epoch, path,
// type "new"|"delete"}, newest first, epochs unique — and is merged into
// RECENT-6h, -1d, -1W, -1M, -1Q, -1Y and -Z. Changes polls the hour file; when
// the cursor's epoch is older than its minmax.min (events the cursor has not
// seen were merged away), it also reads the next longer interval file, and so
// on until one reaches back to the cursor; an interval file the mirror does
// not have is skipped. The Z file, everything, is never read: a cursor older
// than the longest other interval, or one whose file is past the read bound
// (RECENT-1Y.json is 72.6 MB on cpan.metacpan.org), is reported invalid and
// the mirror enumerated again. A changed dirtymark means the mirror's history
// was rebuilt: the cursor is invalid. The cursor is the epoch of the last event dealt with, as the file
// spells it (compared as an exact decimal), and the dirtymark.
//
// An event names a distribution when its path is an archive in an author
// directory, "authors/id/<A>/<AB>/<AUTHOR>/[<subdir>/…]<Dist>-<Version>.<ext>"
// (cpan.ParseDistFilename, the backend's own rule): the change
// "<AUTHOR>[/<subdir>…]/<Dist>"@<Version>, Deleted for a "delete". CHECKSUMS,
// .meta and .readme files, the indices and the modules/ files are not changes.
// PAUSE rewrites an author directory's CHECKSUMS minutes after an upload
// appears (4 to 45 minutes in the recorded files), and Releases lists versions
// from CHECKSUMS: so an upload is reported once a later event shows its
// directory's CHECKSUMS rewritten, or once it is cpanHold old. Until then the
// batch stops before it (the events after it wait too, as the cursor is one
// epoch).
//
// Names are "<AUTHOR>/<Dist>" (CPAN namespaces distributions by the PAUSE id
// that uploaded them; a release in a subdirectory of the author's directory is
// "<AUTHOR>/<subdir>/<Dist>"): include patterns match that, ".*/Moose".
//
// Bootstrap lists every distribution modules/02packages.details.txt.gz
// indexes (read through the proxy, as clients read it) by name, and continues
// from cpanHold before the hour file's newest event: an upload of that time
// may not be indexed yet.
//
// Releases reads the author directory's CHECKSUMS through the proxy and lists
// the distribution's archives in it, with their sizes and upload days; each
// file's path comes from repos/locate's CPAN locator. Releases are ordered by
// upload day. CPAN has no yanking: a deleted file is gone from CHECKSUMS.
//
// The feed option "url" is the directory holding the RECENT files; by default
// the upstream's own root, where every full CPAN mirror (cpan.metacpan.org,
// www.cpan.org, an rsync mirror of either) keeps them. minicpan, Pinto and
// Artifactory or Nexus repositories have no RECENT files: such an upstream
// needs "url" naming a full mirror.

const cpanFeedVersion = 1

// Bounds and waits of the cpan feed.
const (
	// cpanMaxPackages bounds 02packages.details.txt.gz as served, and
	// cpanMaxPackagesText its uncompressed text.
	cpanMaxPackages     = 64 << 20
	cpanMaxPackagesText = 1 << 30
	// cpanMaxChecksums bounds a CHECKSUMS file (the backend's own bound).
	cpanMaxChecksums = 64 << 20
	// cpanPage is how many names one Bootstrap batch carries, and
	// cpanMaxItems how many changes one Changes batch does.
	cpanPage     = 50_000
	cpanMaxItems = 50_000
	// cpanMaxEvents bounds the events of one RECENT file.
	cpanMaxEvents = 2_000_000
	// cpanHold is how long an upload waits for its directory's CHECKSUMS to
	// be rewritten before it is reported anyway.
	cpanHold = 2 * time.Hour
	// cpanMaxSubdirs bounds the subdirectories of an author directory a
	// distribution may be in.
	cpanMaxSubdirs = 4
)

// cpanIntervals are the RECENT files' intervals when the hour file does not
// list them.
var cpanIntervals = []string{"1h", "6h", "1d", "1W", "1M", "1Q", "1Y", "Z"}

type cpanFeed struct {
	k kit
	// feed is the directory holding the RECENT files.
	feed     *url.URL
	hold     time.Duration
	page     int
	maxItems int
}

func cpanNewFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	feed := k.upstream
	if opts["url"] != "" {
		if feed, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
	}
	return &cpanFeed{k: k, feed: feed, hold: cpanHold, page: cpanPage, maxItems: cpanMaxItems}, nil
}

func init() { Register("cpan", cpanNewFeed) }

// cpanCursor is the cpan feed's position.
type cpanCursor struct {
	Format string `json:"format"`
	// Epoch is the epoch of the last event dealt with, as the RECENT file
	// spells it; Dirtymark the files' dirtymark then.
	Epoch     string `json:"epoch"`
	Dirtymark string `json:"dirtymark"`
	// Listing is set while Bootstrap lists the distributions; After is the
	// last name listed.
	Listing bool   `json:"listing,omitempty"`
	After   string `json:"after,omitempty"`
}

func (c *cpanCursor) cursorFormat() string { return c.Format }

func (f *cpanFeed) format() string { return cursorFormat("cpan", cpanFeedVersion) }

func (f *cpanFeed) decode(cursor string, c *cpanCursor) error {
	if err := decodeCursor(cursor, f.format(), c); err != nil {
		return err
	}
	if !cpanDecimal(c.Epoch) || (c.Dirtymark != "" && !cpanDecimal(c.Dirtymark)) {
		return fmt.Errorf("%w: the cpan cursor names no epoch", ErrCursorInvalid)
	}
	if c.After != "" {
		if _, _, ok := cpanParseName(c.After); !ok || !c.Listing {
			return fmt.Errorf("%w: the cpan cursor names no distribution to continue after", ErrCursorInvalid)
		}
	}
	return nil
}

// Bootstrap lists every indexed distribution, then follows the RECENT files
// from shortly before the listing began.
func (f *cpanFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	var c cpanCursor
	if cursor == "" {
		hour, err := f.recent(ctx, "1h")
		if err != nil {
			return Batch{}, err
		}
		newest := hour.newest()
		if newest == "" {
			return Batch{}, Permanent(fmt.Errorf("the CPAN RECENT-1h file states no epoch"))
		}
		c = cpanCursor{Format: f.format(), Epoch: cpanEpochMinus(newest, f.hold), Dirtymark: hour.dirtymark, Listing: true}
	} else if err := f.decode(cursor, &c); err != nil {
		return Batch{}, err
	} else if !c.Listing {
		return Batch{}, fmt.Errorf("%w: the cpan cursor does not continue a listing", ErrCursorInvalid)
	}
	body, err := f.k.read(ctx, "/modules/02packages.details.txt.gz", "", cpanMaxPackages)
	if err != nil {
		return Batch{}, fmt.Errorf("listing the CPAN distributions: %w", err)
	}
	all, err := cpanParsePackages(body)
	if err != nil {
		return Batch{}, Permanent(fmt.Errorf("listing the CPAN distributions: 02packages.details.txt.gz: %w", err))
	}
	i := 0
	if c.After != "" {
		i = sort.SearchStrings(all, c.After)
		if i < len(all) && all[i] == c.After {
			i++
		}
	}
	page, _, more := pageItems(all, i, f.page)
	b := Batch{Head: c.Epoch}
	for _, n := range page {
		b.Items = append(b.Items, Coordinate{Name: n})
	}
	next := cpanCursor{Format: f.format(), Epoch: c.Epoch, Dirtymark: c.Dirtymark}
	if more {
		next.Listing, next.After = true, page[len(page)-1]
		b.More = true
	}
	b.Next = encodeCursor(&next)
	return b, nil
}

// Changes reads the events after the cursor's epoch.
func (f *cpanFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	var c cpanCursor
	if err := f.decode(cursor, &c); err != nil {
		return Batch{}, err
	}
	if c.Listing {
		return Batch{}, fmt.Errorf("%w: the cpan cursor continues a listing", ErrCursorInvalid)
	}
	hour, err := f.recent(ctx, "1h")
	if err != nil {
		return Batch{}, err
	}
	if hour.dirtymark != c.Dirtymark {
		return Batch{}, fmt.Errorf("%w: the CPAN mirror's dirtymark changed from %q to %q (its history was rebuilt)", ErrCursorInvalid, c.Dirtymark, hour.dirtymark)
	}
	files := []cpanRecent{hour}
	if !hour.covers(c.Epoch) {
		covered := false
		for _, iv := range hour.intervals() {
			r, err := f.recent(ctx, iv)
			if errors.Is(err, cpanErrMissing) {
				continue // a mirror without this interval's file
			}
			if errors.Is(err, errTooLarge) {
				break // past the read bound: enumerate again instead
			}
			if err != nil {
				return Batch{}, err
			}
			if r.dirtymark != c.Dirtymark {
				return Batch{}, fmt.Errorf("%w: the CPAN mirror's dirtymark changed from %q to %q (its history was rebuilt)", ErrCursorInvalid, c.Dirtymark, r.dirtymark)
			}
			// The longer file must reach the shorter one: a file that is
			// behind (a mirror or a cache serving an older copy) would
			// leave a gap of events neither holds, and the cursor would
			// move past them. Asked again later, when it has caught up.
			if prev := files[len(files)-1]; prev.min != "" && cpanCompareEpochs(r.newest(), prev.min) < 0 {
				return Batch{}, fmt.Errorf("RECENT-%s.json ends at epoch %s, before the shorter file's oldest event at %s: the events between them are in neither (the mirror's longer file is behind); retried", iv, r.newest(), prev.min)
			}
			files = append(files, r)
			if r.covers(c.Epoch) {
				covered = true
				break
			}
		}
		if !covered {
			return Batch{}, fmt.Errorf("%w: no RECENT file the feed reads reaches back to epoch %s", ErrCursorInvalid, c.Epoch)
		}
	}
	events := cpanMerge(files, c.Epoch)
	newest := hour.newest()
	if len(events) > 0 && cpanCompareEpochs(events[len(events)-1].epoch, newest) > 0 {
		newest = events[len(events)-1].epoch
	}
	// When each author directory's CHECKSUMS was last rewritten.
	rewritten := map[string]string{}
	for _, e := range events {
		if dir, ok := cpanChecksumsDir(e.path); ok && e.typ == "new" && cpanCompareEpochs(e.epoch, rewritten[dir]) > 0 {
			rewritten[dir] = e.epoch
		}
	}
	b := Batch{Head: newest, HeadTime: cpanEpochTime(newest)}
	last := c.Epoch
	stopped := len(events)
	for i, e := range events {
		co, dir, ok := cpanEventCoordinate(e)
		if ok && !co.Deleted {
			ready := rewritten[dir] != "" && cpanCompareEpochs(rewritten[dir], e.epoch) > 0
			if !ready && cpanAge(newest, e.epoch) < f.hold {
				stopped = i // wait for the directory's CHECKSUMS
				break
			}
		}
		if ok {
			if len(b.Items) >= f.maxItems {
				stopped, b.More = i, true
				break
			}
			b.Items = append(b.Items, co)
		}
		last = e.epoch
	}
	for _, e := range events[stopped:] {
		if _, _, ok := cpanEventCoordinate(e); ok {
			b.Lag++
		}
	}
	b.LagKnown = true
	b.CursorTime = cpanEpochTime(last)
	b.Next = encodeCursor(&cpanCursor{Format: f.format(), Epoch: last, Dirtymark: c.Dirtymark})
	return b, nil
}

// cpanRecent is one RECENT file.
type cpanRecent struct {
	aggregator []string
	dirtymark  string
	// min and max are minmax's: the oldest and newest epoch the file holds
	// ("" when it states none).
	min, max string
	events   []cpanEvent
}

// cpanEvent is one event of a RECENT file.
type cpanEvent struct {
	epoch string
	path  string
	typ   string
}

// covers reports whether the file holds every event after epoch: its oldest
// event is not newer than epoch.
func (r cpanRecent) covers(epoch string) bool {
	return r.min != "" && cpanCompareEpochs(epoch, r.min) >= 0
}

// newest is the newest epoch the file states.
func (r cpanRecent) newest() string {
	n := r.max
	for _, e := range r.events {
		if cpanCompareEpochs(e.epoch, n) > 0 {
			n = e.epoch
		}
	}
	return n
}

// intervals are the longer intervals to read after the hour file, without the
// Z file.
func (r cpanRecent) intervals() []string {
	list := r.aggregator
	if len(list) == 0 {
		list = cpanIntervals
	}
	var out []string
	for _, iv := range list {
		if iv != "1h" && iv != "Z" && cpanInterval.MatchString(iv) {
			out = append(out, iv)
		}
	}
	return out
}

// cpanInterval is an interval a RECENT file can be named for.
var cpanInterval = regexp.MustCompile(`^[0-9]{1,4}[smhdWMQY]$`)

// cpanErrMissing marks a RECENT file the mirror does not have.
var cpanErrMissing = errors.New("the mirror has no such RECENT file")

// recent reads the RECENT file of an interval ("1h").
func (f *cpanFeed) recent(ctx context.Context, interval string) (cpanRecent, error) {
	name := "RECENT-" + interval + ".json"
	body, resp, err := f.k.get(ctx, join(f.feed, name), nil, maxFeedPage)
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone) {
			return cpanRecent{}, Permanent(fmt.Errorf("reading the CPAN %s: %w (%w)", name, err, cpanErrMissing))
		}
		return cpanRecent{}, fmt.Errorf("reading the CPAN %s: %w", name, err)
	}
	r, err := cpanParseRecent(body)
	if err != nil {
		return cpanRecent{}, Permanent(fmt.Errorf("reading the CPAN %s: %w", name, err))
	}
	return r, nil
}

// cpanParseRecent reads a RECENT file (its JSON serialisation).
func cpanParseRecent(body []byte) (cpanRecent, error) {
	var doc struct {
		Meta *struct {
			Aggregator []string    `json:"aggregator"`
			Dirtymark  json.Number `json:"dirtymark"`
			Minmax     struct {
				Max json.Number `json:"max"`
				Min json.Number `json:"min"`
			} `json:"minmax"`
		} `json:"meta"`
		Recent []struct {
			Epoch json.Number `json:"epoch"`
			Path  string      `json:"path"`
			Type  string      `json:"type"`
		} `json:"recent"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return cpanRecent{}, fmt.Errorf("not the JSON document expected: %w", err)
	}
	if doc.Meta == nil || doc.Recent == nil {
		return cpanRecent{}, fmt.Errorf("it has no meta or no recent events")
	}
	if len(doc.Recent) > cpanMaxEvents {
		return cpanRecent{}, fmt.Errorf("it lists %d events; at most %d are read", len(doc.Recent), cpanMaxEvents)
	}
	r := cpanRecent{dirtymark: doc.Meta.Dirtymark.String()}
	if r.dirtymark != "" && !cpanDecimal(r.dirtymark) {
		return cpanRecent{}, fmt.Errorf("dirtymark %q is not an epoch", truncate(r.dirtymark, 64))
	}
	if len(doc.Meta.Aggregator) > 16 {
		return cpanRecent{}, fmt.Errorf("it names %d intervals", len(doc.Meta.Aggregator))
	}
	r.aggregator = doc.Meta.Aggregator
	if m := doc.Meta.Minmax.Min.String(); cpanDecimal(m) {
		r.min = m
	}
	if m := doc.Meta.Minmax.Max.String(); cpanDecimal(m) {
		r.max = m
	}
	oldest := ""
	for _, e := range doc.Recent {
		ep := e.Epoch.String()
		if !cpanDecimal(ep) || (e.Type != "new" && e.Type != "delete") || !cleanName(e.Path) {
			continue
		}
		r.events = append(r.events, cpanEvent{epoch: ep, path: e.Path, typ: e.Type})
		if oldest == "" || cpanCompareEpochs(ep, oldest) < 0 {
			oldest = ep
		}
	}
	// A file that states no minmax spans its events.
	if r.min == "" {
		r.min = oldest
	}
	return r, nil
}

// cpanMerge collects the files' events after epoch, each once, oldest first.
func cpanMerge(files []cpanRecent, epoch string) []cpanEvent {
	seen := map[cpanEvent]bool{}
	var out []cpanEvent
	for _, r := range files {
		for _, e := range r.events {
			if cpanCompareEpochs(e.epoch, epoch) > 0 && !seen[e] {
				seen[e] = true
				out = append(out, e)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return cpanCompareEpochs(out[i].epoch, out[j].epoch) < 0 })
	return out
}

// cpanAuthorRel strips the author tree's root from a RECENT path: "authors/id/"
// in a mirror's root RECENT files, "id/" in the authors/ directory's.
func cpanAuthorRel(p string) (string, bool) {
	if rest, ok := strings.CutPrefix(p, "authors/id/"); ok {
		return rest, true
	}
	return strings.CutPrefix(p, "id/")
}

// cpanEventCoordinate maps an event to the distribution release it names, and
// that release's directory below authors/id/.
func cpanEventCoordinate(e cpanEvent) (Coordinate, string, bool) {
	rel, ok := cpanAuthorRel(e.path)
	if !ok {
		return Coordinate{}, "", false
	}
	name, version, dir, ok := cpanDistPath(rel)
	if !ok {
		return Coordinate{}, "", false
	}
	return Coordinate{Name: name, Version: version, Deleted: e.typ == "delete"}, dir, true
}

// cpanChecksumsDir reports whether a RECENT path is an author directory's
// CHECKSUMS, and that directory below authors/id/.
func cpanChecksumsDir(p string) (string, bool) {
	rel, ok := cpanAuthorRel(p)
	if !ok {
		return "", false
	}
	dir, ok := strings.CutSuffix(rel, "/CHECKSUMS")
	if !ok {
		return "", false
	}
	if _, ok := cpanDirAuthor(dir); !ok {
		return "", false
	}
	return dir, true
}

// cpanDirAuthor checks a directory below authors/id/ — "<A>/<AB>/<AUTHOR>"
// and up to cpanMaxSubdirs subdirectories — and returns its PAUSE id.
func cpanDirAuthor(dir string) (string, bool) {
	parts := strings.Split(dir, "/")
	if len(parts) < 3 || len(parts) > 3+cpanMaxSubdirs {
		return "", false
	}
	author := parts[2]
	if !cpanIsAuthor(author) || parts[0] != author[:1] || parts[1] != author[:2] {
		return "", false
	}
	for _, s := range parts[3:] {
		if !cpanIsSegment(s) {
			return "", false
		}
	}
	return author, true
}

// cpanDistPath reads a distribution archive's path below authors/id/:
// "<A>/<AB>/<AUTHOR>/[<subdir>/…]<file>". It returns the release's name
// ("<AUTHOR>[/<subdir>…]/<Dist>"), version and directory.
func cpanDistPath(rel string) (name, version, dir string, ok bool) {
	i := strings.LastIndexByte(rel, '/')
	if i < 0 {
		return "", "", "", false
	}
	dir, file := rel[:i], rel[i+1:]
	author, ok := cpanDirAuthor(dir)
	if !ok || !cpanIsSegment(file) {
		return "", "", "", false
	}
	dist, version, ok := cpan.ParseDistFilename(file)
	if !ok || !cpanIsDist(dist) || !cpanIsVersion(version) {
		return "", "", "", false
	}
	name = author + "/" + dist
	if sub := strings.Join(strings.Split(dir, "/")[3:], "/"); sub != "" {
		name = author + "/" + sub + "/" + dist
	}
	return name, version, dir, true
}

// cpanParseName reads a release name, "<AUTHOR>[/<subdir>…]/<Dist>": its
// directory below authors/id/ and the distribution.
func cpanParseName(name string) (dir, dist string, ok bool) {
	parts := strings.Split(name, "/")
	if len(parts) < 2 || len(parts) > 2+cpanMaxSubdirs {
		return "", "", false
	}
	author, dist := parts[0], parts[len(parts)-1]
	if !cpanIsAuthor(author) || !cpanIsDist(dist) {
		return "", "", false
	}
	dir = author[:1] + "/" + author[:2] + "/" + author
	for _, s := range parts[1 : len(parts)-1] {
		if !cpanIsSegment(s) {
			return "", "", false
		}
		dir += "/" + s
	}
	return dir, dist, true
}

// cpanIsAuthor reports whether s is a PAUSE id: an upper-case letter, then
// upper-case letters, digits and "-", 2 to 32 characters.
func cpanIsAuthor(s string) bool {
	if len(s) < 2 || len(s) > 32 || s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// cpanIsSegment reports whether s can be one segment of a path in an author
// directory: no separator, dot segment, space or character a URL reads
// differently.
func cpanIsSegment(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 255 || !cleanName(s) {
		return false
	}
	return !strings.ContainsAny(s, "/\\ %?#\"'<>")
}

// cpanIsDist reports whether s is a distribution name the feed carries.
func cpanIsDist(s string) bool { return cpanIsSegment(s) && len(s) <= 200 }

// cpanIsVersion reports whether s is a distribution version: letters, digits,
// ".", "_", "-" and "+", starting with a digit or "v" (cpan.ParseDistFilename's
// boundary).
func cpanIsVersion(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == '+') {
			return false
		}
	}
	return true
}

// cpanParsePackages reads 02packages.details.txt (gzip-compressed, as the
// mirror serves it, or already decompressed): header lines up to a blank
// line, then "<package> <version> <A>/<AB>/<AUTHOR>/<file>" lines. It returns
// the names of the distributions they name, sorted, each once.
func cpanParsePackages(body []byte) ([]string, error) {
	var r io.Reader = bytes.NewReader(body)
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("not a gzip file: %w", err)
		}
		r = zr
	}
	lr := &io.LimitedReader{R: r, N: cpanMaxPackagesText + 1}
	sc := bufio.NewScanner(lr)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	header, sawHeader := true, false
	seen := map[string]bool{}
	var out []string
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if header {
			if strings.TrimSpace(line) == "" {
				if !sawHeader {
					return nil, fmt.Errorf("it has no header")
				}
				header = false
				continue
			}
			k, _, ok := strings.Cut(line, ":")
			if !ok || k == "" || strings.ContainsAny(k, " \t") {
				return nil, fmt.Errorf("header line %q is not \"Name: value\"", truncate(line, 64))
			}
			sawHeader = true
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		name, _, _, ok := cpanDistPath(fields[2])
		if ok && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if lr.N <= 0 {
		return nil, fmt.Errorf("%w (%d bytes)", errTooLarge, int64(cpanMaxPackagesText))
	}
	if header {
		return nil, fmt.Errorf("it ends in its header")
	}
	sort.Strings(out)
	return out, nil
}

// Releases lists a distribution's archives in its author directory's
// CHECKSUMS, read through the proxy.
func (f *cpanFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	dir, dist, ok := cpanParseName(name)
	if !ok {
		return nil, Permanent(fmt.Errorf("%q is not a CPAN distribution name (AUTHOR/Distribution)", name))
	}
	body, err := f.k.read(ctx, "/authors/id/"+dir+"/CHECKSUMS", "", cpanMaxChecksums)
	if err != nil {
		return nil, err
	}
	entries, err := cpan.ListChecksums(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the CHECKSUMS of authors/id/%s: %w", dir, err))
	}
	var rels []Release
	index := map[string]int{}
	for _, e := range entries {
		if e.IsDir || !cpanIsSegment(e.File) {
			continue
		}
		d, version, ok := cpan.ParseDistFilename(e.File)
		if !ok || d != dist || !cpanIsVersion(version) {
			continue
		}
		arts, err := f.k.locate(ctx, lockfiles.Dependency{Name: dist, Version: version, ID: dir + "/" + e.File}, nil)
		if err != nil {
			if IsPermanent(err) {
				continue
			}
			return nil, err
		}
		for i := range arts {
			arts[i].Size = e.Size
		}
		i, seen := index[version]
		if !seen {
			index[version] = len(rels)
			rels = append(rels, Release{Version: version, Published: e.Mtime})
			i = len(rels) - 1
		}
		r := &rels[i]
		r.Artifacts = append(r.Artifacts, arts...)
		if !e.Mtime.IsZero() && (r.Published.IsZero() || e.Mtime.Before(r.Published)) {
			r.Published = e.Mtime
		}
	}
	if len(rels) == 0 {
		return nil, Permanent(fmt.Errorf("the CHECKSUMS of authors/id/%s list no release of %s: not found", dir, dist))
	}
	// Oldest first by upload day; CHECKSUMS's (file name) order within a day.
	sort.SliceStable(rels, func(i, j int) bool { return rels[i].Published.Before(rels[j].Published) })
	return rels, nil
}

// cpanDecimal reports whether s is an epoch as the RECENT files write it:
// decimal digits with an optional fraction.
func cpanDecimal(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	whole, frac, dot := strings.Cut(s, ".")
	if !cpanDigits(whole) || len(whole) > 20 {
		return false
	}
	return !dot || (cpanDigits(frac) && len(frac) <= 19)
}

func cpanDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// cpanCompareEpochs orders two epochs exactly, as decimal numbers; "" is
// older than every epoch.
func cpanCompareEpochs(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return -1
	case b == "":
		return 1
	}
	aw, af, _ := strings.Cut(a, ".")
	bw, bf, _ := strings.Cut(b, ".")
	aw, bw = strings.TrimLeft(aw, "0"), strings.TrimLeft(bw, "0")
	if len(aw) != len(bw) {
		if len(aw) < len(bw) {
			return -1
		}
		return 1
	}
	if c := strings.Compare(aw, bw); c != 0 {
		return c
	}
	return strings.Compare(strings.TrimRight(af, "0"), strings.TrimRight(bf, "0"))
}

// cpanEpochSeconds reads an epoch's value, approximately.
func cpanEpochSeconds(s string) float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(v, 0) || math.IsNaN(v) {
		return 0
	}
	return v
}

// cpanEpochTime is an epoch as a time, exact to the nanosecond; zero for none.
func cpanEpochTime(s string) time.Time {
	if !cpanDecimal(s) {
		return time.Time{}
	}
	whole, frac, _ := strings.Cut(s, ".")
	sec, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || sec <= 0 || sec > 1<<40 {
		return time.Time{}
	}
	frac = (frac + "000000000")[:9]
	nsec, _ := strconv.ParseInt(frac, 10, 64)
	return time.Unix(sec, nsec).UTC()
}

// cpanAge is how long before newest epoch was.
func cpanAge(newest, epoch string) time.Duration {
	d := cpanEpochSeconds(newest) - cpanEpochSeconds(epoch)
	if d <= 0 {
		return 0
	}
	if d > float64(math.MaxInt64/int64(time.Second)) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(d * float64(time.Second))
}

// cpanEpochMinus is the epoch d before s, in s's spelling (its fraction
// kept), not before 0.
func cpanEpochMinus(s string, d time.Duration) string {
	whole, frac, dot := strings.Cut(s, ".")
	n, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return s
	}
	n -= int64(d / time.Second)
	if n < 0 {
		return "0"
	}
	out := strconv.FormatInt(n, 10)
	if dot {
		out += "." + frac
	}
	return out
}
