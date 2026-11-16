package fullmirror

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/rubygems"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// rubygems follows the compact index's /versions file.
//
// /versions names every gem once — "name v1,v2,… md5" after a "created_at:"
// line and "---" — and is appended to as gems are pushed and yanked: one line
// per change, naming the versions it adds and, prefixed "-", the ones it
// yanks. At the start of each month rubygems.org rewrites it (yanked versions
// removed, created_at renewed). The follower keeps a copy in Env.Dir and asks
// for what follows it with a Range request from the copy's last byte (so the
// range is never past the end, which rubygems.org answers with the whole
// file), with If-None-Match (a 304 when nothing changed) and without
// compression (the CDN ignores Range for a compressed answer). The copy and
// the tail must hash to the file's Repr-Digest (SHA-256) — or, from a server
// that states none, the file must still start with the copy's first line —
// and the tail must continue the copy at a line boundary; the tail is then
// appended to the copy and every version an appended line adds is reported,
// by gem and version with the platform dropped (a platform gem is one more
// file of its version). Anything else — a digest that does not match, a torn
// tail, another first line, a server that answers with the whole file — means
// the file was rewritten: the whole file is fetched (its digest checked) and
// diffed against the copy, and every version it holds that the copy did not is
// reported. The cursor names the copy — a generation, a length and the SHA-256
// of that many bytes — and a copy that does not match it is not trusted.
//
// Bootstrap fetches the whole file, keeps it as the copy and lists every gem
// it names, by name only; Changes continues from that copy.
//
// Releases reads the gem's /info document through the gated pipeline (what
// Bundler reads), groups its lines by version — "1.16.0" and
// "1.16.0-x86_64-linux" are two files of one version — and takes each file's
// path, "/gems/<name>-<version>[-<platform>].gem", from repos/locate's
// RubyGems locator. A file the backend would read back as another gem's (a
// gem name with "-" before a digit) is left out. Published is the earliest
// created_at of a version's files; /info lists no yanked version, so none is
// marked Yanked.
//
// The activity API (/api/v1/activity/just_updated.json) is not used: it lists
// the 50 gems updated last and is cached for a minute, so between two polls it
// can miss pushes the tail of /versions holds, and a poll that finds nothing
// new costs a 304 either way.
//
// Every upstream is followed at its own /versions (the layout the backend
// serves); the feed option "url" names another base. A server that ignores
// Range answers with the whole file on every poll, which is diffed: correct,
// at the price of the file's size per poll; one that serves no compact index
// cannot be followed.

const rubygemsFeedVersion = 1

const (
	// rubygemsCopyPrefix names the copies of /versions in Env.Dir, one per
	// generation; rubygemsDownload is where a whole file is written first.
	rubygemsCopyPrefix = "rubygems-versions-"
	rubygemsDownload   = "rubygems-download"
	// rubygemsNamesPerBatch is how many gems one Bootstrap batch lists.
	rubygemsNamesPerBatch = 50_000
	// rubygemsMaxItems is how many versions one Changes batch reports
	// before it reports the gems by name.
	rubygemsMaxItems = 50_000
	// rubygemsMaxFile bounds /versions (24 MB on rubygems.org in November
	// 2026), rubygemsMaxLine one of its lines and rubygemsMaxInfo an /info
	// document (the backend's own bound).
	rubygemsMaxFile = maxMetadataDoc
	rubygemsMaxLine = 16 << 20
	rubygemsMaxInfo = 16 << 20
)

type rubygemsFeed struct {
	k kit
	// base is where the compact index lives: /versions is beneath it.
	base  *url.URL
	files files
	// page is how many gems a Bootstrap batch lists, maxItems how many
	// versions a Changes batch reports by version.
	page, maxItems int
}

func rubygemsNewFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	base := k.upstream
	if opts["url"] != "" {
		if base, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
	}
	return &rubygemsFeed{k: k, base: base, files: files{dir: env.Dir}, page: rubygemsNamesPerBatch, maxItems: rubygemsMaxItems}, nil
}

func init() { Register("rubygems", rubygemsNewFeed) }

// rubygemsCursor is the RubyGems feed's position: the copy of /versions
// dealt with.
type rubygemsCursor struct {
	Format string `json:"format"`
	// Gen names the copy kept in Env.Dir; Size is how much of it has been
	// dealt with and SHA256 the digest of those bytes; Created is the
	// file's created_at, ETag the server's validator for it.
	Gen     string `json:"gen"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Created string `json:"created,omitempty"`
	ETag    string `json:"etag,omitempty"`
	// Listing marks Bootstrap's listing of the copy's gems; Offset is how
	// many it has listed.
	Listing bool `json:"listing,omitempty"`
	Offset  int  `json:"offset,omitempty"`
}

func (c *rubygemsCursor) cursorFormat() string { return c.Format }

func (f *rubygemsFeed) format() string { return cursorFormat("rubygems", rubygemsFeedVersion) }

func (f *rubygemsFeed) cursor(c rubygemsCursor) string {
	c.Format = f.format()
	return encodeCursor(&c)
}

func (f *rubygemsFeed) versionsURL() string { return join(f.base, "versions") }

func rubygemsCopyName(gen string) string { return rubygemsCopyPrefix + gen }

// rubygemsSnapshot is a whole /versions file written to rubygemsDownload.
type rubygemsSnapshot struct {
	gen, sha, created, etag string
	size                    int64
	modified                time.Time
}

func (s rubygemsSnapshot) cursor() rubygemsCursor {
	return rubygemsCursor{Gen: s.gen, Size: s.size, SHA256: s.sha, Created: s.created, ETag: s.etag}
}

// Bootstrap fetches /versions and lists every gem it names.
func (f *rubygemsFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	var c rubygemsCursor
	if cursor == "" {
		snap, err := f.download(ctx)
		if err != nil {
			return Batch{}, err
		}
		if err := f.adopt(snap); err != nil {
			return Batch{}, err
		}
		f.files.pruneKeepingNewest(rubygemsCopyPrefix, 1, rubygemsCopyName(snap.gen))
		c = snap.cursor()
		c.Listing = true
	} else {
		if err := decodeCursor(cursor, f.format(), &c); err != nil {
			return Batch{}, err
		}
		if !c.Listing {
			return Batch{}, fmt.Errorf("%w: the RubyGems cursor does not continue a listing", ErrCursorInvalid)
		}
	}
	var names []string
	seen := map[string]bool{}
	if _, _, err := f.load(c, func(name string, _ []string) {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}); err != nil {
		return Batch{}, err
	}
	page, next, more := pageItems(names, c.Offset, f.page)
	b := Batch{Items: make([]Coordinate, 0, len(page)), More: more, Head: strconv.FormatInt(c.Size, 10)}
	for _, n := range page {
		b.Items = append(b.Items, Coordinate{Name: n})
	}
	nc := c
	if more {
		nc.Offset = next
	} else {
		nc.Listing, nc.Offset = false, 0
	}
	b.Next = f.cursor(nc)
	return b, nil
}

// Changes reads what was appended to /versions after the copy.
func (f *rubygemsFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	var c rubygemsCursor
	if err := decodeCursor(cursor, f.format(), &c); err != nil {
		return Batch{}, err
	}
	if c.Listing {
		return Batch{}, fmt.Errorf("%w: the RubyGems cursor continues a listing", ErrCursorInvalid)
	}
	h, first, err := f.load(c, nil)
	if err != nil {
		return Batch{}, err
	}
	// Copies of other generations — older ones, or one a rewrite left that
	// the engine never moved to — are of no further use.
	f.files.pruneKeepingNewest(rubygemsCopyPrefix, 1, rubygemsCopyName(c.Gen))
	u := f.versionsURL()
	hdr := http.Header{"Range": {fmt.Sprintf("bytes=%d-", c.Size-1)}, "Accept-Encoding": {"identity"}, "Accept": {"text/plain"}}
	if c.ETag != "" {
		hdr.Set("If-None-Match", c.ETag)
	}
	resp, err := f.k.do(ctx, http.MethodGet, u, nil, hdr)
	if err != nil {
		return Batch{}, fmt.Errorf("reading the tail of the compact index: %w", err)
	}
	defer drain(resp.Body)
	switch resp.StatusCode {
	case http.StatusNotModified:
		return Batch{Next: cursor, Head: strconv.FormatInt(c.Size, 10), LagKnown: true}, nil
	case http.StatusPartialContent:
		tail, ok, err := f.tail(ctx, resp, c, h, first)
		if err != nil {
			return Batch{}, err
		}
		if !ok {
			drain(resp.Body)
			snap, err := f.download(ctx)
			if err != nil {
				return Batch{}, err
			}
			return f.rewritten(c, snap)
		}
		if err := f.extend(c, tail); err != nil {
			return Batch{}, fmt.Errorf("extending the copy of the compact index: %w", err)
		}
		next := c
		next.Size += int64(len(tail))
		next.SHA256 = hex.EncodeToString(h.Sum(nil))
		next.ETag = rubygemsETag(resp.Header)
		items, err := f.bound(rubygemsAppended(tail))
		if err != nil {
			return Batch{}, err
		}
		b := Batch{Items: items, Next: f.cursor(next), Head: strconv.FormatInt(next.Size, 10), LagKnown: true}
		if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
			b.HeadTime, b.CursorTime = t, t
		}
		return b, nil
	case http.StatusOK:
		// The server sent the whole file (it ignores Range, or the range
		// was past the end of a file that shrank).
		snap, err := f.store(resp)
		if err != nil {
			return Batch{}, err
		}
		return f.rewritten(c, snap)
	case http.StatusRequestedRangeNotSatisfiable:
		drain(resp.Body)
		snap, err := f.download(ctx)
		if err != nil {
			return Batch{}, err
		}
		return f.rewritten(c, snap)
	}
	return Batch{}, httpStatusError(u, resp)
}

// tail reads a 206 answer to the Range request from the copy's last byte and
// returns what follows the copy, with h advanced over it. ok is false when the
// answer does not continue the copy — another range, a first byte other than
// the copy's last newline, a last line cut short, a digest the copy and the
// tail do not hash to, a first line other than the copy's: the file was
// rewritten.
func (f *rubygemsFeed) tail(ctx context.Context, resp *http.Response, c rubygemsCursor, h hash.Hash, first []byte) ([]byte, bool, error) {
	start, end, total, ok := rubygemsParseContentRange(resp.Header.Get("Content-Range"))
	if !ok || start != c.Size-1 || end != total-1 || end-start+1 > maxFeedPage {
		return nil, false, nil
	}
	body, err := readLimited(resp.Body, end-start+1)
	if err != nil {
		return nil, false, fmt.Errorf("reading the tail of the compact index: %w", err)
	}
	if int64(len(body)) != end-start+1 {
		return nil, false, fmt.Errorf("the tail of the compact index is %d bytes, not the %d its Content-Range states", len(body), end-start+1)
	}
	if body[0] != '\n' {
		return nil, false, nil
	}
	tail := body[1:]
	if len(tail) > 0 && tail[len(tail)-1] != '\n' {
		return nil, false, nil
	}
	if _, err := h.Write(tail); err != nil {
		return nil, false, err
	}
	if want, ok := rubygemsDigest(resp.Header); ok {
		return tail, bytes.Equal(h.Sum(nil), want), nil
	}
	same, err := f.sameStart(ctx, first)
	return tail, same, err
}

// sameStart reports whether the server's /versions still begins with the
// copy's first line (its created_at): what tells a rewrite from an append
// when the server states no digest.
func (f *rubygemsFeed) sameStart(ctx context.Context, first []byte) (bool, error) {
	u := f.versionsURL()
	hdr := http.Header{"Range": {fmt.Sprintf("bytes=0-%d", len(first)-1)}, "Accept-Encoding": {"identity"}}
	resp, err := f.k.do(ctx, http.MethodGet, u, nil, hdr)
	if err != nil {
		return false, fmt.Errorf("reading the start of the compact index: %w", err)
	}
	defer drain(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return false, httpStatusError(u, resp)
	}
	got := make([]byte, len(first))
	if _, err := io.ReadFull(resp.Body, got); err != nil {
		return false, nil
	}
	return bytes.Equal(got, first), nil
}

// extend appends a tail to the copy after its first Size bytes; whatever
// follows them is a tail an earlier poll appended for a batch the engine
// never committed.
func (f *rubygemsFeed) extend(c rubygemsCursor, tail []byte) error {
	if f.files.dir == "" {
		return errValidationOnly
	}
	fh, err := os.OpenFile(f.files.path(rubygemsCopyName(c.Gen)), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if err := fh.Truncate(c.Size); err != nil {
		fh.Close()
		return err
	}
	if _, err := fh.WriteAt(tail, c.Size); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}

// rewritten reports the versions a new /versions file holds that the copy
// did not, and moves the follower to the new file.
func (f *rubygemsFeed) rewritten(c rubygemsCursor, snap rubygemsSnapshot) (Batch, error) {
	old := rubygemsSet{}
	if _, _, err := f.load(c, old.replay); err != nil {
		return Batch{}, err
	}
	fresh, err := f.diff(snap, old)
	if err != nil {
		return Batch{}, err
	}
	if err := f.adopt(snap); err != nil {
		return Batch{}, err
	}
	items, err := f.bound(fresh)
	if err != nil {
		return Batch{}, err
	}
	b := Batch{Items: items, Next: f.cursor(snap.cursor()), Head: strconv.FormatInt(snap.size, 10), LagKnown: true}
	if !snap.modified.IsZero() {
		b.HeadTime, b.CursorTime = snap.modified, snap.modified
	}
	return b, nil
}

// diff lists the versions the downloaded file holds at its end that old does
// not: one coordinate per gem version, the platform dropped, in file order.
func (f *rubygemsFeed) diff(snap rubygemsSnapshot, old rubygemsSet) ([]Coordinate, error) {
	live := rubygemsSet{}
	if err := f.scanDownload(live.replay); err != nil {
		return nil, err
	}
	var out []Coordinate
	reported := map[string]bool{}
	err := f.scanDownload(func(name string, versions []string) {
		for _, v := range versions {
			if strings.HasPrefix(v, "-") {
				continue
			}
			ver, _, ok := rubygemsSplit(v)
			if !ok || !live.has(name, v) || old.has(name, v) || reported[name+" "+ver] {
				continue
			}
			reported[name+" "+ver] = true
			out = append(out, Coordinate{Name: name, Version: ver})
		}
	})
	return out, err
}

// scanDownload reads the gem lines of the downloaded file.
func (f *rubygemsFeed) scanDownload(fn func(name string, versions []string)) error {
	fh, err := os.Open(f.files.path(rubygemsDownload))
	if err != nil {
		return err
	}
	defer fh.Close()
	if err := rubygemsScan(fh, fn); err != nil {
		return Permanent(fmt.Errorf("the compact index: %w", err))
	}
	return nil
}

// bound keeps a batch within the engine's limit: past maxItems versions it
// reports the gems by name; past maxItems gems the follower is too far behind
// and the registry is enumerated again.
func (f *rubygemsFeed) bound(items []Coordinate) ([]Coordinate, error) {
	if len(items) <= f.maxItems {
		return items, nil
	}
	seen := map[string]bool{}
	var out []Coordinate
	for _, c := range items {
		if !seen[c.Name] {
			seen[c.Name] = true
			out = append(out, Coordinate{Name: c.Name})
		}
	}
	if len(out) > f.maxItems {
		return nil, fmt.Errorf("%w: %d gems changed since the stored copy of the compact index; enumerating it again", ErrCursorInvalid, len(out))
	}
	return out, nil
}

// download fetches the whole of /versions into rubygemsDownload.
func (f *rubygemsFeed) download(ctx context.Context) (rubygemsSnapshot, error) {
	u := f.versionsURL()
	resp, err := f.k.do(ctx, http.MethodGet, u, nil, http.Header{"Accept": {"text/plain"}})
	if err != nil {
		return rubygemsSnapshot{}, fmt.Errorf("fetching the compact index: %w", err)
	}
	defer drain(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return rubygemsSnapshot{}, httpStatusError(u, resp)
	}
	return f.store(resp)
}

// store writes a whole /versions body to rubygemsDownload. Its SHA-256 must be
// the digest the server states, when it states one: a body that does not hash
// to it is not kept (a transfer gone wrong, tried again later).
func (f *rubygemsFeed) store(resp *http.Response) (rubygemsSnapshot, error) {
	h := sha256.New()
	head := &rubygemsHead{}
	err := f.files.write(rubygemsDownload, func(w io.Writer) error {
		n, err := io.Copy(io.MultiWriter(w, h, head), io.LimitReader(resp.Body, rubygemsMaxFile+1))
		if err != nil {
			return err
		}
		if n > rubygemsMaxFile {
			return Permanent(fmt.Errorf("%w (%d bytes)", errTooLarge, int64(rubygemsMaxFile)))
		}
		return nil
	})
	if err != nil {
		f.files.remove(rubygemsDownload)
		return rubygemsSnapshot{}, fmt.Errorf("fetching the compact index: %w", err)
	}
	sum := h.Sum(nil)
	if want, ok := rubygemsDigest(resp.Header); ok && !bytes.Equal(sum, want) {
		f.files.remove(rubygemsDownload)
		return rubygemsSnapshot{}, fmt.Errorf("the compact index does not match the digest the server states for it")
	}
	created, _, ok := rubygemsHeader(head.buf)
	if !ok {
		f.files.remove(rubygemsDownload)
		return rubygemsSnapshot{}, Permanent(fmt.Errorf("%s is not a compact index /versions file: it does not start with created_at and \"---\"", f.versionsURL()))
	}
	if head.last != '\n' {
		// A file being written, or a transfer cut short: asked for again.
		f.files.remove(rubygemsDownload)
		return rubygemsSnapshot{}, fmt.Errorf("the compact index ends inside a line")
	}
	snap := rubygemsSnapshot{gen: hex.EncodeToString(sum[:8]), sha: hex.EncodeToString(sum), created: created, etag: rubygemsETag(resp.Header), size: head.n}
	if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		snap.modified = t
	}
	return snap, nil
}

// adopt makes the downloaded file the copy of its generation.
func (f *rubygemsFeed) adopt(snap rubygemsSnapshot) error {
	if f.files.dir == "" {
		return errValidationOnly
	}
	if err := os.Rename(f.files.path(rubygemsDownload), f.files.path(rubygemsCopyName(snap.gen))); err != nil {
		return fmt.Errorf("keeping the copy of the compact index: %w", err)
	}
	return nil
}

// load checks that the copy a cursor names is what the cursor says — its
// first Size bytes hash to SHA256, start with its created_at and end a line —
// calling fn for each gem line of those bytes on the way. It returns the hash
// state after them and the copy's first line. A copy that does not match
// invalidates the cursor.
func (f *rubygemsFeed) load(c rubygemsCursor, fn func(name string, versions []string)) (hash.Hash, []byte, error) {
	if !rubygemsHex(c.Gen, 16) || !rubygemsHex(c.SHA256, 64) || c.Size <= 0 || c.Offset < 0 {
		return nil, nil, fmt.Errorf("%w: the RubyGems cursor names no copy of the compact index", ErrCursorInvalid)
	}
	if f.files.dir == "" {
		return nil, nil, errValidationOnly
	}
	fh, err := os.Open(f.files.path(rubygemsCopyName(c.Gen)))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: the copy of the compact index is not stored (%v)", ErrCursorInvalid, err)
	}
	defer fh.Close()
	if st, err := fh.Stat(); err != nil || st.Size() < c.Size {
		return nil, nil, fmt.Errorf("%w: the stored copy of the compact index is shorter than the cursor", ErrCursorInvalid)
	}
	h := sha256.New()
	head := &rubygemsHead{}
	r := io.TeeReader(io.LimitReader(fh, c.Size), io.MultiWriter(h, head))
	var scanErr error
	if fn != nil {
		scanErr = rubygemsScan(r, fn)
	}
	if _, err := io.Copy(io.Discard, r); err != nil {
		return nil, nil, fmt.Errorf("reading the copy of the compact index: %w", err)
	}
	created, first, ok := rubygemsHeader(head.buf)
	if hex.EncodeToString(h.Sum(nil)) != c.SHA256 || head.n != c.Size || head.last != '\n' || !ok || created != c.Created {
		return nil, nil, fmt.Errorf("%w: the stored copy of the compact index does not match the cursor", ErrCursorInvalid)
	}
	if scanErr != nil {
		return nil, nil, fmt.Errorf("%w: reading the copy of the compact index: %v", ErrCursorInvalid, scanErr)
	}
	return h, first, nil
}

// rubygemsHead keeps the start of what is written through it, its last byte
// and its length.
type rubygemsHead struct {
	buf  []byte
	last byte
	n    int64
}

func (r *rubygemsHead) Write(p []byte) (int, error) {
	if room := 4096 - len(r.buf); room > 0 {
		r.buf = append(r.buf, p[:min(room, len(p))]...)
	}
	if len(p) > 0 {
		r.last = p[len(p)-1]
	}
	r.n += int64(len(p))
	return len(p), nil
}

// rubygemsHeader reads the start of a /versions file: a "created_at: <time>"
// line and "---", or "---" alone. It returns the created_at value and the
// first line, its newline included.
func rubygemsHeader(head []byte) (created string, first []byte, ok bool) {
	line, rest, found := bytes.Cut(head, []byte("\n"))
	if !found {
		return "", nil, false
	}
	first = head[:len(line)+1]
	if string(bytes.TrimSuffix(line, []byte("\r"))) == "---" {
		return "", first, true
	}
	v, found := bytes.CutPrefix(line, []byte("created_at:"))
	if !found {
		return "", nil, false
	}
	created = strings.TrimSpace(string(v))
	if created == "" || len(created) > 64 || !cleanName(created) {
		return "", nil, false
	}
	next, _, found := bytes.Cut(rest, []byte("\n"))
	if !found || string(bytes.TrimSuffix(next, []byte("\r"))) != "---" {
		return "", nil, false
	}
	return created, first, true
}

// rubygemsScan calls fn for every gem line of a /versions file — the lines
// after "---" that read as one; others are skipped.
func rubygemsScan(r io.Reader, fn func(name string, versions []string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), rubygemsMaxLine)
	body := false
	for sc.Scan() {
		line := sc.Text()
		if !body {
			body = strings.TrimSuffix(line, "\r") == "---"
			continue
		}
		if name, versions, ok := rubygemsParseLine(line); ok {
			fn(name, versions)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if !body {
		return errors.New("it has no \"---\" line")
	}
	return nil
}

// rubygemsParseLine reads a line of /versions: "name v1,v2,-v3 md5".
func rubygemsParseLine(line string) (string, []string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || !rubygemsValidName(fields[0]) {
		return "", nil, false
	}
	return fields[0], strings.Split(fields[1], ","), true
}

// rubygemsAppended lists the versions appended lines add: one coordinate per
// gem version in the order the lines came, the platform dropped. A yank
// ("-1.0") is not a change to mirror; a version all of whose files the tail
// added and then yanked is left out.
func rubygemsAppended(tail []byte) []Coordinate {
	type change struct {
		c      Coordinate
		tokens []string
	}
	var changes []*change
	byVersion := map[string]*change{}
	live := map[string]bool{}
	_ = rubygemsScan(io.MultiReader(strings.NewReader("---\n"), bytes.NewReader(tail)), func(name string, versions []string) {
		for _, v := range versions {
			if tok, yank := strings.CutPrefix(v, "-"); yank {
				delete(live, name+" "+tok)
				continue
			}
			ver, _, ok := rubygemsSplit(v)
			if !ok {
				continue
			}
			live[name+" "+v] = true
			ch := byVersion[name+" "+ver]
			if ch == nil {
				ch = &change{c: Coordinate{Name: name, Version: ver}}
				byVersion[name+" "+ver] = ch
				changes = append(changes, ch)
			}
			ch.tokens = append(ch.tokens, v)
		}
	})
	var out []Coordinate
	for _, ch := range changes {
		for _, tok := range ch.tokens {
			if live[ch.c.Name+" "+tok] {
				out = append(out, ch.c)
				break
			}
		}
	}
	return out
}

// rubygemsSet is a set of gem version tokens (a name and a version with its
// platform), by 64 bits of a SHA-256 of each: rubygems.org's 1.9 million fit
// in tens of megabytes. The hash is a cryptographic one because the tokens
// are chosen by whoever publishes a gem: with a fast non-cryptographic hash a
// crafted version could be made to collide with another gem's next version
// and hide it from the diff of a monthly rewrite.
type rubygemsSet map[uint64]struct{}

func rubygemsKey(name, token string) uint64 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write([]byte(token))
	var sum [sha256.Size]byte
	return binary.BigEndian.Uint64(h.Sum(sum[:0]))
}

// replay applies one line: its versions are added, its yanks removed.
func (s rubygemsSet) replay(name string, versions []string) {
	for _, v := range versions {
		if strings.HasPrefix(v, "-") {
			delete(s, rubygemsKey(name, v[1:]))
		} else {
			s[rubygemsKey(name, v)] = struct{}{}
		}
	}
}

func (s rubygemsSet) has(name, token string) bool {
	_, ok := s[rubygemsKey(name, token)]
	return ok
}

// rubygemsSplit splits a version token of /versions or /info into its
// version and platform: "1.16.0-x86_64-linux" is version 1.16.0 for
// x86_64-linux (a RubyGems version has no "-": Gem::Version turns one into
// ".pre."). ok is false for a token that is not one.
func rubygemsSplit(token string) (version, platform string, ok bool) {
	if token == "" || len(token) > 256 {
		return "", "", false
	}
	version, platform, dash := strings.Cut(token, "-")
	if version == "" || version[0] < '0' || version[0] > '9' || (dash && platform == "") {
		return "", "", false
	}
	for i := 0; i < len(version); i++ {
		if c := version[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.') {
			return "", "", false
		}
	}
	for i := 0; i < len(platform); i++ {
		if c := platform[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '_' || c == '-') {
			return "", "", false
		}
	}
	return version, platform, true
}

// rubygemsValidName reports whether s is a gem name the compact index holds
// and a path carries: letters, digits, ".", "-" and "_", at most 255
// characters, not "." or "..".
func rubygemsValidName(s string) bool {
	if s == "" || len(s) > 255 || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// rubygemsHex reports whether s is n lower-case hex digits.
func rubygemsHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

// rubygemsDigest reads the SHA-256 a response states for the whole file:
// Repr-Digest (RFC 9530: `sha-256=:<base64>:`; rubygems.org writes
// `sha-256="<base64>"`) or the older Digest (`SHA-256=<base64>`).
func rubygemsDigest(h http.Header) ([]byte, bool) {
	for _, name := range []string{"Repr-Digest", "Digest"} {
		for _, v := range h.Values(name) {
			for _, item := range strings.Split(v, ",") {
				alg, val, ok := strings.Cut(strings.TrimSpace(item), "=")
				if !ok || !strings.EqualFold(strings.TrimSpace(alg), "sha-256") {
					continue
				}
				sum, err := base64.StdEncoding.DecodeString(strings.Trim(strings.TrimSpace(val), `":`))
				if err == nil && len(sum) == sha256.Size {
					return sum, true
				}
			}
		}
	}
	return nil, false
}

// rubygemsParseContentRange reads "bytes <first>-<last>/<length>".
func rubygemsParseContentRange(v string) (first, last, length int64, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(v), "bytes ")
	if !found {
		return 0, 0, 0, false
	}
	rng, total, found := strings.Cut(rest, "/")
	if !found {
		return 0, 0, 0, false
	}
	a, b, found := strings.Cut(rng, "-")
	if !found {
		return 0, 0, 0, false
	}
	var err1, err2, err3 error
	first, err1 = strconv.ParseInt(a, 10, 64)
	last, err2 = strconv.ParseInt(b, 10, 64)
	length, err3 = strconv.ParseInt(total, 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || first < 0 || last < first || length <= last {
		return 0, 0, 0, false
	}
	return first, last, length, true
}

// rubygemsETag is the validator a response states, when it is one a cursor
// can keep.
func rubygemsETag(h http.Header) string {
	e := h.Get("ETag")
	if len(e) > 256 || !cleanName(e) {
		return ""
	}
	return e
}

// Releases reads the gem's /info document through the gated pipeline.
func (f *rubygemsFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	if !rubygemsValidName(name) {
		return nil, Permanent(fmt.Errorf("%q is not a gem name", name))
	}
	body, err := f.k.read(ctx, "/info/"+name, "", rubygemsMaxInfo)
	if err != nil {
		return nil, err
	}
	info, err := rubygems.ParseInfo(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the /info document of %s: %w", name, err))
	}
	type group struct {
		version string
		tokens  []string
	}
	var groups []*group
	byVersion := map[string]*group{}
	for _, v := range info.Versions {
		ver, _, ok := rubygemsSplit(v.Version)
		if !ok {
			continue
		}
		g := byVersion[ver]
		if g == nil {
			g = &group{version: ver}
			byVersion[ver] = g
			groups = append(groups, g)
		}
		if !rubygemsContains(g.tokens, v.Version) {
			g.tokens = append(g.tokens, v.Version)
		}
	}
	if len(info.Versions) > 0 && len(groups) == 0 {
		return nil, Permanent(fmt.Errorf("the /info document of %s: none of its %d lines names a version", name, len(info.Versions)))
	}
	created := rubygemsInfoTimes(body)
	rels := make([]Release, 0, len(groups))
	misread := 0
	for _, g := range groups {
		rel := Release{Version: g.version}
		for _, tok := range g.tokens {
			arts, err := f.k.locate(ctx, lockfiles.Dependency{Name: name, Version: tok}, nil)
			if err != nil {
				if IsPermanent(err) {
					continue
				}
				return nil, err
			}
			kept := false
			for _, a := range arts {
				dec, err := url.PathUnescape(a.Path)
				n, v, ok := rubygems.GemPathCoordinate(dec)
				if err != nil || !ok || n != name || v != tok {
					misread++
					continue
				}
				rel.Artifacts = append(rel.Artifacts, a)
				kept = true
			}
			if t, ok := created[tok]; ok && kept && (rel.Published.IsZero() || t.Before(rel.Published)) {
				rel.Published = t
			}
		}
		if len(rel.Artifacts) > 0 {
			rels = append(rels, rel)
		}
	}
	if len(rels) == 0 && misread > 0 {
		return nil, Permanent(fmt.Errorf("the rubygems backend reads the gem files of %s as another gem's (a \"-\" before a digit ends a gem name there): not mirrored", name))
	}
	orderReleases("rubygems", rels)
	return rels, nil
}

// rubygemsInfoTimes reads the created_at an /info document states for each
// version token ("1.0.0 deps|checksum:…,created_at:2026-08-06T14:29:07Z").
func rubygemsInfoTimes(body []byte) map[string]time.Time {
	out := map[string]time.Time{}
	for _, line := range strings.Split(string(body), "\n") {
		token, rest, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || token == "---" {
			continue
		}
		bar := strings.LastIndexByte(rest, '|')
		if bar < 0 {
			continue
		}
		for _, field := range strings.Split(rest[bar+1:], ",") {
			k, v, ok := strings.Cut(field, ":")
			if !ok || strings.TrimSpace(k) != "created_at" {
				continue
			}
			if t, err := time.Parse(time.RFC3339, strings.TrimSpace(v)); err == nil {
				if _, dup := out[token]; !dup {
					out[token] = t.UTC()
				}
			}
		}
	}
	return out
}

// rubygemsContains reports whether list holds s.
func rubygemsContains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
