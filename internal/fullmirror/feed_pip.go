package fullmirror

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
	"github.com/blechschmidt/pullthrough-security/internal/versions"
)

// pip follows the Python Package Index.
//
// Changes reads PyPI's journal through its XML-RPC API (POST <index>/pypi):
// `changelog_since_serial(serial)` returns the journal rows after a serial —
// [name, version or nil, timestamp, action, serial], at most 50,000 a call —
// and `changelog_last_serial()` the newest serial. A row that adds a file
// ("add py3 file …", "add source file …") or announces a release ("new
// release") becomes the project at that version; "remove project" a deleted
// project (dropping what the same batch reported for it before) and "remove
// release" a deleted version; rows about owners and roles, yanks, documentation
// and project creation name nothing to fetch and are left out. Every version
// is reported once per batch. When a call returns no new row, the head is read:
// a stored serial beyond it means the journal was reset, and the cursor is
// reported invalid.
//
// Bootstrap reads the index's project list once (GET <index>/simple/ as PEP
// 691 JSON: some 700,000 projects, 46 MB), keeps it in Env.Dir sorted by name,
// lists it in pages and ends with the serial the list was taken at
// (meta._last-serial), so that the changelog continues from exactly there.
//
// Project names are PEP 503-normalized ("Foo_Bar" is "foo-bar"): the feed's
// include and exclude patterns match those names.
//
// The feed option "mode" picks how changes are followed: "xmlrpc" (the
// changelog), "simple" (the project list) or "auto", the default — the
// changelog, or the project list where the index has no XML-RPC endpoint (a
// 404 or 405, or a "method not found" fault). In simple mode, which is how
// bandersnatch follows PyPI since it dropped XML-RPC, every poll reads the
// project list again — conditionally, with the ETag of the copy kept — and
// diffs each project's _last-serial against the stored copy: a project that
// is new or whose serial moved is reported by name (the engine then considers
// every version its policy keeps), one that vanished as deleted. Each changed
// poll costs the whole list (46 MB; PyPI's CDN keeps it ten minutes), so a long
// pollInterval suits this mode. An auto follower whose changelog disappears
// (PyPI plans to retire XML-RPC) reports its cursor invalid and enumerates the
// index again, which then continues in simple mode.
//
// Releases reads the project's simple page through the gated pipeline (what pip
// reads), takes each file's path from the URL the backend rewrote into it
// ("/files/<scheme>/<host>/<path>", repos/locate's PipFiles) and groups the
// files by version: a version is yanked when all its files are, published
// when its first file was uploaded. Files whose name carries no version (eggs,
// Windows installers) and files at a location the upstream does not serve are
// not mirrored.
//
// The public index's feeds are at https://pypi.org; another upstream is taken
// to serve them under its own URL, as a Warehouse instance (TestPyPI, a
// self-hosted one) does, and the feed option "url" names another index root.
// An index that serves neither the changelog nor a project list with serials
// cannot be followed: Artifactory, Nexus and most devpi setups serve PEP 503
// HTML without serials (devpi has a changelog protocol of its own,
// /+changelog/<serial>, which this adapter does not speak).

const pypiFeedVersion = 1

// pypiPublicHosts are the public index's names.
var pypiPublicHosts = []string{"pypi.org", "www.pypi.org", "pypi.python.org"}

// pypiPublicBase is where the public index serves its feeds.
const pypiPublicBase = "https://pypi.org"

// Feed modes.
const (
	pypiModeAuto   = "auto"
	pypiModeXMLRPC = "xmlrpc"
	pypiModeSimple = "simple"
)

const (
	// pypiChangelogCap is the most rows changelog_since_serial returns: a
	// call that returns as many has more to give.
	pypiChangelogCap = 50000
	// pypiPage is the most projects one batch lists.
	pypiPage = 100_000
	// pypiMaxProjects bounds the projects one project list may name.
	pypiMaxProjects = 5_000_000
	// pypiMaxStore bounds a stored copy of the project list, uncompressed.
	pypiMaxStore = 1 << 30
	// pypiMaxName bounds a project name.
	pypiMaxName = 256
	// pypiMaxVersion bounds a version.
	pypiMaxVersion = 256
	// pypiRateLimitWait is the wait after a rate-limit fault that states none:
	// PyPI's longer XML-RPC window is a minute.
	pypiRateLimitWait = time.Minute
	// pypiFaultWait is the wait after another server fault.
	pypiFaultWait = time.Minute
	// pypiMinTime and pypiMaxTime bound the changelog times taken for the
	// cursor's time (2000 to 2100): another is not shown.
	pypiMinTime = 946684800
	pypiMaxTime = 4102444800
)

// pypiIndexAccept asks for the PEP 691 JSON project list.
const pypiIndexAccept = "application/vnd.pypi.simple.v1+json"

// pypiPageAccept is what pip asks for a project page: JSON, else HTML.
const pypiPageAccept = "application/vnd.pypi.simple.v1+json, text/html;q=0.1"

type pypiFeed struct {
	k kit
	// mode is the configured mode (auto, xmlrpc or simple).
	mode string
	// xmlrpc is the XML-RPC endpoint, index the project list.
	xmlrpc, index string
	files         files
	// page is how many projects one batch lists; cap how many changelog
	// rows make a full call.
	page, cap int
	// settle holds back changelog rows younger than it (feed option
	// "settle"): the simple page of a release served from the CDN can lag
	// the changelog by a minute or more, and a version reported before its
	// page lists it would be taken for gone.
	settle time.Duration
	now    func() time.Time
	// gone counts consecutive polls that found the XML-RPC endpoint
	// missing; an auto follower switches to the project list only once it
	// stays missing.
	gone int
}

// pypiDefaultSettle is how old a changelog row must be before it is
// reported.
const pypiDefaultSettle = 5 * time.Minute

// pypiGoneSwitch is how many consecutive polls must find the XML-RPC
// endpoint missing before an auto follower enumerates the index again and
// follows its project list: one 404 from a proxy in front of PyPI is not the
// endpoint's retirement.
const pypiGoneSwitch = 3

func newPypiFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "mode", "settle")
	if err != nil {
		return nil, err
	}
	mode, err := opts.oneOf("mode", pypiModeAuto, pypiModeXMLRPC, pypiModeSimple)
	if err != nil {
		return nil, err
	}
	settle, err := gitSettleOption(opts, pypiDefaultSettle)
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	base := k.upstream
	switch {
	case opts["url"] != "":
		if base, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
		// The option names the index's root; its simple index is taken for
		// it too ("https://pypi.org/simple").
		base.Path = strings.TrimSuffix(base.Path, "/simple")
	case hostIs(k.upstream, pypiPublicHosts...):
		base, _ = url.Parse(pypiPublicBase)
	}
	return &pypiFeed{
		k: k, mode: mode,
		xmlrpc: join(base, "pypi"), index: join(base, "simple/"),
		files: files{dir: env.Dir}, page: pypiPage, cap: pypiChangelogCap,
		settle: settle, now: time.Now,
	}, nil
}

func init() { Register("pip", newPypiFeed) }

// pypiCursor is the pip feed's position.
type pypiCursor struct {
	Format string `json:"format"`
	// Mode is how Changes follows the index: "xmlrpc" or "simple".
	Mode string `json:"mode"`
	// Serial is the journal serial the cursor stands at: what comes after it
	// is still to be reported.
	Serial int64 `json:"serial"`
	// Listing is set while Bootstrap lists the stored project list; Skip is
	// how many projects (or, in simple mode, differences) were reported.
	Listing bool `json:"listing,omitempty"`
	Skip    int  `json:"skip,omitempty"`
	// Store is the SHA-256 of the stored copy of the project list: the one
	// listed, or in simple mode the one the next poll is diffed against. To
	// is the newer copy while a difference spanning several batches is
	// reported.
	Store string `json:"store,omitempty"`
	To    string `json:"to,omitempty"`
	// ETag is the project list's validator, for the next conditional poll.
	ETag string `json:"etag,omitempty"`
}

func (c *pypiCursor) cursorFormat() string { return c.Format }

func (f *pypiFeed) format() string { return cursorFormat("pip", pypiFeedVersion) }

// decode reads and checks a cursor.
func (f *pypiFeed) decode(cursor string) (pypiCursor, error) {
	var c pypiCursor
	if err := decodeCursor(cursor, f.format(), &c); err != nil {
		return c, err
	}
	switch {
	case c.Mode != pypiModeXMLRPC && c.Mode != pypiModeSimple:
		return c, fmt.Errorf("%w: the pip cursor's mode %q is not one the feed follows", ErrCursorInvalid, c.Mode)
	case c.Serial < 0 || c.Skip < 0 || c.Skip > pypiMaxProjects:
		return c, fmt.Errorf("%w: the pip cursor's position is out of range", ErrCursorInvalid)
	case c.Store != "" && !pypiIsDigest(c.Store), c.To != "" && !pypiIsDigest(c.To):
		return c, fmt.Errorf("%w: the pip cursor names no stored copy of the index", ErrCursorInvalid)
	case len(c.ETag) > 512:
		return c, fmt.Errorf("%w: the pip cursor's validator is too long", ErrCursorInvalid)
	case c.Listing && (c.Store == "" || c.To != ""):
		return c, fmt.Errorf("%w: the pip listing cursor names no stored project list", ErrCursorInvalid)
	}
	return c, nil
}

// Bootstrap lists every project of the index.
func (f *pypiFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	if cursor != "" {
		c, err := f.decode(cursor)
		if err != nil {
			return Batch{}, err
		}
		if !c.Listing {
			return Batch{}, fmt.Errorf("%w: the pip cursor does not continue a listing", ErrCursorInvalid)
		}
		return f.listStored(c)
	}
	mode := f.mode
	head := int64(-1)
	if mode != pypiModeSimple {
		h, err := f.lastSerial(ctx)
		switch {
		case err == nil:
			mode, head = pypiModeXMLRPC, h
		case mode == pypiModeAuto && errors.Is(err, pypiErrNoXMLRPC):
			mode = pypiModeSimple
		default:
			return Batch{}, err
		}
	}
	idx, _, err := f.fetchIndex(ctx, "")
	if err != nil {
		return Batch{}, err
	}
	if mode == pypiModeSimple && !idx.serials {
		return Batch{}, pypiNoSerials(f.index)
	}
	serial := idx.serial
	if mode == pypiModeXMLRPC && (serial <= 0 || serial > head) {
		// The changelog continues from the older of the two: the list's own
		// serial (a CDN copy may be minutes old), or the head read before it.
		serial = head
	}
	if serial < 0 {
		serial = 0
	}
	digest, err := f.saveStore(idx)
	if err != nil {
		return Batch{}, fmt.Errorf("storing the project list: %w", err)
	}
	f.files.pruneKeepingNewest(pypiStorePrefix, 1, pypiStoreName(digest))
	c := pypiCursor{Format: f.format(), Mode: mode, Serial: serial, Listing: true, Store: digest}
	if mode == pypiModeSimple {
		c.ETag = idx.etag
	}
	end := len(idx.projects)
	if end > f.page {
		end = f.page
	}
	items := make([]Coordinate, 0, end)
	for _, p := range idx.projects[:end] {
		items = append(items, Coordinate{Name: p.name})
	}
	return f.listBatch(c, items, len(idx.projects)), nil
}

// listStored continues a listing from the stored project list.
func (f *pypiFeed) listStored(c pypiCursor) (Batch, error) {
	r, err := f.openStore(c.Store)
	if err != nil {
		return Batch{}, err
	}
	defer r.Close()
	var items []Coordinate
	n := 0
	for r.Next() {
		if n >= c.Skip && len(items) < f.page {
			items = append(items, Coordinate{Name: r.Project().name})
		}
		n++
	}
	if err := r.Err(); err != nil {
		return Batch{}, err
	}
	if c.Skip > n {
		return Batch{}, fmt.Errorf("%w: the listing cursor is past the stored list's end", ErrCursorInvalid)
	}
	return f.listBatch(c, items, n), nil
}

// listBatch is one page of a listing: more to come, or the follow cursor.
func (f *pypiFeed) listBatch(c pypiCursor, items []Coordinate, total int) Batch {
	b := Batch{Items: items, Head: strconv.FormatInt(c.Serial, 10)}
	if next := c.Skip + len(items); next < total {
		c.Skip = next
		b.More, b.Next = true, encodeCursor(&c)
		return b
	}
	follow := pypiCursor{Format: c.Format, Mode: c.Mode, Serial: c.Serial}
	if c.Mode == pypiModeSimple {
		follow.Store, follow.ETag = c.Store, c.ETag
	}
	b.Next = encodeCursor(&follow)
	return b
}

// Changes reports what changed after the cursor.
func (f *pypiFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	c, err := f.decode(cursor)
	if err != nil {
		return Batch{}, err
	}
	if c.Listing {
		return Batch{}, fmt.Errorf("%w: the pip cursor continues a listing", ErrCursorInvalid)
	}
	mode := c.Mode
	switch f.mode {
	case pypiModeSimple:
		if c.Mode != pypiModeSimple {
			return Batch{}, fmt.Errorf("%w: the cursor follows the XML-RPC changelog, but the feed's mode is simple and no copy of the project list is kept", ErrCursorInvalid)
		}
	case pypiModeXMLRPC:
		// A simple-mode cursor's serial is where its copy of the project
		// list stood: the changelog continues from there.
		mode = pypiModeXMLRPC
	}
	if mode == pypiModeSimple {
		return f.simpleChanges(ctx, c)
	}
	return f.changelog(ctx, c)
}

// changelog follows the XML-RPC changelog.
func (f *pypiFeed) changelog(ctx context.Context, c pypiCursor) (Batch, error) {
	// The changelog keeps no copy of the project list.
	f.files.pruneKeepingNewest(pypiStorePrefix, 1)
	rows, total, err := f.sinceSerial(ctx, c.Serial)
	if err != nil {
		return Batch{}, f.changelogGone(err)
	}
	f.gone = 0
	// In serial order: the cursor may not pass a row that is held back.
	sorted := append([]pypiChangelogRow(nil), rows...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].serial < sorted[j].serial })
	var cutoff int64
	if f.settle > 0 {
		cutoff = f.now().Add(-f.settle).Unix()
	}
	fresh := rows[:0:0]
	last := c.Serial
	var lastTime time.Time
	after, held, newest := 0, false, c.Serial
	for _, r := range sorted {
		if r.serial <= c.Serial {
			continue // not after the cursor
		}
		after++
		if r.serial > newest {
			newest = r.serial
		}
		if held {
			continue
		}
		if cutoff > 0 && r.time > cutoff {
			// Younger than the settle period: it, and every row after
			// it, waits for a later poll.
			held = true
			continue
		}
		fresh = append(fresh, r)
		if r.serial > last {
			last, lastTime = r.serial, time.Time{}
			if r.time >= pypiMinTime && r.time <= pypiMaxTime {
				lastTime = time.Unix(r.time, 0).UTC()
			}
		}
	}
	if len(rows) > 0 && after == 0 {
		// Rows that are all at or before the serial asked after: an index
		// that ignores it would be read the same way at every poll.
		return Batch{}, Permanent(fmt.Errorf("changelog_since_serial(%d) answered %d rows, none after that serial", c.Serial, len(rows)))
	}
	more := total >= f.cap && len(fresh) > 0 && !held
	b := Batch{Items: pypiChangelogItems(fresh), More: more,
		Next: encodeCursor(&pypiCursor{Format: f.format(), Mode: pypiModeXMLRPC, Serial: last})}
	if held {
		// Rows newer than the cursor are known: the head is at least the
		// newest of them.
		b.Head, b.Lag, b.LagKnown = strconv.FormatInt(newest, 10), newest-last, true
		if !lastTime.IsZero() {
			b.CursorTime = lastTime
		}
		return b, nil
	}
	if len(fresh) == 0 || more {
		head, err := f.lastSerial(ctx)
		if err != nil {
			return Batch{}, f.changelogGone(err)
		}
		if len(fresh) == 0 && c.Serial > head {
			return Batch{}, fmt.Errorf("%w: the stored serial %d is beyond the index's last serial %d (the journal was reset)", ErrCursorInvalid, c.Serial, head)
		}
		b.Head = strconv.FormatInt(head, 10)
		if head >= last {
			b.Lag, b.LagKnown = head-last, true
		}
	} else {
		// Fewer rows than a full call: the journal has nothing newer.
		b.Head, b.LagKnown = strconv.FormatInt(last, 10), true
	}
	if !lastTime.IsZero() {
		b.CursorTime = lastTime
		if !more {
			b.HeadTime = lastTime
		}
	}
	return b, nil
}

// changelogGone turns an index whose XML-RPC endpoint disappeared into an
// invalid cursor for an auto follower, which then enumerates the index again
// and continues in simple mode.
func (f *pypiFeed) changelogGone(err error) error {
	if f.mode == pypiModeAuto && errors.Is(err, pypiErrNoXMLRPC) {
		if f.gone++; f.gone < pypiGoneSwitch {
			// Not yet: retried, as any failed poll.
			return fmt.Errorf("the index answered that it serves no XML-RPC changelog (%d of %d polls before the follower switches to the project list): %v", f.gone, pypiGoneSwitch, err)
		}
		f.gone = 0
		return fmt.Errorf("%w: the index no longer serves the XML-RPC changelog (%v); it is enumerated again and followed through its project list", ErrCursorInvalid, err)
	}
	return err
}

// simpleChanges follows the project list: a new copy diffed against the
// stored one.
func (f *pypiFeed) simpleChanges(ctx context.Context, c pypiCursor) (Batch, error) {
	if c.Store == "" {
		return Batch{}, fmt.Errorf("%w: the pip cursor names no stored project list", ErrCursorInvalid)
	}
	if f.files.dir == "" {
		return Batch{}, errValidationOnly
	}
	if c.To != "" {
		// The rest of a difference that spans several batches.
		return f.diffPage(c, nil)
	}
	if _, err := os.Stat(f.files.path(pypiStoreName(c.Store))); err != nil {
		return Batch{}, fmt.Errorf("%w: the stored project list %s is missing (%v)", ErrCursorInvalid, pypiShortDigest(c.Store), err)
	}
	f.files.pruneKeepingNewest(pypiStorePrefix, 1, pypiStoreName(c.Store))
	unchanged := Batch{Next: encodeCursor(&c), Head: strconv.FormatInt(c.Serial, 10)}
	idx, notModified, err := f.fetchIndex(ctx, c.ETag)
	if err != nil {
		return Batch{}, err
	}
	if notModified {
		return unchanged, nil
	}
	if !idx.serials {
		return Batch{}, pypiNoSerials(f.index)
	}
	if idx.serial > 0 && idx.serial < c.Serial {
		// An older copy than the one kept (a CDN node behind the others):
		// nothing to report yet.
		return unchanged, nil
	}
	digest, err := f.saveStore(idx)
	if err != nil {
		return Batch{}, fmt.Errorf("storing the project list: %w", err)
	}
	if digest == c.Store {
		c.ETag = idx.etag
		unchanged.Next = encodeCursor(&c)
		return unchanged, nil
	}
	c.To, c.Skip = digest, 0
	return f.diffPage(c, idx)
}

// diffPage reports one page of the difference between the stored project
// list c.Store and the newer c.To (fresh, when it was just read): projects
// that are new or whose serial moved, and projects that vanished.
func (f *pypiFeed) diffPage(c pypiCursor, fresh *pypiIndex) (Batch, error) {
	base, err := f.openStore(c.Store)
	if err != nil {
		return Batch{}, err
	}
	defer base.Close()
	var to pypiProjectIter
	var serial int64
	var etag string
	if fresh != nil {
		to, serial, etag = &pypiSliceIter{p: fresh.projects}, fresh.serial, fresh.etag
	} else {
		r, err := f.openStore(c.To)
		if err != nil {
			return Batch{}, err
		}
		defer r.Close()
		to, serial, etag = r, r.header.Serial, r.header.ETag
	}
	// Keep both copies: the engine may ask again from the stored cursor.
	f.files.pruneKeepingNewest(pypiStorePrefix, 1, pypiStoreName(c.Store), pypiStoreName(c.To))
	var items []Coordinate
	n := 0
	emit := func(co Coordinate) {
		if n >= c.Skip && len(items) < f.page {
			items = append(items, co)
		}
		n++
	}
	a, b := base.Next(), to.Next()
	for a || b {
		switch {
		case !b || (a && base.Project().name < to.Project().name):
			emit(Coordinate{Name: base.Project().name, Deleted: true})
			a = base.Next()
		case !a || to.Project().name < base.Project().name:
			emit(Coordinate{Name: to.Project().name})
			b = to.Next()
		default:
			if base.Project().serial != to.Project().serial {
				emit(Coordinate{Name: to.Project().name})
			}
			a, b = base.Next(), to.Next()
		}
	}
	if err := base.Err(); err != nil {
		return Batch{}, err
	}
	if err := to.Err(); err != nil {
		return Batch{}, err
	}
	if c.Skip > n {
		return Batch{}, fmt.Errorf("%w: the cursor is past the end of the difference", ErrCursorInvalid)
	}
	out := Batch{Items: items, Head: strconv.FormatInt(serial, 10)}
	if next := c.Skip + len(items); next < n {
		c.Skip = next
		out.More, out.Next = true, encodeCursor(&c)
		return out, nil
	}
	out.Next = encodeCursor(&pypiCursor{Format: f.format(), Mode: pypiModeSimple, Serial: serial, Store: c.To, ETag: etag})
	return out, nil
}

// pypiNoSerials is the error for a project list without serials.
func pypiNoSerials(index string) error {
	return Permanent(fmt.Errorf("the project list at %s states no _last-serial for its projects: an index without serials (PEP 503 HTML, as Artifactory, Nexus and most devpi setups serve) cannot be followed", index))
}

// --- the project list -------------------------------------------------------

// pypiProject is one project of the project list: its normalized name and its
// last serial (-1 when the list does not state it).
type pypiProject struct {
	name   string
	serial int64
}

// pypiIndex is a project list as read: its projects sorted by name, each
// once, the list's serial (0 when unknown), its validator, and whether every
// project states its serial.
type pypiIndex struct {
	projects []pypiProject
	serial   int64
	etag     string
	serials  bool
}

// fetchIndex reads the project list; with etag, conditionally (notModified
// when the copy kept is current).
func (f *pypiFeed) fetchIndex(ctx context.Context, etag string) (*pypiIndex, bool, error) {
	hdr := http.Header{"Accept": {pypiIndexAccept}}
	if etag != "" {
		hdr.Set("If-None-Match", etag)
	}
	resp, err := f.k.do(ctx, http.MethodGet, f.index, nil, hdr)
	if err != nil {
		return nil, false, fmt.Errorf("reading the project list: %w", err)
	}
	defer drain(resp.Body)
	if resp.StatusCode == http.StatusNotModified && etag != "" {
		return nil, true, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		err := httpStatusError(f.index, resp)
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
			return nil, false, Permanent(fmt.Errorf("the index serves no project list (%v): set fullMirror.feed.url to the root of an index that does (a Warehouse such as https://pypi.org)", err))
		}
		return nil, false, fmt.Errorf("reading the project list: %w", err)
	}
	if ct := strings.ToLower(resp.Header.Get("Content-Type")); !strings.Contains(ct, "json") {
		return nil, false, Permanent(fmt.Errorf("the project list at %s is %q, not PEP 691 JSON: an index that serves only PEP 503 HTML states no serials and cannot be followed", f.index, truncate(ct, 64)))
	}
	lr := &io.LimitedReader{R: resp.Body, N: maxMetadataDoc + 1}
	idx, err := pypiParseIndex(lr)
	if lr.N <= 0 {
		return nil, false, Permanent(fmt.Errorf("reading the project list: %w (%d bytes)", errTooLarge, int64(maxMetadataDoc)))
	}
	if err != nil {
		var syn *json.SyntaxError
		var typ *json.UnmarshalTypeError
		var bad *pypiIndexError
		if errors.As(err, &syn) || errors.As(err, &typ) || errors.As(err, &bad) {
			return nil, false, Permanent(fmt.Errorf("the project list at %s is not the PEP 691 document expected: %w", f.index, err))
		}
		return nil, false, fmt.Errorf("reading the project list: %w", err)
	}
	if idx.serial <= 0 {
		if s, err := strconv.ParseInt(strings.TrimSpace(resp.Header.Get("X-PyPI-Last-Serial")), 10, 64); err == nil && s > 0 {
			idx.serial = s
		}
	}
	idx.etag = pypiCleanETag(resp.Header.Get("ETag"))
	return idx, false, nil
}

// pypiCleanETag keeps a validator that can be sent back: printable ASCII,
// bounded.
func pypiCleanETag(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 512 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return ""
		}
	}
	return s
}

// pypiIndexError marks a project list that is not the document expected.
type pypiIndexError struct{ msg string }

func (e *pypiIndexError) Error() string { return e.msg }

// pypiParseIndex reads a PEP 691 project list as it streams in:
// {"meta": {"_last-serial": N, "api-version": "1.x"}, "projects": [{"name":
// …, "_last-serial": N}, …]}. Names that are not project names are left out;
// the projects come back normalized, sorted and each once (with its highest
// serial).
func pypiParseIndex(r io.Reader) (*pypiIndex, error) {
	dec := json.NewDecoder(r)
	if err := pypiExpectDelim(dec, '{'); err != nil {
		return nil, err
	}
	idx := &pypiIndex{serials: true}
	listed := false
	count := 0
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		switch key {
		case "meta":
			var m struct {
				LastSerial *int64 `json:"_last-serial"`
				APIVersion string `json:"api-version"`
			}
			if err := dec.Decode(&m); err != nil {
				return nil, err
			}
			if major, _, _ := strings.Cut(m.APIVersion, "."); m.APIVersion != "" && major != "1" {
				return nil, &pypiIndexError{fmt.Sprintf("api-version %q is not one this feed reads (1.x)", truncate(m.APIVersion, 32))}
			}
			if m.LastSerial != nil && *m.LastSerial > 0 {
				idx.serial = *m.LastSerial
			}
		case "projects":
			if listed {
				return nil, &pypiIndexError{"the document lists projects twice"}
			}
			listed = true
			if err := pypiExpectDelim(dec, '['); err != nil {
				return nil, err
			}
			for dec.More() {
				if count++; count > pypiMaxProjects {
					return nil, &pypiIndexError{fmt.Sprintf("the document lists more than %d projects", pypiMaxProjects)}
				}
				var p struct {
					Name       string `json:"name"`
					LastSerial *int64 `json:"_last-serial"`
				}
				if err := dec.Decode(&p); err != nil {
					return nil, err
				}
				name := locate.PipNormalize(p.Name)
				if len(p.Name) > pypiMaxName || !pypiValidName(name) {
					continue
				}
				serial := int64(-1)
				if p.LastSerial != nil && *p.LastSerial >= 0 {
					serial = *p.LastSerial
				} else {
					idx.serials = false
				}
				idx.projects = append(idx.projects, pypiProject{name: name, serial: serial})
			}
			if err := pypiExpectDelim(dec, ']'); err != nil {
				return nil, err
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, err
			}
		}
	}
	if err := pypiExpectDelim(dec, '}'); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, &pypiIndexError{"the document goes on after its end"}
	}
	if !listed {
		return nil, &pypiIndexError{"the document lists no projects"}
	}
	sort.Slice(idx.projects, func(i, j int) bool {
		a, b := idx.projects[i], idx.projects[j]
		if a.name != b.name {
			return a.name < b.name
		}
		return a.serial > b.serial
	})
	out := idx.projects[:0]
	for i, p := range idx.projects {
		if i == 0 || p.name != idx.projects[i-1].name {
			out = append(out, p)
		}
	}
	idx.projects = out
	return idx, nil
}

// pypiExpectDelim reads one JSON delimiter.
func pypiExpectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return &pypiIndexError{fmt.Sprintf("want %q, got %v", want, truncate(fmt.Sprint(tok), 32))}
	}
	return nil
}

// pypiValidName reports whether s is a normalized project name (PEP 503
// normalization of a PEP 508 name): lower-case letters, digits and single
// dashes, neither first nor last.
func pypiValidName(s string) bool {
	if s == "" || len(s) > pypiMaxName || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// pypiValidVersion reports whether s can be a release's version: the
// characters PEP 440 versions (and the legacy ones PyPI still serves) are
// spelt with.
func pypiValidVersion(s string) bool {
	if s == "" || len(s) > pypiMaxVersion {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(".-_+!", c) >= 0) {
			return false
		}
	}
	return true
}

// --- the stored copies of the project list -----------------------------------

// Stored copies: "pip-index-<sha256>.jsonl.gz", gzip of a header line and one
// `["name",serial]` line per project in name order; the name is the SHA-256 of
// the uncompressed content, which a cursor names and every read checks.
const (
	pypiStorePrefix = "pip-index-"
	pypiStoreFormat = "pullthrough-pip-index/1"
)

func pypiStoreName(digest string) string { return pypiStorePrefix + digest + ".jsonl.gz" }

// pypiStoreHeader is a stored copy's first line.
type pypiStoreHeader struct {
	Format  string `json:"format"`
	Serial  int64  `json:"serial"`
	ETag    string `json:"etag,omitempty"`
	Count   int    `json:"count"`
	Serials bool   `json:"serials"`
}

// pypiIsDigest reports whether s is a lower-case hex SHA-256.
func pypiIsDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}

func pypiShortDigest(s string) string { return truncate(s, 12) }

// pypiEncodeStore writes a copy's content.
func pypiEncodeStore(w io.Writer, idx *pypiIndex) error {
	bw := bufio.NewWriter(w)
	hdr, err := json.Marshal(pypiStoreHeader{Format: pypiStoreFormat, Serial: idx.serial, ETag: idx.etag, Count: len(idx.projects), Serials: idx.serials})
	if err != nil {
		return err
	}
	bw.Write(hdr)
	bw.WriteByte('\n')
	for _, p := range idx.projects {
		// Names are lower-case letters, digits and dashes: nothing to escape.
		bw.WriteString(`["`)
		bw.WriteString(p.name)
		bw.WriteString(`",`)
		bw.WriteString(strconv.FormatInt(p.serial, 10))
		bw.WriteString("]\n")
	}
	return bw.Flush()
}

// saveStore keeps a copy of the project list and returns its digest.
func (f *pypiFeed) saveStore(idx *pypiIndex) (string, error) {
	h := sha256.New()
	if err := pypiEncodeStore(h, idx); err != nil {
		return "", err
	}
	digest := hex.EncodeToString(h.Sum(nil))
	err := f.files.write(pypiStoreName(digest), func(w io.Writer) error {
		zw, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
		if err != nil {
			return err
		}
		if err := pypiEncodeStore(zw, idx); err != nil {
			return err
		}
		return zw.Close()
	})
	return digest, err
}

// pypiProjectIter walks a project list in name order.
type pypiProjectIter interface {
	Next() bool
	Project() pypiProject
	Err() error
}

// pypiSliceIter walks a list held in memory.
type pypiSliceIter struct {
	p []pypiProject
	i int
}

func (s *pypiSliceIter) Next() bool {
	if s.i >= len(s.p) {
		return false
	}
	s.i++
	return true
}
func (s *pypiSliceIter) Project() pypiProject { return s.p[s.i-1] }
func (s *pypiSliceIter) Err() error           { return nil }

// pypiStoreReader walks a stored copy. Its content is checked as it is read
// — names valid and strictly ascending, the count the header states — and
// against its digest at the end: Err reports a copy that does not match its
// cursor as ErrCursorInvalid, and a caller acts on what it read only once Next
// has returned false without an error.
type pypiStoreReader struct {
	fh     *os.File
	zr     *gzip.Reader
	sc     *bufio.Scanner
	h      hash.Hash
	want   string
	header pypiStoreHeader
	cur    pypiProject
	n      int
	err    error
	done   bool
}

// openStore opens the stored copy a cursor names.
func (f *pypiFeed) openStore(digest string) (*pypiStoreReader, error) {
	if f.files.dir == "" {
		return nil, errValidationOnly
	}
	if !pypiIsDigest(digest) {
		return nil, fmt.Errorf("%w: %q names no stored project list", ErrCursorInvalid, truncate(digest, 70))
	}
	fh, err := os.Open(f.files.path(pypiStoreName(digest)))
	if err != nil {
		return nil, fmt.Errorf("%w: the stored project list %s is missing (%v)", ErrCursorInvalid, pypiShortDigest(digest), err)
	}
	r := &pypiStoreReader{fh: fh, h: sha256.New(), want: digest}
	if r.zr, err = gzip.NewReader(fh); err != nil {
		fh.Close()
		return nil, r.invalid(err)
	}
	r.sc = bufio.NewScanner(io.TeeReader(io.LimitReader(r.zr, pypiMaxStore), r.h))
	r.sc.Buffer(make([]byte, 0, 64<<10), 64<<10)
	if !r.sc.Scan() {
		r.Close()
		return nil, r.invalid(fmt.Errorf("no header (%v)", r.sc.Err()))
	}
	if err := json.Unmarshal(r.sc.Bytes(), &r.header); err != nil || r.header.Format != pypiStoreFormat || r.header.Count < 0 || r.header.Count > pypiMaxProjects {
		r.Close()
		return nil, r.invalid(fmt.Errorf("not a stored project list (%v)", err))
	}
	return r, nil
}

func (r *pypiStoreReader) invalid(err error) error {
	return fmt.Errorf("%w: the stored project list %s does not read: %v", ErrCursorInvalid, pypiShortDigest(r.want), err)
}

func (r *pypiStoreReader) Next() bool {
	if r.done || r.err != nil {
		return false
	}
	if !r.sc.Scan() {
		r.done = true
		switch {
		case r.sc.Err() != nil:
			r.err = r.invalid(r.sc.Err())
		case r.n != r.header.Count:
			r.err = r.invalid(fmt.Errorf("%d projects, the header says %d", r.n, r.header.Count))
		case hex.EncodeToString(r.h.Sum(nil)) != r.want:
			r.err = r.invalid(errors.New("its content does not match its digest"))
		}
		return false
	}
	p, ok := pypiStoreLine(r.sc.Bytes())
	if !ok || (r.n > 0 && p.name <= r.cur.name) {
		r.err = r.invalid(fmt.Errorf("line %d is not a project in order", r.n+2))
		return false
	}
	r.cur = p
	r.n++
	return true
}

func (r *pypiStoreReader) Project() pypiProject { return r.cur }
func (r *pypiStoreReader) Err() error           { return r.err }

func (r *pypiStoreReader) Close() {
	if r.zr != nil {
		r.zr.Close()
	}
	r.fh.Close()
}

// pypiStoreLine reads a `["name",serial]` line.
func pypiStoreLine(line []byte) (pypiProject, bool) {
	if len(line) < 6 || line[0] != '[' || line[1] != '"' || line[len(line)-1] != ']' {
		return pypiProject{}, false
	}
	end := bytes.IndexByte(line[2:], '"')
	if end < 0 {
		return pypiProject{}, false
	}
	name := string(line[2 : 2+end])
	rest := line[2+end+1 : len(line)-1]
	if len(rest) < 2 || rest[0] != ',' || !pypiValidName(name) {
		return pypiProject{}, false
	}
	n, err := strconv.ParseInt(string(rest[1:]), 10, 64)
	if err != nil || n < -1 {
		return pypiProject{}, false
	}
	return pypiProject{name: name, serial: n}, true
}

// --- XML-RPC -----------------------------------------------------------------

// pypiErrNoXMLRPC marks an index that serves no XML-RPC changelog: its
// endpoint answered 404 or 405, or a "method not found" fault.
var pypiErrNoXMLRPC = errors.New("the index serves no XML-RPC changelog")

// lastSerial calls changelog_last_serial().
func (f *pypiFeed) lastSerial(ctx context.Context) (int64, error) {
	params, err := f.call(ctx, "changelog_last_serial")
	if err != nil {
		return 0, err
	}
	if len(params) != 1 || params[0].Kind != pypiXMLInt || params[0].Int < 0 {
		return 0, Permanent(errors.New("changelog_last_serial did not answer a serial"))
	}
	return params[0].Int, nil
}

// sinceSerial calls changelog_since_serial(serial): the rows that read, and
// how many rows the answer had.
func (f *pypiFeed) sinceSerial(ctx context.Context, serial int64) ([]pypiChangelogRow, int, error) {
	params, err := f.call(ctx, "changelog_since_serial", serial)
	if err != nil {
		return nil, 0, err
	}
	rows, total, err := pypiChangelogRows(params)
	if err != nil {
		return nil, 0, Permanent(fmt.Errorf("changelog_since_serial(%d): %w", serial, err))
	}
	return rows, total, nil
}

// call makes one XML-RPC call and returns the response's params. A fault is an
// error: a rate limit asks for its wait, a "method not found" (or a 404 or
// 405 from the endpoint) is pypiErrNoXMLRPC, a client error is permanent and
// any other fault backs off.
func (f *pypiFeed) call(ctx context.Context, method string, args ...int64) ([]pypiXMLValue, error) {
	var req bytes.Buffer
	req.WriteString("<?xml version='1.0'?>\n<methodCall>\n<methodName>" + method + "</methodName>\n<params>\n")
	for _, a := range args {
		req.WriteString("<param>\n<value><int>" + strconv.FormatInt(a, 10) + "</int></value>\n</param>\n")
	}
	req.WriteString("</params>\n</methodCall>\n")
	what := method + " at " + f.xmlrpc
	resp, err := f.k.do(ctx, http.MethodPost, f.xmlrpc, &req, http.Header{"Content-Type": {"text/xml"}, "Accept": {"text/xml"}})
	if err != nil {
		return nil, fmt.Errorf("calling %w", err)
	}
	defer drain(resp.Body)
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusGone:
		return nil, Permanent(fmt.Errorf("%w: %s answered %s", pypiErrNoXMLRPC, f.xmlrpc, resp.Status))
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, httpStatusError(what, resp)
	}
	body, err := readLimited(resp.Body, maxFeedPage)
	if err != nil {
		return nil, fmt.Errorf("reading the answer of %s: %w", what, err)
	}
	params, fault, err := pypiParseXMLRPC(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the answer of %s is not an XML-RPC response: %w", what, err))
	}
	if fault != nil {
		return nil, fault.classify(what)
	}
	return params, nil
}

// pypiResetIn finds the wait warehouse's rate-limit fault states.
var pypiResetIn = regexp.MustCompile(`(?i)limit may reset in (\d{1,6}) seconds?`)

// pypiFault is an XML-RPC fault.
type pypiFault struct {
	Code    int64
	Message string
}

func (e *pypiFault) Error() string {
	return fmt.Sprintf("XML-RPC fault %d: %s", e.Code, cleanMessage(truncate(e.Message, 512)))
}

// classify turns a fault into the error the engine acts on.
func (e *pypiFault) classify(what string) error {
	err := fmt.Errorf("%s: %w", what, e)
	msg := strings.ToLower(e.Message)
	switch {
	case strings.Contains(msg, "toomanyrequests") || strings.Contains(msg, "too many requests"):
		d := pypiRateLimitWait
		if m := pypiResetIn.FindStringSubmatch(e.Message); m != nil {
			if n, perr := strconv.Atoi(m[1]); perr == nil && n > 0 {
				d = time.Duration(n) * time.Second
			}
		}
		return RetryAfter(err, d)
	case e.Code == -32601 || strings.Contains(msg, "method not found") || strings.Contains(msg, "no longer support"):
		// The method is gone (PyPI answered its retired XML-RPC search with
		// a fault saying it "no longer supports" it).
		return Permanent(fmt.Errorf("%w: %v", pypiErrNoXMLRPC, err))
	case e.Code == -32600 || e.Code == -32602 || e.Code == -32700 || strings.HasPrefix(msg, "client error"):
		return Permanent(err)
	}
	return RetryAfter(err, pypiFaultWait)
}

// pypiChangelogRow is one row of changelog_since_serial.
type pypiChangelogRow struct {
	name       string
	version    string
	hasVersion bool
	time       int64
	action     string
	serial     int64
}

// pypiChangelogRows reads changelog_since_serial's answer: one param, an array
// of [name, version|nil, timestamp, action, serial] rows. Rows of another
// shape are left out; total counts them all.
func pypiChangelogRows(params []pypiXMLValue) ([]pypiChangelogRow, int, error) {
	if len(params) != 1 || params[0].Kind != pypiXMLArray {
		return nil, 0, errors.New("the answer is not a list of changes")
	}
	all := params[0].Items
	out := make([]pypiChangelogRow, 0, len(all))
	for _, r := range all {
		it := r.Items
		if r.Kind != pypiXMLArray || len(it) < 5 || it[0].Kind != pypiXMLString || it[2].Kind != pypiXMLInt ||
			it[3].Kind != pypiXMLString || it[4].Kind != pypiXMLInt || it[4].Int <= 0 {
			continue
		}
		row := pypiChangelogRow{name: it[0].Str, time: it[2].Int, action: it[3].Str, serial: it[4].Int}
		switch it[1].Kind {
		case pypiXMLString:
			row.version, row.hasVersion = it[1].Str, true
		case pypiXMLNil:
		default:
			continue
		}
		out = append(out, row)
	}
	if len(all) > 0 && len(out) == 0 {
		return nil, len(all), fmt.Errorf("none of its %d rows is a change", len(all))
	}
	return out, len(all), nil
}

// pypiFileAdded matches the action of a file upload: "add <python version>
// file <filename>" (a role granted reads "add <role> <user>").
var pypiFileAdded = regexp.MustCompile(`^add [^ ]+ file [^ ]`)

// Changelog actions the feed reports.
const (
	pypiActionNone = iota
	pypiActionRelease
	pypiActionRemoveRelease
	pypiActionRemoveProject
)

// pypiAction classifies a journal action: a file added ("add py3 file
// x.whl", "add source file x.tar.gz") or a release announced ("new release")
// names a version to fetch; "remove release" and "remove project" removals.
// Everything else — "create", owner and role changes ("add Owner x",
// "accepted Owner x"), "remove file", yanks, documentation — names nothing to
// fetch.
func pypiAction(action string) int {
	switch {
	case action == "new release", pypiFileAdded.MatchString(action):
		return pypiActionRelease
	case action == "remove release":
		return pypiActionRemoveRelease
	case action == "remove project":
		return pypiActionRemoveProject
	}
	return pypiActionNone
}

// pypiChangelogItems maps changelog rows to the batch's changes: each version
// once, in the order first named; a project removed in the batch only from its
// (last) removal on.
func pypiChangelogItems(rows []pypiChangelogRow) []Coordinate {
	names := make([]string, len(rows))
	removed := map[string]int{}
	for i, r := range rows {
		if len(r.name) <= pypiMaxName {
			names[i] = locate.PipNormalize(r.name)
		}
		if pypiAction(r.action) == pypiActionRemoveProject && pypiValidName(names[i]) {
			removed[names[i]] = i
		}
	}
	seen := map[Coordinate]bool{}
	var out []Coordinate
	for i, r := range rows {
		name := names[i]
		if !pypiValidName(name) {
			continue
		}
		if j, ok := removed[name]; ok && i < j {
			continue // removed later in the batch: nothing left to fetch
		}
		var c Coordinate
		switch pypiAction(r.action) {
		case pypiActionRelease:
			c = Coordinate{Name: name}
			if r.hasVersion {
				if !pypiValidVersion(r.version) {
					continue
				}
				c.Version = r.version
			}
		case pypiActionRemoveRelease:
			if !r.hasVersion || !pypiValidVersion(r.version) {
				continue
			}
			c = Coordinate{Name: name, Version: r.version, Deleted: true}
		case pypiActionRemoveProject:
			c = Coordinate{Name: name, Deleted: true}
		default:
			continue
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// pypiXMLKind is an XML-RPC value's type.
type pypiXMLKind uint8

const (
	pypiXMLString pypiXMLKind = iota + 1
	pypiXMLInt
	pypiXMLBool
	pypiXMLNil
	pypiXMLArray
	pypiXMLStruct
)

// pypiXMLValue is one XML-RPC value.
type pypiXMLValue struct {
	Kind    pypiXMLKind
	Str     string
	Int     int64
	Bool    bool
	Items   []pypiXMLValue
	Members []pypiXMLMember
}

// pypiXMLMember is one member of a struct.
type pypiXMLMember struct {
	Name  string
	Value pypiXMLValue
}

// Bounds on an XML-RPC response.
const (
	// pypiXMLMaxDepth bounds the nesting of values (a changelog nests two).
	pypiXMLMaxDepth = 8
	// pypiXMLMaxValues bounds the values of one response (a full changelog
	// call holds 300,000).
	pypiXMLMaxValues = 1 << 21
	// pypiXMLMaxString bounds one string.
	pypiXMLMaxString = 64 << 10
	// pypiXMLMaxParams bounds a response's params.
	pypiXMLMaxParams = 16
)

// pypiXMLParser reads an XML-RPC methodResponse token by token.
type pypiXMLParser struct {
	d      *xml.Decoder
	values int
	root   bool
}

// pypiParseXMLRPC reads an XML-RPC methodResponse: its params, or its fault.
// It is strict — no DTD, no namespaces, no type it does not know (string,
// int/i4/i8, boolean, nil, array, struct; untyped text is a string), nothing
// after the response — and bounded in depth, values and string length.
func pypiParseXMLRPC(body []byte) ([]pypiXMLValue, *pypiFault, error) {
	p := &pypiXMLParser{d: xml.NewDecoder(bytes.NewReader(body))}
	p.d.Strict = true
	if err := p.expectStart("methodResponse"); err != nil {
		return nil, nil, err
	}
	p.root = true
	tok, err := p.element()
	if err != nil {
		return nil, nil, err
	}
	s, ok := tok.(xml.StartElement)
	if !ok {
		return nil, nil, fmt.Errorf("want <params> or <fault>, got %s", pypiDescribe(tok))
	}
	var params []pypiXMLValue
	var fault *pypiFault
	switch s.Name.Local {
	case "params":
		for {
			tok, err := p.element()
			if err != nil {
				return nil, nil, err
			}
			if e, ok := tok.(xml.EndElement); ok && e.Name.Local == "params" {
				break
			}
			if s, ok := tok.(xml.StartElement); !ok || s.Name.Local != "param" {
				return nil, nil, fmt.Errorf("want <param>, got %s", pypiDescribe(tok))
			}
			if len(params) == pypiXMLMaxParams {
				return nil, nil, fmt.Errorf("more than %d params", pypiXMLMaxParams)
			}
			if err := p.expectStart("value"); err != nil {
				return nil, nil, err
			}
			v, err := p.value(1)
			if err != nil {
				return nil, nil, err
			}
			params = append(params, v)
			if err := p.expectEnd("param"); err != nil {
				return nil, nil, err
			}
		}
	case "fault":
		if err := p.expectStart("value"); err != nil {
			return nil, nil, err
		}
		v, err := p.value(1)
		if err != nil {
			return nil, nil, err
		}
		if fault, err = pypiFaultOf(v); err != nil {
			return nil, nil, err
		}
		if err := p.expectEnd("fault"); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("want <params> or <fault>, got <%s>", truncate(s.Name.Local, 32))
	}
	if err := p.expectEnd("methodResponse"); err != nil {
		return nil, nil, err
	}
	for {
		tok, err := p.d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		switch t := tok.(type) {
		case xml.Comment:
		case xml.CharData:
			if len(bytes.TrimSpace(t)) != 0 {
				return nil, nil, errors.New("text after the response")
			}
		default:
			return nil, nil, fmt.Errorf("%s after the response", pypiDescribe(tok))
		}
	}
	return params, fault, nil
}

// pypiFaultOf reads a fault's struct.
func pypiFaultOf(v pypiXMLValue) (*pypiFault, error) {
	if v.Kind != pypiXMLStruct {
		return nil, errors.New("the fault is not a struct")
	}
	f := &pypiFault{}
	var code, msg bool
	for _, m := range v.Members {
		switch {
		case m.Name == "faultCode" && m.Value.Kind == pypiXMLInt:
			f.Code, code = m.Value.Int, true
		case m.Name == "faultString" && m.Value.Kind == pypiXMLString:
			f.Message, msg = m.Value.Str, true
		}
	}
	if !code || !msg {
		return nil, errors.New("the fault has no faultCode or faultString")
	}
	return f, nil
}

// token returns the next token that matters: elements and text. Comments are
// skipped; a processing instruction other than the XML declaration, and any
// DTD, are refused.
func (p *pypiXMLParser) token() (xml.Token, error) {
	for {
		tok, err := p.d.Token()
		if err != nil {
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		switch t := tok.(type) {
		case xml.Comment:
			continue
		case xml.ProcInst:
			if p.root || t.Target != "xml" {
				return nil, errors.New("a processing instruction")
			}
			continue
		case xml.Directive:
			return nil, errors.New("a DTD or another directive")
		case xml.StartElement:
			if t.Name.Space != "" {
				return nil, fmt.Errorf("element <%s> is in a namespace", truncate(t.Name.Local, 32))
			}
			return t, nil
		case xml.EndElement, xml.CharData:
			return t, nil
		}
	}
}

// element returns the next element token, skipping whitespace.
func (p *pypiXMLParser) element() (xml.Token, error) {
	for {
		tok, err := p.token()
		if err != nil {
			return nil, err
		}
		if cd, ok := tok.(xml.CharData); ok {
			if len(bytes.TrimSpace(cd)) != 0 {
				return nil, fmt.Errorf("unexpected text %q", truncate(string(cd), 32))
			}
			continue
		}
		return tok, nil
	}
}

func (p *pypiXMLParser) expectStart(name string) error {
	tok, err := p.element()
	if err != nil {
		return err
	}
	if s, ok := tok.(xml.StartElement); !ok || s.Name.Local != name {
		return fmt.Errorf("want <%s>, got %s", name, pypiDescribe(tok))
	}
	return nil
}

func (p *pypiXMLParser) expectEnd(name string) error {
	tok, err := p.element()
	if err != nil {
		return err
	}
	if e, ok := tok.(xml.EndElement); !ok || e.Name.Local != name {
		return fmt.Errorf("want </%s>, got %s", name, pypiDescribe(tok))
	}
	return nil
}

// text reads the text of a scalar element up to its end.
func (p *pypiXMLParser) text(name string) (string, error) {
	var b strings.Builder
	for {
		tok, err := p.token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			if b.Len()+len(t) > pypiXMLMaxString {
				return "", fmt.Errorf("a string of more than %d bytes", pypiXMLMaxString)
			}
			b.Write(t)
		case xml.EndElement:
			if t.Name.Local != name {
				return "", fmt.Errorf("want </%s>, got %s", name, pypiDescribe(tok))
			}
			return b.String(), nil
		default:
			return "", fmt.Errorf("<%s> holds %s", name, pypiDescribe(tok))
		}
	}
}

// value reads a value after its <value> start, up to and including </value>.
func (p *pypiXMLParser) value(depth int) (pypiXMLValue, error) {
	if depth > pypiXMLMaxDepth {
		return pypiXMLValue{}, fmt.Errorf("values nested more than %d deep", pypiXMLMaxDepth)
	}
	if p.values++; p.values > pypiXMLMaxValues {
		return pypiXMLValue{}, fmt.Errorf("more than %d values", pypiXMLMaxValues)
	}
	var text strings.Builder
	var v pypiXMLValue
	typed := false
	for {
		tok, err := p.token()
		if err != nil {
			return v, err
		}
		switch t := tok.(type) {
		case xml.CharData:
			if typed {
				if len(bytes.TrimSpace(t)) != 0 {
					return v, errors.New("text beside a typed value")
				}
				continue
			}
			if text.Len()+len(t) > pypiXMLMaxString {
				return v, fmt.Errorf("a string of more than %d bytes", pypiXMLMaxString)
			}
			text.Write(t)
		case xml.EndElement:
			if t.Name.Local != "value" {
				return v, fmt.Errorf("want </value>, got %s", pypiDescribe(tok))
			}
			if !typed {
				// A value without a type is a string, whitespace and all.
				v = pypiXMLValue{Kind: pypiXMLString, Str: text.String()}
			}
			return v, nil
		case xml.StartElement:
			if typed {
				return v, errors.New("a value of two types")
			}
			if strings.TrimSpace(text.String()) != "" {
				return v, errors.New("text beside a typed value")
			}
			typed = true
			if v, err = p.typed(t.Name.Local, depth); err != nil {
				return v, err
			}
		}
	}
}

// typed reads a value's type element after its start.
func (p *pypiXMLParser) typed(name string, depth int) (pypiXMLValue, error) {
	switch name {
	case "string":
		s, err := p.text(name)
		return pypiXMLValue{Kind: pypiXMLString, Str: s}, err
	case "int", "i4", "i8":
		s, err := p.text(name)
		if err != nil {
			return pypiXMLValue{}, err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return pypiXMLValue{}, fmt.Errorf("<%s> %q is not an integer", name, truncate(s, 32))
		}
		return pypiXMLValue{Kind: pypiXMLInt, Int: n}, nil
	case "boolean":
		s, err := p.text(name)
		if err != nil {
			return pypiXMLValue{}, err
		}
		switch strings.TrimSpace(s) {
		case "0":
			return pypiXMLValue{Kind: pypiXMLBool}, nil
		case "1":
			return pypiXMLValue{Kind: pypiXMLBool, Bool: true}, nil
		}
		return pypiXMLValue{}, fmt.Errorf("<boolean> %q is not 0 or 1", truncate(s, 32))
	case "nil":
		if err := p.expectEnd("nil"); err != nil {
			return pypiXMLValue{}, err
		}
		return pypiXMLValue{Kind: pypiXMLNil}, nil
	case "array":
		if err := p.expectStart("data"); err != nil {
			return pypiXMLValue{}, err
		}
		v := pypiXMLValue{Kind: pypiXMLArray}
		for {
			tok, err := p.element()
			if err != nil {
				return v, err
			}
			if e, ok := tok.(xml.EndElement); ok && e.Name.Local == "data" {
				break
			}
			if s, ok := tok.(xml.StartElement); !ok || s.Name.Local != "value" {
				return v, fmt.Errorf("want <value>, got %s", pypiDescribe(tok))
			}
			item, err := p.value(depth + 1)
			if err != nil {
				return v, err
			}
			v.Items = append(v.Items, item)
		}
		return v, p.expectEnd("array")
	case "struct":
		v := pypiXMLValue{Kind: pypiXMLStruct}
		for {
			tok, err := p.element()
			if err != nil {
				return v, err
			}
			if e, ok := tok.(xml.EndElement); ok && e.Name.Local == "struct" {
				return v, nil
			}
			if s, ok := tok.(xml.StartElement); !ok || s.Name.Local != "member" {
				return v, fmt.Errorf("want <member>, got %s", pypiDescribe(tok))
			}
			if err := p.expectStart("name"); err != nil {
				return v, err
			}
			n, err := p.text("name")
			if err != nil {
				return v, err
			}
			if err := p.expectStart("value"); err != nil {
				return v, err
			}
			mv, err := p.value(depth + 1)
			if err != nil {
				return v, err
			}
			v.Members = append(v.Members, pypiXMLMember{Name: n, Value: mv})
			if err := p.expectEnd("member"); err != nil {
				return v, err
			}
		}
	}
	return pypiXMLValue{}, fmt.Errorf("<%s> is not an XML-RPC type this feed reads", truncate(name, 32))
}

// pypiDescribe names a token for an error message.
func pypiDescribe(tok xml.Token) string {
	switch t := tok.(type) {
	case xml.StartElement:
		return "<" + truncate(t.Name.Local, 32) + ">"
	case xml.EndElement:
		return "</" + truncate(t.Name.Local, 32) + ">"
	case xml.CharData:
		return fmt.Sprintf("text %q", truncate(string(t), 32))
	}
	return fmt.Sprintf("%T", tok)
}

// --- releases -----------------------------------------------------------------

// Releases reads the project's simple page through the gated pipeline.
func (f *pypiFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	norm := ""
	if len(name) <= pypiMaxName {
		norm = locate.PipNormalize(name)
	}
	if !pypiValidName(norm) {
		return nil, Permanent(fmt.Errorf("%q is not a Python project name", truncate(name, 300)))
	}
	page := "/simple/" + norm + "/"
	body, err := f.k.read(ctx, page, pypiPageAccept, maxMetadataDoc)
	if err != nil {
		return nil, err
	}
	files, listed, err := locate.PipFiles(f.k.locateUpstream(), norm, page, locate.Document{Status: http.StatusOK, Body: body})
	if err != nil {
		return nil, Permanent(fmt.Errorf("the simple page of %s: %w", norm, err))
	}
	return pypiReleases(files, listed), nil
}

// pypiReleases groups a simple page's files by version.
func pypiReleases(files []locate.PipFile, listed []string) []Release {
	var distinct []string
	known := map[string]bool{}
	for _, pf := range files {
		if pf.Version != "" && !known[pf.Version] {
			known[pf.Version] = true
			distinct = append(distinct, pf.Version)
		}
	}
	spelling := pypiSpellings(listed, distinct)
	type acc struct {
		rel           Release
		files, yanked int
		paths         map[string]bool
	}
	byVersion := map[string]*acc{}
	var order []string
	for _, pf := range files {
		if pf.Path == "" || pf.Version == "" || !validArtifactPath(pf.Path) {
			continue
		}
		v := spelling[pf.Version]
		if !pypiValidVersion(v) {
			continue
		}
		a := byVersion[v]
		if a == nil {
			a = &acc{rel: Release{Version: v}, paths: map[string]bool{}}
			byVersion[v] = a
			order = append(order, v)
		}
		if a.paths[pf.Path] {
			continue
		}
		a.paths[pf.Path] = true
		a.files++
		if pf.Yanked {
			a.yanked++
		}
		if !pf.Uploaded.IsZero() && (a.rel.Published.IsZero() || pf.Uploaded.Before(a.rel.Published)) {
			a.rel.Published = pf.Uploaded.UTC()
		}
		a.rel.Artifacts = append(a.rel.Artifacts, Artifact{Path: pf.Path, Size: pf.Size})
	}
	rels := make([]Release, 0, len(order))
	for _, v := range order {
		a := byVersion[v]
		a.rel.Yanked = a.yanked == a.files
		rels = append(rels, a.rel)
	}
	orderReleases("pip", rels)
	return rels
}

// pypiSpellings maps each version a file name spells to the release's version
// as the page lists it (PEP 700's "versions": the spelling the changelog uses
// too, "1.0.0-rc1" for a wheel's "1.0.0rc1"), by PEP 440 equality. Versions the
// page does not list are grouped by PEP 440 equality under the spelling met
// first; one that is not PEP 440 stands for itself.
func pypiSpellings(listed, fileVersions []string) map[string]string {
	scheme, _ := versions.For("pip")
	type parsed struct {
		raw string
		v   versions.Version
		pos int
	}
	exact := map[string]bool{}
	var lp []parsed
	for i, s := range listed {
		if exact[s] || len(s) > pypiMaxVersion {
			continue
		}
		exact[s] = true
		if v, err := scheme.Parse(s); err == nil {
			lp = append(lp, parsed{raw: s, v: v, pos: i})
		}
	}
	sort.SliceStable(lp, func(i, j int) bool { return scheme.Compare(lp[i].v, lp[j].v) < 0 })
	out := make(map[string]string, len(fileVersions))
	var unlisted []parsed
	for i, fv := range fileVersions {
		if exact[fv] {
			out[fv] = fv
			continue
		}
		v, err := scheme.Parse(fv)
		if err != nil {
			out[fv] = fv
			continue
		}
		k := sort.Search(len(lp), func(k int) bool { return scheme.Compare(lp[k].v, v) >= 0 })
		if k < len(lp) && scheme.Compare(lp[k].v, v) == 0 {
			out[fv] = lp[k].raw
			continue
		}
		unlisted = append(unlisted, parsed{raw: fv, v: v, pos: i})
	}
	sort.SliceStable(unlisted, func(i, j int) bool { return scheme.Compare(unlisted[i].v, unlisted[j].v) < 0 })
	for i := 0; i < len(unlisted); {
		j, first := i, unlisted[i]
		for j < len(unlisted) && scheme.Compare(unlisted[j].v, unlisted[i].v) == 0 {
			if unlisted[j].pos < first.pos {
				first = unlisted[j]
			}
			j++
		}
		for k := i; k < j; k++ {
			out[unlisted[k].raw] = first.raw
		}
		i = j
	}
	return out
}
