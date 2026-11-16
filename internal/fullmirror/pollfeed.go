package fullmirror

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// This file drives the adapters of the registries that publish a complete
// index rather than a change feed (tier (b) of the catalog, Task 191): APT,
// YUM, Helm, conda, CRAN, Hex, the Homebrew JSON API, a Maven Indexer index,
// Open VSX's sitemap — and the listings that must be read whole at every pass
// (JSR's). An adapter supplies an indexSource, which reads its index into the
// records of a stored copy (snapshot.go); indexFeed does the rest:
//
//   - Bootstrap reads the index once, stores the copy and lists the copy's
//     packages, page by page. Its last batch's cursor names that copy, read
//     when the enumeration began: whatever was published since is in the
//     difference the first Changes reports.
//   - Changes reads the index again — conditionally: the source keeps the
//     validators of the copy it read last (an ETag, a Last-Modified, the
//     digests a signed release file lists) in the cursor, and a registry that
//     answers "not modified" costs one small request — stores the new copy
//     and reports its difference from the cursor's copy: the packages that
//     appeared, the versions added or changed, what is gone. A difference
//     larger than a batch is reported over several, each re-walking the two
//     copies, which stay until the engine has stored a cursor past them.
//   - Releases reads the newest copy, which the cursor of the batch being
//     worked on reached: the adapter turns a package's records into releases
//     (snapReleases), or reads the package's own metadata document where the
//     index names no files.
//
// The copy a cursor names must read back — exist, and match its digest — or
// the cursor is reported invalid and the registry enumerated again.

// indexPage is how many packages a Bootstrap batch lists, and how many
// differences a Changes batch reports.
const indexPage = 10_000

// indexMaxState bounds the validators a source keeps in the cursor, measured
// as the cursor encodes them (JSON escapes "<", ">" and "&" in six bytes): a
// cursor carries two states while a difference is reported over several
// batches, and must stay within maxCursorBytes.
const indexMaxState = 24 << 10

// indexStateSize is a state's size as the cursor encodes it.
func indexStateSize(state json.RawMessage) int {
	if len(state) == 0 {
		return 0
	}
	b, err := json.Marshal(state)
	if err != nil {
		return maxCursorBytes + 1
	}
	return len(b)
}

// indexSource reads one adapter's complete index.
type indexSource interface {
	// readIndex reads the index into b. prev is the state the previous read
	// returned (nil on the first read) and old the copy that read stored
	// (nil on the first): the source sends prev's validators with its
	// requests and answers Unchanged when the registry says nothing changed,
	// and it may copy the records of the parts of the index that did not
	// change from old (b.CopyFrom) instead of reading them again. A read that
	// fails leaves b to be discarded.
	readIndex(ctx context.Context, prev json.RawMessage, old *snapHeader, b *snapBuilder) (indexRead, error)
}

// indexRead is what a read of the index found.
type indexRead struct {
	// State is what the next read is conditioned on (validators, digests),
	// at most indexMaxState bytes of JSON; nil keeps the previous one.
	State json.RawMessage
	// Unchanged reports that the index has not changed since prev: b is
	// discarded and the cursor stays where it is.
	Unchanged bool
	// Head names the index's version (a release's date, a repomd revision)
	// and HeadTime its time, when the registry states them.
	Head     string
	HeadTime time.Time
}

// indexFeed implements Bootstrap and Changes over an indexSource; the adapter
// embeds it and adds Releases (with lookup).
type indexFeed struct {
	typ   string
	files files
	src   indexSource
	page  int

	mu      sync.Mutex
	headers map[string]*snapHeader
}

func newIndexFeed(typ string, env Env, src indexSource) *indexFeed {
	return &indexFeed{typ: typ, files: files{dir: env.Dir}, src: src, page: indexPage, headers: map[string]*snapHeader{}}
}

// indexMaxHead bounds the Head label kept in the cursor.
const indexMaxHead = 256

// indexCursor is the cursor of an indexFeed.
type indexCursor struct {
	Format string `json:"format"`
	// Snap is the digest of the copy the next read is diffed against, and
	// State the source's validators of the read that made it.
	Snap  string          `json:"snap"`
	State json.RawMessage `json:"state,omitempty"`
	// Listing marks Bootstrap's enumeration of Snap; After is the last
	// package listed ("" before the first) and Listed how many were.
	Listing bool   `json:"listing,omitempty"`
	After   string `json:"after,omitempty"`
	Listed  int    `json:"listed,omitempty"`
	// To is the newer copy of a difference being reported over several
	// batches, ToState its validators, and Skip how many differences were
	// reported.
	To      string          `json:"to,omitempty"`
	ToState json.RawMessage `json:"toState,omitempty"`
	Skip    int             `json:"skip,omitempty"`
	// Head and HeadTime are what the newest read said of the index.
	Head     string    `json:"head,omitempty"`
	HeadTime time.Time `json:"headTime,omitempty"`
}

func (c *indexCursor) cursorFormat() string { return c.Format }

func (f *indexFeed) format() string { return cursorFormat(f.typ, 1) }

// decode reads and checks a cursor.
func (f *indexFeed) decode(cursor string) (indexCursor, error) {
	var c indexCursor
	if err := decodeCursor(cursor, f.format(), &c); err != nil {
		return c, err
	}
	switch {
	case !snapIsDigest(c.Snap):
		return c, fmt.Errorf("%w: the %s cursor names no stored copy of the index", ErrCursorInvalid, f.typ)
	case c.To != "" && (!snapIsDigest(c.To) || c.Listing):
		return c, fmt.Errorf("%w: the %s cursor names no newer copy", ErrCursorInvalid, f.typ)
	case c.Skip < 0 || c.Listed < 0 || (c.Skip > 0 && c.To == "") || (!c.Listing && (c.After != "" || c.Listed != 0)):
		return c, fmt.Errorf("%w: the %s cursor's position is not one", ErrCursorInvalid, f.typ)
	case indexStateSize(c.State) > indexMaxState || indexStateSize(c.ToState) > indexMaxState || len(c.Head) > indexMaxHead:
		return c, fmt.Errorf("%w: the %s cursor's state is too large", ErrCursorInvalid, f.typ)
	}
	return c, nil
}

// header returns a stored copy's header, read once per process and file:
// a copy rewritten since (another replica, another version of the proxy) is
// read again.
func (f *indexFeed) header(digest string) (*snapHeader, error) {
	if !snapIsDigest(digest) {
		return nil, snapMissing(digest, errors.New("not the digest of a stored copy"))
	}
	st, err := os.Stat(f.files.path(snapName(digest)))
	if err != nil {
		return nil, snapFail(digest, err)
	}
	f.mu.Lock()
	h, ok := f.headers[digest]
	f.mu.Unlock()
	if ok && h.size == st.Size() && h.mod.Equal(st.ModTime()) {
		return h, nil
	}
	h, err = f.files.readSnapHeader(digest, f.typ)
	if err != nil {
		return nil, f.healed(err)
	}
	f.mu.Lock()
	if len(f.headers) >= 8 {
		for k := range f.headers {
			delete(f.headers, k)
		}
	}
	f.headers[digest] = h
	f.mu.Unlock()
	return h, nil
}

// healed removes the copy err reports damaged, if it reports one, so that the
// next poll finds it missing (the cursor that names it then starts the
// enumeration over, and a pointer to it is set right) instead of failing on
// it for ever. It returns err.
func (f *indexFeed) healed(err error) error {
	if digest, ok := snapDamagedDigest(err); ok && snapIsDigest(digest) && f.files.dir != "" {
		os.Remove(f.files.path(snapName(digest)))
		f.mu.Lock()
		delete(f.headers, digest)
		f.mu.Unlock()
	}
	return err
}

// copyError turns an error met reading a stored copy into what the engine
// should do: a copy missing or damaged invalidates the cursor that names it
// (a damaged one is removed); anything else — an I/O error, a copy rewritten
// while read — is retried.
func (f *indexFeed) copyError(err error) error {
	if errors.Is(err, errSnapInvalid) {
		return fmt.Errorf("%w: %v", ErrCursorInvalid, f.healed(err))
	}
	return err
}

// cursorCopy returns the header of a copy a cursor names.
func (f *indexFeed) cursorCopy(digest string) (*snapHeader, error) {
	h, err := f.header(digest)
	if err != nil {
		return nil, f.copyError(err)
	}
	return h, nil
}

// pointer returns the digest index-current.json names ("" when there is none).
func (f *indexFeed) pointer() string {
	var p struct {
		Snap string `json:"snap"`
	}
	if f.files.readJSON(snapCurrent, 4096, &p) != nil || !snapIsDigest(p.Snap) {
		return ""
	}
	return p.Snap
}

// setCurrent records the copy Releases reads: the newest one a batch came
// from.
func (f *indexFeed) setCurrent(digest string) error {
	return f.files.writeJSON(snapCurrent, map[string]string{"snap": digest})
}

// ensurePointer sets the pointer to digest unless it names it already: the
// copy of the batch about to be worked through. A pointer lost (a restore of
// the state directory file by file) or left at another copy is set right at
// every poll.
func (f *indexFeed) ensurePointer(digest string) error {
	if f.pointer() == digest {
		return nil
	}
	return f.setCurrent(digest)
}

// current returns the copy Releases reads.
func (f *indexFeed) current() (*snapHeader, error) {
	var p struct {
		Snap string `json:"snap"`
	}
	if err := f.files.readJSON(snapCurrent, 4096, &p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no copy of the %s index is kept yet: it is read at the next poll", f.typ)
		}
		return nil, fmt.Errorf("reading the pointer to the copy of the %s index (it is set again at the next poll): %w", f.typ, err)
	}
	h, err := f.header(p.Snap)
	if err != nil {
		return nil, fmt.Errorf("the copy of the %s index Releases reads: %w (the next poll reads the index again, or enumerates it again)", f.typ, err)
	}
	return h, nil
}

// lookup returns a package's records in the newest copy. A package the copy
// does not list is a Permanent error.
func (f *indexFeed) lookup(name string) ([]snapRecord, error) {
	if f.files.dir == "" {
		return nil, errValidationOnly
	}
	h, err := f.current()
	if err != nil {
		return nil, err
	}
	recs, err := f.files.snapLookup(h, name)
	if err != nil {
		return nil, fmt.Errorf("the copy of the %s index Releases reads: %w (the next poll reads the index again, or enumerates it again)", f.typ, f.healed(err))
	}
	if len(recs) == 0 {
		return nil, Permanent(fmt.Errorf("%s is not in the %s index", truncate(name, 200), f.typ))
	}
	return recs, nil
}

// prune removes the copies no cursor can name any more: every one but keep,
// the newest (another replica's, if it just took over) and the current one.
func (f *indexFeed) prune(keep ...string) {
	names := make([]string, 0, len(keep)+1)
	for _, k := range keep {
		if k != "" {
			names = append(names, snapName(k))
		}
	}
	var p struct {
		Snap string `json:"snap"`
	}
	if f.files.readJSON(snapCurrent, 4096, &p) == nil && snapIsDigest(p.Snap) {
		names = append(names, snapName(p.Snap))
	}
	f.files.pruneKeepingNewest(snapPrefix, 1, append(names, snapCurrent)...)
}

// read reads the index into a new copy.
func (f *indexFeed) read(ctx context.Context, prev json.RawMessage, old *snapHeader) (_ *snapHeader, rd indexRead, err error) {
	b := f.files.newSnapBuilder(f.typ)
	finished := false
	defer func() {
		// Also when the source panics: its spilled runs go.
		if !finished {
			b.Abort()
		}
	}()
	rd, err = f.src.readIndex(ctx, prev, old, b)
	if err != nil {
		if errors.Is(err, errSnapInvalid) {
			// The copy the source copied unchanged parts from does not
			// read: the cursor that names it cannot be continued.
			return nil, rd, fmt.Errorf("%w: %v", ErrCursorInvalid, f.healed(err))
		}
		return nil, rd, err
	}
	if rd.State != nil {
		if !json.Valid(rd.State) {
			return nil, rd, Permanent(fmt.Errorf("fullmirror: the %s index source returned a state that is not JSON", f.typ))
		}
		if n := indexStateSize(rd.State); n > indexMaxState {
			return nil, rd, Permanent(fmt.Errorf("fullmirror: the %s index source keeps %d bytes of state; at most %d fit the cursor", f.typ, n, indexMaxState))
		}
	}
	rd.Head = truncate(rd.Head, indexMaxHead)
	if rd.Unchanged {
		if old == nil {
			return nil, rd, fmt.Errorf("fullmirror: the %s index source reported no change without a previous copy", f.typ)
		}
		return nil, rd, nil
	}
	finished = true
	h, err := b.Finish()
	if err != nil {
		return nil, rd, fmt.Errorf("storing a copy of the %s index: %w", f.typ, err)
	}
	if h.Oversized > 0 {
		slog.Warn("fullmirror: packages that list more files than a package may are left out of the copy of the index and not followed",
			"type", f.typ, "packages", h.Oversized, "examples", strings.Join(h.OversizedNames, ", "),
			"maxFiles", snapMaxGroup, "maxBytes", snapMaxGroupBytes)
	}
	return h, rd, nil
}

// Bootstrap reads the index and lists its packages.
func (f *indexFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	if f.files.dir == "" {
		return Batch{}, errValidationOnly
	}
	if cursor != "" {
		c, err := f.decode(cursor)
		if err != nil {
			return Batch{}, err
		}
		if !c.Listing {
			return Batch{}, fmt.Errorf("%w: the %s cursor does not continue a listing", ErrCursorInvalid, f.typ)
		}
		h, err := f.cursorCopy(c.Snap)
		if err != nil {
			return Batch{}, err
		}
		if err := f.ensurePointer(c.Snap); err != nil {
			return Batch{}, err
		}
		return f.listPage(c, h)
	}
	h, rd, err := f.read(ctx, nil, nil)
	if err != nil {
		return Batch{}, err
	}
	if err := f.setCurrent(h.Digest); err != nil {
		return Batch{}, err
	}
	f.prune(h.Digest)
	c := indexCursor{Format: f.format(), Snap: h.Digest, State: rd.State, Listing: true, Head: rd.Head, HeadTime: rd.HeadTime}
	return f.listPage(c, h)
}

// listPage lists the next page of the copy's packages.
func (f *indexFeed) listPage(c indexCursor, h *snapHeader) (Batch, error) {
	names, more, err := f.files.snapListNames(h, c.After, f.page)
	if err != nil {
		return Batch{}, f.copyError(err)
	}
	items := make([]Coordinate, 0, len(names))
	for _, n := range names {
		items = append(items, Coordinate{Name: n})
	}
	c.Listed += len(names)
	b := Batch{Items: items, Head: c.Head, HeadTime: c.HeadTime, LagKnown: true}
	if rest := h.Names - c.Listed; rest > 0 {
		b.Lag = int64(rest)
	}
	if more {
		c.After = names[len(names)-1]
		b.More, b.Next = true, encodeCursor(&c)
		return b, nil
	}
	b.Lag = 0
	b.Next = encodeCursor(&indexCursor{Format: c.Format, Snap: c.Snap, State: c.State, Head: c.Head, HeadTime: c.HeadTime})
	return b, nil
}

// Changes reads the index again and reports its difference from the cursor's
// copy.
func (f *indexFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	if f.files.dir == "" {
		return Batch{}, errValidationOnly
	}
	c, err := f.decode(cursor)
	if err != nil {
		return Batch{}, err
	}
	if c.Listing {
		return Batch{}, fmt.Errorf("%w: the %s cursor continues a listing", ErrCursorInvalid, f.typ)
	}
	// The pointer as this poll found it: a poll that stores a new copy moves
	// it only from there (another replica polling at the same moment — a
	// lease changing hands — must not move it under that replica's batch).
	before := f.pointer()
	from, err := f.cursorCopy(c.Snap)
	if err != nil {
		return Batch{}, err
	}
	if c.To != "" {
		to, err := f.cursorCopy(c.To)
		if err != nil {
			return Batch{}, err
		}
		f.prune(c.Snap, c.To)
		if err := f.ensurePointer(c.To); err != nil {
			return Batch{}, err
		}
		return f.diffPage(ctx, c, from, to)
	}
	f.prune(c.Snap)
	h, rd, err := f.read(ctx, c.State, from)
	if err != nil {
		return Batch{}, err
	}
	state := c.State
	if rd.State != nil {
		state = rd.State
	}
	if rd.Head != "" || !rd.HeadTime.IsZero() {
		c.Head, c.HeadTime = rd.Head, rd.HeadTime
	}
	if h == nil || h.Digest == c.Snap {
		// Nothing changed; the validators may have.
		c.State = state
		if err := f.ensurePointer(c.Snap); err != nil {
			return Batch{}, err
		}
		return Batch{Next: encodeCursor(&c), Head: c.Head, HeadTime: c.HeadTime, LagKnown: true}, nil
	}
	if now := f.pointer(); now != before {
		return Batch{}, fmt.Errorf("fullmirror: the copy of the %s index Releases reads was moved while this poll read the index (another replica polled); the poll is retried", f.typ)
	}
	if err := f.setCurrent(h.Digest); err != nil {
		return Batch{}, err
	}
	f.prune(c.Snap, h.Digest)
	// The cursor's State stays with Snap until the difference is reported.
	c.To, c.ToState, c.Skip = h.Digest, state, 0
	return f.diffPage(ctx, c, from, h)
}

// diffPage reports the next page of the difference between two copies.
func (f *indexFeed) diffPage(ctx context.Context, c indexCursor, from, to *snapHeader) (Batch, error) {
	a, err := f.files.openSnapshot(from, true)
	if err != nil {
		return Batch{}, f.copyError(err)
	}
	defer a.Close()
	b, err := f.files.openSnapshot(to, true)
	if err != nil {
		return Batch{}, f.copyError(err)
	}
	defer b.Close()
	var items []Coordinate
	n, more := 0, false
	err = snapDiffContext(ctx, a, b, func(co Coordinate) bool {
		if n >= c.Skip {
			if len(items) == f.page {
				more = true
				return false
			}
			items = append(items, co)
		}
		n++
		return true
	})
	if err != nil {
		if ctx.Err() != nil {
			return Batch{}, err
		}
		return Batch{}, f.copyError(err)
	}
	if c.Skip > n {
		return Batch{}, fmt.Errorf("%w: the cursor is past the end of the difference", ErrCursorInvalid)
	}
	out := Batch{Items: items, Head: c.Head, HeadTime: c.HeadTime}
	if more {
		c.Skip += len(items)
		out.More, out.Next = true, encodeCursor(&c)
		return out, nil
	}
	out.LagKnown = true
	out.Next = encodeCursor(&indexCursor{Format: c.Format, Snap: c.To, State: c.ToState, Head: c.Head, HeadTime: c.HeadTime})
	return out, nil
}

// httpValidators are the validators of a document read over HTTP, kept in a
// source's state so that the next read is conditional.
type httpValidators struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
}

// validatorsOf reads a response's validators (bounded, without control
// characters: they go back into a request header).
func validatorsOf(resp *http.Response) httpValidators {
	clean := func(v string) string {
		v = strings.TrimSpace(v)
		if len(v) > 512 || strings.ContainsAny(v, "\x00\r\n") {
			return ""
		}
		return v
	}
	return httpValidators{ETag: clean(resp.Header.Get("ETag")), LastModified: clean(resp.Header.Get("Last-Modified"))}
}

// set adds the conditional headers to a request's headers.
func (v httpValidators) set(h http.Header) {
	if v.ETag != "" {
		h.Set("If-None-Match", v.ETag)
	}
	if v.LastModified != "" {
		h.Set("If-Modified-Since", v.LastModified)
	}
}

// unixTime converts Unix seconds to a time (UTC).
func unixTime(s int64) time.Time { return time.Unix(s, 0).UTC() }
