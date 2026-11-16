package fullmirror

import (
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
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/hackage"
)

// hackage follows the repository's incremental index, 01-index.tar.
//
// The index is a tar archive of every package description ever uploaded,
// appended in upload order and never rewritten: "<name>/<version>/<name>.cabal"
// for each upload and revision, "<name>/<version>/package.json" (the TUF target
// metadata of the sdist) once per upload, "<name>/preferred-versions" for each
// change of a package's preferred versions. New entries overwrite the two zero
// blocks that end the archive. cabal-install updates its copy with a Range
// request from the end it holds; Changes does the same: the cursor is the
// offset where the next entry starts, with the offset and SHA-256 of the last
// entry's 512-byte header. Changes asks for the index from that header on,
// checks the header's hash (an index that does not carry the same bytes there
// is not the one the cursor was taken from: the cursor is invalid), and reads
// the entries after it up to the end-of-archive blocks — at most hackageWindow
// bytes per poll. Each package.json is an upload: the change Name@Version. A
// revision changes only the .cabal file in the index, not the sdist, and is
// not a change to mirror.
//
// Bootstrap takes its cursor from the end of the index (a HEAD for its
// length, a Range request for its last bytes, and the chain of headers that
// ends at the end-of-archive blocks), then lists every package name from
// `/packages/` (JSON) and continues from that cursor.
//
// Releases reads `/package/<name>/preferred` (JSON: "normal-version" and
// "deprecated-version", newest first) directly from the repository: the
// hackage backend serves neither that path nor `/packages/` (its classify
// takes only the index, the TUF files and the per-version paths), and it does
// not forward Accept, so neither document can be read through the proxy. A
// deprecated version is Yanked. Each version's file is the sdist in the short
// form cabal-install and Stack request, "/package/<name>-<version>.tar.gz"
// (hackage.SdistPath: the backend caches each spelling of an sdist path under
// its own key). The repository states no size or upload time there.
//
// The index is always read from the upstream itself — hackage.haskell.org, a
// self-hosted hackage-server or a static mirror (hackage-mirror-tool) all
// serve it — so that what the feed reports is what the sdists come from: a
// mirror syncs periodically, and an upload the public index already shows
// would be asked of it before it holds the file. A static mirror does not
// serve the two JSON documents (`/packages/` and the preferred versions); for
// such an upstream the feed option "url" names a hackage-server to read them
// from (the public one).

const hackageFeedVersion = 1

// Bounds on what the hackage feed reads.
const (
	// hackageWindow is the most bytes of the index one Changes reads (the
	// cursor's entry and the entries after it).
	hackageWindow = 32 << 20
	// hackageMaxEntry bounds one index entry: a package description is a few
	// kilobytes. Two entries of this size always fit in hackageWindow, so a
	// poll always gets past the cursor's entry.
	hackageMaxEntry = 8 << 20
	// hackageMaxEntries bounds the entries one walk returns.
	hackageMaxEntries = 100_000
	// hackagePage is how many package names one Bootstrap batch carries.
	hackagePage = 50_000
	// hackageMaxPreferred bounds a package's preferred-versions document.
	hackageMaxPreferred = 4 << 20
	// hackageMaxTailCandidates bounds the header chains tried in the end of
	// the index.
	hackageMaxTailCandidates = 256
)

// hackageTails are the lengths of the end of the index Bootstrap reads to find
// the last entry, the next tried when the last entry starts before the
// shorter one.
var hackageTails = []int64{64 << 10, 1 << 20, 8 << 20}

type hackageFeed struct {
	k    kit
	feed *url.URL
	// window, tails and page are the bounds above (the tests shrink them).
	window int64
	tails  []int64
	page   int
	// short counts consecutive polls that found the index shorter than the
	// cursor: a CDN copy can be a minute behind, so only a lasting one is
	// taken for a replaced index.
	short int
}

// hackageShortPolls is how many consecutive polls must find the index
// shorter than the cursor before the cursor is given up.
const hackageShortPolls = 3

// shortIndex answers an index shorter than the cursor: retried while it may
// be a cache behind, the cursor given up once it lasts.
func (f *hackageFeed) shortIndex(err error) error {
	if f.short++; f.short < hackageShortPolls {
		return fmt.Errorf("the Hackage index served is shorter than what the cursor has read (%d of %d polls before the index is taken for replaced; a cache may be behind): %v", f.short, hackageShortPolls, err)
	}
	f.short = 0
	return err
}

func hackageNewFeed(env Env) (Feed, error) {
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
	return &hackageFeed{k: k, feed: feed, window: hackageWindow, tails: hackageTails, page: hackagePage}, nil
}

func init() { Register("hackage", hackageNewFeed) }

// hackageCursor is the hackage feed's position in the index.
type hackageCursor struct {
	Format string `json:"format"`
	// End is where the entry after the last one read starts: the index's
	// end-of-archive blocks when it was read to its end.
	End int64 `json:"end"`
	// Header is the offset of the last entry's 512-byte header and SHA256
	// that header's hash, which Changes checks before it trusts End. Header
	// is -1 (and End 0) for an index that had no entry.
	Header int64  `json:"header"`
	SHA256 string `json:"sha256,omitempty"`
	// Listing is set while Bootstrap lists the package names; After is the
	// last name listed.
	Listing bool   `json:"listing,omitempty"`
	After   string `json:"after,omitempty"`
}

func (c *hackageCursor) cursorFormat() string { return c.Format }

func (f *hackageFeed) format() string { return cursorFormat("hackage", hackageFeedVersion) }

// decode reads a cursor and checks that its offsets can be an entry's.
func (f *hackageFeed) decode(cursor string, c *hackageCursor) error {
	if err := decodeCursor(cursor, f.format(), c); err != nil {
		return err
	}
	ok := c.End >= 0 && c.End%512 == 0
	if c.Header == -1 {
		ok = ok && c.End == 0 && c.SHA256 == ""
	} else {
		ok = ok && c.Header >= 0 && c.Header%512 == 0 && c.Header+512 <= c.End && hackageLowerHex(c.SHA256, 64)
	}
	if c.After != "" && (!c.Listing || !hackageIsName(c.After)) {
		ok = false
	}
	if !ok {
		return fmt.Errorf("%w: the hackage cursor names no index position", ErrCursorInvalid)
	}
	return nil
}

func (f *hackageFeed) indexURL() string { return join(f.k.upstream, "01-index.tar") }

// Bootstrap lists every package name, then continues from the end the index
// had when the listing began.
func (f *hackageFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	var c hackageCursor
	if cursor == "" {
		start, err := f.tailCursor(ctx)
		if err != nil {
			return Batch{}, fmt.Errorf("reading the end of the Hackage index: %w", err)
		}
		c = start
		c.Listing = true
	} else if err := f.decode(cursor, &c); err != nil {
		return Batch{}, err
	} else if !c.Listing {
		return Batch{}, fmt.Errorf("%w: the hackage cursor does not continue a listing", ErrCursorInvalid)
	}
	body, _, err := f.k.get(ctx, join(f.feed, "packages/"), http.Header{"Accept": {"application/json"}}, maxFeedPage)
	if err != nil {
		return Batch{}, fmt.Errorf("listing the Hackage packages: %w", err)
	}
	all, err := hackageParsePackages(body)
	if err != nil {
		return Batch{}, Permanent(fmt.Errorf("listing the Hackage packages: %w", err))
	}
	i := 0
	if c.After != "" {
		i = sort.SearchStrings(all, c.After)
		if i < len(all) && all[i] == c.After {
			i++
		}
	}
	page, _, more := pageItems(all, i, f.page)
	b := Batch{Head: strconv.FormatInt(c.End, 10)}
	for _, n := range page {
		b.Items = append(b.Items, Coordinate{Name: n})
	}
	next := hackageCursor{Format: f.format(), End: c.End, Header: c.Header, SHA256: c.SHA256}
	if more {
		next.Listing, next.After = true, page[len(page)-1]
		b.More = true
	}
	b.Next = encodeCursor(&next)
	return b, nil
}

// Changes reads the entries appended to the index after the cursor's.
func (f *hackageFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	var c hackageCursor
	if err := f.decode(cursor, &c); err != nil {
		return Batch{}, err
	}
	if c.Listing {
		return Batch{}, fmt.Errorf("%w: the hackage cursor continues a listing", ErrCursorInvalid)
	}
	from := c.Header
	if from < 0 {
		from = 0
	}
	r, err := f.readRange(ctx, from, from+f.window-1)
	if errors.Is(err, hackageErrBeyondEnd) {
		if c.Header < 0 {
			return Batch{Next: cursor, LagKnown: true}, nil // the index is still empty
		}
		return Batch{}, f.shortIndex(fmt.Errorf("%w: the Hackage index ends before offset %d, where the cursor's entry starts: it is not the index the cursor was taken from", ErrCursorInvalid, from))
	}
	if err != nil {
		return Batch{}, fmt.Errorf("reading the Hackage index: %w", err)
	}
	if c.Header >= 0 {
		if len(r.data) < 512 {
			return Batch{}, f.shortIndex(fmt.Errorf("%w: the Hackage index ends inside the cursor's entry at offset %d", ErrCursorInvalid, c.Header))
		}
		sum := sha256.Sum256(r.data[:512])
		if hex.EncodeToString(sum[:]) != c.SHA256 {
			return Batch{}, fmt.Errorf("%w: the Hackage index does not hold the cursor's entry at offset %d: it is not the index the cursor was taken from", ErrCursorInvalid, c.Header)
		}
		_, size, _, _, ok := hackageHeader(r.data[:512])
		if !ok || c.Header+512+hackagePadded(size) != c.End {
			return Batch{}, fmt.Errorf("%w: the cursor's entry at offset %d does not end at %d", ErrCursorInvalid, c.Header, c.End)
		}
		if r.total < c.End {
			return Batch{}, f.shortIndex(fmt.Errorf("%w: the Hackage index is %d bytes long, shorter than the %d the cursor has read", ErrCursorInvalid, r.total, c.End))
		}
		f.short = 0
	}
	entries, _, atEnd, err := hackageWalk(r.data, r.first, c.End, hackageMaxEntries)
	if err != nil {
		return Batch{}, Permanent(fmt.Errorf("reading the Hackage index: %w", err))
	}
	readToEnd := r.first+int64(len(r.data)) >= r.total
	if !atEnd {
		if readToEnd {
			return Batch{}, fmt.Errorf("reading the Hackage index: it ends at %d bytes without its end-of-archive blocks (being rewritten?)", r.total)
		}
		if len(entries) == 0 {
			return Batch{}, Permanent(fmt.Errorf("reading the Hackage index: the entry at offset %d does not fit in %d bytes", c.End, f.window))
		}
	}
	b := Batch{Head: strconv.FormatInt(r.total, 10), HeadTime: r.modified, More: !atEnd}
	next := hackageCursor{Format: f.format(), End: c.End, Header: c.Header, SHA256: c.SHA256}
	if len(entries) > 0 {
		last := entries[len(entries)-1]
		sum := sha256.Sum256(r.data[last.off-r.first : last.off-r.first+512])
		next = hackageCursor{Format: f.format(), End: last.end, Header: last.off, SHA256: hex.EncodeToString(sum[:])}
		if last.mtime > 0 {
			b.CursorTime = time.Unix(last.mtime, 0).UTC()
		}
	}
	b.Next = encodeCursor(&next)
	b.Items = hackageUploads(entries)
	if atEnd {
		b.LagKnown = true
	}
	return b, nil
}

// hackageUploads maps the index's package.json entries to their uploads, each
// once, in index order.
func hackageUploads(entries []hackageEntry) []Coordinate {
	var out []Coordinate
	seen := map[Coordinate]bool{}
	for _, e := range entries {
		if e.typ != '0' && e.typ != 0 {
			continue
		}
		parts := strings.Split(e.name, "/")
		if len(parts) != 3 || parts[2] != "package.json" || !hackageIsName(parts[0]) || !hackageIsVersion(parts[1]) {
			continue
		}
		if _, ok := hackage.SdistPath(parts[0], parts[1]); !ok {
			continue
		}
		c := Coordinate{Name: parts[0], Version: parts[1]}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// hackageErrBeyondEnd reports a Range the index does not reach (416).
var hackageErrBeyondEnd = errors.New("the range starts beyond the end of the index")

// hackageRange is a part of the index a Range request returned.
type hackageRange struct {
	data     []byte
	first    int64 // the offset of data[0] in the index
	total    int64 // the index's length
	modified time.Time
}

// indexLength reads the index's length with a HEAD request.
func (f *hackageFeed) indexLength(ctx context.Context) (int64, error) {
	resp, err := f.k.do(ctx, http.MethodHead, f.indexURL(), nil, http.Header{"Accept-Encoding": {"identity"}})
	if err != nil {
		return 0, err
	}
	defer drain(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return 0, httpStatusError(f.indexURL(), resp)
	}
	if resp.ContentLength < 0 {
		return 0, Permanent(fmt.Errorf("%s states no length", f.indexURL()))
	}
	return resp.ContentLength, nil
}

// readRange fetches bytes [first, last] of the index; the server ends the
// range at the index's end.
func (f *hackageFeed) readRange(ctx context.Context, first, last int64) (hackageRange, error) {
	u := f.indexURL()
	// identity: a compressed answer would not carry the index's offsets.
	hdr := http.Header{"Range": {fmt.Sprintf("bytes=%d-%d", first, last)}, "Accept-Encoding": {"identity"}}
	resp, err := f.k.do(ctx, http.MethodGet, u, nil, hdr)
	if err != nil {
		return hackageRange{}, err
	}
	defer drain(resp.Body)
	r := hackageRange{first: first}
	if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		r.modified = t.UTC()
	}
	switch resp.StatusCode {
	case http.StatusPartialContent:
		start, end, total, ok := hackageContentRange(resp.Header.Get("Content-Range"))
		if !ok || start != first || end < start || end > last || total <= end {
			return hackageRange{}, Permanent(fmt.Errorf("%s answered bytes=%d-%d with Content-Range %q", u, first, last, truncate(resp.Header.Get("Content-Range"), 64)))
		}
		r.total = total
		if r.data, err = readLimited(resp.Body, end-start+1); err != nil {
			return hackageRange{}, fmt.Errorf("reading %s: %w", u, err)
		}
		if int64(len(r.data)) != end-start+1 {
			return hackageRange{}, fmt.Errorf("reading %s: %d of %d bytes", u, len(r.data), end-start+1)
		}
	case http.StatusRequestedRangeNotSatisfiable:
		return hackageRange{}, hackageErrBeyondEnd
	case http.StatusOK:
		// A server that ignores Range sends the whole index: usable only
		// when the request asked for all of it.
		if first != 0 || resp.ContentLength < 0 || resp.ContentLength > last+1 {
			return hackageRange{}, Permanent(fmt.Errorf("%s ignores Range requests: the index cannot be followed", u))
		}
		r.total = resp.ContentLength
		if r.data, err = readLimited(resp.Body, r.total); err != nil {
			return hackageRange{}, fmt.Errorf("reading %s: %w", u, err)
		}
		if int64(len(r.data)) != r.total {
			return hackageRange{}, fmt.Errorf("reading %s: %d of %d bytes", u, len(r.data), r.total)
		}
	default:
		return hackageRange{}, httpStatusError(u, resp)
	}
	return r, nil
}

// hackageContentRange reads "bytes <first>-<last>/<total>".
func hackageContentRange(v string) (first, last, total int64, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(v), "bytes ")
	if !found {
		return 0, 0, 0, false
	}
	span, size, found := strings.Cut(rest, "/")
	if !found {
		return 0, 0, 0, false
	}
	a, b, found := strings.Cut(span, "-")
	if !found {
		return 0, 0, 0, false
	}
	var err1, err2, err3 error
	first, err1 = strconv.ParseInt(a, 10, 64)
	last, err2 = strconv.ParseInt(b, 10, 64)
	total, err3 = strconv.ParseInt(size, 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || first < 0 || last < first || total <= last {
		return 0, 0, 0, false
	}
	return first, last, total, true
}

// tailCursor reads the end of the index and returns the cursor of an index
// read to its end.
func (f *hackageFeed) tailCursor(ctx context.Context) (hackageCursor, error) {
	length, err := f.indexLength(ctx)
	if err != nil {
		return hackageCursor{}, err
	}
	empty := hackageCursor{Format: f.format(), End: 0, Header: -1}
	if length == 0 {
		return empty, nil
	}
	if length%512 != 0 {
		return hackageCursor{}, Permanent(fmt.Errorf("%s is %d bytes long, not a tar archive", f.indexURL(), length))
	}
	for _, n := range f.tails {
		first := length - n
		if first < 0 {
			first = 0
		}
		first -= first % 512
		r, err := f.readRange(ctx, first, length-1)
		if err != nil {
			return hackageCursor{}, err
		}
		if r.total != length {
			return hackageCursor{}, fmt.Errorf("the index changed from %d to %d bytes while its end was read; trying again", length, r.total)
		}
		if c, ok := hackageTailCursor(r.data, r.first, r.total); ok {
			if c.Header == -1 {
				return empty, nil
			}
			c.Format = f.format()
			return c, nil
		}
		if first == 0 {
			break
		}
	}
	return hackageCursor{}, Permanent(fmt.Errorf("no chain of tar headers ends at the end-of-archive blocks of %s", f.indexURL()))
}

// hackageTailCursor finds the last entry of an index whose last bytes buf
// holds (buf starts at offset base and runs to the index's end, total): the
// first header in buf from which the chain of entries leads to the
// end-of-archive blocks — zeros to the end, at least two blocks of them. An
// index of zeros only (base 0) is an empty index: Header -1.
//
// A chain is determined by the block it starts at, so a block a failed chain
// went through fails every chain that reaches it: each block is visited
// once, and the search is linear in buf whatever buf holds.
func hackageTailCursor(buf []byte, base, total int64) (hackageCursor, bool) {
	if base < 0 || base%512 != 0 || base+int64(len(buf)) != total || len(buf)%512 != 0 {
		return hackageCursor{}, false
	}
	n := len(buf) / 512
	// zeroFrom[i]: blocks i… are all zero.
	zeroFrom := make([]bool, n+1)
	zeroFrom[n] = true
	for i := n - 1; i >= 0; i-- {
		zeroFrom[i] = zeroFrom[i+1] && hackageZero(buf[i*512:(i+1)*512])
	}
	if base == 0 && zeroFrom[0] {
		return hackageCursor{End: 0, Header: -1}, true
	}
	dead := make([]bool, n)
	var path []int
	tried := 0
	for i := 0; i < n && tried < hackageMaxTailCandidates; i++ {
		if dead[i] {
			continue
		}
		if _, _, _, _, ok := hackageHeader(buf[i*512 : (i+1)*512]); !ok {
			continue
		}
		tried++
		path = path[:0]
		last := -1
		for j := i; j < n && !dead[j]; {
			path = append(path, j)
			blk := buf[j*512 : (j+1)*512]
			if zeroFrom[j] {
				if last >= 0 && n-j >= 2 {
					sum := sha256.Sum256(buf[last*512 : (last+1)*512])
					return hackageCursor{End: base + int64(j)*512, Header: base + int64(last)*512, SHA256: hex.EncodeToString(sum[:])}, true
				}
				break
			}
			_, size, _, _, ok := hackageHeader(blk)
			if !ok || size > hackageMaxEntry {
				break
			}
			last = j
			j += 1 + int(hackagePadded(size)/512)
		}
		for _, k := range path {
			dead[k] = true
		}
	}
	return hackageCursor{}, false
}

// hackageEntry is one entry of the index.
type hackageEntry struct {
	off   int64 // the offset of its header
	end   int64 // the offset after its data, padded to a block
	name  string
	mtime int64
	typ   byte
}

// hackageWalk reads the entries of the index from offset from on, in buf
// (which holds the index from offset base). It stops at the end-of-archive
// block (atEnd, stop its offset) or before the first entry that does not lie
// wholly within buf (stop its header's offset). A block that is neither is an
// error.
func hackageWalk(buf []byte, base, from int64, maxEntries int) (entries []hackageEntry, stop int64, atEnd bool, err error) {
	if from < base || (from-base)%512 != 0 {
		return nil, from, false, fmt.Errorf("offset %d is not a block of the part read from %d", from, base)
	}
	pos := from
	for {
		rel := pos - base
		if rel+512 > int64(len(buf)) {
			return entries, pos, false, nil
		}
		blk := buf[rel : rel+512]
		if hackageZero(blk) {
			return entries, pos, true, nil
		}
		name, size, mtime, typ, ok := hackageHeader(blk)
		if !ok {
			return entries, pos, false, fmt.Errorf("the block at offset %d is not a tar header", pos)
		}
		if size > hackageMaxEntry {
			return entries, pos, false, fmt.Errorf("the entry at offset %d is %d bytes long; at most %d are read", pos, size, hackageMaxEntry)
		}
		end := pos + 512 + hackagePadded(size)
		if end-base > int64(len(buf)) {
			return entries, pos, false, nil
		}
		if len(entries) >= maxEntries {
			return entries, pos, false, nil
		}
		entries = append(entries, hackageEntry{off: pos, end: end, name: name, mtime: mtime, typ: typ})
		pos = end
	}
}

// hackagePadded rounds a size up to whole blocks.
func hackagePadded(size int64) int64 { return (size + 511) &^ 511 }

// hackageZero reports whether b is all zero bytes.
func hackageZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// hackageHeader parses a ustar (or GNU tar) header block: the entry's path
// (the prefix field joined to the name), size, modification time and type. ok
// is false for a block that is not one — no magic, a checksum that does not
// match, a size that is not octal.
func hackageHeader(b []byte) (name string, size, mtime int64, typ byte, ok bool) {
	if len(b) != 512 {
		return "", 0, 0, 0, false
	}
	magic := string(b[257:265])
	if magic != "ustar\x0000" && magic != "ustar  \x00" {
		return "", 0, 0, 0, false
	}
	sum, okSum := hackageOctal(b[148:156])
	if !okSum {
		return "", 0, 0, 0, false
	}
	var unsigned int64
	for i, c := range b {
		if i >= 148 && i < 156 {
			c = ' '
		}
		unsigned += int64(c)
	}
	if unsigned != sum {
		return "", 0, 0, 0, false
	}
	if size, ok = hackageOctal(b[124:136]); !ok {
		return "", 0, 0, 0, false
	}
	if mtime, ok = hackageOctal(b[136:148]); !ok {
		mtime = 0
	}
	name = hackageCString(b[0:100])
	if magic == "ustar\x0000" {
		if prefix := hackageCString(b[345:500]); prefix != "" {
			name = prefix + "/" + name
		}
	}
	return name, size, mtime, b[156], true
}

// hackageOctal reads a tar numeric field: octal digits, padded with spaces
// or NULs.
func hackageOctal(f []byte) (int64, bool) {
	s := strings.Trim(string(f), " \x00")
	if s == "" || len(s) > 12 {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '7' {
			return 0, false
		}
		n = n<<3 | int64(s[i]-'0')
	}
	return n, true
}

// hackageCString reads a NUL-terminated field.
func hackageCString(f []byte) string {
	if i := bytes.IndexByte(f, 0); i >= 0 {
		f = f[:i]
	}
	return string(f)
}

// hackageParsePackages reads `/packages/` as JSON — [{"packageName": …}] — and
// returns the valid names, sorted, each once.
func hackageParsePackages(body []byte) ([]string, error) {
	var doc []struct {
		PackageName string `json:"packageName"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("the package list is not the JSON document expected: %w", err)
	}
	if doc == nil {
		return nil, fmt.Errorf("the package list is not a list")
	}
	seen := make(map[string]bool, len(doc))
	out := make([]string, 0, len(doc))
	for _, p := range doc {
		if hackageIsName(p.PackageName) && !seen[p.PackageName] {
			seen[p.PackageName] = true
			out = append(out, p.PackageName)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Releases reads the package's preferred versions from the repository.
func (f *hackageFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	if !hackageIsName(name) {
		return nil, Permanent(fmt.Errorf("%q is not a Hackage package name", name))
	}
	body, _, err := f.k.get(ctx, join(f.feed, "package/"+name+"/preferred"), http.Header{"Accept": {"application/json"}}, hackageMaxPreferred)
	if err != nil {
		return nil, err
	}
	vers, err := hackageParsePreferred(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the preferred versions of %s: %w", name, err))
	}
	rels := make([]Release, 0, len(vers))
	for _, v := range vers {
		p, ok := hackage.SdistPath(name, v.version)
		if !ok {
			continue
		}
		rels = append(rels, Release{Version: v.version, Yanked: v.deprecated, Artifacts: []Artifact{{Path: p}}})
	}
	if len(rels) == 0 {
		return nil, Permanent(fmt.Errorf("the preferred versions of %s name no version the proxy serves", name))
	}
	return rels, nil
}

// hackageVersion is one version of a preferred-versions document.
type hackageVersion struct {
	version    string
	deprecated bool
}

// hackageParsePreferred reads `/package/<name>/preferred`: an object whose
// "<status>-version" members list versions ("normal-version",
// "deprecated-version"). Every listed version is served; deprecated ones are
// marked. The versions come back oldest first by Hackage's version order.
func hackageParsePreferred(body []byte) ([]hackageVersion, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("not the JSON document expected: %w", err)
	}
	if doc == nil {
		return nil, fmt.Errorf("not an object")
	}
	status := map[string]bool{}
	lists := 0
	for key, raw := range doc {
		if !strings.HasSuffix(key, "-version") {
			continue
		}
		var vs []string
		if err := json.Unmarshal(raw, &vs); err != nil {
			return nil, fmt.Errorf("%q is not a list of versions", truncate(key, 64))
		}
		lists++
		for _, v := range vs {
			if hackageIsVersion(v) {
				status[v] = status[v] || key == "deprecated-version"
			}
		}
	}
	if lists == 0 {
		return nil, fmt.Errorf("it lists no versions")
	}
	out := make([]hackageVersion, 0, len(status))
	for v, dep := range status {
		out = append(out, hackageVersion{version: v, deprecated: dep})
	}
	sort.Slice(out, func(i, j int) bool { return hackageCompareVersions(out[i].version, out[j].version) < 0 })
	return out, nil
}

// hackageIsName reports whether s is a Hackage package name: components of
// ASCII letters and digits joined by "-", each with a letter (Cabal's rule).
func hackageIsName(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, comp := range strings.Split(s, "-") {
		if comp == "" {
			return false
		}
		letter := false
		for i := 0; i < len(comp); i++ {
			c := comp[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
				letter = true
			case c >= '0' && c <= '9':
			default:
				return false
			}
		}
		if !letter {
			return false
		}
	}
	return true
}

// hackageIsVersion reports whether s is a package version: dot-separated
// decimal numbers ("0.4.2.4").
func hackageIsVersion(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, comp := range strings.Split(s, ".") {
		if comp == "" || len(comp) > 9 {
			return false
		}
		for i := 0; i < len(comp); i++ {
			if comp[i] < '0' || comp[i] > '9' {
				return false
			}
		}
	}
	return true
}

// hackageCompareVersions orders two versions hackageIsVersion accepts by their
// numeric components ("1.10" after "1.9", "1.0" after "1").
func hackageCompareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, _ := strconv.Atoi(as[i])
		y, _ := strconv.Atoi(bs[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return strings.Compare(a, b)
}

// hackageLowerHex reports whether s is n lower-case hex digits.
func hackageLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}
