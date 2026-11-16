package fullmirror

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
)

// nuget follows a NuGet v3 feed's catalog.
//
// The catalog (`Catalog/3.0.0` in the service index) is an append-only log of
// every package operation: an index of pages, a page a set of leaves, a leaf
// a `PackageDetails` (a push, a listing change, a deprecation) or a
// `PackageDelete` of one package version, stamped with the time of the commit
// that wrote it. Neither the index's pages nor a page's leaves are in order,
// and the leaves of one commit share its timestamp. Changes reads the pages
// whose commitTimeStamp is newer than the cursor — the commit timestamp
// processed last — and reports their newer leaves in commit order: a version
// pushed or edited by name and version, a deleted one as Deleted. The cursor
// moves to the last commit the batch holds in full, so a batch never ends
// inside a commit; a leaf delivered twice is harmless. A cursor newer than the
// catalog's last commit means the catalog was rebuilt or rewound, and a
// catalog at another URL is another catalog: either way the cursor is
// reported invalid and the feed is enumerated again.
//
// Bootstrap replays the catalog from its first page. The list of pages, as the
// index stood when the replay began, is kept in Env.Dir (the index runs to
// megabytes and is read once per replay); each batch reads the next pages and
// reports the packages they name once each, by name only — the engine then
// considers every version its policy keeps — and the last batch continues
// with the commit the index stood at when the replay began. A package an
// earlier batch of the same replay reported is not reported again while the
// process runs; after a restart it may be, which costs a metadata read.
//
// Releases reads the package's version list from the flat container (the
// service index's `PackageBaseAddress/3.0.0`), both through the gated
// pipeline as a client reads them, and takes each version's .nupkg path from
// repos/locate's NuGet locator, which maps the base address the backend
// rewrote into the service index. The flat container lists unlisted versions
// like listed ones (only the registration documents tell them apart), so
// they are mirrored alike; it states neither sizes nor dates.
//
// The catalog's location comes from the upstream's own service index
// (`<url>/v3/index.json`), read at the first poll; the feed option "url"
// names a catalog index instead. Not every package source implements the
// catalog: nuget.org does (outside China), Artifactory, Nexus, Azure
// Artifacts and GitHub Packages do not, and an upstream whose service index
// names none cannot be followed unless "url" names a catalog that covers it.

const nugetFeedVersion = 1

const (
	// nugetServiceIndexPath is where a v3 feed serves its service index.
	nugetServiceIndexPath = "/v3/index.json"
	// nugetCatalogType and nugetBaseAddressType are the service-index
	// resources the feed uses.
	nugetCatalogType     = "Catalog/3.0.0"
	nugetBaseAddressType = "PackageBaseAddress/3.0.0"
	// nugetPagesPerBatch and nugetLeavesPerBatch bound one batch: no more
	// pages are read once either is reached (recent nuget.org pages hold some
	// 2,750 leaves; a batch of Changes still ends at a commit boundary, see
	// nugetFeed.newer).
	nugetPagesPerBatch  = 50
	nugetLeavesPerBatch = 50_000
	// nugetMaxServiceIndex bounds a service index (nuget.org's is 9 KB) and
	// nugetMaxVersionList a package's flat-container version list.
	nugetMaxServiceIndex = 4 << 20
	nugetMaxVersionList  = 16 << 20
	// nugetCatalogTTL is how long the catalog's location, read from the
	// service index, is trusted before it is read again; nugetIndexTTL how
	// long Releases reuses the service index it read through the proxy.
	nugetCatalogTTL = time.Hour
	nugetIndexTTL   = 10 * time.Minute
	// nugetMaxSeen bounds the packages a replay remembers having reported
	// (nuget.org has some 600,000).
	nugetMaxSeen = 2_000_000
	// nugetPagesPrefix names the page lists a replay keeps in Env.Dir.
	nugetPagesPrefix = "nuget-pages-"
	// nugetDefaultSettle is how old a commit must be before it is reported:
	// nuget.org's flat container (and its CDN) lists a version a few minutes
	// after the catalog commits it.
	nugetDefaultSettle = 10 * time.Minute
)

type nugetFeed struct {
	k     kit
	files files
	// fixed is the catalog index the feed option "url" names.
	fixed *url.URL
	// pages and leaves bound one batch (nugetPagesPerBatch,
	// nugetLeavesPerBatch).
	pages, leaves int

	// settle holds back commits younger than it (feed option "settle"): the
	// flat container lists a version a few minutes after the catalog
	// commits it, and a version reported before that would be taken for gone.
	settle time.Duration
	now    func() time.Time

	mu        sync.Mutex
	catalog   *url.URL // read from the service index
	catalogAt time.Time
	index     []byte // the service index as the proxy serves it
	indexAt   time.Time
	// seen maps a package (lower-cased) to the first page of the replay
	// batch that reported it, for the replay seenReplay names.
	seen       map[string]int
	seenReplay string
}

func nugetNewFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "settle")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	settle, err := gitSettleOption(opts, nugetDefaultSettle)
	if err != nil {
		return nil, err
	}
	f := &nugetFeed{k: k, files: files{dir: env.Dir}, pages: nugetPagesPerBatch, leaves: nugetLeavesPerBatch, settle: settle, now: time.Now}
	if opts["url"] != "" {
		if f.fixed, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func init() { Register("nuget", nugetNewFeed) }

// nugetCursor is the NuGet feed's position.
type nugetCursor struct {
	Format string `json:"format"`
	// Catalog is the catalog index followed.
	Catalog string `json:"catalog"`
	// Since is the commit timestamp processed last (RFC 3339, UTC); while
	// Bootstrap replays the catalog, the one the replay continues from.
	Since string `json:"since"`
	// Listing marks Bootstrap's replay: Page is the next page of the page
	// list stored for it, Pages its length and Digest its SHA-256.
	Listing bool   `json:"listing,omitempty"`
	Page    int    `json:"page,omitempty"`
	Pages   int    `json:"pages,omitempty"`
	Digest  string `json:"digest,omitempty"`
}

func (c *nugetCursor) cursorFormat() string { return c.Format }

func (f *nugetFeed) format() string { return cursorFormat("nuget", nugetFeedVersion) }

func (f *nugetFeed) cursor(c nugetCursor) string {
	c.Format = f.format()
	return encodeCursor(&c)
}

// Bootstrap replays the catalog from its first page.
func (f *nugetFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	var (
		c     nugetCursor
		pages []string
	)
	if cursor == "" {
		cat, err := f.catalogURL(ctx)
		if err != nil {
			return Batch{}, err
		}
		idx, err := f.readIndex(ctx, cat)
		if err != nil {
			return Batch{}, err
		}
		list := nugetPageList{Catalog: cat.String(), Since: nugetFormatTime(idx.TS)}
		for _, p := range idx.Pages {
			list.Pages = append(list.Pages, p.URL)
		}
		f.files.pruneKeepingNewest(nugetPagesPrefix, 1)
		digest, err := f.savePages(list)
		if err != nil {
			return Batch{}, fmt.Errorf("storing the catalog's page list: %w", err)
		}
		c = nugetCursor{Catalog: list.Catalog, Since: list.Since, Listing: true, Pages: len(list.Pages), Digest: digest}
		pages = list.Pages
	} else {
		if err := decodeCursor(cursor, f.format(), &c); err != nil {
			return Batch{}, err
		}
		if !c.Listing {
			return Batch{}, fmt.Errorf("%w: the NuGet cursor does not continue a replay", ErrCursorInvalid)
		}
		var err error
		if pages, err = f.loadPages(c); err != nil {
			return Batch{}, err
		}
	}
	start, ok := nugetTime(c.Since)
	if !ok || c.Page < 0 || c.Page > len(pages) {
		return Batch{}, fmt.Errorf("%w: the NuGet replay cursor is out of range", ErrCursorInvalid)
	}
	var leaves []nugetLeaf
	end := c.Page
	for end < len(pages) && end-c.Page < f.pages && len(leaves) < f.leaves {
		pl, err := f.readPage(ctx, pages[end])
		if err != nil {
			return Batch{}, err
		}
		for _, l := range pl {
			// What was committed after the replay began is Changes' to
			// report.
			if !l.Deleted && !l.TS.After(start) {
				leaves = append(leaves, l)
			}
		}
		end++
	}
	b := Batch{Head: c.Since, HeadTime: start, Items: f.unreported(c.Catalog+"\n"+c.Since, c.Page, leaves)}
	if end < len(pages) {
		next := c
		next.Page = end
		b.Next, b.More = f.cursor(next), true
		return b, nil
	}
	b.Next = f.cursor(nugetCursor{Catalog: c.Catalog, Since: c.Since})
	b.CursorTime = start
	return b, nil
}

// unreported maps a replay batch's leaves to one name-only coordinate per
// package, in the order the leaves came, leaving out the packages an earlier
// batch of the same replay reported. A package is held back only when the
// batch that reported it started before this one: the same batch asked for
// again (the engine retries a batch it could not store) reports it again.
func (f *nugetFeed) unreported(replay string, start int, leaves []nugetLeaf) []Coordinate {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seenReplay != replay {
		f.seen, f.seenReplay = map[string]int{}, replay
	}
	var out []Coordinate
	batch := map[string]bool{}
	for _, l := range leaves {
		id := strings.ToLower(l.ID)
		if batch[id] {
			continue
		}
		batch[id] = true
		p, known := f.seen[id]
		if known && p < start {
			continue
		}
		if (known && start < p) || (!known && len(f.seen) < nugetMaxSeen) {
			f.seen[id] = start
		}
		out = append(out, Coordinate{Name: l.ID})
	}
	return out
}

// Changes reads the catalog pages committed after the cursor.
func (f *nugetFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	var c nugetCursor
	if err := decodeCursor(cursor, f.format(), &c); err != nil {
		return Batch{}, err
	}
	since, ok := nugetTime(c.Since)
	if c.Listing || c.Catalog == "" || !ok {
		return Batch{}, fmt.Errorf("%w: the NuGet cursor names no catalog position", ErrCursorInvalid)
	}
	// A replay's page list is of no further use once the feed is followed
	// (the newest is kept: another replica may have begun a replay with it).
	f.files.pruneKeepingNewest(nugetPagesPrefix, 1)
	cat, err := f.catalogURL(ctx)
	if err != nil {
		return Batch{}, err
	}
	if cat.String() != c.Catalog {
		return Batch{}, fmt.Errorf("%w: the feed's catalog is now %s, not %s", ErrCursorInvalid, cat.Redacted(), c.Catalog)
	}
	idx, err := f.readIndex(ctx, cat)
	if err != nil {
		return Batch{}, err
	}
	if idx.TS.Before(since) {
		return Batch{}, fmt.Errorf("%w: the stored position %s is newer than the catalog's last commit %s (the catalog was rebuilt or rewound)",
			ErrCursorInvalid, c.Since, nugetFormatTime(idx.TS))
	}
	b := Batch{Head: nugetFormatTime(idx.TS), HeadTime: idx.TS}
	if !idx.TS.After(since) {
		b.Next, b.CursorTime, b.LagKnown = cursor, since, true
		return b, nil
	}
	// Commits younger than the settle period wait for the next poll.
	horizon := idx.TS
	if f.settle > 0 {
		if h := f.now().Add(-f.settle); h.Before(horizon) {
			horizon = h
		}
	}
	if !horizon.After(since) {
		b.Next, b.CursorTime = cursor, since
		return b, nil
	}
	var pending []nugetPage
	for _, p := range idx.Pages {
		if p.TS.After(since) {
			pending = append(pending, p)
		}
	}
	leaves, upTo, more, err := f.newer(ctx, pending, since, horizon)
	if err != nil {
		return Batch{}, err
	}
	b.Items = nugetCoordinates(leaves)
	b.Next = f.cursor(nugetCursor{Catalog: c.Catalog, Since: nugetFormatTime(upTo)})
	b.More, b.CursorTime = more, upTo
	b.LagKnown = !more && !upTo.Before(idx.TS)
	return b, nil
}

// newer reads catalog pages in commit order and returns their leaves newer
// than since and not newer than horizon, up to a commit boundary: every leaf
// committed at or before the time it returns is among them. A page holds the
// commits after the page before it up to its own commitTimeStamp, as the
// catalog index stated it when it was read — a leaf newer than that was
// committed after the index was read (pages are written before the index),
// and its commit may continue on a page the index did not list yet, so it
// waits for the next poll. newer stops after f.pages pages or f.leaves
// leaves — unless one commit fills every page read so far, which it reads to
// its end — and reports more then.
func (f *nugetFeed) newer(ctx context.Context, pages []nugetPage, since, horizon time.Time) ([]nugetLeaf, time.Time, bool, error) {
	var leaves []nugetLeaf
	for i, p := range pages {
		pl, err := f.readPage(ctx, p.URL)
		if err != nil {
			return nil, time.Time{}, false, err
		}
		limit := p.TS
		if horizon.Before(limit) {
			limit = horizon
		}
		for _, l := range pl {
			if l.TS.After(since) && !l.TS.After(limit) {
				leaves = append(leaves, l)
			}
		}
		last := i == len(pages)-1
		if last && !p.TS.After(horizon) {
			// Every page committed after since has been read, and all of
			// its commits have settled: the batch reaches the last commit
			// the index listed.
			return leaves, p.TS, false, nil
		}
		// reached: this page's last commit has not settled, and neither has
		// any commit on the pages after it. A page whose last commit is the
		// horizon itself — the catalog's newest commit, when it has settled
		// — is not reached: that commit may continue on the next page, which
		// is read before the commit is reported.
		reached := p.TS.After(horizon)
		if !reached && i+1 < f.pages && len(leaves) < f.leaves {
			continue
		}
		// The pages after this one hold commits from this page's last one
		// (p.TS) on, and that commit may continue there: the batch ends at
		// the newest commit before it that has settled, which the pages
		// read hold in full.
		cut := since
		for _, l := range leaves {
			if l.TS.Before(p.TS) && l.TS.After(cut) {
				cut = l.TS
			}
		}
		if !cut.After(since) {
			if reached || last {
				return nil, since, false, nil // nothing settled yet
			}
			continue // one commit is all the pages read hold: read on
		}
		kept := make([]nugetLeaf, 0, len(leaves))
		for _, l := range leaves {
			if !l.TS.After(cut) {
				kept = append(kept, l)
			}
		}
		// Past the horizon the rest has not settled: no more for now.
		return kept, cut, !reached, nil
	}
	return nil, since, false, nil
}

// nugetCoordinates orders leaves by commit and reports one change per package
// version, where its last leaf stands: a version edited twice in the batch is
// dealt with once, one pushed and then deleted is reported deleted.
func nugetCoordinates(leaves []nugetLeaf) []Coordinate {
	sort.SliceStable(leaves, func(i, j int) bool { return leaves[i].TS.Before(leaves[j].TS) })
	last := make(map[string]int, len(leaves))
	for i, l := range leaves {
		last[strings.ToLower(l.ID)+"@"+l.Version] = i
	}
	out := make([]Coordinate, 0, len(last))
	for i, l := range leaves {
		if last[strings.ToLower(l.ID)+"@"+l.Version] == i {
			out = append(out, Coordinate{Name: l.ID, Version: l.Version, Deleted: l.Deleted})
		}
	}
	return out
}

// catalogURL returns the catalog index followed: the feed option "url", else
// the catalog the upstream's service index names (read directly from the
// upstream, again after nugetCatalogTTL).
func (f *nugetFeed) catalogURL(ctx context.Context) (*url.URL, error) {
	if f.fixed != nil {
		return f.fixed, nil
	}
	f.mu.Lock()
	if f.catalog != nil && time.Since(f.catalogAt) < nugetCatalogTTL {
		u := f.catalog
		f.mu.Unlock()
		return u, nil
	}
	f.mu.Unlock()
	si := join(f.k.upstream, nugetServiceIndexPath)
	body, _, err := f.k.get(ctx, si, http.Header{"Accept": {"application/json"}}, nugetMaxServiceIndex)
	if err != nil {
		return nil, fmt.Errorf("reading the NuGet service index: %w", err)
	}
	res, err := nugetParseServiceIndex(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the NuGet service index %s: %w", si, err))
	}
	raw := nugetResourceURL(res, nugetCatalogType)
	if raw == "" {
		return nil, Permanent(fmt.Errorf("the service index of upstream %s names no %s resource: the feed publishes no catalog "+
			"(Artifactory, Nexus, Azure Artifacts and GitHub Packages implement none); set fullMirror.feed.url to a catalog index to follow one",
			f.k.upstream.Redacted(), nugetCatalogType))
	}
	u, err := parseBaseURL("the catalog the service index names", raw)
	if err != nil {
		return nil, Permanent(err)
	}
	f.mu.Lock()
	f.catalog, f.catalogAt = u, time.Now()
	f.mu.Unlock()
	return u, nil
}

// readIndex reads and parses the catalog index.
func (f *nugetFeed) readIndex(ctx context.Context, cat *url.URL) (*nugetCatalogIndex, error) {
	body, _, err := f.k.get(ctx, cat.String(), http.Header{"Accept": {"application/json"}}, maxFeedPage)
	if err != nil {
		return nil, fmt.Errorf("reading the NuGet catalog index: %w", err)
	}
	idx, err := nugetParseCatalogIndex(body, cat)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the NuGet catalog index %s: %w", cat.Redacted(), err))
	}
	return idx, nil
}

// readPage reads and parses one catalog page.
func (f *nugetFeed) readPage(ctx context.Context, page string) ([]nugetLeaf, error) {
	body, _, err := f.k.get(ctx, page, http.Header{"Accept": {"application/json"}}, maxFeedPage)
	if err != nil {
		return nil, fmt.Errorf("reading the NuGet catalog page: %w", err)
	}
	leaves, err := nugetParseCatalogPage(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the NuGet catalog page %s: %w", truncate(page, 256), err))
	}
	return leaves, nil
}

// nugetPageList is the page list a replay keeps in Env.Dir: the catalog's
// pages in commit order as the index stood at Since.
type nugetPageList struct {
	Catalog string   `json:"catalog"`
	Since   string   `json:"since"`
	Pages   []string `json:"pages"`
}

// nugetPagesFile names a replay's page list.
func nugetPagesFile(catalog, since string) string {
	sum := sha256.Sum256([]byte(catalog + "\n" + since))
	return nugetPagesPrefix + hex.EncodeToString(sum[:8]) + ".json"
}

// savePages stores a replay's page list and returns its SHA-256.
func (f *nugetFeed) savePages(l nugetPageList) (string, error) {
	data, err := json.Marshal(l)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	err = f.files.write(nugetPagesFile(l.Catalog, l.Since), func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
	return hex.EncodeToString(sum[:]), err
}

// loadPages reads the page list a replay cursor names; one that is missing
// or does not match the cursor invalidates it.
func (f *nugetFeed) loadPages(c nugetCursor) ([]string, error) {
	if f.files.dir == "" {
		return nil, errValidationOnly
	}
	fh, err := os.Open(f.files.path(nugetPagesFile(c.Catalog, c.Since)))
	if err != nil {
		return nil, fmt.Errorf("%w: the catalog's page list is not stored (%v)", ErrCursorInvalid, err)
	}
	defer fh.Close()
	data, err := readLimited(fh, maxMetadataDoc)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the catalog's page list: %v", ErrCursorInvalid, err)
	}
	sum := sha256.Sum256(data)
	var l nugetPageList
	if hex.EncodeToString(sum[:]) != c.Digest || json.Unmarshal(data, &l) != nil ||
		l.Catalog != c.Catalog || l.Since != c.Since || len(l.Pages) != c.Pages {
		return nil, fmt.Errorf("%w: the stored page list does not match the cursor", ErrCursorInvalid)
	}
	return l.Pages, nil
}

// nugetResource is one resource of a service index.
type nugetResource struct {
	ID    string
	Types []string
}

// nugetParseServiceIndex reads a service index's resources.
func nugetParseServiceIndex(body []byte) ([]nugetResource, error) {
	var doc struct {
		Resources []struct {
			ID   string          `json:"@id"`
			Type json.RawMessage `json:"@type"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if doc.Resources == nil {
		return nil, fmt.Errorf("it lists no resources")
	}
	out := make([]nugetResource, 0, len(doc.Resources))
	for _, r := range doc.Resources {
		if types := nugetTypes(r.Type); r.ID != "" && len(types) > 0 {
			out = append(out, nugetResource{ID: r.ID, Types: types})
		}
	}
	return out, nil
}

// nugetTypes reads an "@type": a string or a list of strings.
func nugetTypes(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		if one == "" {
			return nil
		}
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}

// nugetResourceURL returns the URL of the first resource of a type.
func nugetResourceURL(res []nugetResource, typ string) string {
	for _, r := range res {
		for _, t := range r.Types {
			if t == typ {
				return r.ID
			}
		}
	}
	return ""
}

// nugetPage is one page of the catalog index.
type nugetPage struct {
	URL string
	TS  time.Time
}

// nugetCatalogIndex is the catalog index: its last commit and its pages in
// commit order.
type nugetCatalogIndex struct {
	TS    time.Time
	Pages []nugetPage
}

// nugetParseCatalogIndex reads a catalog index. Every page must state when it
// was last committed to and lie on the catalog's origin: a page that cannot be
// placed in commit order would be skipped silently, so the index is refused.
func nugetParseCatalogIndex(body []byte, catalog *url.URL) (*nugetCatalogIndex, error) {
	var doc struct {
		CommitTimeStamp string `json:"commitTimeStamp"`
		Items           []struct {
			ID              string `json:"@id"`
			CommitTimeStamp string `json:"commitTimeStamp"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	ts, ok := nugetTime(doc.CommitTimeStamp)
	if !ok {
		return nil, fmt.Errorf("its commitTimeStamp %q is not a time", truncate(doc.CommitTimeStamp, 64))
	}
	if doc.Items == nil {
		return nil, fmt.Errorf("it lists no pages")
	}
	idx := &nugetCatalogIndex{TS: ts, Pages: make([]nugetPage, 0, len(doc.Items))}
	seen := make(map[string]bool, len(doc.Items))
	for i, it := range doc.Items {
		pts, ok := nugetTime(it.CommitTimeStamp)
		if !ok {
			return nil, fmt.Errorf("the commitTimeStamp of page %d (%q) is not a time", i, truncate(it.CommitTimeStamp, 64))
		}
		if !nugetOnOrigin(catalog, it.ID) {
			return nil, fmt.Errorf("page %q is not a URL on the catalog's origin", truncate(it.ID, 128))
		}
		if seen[it.ID] {
			continue
		}
		seen[it.ID] = true
		if pts.After(idx.TS) {
			idx.TS = pts
		}
		idx.Pages = append(idx.Pages, nugetPage{URL: it.ID, TS: pts})
	}
	sort.SliceStable(idx.Pages, func(i, j int) bool {
		a, b := idx.Pages[i], idx.Pages[j]
		if !a.TS.Equal(b.TS) {
			return a.TS.Before(b.TS)
		}
		na, nb := nugetPageNumber(a.URL), nugetPageNumber(b.URL)
		if na >= 0 && nb >= 0 {
			return na < nb
		}
		return a.URL < b.URL
	})
	return idx, nil
}

// nugetOnOrigin reports whether raw is an http(s) URL without credentials,
// query or fragment on the catalog's scheme, host and port.
func nugetOnOrigin(catalog *url.URL, raw string) bool {
	if raw == "" || len(raw) > 2048 {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && strings.EqualFold(u.Scheme, catalog.Scheme) && strings.EqualFold(u.Host, catalog.Host) &&
		u.User == nil && u.RawQuery == "" && u.Fragment == "" && !strings.ContainsAny(raw, " \x00\r\n")
}

// nugetPageNumber reads the number of a page named "…/page<N>.json"; -1 for
// another name.
func nugetPageNumber(raw string) int {
	name := raw[strings.LastIndexByte(raw, '/')+1:]
	if !strings.HasPrefix(name, "page") || !strings.HasSuffix(name, ".json") {
		return -1
	}
	n, err := strconv.Atoi(name[len("page") : len(name)-len(".json")])
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// nugetLeaf is one leaf of a catalog page.
type nugetLeaf struct {
	ID      string
	Version string
	Deleted bool
	TS      time.Time
}

// nugetParseCatalogPage reads a catalog page's leaves. A leaf of another
// type, or whose id, version or timestamp does not read, is left out.
func nugetParseCatalogPage(body []byte) ([]nugetLeaf, error) {
	var doc struct {
		Items []struct {
			Type            json.RawMessage `json:"@type"`
			ID              string          `json:"nuget:id"`
			Version         string          `json:"nuget:version"`
			CommitTimeStamp string          `json:"commitTimeStamp"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if doc.Items == nil {
		return nil, fmt.Errorf("it lists no items")
	}
	if len(doc.Items) > maxBatchItems {
		return nil, fmt.Errorf("it lists %d items; at most %d are taken", len(doc.Items), maxBatchItems)
	}
	out := make([]nugetLeaf, 0, len(doc.Items))
	for _, it := range doc.Items {
		deleted := false
		switch types := nugetTypes(it.Type); {
		case nugetHasType(types, "nuget:PackageDetails", "PackageDetails"):
		case nugetHasType(types, "nuget:PackageDelete", "PackageDelete"):
			deleted = true
		default:
			continue
		}
		ts, tok := nugetTime(it.CommitTimeStamp)
		v, vok := nugetVersion(it.Version)
		if !tok || !vok || !nugetValidID(it.ID) {
			continue
		}
		out = append(out, nugetLeaf{ID: it.ID, Version: v, Deleted: deleted, TS: ts})
	}
	return out, nil
}

// nugetHasType reports whether types holds one of want.
func nugetHasType(types []string, want ...string) bool {
	for _, t := range types {
		for _, w := range want {
			if t == w {
				return true
			}
		}
	}
	return false
}

// nugetTime reads a catalog timestamp: RFC 3339 with up to seven fractional
// digits, of which trailing zeros are dropped (their number varies, so the
// strings do not sort).
func nugetTime(s string) (time.Time, bool) {
	if s == "" || len(s) > 64 {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// nugetFormatTime renders a commit timestamp for a cursor.
func nugetFormatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// nugetValidID reports whether s is a package id NuGet accepts
// (PackageIdValidator: `^\w+([.-]\w+)*$`, at most 100 characters), in ASCII.
func nugetValidID(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	sep := true
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
			sep = false
		case c == '.' || c == '-':
			if sep {
				return false
			}
			sep = true
		default:
			return false
		}
	}
	return !sep
}

// nugetVersion is a version as the flat container spells it: lower-cased,
// without SemVer 2.0 build metadata. ok is false for anything but a NuGet
// version's characters (digits, letters, "." and "-", starting with a digit).
func nugetVersion(s string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if v == "" || len(v) > 128 || v[0] < '0' || v[0] > '9' {
		return "", false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c == '.' || c == '-') {
			return "", false
		}
	}
	return v, true
}

// Releases reads the package's flat-container version list through the gated
// pipeline.
func (f *nugetFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	if !nugetValidID(name) {
		return nil, Permanent(fmt.Errorf("%q is not a NuGet package id", name))
	}
	index, err := f.serviceIndex(ctx)
	if err != nil {
		return nil, err
	}
	res, err := nugetParseServiceIndex(index)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the service index served through the proxy: %w", err))
	}
	raw := nugetResourceURL(res, nugetBaseAddressType)
	base, ok := f.k.proxyPath(raw)
	if !ok {
		return nil, Permanent(fmt.Errorf("the service index served through the proxy names no package base address the proxy serves (%q)", truncate(raw, 128)))
	}
	base = strings.TrimRight(base, "/")
	id := strings.ToLower(name)
	body, err := f.k.read(ctx, base+"/"+id+"/index.json", "application/json", nugetMaxVersionList)
	if err != nil {
		return nil, err
	}
	versions, err := nugetParseVersionList(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the version list of %s: %w", name, err))
	}
	fetch := nugetIndexFetcher{index: index, next: f.k.fetcher()}
	rels := make([]Release, 0, len(versions))
	for _, v := range versions {
		arts, err := f.k.locate(ctx, lockfiles.Dependency{Name: id, Version: v}, fetch)
		if err != nil {
			if IsPermanent(err) {
				continue
			}
			return nil, err
		}
		rels = append(rels, Release{Version: v, Artifacts: arts})
	}
	orderReleases("nuget", rels)
	return rels, nil
}

// serviceIndex reads the service index through the gated pipeline, as the
// backend rewrites it for clients, reusing it for nugetIndexTTL: every
// package's Releases needs it.
func (f *nugetFeed) serviceIndex(ctx context.Context) ([]byte, error) {
	f.mu.Lock()
	if f.index != nil && time.Since(f.indexAt) < nugetIndexTTL {
		body := f.index
		f.mu.Unlock()
		return body, nil
	}
	f.mu.Unlock()
	body, err := f.k.read(ctx, nugetServiceIndexPath, "application/json", nugetMaxServiceIndex)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.index, f.indexAt = body, time.Now()
	f.mu.Unlock()
	return body, nil
}

// nugetIndexFetcher serves repos/locate the service index the feed read
// through the pipeline and every other document from the pipeline.
type nugetIndexFetcher struct {
	index []byte
	next  locate.Fetcher
}

// FetchDocument implements locate.Fetcher.
func (n nugetIndexFetcher) FetchDocument(ctx context.Context, upstream, path, accept string) (locate.Document, error) {
	if path == nugetServiceIndexPath {
		return locate.Document{Status: http.StatusOK, ContentType: "application/json", Body: n.index}, nil
	}
	return n.next.FetchDocument(ctx, upstream, path, accept)
}

// nugetParseVersionList reads a flat-container version list.
func nugetParseVersionList(body []byte) ([]string, error) {
	var doc struct {
		Versions []string `json:"versions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if doc.Versions == nil {
		return nil, fmt.Errorf("it lists no versions")
	}
	out := make([]string, 0, len(doc.Versions))
	seen := make(map[string]bool, len(doc.Versions))
	for _, raw := range doc.Versions {
		if v, ok := nugetVersion(raw); ok && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, nil
}
