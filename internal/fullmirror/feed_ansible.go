package fullmirror

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/ansible"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// ansible follows Galaxy NG's search of collection versions.
//
// Galaxy NG (galaxy.ansible.com; pulp_ansible serves the same API) lists every
// collection version of a distribution newest first by the creation of its
// content (`/api/v3/plugin/ansible/search/collection-versions/
// ?order_by=-pulp_created&distribution_base_path=<repo>`, offset-paged).
// Changes pages it down to the high-water mark (listfeed.go) and reports each
// new version as namespace.name@version. The first page of a pass holds 50
// versions (about 80 KB: more than a day of Galaxy's publishing), later ones
// 100, each repeating the last 5 of the page before. A version shows in the
// search only once it has been added to the repository — seconds after its
// content was created, later when imports queue, an approval waits, or a copy
// adds content created long before — while its time stays its content's
// creation: the versions younger than the feed option "settle" (default 10
// minutes, by the registry's clock) are held back until a later pass, and
// each pass reads a day below the mark and reports what it had not seen
// there; a version added to the repository more than a day after its content
// was created is not reported. Bootstrap takes the mark, then enumerates the
// repository's collection index, ordered by each collection's creation: new
// versions leave that order alone, and new collections only push the others
// down a page. A search that lists nothing while the index lists collections
// (a Galaxy that does not filter its search by distribution) fails rather than
// follow nothing.
//
// Releases reads the collection's versions list
// (`/api/v3/plugin/ansible/content/<repo>/collections/index/<ns>/<name>/versions/
// ?limit=100&offset=N`) from the Galaxy the feed follows, directly: the gated
// pipeline takes no query, and the list's first page without one holds ten
// versions. Each
// version's artifact path comes from repos/locate's ansible locator and is
// asked for only when the backend reads it back as that version (the backend
// verifies the download against the version detail's SHA-256). The list
// states no artifact size, and Galaxy withdraws no version short of deleting
// it (deprecation is per collection, and a deprecated collection still
// installs), so nothing is yanked. Roles (the v1 API) are GitHub repositories,
// not files on Galaxy, and are not followed.
//
// The repository is the upstream's "repository" setting (default
// "published"), as for the locator: the base path of the distribution whose
// content/<repo>/ paths serve the index, versions lists and artifacts, which
// the search is filtered by too (the repository behind it may be named
// otherwise). Any upstream is taken to serve the same layout under its URL, as
// galaxy_ng and pulp_ansible distributions do. Artifactory's and Nexus's
// Ansible repositories are not documented to serve the search or the
// collection index (the first poll's 404 says to set the feed option "url" to
// the Galaxy they proxy). A Private Automation Hub serves its API beneath
// /api/galaxy/, where neither the feed nor repos/locate's artifact paths
// point: it cannot be followed.

// Pages and bounds of the ansible feed.
const (
	// ansiblePage is how many versions (or collections) a listing page asks
	// for, ansibleFirstPage how many the first page of a pass asks for, and
	// ansibleOverlap how many of a page's entries the next page repeats.
	ansiblePage      = 100
	ansibleFirstPage = 50
	ansibleOverlap   = 5
	// ansibleMaxOffset bounds a listing offset a token names (Galaxy lists
	// some 54,000 versions).
	ansibleMaxOffset = 10_000_000
	// ansibleMaxPage bounds a page of the search, the index or a versions
	// list (100 search results are about 160 KB).
	ansibleMaxPage = 16 << 20
	// ansibleMaxVersions bounds the versions of one collection (Galaxy's
	// largest have a few hundred).
	ansibleMaxVersions = 10_000
	// ansibleDefaultSettle is how old a version must be before it is
	// reported.
	ansibleDefaultSettle = 10 * time.Minute
	// ansibleUnsettledPages bounds the pages one read skips whose versions
	// are all younger than the settle period.
	ansibleUnsettledPages = 20
	// ansibleLookback is how far below the mark a pass looks for versions
	// added to the repository late (Galaxy's 100 newest versions spanned 2.75
	// days on 2026-11-16).
	ansibleLookback = 24 * time.Hour
)

type ansibleFeed struct {
	*listingFeed
	k   kit
	src *ansibleSource
	// repo is the distribution repository (setting "repository").
	repo string
	// versionsPage is how many versions a page of the versions list asks
	// for; maxPage bounds a page.
	versionsPage int
	maxPage      int64
}

// ansibleSource reads Galaxy's search and collection index.
type ansibleSource struct {
	k kit
	// feed is the Galaxy the listings are read from; repo the repository.
	feed *url.URL
	repo string
	// first, page and overlap size the listings' pages (see the constants).
	first, page, overlap int
	// settle holds back the versions younger than it; now is the clock used
	// when a response states no Date.
	settle time.Duration
	now    func() time.Time
	// maxPage bounds a page (ansibleMaxPage).
	maxPage int64
}

func newAnsibleFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "settle")
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
	settle, err := gitSettleOption(opts, ansibleDefaultSettle)
	if err != nil {
		return nil, err
	}
	repo := strings.TrimSpace(env.Settings["repository"])
	if repo == "" {
		repo = "published"
	}
	if !ansibleValidRepository(repo) {
		return nil, fmt.Errorf("the upstream's repository setting %q is not a Galaxy repository name", truncate(repo, 64))
	}
	src := &ansibleSource{k: k, feed: feed, repo: repo, first: ansibleFirstPage, page: ansiblePage, overlap: ansibleOverlap,
		settle: settle, now: time.Now, maxPage: ansibleMaxPage}
	return &ansibleFeed{listingFeed: newListingFeed("ansible", src), k: k, src: src, repo: repo, versionsPage: ansiblePage, maxPage: ansibleMaxPage}, nil
}

func init() { Register("ansible", newAnsibleFeed) }

// ansibleValidRepository reports whether s can name a repository in a path
// segment and a query: letters, digits, "-", "_" and ".", not a dot segment.
func ansibleValidRepository(s string) bool {
	if s == "" || len(s) > 128 || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// lookback is how far below the mark a pass looks (listfeed.go).
func (s *ansibleSource) lookback() time.Duration { return ansibleLookback }

// ansibleOffset reads a listing token: the offset of the page, "" for the
// first.
func ansibleOffset(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(token)
	if err != nil || n <= 0 || n > ansibleMaxOffset || strconv.Itoa(n) != token {
		return 0, fmt.Errorf("%w: %q is not an ansible listing offset", ErrCursorInvalid, truncate(token, 64))
	}
	return n, nil
}

// ansibleNextToken is the token of the page after one at off that held count
// entries, repeating overlap of them; "" when there is none.
func ansibleNextToken(off, count, overlap int, more bool) string {
	if !more || count <= 0 {
		return ""
	}
	next := off + count - overlap
	if next <= off {
		next = off + count
	}
	if next > ansibleMaxOffset {
		return ""
	}
	return strconv.Itoa(next)
}

// get reads one listing page.
func (s *ansibleSource) get(ctx context.Context, what, target string) ([]byte, *http.Response, error) {
	body, resp, err := s.k.get(ctx, target, http.Header{"Accept": {"application/json"}}, s.maxPage)
	if err != nil {
		if IsPermanent(err) && resp != nil && resp.StatusCode == http.StatusNotFound {
			err = fmt.Errorf("%w (the upstream serves no Galaxy NG %s: set fullMirror.feed.url to a Galaxy that does)", err, what)
		}
		return nil, resp, fmt.Errorf("reading Galaxy's %s: %w", what, err)
	}
	return body, resp, nil
}

// recent reads a page of the repository's versions, newest first. The
// versions younger than the settle period are left out, and a page that held
// nothing else is followed by the next — Bootstrap takes its mark from the
// first page's newest version, which must be one that is reported.
func (s *ansibleSource) recent(ctx context.Context, token string) (listingPage, error) {
	off, err := ansibleOffset(token)
	if err != nil {
		return listingPage{}, err
	}
	limit := s.page
	if off == 0 {
		limit = s.first
	}
	for skipped := 0; ; skipped++ {
		pg, err := s.recentPage(ctx, off, limit)
		if err == nil && off == 0 && pg.TotalKnown && pg.Total == 0 {
			err = s.emptySearch(ctx)
		}
		if err != nil || len(pg.Items) > 0 || pg.Next == "" || skipped == ansibleUnsettledPages {
			return pg, err
		}
		if off, err = ansibleOffset(pg.Next); err != nil {
			return listingPage{}, err
		}
		limit = s.page
	}
}

// emptySearch checks a search that lists no version against the
// repository's collection index: an index that lists collections means the
// search is not filtered by the distribution (a Galaxy that ignores the
// filter would list the versions of every repository; one that answers a
// filter it does not know with nothing lists none), and following it would
// follow nothing.
func (s *ansibleSource) emptySearch(ctx context.Context) error {
	q := url.Values{"limit": {"1"}, "offset": {"0"}}
	body, _, err := s.get(ctx, "collection index", join(s.feed, "api/v3/plugin/ansible/content/"+s.repo+"/collections/index/")+"?"+q.Encode())
	if err != nil {
		return err
	}
	idx, err := ansibleParseIndex(body)
	if err != nil {
		return Permanent(fmt.Errorf("reading Galaxy's collection index: %w", err))
	}
	if idx.total > 0 || len(idx.collections) > 0 {
		return Permanent(fmt.Errorf("Galaxy's search lists no version of distribution %q while its collection index lists %d collections: "+
			"the upstream does not filter its search by distribution_base_path (set the repository setting to the distribution's base path, or fullMirror.feed.url to a Galaxy that does)",
			s.repo, max(idx.total, int64(len(idx.collections)))))
	}
	return nil
}

// recentPage reads the page of the search at off.
func (s *ansibleSource) recentPage(ctx context.Context, off, limit int) (listingPage, error) {
	q := url.Values{"order_by": {"-pulp_created"}, "distribution_base_path": {s.repo}, "limit": {strconv.Itoa(limit)}, "offset": {strconv.Itoa(off)}}
	body, resp, err := s.get(ctx, "search", join(s.feed, "api/v3/plugin/ansible/search/collection-versions/")+"?"+q.Encode())
	if err != nil {
		return listingPage{}, err
	}
	pg, err := ansibleParseSearch(body)
	if err != nil {
		return listingPage{}, Permanent(fmt.Errorf("reading Galaxy's search: %w", err))
	}
	cutoff := time.Time{}
	if s.settle > 0 {
		cutoff = ansibleServerTime(resp, s.now).Add(-s.settle)
	}
	out := listingPage{Total: pg.total, TotalKnown: pg.total >= 0, Next: ansibleNextToken(off, pg.count, s.overlap, pg.more)}
	for _, v := range pg.versions {
		if !cutoff.IsZero() && v.created.After(cutoff) {
			continue
		}
		out.Items = append(out.Items, listingItem{Name: v.collection, Version: v.version, Time: v.created})
	}
	return out, nil
}

// every reads a page of the repository's collection index, for Bootstrap.
func (s *ansibleSource) every(ctx context.Context, token string) (listingPage, error) {
	off, err := ansibleOffset(token)
	if err != nil {
		return listingPage{}, err
	}
	q := url.Values{"limit": {strconv.Itoa(s.page)}, "offset": {strconv.Itoa(off)}}
	body, _, err := s.get(ctx, "collection index", join(s.feed, "api/v3/plugin/ansible/content/"+s.repo+"/collections/index/")+"?"+q.Encode())
	if err != nil {
		return listingPage{}, err
	}
	idx, err := ansibleParseIndex(body)
	if err != nil {
		return listingPage{}, Permanent(fmt.Errorf("reading Galaxy's collection index: %w", err))
	}
	out := listingPage{Total: idx.total, TotalKnown: idx.total >= 0, Next: ansibleNextToken(off, idx.count, s.overlap, idx.more)}
	for _, c := range idx.collections {
		out.Items = append(out.Items, listingItem{Name: c})
	}
	return out, nil
}

// ansibleServerTime is the time a response states (its Date), else now: the
// settle period is measured by the registry's clock.
func ansibleServerTime(resp *http.Response, now func() time.Time) time.Time {
	if resp != nil {
		if t, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
			return t
		}
	}
	return now()
}

// ansibleVersion is one version a search page lists.
type ansibleVersion struct {
	collection, version string
	created             time.Time
}

// ansibleSearchPage is what a search page says.
type ansibleSearchPage struct {
	versions []ansibleVersion
	// count is how many results the page held, valid or not.
	count int
	// total is meta.count (-1 when absent); more reports a next page.
	total int64
	more  bool
}

// ansibleLinks is the pagination Galaxy's lists carry.
type ansibleLinks struct {
	Meta *struct {
		Count *int64 `json:"count"`
	} `json:"meta"`
	Links *struct {
		Next json.RawMessage `json:"next"`
	} `json:"links"`
}

// paging reads the total and whether a next page follows.
func (l ansibleLinks) paging() (int64, bool, error) {
	if l.Meta == nil || l.Links == nil {
		return 0, false, fmt.Errorf("it is not a Galaxy list (no meta or links)")
	}
	total := int64(-1)
	if c := l.Meta.Count; c != nil && *c >= 0 {
		total = *c
	}
	next := strings.TrimSpace(string(l.Links.Next))
	return total, next != "" && next != "null" && next != `""`, nil
}

// ansibleParseSearch reads a page of the collection-version search filtered
// by a distribution, keeping the versions whose collection and version the
// backend reads. The distribution serves one repository: results of several
// mean the search was not filtered, and the page is refused.
func ansibleParseSearch(body []byte) (ansibleSearchPage, error) {
	var doc struct {
		ansibleLinks
		Data *[]struct {
			Repository struct {
				Name string `json:"name"`
			} `json:"repository"`
			CollectionVersion struct {
				Namespace   string `json:"namespace"`
				Name        string `json:"name"`
				Version     string `json:"version"`
				PulpCreated string `json:"pulp_created"`
			} `json:"collection_version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return ansibleSearchPage{}, err
	}
	if doc.Data == nil {
		return ansibleSearchPage{}, fmt.Errorf("it is not a search page (no data)")
	}
	total, more, err := doc.paging()
	if err != nil {
		return ansibleSearchPage{}, err
	}
	out := ansibleSearchPage{count: len(*doc.Data), total: total, more: more}
	repo := ""
	for _, d := range *doc.Data {
		switch name := d.Repository.Name; {
		case repo == "":
			repo = name
		case name != repo:
			return ansibleSearchPage{}, fmt.Errorf("it lists versions of repositories %q and %q: the search is not filtered by distribution_base_path",
				truncate(repo, 64), truncate(name, 64))
		}
		cv := d.CollectionVersion
		fqcn := cv.Namespace + "." + cv.Name
		if !ansible.ValidRelease(fqcn, cv.Version) {
			continue
		}
		created, err := time.Parse(time.RFC3339Nano, cv.PulpCreated)
		if err != nil {
			continue
		}
		out.versions = append(out.versions, ansibleVersion{collection: fqcn, version: cv.Version, created: created.UTC()})
	}
	return out, nil
}

// ansibleIndexPage is what a page of the collection index says.
type ansibleIndexPage struct {
	collections []string
	count       int
	total       int64
	more        bool
}

// ansibleParseIndex reads a page of a repository's collection index, keeping
// the collections whose name the backend reads.
func ansibleParseIndex(body []byte) (ansibleIndexPage, error) {
	var doc struct {
		ansibleLinks
		Data *[]struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return ansibleIndexPage{}, err
	}
	if doc.Data == nil {
		return ansibleIndexPage{}, fmt.Errorf("it is not a collection index (no data)")
	}
	total, more, err := doc.paging()
	if err != nil {
		return ansibleIndexPage{}, err
	}
	out := ansibleIndexPage{count: len(*doc.Data), total: total, more: more}
	for _, d := range *doc.Data {
		if fqcn := d.Namespace + "." + d.Name; ansible.ValidCollection(fqcn) {
			out.collections = append(out.collections, fqcn)
		}
	}
	return out, nil
}

// ansibleListedVersion is one version of a collection's versions list.
type ansibleListedVersion struct {
	version string
	created time.Time
}

// ansibleVersionsPage is what a page of a versions list says.
type ansibleVersionsPage struct {
	versions []ansibleListedVersion
	count    int
	total    int64
	more     bool
}

// ansibleParseVersions reads a page of a collection's versions list, keeping
// the versions the backend reads for collection.
func ansibleParseVersions(body []byte, collection string) (ansibleVersionsPage, error) {
	var doc struct {
		ansibleLinks
		Data *[]struct {
			Version   string `json:"version"`
			CreatedAt string `json:"created_at"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return ansibleVersionsPage{}, err
	}
	if doc.Data == nil {
		return ansibleVersionsPage{}, fmt.Errorf("it is not a versions list (no data)")
	}
	total, more, err := doc.paging()
	if err != nil {
		return ansibleVersionsPage{}, err
	}
	out := ansibleVersionsPage{count: len(*doc.Data), total: total, more: more}
	for _, d := range *doc.Data {
		if !ansible.ValidRelease(collection, d.Version) {
			continue
		}
		v := ansibleListedVersion{version: d.Version}
		if t, err := time.Parse(time.RFC3339Nano, d.CreatedAt); err == nil {
			v.created = t.UTC()
		}
		out.versions = append(out.versions, v)
	}
	return out, nil
}

// Releases reads the collection's versions list from the Galaxy the feed
// follows.
func (f *ansibleFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	if !ansible.ValidCollection(name) {
		return nil, Permanent(fmt.Errorf("%q is not a Galaxy collection name the proxy serves (namespace.name, in lower case)", truncate(name, 200)))
	}
	ns, coll, _ := strings.Cut(name, ".")
	base := join(f.src.feed, "api/v3/plugin/ansible/content/"+f.repo+"/collections/index/"+ns+"/"+coll+"/versions/")
	var listed []ansibleListedVersion
	seen := map[string]bool{}
	for off, pages := 0, 0; ; pages++ {
		if pages*f.versionsPage >= ansibleMaxVersions {
			return nil, Permanent(fmt.Errorf("the versions list of %s runs past %d versions", name, ansibleMaxVersions))
		}
		q := url.Values{"limit": {strconv.Itoa(f.versionsPage)}, "offset": {strconv.Itoa(off)}}
		target := base + "?" + q.Encode()
		body, _, err := f.k.get(ctx, target, http.Header{"Accept": {"application/json"}}, f.maxPage)
		if err != nil {
			return nil, fmt.Errorf("reading the versions of %s: %w", name, err)
		}
		pg, err := ansibleParseVersions(body, name)
		if err != nil {
			return nil, Permanent(fmt.Errorf("the versions list of %s: %w", name, err))
		}
		for _, v := range pg.versions {
			if !seen[v.version] {
				seen[v.version] = true
				listed = append(listed, v)
			}
		}
		if !pg.more || pg.count == 0 {
			break
		}
		off += pg.count
	}
	rels := make([]Release, 0, len(listed))
	for i := len(listed) - 1; i >= 0; i-- {
		v := listed[i]
		arts, err := f.k.locate(ctx, lockfiles.Dependency{Name: name, Version: v.version}, nil)
		if err != nil {
			if IsPermanent(err) {
				continue
			}
			return nil, err
		}
		rel := Release{Version: v.version, Published: v.created}
		for _, a := range arts {
			dec, err := url.PathUnescape(a.Path)
			if err != nil {
				continue
			}
			if c, ver, ok := ansible.ArtifactPathCoordinate(dec); ok && c == name && ver == v.version {
				rel.Artifacts = append(rel.Artifacts, a)
			}
		}
		if len(rel.Artifacts) > 0 {
			rels = append(rels, rel)
		}
	}
	// Collection versions are SemVer 2.0, which the npm scheme orders.
	orderReleases("npm", rels)
	return rels, nil
}
