package fullmirror

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/puppet"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// puppet follows the Puppet Forge's release listing.
//
// The Forge lists every module release newest first
// (`/v3/releases?sort_by=release_date`, offset-paged, each release with its
// `created_at`). Changes pages it from the top down to the high-water mark
// (listfeed.go) and reports the module of each new release, by name. The first
// page of a pass is small (25 releases, so that a quiet poll costs one request
// of 25 KB); later pages hold 100 and repeat the last 5 of the page before,
// since a release deleted during the pass shifts the listing up. The pass
// reads a day below the mark (some 11 releases, within the first page) and
// reports what it had not seen there: a release the Forge lists only after a
// delay its time does not show. Bootstrap takes the mark from the newest
// release and enumerates every module from the same listing sorted by module
// (`sort_by=module`): that order is alphabetical, so a module that publishes
// while the enumeration runs — which lasts as long as the engine takes over
// the modules listed before it — stays where it is, where in the modules
// listing (ordered by rank, or by latest release) it could jump ahead of the
// enumeration and be missed with all its older releases.
// Every listing page leaves out the fields the feed does not read (readme,
// changelog, licence, reference, metadata, tasks, plans, tags, malware scan).
//
// Releases reads the module document (`/v3/modules/<owner>-<name>`) through
// the gated pipeline, as r10k does: it lists every release with its
// `created_at`, `file_size` and `deleted_at`. A deleted release is still served
// by exact version, and is listed as yanked. The tarball paths come from
// repos/locate's puppet locator and are asked for only when the backend reads
// them back as that module's release. Module documents are served from the
// Forge's CDN up to an hour old (ages up to 52 minutes observed on 2026-11-16)
// while the listing is not cached: changes are therefore names alone, and a
// release is reported once it is older than the feed option "settle" (by the
// Forge's clock), when the document lists it. The default is 90 minutes when
// the upstream is the Forge, and 3h30m when it is another server in front of
// the Forge whose API the option "url" names: an Artifactory Puppet remote
// keeps a document two hours by default, after the CDN's hour. Premium and
// login-required modules (a dozen) answer 401 without a Forge entitlement:
// they are skipped unless the upstream carries credentials. Module slugs whose
// owner is spelt with upper-case letters (263 of 7,707 modules on 2026-11-16)
// are not slugs the backend parses — it forwards their tarballs uncached — and
// are left out.
//
// The public Forge is forgeapi.puppet.com (forge.puppet.com and
// forgeapi.puppetlabs.com name it too). There is no self-hosted Forge, and an
// Artifactory Puppet repository serves the documents the puppet tool and r10k
// read but is not documented to list releases by date: such an upstream needs
// the feed option "url", the Forge it mirrors.

// puppetPublicHosts are the Forge's names; puppetPublicFeed is its API.
var puppetPublicHosts = []string{"forgeapi.puppet.com", "forge.puppet.com", "forgeapi.puppetlabs.com"}

const puppetPublicFeed = "https://forgeapi.puppet.com"

// Pages and bounds of the puppet feed.
const (
	// puppetPage is how many releases a listing page asks for (the Forge's
	// most), puppetFirstPage how many the first page of a pass asks for, and
	// puppetOverlap how many of a page's releases the next page repeats.
	puppetPage      = 100
	puppetFirstPage = 25
	puppetOverlap   = 5
	// puppetMaxOffset bounds a listing offset a token names (the Forge lists
	// some 55,000 releases).
	puppetMaxOffset = 10_000_000
	// puppetMaxListing bounds a listing page (100 releases are about 110 KB).
	puppetMaxListing = 16 << 20
	// puppetMaxModule bounds a module document: the current release's readme,
	// changelog and reference ride along (puppetlabs-cem_linux's reference is
	// 1.5 MB); the backend serves none larger.
	puppetMaxModule = 32 << 20
	// puppetMaxReleases bounds the releases of one module (puppetlabs-stdlib
	// has 95).
	puppetMaxReleases = 10_000
	// puppetDefaultSettle is how old a release must be before it is reported
	// when the upstream is the Forge: the module document its CDN serves lists
	// it by then. puppetIntermediarySettle is the default when the upstream is
	// another server in front of the Forge, which caches the CDN's documents
	// once more.
	puppetDefaultSettle      = 90 * time.Minute
	puppetIntermediarySettle = 3*time.Hour + 30*time.Minute
	// puppetLookback is how far below the mark a pass looks for releases the
	// Forge listed late.
	puppetLookback = 24 * time.Hour
	// puppetUnsettledPages bounds the pages one read skips whose releases
	// are all younger than the settle period.
	puppetUnsettledPages = 20
)

// puppetExcluded are the fields of a release a listing page leaves out.
const puppetExcluded = "readme changelog license reference metadata tasks plans tags malware_scan"

// puppetTimeLayout is how the Forge spells a time ("2026-11-15 18:22:48 -0800").
const puppetTimeLayout = "2006-01-02 15:04:05 -0700"

type puppetFeed struct {
	*listingFeed
	k   kit
	src *puppetSource
	// maxModule bounds a module document (puppetMaxModule).
	maxModule int64
}

// puppetSource reads the Forge's release listing.
type puppetSource struct {
	k kit
	// feed is the Forge API the listings are read from.
	feed *url.URL
	// first, page and overlap size the listing's pages (see the constants).
	first, page, overlap int
	// maxListing bounds a listing page (puppetMaxListing).
	maxListing int64
	// settle holds back the releases younger than it; now is the clock used
	// when a response states no Date.
	settle time.Duration
	now    func() time.Time
}

func newPuppetFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "settle")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	var feed *url.URL
	switch {
	case opts["url"] != "":
		if feed, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
	case hostIs(k.upstream, puppetPublicHosts...):
		feed, _ = url.Parse(puppetPublicFeed)
	default:
		return nil, fmt.Errorf("upstream %s is not the Puppet Forge, whose release listing is known: set fullMirror.feed.url to a Forge v3 API "+
			"that lists /v3/releases by release date (the Forge an Artifactory Puppet remote mirrors; Artifactory's own repositories are not documented to)",
			k.upstream.Redacted())
	}
	def := puppetDefaultSettle
	if !hostIs(k.upstream, puppetPublicHosts...) && !strings.EqualFold(feed.Host, k.upstream.Host) {
		// The module documents come through a server in front of the Forge
		// the listing is read from, which caches them.
		def = puppetIntermediarySettle
	}
	settle, err := gitSettleOption(opts, def)
	if err != nil {
		return nil, err
	}
	src := &puppetSource{k: k, feed: feed, first: puppetFirstPage, page: puppetPage, overlap: puppetOverlap, maxListing: puppetMaxListing,
		settle: settle, now: time.Now}
	return &puppetFeed{listingFeed: newListingFeed("puppet", src), k: k, src: src, maxModule: puppetMaxModule}, nil
}

func init() { Register("puppet", newPuppetFeed) }

// Changes reports each module once per batch: the listing names it once per
// release.
func (f *puppetFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	b, err := f.listingFeed.Changes(ctx, cursor)
	if err != nil {
		return b, err
	}
	b.Items = puppetUniqueNames(b.Items)
	return b, nil
}

// puppetUniqueNames keeps the first item of each name.
func puppetUniqueNames(items []Coordinate) []Coordinate {
	seen := make(map[string]bool, len(items))
	out := items[:0:0]
	for _, c := range items {
		if !seen[c.Name] {
			seen[c.Name] = true
			out = append(out, c)
		}
	}
	return out
}

// lookback is how far below the mark a pass looks (listfeed.go).
func (s *puppetSource) lookback() time.Duration { return puppetLookback }

// puppetServerTime is the time a response states (its Date), else now: the
// settle period is measured by the Forge's clock.
func puppetServerTime(resp *http.Response, now func() time.Time) time.Time {
	if resp != nil {
		if t, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
			return t
		}
	}
	return now()
}

// puppetOffset reads a listing token: the offset of the page, "" for the
// first.
func puppetOffset(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(token)
	if err != nil || n <= 0 || n > puppetMaxOffset || strconv.Itoa(n) != token {
		return 0, fmt.Errorf("%w: %q is not a puppet listing offset", ErrCursorInvalid, truncate(token, 64))
	}
	return n, nil
}

// recent reads a page of the releases, newest first: each names its module.
// The releases younger than the settle period are left out, and a page that
// held nothing else is followed by the next — Bootstrap takes its mark from
// the first page's newest release, which must be one that is reported.
func (s *puppetSource) recent(ctx context.Context, token string) (listingPage, error) {
	off, err := puppetOffset(token)
	if err != nil {
		return listingPage{}, err
	}
	limit := s.page
	if off == 0 {
		limit = s.first
	}
	for skipped := 0; ; skipped++ {
		pg, err := s.list(ctx, "release_date", off, limit, true)
		if err != nil || len(pg.Items) > 0 || pg.Next == "" || skipped == puppetUnsettledPages {
			return pg, err
		}
		if off, err = puppetOffset(pg.Next); err != nil {
			return listingPage{}, err
		}
		limit = s.page
	}
}

// every reads a page of the releases sorted by module, for Bootstrap's
// enumeration of the modules: each release names its module.
func (s *puppetSource) every(ctx context.Context, token string) (listingPage, error) {
	off, err := puppetOffset(token)
	if err != nil {
		return listingPage{}, err
	}
	return s.list(ctx, "module", off, s.page, false)
}

// list reads one page of /v3/releases in an order; each release is an item
// naming its module. settle leaves out the releases younger than the settle
// period.
func (s *puppetSource) list(ctx context.Context, order string, off, limit int, settle bool) (listingPage, error) {
	q := url.Values{
		"sort_by": {order}, "limit": {strconv.Itoa(limit)}, "offset": {strconv.Itoa(off)},
		"with_html": {"false"}, "exclude_fields": {puppetExcluded},
	}
	target := join(s.feed, "v3/releases") + "?" + q.Encode()
	body, resp, err := s.k.get(ctx, target, http.Header{"Accept": {"application/json"}}, s.maxListing)
	if err != nil {
		return listingPage{}, fmt.Errorf("listing the Forge's releases: %w", err)
	}
	lst, err := puppetParseListing(body)
	if err != nil {
		return listingPage{}, Permanent(fmt.Errorf("listing the Forge's releases: %w", err))
	}
	var cutoff time.Time
	if settle && s.settle > 0 {
		cutoff = puppetServerTime(resp, s.now).Add(-s.settle)
	}
	pg := listingPage{Total: lst.total, TotalKnown: lst.total >= 0}
	for _, r := range lst.releases {
		if !cutoff.IsZero() && r.created.After(cutoff) {
			continue
		}
		pg.Items = append(pg.Items, listingItem{Name: r.module, Time: r.created, ID: r.slug})
	}
	if lst.more && lst.count > 0 {
		next := off + lst.count - s.overlap
		if next <= off {
			next = off + lst.count
		}
		if next <= puppetMaxOffset {
			pg.Next = strconv.Itoa(next)
		}
	}
	return pg, nil
}

// puppetListed is one release of a listing page.
type puppetListed struct {
	module, version, slug string
	created               time.Time
}

// puppetListing is what a listing page says.
type puppetListing struct {
	releases []puppetListed
	// count is how many results the page held, valid or not: the next page's
	// offset follows from it.
	count int
	// total is pagination.total (-1 when absent); more reports a next page.
	total int64
	more  bool
}

// puppetParseListing reads a page of /v3/releases. A release whose module slug
// or version the backend does not read, or whose slug is not
// "<module>-<version>", is left out.
func puppetParseListing(body []byte) (puppetListing, error) {
	var doc struct {
		Pagination *struct {
			Total *int64          `json:"total"`
			Next  json.RawMessage `json:"next"`
		} `json:"pagination"`
		Results *[]struct {
			Slug    string `json:"slug"`
			Version string `json:"version"`
			Module  struct {
				Slug string `json:"slug"`
			} `json:"module"`
			CreatedAt string `json:"created_at"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return puppetListing{}, err
	}
	if doc.Pagination == nil || doc.Results == nil {
		return puppetListing{}, fmt.Errorf("it is not a release listing (no pagination or results)")
	}
	out := puppetListing{count: len(*doc.Results), total: -1}
	if t := doc.Pagination.Total; t != nil && *t >= 0 {
		out.total = *t
	}
	next := strings.TrimSpace(string(doc.Pagination.Next))
	out.more = next != "" && next != "null" && next != `""`
	for _, r := range *doc.Results {
		if !puppet.ValidRelease(r.Module.Slug, r.Version) || r.Slug != r.Module.Slug+"-"+r.Version {
			continue
		}
		created, err := time.Parse(puppetTimeLayout, r.CreatedAt)
		if err != nil {
			continue
		}
		out.releases = append(out.releases, puppetListed{module: r.Module.Slug, version: r.Version, slug: r.Slug, created: created.UTC()})
	}
	return out, nil
}

// Releases reads the module document through the gated pipeline.
func (f *puppetFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	if !puppet.ValidModule(name) {
		return nil, Permanent(fmt.Errorf("%q is not a Forge module slug whose tarballs the proxy caches (owner-name, in lower case)", truncate(name, 200)))
	}
	body, err := f.k.read(ctx, "/v3/modules/"+name, "application/json", f.maxModule)
	if err != nil {
		return nil, err
	}
	mod, err := puppetParseModule(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the module document of %s: %w", name, err))
	}
	if mod.slug != name {
		return nil, Permanent(fmt.Errorf("the module document of %s describes %q", name, truncate(mod.slug, 200)))
	}
	if mod.restricted && f.k.env.Authorize == nil {
		// Its tarballs answer 401 without a Forge entitlement.
		return nil, nil
	}
	rels := make([]Release, 0, len(mod.releases))
	for i := len(mod.releases) - 1; i >= 0; i-- {
		r := mod.releases[i]
		arts, err := f.k.locate(ctx, lockfiles.Dependency{Name: name, Version: r.version}, nil)
		if err != nil {
			if IsPermanent(err) {
				continue
			}
			return nil, err
		}
		rel := Release{Version: r.version, Published: r.created, Yanked: r.deleted}
		for _, a := range arts {
			dec, err := url.PathUnescape(a.Path)
			if err != nil {
				continue
			}
			if m, v, ok := puppet.ReleaseFileCoordinate(dec); !ok || m != name || v != r.version {
				continue
			}
			// The document names the release's file: a release published
			// under another name than the one its slug gives is not one the
			// backend serves.
			if r.fileURI != "" && path.Base(r.fileURI) != path.Base(dec) {
				continue
			}
			a.Size = r.size
			rel.Artifacts = append(rel.Artifacts, a)
		}
		if len(rel.Artifacts) > 0 {
			rels = append(rels, rel)
		}
	}
	// Forge versions are SemVer 2.0, which the npm scheme orders.
	orderReleases("npm", rels)
	return rels, nil
}

// puppetModule is what Releases reads from a module document.
type puppetModule struct {
	slug string
	// restricted marks a premium or login-required module.
	restricted bool
	// releases are in the document's order (newest version first).
	releases []puppetRelease
}

// puppetRelease is one release a module document lists.
type puppetRelease struct {
	version string
	created time.Time
	deleted bool
	fileURI string
	size    int64
}

// puppetParseModule reads a module document: its slug, whether it is premium
// or login-required, and its releases. A release whose version the backend
// does not read is left out.
func puppetParseModule(body []byte) (puppetModule, error) {
	var doc struct {
		Slug          string `json:"slug"`
		Premium       bool   `json:"premium"`
		LoginRequired bool   `json:"login_required"`
		Releases      *[]struct {
			Version   string          `json:"version"`
			CreatedAt string          `json:"created_at"`
			DeletedAt json.RawMessage `json:"deleted_at"`
			FileURI   string          `json:"file_uri"`
			FileSize  int64           `json:"file_size"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return puppetModule{}, err
	}
	if doc.Slug == "" || doc.Releases == nil {
		return puppetModule{}, fmt.Errorf("it is not a module document (no slug or releases)")
	}
	if len(*doc.Releases) > puppetMaxReleases {
		return puppetModule{}, fmt.Errorf("it lists %d releases; at most %d are followed", len(*doc.Releases), puppetMaxReleases)
	}
	mod := puppetModule{slug: doc.Slug, restricted: doc.Premium || doc.LoginRequired}
	seen := map[string]bool{}
	for _, r := range *doc.Releases {
		if !puppet.ValidRelease(doc.Slug, r.Version) || seen[r.Version] {
			continue
		}
		seen[r.Version] = true
		rel := puppetRelease{version: r.Version, fileURI: r.FileURI}
		if t, err := time.Parse(puppetTimeLayout, r.CreatedAt); err == nil {
			rel.created = t.UTC()
		}
		del := strings.TrimSpace(string(r.DeletedAt))
		rel.deleted = del != "" && del != "null"
		if r.FileSize > 0 {
			rel.size = r.FileSize
		}
		mod.releases = append(mod.releases, rel)
	}
	return mod, nil
}
