package fullmirror

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/openvsx"
)

// openvsx follows an Open VSX registry through its sitemap and its listing of
// recent publications (Task 191).
//
// openvsx-server publishes /sitemap.xml: a <url> per active extension,
// "…/extension/{namespace}/{name}", with the date it last changed as
// <lastmod> (the UTC date of its last update, "YYYY-MM-DD"). The feed reads it
// — conditionally where the server sends validators (open-vsx.org sends none:
// 400 KB compressed, 2.6 MB of XML, 21,436 extensions on 2026-11-16) — as a
// stream, and keeps a package-level record per extension, named as the
// backend names an extension's archives ("{namespace}.{name}"), whose digest
// is its date. Changes reports, by name, every extension whose date moved,
// every new one and every one gone.
//
// A date does not move when an extension publishes twice in a day. Every read
// therefore also reads the registry's listing of extensions by the time their
// newest version was published, newest first (/api/-/search?sortBy=timestamp)
// — directly from the registry, as the gated pipeline takes no query — down
// to six hours below the newest time the previous read saw: one request of 100
// extensions at a poll on open-vsx.org (a few hundred publications a day),
// three at most. The time an extension's newest version was published, as far
// as the listing showed it, joins its record's digest for as long as its date
// stays the same: a second publication on a day changes the record, an
// extension dropping out of the listing does not. What the listing misses —
// more publications between two reads than three pages hold, a version
// published below an extension's newest one — is seen when the date moves; a
// listing that cannot be read costs that read's same-day publications only.
// An openvsx-server in mirror mode dates every extension anew at every mirror
// run: a read that finds more than half of at least 100 extensions dated
// within a day of now marks the server as re-dating, and the reads after it do
// not take a date moving as a change of an extension the listing names
// nothing newer of — the whole registry would otherwise be reported once a
// day.
//
// Releases reads the extension's document through the gated pipeline
// (/api/{namespace}/{name}; the backend rewrites its URLs into the proxy):
// whether it exists and may be downloaded, its newest version and the archive
// URLs the registry wrote for it. It then pages each target platform's version
// listing (/api/{namespace}/{name}/{platform}/versions, 100 a page, directly
// from the registry) — "universal" alone for an extension whose newest version
// is built for every platform, every platform openvsx-server knows otherwise,
// as its own mirror mode does — up to 2,000 versions a platform, newest first,
// past a pre-release line to the stable releases below it (rust-analyzer's
// current stable release is 1,416 versions down its linux-x64 listing). A
// version is listed on a platform only where the registry has it built for
// that platform. An archive's path comes from the backend's path builder
// (openvsx.VsixPath: openvsx-server stores every archive under one name
// pattern), checked against the URLs the registry wrote for the newest
// version: where they differ, only those are listed. The option "platforms"
// keeps some target platforms ("linux-x64,darwin-arm64"); "universal" is
// always kept, as editors fall back to it. An extension the registry marks not
// downloadable lists nothing. Versions are listed oldest first by SemVer, the
// newest with its publication time. The registry marks pre-releases only in
// each version's own document, and a Release carries no such mark: they are
// listed as any other version, and a "latest N" version policy keeps the N
// highest versions — for an extension with a separate pre-release line,
// pre-releases.
//
// A self-hosted openvsx-server serves the same sitemap and API beneath its
// URL; the option "url" names another sitemap (the listings are still read
// from the upstream's API).

// Bounds of the openvsx feed.
const (
	// openvsxMaxSitemap bounds the sitemap, as served and decompressed
	// (open-vsx.org's is 2.6 MB).
	openvsxMaxSitemap = 256 << 20
	// openvsxMaxToken bounds one XML token (a <loc> is a URL).
	openvsxMaxToken = 1 << 20
	// openvsxMaxField bounds the text of a <loc> or a <lastmod>.
	openvsxMaxField = 4096
	// openvsxMaxDepth bounds the nesting of the sitemap's elements (three
	// levels).
	openvsxMaxDepth = 16
	// openvsxMaxDoc bounds an extension's document (open-vsx.org's are about
	// 10 KB; the backend rewrites none larger than 32 MiB).
	openvsxMaxDoc = 16 << 20
	// openvsxMaxListing bounds a page of a listing (a search page of 100
	// extensions is about 100 KB, a version page 9 KB).
	openvsxMaxListing = 16 << 20
	// openvsxSearchPage is how many extensions a page of the search listing
	// asks for, openvsxSearchPages how many pages a read reads at most.
	openvsxSearchPage  = 100
	openvsxSearchPages = 3
	// openvsxLookback is how far below the newest time the previous read saw
	// the search listing is read again: a version can become visible later
	// than its publication time says (a mirror publishes what it mirrors
	// under the time it was published upstream). What is read again changes
	// nothing that has not changed.
	openvsxLookback = 6 * time.Hour
	// openvsxVersionPage is how many versions a page of a version listing
	// asks for (the most openvsx-server gives), openvsxVersionPages how many
	// pages of a platform are read: 2,000 versions, newest first.
	openvsxVersionPage  = 100
	openvsxVersionPages = 20
	// openvsxMaxCarry bounds the records of the previous copy whose digests
	// a read carries over (held in memory: some 25 MB at the bound, ten times
	// open-vsx.org's extensions); past it the listing's times are not carried
	// and an extension dropping out of the listing is reported once more.
	openvsxMaxCarry = 250_000
	// openvsxRedatingMin is how many extensions a registry must list before
	// it can be judged to re-date them.
	openvsxRedatingMin = 100
)

type openvsxFeed struct {
	*indexFeed
	k kit
	// platforms are the target platforms kept besides universal; nil keeps
	// every platform.
	platforms map[string]bool
	// versionPage is the size of a version listing's page.
	versionPage int
}

func newOpenVSXFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "platforms")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	sitemap := join(k.upstream, "sitemap.xml")
	if opts["url"] != "" {
		u, err := parseBaseURL("the feed option url", opts["url"])
		if err != nil {
			return nil, err
		}
		if !strings.HasSuffix(u.Path, ".xml") {
			return nil, fmt.Errorf("the feed option url names the sitemap to read (…/sitemap.xml), not %s", u.Redacted())
		}
		sitemap = u.String()
	}
	platforms, err := openvsxParsePlatforms(opts["platforms"])
	if err != nil {
		return nil, err
	}
	src := &openvsxSource{k: k, url: sitemap, now: time.Now, searchPage: openvsxSearchPage}
	return &openvsxFeed{indexFeed: newIndexFeed("openvsx", env, src), k: k, platforms: platforms, versionPage: openvsxVersionPage}, nil
}

func init() { Register("openvsx", newOpenVSXFeed) }

// openvsxParsePlatforms reads the "platforms" option: target platforms
// separated by commas.
func openvsxParsePlatforms(v string) (map[string]bool, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	out := map[string]bool{}
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if !openvsx.IsTargetPlatform(p) {
			return nil, fmt.Errorf("option platforms: %q is not a target platform (%s)", p, strings.Join(openvsx.TargetPlatforms(), ", "))
		}
		out[p] = true
	}
	return out, nil
}

// openvsxSource reads the sitemap and the listing of recent publications.
type openvsxSource struct {
	k   kit
	url string
	now func() time.Time
	// searchPage is the size of a search listing's page.
	searchPage int
}

// openvsxState is what the next read is conditioned on.
type openvsxState struct {
	// ETag and LastModified are the sitemap's validators.
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	// Mark is the newest time the search listing showed, in Unix
	// microseconds.
	Mark int64 `json:"mark,omitempty"`
	// Redating records that the previous read found the server dating
	// (nearly) every extension within a day of now.
	Redating bool `json:"redating,omitempty"`
}

// readIndex reads the sitemap into the copy, each extension's digest its date
// and the time the search listing shows its newest version was published.
func (s *openvsxSource) readIndex(ctx context.Context, prev json.RawMessage, old *snapHeader, b *snapBuilder) (indexRead, error) {
	var st openvsxState
	if old == nil || len(prev) == 0 || json.Unmarshal(prev, &st) != nil || !openvsxUsable(httpValidators{ETag: st.ETag, LastModified: st.LastModified}) || st.Mark < 0 {
		// Without a copy to fall back on, or a state that can be sent, the
		// sitemap is read in full and the listing from its top.
		st = openvsxState{}
	}
	now := s.now().UTC()
	listed, mark, err := s.recent(ctx, st.Mark)
	if err != nil {
		return indexRead{}, err
	}
	next := st
	next.Mark = mark
	hdr := http.Header{"Accept": {"application/xml, text/xml;q=0.9"}, "Accept-Encoding": {"gzip"}}
	httpValidators{ETag: st.ETag, LastModified: st.LastModified}.set(hdr)
	resp, body, err := s.k.getStream(ctx, s.url, hdr, openvsxMaxSitemap)
	if errors.Is(err, errNotModified) {
		if old == nil {
			return indexRead{}, fmt.Errorf("the Open VSX registry answered an unconditional request for its sitemap with 304")
		}
		return openvsxRefresh(b.f, old, b, listed, next, now)
	}
	if err != nil {
		return indexRead{}, fmt.Errorf("reading the Open VSX sitemap: %w", err)
	}
	defer body.Close()
	carry, err := openvsxDigests(b.f, old)
	if err != nil {
		return indexRead{}, err
	}
	content, release, err := openContent(body, s.url, openvsxMaxSitemap)
	defer release()
	if err != nil {
		return indexRead{}, err
	}
	newest := openvsxMarkTime(mark, now)
	total, recent := 0, 0
	err = openvsxParseSitemap(content, func(e openvsxEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		id := e.namespace + "." + e.name
		was, hasOld := carry[id]
		b.Add(openvsxRecord(id, e.lastmod, was, hasOld, listed[id], st.Redating))
		total++
		if t, ok := openvsxTime(e.lastmod); ok {
			if t.After(now.AddDate(0, 0, -2)) && t.Before(now.AddDate(0, 0, 1)) {
				recent++
			}
			if t.After(now) {
				t = now
			}
			if t.After(newest) {
				newest = t
			}
		}
		return nil
	})
	if err != nil {
		return indexRead{}, err
	}
	v := validatorsOf(resp)
	next.ETag, next.LastModified = v.ETag, v.LastModified
	next.Redating = total >= openvsxRedatingMin && 2*recent > total
	state, err := json.Marshal(next)
	if err != nil {
		return indexRead{}, err
	}
	return indexRead{State: state, HeadTime: newest}, nil
}

// openvsxUsable reports whether validators kept in a cursor — which is not
// trusted — can go back into a request header.
func openvsxUsable(v httpValidators) bool {
	for _, h := range []string{v.ETag, v.LastModified} {
		if len(h) > 512 {
			return false
		}
		for i := 0; i < len(h); i++ {
			if c := h[i]; c < 0x20 && c != '\t' || c == 0x7f {
				return false
			}
		}
	}
	return true
}

// recent reads the registry's listing of extensions by the time their newest
// version was published, newest first, down to openvsxLookback below mark (a
// time in Unix microseconds; 0 reads the first pages): each listed extension's
// newest time, and the newest time seen. A listing that cannot be read is left
// out of this read — the mark stays where it was, so the next read reads it
// again — and only a cancelled read is an error.
func (s *openvsxSource) recent(ctx context.Context, mark int64) (map[string]int64, int64, error) {
	listed := map[string]int64{}
	newest := mark
	floor := int64(0)
	if mark > 0 {
		floor = mark - openvsxLookback.Microseconds()
	}
	size := s.searchPage
	if size <= 0 {
		size = openvsxSearchPage
	}
	for page := 0; page < openvsxSearchPages; page++ {
		q := url.Values{"sortBy": {"timestamp"}, "sortOrder": {"desc"}, "size": {strconv.Itoa(size)}, "offset": {strconv.Itoa(page * size)}}
		body, _, err := s.k.get(ctx, join(s.k.upstream, "api/-/search")+"?"+q.Encode(), http.Header{"Accept": {"application/json"}}, openvsxMaxListing)
		if err != nil {
			if ctx.Err() != nil {
				return nil, mark, ctx.Err()
			}
			return listed, mark, nil
		}
		top, n, total, stop, err := openvsxReadSearchPage(body, floor, listed)
		if err != nil {
			return listed, mark, nil
		}
		if top > newest {
			newest = top
		}
		if stop || n < size || (page+1)*size >= total {
			return listed, newest, nil
		}
	}
	// The pages ran out above the floor: what lies below them is not read.
	return listed, newest, nil
}

// openvsxReadSearchPage reads a page of the search listing into listed (each
// extension's newest time, in Unix microseconds), down to floor: the newest
// time on the page, how many entries it holds, the listing's total, and
// whether it reached the floor. An entry without a valid name or time is
// skipped; a page that is not the listing's is an error.
func openvsxReadSearchPage(body []byte, floor int64, listed map[string]int64) (newest int64, n, total int, stop bool, err error) {
	var res struct {
		TotalSize  int `json:"totalSize"`
		Extensions []struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
			Timestamp string `json:"timestamp"`
		} `json:"extensions"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return 0, 0, 0, false, err
	}
	for _, e := range res.Extensions {
		t, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err != nil || !openvsx.ValidName(e.Namespace) || !openvsx.ValidName(e.Name) {
			continue
		}
		ts := t.UnixMicro()
		if ts <= floor || ts <= 0 {
			return newest, len(res.Extensions), res.TotalSize, true, nil
		}
		if id := e.Namespace + "." + e.Name; ts > listed[id] {
			listed[id] = ts
		}
		if ts > newest {
			newest = ts
		}
	}
	return newest, len(res.Extensions), res.TotalSize, false, nil
}

// openvsxMarkTime is a mark (Unix microseconds) as a time, at most now; zero
// for none.
func openvsxMarkTime(mark int64, now time.Time) time.Time {
	if mark <= 0 {
		return time.Time{}
	}
	if t := time.UnixMicro(mark).UTC(); t.Before(now) {
		return t
	}
	return now
}

// openvsxDigests reads the digest the previous copy holds of each extension
// (none without a previous copy, or of one too large to hold: the digests are
// then not carried over).
func openvsxDigests(f files, old *snapHeader) (map[string]string, error) {
	if old == nil || old.Records > openvsxMaxCarry {
		return nil, nil
	}
	r, err := f.openSnapshot(old, true)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := make(map[string]string, old.Records)
	for r.Next() {
		rec := r.Record()
		out[rec.Name] = rec.Digest
	}
	return out, r.Err()
}

// openvsxRefresh rebuilds the previous copy for a sitemap that did not change:
// an extension the search listing shows a newer version of gets that version's
// time in its digest. It reports Unchanged when none did.
func openvsxRefresh(f files, old *snapHeader, b *snapBuilder, listed map[string]int64, next openvsxState, now time.Time) (indexRead, error) {
	state, err := json.Marshal(next)
	if err != nil {
		return indexRead{}, err
	}
	rd := indexRead{Unchanged: true, State: state, HeadTime: openvsxMarkTime(next.Mark, now)}
	if len(listed) == 0 {
		return rd, nil
	}
	r, err := f.openSnapshot(old, true)
	if err != nil {
		return indexRead{}, err
	}
	defer r.Close()
	for r.Next() {
		rec := r.Record()
		if l := listed[rec.Name]; l > 0 {
			if base, ts := openvsxSplitDigest(rec.Digest); l > ts {
				rec.Digest, rd.Unchanged = openvsxJoinDigest(base, l), false
			}
		}
		b.Add(rec)
	}
	if err := r.Err(); err != nil {
		return indexRead{}, err
	}
	return rd, nil
}

// openvsxEntry is one extension the sitemap lists.
type openvsxEntry struct {
	namespace, name string
	// lastmod is the entry's <lastmod> as the sitemap spells it.
	lastmod string
}

// openvsxRecord is an extension's record. Its digest is the extension's date
// in the sitemap, joined by the time its newest version was published as far
// as the search listing has shown it while the date stayed the same: old is
// the digest the previous copy holds (hasOld), listed the time the listing
// shows now (0: not listed). With redating, a date that moved for an
// extension the listing shows nothing newer of is no change: the record stays
// as it was.
func openvsxRecord(id, lastmod, old string, hasOld bool, listed int64, redating bool) snapRecord {
	base := openvsxBase(lastmod)
	oldBase, oldTS := openvsxSplitDigest(old)
	if hasOld && redating && base != oldBase && listed <= oldTS {
		return snapRecord{Name: id, Digest: old}
	}
	ts := listed
	if hasOld && oldBase == base && oldTS > ts {
		ts = oldTS
	}
	return snapRecord{Name: id, Digest: openvsxJoinDigest(base, ts)}
}

// openvsxTime reads a <lastmod>: a date ("2006-01-02", the UTC date
// openvsx-server writes) or a full time stamp.
func openvsxTime(lastmod string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02", time.RFC3339Nano, "2006-01-02T15:04Z07:00"} {
		if t, err := time.Parse(layout, lastmod); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// openvsxBase is the part of a digest a <lastmod> makes: the date as it is,
// a full time stamp in UTC, nothing for none.
func openvsxBase(lastmod string) string {
	if _, err := time.Parse("2006-01-02", lastmod); err == nil {
		return lastmod
	}
	if t, ok := openvsxTime(lastmod); ok {
		return t.Format(time.RFC3339Nano)
	}
	return ""
}

// openvsxSplitDigest splits a digest into its date part and the listing's
// time (0 when it holds none).
func openvsxSplitDigest(d string) (string, int64) {
	base, t, ok := strings.Cut(d, "/")
	if !ok {
		return d, 0
	}
	ts, err := strconv.ParseInt(t, 10, 64)
	if err != nil || ts <= 0 {
		return base, 0
	}
	return base, ts
}

// openvsxJoinDigest joins a digest's date part and the listing's time.
func openvsxJoinDigest(base string, ts int64) string {
	if ts <= 0 {
		return base
	}
	return base + "/" + strconv.FormatInt(ts, 10)
}

// openvsxGuard is the sitemap's reader under the XML decoder: it bounds what
// the decoder buffers for one token — it holds a token whole, however long —
// and keeps the error of the stream itself (a network error is retried,
// malformed XML is not).
type openvsxGuard struct {
	r io.Reader
	// read is how many bytes the decoder has been given, start the offset in
	// the stream where the token being read began.
	read, start int64
	err         error
}

func (g *openvsxGuard) Read(p []byte) (int, error) {
	// Each read is cut to what the token may still take, so the bound holds
	// to the byte.
	left := openvsxMaxToken - (g.read - g.start)
	if left < 0 {
		g.err = Permanent(fmt.Errorf("the sitemap holds an XML token of more than %d bytes", openvsxMaxToken))
		return 0, g.err
	}
	if int64(len(p)) > left+1 {
		p = p[:left+1]
	}
	n, err := g.r.Read(p)
	g.read += int64(n)
	if err != nil && err != io.EOF {
		g.err = err
	}
	return n, err
}

// openvsxParseSitemap reads a sitemap as a stream and calls fn for every
// <url> whose <loc> names an extension. A document that is not a sitemap, or
// does not read as XML, is a permanent error; an entry that names no
// extension is skipped. An error fn returns stops the read and is returned.
func openvsxParseSitemap(r io.Reader, fn func(openvsxEntry) error) error {
	g := &openvsxGuard{r: r}
	dec := xml.NewDecoder(g)
	var (
		depth         int
		urlset, inURL bool
		field         string
		text          strings.Builder
		tooLong       bool
		loc, mod      string
	)
	for {
		g.start = dec.InputOffset()
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			if g.err != nil {
				return g.err
			}
			return Permanent(fmt.Errorf("the sitemap does not read as XML: %w", err))
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			switch {
			case depth > openvsxMaxDepth:
				return Permanent(fmt.Errorf("the sitemap nests its elements more than %d deep", openvsxMaxDepth))
			case depth == 1:
				if t.Name.Local != "urlset" {
					return Permanent(fmt.Errorf("the document is not a sitemap of URLs (its root is <%s>)", truncate(t.Name.Local, 40)))
				}
				urlset = true
			case depth == 2 && t.Name.Local == "url":
				inURL, loc, mod = true, "", ""
			case depth == 3 && inURL && (t.Name.Local == "loc" || t.Name.Local == "lastmod"):
				field, tooLong = t.Name.Local, false
				text.Reset()
			}
		case xml.CharData:
			if field != "" {
				if text.Len()+len(t) > openvsxMaxField {
					tooLong = true
				} else {
					text.Write(t)
				}
			}
		case xml.EndElement:
			switch {
			case depth == 3 && field != "":
				v := strings.TrimSpace(text.String())
				if tooLong {
					v = ""
				}
				if field == "loc" {
					loc = v
				} else {
					mod = v
				}
				field = ""
			case depth == 2 && inURL:
				inURL = false
				if e, ok := openvsxEntryOf(loc, mod); ok {
					if err := fn(e); err != nil {
						return err
					}
				}
			}
			depth--
		}
	}
	if !urlset {
		return Permanent(errors.New("the document is not a sitemap (no <urlset>)"))
	}
	return nil
}

// openvsxEntryOf reads an entry's location, "…/extension/{namespace}/{name}"
// beneath the registry's web address (which need not be its API's).
func openvsxEntryOf(loc, lastmod string) (openvsxEntry, bool) {
	u, err := url.Parse(loc)
	if err != nil {
		return openvsxEntry{}, false
	}
	segs := strings.Split(strings.TrimSuffix(u.EscapedPath(), "/"), "/")
	n := len(segs)
	if n < 3 || segs[n-3] != "extension" || !openvsx.ValidName(segs[n-2]) || !openvsx.ValidName(segs[n-1]) {
		return openvsxEntry{}, false
	}
	return openvsxEntry{namespace: segs[n-2], name: segs[n-1], lastmod: lastmod}, true
}

// openvsxSplitName splits an extension's identifier into its namespace and
// name.
func openvsxSplitName(id string) (string, string, bool) {
	ns, name, ok := strings.Cut(id, ".")
	if !ok || !openvsx.ValidName(ns) || !openvsx.ValidName(name) {
		return "", "", false
	}
	return ns, name, true
}

// openvsxDoc is what Releases reads from an extension's document.
type openvsxDoc struct {
	Namespace      string            `json:"namespace"`
	Name           string            `json:"name"`
	Version        string            `json:"version"`
	TargetPlatform string            `json:"targetPlatform"`
	Timestamp      string            `json:"timestamp"`
	Downloadable   *bool             `json:"downloadable"`
	Downloads      map[string]string `json:"downloads"`
	Files          struct {
		Download string `json:"download"`
	} `json:"files"`
}

// openvsxParseDoc reads an extension's document.
func openvsxParseDoc(body []byte) (openvsxDoc, error) {
	var d openvsxDoc
	if err := json.Unmarshal(body, &d); err != nil {
		return openvsxDoc{}, err
	}
	if d.Namespace == "" || d.Name == "" {
		return openvsxDoc{}, errors.New("it is not an extension's document (no namespace or name)")
	}
	return d, nil
}

// readDoc reads an extension's document through the gated pipeline.
func (f *openvsxFeed) readDoc(ctx context.Context, path string) (openvsxDoc, error) {
	body, err := f.k.read(ctx, path, "application/json", openvsxMaxDoc)
	if err != nil {
		return openvsxDoc{}, err
	}
	d, err := openvsxParseDoc(body)
	if err != nil {
		return openvsxDoc{}, Permanent(fmt.Errorf("%s: %w", path, err))
	}
	return d, nil
}

// Releases lists an extension's versions with their archives.
func (f *openvsxFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	ns, ext, ok := openvsxSplitName(name)
	if !ok {
		return nil, Permanent(fmt.Errorf("%q is not an Open VSX extension (namespace.name)", truncate(name, 200)))
	}
	doc, err := f.readDoc(ctx, "/api/"+ns+"/"+ext)
	if err != nil {
		return nil, err
	}
	if !openvsx.ValidName(doc.Namespace) || !openvsx.ValidName(doc.Name) || !strings.EqualFold(doc.Namespace, ns) || !strings.EqualFold(doc.Name, ext) {
		return nil, Permanent(fmt.Errorf("the document of %s is of %q.%q", name, truncate(doc.Namespace, 100), truncate(doc.Name, 100)))
	}
	if doc.Downloadable != nil && !*doc.Downloadable {
		return nil, nil
	}
	ns, ext = doc.Namespace, doc.Name // as the registry spells them
	l := openvsxListing{ns: ns, ext: ext, byVersion: map[string]*Release{}}
	newest, platforms := f.newestArchives(doc)
	var published time.Time
	if t, err := time.Parse(time.RFC3339Nano, doc.Timestamp); err == nil {
		published = t.UTC()
	}
	trusted := len(newest) > 0
	for p, exact := range newest {
		if f.keeps(p) {
			l.put(doc.Version, exact, published)
		}
		if built, ok := openvsx.VsixPath(ns, ext, p, doc.Version); !ok || built != exact {
			trusted = false
		}
	}
	if trusted {
		listing := []string{openvsx.Universal}
		if len(platforms) != 1 || platforms[0] != openvsx.Universal {
			listing = openvsx.TargetPlatforms()
		}
		for _, p := range listing {
			if !f.keeps(p) {
				continue
			}
			versions, err := f.versions(ctx, ns, ext, p)
			if err != nil {
				return nil, err
			}
			for _, v := range versions {
				if path, ok := openvsx.VsixPath(ns, ext, p, v); ok {
					l.put(v, path, time.Time{})
				}
			}
		}
	}
	return l.releases(), nil
}

// keeps reports whether the option platforms keeps a target platform.
func (f *openvsxFeed) keeps(platform string) bool {
	return f.platforms == nil || platform == openvsx.Universal || f.platforms[platform]
}

// newestArchives returns the archives of the extension's newest version at
// the URLs the registry wrote (the backend rewrote them into the proxy), by
// target platform — those the proxy serves as that version's — and every
// target platform the newest version is built for, sorted.
func (f *openvsxFeed) newestArchives(d openvsxDoc) (map[string]string, []string) {
	urls := map[string]string{}
	for p, u := range d.Downloads {
		if openvsx.IsTargetPlatform(p) {
			urls[p] = u
		}
	}
	if len(urls) == 0 && d.Files.Download != "" {
		p := d.TargetPlatform
		if p == "" {
			p = openvsx.Universal
		}
		if openvsx.IsTargetPlatform(p) {
			urls[p] = d.Files.Download
		}
	}
	id := d.Namespace + "." + d.Name
	out := map[string]string{}
	platforms := make([]string, 0, len(urls))
	for p, u := range urls {
		platforms = append(platforms, p)
		path, ok := f.k.proxyPath(u)
		if !ok {
			continue
		}
		dec, err := url.PathUnescape(path)
		if err != nil {
			continue
		}
		if e, v, ok := openvsx.VsixCoordinate(dec); ok && e == id && v == d.Version && openvsx.ValidVersion(v) {
			out[p] = path
		}
	}
	sort.Strings(platforms)
	return out, platforms
}

// versions pages a target platform's version listing, newest first, directly
// from the registry (the gated pipeline takes no query): at most
// openvsxVersionPages pages. A platform the extension is not built for lists
// nothing; a listing the registry does not have (404) too.
func (f *openvsxFeed) versions(ctx context.Context, ns, ext, platform string) ([]string, error) {
	size := f.versionPage
	if size <= 0 {
		size = openvsxVersionPage
	}
	var out []string
	for page := 0; page < openvsxVersionPages; page++ {
		q := url.Values{"size": {strconv.Itoa(size)}, "offset": {strconv.Itoa(page * size)}}
		body, resp, err := f.k.get(ctx, join(f.k.upstream, "api/"+ns+"/"+ext+"/"+platform+"/versions")+"?"+q.Encode(), http.Header{"Accept": {"application/json"}}, openvsxMaxListing)
		if err != nil {
			if resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone) {
				return out, nil
			}
			return nil, fmt.Errorf("listing the %s versions of %s.%s: %w", platform, ns, ext, err)
		}
		versions, n, total, err := openvsxReadVersionPage(body)
		if err != nil {
			return nil, Permanent(fmt.Errorf("the %s version listing of %s.%s: %w", platform, ns, ext, err))
		}
		out = append(out, versions...)
		if n < size || (page+1)*size >= total {
			break
		}
	}
	return out, nil
}

// openvsxReadVersionPage reads a page of a version listing: the versions the
// registry serves archives of (SemVer, as its file endpoint takes them), how
// many entries the page holds, and the listing's total.
func openvsxReadVersionPage(body []byte) ([]string, int, int, error) {
	var res struct {
		TotalSize int               `json:"totalSize"`
		Versions  map[string]string `json:"versions"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, 0, 0, err
	}
	out := make([]string, 0, len(res.Versions))
	for v := range res.Versions {
		if openvsx.ValidVersion(v) {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out, len(res.Versions), res.TotalSize, nil
}

// openvsxListing collects an extension's releases.
type openvsxListing struct {
	ns, ext   string
	byVersion map[string]*Release
}

// put adds an archive to a version's release.
func (l *openvsxListing) put(version, path string, published time.Time) {
	r, ok := l.byVersion[version]
	if !ok {
		r = &Release{Version: version}
		l.byVersion[version] = r
	}
	for _, a := range r.Artifacts {
		if a.Path == path {
			return
		}
	}
	r.Artifacts = append(r.Artifacts, Artifact{Path: path})
	sort.Slice(r.Artifacts, func(i, j int) bool { return r.Artifacts[i].Path < r.Artifacts[j].Path })
	if !published.IsZero() && (r.Published.IsZero() || published.Before(r.Published)) {
		r.Published = published
	}
}

// releases returns the releases collected, oldest first by SemVer (the
// registry's versions are SemVer 2.0; npm's scheme is SemVer's precedence),
// the order of the map's keys undone first.
func (l *openvsxListing) releases() []Release {
	rels := make([]Release, 0, len(l.byVersion))
	for _, r := range l.byVersion {
		rels = append(rels, *r)
	}
	sort.Slice(rels, func(i, j int) bool { return rels[i].Version < rels[j].Version })
	orderReleases("npm", rels)
	return rels
}
