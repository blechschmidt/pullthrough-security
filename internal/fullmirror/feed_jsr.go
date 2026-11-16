package fullmirror

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/jsr"
)

// jsr follows the JSR registry's package list (Task 191).
//
// The management API lists every package, alphabetically, 100 per page
// ("GET https://api.jsr.io/packages?limit=100&page=N"), with its version
// count, its latest version and when its metadata was last updated; it has
// no order by time and no change feed. Every poll therefore reads the whole
// list (214 requests, 21,228 packages and about 11 MB on 2026-11-16: the
// list ends at its first empty page — its "total" counts packages it does
// not list) into one package-level record per package with at least one
// version, whose
// digest is the latest version, the version count and the update time. A
// publish moves the version count (the update time stays: it is the
// package's metadata's), so the snapshot diff (pollfeed.go) reports a
// package with a new version, by name: the engine considers every version
// its policy keeps.
//
// Releases reads the package's meta.json through the gated pipeline (its
// versions, which are yanked, and when each was published), then each
// version's "<version>_meta.json", whose manifest lists the version's module
// files with their sizes: the artifacts are those files, at the paths the jsr
// backend serves and caches them and verifies them against that manifest
// (jsr.ModuleFilePath) — a runtime downloads a package one module file at a
// time. A version's manifest never changes, so the file lists of every
// package are kept in the adapter's directory ("jsr-files-<hash>.json.gz", one
// per package): a publish costs that package's meta.json and the new
// version's manifest, not one request per version.
//
// The upstream is jsr.io, whose management API is api.jsr.io; any other
// upstream needs the feed option "url", an API that lists packages the same
// way (no self-hosted JSR is in common use).

// Defaults and bounds of the jsr feed.
const (
	jsrPublicAPI = "https://api.jsr.io"
	// jsrPageSize is how many packages a list page asks for (the API's
	// most).
	jsrPageSize = 100
	// jsrMaxPages bounds one pass over the list.
	jsrMaxPages = 10_000
	// jsrMaxListPage bounds a list page (about 60 KB).
	jsrMaxListPage = 16 << 20
	// jsrMaxMeta bounds a package's meta.json and a version's
	// <version>_meta.json (the backend's own bound).
	jsrMaxMeta = 32 << 20
	// jsrMaxVersions bounds the versions listed per package: the newest by
	// version order (2,478 for the package with the most on 2026-11-16).
	jsrMaxVersions = 5_000
	// jsrMaxFiles bounds a version's module files: a version with more is
	// skipped. JSR caps a version at 20 MB of files.
	jsrMaxFiles = 10_000
	// jsrMaxCache bounds a package's stored file lists once decompressed.
	jsrMaxCache = 64 << 20
	// jsrCachePrefix names the files the adapter keeps.
	jsrCachePrefix = "jsr-files-"
)

// jsrPublicHosts are the registry's names.
var jsrPublicHosts = []string{"jsr.io"}

type jsrFeed struct {
	*indexFeed
	k kit
	// cache keeps the file lists of packages with many versions.
	cache files
}

// jsrSource reads the package list.
type jsrSource struct {
	k     kit
	api   *url.URL
	limit int
}

func newJSRFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	var api *url.URL
	switch {
	case opts["url"] != "":
		if api, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
	case hostIs(k.upstream, jsrPublicHosts...):
		api, _ = url.Parse(jsrPublicAPI)
	default:
		return nil, fmt.Errorf("upstream %s is not jsr.io, whose management API is known: set fullMirror.feed.url to an API that lists the registry's packages as https://api.jsr.io does (GET <url>/packages?limit=100&page=N)", k.upstream.Redacted())
	}
	src := &jsrSource{k: k, api: api, limit: jsrPageSize}
	return &jsrFeed{indexFeed: newIndexFeed("jsr", env, src), k: k, cache: files{dir: env.Dir}}, nil
}

func init() { Register("jsr", newJSRFeed) }

// jsrListItem is one package of the list.
type jsrListItem struct {
	Scope         string  `json:"scope"`
	Name          string  `json:"name"`
	LatestVersion *string `json:"latestVersion"`
	VersionCount  int64   `json:"versionCount"`
	UpdatedAt     string  `json:"updatedAt"`
}

// jsrParseList reads a list page.
func jsrParseList(body []byte) ([]jsrListItem, error) {
	var doc struct {
		Items []jsrListItem `json:"items"`
		Total *int64        `json:"total"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if doc.Items == nil {
		return nil, errors.New("the page has no items")
	}
	return doc.Items, nil
}

// record is the package-level record of a list item; false for an item
// without a version, or one whose name no backend path carries.
func (it jsrListItem) record() (snapRecord, bool) {
	if len(it.Scope) > 64 || len(it.Name) > 128 {
		return snapRecord{}, false
	}
	if _, ok := jsr.PackageMetaPath(it.Scope, it.Name); !ok {
		return snapRecord{}, false
	}
	latest := ""
	if it.LatestVersion != nil && jsrValidVersion(*it.LatestVersion) {
		latest = *it.LatestVersion
	}
	if it.VersionCount <= 0 && latest == "" {
		return snapRecord{}, false
	}
	updated := ""
	if len(it.UpdatedAt) <= 64 && snapValidString(it.UpdatedAt, 64) {
		updated = it.UpdatedAt
	}
	return snapRecord{Name: "@" + it.Scope + "/" + it.Name, Digest: latest + "|" + strconv.FormatInt(it.VersionCount, 10) + "|" + updated}, true
}

// jsrValidVersion reports whether v is a version a backend path carries:
// letters, digits, ".", "+" and "-", at most 128 characters.
func jsrValidVersion(v string) bool {
	if v == "" || len(v) > 128 {
		return false
	}
	_, ok := jsr.VersionMetaPath("a", "a", v)
	return ok
}

// readIndex reads every page of the package list, up to its first empty
// page: a page shorter than asked for is not taken for the end (a server may
// leave out an item it cannot render). The list carries no validator: an
// unchanged list makes the same copy, which the diff finds empty.
func (s *jsrSource) readIndex(ctx context.Context, _ json.RawMessage, _ *snapHeader, b *snapBuilder) (indexRead, error) {
	first := ""
	for page := 1; ; page++ {
		if page > jsrMaxPages {
			return indexRead{}, Permanent(fmt.Errorf("the JSR package list runs past %d pages", jsrMaxPages))
		}
		q := url.Values{"limit": {strconv.Itoa(s.limit)}, "page": {strconv.Itoa(page)}}
		target := join(s.api, "packages") + "?" + q.Encode()
		body, _, err := s.k.get(ctx, target, http.Header{"Accept": {"application/json"}}, jsrMaxListPage)
		if err != nil {
			return indexRead{}, fmt.Errorf("listing the JSR packages: %w", err)
		}
		items, err := jsrParseList(body)
		if err != nil {
			return indexRead{}, Permanent(fmt.Errorf("listing the JSR packages: page %d is not the list expected: %w", page, err))
		}
		if len(items) > s.limit {
			return indexRead{}, Permanent(fmt.Errorf("listing the JSR packages: page %d lists %d packages, more than the %d asked for", page, len(items), s.limit))
		}
		if len(items) > 0 {
			// A server that ignores the page would have the pass loop.
			key := items[0].Scope + "/" + items[0].Name
			if page > 1 && key == first {
				return indexRead{}, Permanent(fmt.Errorf("listing the JSR packages: page %d starts where page %d did (%s): the list does not advance", page, page-1, truncate(key, 80)))
			}
			first = key
		}
		if len(items) == 0 {
			return indexRead{}, nil
		}
		for _, it := range items {
			if r, ok := it.record(); ok {
				b.Add(r)
			}
		}
	}
}

// jsrSplitName splits "@scope/name".
func jsrSplitName(name string) (scope, pkg string, ok bool) {
	rest, ok := strings.CutPrefix(name, "@")
	if !ok {
		return "", "", false
	}
	scope, pkg, ok = strings.Cut(rest, "/")
	if !ok || strings.Contains(pkg, "/") {
		return "", "", false
	}
	if _, ok := jsr.PackageMetaPath(scope, pkg); !ok {
		return "", "", false
	}
	return scope, pkg, true
}

// jsrVersion is one version of a package's meta.json.
type jsrVersion struct {
	version string
	yanked  bool
	created time.Time
}

// jsrParseMeta reads a package's meta.json: its versions, oldest first by
// version order, the newest jsrMaxVersions of them.
func jsrParseMeta(body []byte, scope, pkg string) ([]jsrVersion, error) {
	var doc struct {
		Scope    string `json:"scope"`
		Name     string `json:"name"`
		Versions map[string]struct {
			Yanked    bool   `json:"yanked"`
			CreatedAt string `json:"createdAt"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if doc.Versions == nil {
		return nil, errors.New("it lists no versions")
	}
	if (doc.Scope != "" && doc.Scope != scope) || (doc.Name != "" && doc.Name != pkg) {
		return nil, fmt.Errorf("it describes @%s/%s", truncate(doc.Scope, 64), truncate(doc.Name, 64))
	}
	names := make([]string, 0, len(doc.Versions))
	for v := range doc.Versions {
		if jsrValidVersion(v) {
			names = append(names, v)
		}
	}
	sort.Strings(names)
	rels := make([]Release, len(names))
	for i, v := range names {
		rels[i] = Release{Version: v}
	}
	// JSR versions are SemVer: npm's order is theirs.
	orderReleases("npm", rels)
	if len(rels) > jsrMaxVersions {
		rels = rels[len(rels)-jsrMaxVersions:]
	}
	out := make([]jsrVersion, 0, len(rels))
	for _, r := range rels {
		m := doc.Versions[r.Version]
		v := jsrVersion{version: r.Version, yanked: m.Yanked}
		if t, err := time.Parse(time.RFC3339Nano, m.CreatedAt); err == nil {
			v.created = t.UTC()
		}
		out = append(out, v)
	}
	return out, nil
}

// jsrFile is one module file of a version: its manifest key and size.
type jsrFile struct {
	Path string
	Size int64
}

// MarshalJSON stores a file compactly, as [path, size].
func (f jsrFile) MarshalJSON() ([]byte, error) { return json.Marshal([]any{f.Path, f.Size}) }

// UnmarshalJSON reads [path, size].
func (f *jsrFile) UnmarshalJSON(b []byte) error {
	var pair []json.RawMessage
	if err := json.Unmarshal(b, &pair); err != nil || len(pair) != 2 {
		return errors.New("not a [path, size] pair")
	}
	if err := json.Unmarshal(pair[0], &f.Path); err != nil {
		return err
	}
	return json.Unmarshal(pair[1], &f.Size)
}

// jsrParseManifest reads a version's <version>_meta.json: the module files
// its manifest lists, sorted by path. Files no backend path carries are left
// out; a version with more than jsrMaxFiles files is refused.
func jsrParseManifest(body []byte, scope, pkg, version string) ([]jsrFile, error) {
	var doc struct {
		Manifest map[string]struct {
			Size int64 `json:"size"`
		} `json:"manifest"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if doc.Manifest == nil {
		return nil, errors.New("it has no manifest")
	}
	if len(doc.Manifest) > jsrMaxFiles {
		return nil, fmt.Errorf("its manifest lists %d files; at most %d are followed", len(doc.Manifest), jsrMaxFiles)
	}
	out := make([]jsrFile, 0, len(doc.Manifest))
	for p, e := range doc.Manifest {
		if len(p) > 1024 {
			continue
		}
		if _, ok := jsr.ModuleFilePath(scope, pkg, version, p); !ok {
			continue
		}
		size := e.Size
		if size < 0 {
			size = 0
		}
		out = append(out, jsrFile{Path: p, Size: size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Releases reads the package's meta.json and its versions' manifests through
// the gated pipeline.
func (f *jsrFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	scope, pkg, ok := jsrSplitName(name)
	if !ok {
		return nil, Permanent(fmt.Errorf("%q is not a JSR package name (@scope/name)", truncate(name, 200)))
	}
	metaPath, _ := jsr.PackageMetaPath(scope, pkg)
	body, err := f.k.read(ctx, metaPath, "application/json", jsrMaxMeta)
	if err != nil {
		return nil, err
	}
	versions, err := jsrParseMeta(body, scope, pkg)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the meta.json of %s: %w", name, err))
	}
	cache := f.loadCache(name)
	defer f.saveCache(cache, versions)
	var rels []Release
	for _, v := range versions {
		fl, cached := cache.get(v.version)
		if !cached {
			fl, err = f.versionFiles(ctx, scope, pkg, v.version)
			if err != nil {
				if IsPermanent(err) {
					continue // a version whose manifest is refused, gone or malformed
				}
				return nil, err
			}
			cache.put(v.version, fl)
		}
		rel := Release{Version: v.version, Yanked: v.yanked, Published: v.created}
		for _, file := range fl {
			if p, ok := jsr.ModuleFilePath(scope, pkg, v.version, file.Path); ok {
				rel.Artifacts = append(rel.Artifacts, Artifact{Path: p, Size: file.Size})
			}
		}
		if len(rel.Artifacts) > 0 {
			rels = append(rels, rel)
		}
	}
	return rels, nil
}

// versionFiles reads a version's manifest through the gated pipeline.
func (f *jsrFeed) versionFiles(ctx context.Context, scope, pkg, version string) ([]jsrFile, error) {
	p, ok := jsr.VersionMetaPath(scope, pkg, version)
	if !ok {
		return nil, Permanent(fmt.Errorf("version %q of @%s/%s has no metadata path", version, scope, pkg))
	}
	body, err := f.k.read(ctx, p, "application/json", jsrMaxMeta)
	if err != nil {
		return nil, err
	}
	files, err := jsrParseManifest(body, scope, pkg, version)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the %s_meta.json of @%s/%s: %w", version, scope, pkg, err))
	}
	return files, nil
}

// jsrFileCache is the stored file lists of one package's versions. A nil
// cache keeps nothing.
type jsrFileCache struct {
	Format   string               `json:"format"`
	Name     string               `json:"name"`
	Versions map[string][]jsrFile `json:"versions"`
	dirty    bool
}

const jsrCacheFormat = "jsr-files/1"

func (c *jsrFileCache) get(version string) ([]jsrFile, bool) {
	if c == nil {
		return nil, false
	}
	fl, ok := c.Versions[version]
	return fl, ok
}

func (c *jsrFileCache) put(version string, fl []jsrFile) {
	if c != nil {
		c.Versions[version] = fl
		c.dirty = true
	}
}

// jsrCacheName is the file a package's lists are kept in.
func jsrCacheName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return jsrCachePrefix + hex.EncodeToString(sum[:16]) + ".json.gz"
}

// loadCache reads a package's stored file lists; a file that is missing, does
// not read or is another package's is an empty cache. The lists only save
// requests: the paths are built anew from them, for the versions the package's
// meta.json lists, and the backend verifies every file it fetches against
// the version's manifest.
func (f *jsrFeed) loadCache(name string) *jsrFileCache {
	empty := &jsrFileCache{Format: jsrCacheFormat, Name: name, Versions: map[string][]jsrFile{}}
	if f.cache.dir == "" {
		return nil
	}
	fh, err := os.Open(f.cache.path(jsrCacheName(name)))
	if err != nil {
		return empty
	}
	defer fh.Close()
	r, release, err := openContent(fh, "the stored file lists of "+name, jsrMaxCache)
	defer release()
	if err != nil {
		return empty
	}
	var c jsrFileCache
	data, err := io.ReadAll(r)
	if err != nil || json.Unmarshal(data, &c) != nil || c.Format != jsrCacheFormat || c.Name != name || c.Versions == nil {
		return empty
	}
	for v, fl := range c.Versions {
		if !jsrValidVersion(v) || len(fl) > jsrMaxFiles {
			delete(c.Versions, v)
		}
	}
	return &c
}

// saveCache stores the file lists of the versions the package still lists.
func (f *jsrFeed) saveCache(c *jsrFileCache, versions []jsrVersion) {
	if c == nil || !c.dirty {
		return
	}
	keep := make(map[string][]jsrFile, len(versions))
	for _, v := range versions {
		if fl, ok := c.Versions[v.version]; ok {
			keep[v.version] = fl
		}
	}
	data, err := json.Marshal(&jsrFileCache{Format: jsrCacheFormat, Name: c.Name, Versions: keep})
	if err != nil || len(data) > jsrMaxCache {
		return
	}
	_ = f.cache.write(jsrCacheName(c.Name), func(w io.Writer) error {
		zw := gzip.NewWriter(w)
		if _, err := io.Copy(zw, bytes.NewReader(data)); err != nil {
			return err
		}
		return zw.Close()
	})
}
