package fullmirror

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/bazel"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// bazel follows the Bazel Central Registry's Git repository.
//
// A Bzlmod registry is a static tree — "modules/<name>/metadata.json" lists a
// module's versions, "modules/<name>/<version>/" holds each version's
// MODULE.bazel, source.json and the patches and overlay files source.json
// names — with no listing and no change feed of its own. bcr.bazel.build is
// uploaded from bazelbuild/bazel-central-registry, so the feed is that
// repository: Changes diffs the trees of two head commits (gitfeed_tree.go)
// and reports each version whose directory changed, by name and version; the
// removal of a version's MODULE.bazel or source.json is the version's
// removal; a change of metadata.json alone (a yank) brings nothing to fetch
// and is not reported. Commits are reported once they have settled (option
// "settle", default 10 minutes: bcr.bazel.build is uploaded about half a
// minute after a push; see feed_gitsettle.go). Bootstrap lists every module
// of the head once, by name, rather than each of its versions: the engine
// then lists the module once and keeps the versions its policy wants, where
// one item per version would have it read the same metadata.json for each.
//
// Releases reads the module's metadata.json through the gated pipeline, in
// the registry's order (which is version order), with yanked_versions marked
// yanked. Each version's files are its MODULE.bazel, its source archive
// ("/modules/<name>/<version>/archive", from repos/locate's bazel locator:
// the backend fetches the archive source.json names and checks it against
// source.json's integrity) and the patches and overlay files its source.json
// lists — read through the pipeline once per version and kept in a bounded
// memory (a published version's source.json does not change). A source.json
// that cannot be used (refused by a gate, missing, malformed) leaves the
// version with MODULE.bazel and the archive, whose fetches then report what
// the registry and the gates make of them; a source.json of another type
// than "archive" (git_repository, local_path) names no archive the proxy
// serves. source.json itself is rewritten and served live by the backend:
// never an artifact.
//
// The public registry's repository is bazelbuild/bazel-central-registry on
// GitHub. Any other Bzlmod registry is a static tree without its history: it
// needs the feed option "url", its Git repository, or cannot be followed.

// bazelPublicRepo is the Bazel Central Registry's Git repository.
const bazelPublicRepo = "https://github.com/bazelbuild/bazel-central-registry.git"

// bazelPublicHosts are the names of the Bazel Central Registry.
var bazelPublicHosts = []string{"bcr.bazel.build"}

// Defaults and bounds of the bazel feed.
const (
	// bazelDefaultSettle is how old a commit must be before it is reported.
	bazelDefaultSettle = 10 * time.Minute
	// bazelMaxMetadata bounds a metadata.json (the largest are a few KB).
	bazelMaxMetadata = 16 << 20
	// bazelMaxSource bounds a source.json, as the backend does.
	bazelMaxSource = 1 << 20
	// bazelMaxVersions bounds the versions one metadata.json may list (the
	// largest module lists about 150).
	bazelMaxVersions = 10_000
	// bazelMaxSourceFiles bounds the patches and overlay files of a version.
	bazelMaxSourceFiles = 4096
	// bazelSourceMemo is how many versions' source.json are kept in memory
	// (the registry holds about 10,400 versions).
	bazelSourceMemo = 32_768
)

type bazelFeed struct {
	k      kit
	git    *gitIndex
	settle time.Duration
	now    func() time.Time

	mu      sync.Mutex
	sources map[string]bazelSource
	order   []string
}

func newBazelFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "branch", "settle")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	var repo *url.URL
	switch {
	case opts["url"] != "":
		if repo, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
	case hostIs(k.upstream, bazelPublicHosts...):
		repo, _ = url.Parse(bazelPublicRepo)
	default:
		return nil, fmt.Errorf("upstream %s is not the Bazel Central Registry, whose Git repository is known: set fullMirror.feed.url to the registry's Git repository (a registry served only as a static tree, without its history, cannot be followed)", k.upstream.Redacted())
	}
	settle, err := gitSettleOption(opts, bazelDefaultSettle)
	if err != nil {
		return nil, err
	}
	g, err := newGitIndex(k, gitIndexSpec{typ: "bazel", area: bazelArea, coordinate: bazelCoordinate}, repo, opts["branch"])
	if err != nil {
		return nil, err
	}
	return &bazelFeed{k: k, git: g, settle: settle, now: time.Now, sources: map[string]bazelSource{}}, nil
}

func init() { Register("bazel", newBazelFeed) }

// bazelArea admits the root, "modules", "modules/<name>" and
// "modules/<name>/<version>": a version's MODULE.bazel and source.json sit in
// its directory, and its patches and overlay files never change without its
// source.json, which records their integrity.
func bazelArea(dir string) bool {
	if dir == "" || dir == "modules" {
		return true
	}
	rest, ok := strings.CutPrefix(dir, "modules/")
	if !ok {
		return false
	}
	name, version, nested := strings.Cut(rest, "/")
	if !nested {
		_, ok := bazel.MetadataPath(name)
		return ok
	}
	if strings.Contains(version, "/") {
		return false
	}
	_, ok = bazel.ModuleFilePath(name, version)
	return ok
}

// bazelCoordinate maps a changed file of a version's directory to the
// version. A file outside one — metadata.json (a yank, or the version list a
// new version's directory brings anyway), a README, a script — names none.
func bazelCoordinate(p string, c gitChange) (Coordinate, bool) {
	parts := strings.Split(p, "/")
	if len(parts) < 4 || parts[0] != "modules" {
		return Coordinate{}, false
	}
	name, version := parts[1], parts[2]
	if _, ok := bazel.ModuleFilePath(name, version); !ok {
		return Coordinate{}, false
	}
	if c == gitDeleted {
		// The version is gone with its MODULE.bazel or its source.json; the
		// removal of another file leaves it, with nothing new to fetch.
		if len(parts) == 4 && (parts[3] == "MODULE.bazel" || parts[3] == "source.json") {
			return Coordinate{Name: name, Version: version, Deleted: true}, true
		}
		return Coordinate{}, false
	}
	return Coordinate{Name: name, Version: version}, true
}

// Bootstrap lists every module of the head commit, once each.
func (f *bazelFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	b, err := f.git.bootstrap(ctx, cursor)
	if err != nil {
		return Batch{}, err
	}
	b.Items = bazelModules(b.Items)
	return b, nil
}

// bazelModules reduces a listing's versions to their modules. The listing is
// in path order, so a module's versions are adjacent; one that straddles two
// batches is listed in both.
func bazelModules(items []Coordinate) []Coordinate {
	out := make([]Coordinate, 0, len(items)/4+1)
	for _, c := range items {
		if n := len(out); n > 0 && out[n-1].Name == c.Name {
			continue
		}
		out = append(out, Coordinate{Name: c.Name})
	}
	return out
}

// Changes diffs the stored commit against the newest settled one.
func (f *bazelFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	b, err := gitSettleChanges(ctx, f.git, cursor, f.settle, f.now())
	if err != nil {
		return b, err
	}
	// A change to a version's directory can be an edit of its source.json
	// (BCR does edit them in place: URLs, mirror_urls, patches): what is
	// remembered of the reported versions is read again.
	f.forget(b.Items)
	return b, nil
}

// forget drops the remembered source.json of the versions a batch reports.
func (f *bazelFeed) forget(items []Coordinate) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range items {
		key := c.Name + "@" + c.Version
		if _, ok := f.sources[key]; !ok {
			continue
		}
		delete(f.sources, key)
		for i, k := range f.order {
			if k == key {
				f.order = append(f.order[:i], f.order[i+1:]...)
				break
			}
		}
	}
}

// Releases reads the module's metadata.json through the gated pipeline and
// lists each version's files.
func (f *bazelFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	mp, ok := bazel.MetadataPath(name)
	if !ok {
		return nil, Permanent(fmt.Errorf("%q is not a Bazel module name", name))
	}
	body, err := f.k.read(ctx, mp, "", bazelMaxMetadata)
	if err != nil {
		return nil, err
	}
	meta, err := bazelParseMetadata(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the metadata.json of %s: %w", name, err))
	}
	rels := make([]Release, 0, len(meta.versions))
	var first error
	for _, v := range meta.versions {
		arts, err := f.versionFiles(ctx, name, v)
		if err != nil {
			if IsPermanent(err) {
				if first == nil {
					first = err
				}
				continue // a version whose files the proxy cannot serve
			}
			return nil, err
		}
		rels = append(rels, Release{Version: v, Yanked: meta.yanked[v], Artifacts: arts})
	}
	if len(rels) == 0 && first != nil {
		return nil, first
	}
	return rels, nil
}

// versionFiles lists a version's files: MODULE.bazel, the source archive
// unless source.json names none, and the patches and overlay files
// source.json lists.
func (f *bazelFeed) versionFiles(ctx context.Context, name, version string) ([]Artifact, error) {
	mod, ok := bazel.ModuleFilePath(name, version)
	if !ok {
		return nil, Permanent(fmt.Errorf("%q is not a version the registry layout can hold", version))
	}
	src, err := f.source(ctx, name, version)
	switch {
	case err == nil:
	case IsPermanent(err):
		src = bazelSource{archive: true}
	default:
		return nil, err
	}
	arts := []Artifact{{Path: mod}}
	if src.archive {
		located, err := f.k.locate(ctx, lockfiles.Dependency{Name: name, Version: version}, nil)
		if err != nil {
			return nil, err
		}
		arts = append(arts, located...)
	}
	for _, p := range src.patches {
		if path, ok := bazel.PatchPath(name, version, p); ok {
			arts = append(arts, Artifact{Path: path})
		}
	}
	for _, o := range src.overlay {
		if path, ok := bazel.OverlayPath(name, version, o); ok {
			arts = append(arts, Artifact{Path: path})
		}
	}
	return arts, nil
}

// source reads a version's source.json through the gated pipeline, once.
func (f *bazelFeed) source(ctx context.Context, name, version string) (bazelSource, error) {
	key := name + "@" + version
	f.mu.Lock()
	s, ok := f.sources[key]
	f.mu.Unlock()
	if ok {
		return s, nil
	}
	sp, ok := bazel.SourcePath(name, version)
	if !ok {
		return bazelSource{}, Permanent(fmt.Errorf("%q is not a version the registry layout can hold", version))
	}
	body, err := f.k.read(ctx, sp, "", bazelMaxSource)
	if err != nil {
		return bazelSource{}, err
	}
	if s, err = bazelParseSource(body); err != nil {
		return bazelSource{}, Permanent(fmt.Errorf("the source.json of %s %s: %w", name, version, err))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.sources[key]; !ok {
		if len(f.order) >= bazelSourceMemo {
			delete(f.sources, f.order[0])
			f.order = f.order[1:]
		}
		f.sources[key] = s
		f.order = append(f.order, key)
	}
	return s, nil
}

// bazelMetadata is what Releases reads from a metadata.json.
type bazelMetadata struct {
	versions []string
	yanked   map[string]bool
}

// bazelParseMetadata reads a metadata.json's versions, in its order, and its
// yanked versions. Entries that are not plausible version strings are
// skipped (Releases checks each against the registry layout); a document
// without a version list is an error.
func bazelParseMetadata(body []byte) (bazelMetadata, error) {
	var doc struct {
		Versions *[]json.RawMessage         `json:"versions"`
		Yanked   map[string]json.RawMessage `json:"yanked_versions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return bazelMetadata{}, err
	}
	if doc.Versions == nil {
		return bazelMetadata{}, fmt.Errorf("it lists no versions")
	}
	if n := len(*doc.Versions); n > bazelMaxVersions {
		return bazelMetadata{}, fmt.Errorf("it lists %d versions; at most %d are followed", n, bazelMaxVersions)
	}
	m := bazelMetadata{yanked: map[string]bool{}}
	seen := map[string]bool{}
	for _, raw := range *doc.Versions {
		var v string
		if json.Unmarshal(raw, &v) != nil || v == "" || len(v) > 256 || !cleanName(v) || seen[v] {
			continue
		}
		seen[v] = true
		m.versions = append(m.versions, v)
	}
	for v := range doc.Yanked {
		if seen[v] {
			m.yanked[v] = true
		}
	}
	return m, nil
}

// bazelSource is what Releases reads from a source.json: whether it names an
// archive the backend serves, and the patches and overlay files it lists,
// sorted.
type bazelSource struct {
	archive bool
	patches []string
	overlay []string
}

// bazelParseSource reads a source.json. A body that is not a JSON object is
// an error; fields of an unexpected type are taken as absent, as the backend
// takes them.
func bazelParseSource(body []byte) (bazelSource, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return bazelSource{}, err
	}
	if obj == nil {
		return bazelSource{}, fmt.Errorf("it is not a JSON object")
	}
	var s bazelSource
	typ := "archive"
	if raw, ok := obj["type"]; ok {
		if json.Unmarshal(raw, &typ) != nil {
			typ = "" // present but not a string: not the default
		}
		typ = strings.TrimSpace(typ)
	}
	if typ == "archive" {
		var u string
		var mirrors []json.RawMessage
		hasURL := json.Unmarshal(obj["url"], &u) == nil && strings.TrimSpace(u) != ""
		hasMirrors := json.Unmarshal(obj["mirror_urls"], &mirrors) == nil && len(mirrors) > 0
		var legacy []json.RawMessage
		hasLegacy := json.Unmarshal(obj["urls"], &legacy) == nil && len(legacy) > 0
		s.archive = hasURL || hasMirrors || hasLegacy
	}
	keys := func(field string) ([]string, error) {
		var m map[string]json.RawMessage
		if raw, ok := obj[field]; !ok || json.Unmarshal(raw, &m) != nil {
			return nil, nil
		}
		if len(m) > bazelMaxSourceFiles {
			return nil, fmt.Errorf("it lists %d %s; at most %d are followed", len(m), field, bazelMaxSourceFiles)
		}
		out := make([]string, 0, len(m))
		for k := range m {
			if cleanName(k) && len(k) <= 4096 {
				out = append(out, k)
			}
		}
		sort.Strings(out)
		return out, nil
	}
	var err error
	if s.patches, err = keys("patches"); err != nil {
		return bazelSource{}, err
	}
	if s.overlay, err = keys("overlay"); err != nil {
		return bazelSource{}, err
	}
	return s, nil
}
