package fullmirror

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/homebrew"
)

// homebrew follows homebrew-core's Git history.
//
// formulae.brew.sh is generated from Homebrew/homebrew-core, where every
// formula is a Ruby file "Formula/<shard>/<name>.rb" (the shard is the
// name's first letter, or "lib") — "Formula/<name>.rb" before the sharding —
// whose bottle block is committed once its bottles are on ghcr.io. The feed
// diffs the trees of two head commits (gitfeed_tree.go), only "Formula" and
// its shards, and reports each formula whose file changed, by name; a
// deleted file is a deleted formula. Casks live in another repository and
// are not served by the proxy: they are not followed. Commits are reported
// once they have settled (option "settle", default 30 minutes:
// formulae.brew.sh is regenerated from the repository and cached for ten
// minutes; see feed_gitsettle.go). Bootstrap lists every formula of the head.
//
// Releases reads the formula's JSON document ("/api/formula/<name>.json")
// through the gated pipeline, in which the backend has rewritten each
// bottle's URL to its synthetic "/bottle/<name>/<version>/v2/<repo>/blobs/
// sha256:<digest>" endpoint, and lists one release: the formula's current
// version, spelt as the backend spells it in those paths (versions.stable —
// without the formula's revision or the bottle's rebuild), with one artifact
// per bottle. The JSON API knows only a formula's current version, so older
// versions are never listed. The option "platforms" (comma-separated bottle
// tags, "arm64_sequoia,x86_64_linux") keeps those bottles and the "all"
// bottle a platform-independent formula has; by default every bottle is
// mirrored. A deprecated formula is mirrored (brew installs it, with a
// warning); a disabled one is not (brew refuses to install it). Both bottle
// paths — the synthetic one listed here and the registry-native one brew
// requests — share one digest-keyed cache entry in the backend.
//
// The public registry's repository is Homebrew/homebrew-core on GitHub.
// Homebrew mirrors (HOMEBREW_API_DOMAIN, HOMEBREW_BOTTLE_DOMAIN) are static
// copies without history: they need the feed option "url", a clone of
// homebrew-core, or cannot be followed.

// homebrewPublicRepo is homebrew-core's Git repository.
const homebrewPublicRepo = "https://github.com/Homebrew/homebrew-core.git"

// homebrewPublicHosts are the names of the formulae JSON API.
var homebrewPublicHosts = []string{"formulae.brew.sh"}

// Defaults and bounds of the homebrew feed.
const (
	// homebrewDefaultSettle is how old a commit must be before it is
	// reported.
	homebrewDefaultSettle = 30 * time.Minute
	// homebrewMaxFormula bounds a formula document (a few KB).
	homebrewMaxFormula = 16 << 20
	// homebrewMaxBottles bounds the bottles of a formula (about ten).
	homebrewMaxBottles = 256
)

type homebrewFeed struct {
	k      kit
	git    *gitIndex
	settle time.Duration
	now    func() time.Time
	// platforms are the bottle tags kept; nil keeps every bottle.
	platforms map[string]bool
}

func newHomebrewFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "branch", "settle", "platforms")
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
	case hostIs(k.upstream, homebrewPublicHosts...):
		repo, _ = url.Parse(homebrewPublicRepo)
	default:
		return nil, fmt.Errorf("upstream %s is not formulae.brew.sh, whose repository is known: set fullMirror.feed.url to a clone of homebrew-core (a Homebrew mirror's static copy has no history and cannot be followed)", k.upstream.Redacted())
	}
	settle, err := gitSettleOption(opts, homebrewDefaultSettle)
	if err != nil {
		return nil, err
	}
	platforms, err := homebrewParsePlatforms(opts["platforms"])
	if err != nil {
		return nil, err
	}
	g, err := newGitIndex(k, gitIndexSpec{typ: "homebrew", area: homebrewArea, coordinate: homebrewCoordinate}, repo, opts["branch"])
	if err != nil {
		return nil, err
	}
	return &homebrewFeed{k: k, git: g, settle: settle, now: time.Now, platforms: platforms}, nil
}

func init() { Register("homebrew", newHomebrewFeed) }

// homebrewParsePlatforms reads the "platforms" option: bottle tags separated
// by commas.
func homebrewParsePlatforms(v string) (map[string]bool, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	out := map[string]bool{}
	for _, tag := range strings.Split(v, ",") {
		tag = strings.TrimSpace(tag)
		if !homebrewValidTag(tag) {
			return nil, fmt.Errorf("option platforms: %q is not a bottle tag (like arm64_sequoia or x86_64_linux)", tag)
		}
		out[tag] = true
	}
	return out, nil
}

// homebrewValidTag reports whether s is a bottle tag: lower-case letters,
// digits and "_".
func homebrewValidTag(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// homebrewArea admits the root, "Formula" and its shards.
func homebrewArea(dir string) bool {
	if dir == "" || dir == "Formula" {
		return true
	}
	shard, ok := strings.CutPrefix(dir, "Formula/")
	return ok && shard != "" && !strings.Contains(shard, "/") && !strings.HasPrefix(shard, ".")
}

// homebrewCoordinate maps a changed formula file — "Formula/<shard>/<name>.rb"
// or the unsharded "Formula/<name>.rb" — to the formula.
func homebrewCoordinate(p string, c gitChange) (Coordinate, bool) {
	rest, ok := strings.CutPrefix(p, "Formula/")
	if !ok {
		return Coordinate{}, false
	}
	if shard, file, nested := strings.Cut(rest, "/"); nested {
		if shard == "" || strings.Contains(file, "/") {
			return Coordinate{}, false
		}
		rest = file
	}
	name, ok := strings.CutSuffix(rest, ".rb")
	if !ok || !homebrewValidName(name) {
		return Coordinate{}, false
	}
	return Coordinate{Name: name, Deleted: c == gitDeleted}, true
}

// homebrewValidName reports whether s is a formula name the backend serves a
// document for: lower-case letters, digits and "+", "-", "_", ".", "@",
// starting with a letter or digit ("openssl@3", "libxml++").
func homebrewValidName(s string) bool {
	if len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("+-_.@", c) >= 0) {
			return false
		}
	}
	_, ok := homebrew.FormulaDocumentPath(s)
	return ok
}

func (f *homebrewFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	return f.git.bootstrap(ctx, cursor)
}

// Changes diffs the stored commit against the newest settled one.
func (f *homebrewFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	b, err := gitSettleChanges(ctx, f.git, cursor, f.settle, f.now())
	if err != nil {
		return Batch{}, err
	}
	b.Items = homebrewDropMoved(b.Items)
	return b, nil
}

// homebrewDropMoved drops the removal of a formula whose file moved (into a
// shard, or from one to another): the formula is still there, changed.
func homebrewDropMoved(items []Coordinate) []Coordinate {
	present := map[string]bool{}
	for _, c := range items {
		if !c.Deleted {
			present[c.Name] = true
		}
	}
	out := items[:0:0]
	for _, c := range items {
		if !c.Deleted || !present[c.Name] {
			out = append(out, c)
		}
	}
	return out
}

// Releases reads the formula's JSON document through the gated pipeline: its
// current version, with the bottles the backend rewrote through the proxy.
func (f *homebrewFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	if !homebrewValidName(name) {
		return nil, Permanent(fmt.Errorf("%q is not a formula name", name))
	}
	doc, _ := homebrew.FormulaDocumentPath(name)
	body, err := f.k.read(ctx, doc, "", homebrewMaxFormula)
	if err != nil {
		return nil, err
	}
	fm, err := homebrewParseFormula(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the formula document of %s: %w", name, err))
	}
	if fm.disabled {
		return nil, nil // brew refuses to install it
	}
	if fm.version == "" {
		return nil, Permanent(fmt.Errorf("the formula document of %s states no stable version", name))
	}
	var arts []Artifact
	for _, b := range fm.bottles {
		if f.platforms != nil && b.tag != "all" && !f.platforms[b.tag] {
			continue
		}
		if p, ok := f.bottlePath(b.url, name, fm.version); ok {
			arts = append(arts, Artifact{Path: p})
		}
	}
	if len(arts) == 0 {
		return nil, nil // no bottle (of the platforms kept) the proxy serves
	}
	return []Release{{Version: fm.version, Artifacts: arts}}, nil
}

// bottlePath maps a bottle URL the backend rewrote to the synthetic bottle
// path it serves, for the formula and version the document is of. A URL the
// backend left pointing at its origin (a bottle on another host than the
// bottle registry) is not one the proxy serves.
func (f *homebrewFeed) bottlePath(raw, name, version string) (string, bool) {
	p, ok := f.k.proxyPath(raw)
	if !ok {
		return "", false
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(segs) < 4 || segs[0] != "bottle" {
		return "", false
	}
	n, err1 := url.PathUnescape(segs[1])
	v, err2 := url.PathUnescape(segs[2])
	if err1 != nil || err2 != nil || n != name || v != version {
		return "", false
	}
	return p, true
}

// homebrewFormula is what Releases reads from a formula document.
type homebrewFormula struct {
	name     string
	version  string
	disabled bool
	// bottles are sorted by tag.
	bottles []homebrewBottle
}

// homebrewBottle is one bottle: its tag and its (rewritten) URL.
type homebrewBottle struct {
	tag string
	url string
}

// homebrewParseFormula reads a formula document: its name, its stable
// version, whether it is disabled, and its bottles' URLs by tag.
func homebrewParseFormula(body []byte) (homebrewFormula, error) {
	var doc struct {
		Name     string `json:"name"`
		Versions *struct {
			Stable *string `json:"stable"`
		} `json:"versions"`
		Disabled bool `json:"disabled"`
		Bottle   struct {
			Stable struct {
				Files map[string]struct {
					URL string `json:"url"`
				} `json:"files"`
			} `json:"stable"`
		} `json:"bottle"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return homebrewFormula{}, err
	}
	if doc.Name == "" || doc.Versions == nil {
		return homebrewFormula{}, fmt.Errorf("it is not a formula (no name or versions)")
	}
	fm := homebrewFormula{name: doc.Name, disabled: doc.Disabled}
	if s := doc.Versions.Stable; s != nil {
		if v := strings.TrimSpace(*s); v != "" && len(v) <= 256 && cleanName(v) && !strings.Contains(v, "/") {
			fm.version = v
		}
	}
	if len(doc.Bottle.Stable.Files) > homebrewMaxBottles {
		return homebrewFormula{}, fmt.Errorf("it lists %d bottles; at most %d are followed", len(doc.Bottle.Stable.Files), homebrewMaxBottles)
	}
	for tag, file := range doc.Bottle.Stable.Files {
		if homebrewValidTag(tag) && file.URL != "" {
			fm.bottles = append(fm.bottles, homebrewBottle{tag: tag, url: file.URL})
		}
	}
	sort.Slice(fm.bottles, func(i, j int) bool { return fm.bottles[i].tag < fm.bottles[j].tag })
	return fm, nil
}
