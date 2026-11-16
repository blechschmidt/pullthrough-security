package fullmirror

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/versions"
)

// julia follows a Julia Pkg server's registries (the Pkg server protocol:
// pkg.julialang.org, or a PkgServer.jl serving private registries).
//
// `/registries` lists the registries the server serves, each as
// "/registry/<uuid>/<tree-hash>" of its current snapshot; the cursor is that
// list. Pkg asks for it with the header Julia-Registry-Preference, and so does
// the feed: "conservative" (the default — what Julia clients get by default,
// a snapshot the storage servers hold every package of) or "eager" (the
// newest snapshot), the feed option "flavor". The server redirects to
// /registries.<flavor> (pkg.julialang.org first to a regional server, which
// the egress policy must admit, as it must for the backend's own fetches);
// the client follows.
//
// A registry whose hash changed is downloaded as the client downloads it,
// `/registry/<uuid>/<hash>` through the proxy (the backend checks it against
// the tree hash and caches it), written to a file in Env.Dir rather than held
// in memory (General is 12 MB compressed, 90 MB of TOML), and read from it as
// a stream: Registry.toml's [packages] table (uuid = { name, path }) and each
// package's Versions.toml (["<version>"] tables with git-tree-sha1 and
// yanked), with a parser written for exactly those shapes. The result — each
// package's versions with their tree hashes — is an index stored in Env.Dir
// as gzip-compressed JSON, named by the snapshot list; the feed keeps the
// cursor's index and the newest one. Changes diffs the cursor's index against
// the new snapshot's: Name@Version for each version it adds (or whose tree
// changed), Deleted for a package it no longer has. Bootstrap indexes the
// current snapshot and lists every package by name.
//
// Releases answers from the newest stored index, without a request: each
// version's file is the package tarball `/package/<uuid>/<tree-sha1>`, from
// repos/locate's Julia locator, Yanked as Versions.toml says. A name two
// registries both hold lists both packages' files. The artifacts a package's
// Artifacts.toml names (prebuilt binaries, `/artifact/<hash>`) are not
// followed: they are known only from inside the package tarball.
//
// The feed is the configured Pkg server itself: a PkgServer.jl serves the
// same protocol for private registries, flavours included.

const juliaFeedVersion = 1

// juliaIndexFormat is the format of the index files.
const juliaIndexFormat = "julia-index/1"

// Bounds of the julia feed.
const (
	juliaMaxRegistries = 256
	// juliaMaxRegistryTarball bounds a registry tarball as served, and
	// juliaMaxRegistryBytes its uncompressed content.
	// General is 12 MB compressed, 90 MB of files, 171,000 versions.
	juliaMaxRegistryTarball = 1 << 30
	juliaMaxRegistryBytes   = 1 << 30
	juliaMaxRegistryEntries = 4_000_000
	juliaMaxRegistryTOML    = 64 << 20
	juliaMaxVersionsTOML    = 8 << 20
	juliaMaxTOMLLine        = 64 << 10
	juliaMaxPackages        = 2_000_000
	// juliaMaxVersions bounds one package's versions, and
	// juliaMaxRegistryVersions a registry's.
	juliaMaxVersions         = 100_000
	juliaMaxRegistryVersions = 5_000_000
	// juliaMaxIndex bounds an index file read back, uncompressed.
	juliaMaxIndex = 1 << 30
	// juliaPage is how many changes one batch carries.
	juliaPage = 50_000
)

const (
	juliaIndexPrefix = "julia-index-"
	// juliaDownloadPrefix names a registry tarball being downloaded (as a
	// temporary file, ".julia-registry-*.tmp").
	juliaDownloadPrefix = "julia-registry-"
	juliaCurrentFile    = "julia-current.json"
)

type juliaFeed struct {
	k      kit
	flavor string
	files  files
	page   int

	mu sync.Mutex
	// cur is the newest index, loaded; curFile its file.
	cur     *juliaIndex
	curFile string
}

func juliaNewFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "flavor")
	if err != nil {
		return nil, err
	}
	flavor, err := opts.oneOf("flavor", "conservative", "eager")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	return &juliaFeed{k: k, flavor: flavor, files: files{dir: env.Dir}, page: juliaPage}, nil
}

func init() { Register("julia", juliaNewFeed) }

// juliaCursor is the julia feed's position: the snapshot of the server's
// registries the stored index is of.
type juliaCursor struct {
	Format string `json:"format"`
	// Registries are "<uuid>/<tree-hash>", sorted.
	Registries []string `json:"registries"`
	// To is the snapshot a difference spanning several batches leads to,
	// Skip how many of its changes (or, while Listing, of the names)
	// earlier batches carried. Listing marks Bootstrap's listing.
	To      *[]string `json:"to,omitempty"`
	Skip    int       `json:"skip,omitempty"`
	Listing bool      `json:"listing,omitempty"`
}

func (c *juliaCursor) cursorFormat() string { return c.Format }

func (f *juliaFeed) format() string { return cursorFormat("julia", juliaFeedVersion) }

func (f *juliaFeed) decode(cursor string, c *juliaCursor) error {
	if err := decodeCursor(cursor, f.format(), c); err != nil {
		return err
	}
	ok := c.Skip >= 0 && juliaValidSnapshot(c.Registries) && !(c.Listing && c.To != nil)
	if c.To != nil {
		ok = ok && juliaValidSnapshot(*c.To)
	}
	if !ok {
		return fmt.Errorf("%w: the julia cursor names no registry snapshot", ErrCursorInvalid)
	}
	return nil
}

func (f *juliaFeed) cursor(c juliaCursor) string {
	c.Format = f.format()
	if c.Registries == nil {
		c.Registries = []string{}
	}
	return encodeCursor(&c)
}

// juliaValidSnapshot reports whether list is a snapshot the feed writes:
// "<uuid>/<hash>" entries, sorted, one per registry.
func juliaValidSnapshot(list []string) bool {
	if len(list) > juliaMaxRegistries {
		return false
	}
	seen := map[string]bool{}
	for i, e := range list {
		uuid, hash, ok := strings.Cut(e, "/")
		if !ok || !juliaUUID(uuid) || !juliaTreeHash(hash) || seen[uuid] || (i > 0 && list[i-1] >= e) {
			return false
		}
		seen[uuid] = true
	}
	return true
}

// Bootstrap indexes the server's current registries and lists every package.
func (f *juliaFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	var c juliaCursor
	var idx *juliaIndex
	if cursor == "" {
		list, err := f.registries(ctx)
		if err != nil {
			return Batch{}, err
		}
		name := juliaIndexName(list)
		if stored, err := f.load(list); err == nil {
			// The snapshot is indexed already (a new enumeration the
			// operator asked for).
			idx = stored
			if err := f.setCurrent(idx, name); err != nil {
				return Batch{}, err
			}
		} else {
			if idx, err = f.build(ctx, list, nil); err != nil {
				return Batch{}, err
			}
			if _, err := f.store(idx); err != nil {
				return Batch{}, err
			}
		}
		f.files.pruneKeepingNewest(juliaIndexPrefix, 1, name)
		c = juliaCursor{Registries: list, Listing: true}
	} else {
		if err := f.decode(cursor, &c); err != nil {
			return Batch{}, err
		}
		if !c.Listing {
			return Batch{}, fmt.Errorf("%w: the julia cursor does not continue a listing", ErrCursorInvalid)
		}
		var err error
		if idx, err = f.load(c.Registries); err != nil {
			return Batch{}, err
		}
	}
	all := idx.names()
	page, next, more := pageItems(all, c.Skip, f.page)
	b := Batch{Head: juliaHead(c.Registries), More: more}
	for _, n := range page {
		b.Items = append(b.Items, Coordinate{Name: n})
	}
	if more {
		b.Next = f.cursor(juliaCursor{Registries: c.Registries, Listing: true, Skip: next})
	} else {
		b.Next = f.cursor(juliaCursor{Registries: c.Registries})
	}
	return b, nil
}

// Changes diffs the cursor's snapshot against the server's current one.
func (f *juliaFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	var c juliaCursor
	if err := f.decode(cursor, &c); err != nil {
		return Batch{}, err
	}
	if c.Listing {
		return Batch{}, fmt.Errorf("%w: the julia cursor continues a listing", ErrCursorInvalid)
	}
	var from, to *juliaIndex
	var toList []string
	var err error
	if c.To != nil {
		// The rest of a difference that spans several batches: both
		// indexes are stored.
		toList = *c.To
		if from, err = f.load(c.Registries); err != nil {
			return Batch{}, err
		}
		if to, err = f.load(toList); err != nil {
			return Batch{}, err
		}
	} else {
		if toList, err = f.registries(ctx); err != nil {
			return Batch{}, err
		}
		if juliaSameSnapshot(toList, c.Registries) {
			return Batch{Next: f.cursor(juliaCursor{Registries: c.Registries}), Head: juliaHead(c.Registries), LagKnown: true}, nil
		}
		if from, err = f.load(c.Registries); err != nil {
			return Batch{}, err
		}
		if stored, err := f.load(toList); err == nil {
			// Asked again from the same cursor (after a restart): the new
			// snapshot is indexed already.
			to = stored
			if err := f.setCurrent(to, juliaIndexName(toList)); err != nil {
				return Batch{}, err
			}
		} else {
			if to, err = f.build(ctx, toList, from); err != nil {
				return Batch{}, err
			}
			if _, err := f.store(to); err != nil {
				return Batch{}, err
			}
		}
	}
	// Keep the cursor's index (the engine may ask again from the same
	// cursor after a restart) and the new one.
	f.files.pruneKeepingNewest(juliaIndexPrefix, 1, juliaIndexName(c.Registries), juliaIndexName(toList))
	all := juliaDiff(from, to)
	items, next, more := pageItems(all, c.Skip, f.page)
	b := Batch{Items: items, More: more, Head: juliaHead(toList)}
	if more {
		b.Next = f.cursor(juliaCursor{Registries: c.Registries, To: &toList, Skip: next})
	} else {
		b.Next = f.cursor(juliaCursor{Registries: toList})
		b.LagKnown = true
	}
	return b, nil
}

// juliaHead shows a snapshot: its registries' tree hashes.
func juliaHead(list []string) string {
	hashes := make([]string, 0, len(list))
	for _, e := range list {
		_, h, _ := strings.Cut(e, "/")
		hashes = append(hashes, h)
	}
	if len(hashes) == 0 {
		return "(no registry)"
	}
	return strings.Join(hashes, ",")
}

func juliaSameSnapshot(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// registries reads the server's registry list in the feed's flavour.
func (f *juliaFeed) registries(ctx context.Context) ([]string, error) {
	body, _, err := f.k.get(ctx, join(f.k.upstream, "registries"), http.Header{"Julia-Registry-Preference": {f.flavor}}, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("reading the Pkg server's registries: %w", err)
	}
	list, err := juliaParseRegistries(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("reading the Pkg server's registries: %w", err))
	}
	return list, nil
}

// juliaParseRegistries reads a Pkg server's registry list: one
// "/registry/<uuid>/<tree-hash>" per line. Lines that are not one are
// skipped; a list none of whose lines is one is an error, as is a registry
// named twice. It returns "<uuid>/<hash>" entries, sorted.
func juliaParseRegistries(body []byte) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	lines := 0
	for _, l := range strings.Split(string(body), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		lines++
		rest, ok := strings.CutPrefix(l, "/registry/")
		uuid, hash, ok2 := strings.Cut(rest, "/")
		if !ok || !ok2 || !juliaUUID(uuid) || !juliaTreeHash(hash) {
			continue
		}
		if seen[uuid] {
			return nil, fmt.Errorf("it names registry %s twice", uuid)
		}
		seen[uuid] = true
		out = append(out, uuid+"/"+hash)
		if len(out) > juliaMaxRegistries {
			return nil, fmt.Errorf("it names more than %d registries", juliaMaxRegistries)
		}
	}
	if lines > 0 && len(out) == 0 {
		return nil, fmt.Errorf("none of its %d lines names a registry", lines)
	}
	sort.Strings(out)
	return out, nil
}

// juliaIndex is what the feed knows of one snapshot of the server's
// registries.
type juliaIndex struct {
	Format     string               `json:"format"`
	Registries []juliaRegistryIndex `json:"registries"`

	byName map[string][]*juliaPackage // built on demand
}

// juliaRegistryIndex is one registry's packages at one tree hash.
type juliaRegistryIndex struct {
	UUID string `json:"uuid"`
	Hash string `json:"hash"`
	// Packages are sorted by name, then UUID.
	Packages []juliaPackage `json:"packages"`
}

// juliaPackage is a package of a registry and its versions.
type juliaPackage struct {
	Name     string         `json:"name"`
	UUID     string         `json:"uuid"`
	Versions []juliaVersion `json:"versions"`
}

// juliaVersion is one ["<version>"] table of a Versions.toml.
type juliaVersion struct {
	Version string `json:"v"`
	Tree    string `json:"t"`
	Yanked  bool   `json:"y,omitempty"`
}

// snapshot is the registry list the index is of.
func (x *juliaIndex) snapshot() []string {
	out := make([]string, 0, len(x.Registries))
	for _, r := range x.Registries {
		out = append(out, r.UUID+"/"+r.Hash)
	}
	return out
}

// registry returns the index of a registry at a hash, if x holds it.
func (x *juliaIndex) registry(uuid, hash string) *juliaRegistryIndex {
	if x == nil {
		return nil
	}
	for i := range x.Registries {
		if x.Registries[i].UUID == uuid && x.Registries[i].Hash == hash {
			return &x.Registries[i]
		}
	}
	return nil
}

// lookup returns the packages of a name, in every registry.
func (x *juliaIndex) lookup(name string) []*juliaPackage {
	if x.byName == nil {
		x.byName = map[string][]*juliaPackage{}
		for i := range x.Registries {
			for j := range x.Registries[i].Packages {
				p := &x.Registries[i].Packages[j]
				x.byName[p.Name] = append(x.byName[p.Name], p)
			}
		}
	}
	return x.byName[name]
}

// names lists every package name, sorted, each once.
func (x *juliaIndex) names() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range x.Registries {
		for _, p := range r.Packages {
			if !seen[p.Name] {
				seen[p.Name] = true
				out = append(out, p.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// juliaIndexName is the file the index of a snapshot is stored in.
func juliaIndexName(list []string) string {
	sum := sha256.Sum256([]byte(strings.Join(list, "\n")))
	return juliaIndexPrefix + hex.EncodeToString(sum[:16]) + ".json.gz"
}

// build indexes a snapshot: the registries base indexed at the same hash are
// taken from it, the others downloaded through the proxy.
func (f *juliaFeed) build(ctx context.Context, list []string, base *juliaIndex) (*juliaIndex, error) {
	idx := &juliaIndex{Format: juliaIndexFormat}
	for _, e := range list {
		uuid, hash, _ := strings.Cut(e, "/")
		if r := base.registry(uuid, hash); r != nil {
			idx.Registries = append(idx.Registries, *r)
			continue
		}
		r, err := f.fetchRegistry(ctx, uuid, hash)
		if err != nil {
			return nil, err
		}
		idx.Registries = append(idx.Registries, r)
	}
	return idx, nil
}

// fetchRegistry downloads a registry's tarball through the proxy and reads
// it.
func (f *juliaFeed) fetchRegistry(ctx context.Context, uuid, hash string) (juliaRegistryIndex, error) {
	p := "/registry/" + uuid + "/" + hash
	fh, err := f.readToFile(ctx, p, juliaMaxRegistryTarball)
	if err != nil {
		return juliaRegistryIndex{}, fmt.Errorf("reading registry %s: %w", uuid, err)
	}
	defer func() {
		fh.Close()
		os.Remove(fh.Name())
	}()
	pkgs, err := juliaParseRegistryTarball(fh, uuid)
	if err != nil {
		return juliaRegistryIndex{}, Permanent(fmt.Errorf("registry %s at %s: %w", uuid, hash, err))
	}
	return juliaRegistryIndex{UUID: uuid, Hash: hash, Packages: pkgs}, nil
}

// juliaFileWriter writes to a file up to a limit.
type juliaFileWriter struct {
	f        *os.File
	n, limit int64
	exceeded bool
}

func (w *juliaFileWriter) Write(p []byte) (int, error) {
	if w.n+int64(len(p)) > w.limit {
		w.exceeded = true
		return 0, errTooLarge
	}
	n, err := w.f.Write(p)
	w.n += int64(n)
	return n, err
}

// readToFile reads a path of the upstream's mount through the gated pipeline
// into a temporary file in Env.Dir, positioned at its start (kit.read holds
// a document in memory; a registry is too big for that). The caller closes
// and removes it.
func (f *juliaFeed) readToFile(ctx context.Context, p string, limit int64) (*os.File, error) {
	if f.k.env.Read == nil || f.files.dir == "" {
		return nil, errValidationOnly
	}
	// A download a crash cut short is left behind as a temporary file; the
	// sweep removes such files once they are an hour old (no other file of
	// the feed starts with the prefix).
	f.files.pruneKeepingNewest(juliaDownloadPrefix, 0)
	fh, err := os.CreateTemp(f.files.dir, "."+juliaDownloadPrefix+"*.tmp")
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) {
		fh.Close()
		os.Remove(fh.Name())
		return nil, err
	}
	w := &juliaFileWriter{f: fh, limit: limit}
	res, err := f.k.env.Read(ctx, p, "", w)
	if w.exceeded {
		return fail(Permanent(fmt.Errorf("reading %s: %w (%d bytes)", p, errTooLarge, limit)))
	}
	if err != nil {
		return fail(fmt.Errorf("reading %s through the proxy: %w", p, err))
	}
	if res.Status != http.StatusOK {
		return fail(readError(p, res))
	}
	if _, err := fh.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	return fh, nil
}

// juliaParseRegistryTarball reads a registry tarball (a gzip-compressed tar,
// as a Pkg server serves it) as it streams: Registry.toml and every
// Versions.toml, joined into the registry's packages, sorted by name. A
// package whose Versions.toml does not parse, or that has none, is left out;
// a Registry.toml that does not parse, or names another registry, is an
// error.
func juliaParseRegistryTarball(r io.Reader, uuid string) ([]juliaPackage, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("not a gzip file: %w", err)
	}
	lr := &io.LimitedReader{R: zr, N: juliaMaxRegistryBytes}
	tr := tar.NewReader(lr)
	var reg *juliaRegistryTOML
	versionsOf := map[string][]juliaVersion{}
	total := 0
	for entries := 0; ; entries++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if lr.N <= 0 {
				return nil, fmt.Errorf("%w (%d bytes uncompressed)", errTooLarge, int64(juliaMaxRegistryBytes))
			}
			return nil, fmt.Errorf("not a tar archive: %w", err)
		}
		if entries >= juliaMaxRegistryEntries {
			return nil, fmt.Errorf("it has more than %d entries", juliaMaxRegistryEntries)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.TrimPrefix(h.Name, "./")
		switch {
		case name == "Registry.toml":
			if h.Size > juliaMaxRegistryTOML {
				return nil, fmt.Errorf("its Registry.toml is %d bytes long", h.Size)
			}
			data, err := io.ReadAll(io.LimitReader(tr, h.Size))
			if err != nil {
				return nil, err
			}
			t, err := juliaParseRegistryTOML(data)
			if err != nil {
				return nil, fmt.Errorf("Registry.toml: %w", err)
			}
			reg = &t
		case path.Base(name) == "Versions.toml" && h.Size <= juliaMaxVersionsTOML:
			dir := path.Dir(name)
			data, err := io.ReadAll(io.LimitReader(tr, h.Size))
			if err != nil {
				return nil, err
			}
			if vs, err := juliaParseVersionsTOML(data); err == nil {
				if total += len(vs); total > juliaMaxRegistryVersions {
					return nil, fmt.Errorf("it lists more than %d versions", juliaMaxRegistryVersions)
				}
				versionsOf[dir] = vs
			}
		}
	}
	if reg == nil {
		return nil, fmt.Errorf("it has no Registry.toml")
	}
	if reg.uuid != uuid {
		return nil, fmt.Errorf("it is registry %s", reg.uuid)
	}
	out := make([]juliaPackage, 0, len(reg.packages))
	for _, p := range reg.packages {
		vs := versionsOf[p.path]
		if len(vs) == 0 {
			continue
		}
		out = append(out, juliaPackage{Name: p.name, UUID: p.uuid, Versions: vs})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].UUID < out[j].UUID
	})
	return out, nil
}

// juliaRegistryTOML is what the feed reads of a Registry.toml.
type juliaRegistryTOML struct {
	uuid     string
	packages []juliaRegistryEntry
}

// juliaRegistryEntry is one entry of Registry.toml's [packages] table.
type juliaRegistryEntry struct {
	uuid, name, path string
}

// juliaTOMLScanner reads one line of a TOML file.
type juliaTOMLScanner struct {
	s string
	i int
}

func (p *juliaTOMLScanner) space() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

// end reports whether the rest of the line is blank or a comment.
func (p *juliaTOMLScanner) end() bool {
	p.space()
	return p.i == len(p.s) || p.s[p.i] == '#'
}

// peek returns the next character after blanks, or 0.
func (p *juliaTOMLScanner) peek() byte {
	p.space()
	if p.i < len(p.s) {
		return p.s[p.i]
	}
	return 0
}

// expect consumes c after blanks.
func (p *juliaTOMLScanner) expect(c byte) bool {
	if p.peek() == c {
		p.i++
		return true
	}
	return false
}

// key reads a bare or a quoted key.
func (p *juliaTOMLScanner) key() (string, bool) {
	if c := p.peek(); c == '"' || c == '\'' {
		return p.str()
	}
	start := p.i
	for p.i < len(p.s) {
		c := p.s[p.i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			break
		}
		p.i++
	}
	return p.s[start:p.i], p.i > start
}

// str reads a one-line basic ("…", with escapes) or literal ('…') string.
func (p *juliaTOMLScanner) str() (string, bool) {
	switch p.peek() {
	case '\'':
		end := strings.IndexByte(p.s[p.i+1:], '\'')
		if end < 0 {
			return "", false
		}
		v := p.s[p.i+1 : p.i+1+end]
		p.i += end + 2
		return v, juliaNoControl(v)
	case '"':
	default:
		return "", false
	}
	var b strings.Builder
	for j := p.i + 1; j < len(p.s); j++ {
		c := p.s[j]
		switch {
		case c == '"':
			p.i = j + 1
			return b.String(), true
		case c == '\\':
			j++
			if j >= len(p.s) {
				return "", false
			}
			switch e := p.s[j]; e {
			case '"', '\\':
				b.WriteByte(e)
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'u', 'U':
				n := 4
				if e == 'U' {
					n = 8
				}
				if j+n >= len(p.s) {
					return "", false
				}
				v, err := strconv.ParseUint(p.s[j+1:j+1+n], 16, 32)
				if err != nil || !utf8.ValidRune(rune(v)) {
					return "", false
				}
				b.WriteRune(rune(v))
				j += n
			default:
				return "", false
			}
		case c < 0x20 && c != '\t' || c == 0x7f:
			return "", false
		default:
			b.WriteByte(c)
		}
	}
	return "", false
}

// juliaNoControl reports whether s has no control character but tab.
func juliaNoControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}

// header reads a table header line, "[a.b]" or "[[a.b]]", returning its
// dotted key.
func (p *juliaTOMLScanner) header() (string, bool) {
	if !p.expect('[') {
		return "", false
	}
	array := p.expect('[')
	var parts []string
	for {
		k, ok := p.key()
		if !ok {
			return "", false
		}
		parts = append(parts, k)
		if !p.expect('.') {
			break
		}
	}
	if !p.expect(']') || (array && !p.expect(']')) || !p.end() {
		return "", false
	}
	return strings.Join(parts, "."), true
}

// skipValue skips a value the feed does not read: a string (one that runs
// over several lines returns its closing delimiter), a boolean, a number or
// a date. Arrays and inline tables are not expected outside [packages].
func (p *juliaTOMLScanner) skipValue() (multiline string, ok bool) {
	p.space()
	rest := p.s[p.i:]
	for _, delim := range []string{`"""`, `'''`} {
		if strings.HasPrefix(rest, delim) {
			p.i += 3
			if juliaCloseMultiline(p, delim) {
				return "", p.end()
			}
			return delim, true
		}
	}
	if c := p.peek(); c == '"' || c == '\'' {
		_, ok := p.str()
		return "", ok && p.end()
	}
	start := p.i
	for p.i < len(p.s) {
		c := p.s[p.i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_:.+-", c) >= 0) {
			break
		}
		p.i++
	}
	return "", p.i > start && p.end()
}

// juliaCloseMultiline finds the end of a multi-line string from p's
// position: the delimiter not escaped (a basic string's), with up to two
// quotes of the content before it.
func juliaCloseMultiline(p *juliaTOMLScanner, delim string) bool {
	for {
		k := strings.Index(p.s[p.i:], delim)
		if k < 0 {
			return false
		}
		at := p.i + k
		if delim == `"""` {
			bs := 0
			for j := at - 1; j >= p.i && p.s[j] == '\\'; j-- {
				bs++
			}
			if bs%2 == 1 {
				p.i = at + 1
				continue
			}
		}
		p.i = at + 3
		for n := 0; n < 2 && p.i < len(p.s) && p.s[p.i] == delim[0]; n++ {
			p.i++
		}
		return true
	}
}

// juliaLines calls fn for each line of a TOML document, at most
// juliaMaxTOMLLine long.
func juliaLines(data []byte, fn func(n int, line string) error) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("it is not UTF-8")
	}
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if len(line) > juliaMaxTOMLLine {
			return fmt.Errorf("line %d is longer than %d bytes", n+1, juliaMaxTOMLLine)
		}
		if err := fn(n+1, line); err != nil {
			return err
		}
	}
	return nil
}

// juliaParseRegistryTOML reads a registry's Registry.toml: the registry's
// uuid (a top-level key) and its [packages] table, one
// `<uuid> = { name = "<Name>", path = "<L>/<Name>" }` per line. Other keys
// and tables are skipped; an entry whose uuid, name or path is not valid is
// left out. A document that is not of these shapes is an error.
func juliaParseRegistryTOML(data []byte) (juliaRegistryTOML, error) {
	var reg juliaRegistryTOML
	if len(data) > juliaMaxRegistryTOML {
		return reg, fmt.Errorf("it is %d bytes long", len(data))
	}
	table := ""
	multiline := ""
	seen := map[string]bool{}
	err := juliaLines(data, func(n int, line string) error {
		p := &juliaTOMLScanner{s: line}
		if multiline != "" {
			if juliaCloseMultiline(p, multiline) {
				multiline = ""
				if !p.end() {
					return fmt.Errorf("line %d: text after a multi-line string", n)
				}
			}
			return nil
		}
		if p.end() {
			return nil
		}
		if p.peek() == '[' {
			h, ok := p.header()
			switch {
			case !ok:
				return fmt.Errorf("line %d is not a table header", n)
			case h == "packages":
				table = "packages"
			case strings.HasPrefix(h, "packages."):
				return fmt.Errorf("line %d: [packages] as sub-tables is not read", n)
			default:
				table = "other"
			}
			return nil
		}
		key, ok := p.key()
		if !ok || !p.expect('=') {
			return fmt.Errorf("line %d is not `key = value`", n)
		}
		switch {
		case table == "packages":
			e, ok := juliaPackageEntry(p, key)
			if !ok {
				return nil // an entry that is not valid is left out
			}
			if !seen[e.uuid] {
				seen[e.uuid] = true
				if len(reg.packages) >= juliaMaxPackages {
					return fmt.Errorf("it lists more than %d packages", juliaMaxPackages)
				}
				reg.packages = append(reg.packages, e)
			}
		case table == "" && key == "uuid":
			v, ok := p.str()
			if !ok || !p.end() || !juliaUUID(strings.ToLower(v)) {
				return fmt.Errorf("line %d: the registry's uuid is not a UUID", n)
			}
			reg.uuid = strings.ToLower(v)
		default:
			delim, ok := p.skipValue()
			if !ok {
				return fmt.Errorf("line %d: a value the feed does not read", n)
			}
			multiline = delim
		}
		return nil
	})
	if err != nil {
		return juliaRegistryTOML{}, err
	}
	if multiline != "" {
		return juliaRegistryTOML{}, fmt.Errorf("a multi-line string does not end")
	}
	if reg.uuid == "" {
		return juliaRegistryTOML{}, fmt.Errorf("it states no uuid")
	}
	return reg, nil
}

// juliaPackageEntry reads the inline table of a [packages] entry.
func juliaPackageEntry(p *juliaTOMLScanner, key string) (juliaRegistryEntry, bool) {
	e := juliaRegistryEntry{uuid: strings.ToLower(key)}
	if !juliaUUID(e.uuid) || !p.expect('{') {
		return e, false
	}
	for first := true; ; first = false {
		if p.expect('}') {
			break
		}
		if !first && !p.expect(',') {
			return e, false
		}
		k, ok := p.key()
		if !ok || !p.expect('=') {
			return e, false
		}
		v, ok := p.str()
		if !ok {
			return e, false
		}
		switch k {
		case "name":
			e.name = v
		case "path":
			e.path = v
		}
	}
	if !p.end() || !juliaIsName(e.name) || !juliaRelPath(e.path) {
		return e, false
	}
	e.path = path.Clean(e.path)
	return e, true
}

// juliaParseVersionsTOML reads a package's Versions.toml: one
// `["<version>"]` table per version with `git-tree-sha1 = "<40 hex>"` and,
// for a withdrawn version, `yanked = true`. Other string or boolean keys are
// skipped; a version without a valid tree hash is left out. A document that
// is not of these shapes, or names a version twice, is an error.
func juliaParseVersionsTOML(data []byte) ([]juliaVersion, error) {
	if len(data) > juliaMaxVersionsTOML {
		return nil, fmt.Errorf("it is %d bytes long", len(data))
	}
	var out []juliaVersion
	cur := -1 // the version being read; -1 before the first table, -2 in one left out
	seen := map[string]bool{}
	err := juliaLines(data, func(n int, line string) error {
		p := &juliaTOMLScanner{s: line}
		if p.end() {
			return nil
		}
		if p.peek() == '[' {
			p.i++
			v, ok := p.str()
			if !ok || !p.expect(']') || !p.end() {
				return fmt.Errorf("line %d is not a [\"<version>\"] header", n)
			}
			if seen[v] {
				return fmt.Errorf("line %d: version %q again", n, truncate(v, 64))
			}
			seen[v] = true
			if !juliaIsVersion(v) {
				cur = -2
				return nil
			}
			if len(out) >= juliaMaxVersions {
				return fmt.Errorf("it lists more than %d versions", juliaMaxVersions)
			}
			out = append(out, juliaVersion{Version: v})
			cur = len(out) - 1
			return nil
		}
		if cur == -1 {
			return fmt.Errorf("line %d: a key outside a version's table", n)
		}
		key, ok := p.key()
		if !ok || !p.expect('=') {
			return fmt.Errorf("line %d is not `key = value`", n)
		}
		switch c := p.peek(); {
		case c == '"' || c == '\'':
			v, ok := p.str()
			if !ok || !p.end() {
				return fmt.Errorf("line %d: a string that does not end", n)
			}
			if key == "git-tree-sha1" && cur >= 0 {
				out[cur].Tree = strings.ToLower(v)
			}
		case strings.HasPrefix(p.s[p.i:], "true") || strings.HasPrefix(p.s[p.i:], "false"):
			b := strings.HasPrefix(p.s[p.i:], "true")
			if b {
				p.i += 4
			} else {
				p.i += 5
			}
			if !p.end() {
				return fmt.Errorf("line %d: text after a boolean", n)
			}
			if key == "yanked" && cur >= 0 {
				out[cur].Yanked = b
			}
		default:
			return fmt.Errorf("line %d: a value the feed does not read", n)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	kept := out[:0]
	for _, v := range out {
		if juliaTreeHash(v.Tree) && len(v.Tree) == 40 {
			kept = append(kept, v)
		}
	}
	return kept, nil
}

// juliaUUID reports whether s is a lower-case hyphenated UUID, the form the
// Pkg server protocol (and the backend) take.
func juliaUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// juliaTreeHash reports whether s is a content hash the backend serves: a
// git-tree-sha1 (40 lower-case hex digits) or the reserved SHA3-256 form
// (64).
func juliaTreeHash(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// juliaIsName reports whether s is a package name: an ASCII identifier.
func juliaIsName(s string) bool {
	if s == "" || len(s) > 128 || s[0] >= '0' && s[0] <= '9' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// juliaIsVersion reports whether s is a version as Versions.toml writes
// them: a digit, then letters, digits, ".", "-" and "+".
func juliaIsVersion(s string) bool {
	if s == "" || len(s) > 64 || s[0] < '0' || s[0] > '9' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '+') {
			return false
		}
	}
	return true
}

// juliaRelPath reports whether s is a package's directory in the registry: a
// relative path without dot segments.
func juliaRelPath(s string) bool {
	if s == "" || len(s) > 512 || strings.HasPrefix(s, "/") || strings.ContainsAny(s, "\\\x00") {
		return false
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// store writes an index and makes it the newest; it returns the file name.
func (f *juliaFeed) store(idx *juliaIndex) (string, error) {
	name := juliaIndexName(idx.snapshot())
	err := f.files.write(name, func(w io.Writer) error {
		zw := gzip.NewWriter(w)
		if err := json.NewEncoder(zw).Encode(idx); err != nil {
			return err
		}
		return zw.Close()
	})
	if err != nil {
		return "", fmt.Errorf("storing the registry index: %w", err)
	}
	return name, f.setCurrent(idx, name)
}

// setCurrent makes a stored index the newest: Releases answers from it, and
// after a restart from the file the pointer names.
func (f *juliaFeed) setCurrent(idx *juliaIndex, name string) error {
	if err := f.files.writeJSON(juliaCurrentFile, map[string]string{"index": name}); err != nil {
		return fmt.Errorf("storing the registry index: %w", err)
	}
	f.mu.Lock()
	f.cur, f.curFile = idx, name
	f.mu.Unlock()
	return nil
}

// load reads the stored index of a cursor's snapshot; a missing one, or one
// of another snapshot, invalidates the cursor.
func (f *juliaFeed) load(list []string) (*juliaIndex, error) {
	name := juliaIndexName(list)
	f.mu.Lock()
	cur, curFile := f.cur, f.curFile
	f.mu.Unlock()
	if cur != nil && curFile == name && juliaSameSnapshot(cur.snapshot(), list) {
		return cur, nil
	}
	idx, err := f.readIndex(name)
	if err != nil {
		return nil, fmt.Errorf("%w: the registry index of the cursor is not stored (%v)", ErrCursorInvalid, err)
	}
	if !juliaSameSnapshot(idx.snapshot(), list) {
		return nil, fmt.Errorf("%w: the stored registry index is of another snapshot", ErrCursorInvalid)
	}
	return idx, nil
}

// readIndex reads an index file and checks every value in it.
func (f *juliaFeed) readIndex(name string) (*juliaIndex, error) {
	if f.files.dir == "" {
		return nil, errValidationOnly
	}
	fh, err := os.Open(f.files.path(name))
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		return nil, err
	}
	var idx juliaIndex
	if err := json.NewDecoder(io.LimitReader(zr, juliaMaxIndex)).Decode(&idx); err != nil {
		return nil, err
	}
	if idx.Format != juliaIndexFormat {
		return nil, fmt.Errorf("an index of format %q", idx.Format)
	}
	if !juliaValidSnapshot(idx.snapshot()) {
		return nil, errors.New("the index names no valid snapshot")
	}
	for _, r := range idx.Registries {
		for _, p := range r.Packages {
			if !juliaIsName(p.Name) || !juliaUUID(p.UUID) {
				return nil, fmt.Errorf("the index holds a package %q that is not valid", truncate(p.Name, 64))
			}
			for _, v := range p.Versions {
				if !juliaIsVersion(v.Version) || !juliaTreeHash(v.Tree) {
					return nil, fmt.Errorf("the index holds a version of %s that is not valid", p.Name)
				}
			}
		}
	}
	return &idx, nil
}

// current returns the newest stored index: the one this feed built, or after
// a restart the one the pointer file names (else the newest index file).
func (f *juliaFeed) current() (*juliaIndex, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cur != nil {
		return f.cur, nil
	}
	var ptr struct {
		Index string `json:"index"`
	}
	var candidates []string
	if err := f.files.readJSON(juliaCurrentFile, 1<<10, &ptr); err == nil && strings.HasPrefix(ptr.Index, juliaIndexPrefix) && !strings.ContainsAny(ptr.Index, "/\\") {
		candidates = append(candidates, ptr.Index)
	}
	candidates = append(candidates, f.newestIndexFiles()...)
	var last error = errors.New("no registry index is stored yet")
	for _, name := range candidates {
		idx, err := f.readIndex(name)
		if err != nil {
			last = err
			continue
		}
		f.cur, f.curFile = idx, name
		return idx, nil
	}
	return nil, Permanent(fmt.Errorf("reading the registry index: %w", last))
}

// newestIndexFiles lists the stored index files, newest first.
func (f *juliaFeed) newestIndexFiles() []string {
	if f.files.dir == "" {
		return nil
	}
	entries, err := os.ReadDir(f.files.dir)
	if err != nil {
		return nil
	}
	type file struct {
		name string
		mod  int64
	}
	var list []file
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), juliaIndexPrefix) || !e.Type().IsRegular() {
			continue
		}
		if info, err := e.Info(); err == nil {
			list = append(list, file{e.Name(), info.ModTime().UnixNano()})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].mod > list[j].mod })
	out := make([]string, 0, len(list))
	for _, fl := range list {
		out = append(out, fl.name)
	}
	return out
}

// juliaRef is one version of a package in one registry.
type juliaRef struct {
	uuid string
	juliaVersion
}

// juliaDiff lists what the new index adds to the old one, by name: each
// version (of each package of the name) it adds or whose tree changed, and
// Deleted for a name it no longer has. Names are in order, and a name's
// versions in version order.
func juliaDiff(old, cur *juliaIndex) []Coordinate {
	refs := func(x *juliaIndex) map[string]map[juliaRef]bool {
		out := map[string]map[juliaRef]bool{}
		for _, r := range x.Registries {
			for _, p := range r.Packages {
				m := out[p.Name]
				if m == nil {
					m = map[juliaRef]bool{}
					out[p.Name] = m
				}
				for _, v := range p.Versions {
					m[juliaRef{uuid: p.UUID, juliaVersion: juliaVersion{Version: v.Version, Tree: v.Tree}}] = true
				}
			}
		}
		return out
	}
	before, after := refs(old), refs(cur)
	names := make([]string, 0, len(after))
	for n := range after {
		names = append(names, n)
	}
	for n := range before {
		if _, ok := after[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var out []Coordinate
	for _, n := range names {
		now, ok := after[n]
		if !ok {
			out = append(out, Coordinate{Name: n, Deleted: true})
			continue
		}
		added := map[string]bool{}
		for ref := range now {
			if !before[n][ref] {
				added[ref.Version] = true
			}
		}
		vs := make([]string, 0, len(added))
		for v := range added {
			vs = append(vs, v)
		}
		juliaSortVersions(vs)
		for _, v := range vs {
			out = append(out, Coordinate{Name: n, Version: v})
		}
	}
	return out
}

// juliaScheme orders Julia versions: VersionNumber is SemVer 2.0
// (MAJOR.MINOR.PATCH[-PRE][+BUILD]), which the cargo scheme parses.
var juliaScheme, _ = versions.For("cargo")

// juliaCompareVersions orders two versions; one that does not parse comes
// first, then the strings decide.
func juliaCompareVersions(a, b string) int {
	if juliaScheme != nil {
		va, ea := juliaScheme.Parse(a)
		vb, eb := juliaScheme.Parse(b)
		switch {
		case ea == nil && eb == nil:
			if c := juliaScheme.Compare(va, vb); c != 0 {
				return c
			}
		case ea != nil && eb == nil:
			return -1
		case ea == nil && eb != nil:
			return 1
		}
	}
	return strings.Compare(a, b)
}

func juliaSortVersions(vs []string) {
	sort.SliceStable(vs, func(i, j int) bool { return juliaCompareVersions(vs[i], vs[j]) < 0 })
}

// Releases lists a package's versions from the newest stored index.
func (f *juliaFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	if !juliaIsName(name) {
		return nil, Permanent(fmt.Errorf("%q is not a Julia package name", name))
	}
	idx, err := f.current()
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	pkgs := idx.lookup(name)
	f.mu.Unlock()
	if len(pkgs) == 0 {
		return nil, Permanent(fmt.Errorf("the registries name no package %s: not found", name))
	}
	byVersion := map[string]*Release{}
	var order []string
	for _, p := range pkgs {
		for _, v := range p.Versions {
			arts, err := f.k.locate(ctx, lockfiles.Dependency{Name: name, Version: v.Version, ID: p.UUID,
				Digests: []lockfiles.Digest{{Algorithm: "sha1", Value: v.Tree, Of: "git-tree"}}}, nil)
			if err != nil {
				if IsPermanent(err) {
					continue
				}
				return nil, err
			}
			r := byVersion[v.Version]
			if r == nil {
				r = &Release{Version: v.Version, Yanked: true}
				byVersion[v.Version] = r
				order = append(order, v.Version)
			}
			r.Yanked = r.Yanked && v.Yanked
			r.Artifacts = append(r.Artifacts, arts...)
		}
	}
	if len(order) == 0 {
		return nil, Permanent(fmt.Errorf("no version of %s can be fetched through the proxy", name))
	}
	juliaSortVersions(order)
	rels := make([]Release, 0, len(order))
	for _, v := range order {
		rels = append(rels, *byVersion[v])
	}
	return rels, nil
}
