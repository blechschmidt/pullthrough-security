//go:build integration
// +build integration

package fullmirror

import (
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/e2e/pkgscan"
)

// Maven: the adapter follows a repository manager's Maven Indexer index
// beneath "<repository>/.index/". Every poll reads
// nexus-maven-repository-index.properties conditionally; while the chain it
// names is the one the stored copy was made from, the adapter fetches the
// incremental chunks after the copy's (nexus-maven-repository-index.<n>.gz)
// and applies them to the copy, otherwise it reads the full index
// (nexus-maven-repository-index.gz). An index document stands for one file of
// a release — here each release's jar — and the adapter has the mirror fetch
// it and the release's POM.
//
// The stub's repository packs its index the way Apache Maven Indexer's packer
// (DefaultIndexPacker) does, in both of the ways real repositories publish
// one:
//
//   - The seed's packing begins a chain, and the benign and the malicious
//     package are packed as its first incremental chunk, the properties of the
//     packing before carried over. Nexus 2 packs a hosted repository's index
//     so: nexus.xwiki.org's releases list chunks 1 to 11 of a chain begun on
//     2026-10-01, repository.apache.org's snapshots chunk 3384 of a chain of
//     2014 (both read on 2026-11-16; Maven Central's chain of 2011 too).
//   - While the proxy is stopped, the index is built anew and published with
//     the late package as a new chain: a new chain id, last-incremental 0, the
//     full index alone (the old chain's chunk is gone). The packer starts a
//     chain so whenever it finds no properties to continue, and Clojars, the
//     Jenkins project's Artifactory and repository.apache.org's releases
//     publish theirs so: the properties recorded of each
//     (internal/fullmirror/testdata/feeds/maven) name a chain begun by the
//     run that wrote them, and Jenkins' named a new one ten hours later.
//
// The data files are written as Maven Indexer's IndexDataWriter writes them —
// the format version, the index's time stamp, then each document's stored
// fields with their flags — and hold what it stores of a jar: the UINFO, the
// time it was indexed, the INFO (packaging, last modified, size, extension),
// name, description and SHA-1, with the index's descriptor in the full index
// and the group lists at the end of every file. Every file of the index is
// served as Nexus 2 serves it, with an ETag of its SHA-1 ("{SHA1{…}}") and the
// time of its packing. The index id is not "central", nor the chain id
// Central's: the adapter refuses Maven Central's index wherever it is served
// from.

func init() {
	register(row{
		Type:    "maven",
		Feed:    "a Maven Indexer index under `/.index/`: the properties, the full index, an incremental chunk on its chain, then a new chain",
		Start:   func(env *feedEnv) error { return mavenFeed(env).pack(env, env.Publications(), false) },
		Publish: mavenPublish,
		Options: func(*feedEnv) map[string]string { return nil },
		Files: func(_ *feedEnv, p publication) []file {
			return []file{{Path: p.Pkg.Path}, {Path: strings.TrimSuffix(p.Pkg.Path, ".jar") + ".pom"}}
		},
		Resumed: mavenResumed,
		Notes: []string{
			"jars only: classifier artifacts (option classifiers) are not covered",
			"a full index rewritten on its chain without a chunk (the packer without incremental chunks) is not covered: the adapter takes it as unchanged (reported)",
		},
	})
}

// The repository's index: its id (nexus.index.id), directory and files.
const (
	mavenIndexID    = "maven-releases"
	mavenIndexDir   = "/.index/"
	mavenPropsName  = "nexus-maven-repository-index.properties"
	mavenFullName   = "nexus-maven-repository-index.gz"
	mavenChunkNames = "nexus-maven-repository-index." // + <n>.gz
)

// mavenIndexer is the stub repository's index: what Maven Indexer keeps
// between packings, and what the Resumed check compares with.
type mavenIndexer struct {
	mu sync.Mutex
	// chain is the chain id, last the newest chunk and kept the chunks the
	// properties list, newest first; stamp is the time of the last packing.
	chain int64
	last  int
	kept  []int
	stamp time.Time
	// pubs are the packages indexed, and docs their documents, in the order
	// they were indexed.
	pubs []publication
	docs [][]mavenField
	// props are the properties as served now.
	props []byte
	// For the restart: where the restarted proxy's requests begin in the
	// stub's log, the ETag of the properties the first proxy read last, and
	// the digest of the new chain's full index.
	mark     int
	heldETag string
	newFull  string
}

// mavenField is one stored field of an index document.
type mavenField struct {
	flags       byte
	name, value string
}

// The flags Maven Indexer writes a field with: indexed 1, tokenized 2,
// stored 4.
const (
	mavenFlagsKey   = 7 // indexed, tokenized, stored: u, n, d, 1, DESCRIPTOR, IDXINFO
	mavenFlagsValue = 6 // tokenized, stored: m, i
	mavenFlagsGroup = 5 // indexed, stored: the group lists
)

func mavenFeed(env *feedEnv) *mavenIndexer {
	if ix, ok := env.get("index").(*mavenIndexer); ok {
		return ix
	}
	ix := &mavenIndexer{}
	env.set("index", ix)
	return ix
}

// mavenPublish packs the packages published: the benign and the malicious
// package as a chunk of the chain; the late package, published while the
// proxy is stopped, with the index built anew as a new chain.
func mavenPublish(env *feedEnv, added []publication) error {
	ix := mavenFeed(env)
	anew := false
	for _, p := range added {
		anew = anew || p.Variant == pkgLate
	}
	if anew {
		ix.mu.Lock()
		ix.mark, ix.heldETag = len(env.Stub.Log()), mavenETag(ix.props)
		ix.mu.Unlock()
	}
	return ix.pack(env, added, anew)
}

// pack indexes the packages published and packs the index as the packer does:
// a chunk of the new documents when it continues a chain (none on the
// packing that begins one), the full index, then the properties naming them.
// anew builds the index from scratch and begins a new chain.
func (ix *mavenIndexer) pack(env *feedEnv, added []publication, anew bool) error {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Millisecond)
	if !now.After(ix.stamp) {
		now = ix.stamp.Add(time.Millisecond)
	}
	ix.pubs = append(ix.pubs, added...)
	indexed := added
	if anew {
		// Every document indexed again; the old chain and its chunks gone.
		indexed, ix.docs = ix.pubs, nil
		for _, n := range ix.kept {
			env.Stub.Handle(mavenIndexDir+mavenChunkNames+strconv.Itoa(n)+".gz", func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "Not Found", http.StatusNotFound)
			})
		}
		ix.chain, ix.last, ix.kept = 0, 0, nil
	}
	var docs [][]mavenField
	for _, p := range indexed {
		d, err := mavenDocument(env, p, now)
		if err != nil {
			return err
		}
		docs = append(docs, d)
	}
	ix.docs = append(ix.docs, docs...)
	if ix.chain == 0 {
		// The packer's initializeProperties: a chain id of the time, no chunk.
		ix.chain = now.UnixMilli()
	} else {
		ix.last++
		ix.kept = append([]int{ix.last}, ix.kept...)
		if len(ix.kept) > 30 {
			ix.kept = ix.kept[:30]
		}
		chunk, err := ix.data(now, docs, false)
		if err != nil {
			return err
		}
		mavenServe(env, mavenIndexDir+mavenChunkNames+strconv.Itoa(ix.last)+".gz", chunk, now, "application/gzip")
	}
	ix.stamp = now
	full, err := ix.data(now, ix.docs, true)
	if err != nil {
		return err
	}
	if anew {
		ix.newFull = pkgscan.Digest(full)
	}
	ix.props = ix.properties(now)
	mavenServe(env, mavenIndexDir+mavenFullName, full, now, "application/gzip")
	mavenServe(env, mavenIndexDir+mavenPropsName, ix.props, now, "text/plain")
	return nil
}

// mavenServe serves a file of the index as Nexus 2 serves one: Range and
// conditional requests answered, an ETag of its SHA-1, the time it was packed
// as Last-Modified.
func mavenServe(env *feedEnv, path string, body []byte, modTime time.Time, contentType string) {
	etag := mavenETag(body)
	env.Stub.Handle(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("ETag", etag)
		http.ServeContent(w, r, "", modTime, bytes.NewReader(body))
	})
}

// mavenETag is the ETag Nexus 2 serves a file with.
func mavenETag(body []byte) string {
	sum := sha1.Sum(body)
	return `"{SHA1{` + hex.EncodeToString(sum[:]) + `}}"`
}

// mavenDocument is the index document of a published jar.
func mavenDocument(env *feedEnv, p publication, indexed time.Time) ([]mavenField, error) {
	group, artifact, ok := strings.Cut(p.Pkg.Name, ":")
	if !ok || !strings.HasSuffix(p.Pkg.Path, ".jar") {
		return nil, fmt.Errorf("the maven stub's %s package is not a jar of a groupId:artifactId (%s, %s)", p.Variant, p.Pkg.Name, p.Pkg.Path)
	}
	pom, err := env.fetch(strings.TrimSuffix(p.Pkg.Path, ".jar") + ".pom")
	if err != nil {
		return nil, err
	}
	description := ""
	if _, rest, ok := strings.Cut(string(pom), "<description>"); ok {
		description, _, _ = strings.Cut(rest, "</description>")
	}
	sum := sha1.Sum(p.Pkg.Body)
	return []mavenField{
		{mavenFlagsKey, "u", group + "|" + artifact + "|" + p.Pkg.Version + "|NA|jar"},
		{mavenFlagsValue, "m", strconv.FormatInt(indexed.UnixMilli(), 10)},
		{mavenFlagsValue, "i", fmt.Sprintf("jar|%d|%d|0|0|0|jar", p.Time.UnixMilli(), len(p.Pkg.Body))},
		{mavenFlagsKey, "n", artifact},
		{mavenFlagsKey, "d", description},
		{mavenFlagsKey, "1", hex.EncodeToString(sum[:])},
	}, nil
}

// data writes an index data file as IndexDataWriter writes one, gzipped: the
// header, the descriptor (the full index only), the documents, the group
// lists of the whole index.
func (ix *mavenIndexer) data(stamp time.Time, docs [][]mavenField, full bool) ([]byte, error) {
	var raw bytes.Buffer
	raw.WriteByte(1)
	_ = binary.Write(&raw, binary.BigEndian, stamp.UnixMilli())
	all := [][]mavenField{}
	if full {
		all = append(all, []mavenField{{mavenFlagsKey, "DESCRIPTOR", "NexusIndex"}, {mavenFlagsKey, "IDXINFO", "1.0|" + mavenIndexID}})
	}
	all = append(all, docs...)
	groups, roots := map[string]bool{}, map[string]bool{}
	for _, d := range ix.docs {
		group, _, _ := strings.Cut(d[0].value, "|")
		groups[group] = true
		root, _, _ := strings.Cut(group, ".")
		roots[root] = true
	}
	all = append(all,
		[]mavenField{{mavenFlagsGroup, "allGroups", "allGroups"}, {mavenFlagsGroup, "allGroupsList", mavenList(groups)}},
		[]mavenField{{mavenFlagsGroup, "rootGroups", "rootGroups"}, {mavenFlagsGroup, "rootGroupsList", mavenList(roots)}})
	for _, d := range all {
		_ = binary.Write(&raw, binary.BigEndian, int32(len(d)))
		for _, f := range d {
			raw.WriteByte(f.flags)
			_ = binary.Write(&raw, binary.BigEndian, uint16(len(f.name)))
			raw.WriteString(f.name)
			_ = binary.Write(&raw, binary.BigEndian, int32(len(f.value)))
			raw.WriteString(f.value)
		}
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return gz.Bytes(), nil
}

// mavenList renders a group list as Maven Indexer stores one: "|"-separated.
func mavenList(set map[string]bool) string {
	list := make([]string, 0, len(set))
	for s := range set {
		list = append(list, s)
	}
	sort.Strings(list)
	return strings.Join(list, "|")
}

// properties renders nexus-maven-repository-index.properties as
// java.util.Properties stores it: a date comment, then the keys in their
// natural order.
func (ix *mavenIndexer) properties(stamp time.Time) []byte {
	props := map[string]string{
		"nexus.index.id":               mavenIndexID,
		"nexus.index.chain-id":         strconv.FormatInt(ix.chain, 10),
		"nexus.index.last-incremental": strconv.Itoa(ix.last),
		"nexus.index.timestamp":        stamp.Format("20060102150405.000 -0700"),
	}
	for i, n := range ix.kept {
		props["nexus.index.incremental-"+strconv.Itoa(i)] = strconv.Itoa(n)
	}
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("#" + stamp.Format("Mon Jan 02 15:04:05 MST 2006") + "\n")
	for _, k := range keys {
		b.WriteString(k + "=" + props[k] + "\n")
	}
	return []byte(b.String())
}

// mavenResumed checks how the restarted mirror read the index. Its first read
// of the properties was conditional on the ETag of the properties it had read
// before it stopped — the validators its cursor stored — and was answered in
// full: the chain had changed. It then read the new chain's full index, once,
// and no chunk: the chain its copy was made from is gone.
func mavenResumed(env *feedEnv, _ []string) error {
	ix := mavenFeed(env)
	ix.mu.Lock()
	mark, held, full := ix.mark, ix.heldETag, ix.newFull
	ix.mu.Unlock()
	log := env.Stub.Log()
	if mark > len(log) {
		return fmt.Errorf("the stub's log is shorter than when the late package was published")
	}
	var props []pkgscan.Request
	fulls := 0
	for _, r := range log[mark:] {
		path, _, _ := strings.Cut(r.URI, "?")
		name, ok := strings.CutPrefix(path, mavenIndexDir)
		switch {
		case !ok:
		case name == mavenPropsName:
			props = append(props, r)
		case name == mavenFullName:
			fulls++
			if r.Status != http.StatusOK || r.Digest != full {
				return fmt.Errorf("the restarted mirror's read of the full index was not answered with the new chain's (%s, %s)", r, r.Digest)
			}
		case strings.HasPrefix(name, mavenChunkNames) && strings.HasSuffix(name, ".gz"):
			return fmt.Errorf("the restarted mirror read a chunk on a new chain, which lists none: %s", r)
		}
	}
	switch {
	case len(props) == 0:
		return fmt.Errorf("the restarted mirror did not read the properties")
	case props[0].Header.Get("If-None-Match") != held:
		return fmt.Errorf("the restarted mirror's first read of the properties was conditional on %q, not on %s, the ETag of the properties it had read: it did not continue from the validators it stored",
			props[0].Header.Get("If-None-Match"), held)
	case props[0].Status != http.StatusOK:
		return fmt.Errorf("the restarted mirror's first read of the properties was answered %d, want 200 (a new chain)", props[0].Status)
	case fulls != 1:
		return fmt.Errorf("the restarted mirror read the full index %d times, want once", fulls)
	}
	return nil
}
