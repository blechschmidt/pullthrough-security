package fullmirror

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/maven"
	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
)

// maven follows a repository's Maven Indexer index (Task 191).
//
// Nexus, Artifactory and other repository managers publish an index of what
// they host in Apache Maven Indexer's format beneath "<repository>/.index/":
// "nexus-maven-repository-index.properties" names the index's chain
// (nexus.index.chain-id) and its newest incremental chunk
// (nexus.index.last-incremental, with the chunks still kept listed as
// nexus.index.incremental-<n>); "nexus-maven-repository-index.gz" is the full
// index and "nexus-maven-repository-index.<n>.gz" chunk n. Every poll reads
// the properties file — conditionally, with the validators of the last read —
// and when the chain is the one the stored copy was made from and the chunk
// after the copy's is still listed, fetches the chunks from there to the
// newest and applies them to the copy (a chunk lists the documents added or
// changed since the one before, and deletion markers); otherwise it reads the
// full index. Both are streamed and parsed document by document with every
// length bounded (mavenIndexReader), the copy built in bounded memory.
//
// One index document stands for one file of a release (groupId, artifactId,
// version, classifier, extension: its UINFO), with the release's packaging,
// the file's size, time and SHA-1. It becomes the records of the files a
// build downloads: the file itself when it is a main artifact (no
// classifier) or of a classifier the feed option "classifiers" names
// (comma-separated, "*" for every one; none by default), and for a main
// artifact the release's POM. An index that lists only a release's POM
// (repo.clojars.org's does, for nearly every release) stands for its main
// artifact too, whose extension the packaging names as the release pinner's
// locator reads it ("jar" for a packaging it does not know, the type a
// dependency requests by default; none for "pom"). Every record carries the
// UINFO of its document (snapRecord.Index), which is what a later chunk's
// change or deletion of that document replaces. Paths come from the maven
// backend's own builder (maven.ArtifactPath), so they are exactly the paths
// clients request; snapshot versions (revalidated by the backend, never
// cached), signature and checksum files are left out. Records carry their
// versions: a change names the version (groupId:artifactId@version), and
// Releases answers from the stored copy without a request.
//
// Maven Central is never followed: its terms of service forbid mirroring it.
// Another upstream is followed at "<url>/.index/" (feed option "url" names
// the index directory elsewhere). The full index is fetched whenever the
// chain changes — repo.clojars.org, repo.jenkins-ci.org and
// repository.apache.org rebuild theirs as a new chain every time — and must
// download within the engine's poll timeout.

// Files and bounds of the maven feed.
const (
	mavenPropsFile = "nexus-maven-repository-index.properties"
	mavenFullFile  = "nexus-maven-repository-index.gz"
	// mavenMaxProps bounds the properties file (a few hundred bytes).
	mavenMaxProps = 64 << 10
	// mavenMaxIndex bounds the full index as downloaded (Central's runs to
	// 3.4 GB, repository.apache.org's to 1.8 GB) and mavenMaxIndexData its
	// decompressed content.
	mavenMaxIndex     = 16 << 30
	mavenMaxIndexData = 64 << 30
	// mavenMaxChunk and mavenMaxChunkData bound one incremental chunk.
	mavenMaxChunk     = 1 << 30
	mavenMaxChunkData = 8 << 30
	// mavenMaxChunks bounds the chunks one read applies (the properties file
	// lists the newest 30).
	mavenMaxChunks = 64
	// mavenMaxChunkDocs bounds the documents of the chunks one read holds in
	// memory to apply them; past it the full index is read instead, as a
	// stream.
	mavenMaxChunkDocs = 50_000
	// A document with more than mavenMaxFields fields, or a value longer
	// than mavenMaxValue (a jar's list of class names runs to megabytes), is
	// dropped; mavenMaxKept bounds a value the adapter keeps.
	mavenMaxFields = 1024
	mavenMaxValue  = 64 << 20
	mavenMaxKept   = 1024
	// mavenMaxClassifiers bounds the "classifiers" option.
	mavenMaxClassifiers = 64
	// mavenStateVersion is the version of the records a copy holds: a copy
	// made by another version is not patched with chunks.
	mavenStateVersion = 1
)

type mavenFeed struct {
	*indexFeed
	src *mavenSource
}

// mavenSource reads a repository's Maven Indexer index.
type mavenSource struct {
	k kit
	// dir is the index directory.
	dir *url.URL
	// classifiers are the classifiers mirrored besides the main artifacts;
	// all mirrors every one.
	classifiers map[string]bool
	all         bool
}

func newMavenFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "classifiers")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	if mavenIsCentral(k.upstream) {
		return nil, mavenCentralRefusal("upstream " + k.upstream.Redacted())
	}
	dir := *k.upstream
	dir.Path = strings.TrimRight(dir.Path, "/") + "/.index"
	if opts["url"] != "" {
		u, err := parseBaseURL("the feed option url", opts["url"])
		if err != nil {
			return nil, err
		}
		if mavenIsCentral(u) {
			return nil, mavenCentralRefusal("the feed option url " + u.Redacted())
		}
		dir = *u
	}
	src := &mavenSource{k: k, dir: &dir}
	if src.classifiers, src.all, err = mavenParseClassifiers(opts["classifiers"]); err != nil {
		return nil, err
	}
	return &mavenFeed{indexFeed: newIndexFeed("maven", env, src), src: src}, nil
}

func init() { Register("maven", newMavenFeed) }

// mavenCentralMirrors are the hosts of Google's copies of Maven Central, which
// serve Central's index too.
var mavenCentralMirrors = []string{
	"maven-central.storage-download.googleapis.com",
	"maven-central-eu.storage-download.googleapis.com",
	"maven-central-asia.storage-download.googleapis.com",
}

// mavenCentralID and mavenCentralChain are the index id (in any case) and the
// chain id of Maven Central's own index (nexus.index.id,
// nexus.index.chain-id), checked at every read of the properties wherever
// they are served from: a mirror, a redirect, a repository manager
// republishing the index of its proxy of Central (Nexus names that proxy
// "central").
const (
	mavenCentralID    = "central"
	mavenCentralChain = "1318453614498"
)

// mavenIsCentral reports whether u is on a host Maven Central is known by.
func mavenIsCentral(u *url.URL) bool {
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	for _, c := range append(locate.MavenCentralHosts(), mavenCentralMirrors...) {
		if h == c {
			return true
		}
	}
	return false
}

// mavenCentralRefusal is the factory's answer for Maven Central.
func mavenCentralRefusal(what string) error {
	return fmt.Errorf("%s is Maven Central, whose terms of service forbid mirroring it (they list \"scraping or mirroring any content\" as abuse): "+
		"it cannot be followed; follow a repository manager's own Maven Indexer index instead, and let builds pull what they depend on from Central "+
		"(see docs/full-mirroring.md#maven)", what)
}

// mavenParseClassifiers reads the "classifiers" option: classifiers separated
// by commas, or "*" for every one.
func mavenParseClassifiers(v string) (map[string]bool, bool, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, false, nil
	}
	if v == "*" {
		return nil, true, nil
	}
	out := map[string]bool{}
	for _, c := range strings.Split(v, ",") {
		c = strings.TrimSpace(c)
		if !mavenPlain(c) || len(c) > 128 {
			return nil, false, fmt.Errorf("option classifiers: %q is not a classifier (like sources, javadoc or linux-x86_64), and \"*\" stands alone", c)
		}
		out[c] = true
	}
	if len(out) > mavenMaxClassifiers {
		return nil, false, fmt.Errorf("option classifiers names %d classifiers; at most %d are taken", len(out), mavenMaxClassifiers)
	}
	return out, false, nil
}

// selection renders the classifier selection canonically, for the state: a
// copy made with another selection is read anew rather than patched.
func (s *mavenSource) selection() string {
	if s.all {
		return "*"
	}
	list := make([]string, 0, len(s.classifiers))
	for c := range s.classifiers {
		list = append(list, c)
	}
	sort.Strings(list)
	return strings.Join(list, ",")
}

// mavenPlain reports whether s is written in the characters Maven coordinates
// are made of: letters, digits, ".", "_", "-" and "+".
func mavenPlain(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == '+') {
			return false
		}
	}
	return true
}

// mavenState is what a read of the index keeps for the next one.
type mavenState struct {
	V int `json:"v"`
	// Props are the properties file's validators.
	Props httpValidators `json:"props"`
	// Chain and Last are the chain and the newest chunk the copy holds.
	Chain string `json:"chain,omitempty"`
	Last  int    `json:"last"`
	// Stamp is the time stamp of the properties the copy was made with
	// (nexus.index.timestamp; zero when they state none, or when an earlier
	// version of the adapter made the copy).
	Stamp time.Time `json:"stamp,omitzero"`
	// Classifiers is the classifier selection the copy was made with.
	Classifiers string `json:"classifiers,omitempty"`
	// Partial marks a copy read from a full index older than the properties
	// file that named chunk Last: the chunks between may be missing from it,
	// so no chunk is applied to it — the next change is a full read.
	Partial bool `json:"partial,omitempty"`
}

func (s *mavenSource) readIndex(ctx context.Context, prev json.RawMessage, old *snapHeader, b *snapBuilder) (indexRead, error) {
	var st mavenState
	known := prev != nil && old != nil && json.Unmarshal(prev, &st) == nil && st.V == mavenStateVersion
	// A copy made with another classifier selection is read anew whatever
	// the repository says: its properties are asked for unconditionally.
	same := known && st.Classifiers == s.selection()
	hdr := http.Header{}
	if same {
		st.Props.set(hdr)
	}
	props, validators, err := s.readProps(ctx, hdr)
	if err != nil {
		if errors.Is(err, errNotModified) && same {
			return indexRead{Unchanged: true}, nil
		}
		return indexRead{}, err
	}
	next := mavenState{V: mavenStateVersion, Props: validators, Chain: props.chain, Last: props.last, Stamp: props.timestamp, Classifiers: s.selection()}
	rd := indexRead{Head: props.head(), HeadTime: props.timestamp}
	if same && props.chain != "" && props.chain == st.Chain {
		switch {
		case props.last == st.Last && (len(props.chunks) > 0 || props.timestamp.Equal(st.Stamp)):
			// No new chunk, and nothing else new. A chain that lists
			// chunks makes one for every change: a packing that found
			// nothing to put in one moves the time stamp alone. On a chain
			// that lists none, the packer writes the full index alone and
			// keeps the chain id and last-incremental of the packing before
			// (Maven Indexer's DefaultIndexPacker without incremental
			// chunks): a new time stamp there is a new full index, read
			// below — as Maven Indexer's own updater reads it, comparing
			// the time stamps where no chunk can be applied.
			next.Partial = st.Partial
			rd.State, _ = json.Marshal(next)
			rd.Unchanged = true
			return rd, nil
		case props.last > st.Last && props.last-st.Last <= mavenMaxChunks && props.chunks[st.Last+1] && !st.Partial:
			applied, err := s.readChunks(ctx, st.Last+1, props.last, old, b)
			if err != nil {
				return indexRead{}, err
			}
			if applied {
				rd.State, _ = json.Marshal(next)
				return rd, nil
			}
			// Too many changes to hold in memory, or a chunk the
			// repository does not serve as listed: the full index is
			// read instead.
		}
	}
	stamp, err := s.readFull(ctx, b)
	if err != nil {
		return indexRead{}, err
	}
	// A full index older than the properties lacks the chunks published
	// since it was written (a repository that rebuilds only its chunks, a
	// stale copy at a CDN): chunks are not applied on top of it.
	next.Partial = !stamp.IsZero() && !props.timestamp.IsZero() && stamp.Before(props.timestamp.Add(-time.Second))
	rd.State, _ = json.Marshal(next)
	return rd, nil
}

// mavenProps is what the properties file says.
type mavenProps struct {
	id        string
	chain     string
	last      int
	chunks    map[int]bool
	timestamp time.Time
}

func (p mavenProps) head() string {
	if p.chain == "" {
		return ""
	}
	return p.chain + "/" + strconv.Itoa(p.last)
}

// readProps reads the properties file (a 304 is errNotModified).
func (s *mavenSource) readProps(ctx context.Context, hdr http.Header) (mavenProps, httpValidators, error) {
	target := join(s.dir, mavenPropsFile)
	resp, body, err := s.k.getStream(ctx, target, hdr, mavenMaxProps)
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone) {
			return mavenProps{}, httpValidators{}, fmt.Errorf("the repository publishes no Maven Indexer index at %s (set fullMirror.feed.url to its index directory): %w", s.dir.Redacted(), err)
		}
		return mavenProps{}, httpValidators{}, fmt.Errorf("reading the Maven index's properties: %w", err)
	}
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		return mavenProps{}, httpValidators{}, fmt.Errorf("reading %s: %w", target, err)
	}
	props, err := mavenParseProps(data)
	if err != nil {
		return mavenProps{}, httpValidators{}, Permanent(fmt.Errorf("%s: %w", target, err))
	}
	if strings.EqualFold(props.id, mavenCentralID) || props.chain == mavenCentralChain {
		return mavenProps{}, httpValidators{}, Permanent(mavenCentralRefusal(fmt.Sprintf("the index at %s (index id %q, chain %s)", s.dir.Redacted(), props.id, props.chain)))
	}
	return props, validatorsOf(resp), nil
}

// mavenParseProps reads the properties file (java.util.Properties' format;
// only the keys of the index are read).
func mavenParseProps(data []byte) (mavenProps, error) {
	p := mavenProps{chunks: map[int]bool{}}
	lastSet := false
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(text, "\n")
	keys := 0
	for i := 0; i < len(lines); i++ {
		line := strings.TrimLeft(lines[i], " \t\f")
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		if mavenContinues(line) {
			// A line ending in an odd number of backslashes continues on
			// the next.
			var b strings.Builder
			b.WriteString(line[:len(line)-1])
			for i+1 < len(lines) {
				i++
				next := strings.TrimLeft(lines[i], " \t\f")
				if !mavenContinues(next) {
					b.WriteString(next)
					break
				}
				b.WriteString(next[:len(next)-1])
			}
			line = b.String()
		}
		keys++
		if keys > 4096 {
			return mavenProps{}, errors.New("it holds more than 4096 properties")
		}
		sep := strings.IndexAny(line, "=:")
		if sep < 0 {
			continue
		}
		key := strings.TrimSpace(line[:sep])
		value := strings.TrimSpace(line[sep+1:])
		switch {
		case key == "nexus.index.id":
			if mavenPropValue(value) {
				p.id = value
			}
		case key == "nexus.index.chain-id":
			if !mavenPropValue(value) {
				return mavenProps{}, fmt.Errorf("the chain id %q is not one", truncate(value, 64))
			}
			p.chain = value
		case key == "nexus.index.last-incremental":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 1_000_000_000 {
				return mavenProps{}, fmt.Errorf("the last incremental chunk %q is not a counter", truncate(value, 64))
			}
			p.last, lastSet = n, true
		case strings.HasPrefix(key, "nexus.index.incremental-"):
			if n, err := strconv.Atoi(value); err == nil && n >= 0 && n <= 1_000_000_000 {
				p.chunks[n] = true
			}
		case key == "nexus.index.timestamp" || (key == "nexus.index.time" && p.timestamp.IsZero()):
			if t, err := time.Parse("20060102150405.000 -0700", value); err == nil {
				p.timestamp = t.UTC()
			}
		}
	}
	if !lastSet {
		// An index published without chunks: every change is a new chain
		// (or, without one, a new full index).
		p.last = 0
	}
	return p, nil
}

// mavenContinues reports whether a properties line continues on the next: it
// ends in an odd number of backslashes.
func mavenContinues(line string) bool {
	return (len(line)-len(strings.TrimRight(line, "\\")))%2 == 1
}

// mavenPropValue reports whether a chain id is one: printable ASCII without
// spaces, at most 64 characters.
func mavenPropValue(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// readFull reads the full index into b and returns the time stamp its header
// states (zero for none).
func (s *mavenSource) readFull(ctx context.Context, b *snapBuilder) (time.Time, error) {
	target := join(s.dir, mavenFullFile)
	_, body, err := s.k.getStream(ctx, target, nil, mavenMaxIndex)
	if err != nil {
		return time.Time{}, fmt.Errorf("reading the Maven index: %w", err)
	}
	defer body.Close()
	return mavenParse(ctx, body, target, mavenMaxIndexData, func(d mavenDoc) bool {
		if d.uinfo != "" {
			// Deletion markers, the descriptor and the group lists hold no
			// file: a full index lists what is there.
			for _, r := range s.records(d) {
				b.Add(r)
			}
		}
		return true
	})
}

// mavenChanges collects what a run of chunks changes: the documents (UINFOs)
// they add, change or delete, and the records of those present after the
// last chunk.
type mavenChanges struct {
	touched map[string]bool
	recs    map[string][]snapRecord
	docs    int
}

// apply applies one document of a chunk, in the chunks' order.
func (c *mavenChanges) apply(d mavenDoc, records func(mavenDoc) []snapRecord) {
	// A UINFO longer than a record's Index can hold names no record of the
	// copy, and makes none.
	switch {
	case d.uinfo != "" && len(d.uinfo) <= 256:
		c.docs++
		c.touched[d.uinfo] = true
		c.recs[d.uinfo] = records(d)
	case d.uinfo == "" && d.deleted != "" && len(d.deleted) <= 256:
		c.docs++
		c.touched[d.deleted] = true
		delete(c.recs, d.deleted)
	}
}

// readChunks fetches chunks from to to and applies them to the old copy into
// b. It reports false, with b untouched, when the chunks change too much to
// be held in memory, or when a chunk is not there or not an index (a partial
// sync of the index directory, a clean-up racing the properties): the full
// index is read instead. Any other failure is returned, to be tried again.
func (s *mavenSource) readChunks(ctx context.Context, from, to int, old *snapHeader, b *snapBuilder) (bool, error) {
	ch := &mavenChanges{touched: map[string]bool{}, recs: map[string][]snapRecord{}}
	for n := from; n <= to; n++ {
		target := join(s.dir, "nexus-maven-repository-index."+strconv.Itoa(n)+".gz")
		_, body, err := s.k.getStream(ctx, target, nil, mavenMaxChunk)
		if err != nil {
			if IsPermanent(err) {
				return false, nil
			}
			return false, fmt.Errorf("reading chunk %d of the Maven index: %w", n, err)
		}
		tooMany := false
		_, err = mavenParse(ctx, body, target, mavenMaxChunkData, func(d mavenDoc) bool {
			if ch.docs >= mavenMaxChunkDocs {
				tooMany = true
				return false
			}
			ch.apply(d, s.records)
			return true
		})
		body.Close()
		if tooMany || IsPermanent(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
	// A copy that does not read is the cursor's fault: the toolkit tells it
	// from an I/O error, removes it and starts over.
	if err := b.CopyFrom(old, func(r *snapRecord) bool { return !ch.touched[r.Index] }); err != nil {
		return false, err
	}
	uinfos := make([]string, 0, len(ch.recs))
	for u := range ch.recs {
		uinfos = append(uinfos, u)
	}
	sort.Strings(uinfos)
	for _, u := range uinfos {
		for _, r := range ch.recs[u] {
			b.Add(r)
		}
	}
	return true, nil
}

// mavenParse reads an index data file (compressed or not) and calls fn for
// each document until it returns false. It returns the time stamp the file's
// header states (zero for none).
func mavenParse(ctx context.Context, r io.Reader, what string, limit int64, fn func(mavenDoc) bool) (time.Time, error) {
	content, release, err := openContent(r, what, limit)
	defer release()
	if err != nil {
		return time.Time{}, err
	}
	ir, err := newMavenIndexReader(content, what)
	if err != nil {
		return time.Time{}, err
	}
	for ir.next() {
		if ir.n%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return ir.stamp, err
			}
		}
		if !fn(ir.doc) {
			return ir.stamp, nil
		}
	}
	return ir.stamp, ir.err
}

// mavenDoc is what the adapter reads of one index document.
type mavenDoc struct {
	// uinfo is the artifact's "u" field (groupId|artifactId|version|
	// classifier|extension, the classifier "NA" when none), info its "i"
	// field (packaging|lastModified|size|sources|javadoc|signature|
	// extension), sha1 its "1" field, deleted the "del" field of a deletion
	// marker. A value longer than mavenMaxKept, or not plain ASCII, is not
	// kept.
	uinfo, info, sha1, deleted string
}

// mavenIndexReader reads a Maven Indexer data file in the format Apache Maven
// Indexer's IndexDataWriter writes and IndexDataReader reads: a format
// version byte (1) and the index's time stamp (a big-endian long of
// milliseconds, -1 for none), then documents to the end of the stream, each
// an int count of its fields and the fields — a flags byte, the name as
// Java's writeUTF writes it (an unsigned short length and the bytes) and the
// value as an int length and the bytes (Java's modified UTF-8). Every length
// is checked against a bound; the values of the fields the adapter uses are
// kept, every other value is skipped unread.
type mavenIndexReader struct {
	r    *bufio.Reader
	what string
	// stamp is the index's time stamp; zero when it states none.
	stamp time.Time
	doc   mavenDoc
	// dropped counts the documents dropped as too large.
	dropped int
	n       int
	err     error
	name    [8]byte
	val     [mavenMaxKept]byte
}

func newMavenIndexReader(r io.Reader, what string) (*mavenIndexReader, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var hdr [9]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, Permanent(fmt.Errorf("%s is not a Maven Indexer index: it ends before its header", what))
		}
		return nil, fmt.Errorf("reading %s: %w", what, err)
	}
	if hdr[0] != 1 {
		return nil, Permanent(fmt.Errorf("%s is not a Maven Indexer index (data format %d, not 1)", what, hdr[0]))
	}
	m := &mavenIndexReader{r: br, what: what}
	if ts := int64(binary.BigEndian.Uint64(hdr[1:])); ts > 0 && ts < 1<<50 {
		m.stamp = time.UnixMilli(ts).UTC()
	}
	return m, nil
}

// fail records a read error: a stream that ends inside a document is cut
// short (a connection lost, or a damaged file) and worth reading again.
func (m *mavenIndexReader) fail(err error) {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		m.err = fmt.Errorf("%s ends inside document %d (truncated)", m.what, m.n+1)
		return
	}
	m.err = fmt.Errorf("reading %s: %w", m.what, err)
}

// malformed records a document that cannot be one.
func (m *mavenIndexReader) malformed(format string, args ...any) {
	m.err = Permanent(fmt.Errorf("%s: document %d: %s", m.what, m.n+1, fmt.Sprintf(format, args...)))
}

// next reads the next document into doc; false at the end of the stream or
// on an error (err).
func (m *mavenIndexReader) next() bool {
	if m.err != nil {
		return false
	}
	var b4 [4]byte
	if n, err := io.ReadFull(m.r, b4[:]); err != nil {
		if err == io.EOF && n == 0 {
			return false
		}
		m.fail(err)
		return false
	}
	count := int32(binary.BigEndian.Uint32(b4[:]))
	if count < 0 {
		m.malformed("%d fields", count)
		return false
	}
	// A document of more fields than any the adapter follows, or with a
	// value past mavenMaxValue, is read through and dropped: one odd
	// document must not fail the index. (The stream's own bound still holds.)
	drop := count > mavenMaxFields
	m.doc = mavenDoc{}
	for i := int32(0); i < count; i++ {
		var head [3]byte // the flags byte and the name's length
		if _, err := io.ReadFull(m.r, head[:]); err != nil {
			m.fail(err)
			return false
		}
		nameLen := int(binary.BigEndian.Uint16(head[1:]))
		field := ""
		if nameLen <= len(m.name) {
			if _, err := io.ReadFull(m.r, m.name[:nameLen]); err != nil {
				m.fail(err)
				return false
			}
			switch string(m.name[:nameLen]) {
			case "u", "i", "1", "del":
				field = string(m.name[:nameLen])
			}
		} else if _, err := m.r.Discard(nameLen); err != nil {
			m.fail(err)
			return false
		}
		if _, err := io.ReadFull(m.r, b4[:]); err != nil {
			m.fail(err)
			return false
		}
		valLen := int32(binary.BigEndian.Uint32(b4[:]))
		if valLen < 0 {
			m.malformed("a value of %d bytes", valLen)
			return false
		}
		if valLen > mavenMaxValue {
			drop = true
		}
		if drop || field == "" || int(valLen) > len(m.val) {
			if _, err := m.r.Discard(int(valLen)); err != nil {
				m.fail(err)
				return false
			}
			continue
		}
		v := m.val[:valLen]
		if _, err := io.ReadFull(m.r, v); err != nil {
			m.fail(err)
			return false
		}
		if !mavenASCII(v) {
			continue
		}
		switch field {
		case "u":
			m.doc.uinfo = string(v)
		case "i":
			m.doc.info = string(v)
		case "1":
			m.doc.sha1 = string(v)
		case "del":
			m.doc.deleted = string(v)
		}
	}
	if drop {
		m.doc = mavenDoc{}
		m.dropped++
	}
	m.n++
	return true
}

// mavenASCII reports whether b is printable ASCII: the fields the adapter
// keeps are written in it, and a value that is not cannot name a path.
func mavenASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

// mavenUINFO is a document's UINFO, parsed.
type mavenUINFO struct {
	group, artifact, version, classifier, extension string
}

// mavenParseUINFO reads "groupId|artifactId|version|classifier[|extension]"
// (the classifier "NA" when there is none).
func mavenParseUINFO(s string) (mavenUINFO, bool) {
	parts := strings.Split(s, "|")
	if len(parts) != 4 && len(parts) != 5 {
		return mavenUINFO{}, false
	}
	u := mavenUINFO{group: parts[0], artifact: parts[1], version: parts[2], classifier: parts[3]}
	if u.classifier == "NA" {
		u.classifier = ""
	}
	if len(parts) == 5 {
		u.extension = parts[4]
	}
	if u.group == "" || u.artifact == "" || u.version == "" {
		return mavenUINFO{}, false
	}
	return u, true
}

// mavenINFO is a document's INFO, parsed.
type mavenINFO struct {
	packaging    string
	lastModified int64
	size         int64
	extension    string
}

// mavenParseINFO reads "packaging|lastModified|size|sourcesExists|
// javadocExists|signatureExists[|extension]"; fields that do not parse are
// left unknown.
func mavenParseINFO(s string) mavenINFO {
	parts := strings.Split(s, "|")
	var in mavenINFO
	if len(parts) > 0 && parts[0] != "NA" {
		in.packaging = parts[0]
	}
	if len(parts) > 1 {
		in.lastModified, _ = strconv.ParseInt(parts[1], 10, 64)
	}
	if len(parts) > 2 {
		in.size, _ = strconv.ParseInt(parts[2], 10, 64)
	}
	if len(parts) > 6 {
		in.extension = parts[6]
	}
	return in
}

// mavenSidecar reports whether an extension is a signature's or a checksum's.
func mavenSidecar(ext string) bool {
	last := strings.ToLower(ext[strings.LastIndex(ext, ".")+1:])
	switch last {
	case "sig", "asc", "md5", "sha1", "sha256", "sha512":
		return true
	}
	return false
}

// mavenSnapshot reports whether a version is a snapshot, which the backend
// revalidates on every request and never caches.
func mavenSnapshot(v string) bool { return strings.HasSuffix(strings.ToUpper(v), "SNAPSHOT") }

// records turns one document of the index into the records of the files it
// stands for (none for a document the adapter does not follow).
func (s *mavenSource) records(d mavenDoc) []snapRecord {
	if !snapValidString(d.uinfo, 256) {
		// The UINFO is every record's Index.
		return nil
	}
	u, ok := mavenParseUINFO(d.uinfo)
	if !ok || mavenSnapshot(u.version) {
		return nil
	}
	info := mavenParseINFO(d.info)
	ext := u.extension
	if ext == "" {
		ext = info.extension
	}
	if ext == "" {
		// Maven Indexer's own reading of an index that names no extension.
		if p := info.packaging; u.classifier != "" || p == "pom" || p == "war" || p == "ear" {
			ext = p
		} else {
			ext = "jar"
		}
	}
	if ext == "" || mavenSidecar(ext) {
		return nil
	}
	if u.classifier != "" && !s.all && !s.classifiers[u.classifier] {
		return nil
	}
	name := u.group + ":" + u.artifact
	var t, size int64
	if info.lastModified > 0 {
		t = info.lastModified / 1000
	}
	if info.size > 0 {
		size = info.size
	}
	digest := ""
	if mavenIsSHA1(d.sha1) {
		digest = strings.ToLower(d.sha1)
	}
	// The document's own file: one no path carries makes the document one
	// the adapter does not follow.
	p, ok := maven.ArtifactPath(u.group, u.artifact, u.version, u.classifier, ext)
	if !ok {
		return nil
	}
	out := []snapRecord{{Name: name, Version: u.version, Path: p, Index: d.uinfo, Size: size, Time: t, Digest: digest}}
	if u.classifier != "" {
		return out
	}
	add := func(extension string) {
		if p, ok := maven.ArtifactPath(u.group, u.artifact, u.version, "", extension); ok {
			out = append(out, snapRecord{Name: name, Version: u.version, Path: p, Index: d.uinfo})
		}
	}
	switch {
	case ext != "pom":
		add("pom")
	case info.packaging != "pom":
		main, known := locate.MavenExtension(info.packaging)
		if !known {
			// The release pinner's locator assumes a jar too: it is the
			// type a dependency requests unless it names another.
			main = "jar"
		}
		add(main)
	}
	return out
}

// mavenIsSHA1 reports whether s is a hex SHA-1.
func mavenIsSHA1(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// Releases lists a coordinate's releases from the stored copy of the index.
func (f *mavenFeed) Releases(_ context.Context, name string) ([]Release, error) {
	group, artifact, ok := strings.Cut(name, ":")
	if !ok || !mavenPlain(group) || !mavenPlain(artifact) {
		return nil, Permanent(fmt.Errorf("%q is not a Maven coordinate (groupId:artifactId)", truncate(name, 200)))
	}
	recs, err := f.lookup(name)
	if err != nil {
		return nil, err
	}
	rels := mavenReleases(recs)
	orderReleases("maven", rels)
	return rels, nil
}

// mavenReleases groups a coordinate's records into releases: one per version,
// whose files are its records' paths, each once — the size the largest the
// records state (a file the index lists itself states it; one a document
// stands for does not) — sorted by path. Published is the earliest time the
// records state.
func mavenReleases(recs []snapRecord) []Release {
	type file struct {
		path string
		size int64
	}
	type version struct {
		rel   Release
		files map[string]int64
	}
	var order []string
	byVersion := map[string]*version{}
	for _, r := range recs {
		if r.Version == "" || r.Path == "" {
			continue
		}
		v, ok := byVersion[r.Version]
		if !ok {
			v = &version{rel: Release{Version: r.Version}, files: map[string]int64{}}
			byVersion[r.Version] = v
			order = append(order, r.Version)
		}
		if size, seen := v.files[r.Path]; !seen || r.Size > size {
			v.files[r.Path] = r.Size
		}
		if r.Time > 0 {
			if t := unixTime(r.Time); v.rel.Published.IsZero() || t.Before(v.rel.Published) {
				v.rel.Published = t
			}
		}
	}
	out := make([]Release, 0, len(order))
	for _, ver := range order {
		v := byVersion[ver]
		files := make([]file, 0, len(v.files))
		for p, size := range v.files {
			files = append(files, file{p, size})
		}
		sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
		for _, fl := range files {
			v.rel.Artifacts = append(v.rel.Artifacts, Artifact{Path: fl.path, Size: fl.size})
		}
		out = append(out, v.rel)
	}
	return out
}
