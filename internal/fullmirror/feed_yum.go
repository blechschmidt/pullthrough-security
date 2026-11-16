package fullmirror

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/yum"
)

// yum follows one RPM repository: a YUM/DNF repository root, the directory
// that holds repodata/ (a Fedora or EPEL updates tree, a RHEL-family BaseOS or
// AppStream, a Pulp, Artifactory or Nexus repository, any createrepo_c tree).
// The yum backend serves repodata/repomd.xml at the upstream's root only, so
// one upstream is one repository, and so is one feed.
//
// Every poll reads repodata/repomd.xml conditionally, with the ETag and
// Last-Modified the cursor keeps: a 304 costs one small request. repomd.xml
// names the package list, <data type="primary"> — never primary_zck, which is
// zchunk, not zstd — with its size and checksum, and those of its content once
// decompressed. A repomd.xml whose primary is the one already read (Fedora
// rewrites repomd.xml for updateinfo alone) changes nothing either. Otherwise
// the primary is read as a stream: its size and checksum are verified as the
// bytes arrive, it is decompressed (zstd for current Fedora, gzip for the
// RHEL family, xz for EPEL) with the decoder's memory bounded, its open-size
// and open-checksum are verified as it decompresses, and it is parsed one
// <package> at a time by the backend's own streaming reader
// (yum.StreamPrimary), its <format> subtree skipped: the memory a poll takes
// does not grow with the repository (Rocky Linux 9's BaseOS primary is 331 MB
// of XML). Each package file becomes a record of the stored copy
// (snapshot.go): its name, its version spelt "[epoch:]version-release" (the
// release is part of it: "1.8.12-1.el9" and "1.8.12-1.el9_8.1" are two
// versions), its path, size, time and checksum (in full, "<alg>:<hex>"). The
// copy is diffed against the previous one: a version added or changed is
// reported as name@version, one gone as deleted.
//
// Releases answers from the copy: a package's versions ordered by RPM's
// version comparison (rpmvercmp over epoch, version and release), oldest
// first, each with its files — one per architecture — at the paths the
// repository lists them under (the location hrefs), which the backend serves
// as they are and verifies against the primary's checksums. A file whose
// location carries an xml:base is served from another host, not through this
// upstream: it is left out.
//
// The feed is read from the upstream's own URL — public and private
// repositories alike — or from the root the option "url" names (another
// mirror of the same repository).

// Bounds of the yum feed.
const (
	// yumMaxRepomd bounds repomd.xml (a few KB; the backend's bound).
	yumMaxRepomd = 8 << 20
	// yumMaxPrimaryFile bounds the compressed primary (Rocky Linux 9's
	// BaseOS: 45.5 MB of gzip).
	yumMaxPrimaryFile = 512 << 20
	// yumMaxPrimaryXML bounds the decompressed primary (the same BaseOS: 331
	// MB of XML).
	yumMaxPrimaryXML = 2 << 30
	// yumMaxData bounds the <data> entries of a repomd.xml (a dozen).
	yumMaxData = 1000
	// yumMaxField bounds a repomd.xml field.
	yumMaxField = 4 << 10
	// yumMaxDepth bounds how deeply repomd.xml's elements nest.
	yumMaxDepth = 32
	// yumMaxValidator bounds an ETag or Last-Modified kept in the cursor.
	yumMaxValidator = 256
)

type yumFeed struct {
	*indexFeed
}

// yumSource reads one repository's primary.
type yumSource struct {
	k    kit
	root *url.URL
}

func newYumFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	root := k.upstream
	if opts["url"] != "" {
		if root, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
	}
	return &yumFeed{indexFeed: newIndexFeed("yum", env, &yumSource{k: k, root: root})}, nil
}

func init() { Register("yum", newYumFeed) }

// Releases lists a package's versions from the newest copy, oldest first by
// RPM's version order.
func (f *yumFeed) Releases(_ context.Context, name string) ([]Release, error) {
	if !yumValidName(name) {
		return nil, Permanent(fmt.Errorf("%q is not an RPM package name", truncate(name, 200)))
	}
	recs, err := f.lookup(name)
	if err != nil {
		return nil, err
	}
	rels := snapReleases(recs)
	yumSortReleases(rels)
	return rels, nil
}

// yumState is what the next read is conditioned on.
type yumState struct {
	// Validators are repomd.xml's.
	Validators httpValidators `json:"validators"`
	// Primary is the checksum of the primary read ("sha256:<hex>").
	Primary string `json:"primary"`
}

func (s *yumSource) readIndex(ctx context.Context, prev json.RawMessage, old *snapHeader, b *snapBuilder) (indexRead, error) {
	var ps yumState
	if old != nil && prev != nil && json.Unmarshal(prev, &ps) != nil {
		// Not a state this source wrote: read the repository afresh.
		ps = yumState{}
	}
	hdr := http.Header{}
	if old != nil {
		ps.Validators.set(hdr)
	}
	repomdURL := join(s.root, "repodata/repomd.xml")
	resp, body, err := s.k.getStream(ctx, repomdURL, hdr, yumMaxRepomd)
	switch {
	case errors.Is(err, errNotModified) && len(hdr) == 0:
		return indexRead{}, fmt.Errorf("%s answered 304 Not Modified to a request that was not conditional", repomdURL)
	case errors.Is(err, errNotModified):
		return indexRead{Unchanged: true}, nil
	case err != nil && resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone):
		return indexRead{}, fmt.Errorf("%w (the upstream URL — or the feed option url — must be a repository root, the directory holding repodata/)", err)
	case err != nil:
		return indexRead{}, err
	}
	data, err := readLimited(body, yumMaxRepomd)
	body.Close()
	if err != nil {
		return indexRead{}, fmt.Errorf("reading %s: %w", repomdURL, err)
	}
	md, err := yumParseRepomd(data)
	if err != nil {
		return indexRead{}, Permanent(fmt.Errorf("%s: %w", repomdURL, err))
	}
	p, err := md.primary()
	if err != nil {
		return indexRead{}, Permanent(fmt.Errorf("%s: %w", repomdURL, err))
	}
	v := yumKeepValidators(validatorsOf(resp), yumMaxValidator)
	st, _ := json.Marshal(yumState{Validators: v, Primary: p.Checksum.key()})
	rd := indexRead{State: st}
	rd.Head, rd.HeadTime = md.head(p)
	if old != nil && ps.Primary == p.Checksum.key() {
		rd.Unchanged = true
		return rd, nil
	}
	if err := s.readPrimary(ctx, p, b); err != nil {
		return indexRead{}, err
	}
	return rd, nil
}

// readPrimary reads the primary into b as it streams in.
func (s *yumSource) readPrimary(ctx context.Context, p yumRepoData, b *snapBuilder) error {
	what := "the primary " + truncate(p.Href, 200)
	fileLimit, xmlLimit := int64(yumMaxPrimaryFile), int64(yumMaxPrimaryXML)
	if p.Size > fileLimit || p.OpenSize > xmlLimit {
		return Permanent(fmt.Errorf("%s is %d bytes (%d decompressed); the feed reads at most %d (%d)", what, p.Size, p.OpenSize, fileLimit, xmlLimit))
	}
	// The file is compressed already, and its checksum is of its bytes as
	// published: ask for them as they are (net/http would otherwise ask for
	// gzip and undo a Content-Encoding a server put on a .gz file).
	_, body, err := s.k.getStream(ctx, join(s.root, p.Href), http.Header{"Accept-Encoding": {"identity"}}, fileLimit)
	if err != nil {
		return fmt.Errorf("reading %s: %w", what, err)
	}
	defer body.Close()
	// What fails below is the repository's fault — a file that does not
	// decompress, a document that does not parse — only if the file is the
	// one repomd.xml declared: the file is read to its end and verified
	// before a failure is called permanent. A failed read of the file (the
	// network, its size bound, the context) is returned as it is.
	file := newYumDigest(body, p.Checksum, p.Size)
	fault := func(err error) error {
		if file.err == nil {
			if _, rerr := io.Copy(io.Discard, file); rerr != nil && file.err == nil {
				file.err = rerr
			}
		}
		if file.err != nil {
			return fmt.Errorf("reading %s: %w", what, file.err)
		}
		if verr := file.verify(what, p.Size); verr != nil {
			return verr
		}
		if IsPermanent(err) {
			return err
		}
		return Permanent(fmt.Errorf("%s: %w", what, err))
	}
	content, release, err := openContent(file, what, xmlLimit)
	if err != nil {
		return fault(err)
	}
	defer release()
	xmlDoc := newYumDigest(content, p.OpenChecksum, p.OpenSize)
	err = yum.StreamPrimary(xmlDoc, func(e yum.PrimaryEntry) error {
		if rec, ok := yumRecord(e); ok {
			b.Add(rec)
		}
		return nil
	})
	if err == nil {
		// Read the document to its end (whatever follows its root element),
		// so that its digest covers all of it.
		_, err = io.Copy(io.Discard, xmlDoc)
	}
	if err != nil {
		return fault(err)
	}
	if err := xmlDoc.verify(what+" (decompressed)", p.OpenSize); err != nil {
		return fault(err)
	}
	if _, err := io.Copy(io.Discard, file); err != nil {
		return fmt.Errorf("reading %s: %w", what, err)
	}
	return file.verify(what, p.Size)
}

// yumKeepValidators keeps the validators the cursor can carry compactly — at
// most max bytes of printable ASCII without the characters JSON spells at
// length ("<", ">", "&", the backslash) — and drops the others: the next read
// is then unconditional. (The apt feed keeps its validators so too.)
func yumKeepValidators(v httpValidators, max int) httpValidators {
	keep := func(s string) string {
		if len(s) > max {
			return ""
		}
		for i := 0; i < len(s); i++ {
			if c := s[i]; c < 0x20 || c > 0x7e || strings.IndexByte(`<>&\`, c) >= 0 {
				return ""
			}
		}
		return s
	}
	return httpValidators{ETag: keep(v.ETag), LastModified: keep(v.LastModified)}
}

// yumRecord makes a package file's record: nothing for an entry the proxy
// cannot fetch or name.
func yumRecord(e yum.PrimaryEntry) (snapRecord, bool) {
	if e.LocationBase != "" || !yumValidName(e.Name) || (e.Arch != "" && !yumValidArch(e.Arch)) {
		return snapRecord{}, false
	}
	version, ok := yumEVR(e.Epoch, e.Version, e.Release)
	if !ok {
		return snapRecord{}, false
	}
	p, ok := yumPath(e.Location)
	if !ok {
		return snapRecord{}, false
	}
	rec := snapRecord{Name: e.Name, Version: version, Path: p, Size: e.Size}
	if e.Time > 0 && e.Time < yumMaxTime {
		rec.Time = e.Time
	}
	if _, alg, n, ok := yumNewHash(e.ChecksumType); ok {
		if sum := strings.ToLower(e.Checksum); len(sum) == n && yumIsHex(sum) {
			// In full, as the primary declares it: a file republished under
			// the same path is a change, and a fetch may check it.
			rec.Digest = alg + ":" + sum
		}
	}
	return rec, true
}

// yumMaxTime bounds the times taken from a repository (2100-01-01).
const yumMaxTime = 4102444800

// yumValidName reports whether s is an RPM package name the feed carries:
// letters, digits and "._+-", starting with a letter, a digit or "_".
func yumValidName(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		case i > 0 && (c == '.' || c == '+' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// yumValidArch reports whether s is an architecture name ("x86_64", "noarch").
func yumValidArch(s string) bool {
	if len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return s != ""
}

// yumEVR spells a package's version: "version-release", prefixed with
// "epoch:" when the epoch is not zero (as dnf shows it). A version or release
// must be letters, digits and "._+~^"; an epoch, digits.
func yumEVR(epoch, ver, rel string) (string, bool) {
	if !yumValidVR(ver) || !yumValidVR(rel) {
		return "", false
	}
	out := ver + "-" + rel
	if epoch != "" {
		n, err := strconv.ParseUint(epoch, 10, 31)
		if err != nil {
			return "", false
		}
		if n > 0 {
			out = strconv.FormatUint(n, 10) + ":" + out
		}
	}
	return out, true
}

func yumValidVR(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._+~^", c) >= 0) {
			return false
		}
	}
	return true
}

// yumPath maps a location href to the path the backend serves the file at: the
// href below the repository root, an .rpm.
func yumPath(href string) (string, bool) {
	href = strings.TrimLeft(href, "/")
	if href == "" || len(href) > 1024 || !strings.HasSuffix(href, ".rpm") || strings.ContainsAny(href, "?#\\%") || strings.Contains(href, "://") {
		return "", false
	}
	for _, seg := range strings.Split(href, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", false
		}
	}
	p := (&url.URL{Path: "/" + href}).EscapedPath()
	return p, validArtifactPath(p)
}

func yumIsHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return s != ""
}

// --- repomd.xml --------------------------------------------------------------

// yumRepomd is what the feed reads from repomd.xml.
type yumRepomd struct {
	Revision string
	Data     []yumRepoData
}

// yumRepoData is one <data> entry.
type yumRepoData struct {
	Type         string
	Href, Base   string
	Checksum     yumSum
	OpenChecksum yumSum
	Size         int64
	OpenSize     int64
	Timestamp    int64
}

// yumSum is a declared checksum: its algorithm and lower-case hex value.
type yumSum struct {
	Alg string
	Hex string
}

func (s yumSum) key() string { return s.Alg + ":" + s.Hex }

// yumNewHash returns the hash of a checksum type repomd.xml declares
// (createrepo_c's sha1/"sha", sha224, sha256, sha384, sha512), and the
// algorithm's name and hex length.
func yumNewHash(typ string) (func() hash.Hash, string, int, bool) {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "sha", "sha1":
		return sha1.New, "sha1", 40, true
	case "sha224":
		return sha256.New224, "sha224", 56, true
	case "sha256":
		return sha256.New, "sha256", 64, true
	case "sha384":
		return sha512.New384, "sha384", 96, true
	case "sha512":
		return sha512.New, "sha512", 128, true
	}
	return nil, "", 0, false
}

// primary returns the repository's primary entry, checked.
func (md yumRepomd) primary() (yumRepoData, error) {
	for _, d := range md.Data {
		if d.Type != "primary" {
			continue
		}
		switch {
		case d.Base != "":
			return d, errors.New("its primary is served from another base URL (xml:base), which the feed does not follow")
		case d.Checksum.Hex == "":
			return d, errors.New("its primary states no checksum the feed can verify (sha1, sha224, sha256, sha384 or sha512)")
		}
		if _, ok := yumRelPath(d.Href); !ok {
			return d, fmt.Errorf("its primary's location %q is not a path below the repository root", truncate(d.Href, 200))
		}
		return d, nil
	}
	return yumRepoData{}, errors.New("it lists no primary (<data type=\"primary\">)")
}

// yumRelPath checks a repodata location: a relative path without dot segments.
func yumRelPath(href string) (string, bool) {
	if href == "" || len(href) > 1024 || strings.HasPrefix(href, "/") || strings.ContainsAny(href, "?#\\%") || strings.Contains(href, "://") {
		return "", false
	}
	for _, seg := range strings.Split(href, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", false
		}
	}
	return href, cleanName(href)
}

// head names the repository's state: its revision (a Unix time for Fedora,
// "9.8" for Rocky Linux), and when its primary was made.
func (md yumRepomd) head(p yumRepoData) (string, time.Time) {
	head := md.Revision
	if !cleanName(head) || len(head) > 128 {
		head = ""
	}
	var t time.Time
	if p.Timestamp > 0 && p.Timestamp < yumMaxTime {
		t = unixTime(p.Timestamp)
	} else if n, err := strconv.ParseInt(md.Revision, 10, 64); err == nil && n > 946684800 && n < yumMaxTime {
		t = unixTime(n)
	}
	if head == "" && p.Checksum.Hex != "" {
		head = p.Checksum.key()
	}
	return head, t
}

// yumParseRepomd reads repomd.xml: its revision and its <data> entries. It
// walks the tokens with its own depth bound (encoding/xml's Unmarshal and
// Skip recurse once per level of nesting).
func yumParseRepomd(data []byte) (yumRepomd, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var md yumRepomd
	inRoot, done := false, false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if !done {
				return md, errors.New("it is not a repomd.xml (no <repomd> element)")
			}
			return md, nil
		}
		if err != nil {
			return md, fmt.Errorf("it is not XML: %v", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case done:
				return md, errors.New("an element follows the <repomd> element")
			case !inRoot:
				if t.Name.Local != "repomd" {
					return md, fmt.Errorf("it is not a repomd.xml (its root element is <%s>)", truncate(t.Name.Local, 40))
				}
				inRoot = true
			case t.Name.Local == "revision":
				if md.Revision, err = yumXMLText(dec); err != nil {
					return md, err
				}
			case t.Name.Local == "data":
				if len(md.Data) >= yumMaxData {
					return md, fmt.Errorf("it lists more than %d data entries", yumMaxData)
				}
				d, err := yumReadData(dec, t)
				if err != nil {
					return md, err
				}
				md.Data = append(md.Data, d)
			default:
				if err := yumXMLSkip(dec); err != nil {
					return md, err
				}
			}
		case xml.EndElement:
			inRoot, done = false, true
		}
	}
}

// yumReadData reads a <data> element whose start tag was just read.
func yumReadData(dec *xml.Decoder, start xml.StartElement) (yumRepoData, error) {
	d := yumRepoData{Type: yumAttr(start, "", "type")}
	for {
		tok, err := dec.Token()
		if err != nil {
			return d, fmt.Errorf("it is not XML: %v", err)
		}
		switch t := tok.(type) {
		case xml.EndElement:
			return d, nil
		case xml.StartElement:
			var text string
			switch t.Name.Local {
			case "location":
				d.Href, d.Base = yumAttr(t, "", "href"), yumAttr(t, "xml", "base")
				err = yumXMLSkip(dec)
			case "checksum", "open-checksum", "size", "open-size", "timestamp":
				text, err = yumXMLText(dec)
			default:
				err = yumXMLSkip(dec)
			}
			if err != nil {
				return d, err
			}
			switch t.Name.Local {
			case "checksum":
				d.Checksum = yumParseSum(yumAttr(t, "", "type"), text)
			case "open-checksum":
				d.OpenChecksum = yumParseSum(yumAttr(t, "", "type"), text)
			case "size":
				d.Size = yumNumber(text)
			case "open-size":
				d.OpenSize = yumNumber(text)
			case "timestamp":
				d.Timestamp = yumNumber(text)
			}
		}
	}
}

// yumParseSum reads a declared checksum; one of a type the feed does not
// verify, or not of the type's length, is none.
func yumParseSum(typ, value string) yumSum {
	_, alg, n, ok := yumNewHash(typ)
	value = strings.ToLower(strings.TrimSpace(value))
	if !ok || len(value) != n || !yumIsHex(value) {
		return yumSum{}
	}
	return yumSum{Alg: alg, Hex: value}
}

// yumNumber reads a non-negative decimal; anything else is zero.
func yumNumber(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// yumAttr returns an attribute's value, trimmed (space "xml" for xml:base).
func yumAttr(t xml.StartElement, space, local string) string {
	for _, a := range t.Attr {
		if a.Name.Local != local {
			continue
		}
		switch {
		case space == "" && a.Name.Space != "":
			continue
		case space == "xml" && a.Name.Space != "xml" && a.Name.Space != "http://www.w3.org/XML/1998/namespace":
			continue
		}
		if len(a.Value) > yumMaxField {
			return ""
		}
		return strings.TrimSpace(a.Value)
	}
	return ""
}

// yumXMLText reads an element's text up to its end tag, bounded.
func yumXMLText(dec *xml.Decoder) (string, error) {
	var b strings.Builder
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", fmt.Errorf("it is not XML: %v", err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			if depth == 0 && b.Len()+len(t) <= yumMaxField {
				b.Write(t)
			}
		case xml.StartElement:
			if depth++; depth > yumMaxDepth {
				return "", fmt.Errorf("its elements nest more than %d levels deep", yumMaxDepth)
			}
		case xml.EndElement:
			if depth == 0 {
				return strings.TrimSpace(b.String()), nil
			}
			depth--
		}
	}
}

// yumXMLSkip reads past the end of the element whose start tag was just read.
func yumXMLSkip(dec *xml.Decoder) error {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("it is not XML: %v", err)
		}
		switch tok.(type) {
		case xml.StartElement:
			if depth++; depth > yumMaxDepth {
				return fmt.Errorf("its elements nest more than %d levels deep", yumMaxDepth)
			}
		case xml.EndElement:
			if depth == 0 {
				return nil
			}
			depth--
		}
	}
}

// --- verifying what was read ---------------------------------------------------

// yumDigest hashes and counts what is read through it, fails a read past the
// size repomd.xml states (size 0: none stated), and keeps the first error its
// reader returned.
type yumDigest struct {
	r    io.Reader
	sum  yumSum
	size int64
	h    hash.Hash
	n    int64
	err  error
}

func newYumDigest(r io.Reader, sum yumSum, size int64) *yumDigest {
	d := &yumDigest{r: r, sum: sum, size: size}
	if newHash, _, _, ok := yumNewHash(sum.Alg); ok && sum.Hex != "" {
		d.h = newHash()
	}
	return d
}

func (d *yumDigest) Read(p []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	n, err := d.r.Read(p)
	d.n += int64(n)
	if d.h != nil {
		d.h.Write(p[:n])
	}
	if d.size > 0 && d.n > d.size {
		// More than repomd.xml says: not the file it declared. Worth
		// retrying, not a verdict.
		err = fmt.Errorf("more than the %d bytes repomd.xml states (the repository changed while it was read?)", d.size)
	}
	if err != nil && err != io.EOF {
		d.err = err
	}
	return n, err
}

// verify checks the size (when stated) and the checksum (when declared) of
// what was read. A mismatch is worth retrying: the repository was rewritten
// while it was read, or a cache served a damaged copy.
func (d *yumDigest) verify(what string, size int64) error {
	if size > 0 && d.n != size {
		return fmt.Errorf("%s: read %d bytes, repomd.xml states %d (the repository changed while it was read?)", what, d.n, size)
	}
	if d.h != nil {
		if got := hex.EncodeToString(d.h.Sum(nil)); got != d.sum.Hex {
			return fmt.Errorf("%s: %s %s, repomd.xml states %s (the repository changed while it was read?)", what, d.sum.Alg, got, d.sum.Hex)
		}
	}
	return nil
}

// --- version order -------------------------------------------------------------

// yumSortReleases orders releases oldest first by RPM's version comparison.
func yumSortReleases(rels []Release) {
	sort.SliceStable(rels, func(i, j int) bool { return yumCompareEVR(rels[i].Version, rels[j].Version) < 0 })
}

// yumCompareEVR compares two versions spelt "[epoch:]version-release" as rpm
// does: the epochs as numbers, then the versions, then the releases, each by
// rpmvercmp.
func yumCompareEVR(a, b string) int {
	ea, va, ra := yumSplitEVR(a)
	eb, vb, rb := yumSplitEVR(b)
	if c := yumCompareDigits(ea, eb); c != 0 {
		return c
	}
	if c := yumVercmp(va, vb); c != 0 {
		return c
	}
	return yumVercmp(ra, rb)
}

// yumSplitEVR splits "[epoch:]version-release"; the epoch is "0" when absent.
func yumSplitEVR(s string) (epoch, ver, rel string) {
	epoch = "0"
	if i := strings.IndexByte(s, ':'); i > 0 && yumAllDigits(s[:i]) {
		epoch, s = s[:i], s[i+1:]
	}
	ver = s
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		ver, rel = s[:i], s[i+1:]
	}
	return epoch, ver, rel
}

func yumAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// yumCompareDigits compares two strings of digits as numbers.
func yumCompareDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// yumVercmp is rpm's rpmvercmp: the strings are split into runs of digits and
// of letters (ASCII), everything else separating them; "~" sorts before
// anything, even the end of the string, and "^" after the end but before
// anything else; runs compare numerically or lexically, and a numeric run is
// newer than a letter run.
func yumVercmp(a, b string) int {
	if a == b {
		return 0
	}
	isAlpha := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	isAlnum := func(c byte) bool { return isAlpha(c) || isDigit(c) }
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		// The tilde sorts before everything else.
		if i < len(a) && a[i] == '~' || j < len(b) && b[j] == '~' {
			if i >= len(a) || a[i] != '~' {
				return 1
			}
			if j >= len(b) || b[j] != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		// The caret sorts after the end of a string, before anything else.
		if i < len(a) && a[i] == '^' || j < len(b) && b[j] == '^' {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if a[i] != '^' {
				return 1
			}
			if b[j] != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		num := isDigit(a[i])
		if num {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		x, y := a[si:i], b[sj:j]
		if y == "" {
			// Runs of different kinds: the numeric one is newer.
			if num {
				return 1
			}
			return -1
		}
		if num {
			if c := yumCompareDigits(x, y); c != 0 {
				return c
			}
			continue
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	}
	return 1
}
