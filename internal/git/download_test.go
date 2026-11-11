package git

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Request bodies as the git client sends them.
const (
	// Protocol v0/v1: the negotiation opens with a want line.
	fetchV0 = "0098want 95dcfa3633004da0049d3d0fa03f80589cbcaf31 multi_ack_detailed no-done side-band-64k thin-pack ofs-delta deepen-since deepen-not agent=git/2.43.0\n00000009done\n"
	// Protocol v2: a ref listing and a fetch are both a POST to git-upload-pack;
	// only the command tells them apart.
	lsRefsV2 = "0014command=ls-refs\n0015agent=git/2.43.0\n00010009peel\n000csymrefs\n0000"
	fetchV2  = "0012command=fetch\n0015agent=git/2.43.0\n0001000ethin-pack\n0032want 95dcfa3633004da0049d3d0fa03f80589cbcaf31\n0009done\n0000"
)

func gzipped(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func uploadPackRequest(body []byte, gz bool) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/o/r.git/git-upload-pack", bytes.NewReader(body))
	r.Header.Set("Content-Type", ctUploadPackRequest)
	if gz {
		r.Header.Set("Content-Encoding", "gzip")
	}
	return r
}

func TestDescribeDownloadTellsFetchFromRefListing(t *testing.T) {
	b := newPassthroughBackend(t, "https://git.example.invalid", upstream.Credentials{}, nil, 0)

	// A large request, as a fetch with many haves is: the command is still the
	// first thing in it, well within what is examined.
	bigFetch := fetchV2 + strings.Repeat("0032have 95dcfa3633004da0049d3d0fa03f80589cbcaf31\n", 400)

	tests := []struct {
		name string
		body []byte
		gzip bool
		want bool
	}{
		{"v0 fetch", []byte(fetchV0), false, true},
		{"v2 fetch", []byte(fetchV2), false, true},
		{"v2 ref listing", []byte(lsRefsV2), false, false},
		{"v0 fetch, gzip", gzipped(t, fetchV0), true, true},
		{"v2 fetch, gzip", gzipped(t, fetchV2), true, true},
		{"v2 ref listing, gzip", gzipped(t, lsRefsV2), true, false},
		{"large v2 fetch", []byte(bigFetch), false, true},
		{"large v2 fetch, gzip", gzipped(t, bigFetch), true, true},
		{"empty body", nil, false, false},
		{"flush only", []byte("0000"), false, false},
		{"another v2 command that hands out no objects", []byte("0018command=object-info\n0000"), false, false},
		// What cannot be read is not given the benefit of the doubt: it is
		// recorded, and the entry shows what the server made of it.
		{"not a pkt-line", []byte("GET / HTTP/1.1\r\n\r\n"), false, true},
		{"gzip declared, plain body", []byte(fetchV2), true, true},
		{"gzip declared, plain ref listing", []byte(lsRefsV2), true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := uploadPackRequest(tc.body, tc.gzip)
			d, ok := b.DescribeDownload(r, "/o/r.git/git-upload-pack")
			if ok != tc.want {
				t.Fatalf("DescribeDownload ok = %v, want %v", ok, tc.want)
			}
			if ok && d != (backends.Download{Name: "o/r.git"}) {
				t.Fatalf("download = %+v, want the repository o/r.git", d)
			}
			// Whatever was examined, the handler must still see the whole body.
			got, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.body) {
				t.Fatalf("the request body was altered: %d bytes left of %d", len(got), len(tc.body))
			}
		})
	}
}

func TestDescribeDownloadIgnoresProtocolChatter(t *testing.T) {
	b := newPassthroughBackend(t, "https://git.example.invalid", upstream.Credentials{}, nil, 0)
	tests := []struct {
		method, path string
		body         string
	}{
		{http.MethodGet, "/o/r.git/info/refs", ""},
		{http.MethodGet, "/o/r.git/git-upload-pack", ""},        // wrong method
		{http.MethodPost, "/o/r.git/git-receive-pack", fetchV0}, // a push, refused elsewhere
		{http.MethodPost, "/o/r.git/unknown", fetchV0},
		{http.MethodPost, "/../etc/git-upload-pack", fetchV0}, // traversal: no repository
		{http.MethodPost, "/git-upload-pack", fetchV0},        // no repository at all
		// LFS endpoints on a backend without LFS are not LFS endpoints.
		{http.MethodGet, "/o/r.git/info/lfs/objects/" + strings.Repeat("a", 64), ""},
	}
	for _, tc := range tests {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		if d, ok := b.DescribeDownload(r, tc.path); ok {
			t.Errorf("%s %s was described as a download: %+v", tc.method, tc.path, d)
		}
	}
}

func TestDescribeDownloadLFSObjects(t *testing.T) {
	b := newLFSBackend(t, "https://git.example.invalid", cache.NewMemoryCache(), LFSOptions{Enabled: true})
	oid := strings.Repeat("ab", 32)

	r := httptest.NewRequest(http.MethodGet, "/o/r.git/info/lfs/objects/"+oid, nil)
	d, ok := b.DescribeDownload(r, "/o/r.git/info/lfs/objects/"+oid)
	want := backends.Download{Name: "o/r.git", Artifact: oid, Digest: "sha256:" + oid}
	if !ok || d != want {
		t.Fatalf("LFS object = %+v, %v; want %+v", d, ok, want)
	}

	// An object ID that is not a SHA-256 is described without a digest.
	r = httptest.NewRequest(http.MethodGet, "/o/r.git/info/lfs/objects/not-a-digest", nil)
	d, ok = b.DescribeDownload(r, "/o/r.git/info/lfs/objects/not-a-digest")
	if !ok || d.Digest != "" || d.Artifact != "not-a-digest" {
		t.Fatalf("odd object ID = %+v, %v", d, ok)
	}

	// The batch negotiation transfers no object.
	r = httptest.NewRequest(http.MethodPost, "/o/r.git/info/lfs/objects/batch", strings.NewReader(`{"operation":"download"}`))
	if d, ok := b.DescribeDownload(r, "/o/r.git/info/lfs/objects/batch"); ok {
		t.Fatalf("the LFS batch API was described as a download: %+v", d)
	}
	// Nor does anything but a GET of an object …
	r = httptest.NewRequest(http.MethodPut, "/o/r.git/info/lfs/objects/"+oid, strings.NewReader("x"))
	if d, ok := b.DescribeDownload(r, "/o/r.git/info/lfs/objects/"+oid); ok {
		t.Fatalf("an LFS upload was described as a download: %+v", d)
	}
	// … and the HEAD for it. A HEAD that is answered transfers nothing and is
	// not logged, but the content gates answer a HEAD like the GET: a refused
	// one is an attempt on the object, and the log can only show it if the
	// request is known for what it is.
	r = httptest.NewRequest(http.MethodHead, "/o/r.git/info/lfs/objects/"+oid, nil)
	if d, ok := b.DescribeDownload(r, "/o/r.git/info/lfs/objects/"+oid); !ok || d != want {
		t.Fatalf("HEAD of an LFS object = %+v, %v; want %+v", d, ok, want)
	}
}

// A request is left out of the log only when its body shows it to transfer no
// objects. Everything here that is not such a body must answer false — "it may
// be a fetch" — including what a server would reject.
func TestAsksForNothingButRefs(t *testing.T) {
	const want = "want 95dcfa3633004da0049d3d0fa03f80589cbcaf31\n"
	tests := []struct {
		name  string
		body  string
		whole bool
		want  bool
	}{
		// Ref listings, as git sends them and as a server would accept them.
		{"v2 ref listing", lsRefsV2, true, true},
		{"v2 ref listing, only its start examined", lsRefsV2[:len(lsRefsV2)-8], false, true},
		{"v2 ref listing without arguments", pktLine("command=ls-refs\n") + "0000", true, true},
		{"v2 ref listing, capability before the command", pktLine("agent=git/2.43.0\n") + pktLine("command=ls-refs\n") + "0001" + pktLine("peel\n") + "0000", true, true},
		{"v2 ref listing, command without a line feed", pktLine("command=ls-refs") + "0001" + "0000", true, true},
		{"v2 object-info", pktLine("command=object-info\n") + "0001" + pktLine("size\n") + "0000", true, true},
		{"v2 bundle-uri", pktLine("command=bundle-uri\n") + "0000", true, true},
		// A request that asks for nothing.
		{"empty body", "", true, true},
		{"a lone flush", "0000", true, true},

		// Fetches.
		{"v0 fetch", fetchV0, true, false},
		{"v2 fetch", fetchV2, true, false},
		{"v2 fetch, capability before the command", pktLine("agent=git/2.43.0\n") + pktLine("command=fetch\n") + "0001" + pktLine(want) + "0000", true, false},
		{"v0 fetch, deepen before the first want", pktLine("deepen 1\n") + pktLine(want) + "0000" + pktLine("done\n"), true, false},
		{"v2 fetch, command far down the capability list", strings.Repeat(pktLine("agent=git/2.43.0\n"), 40) + pktLine("command=fetch\n") + "0001" + pktLine(want) + "0000", true, false},
		{"a want line in a ref listing's capability section", pktLine("command=ls-refs\n") + pktLine(want) + "0001" + "0000", true, false},

		// Nothing vouches for these: they are treated as fetches.
		{"two commands", pktLine("command=ls-refs\n") + pktLine("command=fetch\n") + "0001" + "0000", true, false},
		{"the same command twice", pktLine("command=ls-refs\n") + pktLine("command=ls-refs\n") + "0000", true, false},
		{"an unknown command", pktLine("command=upload-archive\n") + "0000", true, false},
		{"a command with a value", pktLine("command=ls-refs=x\n") + "0000", true, false},
		{"a command with trailing whitespace", pktLine("command=ls-refs \n") + "0000", true, false},
		{"a command with a carriage return", pktLine("command=ls-refs\r\n") + "0000", true, false},
		{"a command in another case", pktLine("COMMAND=ls-refs\n") + "0000", true, false},
		{"capabilities without a command", pktLine("agent=git/2.43.0\n") + "0000", true, false},
		{"a delimiter without a command", "0001" + pktLine(want) + "0000", true, false},
		{"lines but no flush", pktLine("command=ls-refs\n"), true, false},
		{"the command section runs past what was examined", pktLine("command=ls-refs\n") + pktLine("agent=git/2.43.0\n")[:9], false, false},
		{"empty, but not known to be all of it", "", false, false},
		{"a flush, with more after it", "0000" + pktLine(want), true, false},
		{"a flush, but not known to be all of it", "0000", false, false},
		{"not a pkt-line", "GET / HTTP/1.1\r\n\r\n", true, false},
		{"a length that is not hex", "zzzz" + lsRefsV2, true, false},
		{"a length no pkt-line has", "0003" + lsRefsV2, true, false},
		{"a response-end packet", "0002" + lsRefsV2, true, false},
		{"a length beyond the data", "ffff" + "command=ls-refs\n", true, false},
		{"fewer than four bytes", "00", true, false},
	}
	for _, tc := range tests {
		if got := asksForNothingButRefs([]byte(tc.body), tc.whole); got != tc.want {
			t.Errorf("%s: asksForNothingButRefs = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Ways to phrase a fetch that a Git server answers with a pack, and that a
// reading of only the first pkt-line (or only the first kilobyte) took for
// something else. Every one of them must be recorded. Whether the real git
// serves them is checked against the real git in the integration test
// (TestFetchesGitServesAreAllRecorded); this one needs no git.
func TestDescribeDownloadRecordsEveryPhrasingOfAFetch(t *testing.T) {
	b := newPassthroughBackend(t, "https://git.example.invalid", upstream.Credentials{}, nil, 0)
	const want = "want 95dcfa3633004da0049d3d0fa03f80589cbcaf31\n"
	fetch := pktLine("command=fetch\n") + pktLine("agent=git/2.43.0\n") + "0001" + pktLine(want) + pktLine("done\n") + "0000"

	tests := []struct {
		name     string
		body     []byte
		encoding string
	}{
		{"as git sends it", []byte(fetch), ""},
		{"a capability line before the command", []byte(pktLine("agent=git/2.43.0\n") + pktLine("command=fetch\n") + "0001" + pktLine(want) + pktLine("done\n") + "0000"), ""},
		{"v0, a deepen line before the first want", []byte(pktLine("deepen 1\n") + pktLine(want) + "0000" + pktLine("done\n")), ""},
		{"gzip", gzipped(t, fetch), "gzip"},
		{"x-gzip", gzipped(t, fetch), "x-gzip"},
		{"gzip in another case", gzipped(t, fetch), "GZip"},
		{"gzip with a header extra field longer than the first kilobyte", gzipWithExtra(t, fetch, 2000), "gzip"},
		{"gzip with a header extra field longer than what is examined", gzipWithExtra(t, fetch, 60000), "gzip"},
		{"gzip opening with empty stored blocks", gzipWithEmptyBlocks(t, fetch, 300), "gzip"},
		{"gzip opening with more empty stored blocks than are examined", gzipWithEmptyBlocks(t, fetch, 5000), "gzip"},
		{"an encoding the proxy does not read", []byte(fetch), "deflate"},
		{"two encodings", gzipped(t, fetch), "gzip, gzip"},
		{"identity", []byte(fetch), "identity"},
	}
	for _, tc := range tests {
		r := uploadPackRequest(tc.body, false)
		if tc.encoding != "" {
			r.Header.Set("Content-Encoding", tc.encoding)
		}
		if _, ok := b.DescribeDownload(r, "/o/r.git/git-upload-pack"); !ok {
			t.Errorf("%s: the fetch is not recorded", tc.name)
		}
		got, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(got, tc.body) {
			t.Errorf("%s: the request body was altered (%d bytes left of %d, %v)", tc.name, len(got), len(tc.body), err)
		}
	}

	// And a ref listing stays out of the log in every encoding the proxy reads.
	for _, tc := range []struct {
		name     string
		body     []byte
		encoding string
	}{
		{"plain", []byte(lsRefsV2), ""},
		{"gzip", gzipped(t, lsRefsV2), "gzip"},
		{"x-gzip", gzipped(t, lsRefsV2), "x-gzip"},
		{"identity", []byte(lsRefsV2), "identity"},
	} {
		r := uploadPackRequest(tc.body, false)
		if tc.encoding != "" {
			r.Header.Set("Content-Encoding", tc.encoding)
		}
		if d, ok := b.DescribeDownload(r, "/o/r.git/git-upload-pack"); ok {
			t.Errorf("a ref listing (%s) was recorded as a download: %+v", tc.name, d)
		}
	}
}

// gzipWithExtra compresses s with a header extra field of n bytes, which moves
// the compressed data n bytes into the stream.
func gzipWithExtra(t *testing.T, s string, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Header.Extra = bytes.Repeat([]byte{0}, n)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// gzipWithEmptyBlocks compresses s into a gzip stream whose deflate data opens
// with n empty stored blocks: valid input that decodes to nothing for 5n bytes.
func gzipWithEmptyBlocks(t *testing.T, s string, n int) []byte {
	t.Helper()
	var raw bytes.Buffer
	raw.Write([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff})
	for i := 0; i < n; i++ {
		raw.Write([]byte{0x00, 0x00, 0x00, 0xff, 0xff}) // a non-final stored block of length 0
	}
	fw, err := flate.NewWriter(&raw, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	var trailer [8]byte
	binary.LittleEndian.PutUint32(trailer[0:], crc32.ChecksumIEEE([]byte(s)))
	binary.LittleEndian.PutUint32(trailer[4:], uint32(len(s)))
	raw.Write(trailer[:])
	return raw.Bytes()
}

// The sniffer must reach the same verdict however the transport chops the
// stream up, and must never alter what passes through it.
func TestFetchSnifferSeesFetchAcrossAnyChunking(t *testing.T) {
	streams := []struct {
		name string
		data string
		want bool
	}{
		{"v0 clone", fetchV0, true},
		{"v0 ref listing only (flush)", "0000", false},
		{"v2 listing then fetch", lsRefsV2 + fetchV2, true},
		{"v2 listing only", lsRefsV2 + "0000", false},
		{"v2 two listings", lsRefsV2 + lsRefsV2, false},
		{"empty", "", false},
		{"garbage", "this is not a pkt-line stream at all", false},
		{"garbage then what looks like a fetch", "zzzz0012command=fetch\n", false},
		{"commands are case-sensitive and exact", "0012COMMAND=fetch\n0016command=fetch-not\n", false},
		{"the fetch command without a line feed", "0011command=fetch0000", true},
		{"hex length with letters", "000fwant abcde\n", true},
		{"upper-case hex length", "000Fwant abcde\n", true},
		{"a want hidden inside a payload is not a want line", "0023agent=git/2.43.0 want 95dcfa36\n0000", false},
		{"delimiter and response-end packets carry no payload", "000100020000" + fetchV2, true},
	}
	for _, tc := range streams {
		for chunk := 1; chunk <= len(tc.data)+1; chunk++ {
			s := &fetchSniffer{r: &chunkReader{data: []byte(tc.data), chunk: chunk}}
			got, err := io.ReadAll(s)
			if err != nil {
				t.Fatalf("%s (chunk %d): %v", tc.name, chunk, err)
			}
			if string(got) != tc.data {
				t.Fatalf("%s (chunk %d): the stream was altered", tc.name, chunk)
			}
			if s.fetch != tc.want {
				t.Fatalf("%s (chunk %d): fetch = %v, want %v", tc.name, chunk, s.fetch, tc.want)
			}
		}
	}
}

// chunkReader yields its data at most chunk bytes at a time.
type chunkReader struct {
	data  []byte
	chunk int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := min(c.chunk, len(c.data), len(p))
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func TestPktLength(t *testing.T) {
	for in, want := range map[string]int{"0000": 0, "0004": 4, "0012": 18, "ffff": 65535, "FFFF": 65535, "00aB": 171} {
		var h [4]byte
		copy(h[:], in)
		if got, ok := pktLength(h); !ok || got != want {
			t.Errorf("pktLength(%q) = %d, %v; want %d", in, got, ok, want)
		}
	}
	for _, bad := range []string{"00g0", "    ", "-001", "0x10"} {
		var h [4]byte
		copy(h[:], bad)
		if _, ok := pktLength(h); ok {
			t.Errorf("pktLength(%q) accepted", bad)
		}
	}
}

func TestCountingWriter(t *testing.T) {
	var buf bytes.Buffer
	cw := &countingWriter{w: &buf}
	for _, s := range []string{"PACK", "", "data"} {
		if _, err := cw.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if cw.n != 8 || buf.String() != "PACKdata" {
		t.Fatalf("counted %d bytes, wrote %q", cw.n, buf.String())
	}
}

// The content gate on LFS objects is the backend's own: when it refuses an
// object, the backend says so through the request context, so that the download
// log records "blocked by lfs-content" rather than a request that failed. An
// object the gate lets through reports nothing.
func TestLFSContentGateReportsItsRefusal(t *testing.T) {
	blob := []byte("secret: AKIA_EXAMPLE_KEY")
	oid := oidOf(blob)
	request := func(b *Backend, method string) (status int, refusals []string) {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest(method, "/v1/gh/o/r.git/info/lfs/objects/"+oid+"?size="+strconv.Itoa(len(blob)), nil)
		r = r.WithContext(backends.WithRefusalRecorder(r.Context(), func(gate string) { refusals = append(refusals, gate) }))
		b.ServeBackendHTTP(rr, r, "o/r.git/info/lfs/objects/"+oid)
		return rr.Code, refusals
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		up := newLFSUpstream(t, map[string][]byte{oid: blob})
		blocking := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{BlockOnFindings: true, Gate: &fakeGate{findings: 1}})
		status, refusals := request(blocking, method)
		if status != http.StatusForbidden {
			t.Fatalf("%s: status %d, want the gate's 403", method, status)
		}
		if len(refusals) != 1 || refusals[0] != "lfs-content" {
			t.Errorf("%s: the refusal was reported as %v, want [lfs-content]", method, refusals)
		}
	}

	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	passing := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{BlockOnFindings: true, Gate: &fakeGate{findings: 0}})
	if status, refusals := request(passing, http.MethodGet); status != http.StatusOK || len(refusals) != 0 {
		t.Errorf("an admitted object: status %d, refusals %v", status, refusals)
	}
	// Without a recorder in the context (a request that did not come through the
	// proxy core) reporting is a no-op, not a crash.
	if rr := doObject(passing, oid, int64(len(blob)), ""); rr.Code != http.StatusOK {
		t.Errorf("without a recorder: status %d", rr.Code)
	}
}
