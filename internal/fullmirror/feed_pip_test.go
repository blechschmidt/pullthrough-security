package fullmirror

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/pkgmgr"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The pip fixtures (testdata/feeds/pip) were recorded from pypi.org on
// 2026-11-16: XML-RPC answers (last.xml, last-43709032.xml, since-*.xml,
// fault-*.xml), the project list's head (simple-index.json: its complete
// entries in PyPI's order, plus requests and six with the serials their pages
// state; simple-index-later.json edits it as a later poll would find it), and
// the simple pages of six and requests, trimmed to a few versions, with their
// file URLs rewritten as pkgmgr.NewPyPI rewrites them for an upstream named
// pip-test behind http://proxy.example.

// pypiTestIndex stands in for a Warehouse index: XML-RPC calls to /pypi are
// answered by method (or by "method(args)"), every other request by the
// fixtureServer's routes.
type pypiTestIndex struct {
	t     *testing.T
	fs    *fixtureServer
	srv   *httptest.Server
	mu    sync.Mutex
	rpc   map[string]pypiTestReply
	calls []string
}

type pypiTestReply struct {
	status int
	body   []byte
	header map[string]string
}

var (
	pypiTestCall = regexp.MustCompile(`(?s)^<\?xml version='1.0'\?>\n<methodCall>\n<methodName>([a-z_]+)</methodName>\n<params>\n(.*)</params>\n</methodCall>\n$`)
	pypiTestArg  = regexp.MustCompile(`<param>\n<value><int>(-?\d+)</int></value>\n</param>\n`)
)

func newPypiTestIndex(t *testing.T) *pypiTestIndex {
	t.Helper()
	ix := &pypiTestIndex{t: t, fs: newFixtureServer(t), rpc: map[string]pypiTestReply{}}
	ix.srv = httptest.NewServer(http.HandlerFunc(ix.serve))
	t.Cleanup(ix.srv.Close)
	return ix
}

func (ix *pypiTestIndex) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/pypi" {
		ix.fs.serve(w, r)
		return
	}
	body, _ := io.ReadAll(r.Body)
	m := pypiTestCall.FindSubmatch(body)
	if r.Method != http.MethodPost || m == nil || r.Header.Get("Content-Type") != "text/xml" {
		ix.t.Errorf("not an XML-RPC call: %s %s %q", r.Method, r.URL, body)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var args []string
	for _, a := range pypiTestArg.FindAllSubmatch(m[2], -1) {
		args = append(args, string(a[1]))
	}
	call := string(m[1]) + "(" + strings.Join(args, ",") + ")"
	ix.mu.Lock()
	ix.calls = append(ix.calls, call)
	rep, ok := ix.rpc[call]
	if !ok {
		rep, ok = ix.rpc[string(m[1])]
	}
	ix.mu.Unlock()
	if !ok {
		ix.t.Errorf("unexpected XML-RPC call %s", call)
		http.Error(w, "no fixture", 599)
		return
	}
	w.Header().Set("Content-Type", "text/xml; charset=UTF-8")
	for k, v := range rep.header {
		w.Header().Set(k, v)
	}
	if rep.status == 0 {
		rep.status = http.StatusOK
	}
	w.WriteHeader(rep.status)
	_, _ = w.Write(rep.body)
}

// answer sets the reply to a method (or to one "method(args)" call).
func (ix *pypiTestIndex) answer(call string, rep pypiTestReply) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.rpc[call] = rep
}

// takeCalls returns the XML-RPC calls made since the last take.
func (ix *pypiTestIndex) takeCalls() []string {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	out := ix.calls
	ix.calls = nil
	return out
}

// list serves a project list at /simple/.
func (ix *pypiTestIndex) list(body []byte, etag, serial string) *route {
	r := ix.fs.on("GET", "/simple/").reply(http.StatusOK, body).requireHeader("Accept", pypiIndexAccept).
		withHeader("Content-Type", "application/vnd.pypi.simple.v1+json")
	if etag != "" {
		r.withHeader("ETag", etag)
	}
	if serial != "" {
		r.withHeader("X-PyPI-Last-Serial", serial)
	}
	return r
}

func pypiTestFeed(t *testing.T, opts map[string]string) (*pypiFeed, *pypiTestIndex, *fakeReads) {
	t.Helper()
	ix := newPypiTestIndex(t)
	reads := newFakeReads()
	f := mustFeed(t, testEnv(t, "pip", ix.srv.URL, reads, opts)).(*pypiFeed)
	return f, ix, reads
}

func pypiTestXML(t *testing.T, name string) pypiTestReply {
	return pypiTestReply{body: fixture(t, "pip", name)}
}

// pypiStores lists the stored project lists.
func pypiStores(t *testing.T, f *pypiFeed) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(f.files.dir, pypiStorePrefix+"*"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range m {
		m[i] = filepath.Base(m[i])
	}
	return m
}

func TestPipFeedLocation(t *testing.T) {
	for _, tc := range []struct {
		url           string
		opts          map[string]string
		xmlrpc, index string
		mode          string
	}{
		{"https://pypi.org", nil, "https://pypi.org/pypi", "https://pypi.org/simple/", "auto"},
		{"https://pypi.python.org/", nil, "https://pypi.org/pypi", "https://pypi.org/simple/", "auto"},
		{"https://test.pypi.org", map[string]string{"mode": "XMLRPC"}, "https://test.pypi.org/pypi", "https://test.pypi.org/simple/", "xmlrpc"},
		{"https://warehouse.internal.example/root/", nil, "https://warehouse.internal.example/root/pypi", "https://warehouse.internal.example/root/simple/", "auto"},
		{"https://devpi.internal.example/root/pypi", map[string]string{"url": "https://pypi.org/", "mode": "simple"}, "https://pypi.org/pypi", "https://pypi.org/simple/", "simple"},
		{"https://nexus.internal.example/repository/pypi", map[string]string{"url": "https://warehouse.internal.example/simple/"}, "https://warehouse.internal.example/pypi", "https://warehouse.internal.example/simple/", "auto"},
	} {
		f, err := newPypiFeed(Env{Upstream: "p", Type: "pip", URL: tc.url, Options: tc.opts})
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		pf := f.(*pypiFeed)
		if pf.xmlrpc != tc.xmlrpc || pf.index != tc.index || pf.mode != tc.mode {
			t.Errorf("%s: XML-RPC %s, index %s, mode %s; want %s, %s, %s", tc.url, pf.xmlrpc, pf.index, pf.mode, tc.xmlrpc, tc.index, tc.mode)
		}
	}
	if err := Check(Env{Upstream: "p", Type: "pip", URL: "https://pypi.org", Options: map[string]string{"mode": "auto"}}); err != nil {
		t.Errorf("Check: %v", err)
	}
	for _, opts := range []map[string]string{{"since": "1"}, {"mode": "rss"}, {"url": "ftp://pypi.org"}, {"url": "https://u:p@pypi.org"}, {"url": "https://pypi.org/?x=1"}} {
		if err := Check(Env{Upstream: "p", Type: "pip", URL: "https://pypi.org", Options: opts}); err == nil {
			t.Errorf("Check accepted options %v", opts)
		}
	}
	// An adapter built to validate the configuration does no I/O.
	f, _ := newPypiFeed(Env{Upstream: "p", Type: "pip", URL: "https://pypi.org"})
	if _, err := f.Bootstrap(context.Background(), ""); !errors.Is(err, errValidationOnly) {
		t.Errorf("a validation-only adapter: %v", err)
	}
}

func TestPipBootstrapListsTheIndexThenFollowsTheChangelog(t *testing.T) {
	f, ix, _ := pypiTestFeed(t, nil)
	f.page = 5
	ix.answer("changelog_last_serial", pypiTestXML(t, "last.xml"))
	ix.list(fixture(t, "pip", "simple-index.json"), `"/hgTTY6Wei0hV20hspcwZw"`, "43707253").once()
	ctx := context.Background()

	var pages []Batch
	b, err := f.Bootstrap(ctx, "")
	for err == nil {
		pages = append(pages, b)
		if !b.More {
			break
		}
		b, err = f.Bootstrap(ctx, b.Next)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 3 {
		t.Fatalf("%d pages, want 3 (13 projects, 5 a page)", len(pages))
	}
	for i, p := range pages {
		checkGolden(t, "pip", "bootstrap-page-"+string(rune('1'+i)), viewBatch(t, p))
	}
	// The head is read once, to choose the changelog; the list once; the
	// later pages come from the stored copy.
	if calls := ix.takeCalls(); len(calls) != 1 || calls[0] != "changelog_last_serial()" {
		t.Errorf("calls %v", calls)
	}
	// The changelog continues from the list's own serial (older than the
	// head read before it).
	last := pages[len(pages)-1]
	c, err := f.decode(last.Next)
	if err != nil || c.Mode != pypiModeXMLRPC || c.Serial != 43707253 || c.Listing || c.Store != "" {
		t.Errorf("final cursor %+v (%v)", c, err)
	}
	if got := pypiStores(t, f); len(got) != 1 {
		t.Errorf("stored lists %v, want the one listed", got)
	}
	// Changes refuses a listing cursor; Bootstrap the follow cursor.
	_, err = f.Changes(ctx, pages[0].Next)
	mustErr(t, err, false, true, "continues a listing")
	_, err = f.Bootstrap(ctx, last.Next)
	mustErr(t, err, false, true, "does not continue a listing")
	// Following the changelog needs no copy of the list.
	ix.answer("changelog_since_serial", pypiTestXML(t, "since-owners.xml"))
	if _, err := f.Changes(ctx, last.Next); err != nil {
		t.Fatal(err)
	}
	// (The newest copy is kept: a replica that lost its lease mid-poll may
	// still be listing from it.)
	got := pypiStores(t, f)
	if len(got) > 1 {
		t.Errorf("stored lists %v after the changelog took over", got)
	}
	// The listing is resumed from the stored copy — and refused once it is
	// gone.
	for _, p := range got {
		os.Remove(filepath.Join(f.files.dir, p))
	}
	_, err = f.Bootstrap(ctx, pages[1].Next)
	mustErr(t, err, false, true, "is missing")
}

func TestPipChangesFollowTheChangelog(t *testing.T) {
	f, ix, _ := pypiTestFeed(t, nil)
	ix.answer("changelog_since_serial(43708647)", pypiTestXML(t, "since-43708647.xml"))
	b, err := f.Changes(context.Background(), encodeCursor(&pypiCursor{Format: f.format(), Mode: pypiModeXMLRPC, Serial: 43708647}))
	if err != nil {
		t.Fatal(err)
	}
	// Each version once, removals as such; "create" and "add Owner" name
	// nothing to fetch.
	checkGolden(t, "pip", "changes", viewBatch(t, b))
	// A call with fewer rows than the cap is the head: no second call.
	if calls := ix.takeCalls(); len(calls) != 1 {
		t.Errorf("calls %v", calls)
	}

	// Ownership changes (version nil) are left out; a release's files are one
	// change.
	ix.answer("changelog_since_serial(43707959)", pypiTestXML(t, "since-owners.xml"))
	b, err = f.Changes(context.Background(), encodeCursor(&pypiCursor{Format: f.format(), Mode: pypiModeXMLRPC, Serial: 43707959}))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names(b.Items), " "); got != "unstuck@0.2.3" || b.More {
		t.Errorf("items %s more=%v", got, b.More)
	}
}

func TestPipFullChangelogCallAsksForMore(t *testing.T) {
	f, ix, _ := pypiTestFeed(t, nil)
	f.cap = 18 // the fixture's rows
	ix.answer("changelog_since_serial", pypiTestXML(t, "since-43708647.xml"))
	ix.answer("changelog_last_serial", pypiTestXML(t, "last-43709032.xml"))
	b, err := f.Changes(context.Background(), encodeCursor(&pypiCursor{Format: f.format(), Mode: pypiModeXMLRPC, Serial: 43708647}))
	if err != nil {
		t.Fatal(err)
	}
	if !b.More || b.Head != "43709032" || !b.LagKnown || b.Lag != 43709032-43708665 || !b.HeadTime.IsZero() || b.CursorTime.Unix() != 1794797040 {
		t.Errorf("batch head %s lag %d/%v more %v times %v %v", b.Head, b.Lag, b.LagKnown, b.More, b.HeadTime, b.CursorTime)
	}
	if calls := ix.takeCalls(); strings.Join(calls, " ") != "changelog_since_serial(43708647) changelog_last_serial()" {
		t.Errorf("calls %v", calls)
	}
}

func TestPipSerialBeyondTheHeadInvalidatesTheCursor(t *testing.T) {
	f, ix, _ := pypiTestFeed(t, nil)
	ix.answer("changelog_since_serial", pypiTestXML(t, "since-empty.xml"))
	ix.answer("changelog_last_serial", pypiTestXML(t, "last.xml"))
	_, err := f.Changes(context.Background(), encodeCursor(&pypiCursor{Format: f.format(), Mode: pypiModeXMLRPC, Serial: 43800000}))
	mustErr(t, err, false, true, "journal was reset")

	// At the head, an empty answer is no change.
	b, err := f.Changes(context.Background(), encodeCursor(&pypiCursor{Format: f.format(), Mode: pypiModeXMLRPC, Serial: 43707967}))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Items) != 0 || b.More || b.Head != "43707967" || !b.LagKnown || b.Lag != 0 {
		t.Errorf("batch %+v", b)
	}
}

func TestPipFaultsAndRateLimits(t *testing.T) {
	ctx := context.Background()
	f, ix, _ := pypiTestFeed(t, map[string]string{"mode": "xmlrpc"})
	cur := encodeCursor(&pypiCursor{Format: f.format(), Mode: pypiModeXMLRPC, Serial: 1})

	// A client error is permanent.
	ix.answer("changelog_since_serial", pypiTestXML(t, "fault-params.xml"))
	_, err := f.Changes(ctx, cur)
	mustErr(t, err, true, false, "-32602")

	// A missing method: in xmlrpc mode a permanent error, in auto mode the
	// cursor is given up so that the index is enumerated (in simple mode).
	ix.answer("changelog_since_serial", pypiTestXML(t, "fault-method.xml"))
	_, err = f.Changes(ctx, cur)
	mustErr(t, err, true, false, "requested method not found")
	if !errors.Is(err, pypiErrNoXMLRPC) {
		t.Errorf("not reported as a missing changelog: %v", err)
	}
	// An auto follower switches only once the endpoint stays missing: one
	// 404 from a proxy in front of the index is retried.
	auto, aix, _ := pypiTestFeed(t, nil)
	aix.answer("changelog_since_serial", pypiTestXML(t, "fault-method.xml"))
	_, err = auto.Changes(ctx, cur)
	mustErr(t, err, false, false, "1 of 3")
	aix.answer("changelog_since_serial", pypiTestReply{status: http.StatusNotFound, body: []byte("Not Found")})
	_, err = auto.Changes(ctx, cur)
	mustErr(t, err, false, false, "2 of 3")
	_, err = auto.Changes(ctx, cur)
	mustErr(t, err, false, true, "no longer serves the XML-RPC changelog")
	// A poll that reaches the changelog again starts the count over.
	aix.answer("changelog_since_serial", pypiTestXML(t, "fault-method.xml"))
	_, err = auto.Changes(ctx, cur)
	mustErr(t, err, false, false, "1 of 3")

	// Warehouse's rate-limit fault (its message format; not recorded, PyPI
	// was not to be made to refuse) asks for the wait it states.
	ix.answer("changelog_since_serial", pypiTestReply{body: []byte(pypiTestFault(-32500,
		"HTTPTooManyRequests: The action could not be performed because there were too many requests by the client. Limit may reset in 23 seconds."))})
	_, err = f.Changes(ctx, cur)
	if d, ok := RetryAfterOf(err); !ok || d != 23*time.Second || IsPermanent(err) {
		t.Errorf("a rate-limit fault: %v (%v)", err, d)
	}
	// Another server fault backs off.
	ix.answer("changelog_since_serial", pypiTestReply{body: []byte(pypiTestFault(-32603, "server error; internal error"))})
	_, err = f.Changes(ctx, cur)
	if d, ok := RetryAfterOf(err); !ok || d != pypiFaultWait || IsPermanent(err) {
		t.Errorf("a server fault: %v (%v)", err, d)
	}
	// A 429 asks for its Retry-After; a 502 is retried.
	ix.answer("changelog_since_serial", pypiTestReply{status: http.StatusTooManyRequests, header: map[string]string{"Retry-After": "30"}})
	_, err = f.Changes(ctx, cur)
	if d, ok := RetryAfterOf(err); !ok || d != 30*time.Second {
		t.Errorf("a 429: %v (%v)", err, d)
	}
	ix.answer("changelog_since_serial", pypiTestReply{status: http.StatusBadGateway})
	_, err = f.Changes(ctx, cur)
	mustErr(t, err, false, false, "502")
	// Something that is not an XML-RPC response, or not a changelog.
	for body, want := range map[string]string{
		"<html><body>Service</body></html>": "not an XML-RPC response",
		`<?xml version="1.0"?><!DOCTYPE methodResponse [<!ENTITY a "b">]><methodResponse><params/></methodResponse>`:                                                           "directive",
		"<?xml version='1.0'?>\n<methodResponse><params><param><value><int>5</int></value></param></params></methodResponse>":                                                  "not a list of changes",
		"<?xml version='1.0'?>\n<methodResponse><params><param><value><array><data><value><string>x</string></value></data></array></value></param></params></methodResponse>": "none of its 1 rows",
	} {
		ix.answer("changelog_since_serial", pypiTestReply{body: []byte(body)})
		_, err = f.Changes(ctx, cur)
		mustErr(t, err, true, false, want)
	}
	// Rows that all lie at or before the serial asked after: an index that
	// ignores it would be read alike at every poll.
	ix.answer("changelog_since_serial", pypiTestXML(t, "since-owners.xml"))
	_, err = f.Changes(ctx, encodeCursor(&pypiCursor{Format: f.format(), Mode: pypiModeXMLRPC, Serial: 43707967}))
	mustErr(t, err, true, false, "none after that serial")
}

// pypiTestFault renders a fault as warehouse does.
func pypiTestFault(code int, msg string) string {
	return "<?xml version='1.0'?>\n<methodResponse>\n<fault>\n<value><struct>\n<member>\n<name>faultCode</name>\n<value><int>" +
		strconv.Itoa(code) + "</int></value>\n</member>\n<member>\n<name>faultString</name>\n<value><string>" +
		msg + "</string></value>\n</member>\n</struct></value>\n</fault>\n</methodResponse>\n"
}

func TestPipAutoModeFollowsTheProjectListWithoutXMLRPC(t *testing.T) {
	f, ix, _ := pypiTestFeed(t, nil)
	ctx := context.Background()
	ix.answer("changelog_last_serial", pypiTestReply{status: http.StatusNotFound, body: []byte("Not Found")})
	ix.list(fixture(t, "pip", "simple-index.json"), `"/hgTTY6Wei0hV20hspcwZw"`, "43707253")
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if b.More || len(b.Items) != 13 {
		t.Fatalf("bootstrap: %d items, more %v", len(b.Items), b.More)
	}
	start, err := f.decode(b.Next)
	if err != nil || start.Mode != pypiModeSimple || start.Serial != 43707253 || start.Store == "" || start.ETag != `"/hgTTY6Wei0hV20hspcwZw"` {
		t.Fatalf("follow cursor %+v (%v)", start, err)
	}

	// The next poll is conditional; the list changed: a project vanished,
	// one moved, one is new.
	ix.list(fixture(t, "pip", "simple-index-later.json"), `"later"`, "43707967").requireHeader("If-None-Match", `"/hgTTY6Wei0hV20hspcwZw"`)
	c, err := f.Changes(ctx, b.Next)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "pip", "changes-simple", viewBatch(t, c))

	// The engine may ask again from the stored cursor after a restart.
	again, err := f.Changes(ctx, b.Next)
	if err != nil || strings.Join(names(again.Items), " ") != strings.Join(names(c.Items), " ") || again.Next != c.Next {
		t.Errorf("asked again: %v %v", names(again.Items), err)
	}

	// Not modified: nothing to report, the cursor stays.
	ix.fs.on("GET", "/simple/").reply(http.StatusNotModified, nil).requireHeader("If-None-Match", `"later"`)
	d, err := f.Changes(ctx, c.Next)
	if err != nil || len(d.Items) != 0 || d.Next != c.Next {
		t.Errorf("not modified: %+v %v", d, err)
	}
	// Once the newer cursor was used, at most the newest older copy is kept
	// besides it (for a replica that lost its lease mid-poll).
	if got := pypiStores(t, f); len(got) > 2 {
		t.Errorf("stored lists %v", got)
	}
	// An older list than the one kept (a CDN node behind): nothing yet.
	ix.list(fixture(t, "pip", "simple-index.json"), `"older"`, "43707253").requireHeader("If-None-Match", `"later"`)
	d, err = f.Changes(ctx, c.Next)
	if err != nil || len(d.Items) != 0 || d.Next != c.Next {
		t.Errorf("an older copy: %+v %v", d, err)
	}
	// Only the list was polled: the XML-RPC endpoint was asked once.
	if calls := ix.takeCalls(); len(calls) != 1 {
		t.Errorf("calls %v", calls)
	}
}

func TestPipSimpleModeDiffSpansBatches(t *testing.T) {
	f, ix, _ := pypiTestFeed(t, map[string]string{"mode": "simple"})
	ctx := context.Background()
	ix.list(fixture(t, "pip", "simple-index.json"), `"a"`, "")
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if calls := ix.takeCalls(); len(calls) != 0 {
		t.Errorf("simple mode called XML-RPC: %v", calls)
	}
	f.page = 2
	ix.list(fixture(t, "pip", "simple-index-later.json"), `"b"`, "")
	first, err := f.Changes(ctx, b.Next)
	if err != nil {
		t.Fatal(err)
	}
	if !first.More || len(first.Items) != 2 {
		t.Fatalf("first page %+v", first)
	}
	second, err := f.Changes(ctx, first.Next)
	if err != nil {
		t.Fatal(err)
	}
	if second.More || len(second.Items) != 1 {
		t.Fatalf("second page %+v", second)
	}
	got := strings.Join(append(names(first.Items), names(second.Items)...), " ")
	if got != "0101 requests unstuck" || !first.Items[0].Deleted {
		t.Errorf("difference %s (%+v)", got, first.Items)
	}
	fc, _ := f.decode(first.Next)
	sc, _ := f.decode(second.Next)
	if fc.To == "" || sc.To != "" || sc.Store != fc.To || sc.Serial != 43707967 || sc.ETag != `"b"` {
		t.Errorf("cursors %+v then %+v", fc, sc)
	}
	// A stored copy that does not match its cursor is not trusted.
	p := filepath.Join(f.files.dir, pypiStoreName(fc.To))
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(data[:len(data)-8:len(data)-8], 0, 0, 0, 0, 0, 0, 0, 0), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = f.Changes(ctx, first.Next)
	mustErr(t, err, false, true, "does not read")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	_, err = f.Changes(ctx, first.Next)
	mustErr(t, err, false, true, "is missing")
	// A follow cursor of the changelog cannot be followed in simple mode.
	_, err = f.Changes(ctx, encodeCursor(&pypiCursor{Format: f.format(), Mode: pypiModeXMLRPC, Serial: 5}))
	mustErr(t, err, false, true, "mode is simple")
}

func TestPipStoredListIsCheckedAgainstItsDigest(t *testing.T) {
	f, _, _ := pypiTestFeed(t, nil)
	idx := &pypiIndex{projects: []pypiProject{{"a", 1}, {"b", 2}}, serial: 7, serials: true}
	digest, err := f.saveStore(idx)
	if err != nil {
		t.Fatal(err)
	}
	// A copy whose content was replaced under its name (same length).
	other := &pypiIndex{projects: []pypiProject{{"a", 1}, {"c", 2}}, serial: 7, serials: true}
	d2, err := f.saveStore(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(f.files.dir, pypiStoreName(d2)), filepath.Join(f.files.dir, pypiStoreName(digest))); err != nil {
		t.Fatal(err)
	}
	r, err := f.openStore(digest)
	if err != nil {
		t.Fatal(err)
	}
	for r.Next() {
	}
	r.Close()
	if err := r.Err(); err == nil || !errors.Is(err, ErrCursorInvalid) || !strings.Contains(err.Error(), "digest") {
		t.Errorf("a replaced copy: %v", err)
	}
	if _, err := f.openStore("../../etc/passwd"); !errors.Is(err, ErrCursorInvalid) {
		t.Errorf("a path for a digest: %v", err)
	}
}

func TestPipProjectListsThatCannotBeFollowed(t *testing.T) {
	ctx := context.Background()
	f, ix, _ := pypiTestFeed(t, map[string]string{"mode": "simple"})
	// PEP 503 HTML (Artifactory, Nexus, devpi).
	ix.fs.on("GET", "/simple/").reply(http.StatusOK, []byte("<html><body><a href=\"/simple/six/\">six</a></body></html>")).withHeader("Content-Type", "text/html")
	_, err := f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "not PEP 691 JSON")
	// JSON without serials.
	ix.list([]byte(`{"meta":{"api-version":"1.1"},"projects":[{"name":"six"},{"name":"requests"}]}`), "", "")
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "states no _last-serial")
	// Malformed, unknown versions, too deep: permanent.
	for body, want := range map[string]string{
		`{"meta":{"api-version":"2.0"},"projects":[]}`:   "api-version",
		`{"meta":{"_last-serial":5},"projects":{"a":1}}`: "want",
		`{"meta":{"_last-serial":5}}`:                    "lists no projects",
		`{"projects":[{"name":"a","_last-serial":"x"}]}`: "not the PEP 691 document",
		`{"projects":[]} {"projects":[]}`:                "goes on after its end",
		`[1,2,3]`:                                        "want",
	} {
		ix.list([]byte(body), "", "")
		_, err = f.Bootstrap(ctx, "")
		mustErr(t, err, true, false, want)
	}
	// A missing index is permanent; a 503 asks for its wait.
	ix.fs.on("GET", "/simple/").reply(http.StatusNotFound, nil)
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "serves no project list")
	ix.fs.on("GET", "/simple/").reply(http.StatusServiceUnavailable, nil).withHeader("Retry-After", "60")
	_, err = f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d != time.Minute {
		t.Errorf("a 503: %v", err)
	}
}

func TestPipCursorsAreChecked(t *testing.T) {
	f, _, _ := pypiTestFeed(t, nil)
	ctx := context.Background()
	digest := strings.Repeat("a", 64)
	for _, bad := range []string{
		"43707253",
		`{"format":"npm/1","since":"1"}`,
		`{"format":"pip/1","mode":"xmlrpc","serial":1,"extra":1}`,
		`{"format":"pip/1","mode":"rss","serial":1}`,
		`{"format":"pip/1","mode":"xmlrpc","serial":-1}`,
		`{"format":"pip/1","mode":"simple","serial":1,"store":"../x"}`,
		`{"format":"pip/1","mode":"simple","serial":1}`,
		`{"format":"pip/1","mode":"simple","serial":1,"store":"` + digest + `"}`,
	} {
		_, err := f.Changes(ctx, bad)
		mustErr(t, err, false, true, "")
	}
	for _, bad := range []string{
		`{"format":"pip/1","mode":"xmlrpc","serial":1,"listing":true}`,
		`{"format":"pip/1","mode":"xmlrpc","serial":1,"listing":true,"store":"` + digest + `","skip":-1}`,
	} {
		_, err := f.Bootstrap(ctx, bad)
		mustErr(t, err, false, true, "")
	}
}

func TestPipReleasesComeFromTheRewrittenSimplePage(t *testing.T) {
	f, _, reads := pypiTestFeed(t, nil)
	reads.set("/simple/six/", fixture(t, "pip", "page-six.json"))
	reads.set("/simple/requests/", fixture(t, "pip", "page-requests.json"))
	ctx := context.Background()
	backend, err := pkgmgr.NewPyPI(pkgmgr.Options{Name: f.k.env.Upstream, UpstreamURL: "https://pypi.org", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"six", "Requests"} {
		rels, err := f.Releases(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		norm := strings.ToLower(name)
		checkGolden(t, "pip", "releases-"+norm, viewReleases(rels))
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return norm, r.Version })
	}
	// A gate's verdict on the page is final; access control is not a verdict
	// on the project.
	reads.setDoc("/simple/typo-squat/", fakeDoc{status: 403, gate: "nameguard", code: "typosquat"})
	_, err = f.Releases(ctx, "typo_squat")
	mustErr(t, err, true, false, "nameguard")
	reads.setDoc("/simple/held/", fakeDoc{status: 403, gate: "access-control", code: "forbidden"})
	_, err = f.Releases(ctx, "held")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("an access-control refusal: %v", err)
	}
	// Unknown, malformed, not a name.
	_, err = f.Releases(ctx, "missing")
	mustErr(t, err, true, false, "not found")
	reads.set("/simple/broken/", []byte(`{"files":"x"}`))
	_, err = f.Releases(ctx, "broken")
	mustErr(t, err, true, false, "simple page of broken")
	for _, bad := range []string{"../etc/passwd", "-x", "a b", ""} {
		_, err = f.Releases(ctx, bad)
		mustErr(t, err, true, false, "not a Python project name")
	}
}

func TestPipReleasesAreTheVersionsTheIndexNames(t *testing.T) {
	// Synthetic pages in PyPI's formats: a release whose version is not spelt
	// as its file names spell it (wheels and new sdists carry the normalized
	// form), and an HTML page that lists no versions.
	f, _, reads := pypiTestFeed(t, nil)
	file := func(name string, yanked string, size int) string {
		return `{"filename":"` + name + `","hashes":{},"size":` + strconv.Itoa(size) + `,"upload-time":"2026-01-0` + strconv.Itoa(size%9+1) +
			`T00:00:00Z","url":"http://proxy.example/v1/pip-test/files/https/files.pythonhosted.org/packages/aa/bb/` + name + `","yanked":` + yanked + `}`
	}
	reads.set("/simple/my-pkg/", []byte(`{"meta":{"api-version":"1.1","_last-serial":9},"name":"my-pkg","files":[`+
		file("my_pkg-1.0.0rc1-py3-none-any.whl", "false", 1)+","+file("my_pkg-1.0.0rc1.tar.gz", `"broken"`, 2)+","+
		file("my_pkg-2.0.0-py3-none-any.whl", `"broken"`, 3)+","+file("my-pkg-2.0.tar.gz", "true", 4)+","+
		file("my_pkg-3.0.egg", "false", 5)+","+
		`{"filename":"my_pkg-4.0.tar.gz","hashes":{},"url":"https://elsewhere.example/my_pkg-4.0.tar.gz","yanked":false}`+
		`],"versions":["1.0.0-rc1","2.0","3.0","4.0","5.0"]}`))
	rels, err := f.Releases(context.Background(), "My.Pkg")
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, r := range rels {
		y := ""
		if r.Yanked {
			y = " yanked"
		}
		got = append(got, r.Version+y+" "+strconv.Itoa(len(r.Artifacts))+" "+r.Published.Format("01-02"))
	}
	// 1.0.0-rc1 (one of its files yanked: not the release), 2.0 (both
	// files yanked), and nothing for an egg, a file the upstream does not
	// serve, or a version without files.
	if want := "1.0.0-rc1 2 01-02|2.0 yanked 2 01-04"; strings.Join(got, "|") != want {
		t.Errorf("releases %q, want %q", strings.Join(got, "|"), want)
	}
	// An HTML page lists no versions: files whose versions are equal under
	// PEP 440 are one release, spelt as the first file spells it.
	reads.set("/simple/old/", []byte(`<html><body>
<a href="/v1/pip-test/files/https/files.pythonhosted.org/packages/old-1.0.tar.gz#sha256=aa">old-1.0.tar.gz</a>
<a href="/v1/pip-test/files/https/files.pythonhosted.org/packages/old-1.0.0-py3-none-any.whl" data-yanked="">old-1.0.0-py3-none-any.whl</a>
<a href="/v1/pip-test/files/https/files.pythonhosted.org/packages/old-0.9.tar.gz">old-0.9.tar.gz</a>
</body></html>`))
	rels, err = f.Releases(context.Background(), "old")
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 2 || rels[0].Version != "0.9" || rels[1].Version != "1.0" || len(rels[1].Artifacts) != 2 || rels[1].Yanked {
		t.Errorf("releases %+v", rels)
	}
}

func TestPipXMLRPCParser(t *testing.T) {
	ok := map[string]pypiXMLValue{
		`<value>plain text</value>`:                       {Kind: pypiXMLString, Str: "plain text"},
		`<value> <string>a &amp; b</string> </value>`:     {Kind: pypiXMLString, Str: "a & b"},
		`<value><i4>-3</i4></value>`:                      {Kind: pypiXMLInt, Int: -3},
		`<value><i8>9007199254740993</i8></value>`:        {Kind: pypiXMLInt, Int: 9007199254740993},
		`<value><boolean>1</boolean></value>`:             {Kind: pypiXMLBool, Bool: true},
		`<value><nil/></value>`:                           {Kind: pypiXMLNil},
		`<value><array><data/></array></value>`:           {Kind: pypiXMLArray},
		`<value><!-- c --><string>x</string></value>`:     {Kind: pypiXMLString, Str: "x"},
		`<value><string><![CDATA[<x>]]></string></value>`: {Kind: pypiXMLString, Str: "<x>"},
	}
	for v, want := range ok {
		params, fault, err := pypiParseXMLRPC([]byte("<?xml version='1.0'?><methodResponse><params><param>" + v + "</param></params></methodResponse>"))
		if err != nil || fault != nil || len(params) != 1 {
			t.Errorf("%s: %v %v %v", v, params, fault, err)
			continue
		}
		g := params[0]
		if g.Kind != want.Kind || g.Str != want.Str || g.Int != want.Int || g.Bool != want.Bool || len(g.Items) != 0 {
			t.Errorf("%s: %+v, want %+v", v, g, want)
		}
	}
	deep := strings.Repeat("<value><array><data>", pypiXMLMaxDepth+1) + "<value>x</value>" + strings.Repeat("</data></array></value>", pypiXMLMaxDepth+1)
	for v, want := range map[string]string{
		`<value><double>1.5</double></value>`:                               "not an XML-RPC type",
		`<value><x:nil xmlns:x="urn:x"/></value>`:                           "namespace",
		`<value><string>a</string><string>b</string></value>`:               "two types",
		`<value>text<string>b</string></value>`:                             "text beside",
		`<value><int>12x</int></value>`:                                     "not an integer",
		`<value><boolean>2</boolean></value>`:                               "not 0 or 1",
		`<value><struct><member><value>x</value></member></struct></value>`: "want <name>",
		deep: "nested",
		`<value><string>` + strings.Repeat("a", pypiXMLMaxString+1) + `</string></value>`: "more than",
	} {
		_, _, err := pypiParseXMLRPC([]byte("<methodResponse><params><param>" + v + "</param></params></methodResponse>"))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%.60s: %v, want an error saying %q", v, err, want)
		}
	}
	for doc, want := range map[string]string{
		"":                         "EOF",
		"<methodResponse><params>": "EOF",
		"<methodResponse><params/></methodResponse><x/>":                           "after the response",
		"<methodResponse><params/></methodResponse>junk":                           "text after",
		"<?pi x?><methodResponse/>":                                                "processing instruction",
		"<methodResponse><fault><value><struct/></value></fault></methodResponse>": "no faultCode",
		"<methodCall/>": "want <methodResponse>",
	} {
		_, _, err := pypiParseXMLRPC([]byte(doc))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want an error saying %q", doc, err, want)
		}
	}
	// The recorded fault.
	_, fault, err := pypiParseXMLRPC(fixture(t, "pip", "fault-params.xml"))
	if err != nil || fault == nil || fault.Code != -32602 || !strings.Contains(fault.Message, "Input should be a valid integer") {
		t.Errorf("fault %+v %v", fault, err)
	}
}

func TestPipChangelogRowsWaitUntilTheyHaveSettled(t *testing.T) {
	// A release's simple page can reach the CDN a minute or more after the
	// changelog names it: rows younger than the settle period (5m) wait, and
	// the cursor stops before the first of them, in serial order.
	f, ix, _ := pypiTestFeed(t, nil)
	ix.answer("changelog_since_serial(43708647)", pypiTestXML(t, "since-43708647.xml"))
	f.now = func() time.Time { return time.Unix(1794797030, 0).Add(5 * time.Minute) }
	cur := encodeCursor(&pypiCursor{Format: f.format(), Mode: pypiModeXMLRPC, Serial: 43708647})
	b, err := f.Changes(context.Background(), cur)
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.decode(b.Next)
	if err != nil || c.Serial != 43708656 {
		t.Errorf("cursor %+v (%v), want the last settled row 43708656", c, err)
	}
	if got := strings.Join(names(b.Items), " "); got != "aixand-suite-runner-client@0.1.0a2 mgm2-community@2.1.0 onefollowup-cli@0.6.0" {
		t.Errorf("items %s", got)
	}
	if b.More || !b.LagKnown || b.Head != "43708665" {
		t.Errorf("batch %+v", b)
	}
	// Nothing has settled: an empty batch, the cursor stays.
	f.now = func() time.Time { return time.Unix(1794797000, 0).Add(5 * time.Minute) }
	b2, err := f.Changes(context.Background(), cur)
	if err != nil || len(b2.Items) != 0 || b2.Next != cur {
		t.Errorf("nothing settled: %+v %v", b2, err)
	}
	// settle 0 takes every row.
	g, gix, _ := pypiTestFeed(t, map[string]string{"settle": "0"})
	gix.answer("changelog_since_serial(43708647)", pypiTestXML(t, "since-43708647.xml"))
	g.now = f.now
	b3, err := g.Changes(context.Background(), cur)
	if err != nil {
		t.Fatal(err)
	}
	if c3, _ := g.decode(b3.Next); c3.Serial != 43708665 {
		t.Errorf("settle 0: cursor %+v", c3)
	}
}
