//go:build integration
// +build integration

package fullmirror

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/e2e/pkgscan"
	fm "github.com/blechschmidt/pullthrough-security/internal/fullmirror"
	"github.com/blechschmidt/pullthrough-security/internal/fullscan"
)

// policyMalicious is the X-Policy-Code of a pull the LLM package scan refuses
// as malicious.
const policyMalicious = "llm-package-malicious"

// mirrorUserAgent is the User-Agent of the mirror's fetches, as the download
// log records them (cmd/pullthrough: fullMirrorUserAgent).
const mirrorUserAgent = "pullthrough-full-mirror"

// runner runs one row: the scenario of doc.go against one upstream type.
type runner struct {
	t   *testing.T
	bin string
	r   row
	res *rowResult

	dir      string
	stateDir string
	env      *feedEnv
	llm      *pkgscan.MockLLM
	proc     *proxyProc
	// fatal is set once an assertion the rest of the row depends on failed.
	fatal bool
}

func newRunner(t *testing.T, bin, workDir string, r row, res *rowResult) *runner {
	dir := filepath.Join(workDir, r.Type)
	_ = os.RemoveAll(dir)
	return &runner{t: t, bin: bin, r: r, res: res, dir: dir, stateDir: filepath.Join(dir, "state")}
}

// failf marks a column failed and fails the test.
func (x *runner) failf(c column, format string, args ...any) {
	x.t.Helper()
	msg := fmt.Sprintf(format, args...)
	x.res.fail(c, msg)
	x.t.Errorf("%s: %s", c.ID, msg)
}

// abort fails every column not decided yet and stops the row.
func (x *runner) abort(format string, args ...any) {
	x.t.Helper()
	msg := fmt.Sprintf(format, args...)
	for _, c := range columns {
		x.res.mu.Lock()
		state := x.res.Cells[c.ID].State
		x.res.mu.Unlock()
		if state == cellNotRun {
			x.res.fail(c, "not reached: "+firstLine([]byte(msg)))
		}
	}
	x.fatal = true
	x.t.Errorf("%s", msg)
}

// diagnosis renders what the proxy and the stub say, for a failure message.
func (x *runner) diagnosis() string {
	var b strings.Builder
	if x.proc != nil {
		if st, err := x.proc.mirrorStatus(); err == nil {
			raw, _ := json.MarshalIndent(st, "", "  ")
			b.WriteString("\nfull mirror status:\n" + string(raw))
		} else {
			b.WriteString("\nfull mirror status: " + err.Error())
		}
		if st, err := x.proc.scanStatus(); err == nil {
			raw, _ := json.Marshal(st)
			b.WriteString("\nfull scan status: " + string(raw))
		}
		b.WriteString("\nproxy log (tail):\n" + tailFile(x.proc.logPath, 25))
	}
	if x.env != nil && x.env.Stub != nil {
		reqs := x.env.Stub.Requests()
		if len(reqs) > 40 {
			reqs = reqs[len(reqs)-40:]
		}
		b.WriteString("\nstub requests (last 40):\n  " + strings.Join(reqs, "\n  "))
	}
	return b.String()
}

// cleanup stops what the row started and removes its workspace unless it
// failed or the run keeps workspaces.
func (x *runner) cleanup(keep bool) {
	if x.proc != nil {
		x.proc.stop()
	}
	if x.llm != nil {
		x.llm.Close()
	}
	if x.env != nil && x.env.Stub != nil {
		x.env.Stub.Close()
	}
	if x.t.Failed() || keep {
		x.t.Logf("workspace kept: %s", x.dir)
		return
	}
	_ = os.RemoveAll(x.dir)
}

// start starts a proxy process mirroring the row's upstream.
func (x *runner) start(role string) *proxyProc {
	x.t.Helper()
	base := x.env.Stub.Settings()
	settings := base
	if x.r.Settings != nil {
		settings = x.r.Settings(x.env, base)
	}
	upURL := x.env.Stub.UpstreamURL()
	if x.r.UpstreamURL != nil {
		upURL = x.r.UpstreamURL(x.env)
	}
	pc := procConfig{
		Type: x.r.Type, URL: upURL, Settings: settings, Feed: x.r.Options(x.env), Mirror: true,
		StateDir: x.stateDir, LLMBaseURL: x.llm.BaseURL("claude"), LLMAPIKey: x.llm.APIKey(),
	}
	p, err := startProxy(x.bin, x.dir, role, pc)
	if err != nil {
		x.abort("starting the proxy (%s): %v", role, err)
		return nil
	}
	return p
}

// expectation is what the mirror must have fetched and refused once the
// packages published so far are mirrored.
type expectation struct {
	fetched map[string]publication // file path → its package
	refused map[string]publication
	accept  map[string]string
	// metadata are the files the download log leaves out when served.
	metadata map[string]bool
	// rereported is how many files the mirror finds cached because the
	// adapter reports their packages again by design (row.Rereported).
	rereported uint64
}

func (x *runner) expect() expectation {
	e := expectation{fetched: map[string]publication{}, refused: map[string]publication{}, accept: map[string]string{}, metadata: map[string]bool{}}
	for _, p := range x.env.Publications() {
		refused := x.r.refused(x.env, p)
		for _, f := range x.r.files(x.env, p) {
			if refused[f.Path] {
				e.refused[f.Path] = p
			} else {
				e.fetched[f.Path] = p
			}
			e.accept[f.Path] = f.Accept
			if f.Metadata {
				e.metadata[f.Path] = true
			}
		}
	}
	for _, v := range x.r.Rereported {
		if p, ok := x.env.Publication(v); ok {
			e.rereported += uint64(len(x.r.files(x.env, p)))
		}
	}
	return e
}

// waitMirrored waits until the mirror has dealt with every file the packages
// published so far have: fetched or refused, its batch finished, and the full
// scan has a reading of each.
func (x *runner) waitMirrored(phase string, bound time.Duration) (fm.UpstreamStatus, bool) {
	x.t.Helper()
	want := x.expect()
	benign, malicious := 0, 0
	for _, p := range x.env.Publications() {
		if p.Variant == pkgMalicious {
			malicious++
		} else {
			benign++
		}
	}
	var last fm.UpstreamStatus
	err := waitFor(bound, func() (bool, string) {
		st, err := x.proc.mirrorStatus()
		if err != nil {
			return false, err.Error()
		}
		last = st
		c := st.Counters
		switch {
		case c.Failed > 0 || c.PackageErrors > 0:
			// Final: the mirror gave up on a file or a package.
			return true, ""
		case st.Phase != "follow":
			return false, fmt.Sprintf("phase %q (state %s: %s)", st.Phase, st.State, st.Detail)
		case c.Fetched+c.Refused < uint64(len(want.fetched)+len(want.refused)):
			return false, fmt.Sprintf("fetched %d + refused %d of %d files (state %s: %s)", c.Fetched, c.Refused, len(want.fetched)+len(want.refused), st.State, st.Detail)
		case st.Queued > 0 || st.InFlight > 0 || st.Deferred > 0:
			return false, fmt.Sprintf("queued %d, in flight %d, deferred %d", st.Queued, st.InFlight, st.Deferred)
		}
		// The full scan learns of the mirror's fetches through notes it takes
		// in when its loop wakes: its figures follow the mirror's counters.
		fs, err := x.proc.scanStatus()
		if err != nil {
			return false, err.Error()
		}
		switch {
		case fs.Pending > 0:
			return false, fmt.Sprintf("the full scan has %d pending", fs.Pending)
		case fs.Benign < benign || fs.Malicious < malicious:
			return false, fmt.Sprintf("the full scan counts %d benign and %d malicious, want %d and %d (%+v)", fs.Benign, fs.Malicious, benign, malicious, fs.Figures)
		}
		return true, ""
	})
	if err != nil {
		x.abort("%s: the mirror did not fetch what was published: %v%s", phase, err, x.diagnosis())
		return last, false
	}
	if c := last.Counters; c.Failed > 0 || c.PackageErrors > 0 {
		x.abort("%s: the mirror gave up: %d files failed, %d packages could not be listed%s", phase, c.Failed, c.PackageErrors, x.diagnosis())
		return last, false
	}
	return last, true
}

// run runs the row's scenario.
func (x *runner) run(keep bool) {
	began := time.Now()
	defer func() {
		x.res.Seconds = time.Since(began).Seconds()
		if x.llm != nil {
			x.res.LLMCalls = x.llm.PackageScans()
		}
		x.cleanup(keep)
	}()
	if err := os.MkdirAll(x.dir, 0o755); err != nil {
		x.abort("creating the workspace: %v", err)
		return
	}

	// The registry, with the seed published, and the feed in front of it.
	stub, err := pkgscan.StartMirrorStub(x.r.stubID(), pkgSeed)
	if err != nil {
		x.abort("starting the stub registry: %v", err)
		return
	}
	x.res.Title, x.res.Format = stub.Title(), stub.Format()
	feedDir := filepath.Join(x.dir, "feed")
	if err := os.MkdirAll(feedDir, 0o755); err != nil {
		x.abort("creating the feed directory: %v", err)
		return
	}
	x.env = &feedEnv{Stub: stub, Dir: feedDir}
	if err := x.env.adopt(pkgSeed); err != nil {
		x.abort("%v", err)
		return
	}
	if err := x.r.Start(x.env); err != nil {
		x.abort("starting the feed: %v", err)
		return
	}
	x.llm = pkgscan.StartMockLLM()

	// 1. The enumeration fetches the seed.
	if x.proc = x.start("first"); x.proc == nil {
		return
	}
	if _, ok := x.waitMirrored("bootstrap", waitBootstrap); !ok {
		return
	}

	// 2. A benign and a malicious package are published; a poll finds them.
	added, err := x.env.publish(pkgBenign, pkgMalicious)
	if err == nil && x.r.Publish != nil {
		err = x.r.Publish(x.env, added)
	}
	if err != nil {
		x.abort("publishing the benign and the malicious package: %v", err)
		return
	}
	st, ok := x.waitMirrored("follow", waitFollow)
	if !ok {
		return
	}
	x.checkMirrored(st)
	if x.fatal {
		return
	}

	// 3. Stopped, a package published, started again: the mirror continues
	// from its cursor.
	x.checkResume(st)
	if !x.fatal {
		if err := verifyAudit(x.bin, x.stateDir); err != nil {
			x.failf(colLogged, "%v", err)
		}
	}
}

// adopt records the publications of packages the stub was started with.
func (e *feedEnv) adopt(variants ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, v := range variants {
		pkg, ok := e.Stub.Package(v)
		if !ok {
			return fmt.Errorf("the stub registry does not serve the %s package", v)
		}
		e.pubs = append(e.pubs, publication{Variant: v, Pkg: pkg, Seq: len(e.pubs) + 1, Time: e.Stub.PublishedAt(v)})
	}
	return nil
}

// checkMirrored asserts what holds once the benign and the malicious package
// are mirrored — first everything that needs no client request, then the
// clients' pulls.
func (x *runner) checkMirrored(st fm.UpstreamStatus) {
	x.t.Helper()
	want := x.expect()
	p := x.proc

	// --- logged: the counts, and the download log, before any client request.
	x.checkCounts(colLogged, st, want, "after the poll")
	entries, err := p.downloads()
	if err != nil {
		x.failf(colLogged, "reading the download log: %v", err)
		entries = nil
	} else {
		x.checkLog(entries, want, nil)
	}

	// --- mirrored: every file the mirror counts fetched is in the cache under
	// the path it was fetched by, and every package's bytes came from the
	// registry — before anyone asked for them.
	x.checkCache(want)
	for _, pub := range x.env.Publications() {
		if n := x.env.Stub.Served(digestOf(pub.Pkg.Body)); n == 0 {
			c := colMirrored
			if pub.Variant == pkgMalicious {
				c = colBlocked
			}
			x.failf(c, "the registry never served the %s package's bytes: the mirror did not fetch it", pub.Variant)
		}
	}
	// The seed was fetched by the enumeration: before the bootstrap ended.
	if entries != nil {
		seed, _ := x.env.Publication(pkgSeed)
		path := "/v1/" + upstreamName + x.r.files(x.env, seed)[0].Path
		for _, e := range entries {
			if e.Path == path && e.Time.After(st.BootstrapFinished) {
				x.failf(colMirrored, "the seed's payload was fetched at %s, after the enumeration ended (%s): a poll found it, not the enumeration", e.Time, st.BootstrapFinished)
			}
		}
	}

	// --- scanned and blocked, as the proxy's stores say.
	verdicts, err := p.verdicts()
	if err != nil {
		x.failf(colScanned, "reading the verdicts: %v", err)
		x.failf(colBlocked, "reading the verdicts: %v", err)
	}
	cached, err := p.cachedDigests()
	if err != nil {
		x.failf(colMirrored, "%v", err)
		x.failf(colBlocked, "%v", err)
	}
	fs, err := p.scanStatus()
	if err != nil {
		x.failf(colScanned, "reading the full scan's status: %v", err)
		x.failf(colBlocked, "reading the full scan's status: %v", err)
	}
	for _, pub := range x.env.Publications() {
		digest := digestOf(pub.Pkg.Body)
		v, has := verdicts[digest]
		saw, outcome := x.llm.Saw(pub.Pkg.Token)
		switch pub.Variant {
		case pkgSeed, pkgBenign:
			if !cached[digest] {
				x.failf(colMirrored, "the %s package's payload (%s, %s) is not in the cache", pub.Variant, pub.Pkg.Path, digest)
			}
			if !saw || outcome != "benign" {
				x.failf(colScanned, "the mock LLM was not shown the %s package's content token (seen %v, answered %q)", pub.Variant, saw, outcome)
			}
			if !has || v.Verdict != "benign" {
				x.failf(colScanned, "no benign verdict on the %s package's payload %s (have %v: %+v)", pub.Variant, digest, has, v)
			}
		case pkgMalicious:
			if cached[digest] {
				x.failf(colBlocked, "the malicious package's payload %s is in the cache", digest)
			}
			if !saw || outcome != "malicious" {
				x.failf(colBlocked, "the mock LLM was not shown the malicious package's content token (seen %v, answered %q)", saw, outcome)
			}
			if !has || v.Verdict != "malicious" || !v.Standing.Refused {
				x.failf(colBlocked, "no refusing malicious verdict on the malicious package's payload %s (have %v: %+v)", digest, has, v)
			}
		}
	}
	if err == nil {
		x.checkScanFigures(fs, 2, "after the poll")
	}
	// The figures after the restart are checked in checkResume.
	if c := st.Counters; c.RefusedBy["llmpkgscan"] != uint64(len(want.refused)) {
		x.failf(colBlocked, "the mirror counts %d files refused by llmpkgscan (%v), want %d", c.RefusedBy["llmpkgscan"], c.RefusedBy, len(want.refused))
	}

	// --- the clients' pulls.
	scans := x.llm.PackageScans()
	for _, v := range []string{pkgSeed, pkgBenign} {
		pub, _ := x.env.Publication(v)
		hits := x.env.Stub.Served(digestOf(pub.Pkg.Body))
		res, err := p.get(pub.Pkg.Path, pub.Pkg.Header)
		switch {
		case err != nil:
			x.failf(colMirrored, "pulling the %s package: %v", v, err)
			continue
		case res.Status != 200:
			x.failf(colMirrored, "pulling the %s package %s: status %d: %s", v, pub.Pkg.Path, res.Status, firstLine(res.Body))
			continue
		case !bytes.Equal(res.Body, pub.Pkg.Body):
			x.failf(colMirrored, "pulling the %s package: %d bytes that are not the package's %d", v, len(res.Body), len(pub.Pkg.Body))
		}
		if got := res.Header.Get("X-Cache"); got != "HIT" {
			x.failf(colMirrored, "pulling the %s package: X-Cache %q, want HIT (the mirror cached it)", v, got)
		}
		if n := x.env.Stub.Served(digestOf(pub.Pkg.Body)); n != hits {
			x.failf(colMirrored, "pulling the %s package fetched it from the registry again (%d fetches, %d before)", v, n, hits)
		}
		if got := res.Header.Get("X-LLMPkgScan-Verdict"); got != "benign" {
			x.failf(colScanned, "pulling the %s package: X-LLMPkgScan-Verdict %q, want benign", v, got)
		}
	}
	mal, _ := x.env.Publication(pkgMalicious)
	res, err := p.get(mal.Pkg.Path, mal.Pkg.Header)
	switch {
	case err != nil:
		x.failf(colBlocked, "pulling the malicious package: %v", err)
	case res.Status != 403 || res.Header.Get("X-Policy-Code") != policyMalicious:
		x.failf(colBlocked, "pulling the malicious package %s: status %d, X-Policy-Code %q (want 403, %s): %s",
			mal.Pkg.Path, res.Status, res.Header.Get("X-Policy-Code"), policyMalicious, firstLine(res.Body))
	case bytes.Contains(res.Body, mal.Pkg.Body[:min(len(mal.Pkg.Body), 64)]):
		x.failf(colBlocked, "the refusal of the malicious package carries its bytes")
	}
	if n := x.llm.PackageScans(); n != scans {
		x.failf(colScanned, "the clients' pulls cost %d model calls; the mirror's verdicts must answer them", n-scans)
	}
	x.res.pass(colMirrored)
	x.res.pass(colScanned)
	x.res.pass(colBlocked)
	x.res.pass(colLogged)
}

// checkCounts asserts the mirror's counters: exactly the files expected,
// fetched or refused, nothing failed, nothing skipped.
func (x *runner) checkCounts(c column, st fm.UpstreamStatus, want expectation, when string) {
	x.t.Helper()
	got := st.Counters
	x.res.Fetched, x.res.Refused = got.Fetched, got.Refused
	x.res.Files = len(want.fetched) + len(want.refused)
	if got.Fetched != uint64(len(want.fetched)) || got.Refused != uint64(len(want.refused)) ||
		got.Failed != 0 || got.PackageErrors != 0 ||
		got.SkippedTotal() != want.rereported || got.Skipped[fm.SkipCached] != want.rereported {
		x.failf(c, "%s the mirror counts fetched %d, refused %d (%v), failed %d, package errors %d, skipped %v; want fetched %d (%s), refused %d (%s), skipped (cached) %d",
			when, got.Fetched, got.Refused, got.RefusedBy, got.Failed, got.PackageErrors, got.Skipped,
			len(want.fetched), keys(want.fetched), len(want.refused), keys(want.refused), want.rereported)
	}
}

// checkLog asserts the download log: an entry with via=system for every file
// the mirror fetched or refused (none for metadata it fetched), and no entry of
// a client request. only, when set, limits the files to those of the given
// packages.
func (x *runner) checkLog(entries []downloadlog.Entry, want expectation, only map[string]bool) {
	x.t.Helper()
	mount := "/v1/" + upstreamName
	byPath := map[string][]downloadlog.Entry{}
	for _, e := range entries {
		if e.Via != downloadlog.ViaSystem {
			x.failf(colLogged, "the download log holds an entry not made by the mirror before any client request: %s %s via=%q subject=%q", e.Method, e.Path, e.Via, e.Subject)
			continue
		}
		if e.Subject != fm.Subject || e.UserAgent != mirrorUserAgent {
			x.failf(colLogged, "a via=system entry of %s names subject %q and user agent %q, want %q and %q", e.Path, e.Subject, e.UserAgent, fm.Subject, mirrorUserAgent)
		}
		byPath[e.Path] = append(byPath[e.Path], e)
	}
	check := func(path string, pub publication, refused bool) {
		if only != nil && !only[pub.Variant] {
			return
		}
		list := byPath[mount+path]
		if !refused && want.metadata[path] {
			// Served metadata is not a download: the log leaves it out.
			if len(list) > 0 {
				x.failf(colLogged, "the download log records %s, which the backend classifies as metadata (left out unless refused)", mount+path)
			}
			return
		}
		if len(list) == 0 {
			x.failf(colLogged, "the download log has no via=system entry for %s (the %s package's file)", mount+path, pub.Variant)
			return
		}
		e := list[len(list)-1]
		switch {
		case refused && (e.Outcome != downloadlog.OutcomeBlocked || e.Gate != "llmpkgscan"):
			x.failf(colLogged, "the download log records the refused %s as %s (gate %q, status %d), want blocked by llmpkgscan", path, e.Outcome, e.Gate, e.Status)
		case !refused && (e.Outcome != downloadlog.OutcomeServed || e.Status != 200):
			x.failf(colLogged, "the download log records the mirrored %s as %s (status %d, gate %q), want served", path, e.Outcome, e.Status, e.Gate)
		}
	}
	for path, pub := range want.fetched {
		check(path, pub, false)
	}
	for path, pub := range want.refused {
		check(path, pub, true)
	}
}

// checkCache asserts that every file the mirror fetched is in the cache, under
// the path it was fetched by (the fill provenance the gateway records), and
// that no file it refused is.
func (x *runner) checkCache(want expectation) {
	x.t.Helper()
	entries, err := x.proc.cacheEntries()
	if err != nil {
		x.failf(colMirrored, "%v", err)
		return
	}
	byPath := map[string]bool{}
	for _, e := range entries {
		if e.Metadata[cacheFillUpstream] != upstreamName {
			continue
		}
		path := e.Metadata[cacheFillPath]
		if p, err := url.PathUnescape(path); err == nil {
			path = p
		}
		byPath[path] = true
	}
	for path, pub := range want.fetched {
		if !byPath[path] {
			x.failf(colMirrored, "the cache holds no entry filled by %s (the %s package's file; %d entries)", path, pub.Variant, len(entries))
		}
	}
	for path := range want.refused {
		if byPath[path] {
			x.failf(colBlocked, "the cache holds the refused file %s", path)
		}
	}
}

// checkScanFigures asserts the full scan's figures for the upstream: every
// benign payload scanned benign, the malicious one malicious and removed from
// the cache, nothing pending or failed.
func (x *runner) checkScanFigures(fs fullscan.UpstreamStatus, benign int, when string) {
	x.t.Helper()
	f := fs.Figures
	if f.Pending != 0 || f.Errors != 0 || f.Unscannable != 0 || f.Refused != 0 {
		x.failf(colScanned, "%s the full scan has %d pending, %d errors, %d unscannable, %d refused by the model (%+v)", when, f.Pending, f.Errors, f.Unscannable, f.Refused, fs.Counters.Unscanned)
	}
	if f.Benign < benign {
		x.failf(colScanned, "%s the full scan counts %d artifacts benign, want at least %d (%+v)", when, f.Benign, benign, f)
	}
	if f.Malicious != 1 || f.Quarantined != 1 {
		x.failf(colBlocked, "%s the full scan counts %d malicious, %d removed from the cache, want 1 and 1 (%+v)", when, f.Malicious, f.Quarantined, f)
	}
	// The full scan names an artifact by the path that first fetched it: the
	// mirror's, which may spell the payload otherwise than a client does
	// (Bazel's /modules/<m>/<v>/archive for the archive's own path; one cache
	// entry) — the row's first file.
	mal, _ := x.env.Publication(pkgMalicious)
	payload := x.r.files(x.env, mal)[0].Path
	found := false
	for _, r := range fs.RecentMalicious {
		if r.Path == payload || r.Path == mal.Pkg.Path {
			found = true
		}
	}
	if !found {
		x.failf(colBlocked, "%s the full scan's recent malicious verdicts do not name %s (%+v)", when, payload, fs.RecentMalicious)
	}
}

// checkResume stops the proxy, publishes the late package and starts the
// proxy again on the same state.
func (x *runner) checkResume(before fm.UpstreamStatus) {
	x.t.Helper()
	// What the stub received from here on is the restarted proxy's: the first
	// one is stopped before the position is taken (a poll it had in flight
	// would otherwise count as the restarted proxy's first read).
	x.proc.stop()
	x.proc = nil
	from := len(x.env.Stub.Requests())
	x.env.set(restartLogKey, from)
	added, err := x.env.publish(pkgLate)
	if err == nil && x.r.Publish != nil {
		err = x.r.Publish(x.env, added)
	}
	if err != nil {
		x.abort("publishing the late package: %v", err)
		return
	}
	old := map[string]bool{}
	for path := range x.expect().fetched {
		old[path] = true
	}
	for path := range x.expect().refused {
		old[path] = true
	}
	late := x.r.files(x.env, added[0])
	for _, f := range late {
		delete(old, f.Path)
	}
	if x.proc = x.start("restarted"); x.proc == nil {
		return
	}
	st, ok := x.waitMirrored("after the restart", waitRestart)
	if !ok {
		return
	}
	want := x.expect()
	x.checkCounts(colResumed, st, want, "after the restart")
	if !st.BootstrapStarted.Equal(before.BootstrapStarted) || !st.BootstrapFinished.Equal(before.BootstrapFinished) {
		x.failf(colResumed, "the restarted mirror enumerated the registry again (bootstrap %s–%s, before %s–%s)",
			st.BootstrapStarted, st.BootstrapFinished, before.BootstrapStarted, before.BootstrapFinished)
	}
	if st.Counters.Polls <= before.Counters.Polls {
		x.failf(colResumed, "the restarted mirror counts %d polls, %d before the restart: its counters were not kept, or it did not poll", st.Counters.Polls, before.Counters.Polls)
	}
	oldDigests := map[string]string{}
	for _, p := range x.env.Publications() {
		if p.Variant != pkgLate {
			oldDigests[digestOf(p.Pkg.Body)] = p.Variant
		}
	}
	for _, r := range x.env.Stub.Log()[from:] {
		if v, ok := oldDigests[r.Digest]; ok && r.Status >= 200 && r.Status < 300 {
			x.failf(colResumed, "the restarted mirror fetched the %s package's bytes from the registry again (%s)", v, r)
		}
	}
	after := x.env.Stub.Requests()[from:]
	for _, line := range after {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		path, _, _ := strings.Cut(fields[1], "?")
		if old[path] {
			x.failf(colResumed, "the restarted mirror fetched %s again: it was mirrored before the restart (%s)", path, line)
		}
	}
	if x.r.Resumed != nil {
		if err := x.r.Resumed(x.env, after); err != nil {
			x.failf(colResumed, "the feed was not read from the stored cursor: %v", err)
		}
	}
	if fs, err := x.proc.scanStatus(); err != nil {
		x.failf(colResumed, "reading the full scan's status: %v", err)
	} else if f := fs.Figures; f.Benign < 3 || f.Malicious != 1 || f.Quarantined != 1 || f.Pending != 0 || f.Errors != 0 {
		x.failf(colResumed, "after the restart the full scan counts %d benign, %d malicious, %d removed, %d pending, %d errors; want at least 3, 1, 1, 0, 0 (its state was not kept?)",
			f.Benign, f.Malicious, f.Quarantined, f.Pending, f.Errors)
	}
	if saw, outcome := x.llm.Saw(added[0].Pkg.Token); !saw || outcome != "benign" {
		x.failf(colResumed, "the late package was not scanned (seen %v, answered %q)", saw, outcome)
	}
	if entries, err := x.proc.downloads(); err != nil {
		x.failf(colResumed, "reading the download log: %v", err)
	} else {
		x.checkLog(entries, want, map[string]bool{pkgLate: true})
	}
	if events, err := auditEvents(x.stateDir); err != nil {
		x.failf(colResumed, "reading the audit log: %v", err)
	} else {
		n := 0
		for _, e := range events {
			if e.Type == "full_mirror" && e.Reason == "fullmirror:bootstrap-started" {
				n++
			}
		}
		if n != 1 {
			x.failf(colResumed, "the audit log records %d enumerations of the registry, want 1", n)
		}
	}
	x.res.pass(colResumed)
	x.proc.stop()
}

// digestOf is the sha256 digest of b as the proxy writes digests.
func digestOf(b []byte) string { return pkgscan.Digest(b) }

func keys[V any](m map[string]V) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}
