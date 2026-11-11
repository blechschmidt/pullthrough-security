//go:build integration
// +build integration

package downloadlog

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	dl "github.com/blechschmidt/pullthrough-security/internal/downloadlog"
)

// ecosystem is one package ecosystem under test.
type ecosystem struct {
	// id is the ecosystem label, and the name of its upstream in the proxy
	// configuration ("cargo", "go").
	id string
	// subnet is the /24 the ecosystem's client machines live in ("127.0.10");
	// machine addresses are subnet.1, .2, …
	subnet string
	// forwardedClient is the address of the machine behind the trusted proxy,
	// as that proxy reports it; forgedAddr is what the untrusted peer claims.
	forwardedClient string
	forgedAddr      string
	// pkgs are the stub's packages by role.
	pkgs map[string]pkg
	// inst is the package manager.
	inst installer
}

func (e ecosystem) addr(n int) string { return e.subnet + "." + strconv.Itoa(n) }
func (e ecosystem) cidr() string      { return e.subnet + ".0/24" }

// suite is the shared state of one run.
type suite struct {
	t      *testing.T
	stub   *stub
	proxy  *proxyProc
	report *report
	work   string
	start  time.Time
	// egresses are every client machine's way out, closed at the end.
	egresses []*egress
	// expected counts what the log must hold per ecosystem once that
	// ecosystem's checks have run, by outcome.
	expected map[string]map[dl.Outcome]int
}

// machine starts the egress of a client machine.
func (s *suite) machine(name, addr, forwardFor string) *egress {
	s.t.Helper()
	_, port, _ := net.SplitHostPort(s.proxy.listen)
	eg, err := newEgress(name, addr, forwardFor, s.proxy.listen, net.JoinHostPort(publicHost, port))
	if err != nil {
		s.t.Fatalf("starting the egress of machine %s: %v", name, err)
	}
	s.egresses = append(s.egresses, eg)
	return eg
}

// installOn has the ecosystem's package manager install p on a client machine,
// from cold caches.
func (s *suite) installOn(eco ecosystem, eg *egress, p pkg) (bool, string) {
	dir := filepath.Join(s.work, "clients", eg.name+"-"+strconv.Itoa(len(s.egresses))+"-"+strconv.FormatInt(time.Now().UnixNano(), 36))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return eco.inst.install(ctx, s.proxy.publicURL+"/v1/"+eco.id, eg, p, dir)
}

func (s *suite) count(eco string, outcome dl.Outcome) {
	if s.expected[eco] == nil {
		s.expected[eco] = map[dl.Outcome]int{}
	}
	s.expected[eco][outcome]++
}

func q(pairs ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		v.Set(pairs[i], pairs[i+1])
	}
	return v
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func clientIPs(entries []dl.Entry) []string {
	set := map[string]bool{}
	for _, e := range entries {
		set[e.ClientIP] = true
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func sameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	for i := range g {
		if g[i] != w[i] {
			return false
		}
	}
	return true
}

// TestDownloadLog is the suite. See the package documentation for what is real,
// what is stubbed, and what is asserted.
func TestDownloadLog(t *testing.T) {
	bin := proxyBinary(t)

	work := os.Getenv(envWorkDir)
	if work == "" {
		dir, err := os.MkdirTemp("", "downloadlog-e2e-")
		if err != nil {
			t.Fatal(err)
		}
		work = dir
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Logf("work directory: %s", work)

	st, err := newStub()
	if err != nil {
		t.Fatalf("building the stub registries: %v", err)
	}
	defer st.close()

	stateDir := filepath.Join(work, "proxy")
	logPath := filepath.Join(work, "proxy.log")
	proxy, err := startProxy(bin, stateDir, logPath, st, "")
	if err != nil {
		t.Fatalf("starting the proxy: %v", err)
	}
	s := &suite{t: t, stub: st, proxy: proxy, report: newReport(), work: work, start: time.Now(), expected: map[string]map[dl.Outcome]int{}}
	defer func() {
		s.proxy.stop()
		for _, eg := range s.egresses {
			eg.close()
		}
		if t.Failed() || os.Getenv(envKeep) != "" {
			t.Logf("work directory kept for inspection: %s (proxy log: %s)", work, logPath)
			return
		}
		_ = os.RemoveAll(work)
	}()

	mode := strings.ToLower(strings.TrimSpace(os.Getenv(envClients)))
	cargo, err := pickInstaller(mode, findCargo, scriptedCargo{}, "cargo")
	if err != nil {
		t.Fatal(err)
	}
	gocmd, err := pickInstaller(mode, findGo, scriptedGo{}, "the go command")
	if err != nil {
		t.Fatal(err)
	}
	ecosystems := []ecosystem{
		{id: "cargo", subnet: "127.0.10", forwardedClient: "203.0.113.10", forgedAddr: "198.51.100.10", pkgs: st.crates, inst: cargo},
		{id: "go", subnet: "127.0.20", forwardedClient: "203.0.113.20", forgedAddr: "198.51.100.20", pkgs: st.modules, inst: gocmd},
	}
	for _, eco := range ecosystems {
		s.report.addEcosystem(eco.id, eco.inst)
		t.Logf("%s client: %s (real: %v)", eco.id, eco.inst.describe(), eco.inst.real())
	}

	// The report is written whatever happens, and its verdict is the test's: a
	// check that failed or was never reached fails the run.
	defer func() {
		if page, err := s.proxy.downloads(nil); err == nil {
			s.report.setLog(page.Entries)
		}
		problems := s.report.finalize()
		path, werr := s.report.write()
		switch {
		case werr != nil:
			t.Errorf("writing the report: %v", werr)
		case path != "":
			t.Logf("report written to %s", path)
		}
		t.Logf("\n%s", s.report.markdown())
		for _, p := range problems {
			t.Errorf("not passed: %s", p)
		}
	}()

	for _, eco := range ecosystems {
		eco := eco
		t.Run(eco.id, func(t *testing.T) { s.runEcosystem(t, eco) })
	}
	t.Run("common", func(t *testing.T) { s.runCommon(t, ecosystems) })
}

// checker runs named checks in order and records them in the report. A check
// that fails makes the checks after it "skipped": they build on its result.
type checker struct {
	t      *testing.T
	report *report
	scope  string
	failed bool
}

func (c *checker) run(name string, fn func() (string, error)) {
	c.t.Helper()
	if c.failed {
		return // stays "skipped" in the report
	}
	detail, err := fn()
	if err != nil {
		c.failed = true
		c.report.set(c.scope, name, statusFail, err.Error())
		c.t.Errorf("[%s] %s: %v", c.label(), name, err)
		return
	}
	c.report.set(c.scope, name, statusPass, detail)
	c.t.Logf("[%s] PASS %s: %s", c.label(), name, detail)
}

func (c *checker) label() string {
	if c.scope == "" {
		return "common"
	}
	return c.scope
}

func (s *suite) runEcosystem(t *testing.T, eco ecosystem) {
	good, extra, denied := eco.pkgs[roleGood], eco.pkgs[roleExtra], eco.pkgs[roleDenied]
	machineA := s.machine(eco.id+"-a", eco.addr(1), "")
	machineB := s.machine(eco.id+"-b", eco.addr(2), "")
	machineC := s.machine(eco.id+"-c", eco.addr(3), "")
	// The load balancer: its address is the one in server.trustedProxies, and it
	// reports the client it forwards for.
	balancer := s.machine(eco.id+"-lb", trustedProxyAddr, eco.forwardedClient)
	// A peer that is not trusted and claims to forward for someone else.
	forger := s.machine(eco.id+"-forger", eco.addr(5), eco.forgedAddr)

	c := &checker{t: t, report: s.report, scope: eco.id}

	c.run(checkInstall, func() (string, error) {
		ok, out := s.installOn(eco, machineA, good)
		if !ok {
			return "", fmt.Errorf("%s could not install %s through the proxy:\n%s", eco.inst.describe(), good, tail(out, 25))
		}
		return fmt.Sprintf("%s installed %s through %s/v1/%s", eco.inst.describe(), good, s.proxy.publicURL, eco.id), nil
	})

	c.run(checkLogged, func() (string, error) {
		entries, err := s.proxy.awaitEntries(q("ip", machineA.addr), 1)
		if err != nil {
			return "", err
		}
		// Installing one package takes several requests — the registry
		// configuration and the index for cargo; the version list, .info and
		// .mod for go. Exactly one of them is the package.
		if len(entries) != 1 {
			return "", fmt.Errorf("the log holds %d entries for %s, want exactly 1 (the package; not the index requests): %s",
				len(entries), machineA.addr, describe(entries))
		}
		e := entries[0]
		s.count(eco.id, dl.OutcomeServed)
		want := dl.Entry{
			ID: e.ID, Time: e.Time, DurationMs: e.DurationMs, Path: e.Path, UserAgent: e.UserAgent,
			ClientIP: machineA.addr, Ecosystem: eco.id, Upstream: eco.id,
			Package: good.Name, Version: good.Version, Artifact: good.Artifact, Kind: dl.KindPackage,
			Method: http.MethodGet, Status: http.StatusOK, Outcome: dl.OutcomeServed, Cache: "MISS",
			Bytes: int64(len(good.Body)), Size: int64(len(good.Body)),
		}
		if e != want {
			return "", fmt.Errorf("the entry is\n  %+v\nwant\n  %+v", e, want)
		}
		if !strings.HasPrefix(e.Path, "/v1/"+eco.id+"/") {
			return "", fmt.Errorf("the entry's path %q is not below the %s mount", e.Path, eco.id)
		}
		if !strings.HasPrefix(e.UserAgent, eco.inst.userAgent()) {
			return "", fmt.Errorf("the entry's client tool is %q, want one starting with %q", e.UserAgent, eco.inst.userAgent())
		}
		if e.Time.Before(s.start.Add(-time.Second)) || e.Time.After(time.Now().Add(time.Second)) {
			return "", fmt.Errorf("the entry's time %s is outside the run (%s … now)", e.Time, s.start)
		}
		return fmt.Sprintf("%s from %s: served, %s, %d bytes, client %q", good, e.ClientIP, e.Cache, e.Bytes, e.UserAgent), nil
	})

	c.run(checkCacheHit, func() (string, error) {
		ok, out := s.installOn(eco, machineB, good)
		if !ok {
			return "", fmt.Errorf("the second machine could not install %s:\n%s", good, tail(out, 25))
		}
		entries, err := s.proxy.awaitEntries(q("ip", machineB.addr), 1)
		if err != nil {
			return "", err
		}
		if len(entries) != 1 {
			return "", fmt.Errorf("the log holds %d entries for %s, want 1: %s", len(entries), machineB.addr, describe(entries))
		}
		e := entries[0]
		s.count(eco.id, dl.OutcomeServed)
		if e.Package != good.Name || e.Version != good.Version || e.Outcome != dl.OutcomeServed || e.Cache != "HIT" || e.Bytes != int64(len(good.Body)) {
			return "", fmt.Errorf("the second machine's entry is %+v; want %s served from cache (HIT), %d bytes", e, good, len(good.Body))
		}
		if n := s.stub.fetches(good); n != 1 {
			return "", fmt.Errorf("the proxy fetched %s from upstream %d times, want once", good, n)
		}
		return fmt.Sprintf("%s from %s: served from cache; upstream fetched once", good, e.ClientIP), nil
	})

	c.run(checkWhoPulled, func() (string, error) {
		want := []string{machineA.addr, machineB.addr}
		page, err := s.proxy.downloads(q("package", good.Name, "version", good.Version, "ecosystem", eco.id))
		if err != nil {
			return "", err
		}
		if got := clientIPs(page.Entries); !sameSet(got, want) || page.Total != 2 {
			return "", fmt.Errorf("filtering by %s lists %d entries from %v, want 2 entries from %v", good, page.Total, got, want)
		}
		// Newest first: the second machine's pull is listed before the first's.
		if page.Entries[0].ClientIP != machineB.addr || page.Entries[1].ClientIP != machineA.addr {
			return "", fmt.Errorf("entries are not newest first: %s", describe(page.Entries))
		}
		sum, err := s.proxy.summary(q("package", good.Name, "ecosystem", eco.id))
		if err != nil {
			return "", err
		}
		var summarized []string
		for _, cs := range sum.ByClient {
			summarized = append(summarized, cs.ClientIP)
		}
		if !sameSet(summarized, want) || sum.Clients != 2 || sum.Packages != 1 || len(sum.ByPackage) != 1 || sum.ByPackage[0].Clients != 2 {
			return "", fmt.Errorf("the summary of %s names clients %v (%d clients, %d packages), want %v", good, summarized, sum.Clients, sum.Packages, want)
		}
		// A wildcard finds it too, and a different name does not.
		wild, err := s.proxy.downloads(q("package", strings.TrimSuffix(good.Name, "good")+"g*", "ecosystem", eco.id))
		if err != nil {
			return "", err
		}
		other, err := s.proxy.downloads(q("package", good.Name+"-not", "ecosystem", eco.id))
		if err != nil {
			return "", err
		}
		if wild.Total != 2 || other.Total != 0 {
			return "", fmt.Errorf("wildcard filter found %d entries (want 2), a different name %d (want 0)", wild.Total, other.Total)
		}
		return fmt.Sprintf("%s was pulled by %s", good, strings.Join(want, " and ")), nil
	})

	c.run(checkBlocked, func() (string, error) {
		ok, out := s.installOn(eco, machineC, denied)
		if ok {
			return "", fmt.Errorf("%s INSTALLED %s although the dependency firewall denies it:\n%s", eco.inst.describe(), denied, tail(out, 25))
		}
		entries, err := s.proxy.awaitEntries(q("ip", machineC.addr), 1)
		if err != nil {
			return "", err
		}
		if len(entries) == 0 {
			return "", fmt.Errorf("the client failed but the log holds no entry for %s; client output:\n%s", machineC.addr, tail(out, 25))
		}
		for _, e := range entries {
			s.count(eco.id, dl.OutcomeBlocked)
			if e.Package != denied.Name || e.Version != denied.Version || e.Outcome != dl.OutcomeBlocked ||
				e.Gate != "depfirewall" || e.Code != "denied" || e.Status != http.StatusForbidden || e.Bytes != 0 || e.Reason == "" {
				return "", fmt.Errorf("the refused attempt is logged as %+v; want %s blocked by depfirewall (code denied, 403, no bytes, with a reason)", e, denied)
			}
		}
		served, err := s.proxy.downloads(q("package", denied.Name, "outcome", "served"))
		if err != nil {
			return "", err
		}
		if served.Total != 0 {
			return "", fmt.Errorf("the log shows %s as served: %s", denied, describe(served.Entries))
		}
		if n := s.stub.fetches(denied); n != 0 {
			return "", fmt.Errorf("the proxy fetched the denied %s from upstream %d times", denied, n)
		}
		e := entries[0]
		return fmt.Sprintf("%s from %s: blocked by %s (%s) — %s; %s failed", denied, e.ClientIP, e.Gate, e.Code, e.Reason, eco.inst.describe()), nil
	})

	c.run(checkWhatPulled, func() (string, error) {
		// One address: that machine's entries and nobody else's.
		for _, tc := range []struct {
			machine *egress
			pkg     pkg
			outcome dl.Outcome
		}{
			{machineA, good, dl.OutcomeServed},
			{machineB, good, dl.OutcomeServed},
			{machineC, denied, dl.OutcomeBlocked},
		} {
			page, err := s.proxy.downloads(q("ip", tc.machine.addr))
			if err != nil {
				return "", err
			}
			if page.Total == 0 {
				return "", fmt.Errorf("filtering by %s returns nothing", tc.machine.addr)
			}
			for _, e := range page.Entries {
				if e.ClientIP != tc.machine.addr || e.Package != tc.pkg.Name || e.Outcome != tc.outcome {
					return "", fmt.Errorf("filtering by %s returned %+v; want only %s (%s) from that address", tc.machine.addr, e, tc.pkg, tc.outcome)
				}
			}
		}
		// A CIDR: the ecosystem's three machines, and no machine of the other
		// ecosystem.
		page, err := s.proxy.downloads(q("ip", eco.cidr()))
		if err != nil {
			return "", err
		}
		want := []string{machineA.addr, machineB.addr, machineC.addr}
		if got := clientIPs(page.Entries); !sameSet(got, want) {
			return "", fmt.Errorf("filtering by %s lists %v, want %v", eco.cidr(), got, want)
		}
		blocked, err := s.proxy.downloads(q("ip", eco.cidr(), "outcome", "blocked"))
		if err != nil {
			return "", err
		}
		if got := clientIPs(blocked.Entries); !sameSet(got, []string{machineC.addr}) {
			return "", fmt.Errorf("filtering by %s and outcome=blocked lists %v, want only %s", eco.cidr(), got, machineC.addr)
		}
		// The summary of one address is what it pulled.
		sum, err := s.proxy.summary(q("ip", machineC.addr))
		if err != nil {
			return "", err
		}
		if sum.Served != 0 || sum.Blocked == 0 || len(sum.ByPackage) != 1 || sum.ByPackage[0].Package != denied.Name {
			return "", fmt.Errorf("the summary of %s is %+v; want only blocked attempts at %s", machineC.addr, sum.Summary, denied)
		}
		// An address nobody used has no entries.
		none, err := s.proxy.downloads(q("ip", eco.addr(200)))
		if err != nil {
			return "", err
		}
		if none.Total != 0 {
			return "", fmt.Errorf("filtering by the unused %s returns %d entries", eco.addr(200), none.Total)
		}
		return fmt.Sprintf("ip=%s, ip=%s and ip=%s each list one machine; ip=%s lists all three", machineA.addr, machineB.addr, machineC.addr, eco.cidr()), nil
	})

	c.run(checkForwarded, func() (string, error) {
		ok, out := s.installOn(eco, balancer, extra)
		if !ok {
			return "", fmt.Errorf("the machine behind the trusted proxy could not install %s:\n%s", extra, tail(out, 25))
		}
		entries, err := s.proxy.awaitEntries(q("ip", eco.forwardedClient), 1)
		if err != nil {
			return "", err
		}
		if len(entries) != 1 {
			return "", fmt.Errorf("the log holds %d entries for the forwarded client %s, want 1: %s", len(entries), eco.forwardedClient, describe(entries))
		}
		e := entries[0]
		s.count(eco.id, dl.OutcomeServed)
		if e.ClientIP != eco.forwardedClient || e.ForwardedBy != trustedProxyAddr || e.Package != extra.Name || e.Outcome != dl.OutcomeServed || e.Cache != "MISS" {
			return "", fmt.Errorf("the entry is %+v; want %s from %s, forwarded by %s", e, extra, eco.forwardedClient, trustedProxyAddr)
		}
		// The balancer is the transport peer, not the client: nothing is
		// attributed to its own address in this ecosystem.
		own, err := s.proxy.downloads(q("ip", trustedProxyAddr, "ecosystem", eco.id))
		if err != nil {
			return "", err
		}
		if own.Total != 0 {
			return "", fmt.Errorf("%d entries are attributed to the trusted proxy's own address %s: %s", own.Total, trustedProxyAddr, describe(own.Entries))
		}
		return fmt.Sprintf("%s from %s (X-Forwarded-For), forwarded by the trusted proxy %s", extra, e.ClientIP, e.ForwardedBy), nil
	})

	c.run(checkSpoofRejected, func() (string, error) {
		ok, out := s.installOn(eco, forger, extra)
		if !ok {
			return "", fmt.Errorf("the untrusted peer could not install %s:\n%s", extra, tail(out, 25))
		}
		entries, err := s.proxy.awaitEntries(q("ip", forger.addr), 1)
		if err != nil {
			return "", err
		}
		if len(entries) != 1 {
			return "", fmt.Errorf("the log holds %d entries for %s, want 1: %s", len(entries), forger.addr, describe(entries))
		}
		e := entries[0]
		s.count(eco.id, dl.OutcomeServed)
		if e.ClientIP != forger.addr || e.ForwardedBy != "" || e.Package != extra.Name || e.Outcome != dl.OutcomeServed {
			return "", fmt.Errorf("the entry is %+v; want %s attributed to the peer %s itself, with no forwarder", e, extra, forger.addr)
		}
		forged, err := s.proxy.downloads(q("ip", eco.forgedAddr))
		if err != nil {
			return "", err
		}
		if forged.Total != 0 {
			return "", fmt.Errorf("the forged address %s appears in the log: %s", eco.forgedAddr, describe(forged.Entries))
		}
		return fmt.Sprintf("a request from %s claiming X-Forwarded-For: %s is logged as %s", forger.addr, eco.forgedAddr, e.ClientIP), nil
	})
}

// describe renders entries compactly for failure messages.
func describe(entries []dl.Entry) string {
	if len(entries) == 0 {
		return "(no entries)"
	}
	var parts []string
	for _, e := range entries {
		parts = append(parts, fmt.Sprintf("#%d %s %s %s@%s %s %s %s", e.ID, e.ClientIP, e.Kind, e.Package, e.Version, e.Outcome, e.Method, e.Path))
	}
	return "\n  " + strings.Join(parts, "\n  ")
}

var metricLine = regexp.MustCompile(`(?m)^(pullthrough_downloadlog_[a-z_]+)(\{[^}]*\})? ([0-9.e+]+)$`)

// logMetrics returns the proxy's download-log metrics by "name{labels}".
func (s *suite) logMetrics() (map[string]float64, error) {
	resp, err := s.proxy.client.Get("http://" + s.proxy.listen + "/metrics")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	out := map[string]float64{}
	for _, m := range metricLine.FindAllStringSubmatch(buf.String(), -1) {
		v, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			continue
		}
		out[m[1]+m[2]] = v
	}
	return out, nil
}

func (s *suite) runCommon(t *testing.T, ecosystems []ecosystem) {
	c := &checker{t: t, report: s.report, scope: ""}

	// What the per-ecosystem checks put into the log.
	total := 0
	byOutcome := map[dl.Outcome]int{}
	for _, eco := range ecosystems {
		for outcome, n := range s.expected[eco.id] {
			total += n
			byOutcome[outcome] += n
		}
	}

	c.run(checkEcosystems, func() (string, error) {
		if total == 0 {
			return "", errors.New("the per-ecosystem checks recorded nothing to compare against")
		}
		all, err := s.proxy.downloads(nil)
		if err != nil {
			return "", err
		}
		if !all.Enabled || all.Total != total {
			return "", fmt.Errorf("the log holds %d entries (enabled: %v), want %d: %s", all.Total, all.Enabled, total, describe(all.Entries))
		}
		var parts []string
		for _, eco := range ecosystems {
			want := 0
			for _, n := range s.expected[eco.id] {
				want += n
			}
			page, err := s.proxy.downloads(q("ecosystem", eco.id))
			if err != nil {
				return "", err
			}
			if page.Total != want {
				return "", fmt.Errorf("ecosystem=%s lists %d entries, want %d", eco.id, page.Total, want)
			}
			for _, e := range page.Entries {
				if e.Ecosystem != eco.id || e.Upstream != eco.id {
					return "", fmt.Errorf("ecosystem=%s returned an entry of %s/%s: %+v", eco.id, e.Ecosystem, e.Upstream, e)
				}
			}
			parts = append(parts, fmt.Sprintf("%s: %d", eco.id, want))
		}
		sum, err := s.proxy.summary(nil)
		if err != nil {
			return "", err
		}
		if sum.Total != total || sum.Served != byOutcome[dl.OutcomeServed] || sum.Blocked != byOutcome[dl.OutcomeBlocked] || len(sum.ByEcosystem) != len(ecosystems) {
			return "", fmt.Errorf("the summary counts %d entries (%d served, %d blocked) in %d ecosystems; want %d (%d served, %d blocked) in %d",
				sum.Total, sum.Served, sum.Blocked, len(sum.ByEcosystem), total, byOutcome[dl.OutcomeServed], byOutcome[dl.OutcomeBlocked], len(ecosystems))
		}
		// The log is on without having been switched on, bounded, and persistent
		// because a path was configured.
		if all.Log.Capacity != dl.DefaultMaxEntries || all.Log.RetentionSeconds != int64(dl.DefaultRetention/time.Second) || !all.Log.Persistent || all.Log.Retained != total {
			return "", fmt.Errorf("the log reports its bounds as %+v", all.Log)
		}
		return fmt.Sprintf("%d entries (%s); %d served, %d blocked", total, strings.Join(parts, ", "), sum.Served, sum.Blocked), nil
	})

	c.run(checkCSV, func() (string, error) {
		status, header, body, err := s.proxy.adminGet("/admin/api/downloads?format=csv", adminToken)
		if err != nil {
			return "", err
		}
		if status != http.StatusOK || !strings.HasPrefix(header.Get("Content-Type"), "text/csv") {
			return "", fmt.Errorf("the CSV export answered %d %q", status, header.Get("Content-Type"))
		}
		rows, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
		if err != nil {
			return "", fmt.Errorf("the export is not valid CSV: %w", err)
		}
		if len(rows) != total+1 {
			return "", fmt.Errorf("the export has %d rows, want a header and %d entries", len(rows), total)
		}
		col := map[string]int{}
		for i, name := range rows[0] {
			col[name] = i
		}
		for _, name := range []string{"time", "client_ip", "forwarded_by", "ecosystem", "package", "version", "outcome", "gate"} {
			if _, ok := col[name]; !ok {
				return "", fmt.Errorf("the export has no %q column: %v", name, rows[0])
			}
		}
		// Every (address, package, outcome) the suite caused is a row.
		type key struct{ ip, pkg, outcome string }
		have := map[key]bool{}
		for _, row := range rows[1:] {
			have[key{row[col["client_ip"]], row[col["package"]], row[col["outcome"]]}] = true
		}
		for _, eco := range ecosystems {
			for _, want := range []key{
				{eco.addr(1), eco.pkgs[roleGood].Name, "served"},
				{eco.addr(2), eco.pkgs[roleGood].Name, "served"},
				{eco.addr(3), eco.pkgs[roleDenied].Name, "blocked"},
				{eco.forwardedClient, eco.pkgs[roleExtra].Name, "served"},
				{eco.addr(5), eco.pkgs[roleExtra].Name, "served"},
			} {
				if !have[want] {
					return "", fmt.Errorf("the export has no row for %s / %s / %s", want.ip, want.pkg, want.outcome)
				}
			}
		}
		return fmt.Sprintf("%d rows; every address, package and outcome of the run is in the export", len(rows)-1), nil
	})

	c.run(checkCredential, func() (string, error) {
		for _, path := range []string{"/admin/api/downloads", "/admin/api/downloads/summary", "/admin/api/downloads?format=csv"} {
			for _, token := range []string{"", "not-the-token"} {
				status, _, body, err := s.proxy.adminGet(path, token)
				if err != nil {
					return "", err
				}
				if status != http.StatusUnauthorized {
					return "", fmt.Errorf("GET %s with token %q answered %d, want 401", path, token, status)
				}
				if bytes.Contains(body, []byte("clientIp")) || bytes.Contains(body, []byte("127.0.")) {
					return "", fmt.Errorf("GET %s without the credential leaked log data: %s", path, firstLine(body))
				}
			}
		}
		// And a filter that cannot be applied is refused, not ignored.
		status, _, body, err := s.proxy.adminGet("/admin/api/downloads?ip=not-an-address", adminToken)
		if err != nil {
			return "", err
		}
		if status != http.StatusBadRequest {
			return "", fmt.Errorf("an unparseable ip filter answered %d (%s), want 400", status, firstLine(body))
		}
		return "the log is served to the admin token only (401 without it); an invalid filter is a 400", nil
	})

	c.run(checkMetrics, func() (string, error) {
		m, err := s.logMetrics()
		if err != nil {
			return "", err
		}
		for name, want := range map[string]float64{
			`pullthrough_downloadlog_entries_total{outcome="served"}`:  float64(byOutcome[dl.OutcomeServed]),
			`pullthrough_downloadlog_entries_total{outcome="blocked"}`: float64(byOutcome[dl.OutcomeBlocked]),
			`pullthrough_downloadlog_retained_entries`:                 float64(total),
			`pullthrough_downloadlog_capacity_entries`:                 float64(dl.DefaultMaxEntries),
			`pullthrough_downloadlog_persist_errors_total`:             0,
			`pullthrough_downloadlog_persist_lost_total`:               0,
		} {
			got, ok := m[name]
			if !ok || got != want {
				return "", fmt.Errorf("metric %s = %v (present: %v), want %v", name, got, ok, want)
			}
		}
		return fmt.Sprintf("pullthrough_downloadlog_entries_total: %d served, %d blocked; %d retained", byOutcome[dl.OutcomeServed], byOutcome[dl.OutcomeBlocked], total), nil
	})

	c.run(checkHermetic, func() (string, error) {
		requests := 0
		for _, eg := range s.egresses {
			if strays := eg.strayRequests(); len(strays) > 0 {
				return "", fmt.Errorf("machine %s asked for something other than the proxy: %v", eg.name, strays)
			}
			eg.mu.Lock()
			requests += eg.requests
			eg.mu.Unlock()
		}
		return fmt.Sprintf("%d client requests, every one of them to the proxy", requests), nil
	})

	c.run(checkRestart, func() (string, error) {
		before, err := s.proxy.downloads(nil)
		if err != nil {
			return "", err
		}
		s.proxy.stop()

		// The file the log is persisted to holds one line per entry and is
		// private: it names client addresses.
		path := filepath.Join(s.proxy.stateDir, "downloads.jsonl")
		info, err := os.Stat(path)
		if err != nil {
			return "", fmt.Errorf("the on-disk log: %w", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			return "", fmt.Errorf("the on-disk log has mode %o, want 600", perm)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if lines := bytes.Count(data, []byte("\n")); lines != before.Total {
			return "", fmt.Errorf("the on-disk log has %d lines, want %d", lines, before.Total)
		}

		restarted, err := startProxy(s.proxy.bin, s.proxy.stateDir, s.proxy.logPath, s.stub, s.proxy.listen)
		if err != nil {
			return "", fmt.Errorf("restarting the proxy: %w", err)
		}
		s.proxy = restarted
		after, err := s.proxy.downloads(nil)
		if err != nil {
			return "", err
		}
		if after.Total != before.Total || len(after.Entries) != len(before.Entries) {
			return "", fmt.Errorf("after the restart the log holds %d entries, want %d", after.Total, before.Total)
		}
		for i := range before.Entries {
			if !before.Entries[i].Time.Equal(after.Entries[i].Time) {
				return "", fmt.Errorf("entry %d changed its time across the restart", before.Entries[i].ID)
			}
			b, a := before.Entries[i], after.Entries[i]
			b.Time, a.Time = time.Time{}, time.Time{}
			if a != b {
				return "", fmt.Errorf("entry changed across the restart:\n  before %+v\n  after  %+v", b, a)
			}
		}

		// The log goes on where it stopped: a new machine's pull is the next
		// entry, and — the cache having survived too — a cache hit.
		eco := ecosystems[0]
		late := s.machine(eco.id+"-late", eco.addr(9), "")
		good := eco.pkgs[roleGood]
		if ok, out := s.installOn(eco, late, good); !ok {
			return "", fmt.Errorf("installing %s after the restart failed:\n%s", good, tail(out, 25))
		}
		entries, err := s.proxy.awaitEntries(q("ip", late.addr), 1)
		if err != nil {
			return "", err
		}
		if len(entries) != 1 {
			return "", fmt.Errorf("the log holds %d entries for %s after the restart, want 1", len(entries), late.addr)
		}
		e := entries[0]
		if want := before.Entries[0].ID + 1; e.ID != want || e.Cache != "HIT" || e.Package != good.Name {
			return "", fmt.Errorf("the first entry after the restart is %+v; want ID %d, %s, a cache hit", e, want, good)
		}
		return fmt.Sprintf("%d entries restored unchanged from %s (mode 600); recording continued with entry %d",
			before.Total, filepath.Base(path), e.ID), nil
	})
}
