package livescan

import (
	"encoding/base64"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCorpusLoadsAndBuilds(t *testing.T) {
	samples, err := Corpus()
	if err != nil {
		t.Fatal(err)
	}
	// Task 184 asked for research on at least five known infected packages.
	if len(samples) < 5 {
		t.Errorf("the corpus has %d samples; it must hold at least five known attacks", len(samples))
	}
	campaigns := map[string]int{}
	kinds := map[string]int{}
	for _, s := range samples {
		campaigns[s.Campaign]++
		kinds[s.Kind]++
		// Every variant builds into its artifact.
		for _, v := range []Variant{Benign, Malicious} {
			tree := s.Files(v)
			var art []byte
			switch s.Kind {
			case KindNPM:
				art = NPMTarball(tree)
			case KindWheel:
				art = Wheel(s.Name, s.VersionOf(v), tree)
			case KindSdist:
				art = Sdist(s.Name, s.VersionOf(v), tree)
			case KindOCIImage:
				art = BuildImage(tree, s.Image).Manifest
			case KindVSIX:
				art = VSIX(s.Extension.Publisher, s.Extension.Name, s.VersionOf(v), tree)
			case KindTarball:
				art = Tarball(s.Name, tree)
			case KindGitCommit:
				continue
			}
			if len(art) == 0 {
				t.Errorf("%s: the %s variant built into nothing", s.ID, v)
			}
		}
	}
	if campaigns["teampcp-trivy-2026"] == 0 {
		t.Error("the corpus has no sample of the TeamPCP campaign that began with Trivy")
	}
	t.Logf("%d samples, %d campaigns, kinds %v", len(samples), len(campaigns), kinds)
}

// Artifacts build the same bytes every time: a verdict stored by one run is
// recognizable in the next, and reports compare across runs.
func TestCorpusArtifactsAreDeterministic(t *testing.T) {
	samples, err := Corpus()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range samples {
		tree := s.Files(Malicious)
		if s.Kind == KindNPM && string(NPMTarball(tree)) != string(NPMTarball(tree)) {
			t.Errorf("%s: two builds of the npm tarball differ", s.ID)
		}
		if s.Kind == KindWheel && string(Wheel(s.Name, s.Version, tree)) != string(Wheel(s.Name, s.Version, tree)) {
			t.Errorf("%s: two builds of the wheel differ", s.ID)
		}
	}
}

// inertHosts may appear anywhere, malicious code included: namespaces and
// schema identifiers that nothing connects to.
var inertHosts = map[string]bool{
	"schemas.microsoft.com": true, "schemas.openxmlformats.org": true, "www.w3.org": true,
	"json-schema.org": true, "example.com": true, "www.example.com": true,
}

// legitHosts may appear in the shared and benign files: the legitimate code of
// the packages talks to them. In malicious code they are defanged like every
// other endpoint — an attacker abusing a real service (GitHub's API for an
// exfiltration repository, webhook.site, a registry to republish to) must not
// be reachable from a fixture either.
var legitHosts = map[string]bool{
	"github.com": true, "api.github.com": true, "raw.githubusercontent.com": true,
	"registry.npmjs.org": true, "www.npmjs.com": true, "pypi.org": true, "files.pythonhosted.org": true,
	"docs.ultralytics.com": true, "ultralytics.com": true, "docs.litellm.ai": true, "api.openai.com": true,
	"api.anthropic.com": true, "api.mainnet-beta.solana.com": true, "api.devnet.solana.com": true,
	"trivy.dev": true, "aquasecurity.github.io": true, "ghcr.io": true, "mirror.gcr.io": true,
	"nx.dev": true, "telnyx.com": true, "api.telnyx.com": true, "checkmarx.com": true,
	"code.visualstudio.com": true, "open-vsx.org": true,
}

// reservedSuffixes are names that can never resolve (RFC 2606 / RFC 6761).
var reservedSuffixes = []string{".invalid", ".example", ".test", ".localhost"}

// urlHostPattern finds the host of a URL: what follows a scheme (http,
// https, ws, …) up to the next slash, colon, quote or space. Only a real URL
// names a network endpoint; a method call like logger.info or subprocess.run
// is not one, so the check looks at URLs, not at every dotted token.
var urlHostPattern = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://([^/:"'\s\\<>)]+)`)

// ipPattern finds dotted quads.
var ipPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// testNets are the address blocks reserved for documentation (RFC 5737) and
// loopback: the only addresses a fixture may name.
var testNets = []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8", "0.0.0.0/32"}

// TestCorpusIsDefanged keeps every sample inert: every host a URL names, and
// every IP address, is either a reviewed, legitimate one or defanged beyond
// resolution (a reserved name, a documentation address). A sample that ran by
// accident — malicious code or not — could reach nothing. The malicious code of
// every attack has its real endpoints replaced; the surrounding legitimate code
// keeps the hosts the real library talks to, so the trees read naturally.
func TestCorpusIsDefanged(t *testing.T) {
	samples, err := Corpus()
	if err != nil {
		t.Fatal(err)
	}
	var nets []*net.IPNet
	for _, c := range testNets {
		_, n, _ := net.ParseCIDR(c)
		nets = append(nets, n)
	}
	for _, s := range samples {
		for _, section := range []struct {
			name  string
			files map[string][]byte
		}{{"shared", s.Shared}, {"benign", s.BenignOnly}, {"malicious", s.MaliciousOnly}} {
			for _, p := range Paths(section.files) {
				for _, text := range withDecodedBase64(string(section.files[p]), 3) {
					checkText(t, s, section.name, p, text, nets)
				}
			}
		}
	}
}

// checkText applies the defanging rules to one text: a URL host must be inert,
// legitimate or reserved; an IP address must sit in a documentation range.
func checkText(t *testing.T, s *Sample, section, p, text string, nets []*net.IPNet) {
	t.Helper()
	id := s.ID
	for _, m := range urlHostPattern.FindAllStringSubmatch(text, -1) {
		host := strings.ToLower(m[1])
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:] // strip userinfo
		}
		if ip := net.ParseIP(host); ip != nil {
			continue // an IP endpoint; the IP sweep below judges it
		}
		switch {
		case hasReservedSuffix(host), inertHosts[host]:
		case legitHosts[host] && section != "malicious":
			// The legitimate code of a package talks to the hosts of the real
			// library.
		case containsString(s.LegitimateHosts, host):
			// A malicious file that also holds the library's legitimate code
			// (a manifest, a client) may name the hosts its sample declares.
			// Every other host in a malicious file — a registry to republish
			// to, GitHub's API for an exfiltration repository, a model API —
			// must be unresolvable.
		default:
			t.Errorf("%s: %s/%s has a URL to the host %q: an attacker endpoint, and every endpoint in a malicious file, must be defanged (append \".invalid\"); a legitimate one in shared or benign code must be on legitHosts",
				id, section, p, host)
		}
	}
	for _, loc := range ipPattern.FindAllStringIndex(text, -1) {
		if loc[0] > 0 && (text[loc[0]-1] == '.' || isDigit(text[loc[0]-1])) {
			continue // part of a longer dotted version string
		}
		if loc[1] < len(text) && text[loc[1]] == '.' && loc[1]+1 < len(text) && isDigit(text[loc[1]+1]) {
			continue
		}
		ip := net.ParseIP(text[loc[0]:loc[1]])
		if ip == nil {
			continue // not an address (an octet over 255): a version
		}
		ok := false
		for _, n := range nets {
			if n.Contains(ip) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s: %s/%s names the address %s: use one from 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24", id, section, p, ip)
		}
	}
}

// base64Run finds runs that may be base64.
var base64Run = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)

// withDecodedBase64 returns text plus the text of every base64 run in it that
// decodes to readable text, recursively (payloads are often encoded twice): an
// endpoint hidden in an encoded blob must be defanged too.
func withDecodedBase64(text string, depth int) []string {
	out := []string{text}
	if depth == 0 {
		return out
	}
	for _, run := range base64Run.FindAllString(text, -1) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
			dec, err := enc.DecodeString(run)
			if err != nil || len(dec) < 16 || !utf8.Valid(dec) || !mostlyPrintable(dec) {
				continue
			}
			out = append(out, withDecodedBase64(string(dec), depth-1)...)
			break
		}
	}
	return out
}

func mostlyPrintable(b []byte) bool {
	printable := 0
	for _, c := range b {
		if c == '\n' || c == '\t' || c == '\r' || (c >= 0x20 && c < 0x7f) || c >= 0x80 {
			printable++
		}
	}
	return printable*10 >= len(b)*9
}

// readDoc reads the corpus's documentation page.
func readDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../../docs/llm-live-scan.md")
	if err != nil {
		t.Fatalf("reading the docs page: %v", err)
	}
	return string(b)
}

func hasReservedSuffix(host string) bool {
	for _, suf := range reservedSuffixes {
		if strings.HasSuffix(host, suf) {
			return true
		}
	}
	return false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// Every sample cites public analyses, and the docs page lists every sample.
func TestCorpusIsDocumented(t *testing.T) {
	samples, err := Corpus()
	if err != nil {
		t.Fatal(err)
	}
	doc := readDoc(t)
	var missing []string
	for _, s := range samples {
		if !strings.Contains(doc, "`"+s.ID+"`") {
			missing = append(missing, s.ID)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("docs/llm-live-scan.md does not list the samples %v (as `id`)", missing)
	}
}

// The fake model of the hermetic suite matches every sample's indicators against
// every piece of material, so an indicator that also occurs in another sample's
// control (its clean tree, its commit messages) would flag that control and
// point the red job at the wrong sample. validate() only checks a sample against
// its own benign tree.
func TestCorpusIndicatorsAreUnique(t *testing.T) {
	samples, err := Corpus()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range samples {
		for _, b := range samples {
			if a.ID == b.ID {
				continue
			}
			control := b.Files(Benign)
			var messages []string
			if b.Commit != nil {
				messages = []string{b.Commit.BaseMessage, b.Commit.BenignMessage, b.Commit.Author, b.Commit.Repository}
			}
			for _, ind := range a.Indicators {
				if treeContains(control, ind) {
					t.Errorf("indicator %q of %s occurs in the clean tree of %s: the hermetic model would flag %s's control", ind, a.ID, b.ID, b.ID)
				}
				for _, m := range messages {
					if strings.Contains(m, ind) {
						t.Errorf("indicator %q of %s occurs in %s's commit metadata %q", ind, a.ID, b.ID, m)
					}
				}
			}
		}
	}
}

// A commit sample's tree is committed into a repository: a .git component
// would reach git's own directory, and the repository name becomes a path.
func TestParseSampleRejectsWhatWouldEscapeTheWorkingTree(t *testing.T) {
	var base []byte
	all, err := corpusFS.ReadFile("testdata/corpus/trivy-action-teampcp.txtar")
	if err != nil {
		t.Fatal(err)
	}
	base = all
	if _, err := ParseSample(base); err != nil {
		t.Fatalf("the unmodified sample must parse: %v", err)
	}
	for name, mutate := range map[string]func(string) string{
		"a .git component": func(s string) string {
			return strings.Replace(s, "-- shared/action.yaml --", "-- shared/.git/hooks/pre-commit --\n#!/bin/sh\n-- shared/action.yaml --", 1)
		},
		"a .GIT component": func(s string) string {
			return strings.Replace(s, "-- shared/action.yaml --", "-- shared/sub/.GIT/config --\nx\n-- shared/action.yaml --", 1)
		},
		"a traversing repository name": func(s string) string {
			return strings.Replace(s, "  repository: aquasecurity/trivy-action", "  repository: ../../etc/x", 1)
		},
		"a repository name without an owner": func(s string) string {
			return strings.Replace(s, "  repository: aquasecurity/trivy-action", "  repository: trivy-action", 1)
		},
	} {
		mutated := mutate(string(base))
		if mutated == string(base) {
			t.Fatalf("%s: the mutation did not apply", name)
		}
		if _, err := ParseSample([]byte(mutated)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
