package ecotest

// These tests run on every `go test ./...`, without Docker or network access.
// They keep the real-client suite (build tag `ecosystem`) honest between its CI
// runs: the catalog covers every supported ecosystem, every client script exists
// and follows the environment contract, and the proxy configuration the harness
// renders is accepted by the real configuration loader.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/testset"
)

func TestCatalogIsValid(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
}

// upstreamAliases are the upstream types the configuration accepts as second
// names of another type.
var upstreamAliases = map[string]string{"deb": "apt", "rpm": "yum", "pub": "dart"}

// TestCatalogCoversEverySupportedEcosystem ties the real-client suite to the
// upstream types the proxy's configuration accepts: adding a backend without a
// real-client test fails here, on the default test run — as does a catalog
// entry for a type the proxy does not have.
func TestCatalogCoversEverySupportedEcosystem(t *testing.T) {
	have := map[string]bool{}
	for _, id := range IDs() {
		have[id] = true
	}
	want := map[string]bool{}
	for _, typ := range config.UpstreamTypes() {
		if canonical, ok := upstreamAliases[typ]; ok {
			typ = canonical
		}
		want[typ] = true
		if !have[typ] {
			t.Errorf("upstream type %q has no real-client test in the ecotest catalog", typ)
		}
	}
	for id := range have {
		if !want[id] {
			t.Errorf("ecotest catalog entry %q is not an upstream type the configuration accepts", id)
		}
		if e, _ := Lookup(id); e.Upstream.Type != id {
			t.Errorf("ecotest catalog entry %q tests an upstream of type %q", id, e.Upstream.Type)
		}
	}
	// The minimal real builds of internal/testset are a subset: every one of
	// them has a real-client test too.
	for _, id := range testset.Ecosystems() {
		if !have[id] {
			t.Errorf("testset ecosystem %q has no real-client test in the ecotest catalog", id)
		}
	}
}

func TestCatalogAccessors(t *testing.T) {
	ids := IDs()
	if len(ids) == 0 {
		t.Fatal("empty catalog")
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Fatalf("IDs() is not sorted/unique: %v", ids)
		}
	}
	cat := Catalog()
	if len(cat) != len(ids) {
		t.Fatalf("Catalog() has %d entries, IDs() %d", len(cat), len(ids))
	}
	for i, e := range cat {
		if e.ID != ids[i] {
			t.Fatalf("Catalog()[%d] = %q, want %q (sorted)", i, e.ID, ids[i])
		}
	}
	// Catalog returns a copy: mutating it must not affect later calls.
	cat[0].ID = "mutated"
	if Catalog()[0].ID == "mutated" {
		t.Error("Catalog() exposes the internal slice")
	}

	if _, ok := Lookup("npm"); !ok {
		t.Error("Lookup(npm) failed")
	}
	if _, ok := Lookup("no-such-ecosystem"); ok {
		t.Error("Lookup of an unknown ecosystem succeeded")
	}
}

// TestClientScriptsFollowTheContract checks each script against the contract in
// clients/README.md. A script that silently ignores a failing command, never
// uses the proxy, or never installs the requested package would make its
// ecosystem's test meaningless.
func TestClientScriptsFollowTheContract(t *testing.T) {
	// The proxy and the package are read either by the shell ($MOUNT, $PKG_NAME)
	// or by the client's own language (Sys.getenv("MOUNT"), ENV["PKG_NAME"]).
	usesProxy := regexp.MustCompile(`\b(MOUNT|PROXY_URL|PROXY_HOST)\b`)
	usesPackage := regexp.MustCompile(`\bPKG_[A-Z_]+\b`)
	for _, e := range Catalog() {
		t.Run(e.ID, func(t *testing.T) {
			raw, err := e.Script()
			if err != nil {
				t.Fatal(err)
			}
			script := string(raw)
			if !strings.HasPrefix(script, "#!/bin/sh\n") {
				t.Error("must start with a #!/bin/sh shebang (the client images only guarantee a POSIX shell)")
			}
			if !regexp.MustCompile(`(?m)^set -eu$`).MatchString(script) {
				t.Error("must `set -eu` so a failing command fails the install")
			}
			if !strings.Contains(script, "ECOTEST_CLIENT_VERSION=") {
				t.Error("must print ECOTEST_CLIENT_VERSION=<version>")
			}
			if !usesProxy.MatchString(script) {
				t.Error("never references $MOUNT / $PROXY_URL / $PROXY_HOST: it does not configure the client to use the proxy")
			}
			if !usesPackage.MatchString(script) {
				t.Error("never references $PKG_NAME (or another $PKG_* variable): it does not install the requested package")
			}
			// Every ecosystem-specific variable the catalog passes must be consumed.
			for _, pkg := range []*Package{&e.Good, e.Bad} {
				if pkg == nil {
					continue
				}
				for key := range pkg.Env {
					if !regexp.MustCompile(`\b` + regexp.QuoteMeta(key) + `\b`).MatchString(script) {
						t.Errorf("the catalog passes %s but the script never uses it", key)
					}
				}
			}
			if e.TLS && !strings.Contains(script, "PT_CA_CERT") {
				t.Error("the ecosystem is served over HTTPS but the script never trusts $PT_CA_CERT")
			}
			// The scripts are reproduced verbatim in the generated reference, which
			// the documentation site renders with Jekyll: Liquid would swallow a
			// Go-template or Liquid tag.
			for _, liquid := range []string{"{{", "{%"} {
				if strings.Contains(script, liquid) {
					t.Errorf("contains %q, which the documentation site's Liquid templating would mangle", liquid)
				}
			}
			// Bash-only constructs break under the dash/busybox shells of the images.
			for _, bashism := range []string{"[[", "<<<", "function ", "set -o pipefail", "&>"} {
				if strings.Contains(script, bashism) {
					t.Errorf("uses the bash-only construct %q", bashism)
				}
			}
		})
	}
}

// TestTransparentScriptsFollowTheContract holds the interception scripts
// (clients/transparent/) to their contract: the same shell rules as the
// explicit scripts, and — the point of them — no proxy address at all. The
// client keeps its own registry; what it is given is the interception CA (and,
// in interception mode, the proxy environment the harness exports).
func TestTransparentScriptsFollowTheContract(t *testing.T) {
	usesProxyAddress := regexp.MustCompile(`\$\{?(MOUNT|PROXY_URL|PROXY_HOST)\b|getenv\("(MOUNT|PROXY_URL|PROXY_HOST)"\)|ENV\["(MOUNT|PROXY_URL|PROXY_HOST)"\]`)
	usesPackage := regexp.MustCompile(`\bPKG_[A-Z_]+\b`)
	// Clients whose transfers are plain HTTP verified by the archive's own
	// signatures need no certificate to trust.
	plainHTTP := map[string]bool{"apt": true, "yum": true, "cpan": true}
	for _, e := range Catalog() {
		if !e.transparent() {
			continue
		}
		t.Run(e.ID, func(t *testing.T) {
			raw, err := e.TransparentScript()
			if err != nil {
				t.Fatal(err)
			}
			script := string(raw)
			if !strings.HasPrefix(script, "#!/bin/sh\n") {
				t.Error("must start with a #!/bin/sh shebang")
			}
			if !regexp.MustCompile(`(?m)^set -eu$`).MatchString(script) {
				t.Error("must `set -eu` so a failing command fails the install")
			}
			if !strings.Contains(script, "ECOTEST_CLIENT_VERSION=") {
				t.Error("must print ECOTEST_CLIENT_VERSION=<version>")
			}
			if m := usesProxyAddress.FindString(script); m != "" {
				t.Errorf("uses %s: an interception script has no proxy address — the client keeps its own registry", m)
			}
			if !usesPackage.MatchString(script) {
				t.Error("never references $PKG_NAME (or another $PKG_* variable)")
			}
			for _, pkg := range []*Package{&e.Good, e.Bad} {
				if pkg == nil {
					continue
				}
				for key := range pkg.Env {
					// PKG_UPSTREAM names a proxy upstream, for an explicit
					// reference: proxy knowledge an interception script has no
					// use for.
					if key == "PKG_UPSTREAM" {
						continue
					}
					if !regexp.MustCompile(`\b` + regexp.QuoteMeta(key) + `\b`).MatchString(script) {
						t.Errorf("the catalog passes %s but the script never uses it", key)
					}
				}
			}
			if !plainHTTP[e.ID] && !strings.Contains(script, "PT_CA_CERT") {
				t.Error("never trusts $PT_CA_CERT: the client cannot verify the certificates the proxy mints")
			}
			for _, liquid := range []string{"{{", "{%"} {
				if strings.Contains(script, liquid) {
					t.Errorf("contains %q, which the documentation site's Liquid templating would mangle", liquid)
				}
			}
			for _, bashism := range []string{"[[", "<<<", "function ", "set -o pipefail", "&>"} {
				if strings.Contains(script, bashism) {
					t.Errorf("uses the bash-only construct %q", bashism)
				}
			}
		})
	}
}

// renderFor renders the proxy configuration for an ecosystem with plausible
// run-time values.
func renderFor(t *testing.T, e Ecosystem, dir string) ([]byte, RunConfig) {
	t.Helper()
	rc := RunConfig{
		Ecosystem:       e,
		ListenAddr:      "127.0.0.1:18999",
		PublicURL:       "http://127.0.0.1:18999",
		StateDir:        dir,
		LLMProvider:     "claude",
		LLMBaseURL:      "http://127.0.0.1:18998",
		SourceRepo:      filepath.Join(dir, "source.git"),
		BenignCommit:    strings.Repeat("b", 40),
		MaliciousCommit: strings.Repeat("a", 40),
	}
	if e.TLS {
		rc.PublicURL = "https://localhost:18999"
		rc.TLSCertFile = filepath.Join(dir, "server.crt")
		rc.TLSKeyFile = filepath.Join(dir, "server.key")
	}
	out, err := RenderConfig(rc)
	if err != nil {
		t.Fatalf("RenderConfig(%s): %v", e.ID, err)
	}
	return out, rc
}

// TestRenderedConfigLoads runs every ecosystem's rendered proxy configuration
// through the real loader and validator, so a renamed or removed config key is
// caught on the default test run rather than only when the real-client suite
// starts a proxy in CI.
func TestRenderedConfigLoads(t *testing.T) {
	for _, e := range Catalog() {
		t.Run(e.ID, func(t *testing.T) {
			dir := t.TempDir()
			rendered, rc := renderFor(t, e, dir)
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, rendered, 0o644); err != nil {
				t.Fatal(err)
			}

			// Strict check first: unknown keys and validation warnings count.
			report, err := config.CheckFile(path)
			if err != nil {
				t.Fatalf("CheckFile: %v\n%s", err, rendered)
			}
			// Warnings count too: an unknown key is reported as one, and a typo in
			// a key the harness renders would silently disable what it configures.
			// One warning is expected and says what the suite does on purpose:
			// personal links without an identity provider, issued by the operator.
			var issues []config.Issue
			expected := 0
			for _, is := range report.Issues {
				if is.Path == "userLinks.oidc.enabled" && is.Severity == config.SeverityWarning {
					expected++
					continue
				}
				issues = append(issues, is)
			}
			if !report.OK || len(issues) > 0 {
				t.Fatalf("the rendered config has issues: %+v\n---\n%s", issues, rendered)
			}
			if expected != 1 {
				t.Errorf("the configuration check reported the operator-issued personal links %d times, want once", expected)
			}

			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load: %v\n%s", err, rendered)
			}
			if cfg.Server.HTTPAddr != rc.ListenAddr || cfg.Server.PublicURL != rc.PublicURL {
				t.Errorf("server = %q / %q, want %q / %q", cfg.Server.HTTPAddr, cfg.Server.PublicURL, rc.ListenAddr, rc.PublicURL)
			}
			up, ok := cfg.Upstreams[e.ID]
			if !ok || up.Type != e.Upstream.Type || up.URL != e.Upstream.URL {
				t.Errorf("upstream %q = %+v, want type %q url %q", e.ID, up, e.Upstream.Type, e.Upstream.URL)
			}
			for _, extra := range e.Extra {
				if _, ok := cfg.Upstreams[extra.Name]; !ok {
					t.Errorf("auxiliary upstream %q missing", extra.Name)
				}
			}
			if e.TLS != (cfg.Server.TLSCertFile != "") {
				t.Errorf("TLS = %v but tlsCertFile = %q", e.TLS, cfg.Server.TLSCertFile)
			}
			if cfg.Server.Registry.DefaultUpstream != e.RegistryDefault {
				t.Errorf("registry default upstream = %q, want %q", cfg.Server.Registry.DefaultUpstream, e.RegistryDefault)
			}
			if !cfg.Audit.Enabled || cfg.Audit.File != AuditLogPath(dir) {
				t.Errorf("audit = %+v, want enabled at %s", cfg.Audit, AuditLogPath(dir))
			}

			if e.Bad == nil {
				// No package coordinate to gate: a plain caching proxy.
				if cfg.Scanning.Enabled || cfg.Provenance.Enabled || cfg.Policy.Enabled {
					t.Errorf("an ecosystem without a bad package must not enable the admission chain")
				}
				return
			}

			// The full "gate pulls on the LLM scan of the source commit" chain.
			if !cfg.Scanning.Enabled || cfg.Scanning.Provider != "claude" || cfg.Scanning.BaseURL != rc.LLMBaseURL {
				t.Errorf("scanning = enabled:%v provider:%q baseUrl:%q", cfg.Scanning.Enabled, cfg.Scanning.Provider, cfg.Scanning.BaseURL)
			}
			w := cfg.Scanning.Watch
			if !w.Enabled || !w.Backfill || len(w.Repos) != 1 || w.Repos[0].URL != rc.SourceRepo {
				t.Errorf("commit watcher = %+v, want it watching %s with backfill", w, rc.SourceRepo)
			}
			if !cfg.Policy.Enabled || !cfg.Policy.FailClosed || !cfg.Policy.Default.BlockMalicious {
				t.Errorf("policy = %+v, want enabled, fail-closed, blockMalicious", cfg.Policy)
			}
			if cfg.Policy.Default.OnMissingProvenance != "allow" {
				t.Errorf("onMissingProvenance = %q, want allow (unpinned transitive dependencies must install)", cfg.Policy.Default.OnMissingProvenance)
			}

			if !cfg.Provenance.Enabled || len(cfg.Provenance.Pins) != 2 {
				t.Fatalf("provenance = enabled:%v pins:%d, want 2 pins", cfg.Provenance.Enabled, len(cfg.Provenance.Pins))
			}
			good, bad := cfg.Provenance.Pins[0], cfg.Provenance.Pins[1]
			if good.Name != e.Good.pinName() || good.Commit != rc.BenignCommit || good.Version != e.Good.CoordinateVersion {
				t.Errorf("good pin = %+v, want %s@%q -> benign commit", good, e.Good.pinName(), e.Good.CoordinateVersion)
			}
			if bad.Name != e.Bad.pinName() || bad.Commit != rc.MaliciousCommit || bad.Version != e.Bad.CoordinateVersion {
				t.Errorf("bad pin = %+v, want %s@%q -> malicious commit", bad, e.Bad.pinName(), e.Bad.CoordinateVersion)
			}
			for _, pin := range cfg.Provenance.Pins {
				if pin.Ecosystem != e.Upstream.Type {
					t.Errorf("pin %+v is not scoped to ecosystem %q", pin, e.Upstream.Type)
				}
			}
		})
	}
}

func TestRenderConfigIsDeterministic(t *testing.T) {
	e, _ := Lookup("npm")
	dir := t.TempDir()
	a, _ := renderFor(t, e, dir)
	for i := 0; i < 5; i++ {
		b, _ := renderFor(t, e, dir)
		if !bytes.Equal(a, b) {
			t.Fatalf("RenderConfig is not byte-stable:\n%s\n---\n%s", a, b)
		}
	}
}

func TestRenderConfigRejectsIncompleteInput(t *testing.T) {
	npm, _ := Lookup("npm")
	nuget, _ := Lookup("nuget")
	complete := func(e Ecosystem) RunConfig {
		return RunConfig{
			Ecosystem: e, ListenAddr: "127.0.0.1:1", PublicURL: "http://127.0.0.1:1", StateDir: "/tmp/x",
			LLMProvider: "claude", LLMBaseURL: "http://127.0.0.1:2", SourceRepo: "/tmp/x/source.git",
			BenignCommit: strings.Repeat("b", 40), MaliciousCommit: strings.Repeat("a", 40),
		}
	}
	cases := map[string]func() RunConfig{
		"no listen address": func() RunConfig { rc := complete(npm); rc.ListenAddr = ""; return rc },
		"no public url":     func() RunConfig { rc := complete(npm); rc.PublicURL = ""; return rc },
		"no state dir":      func() RunConfig { rc := complete(npm); rc.StateDir = ""; return rc },
		"no llm":            func() RunConfig { rc := complete(npm); rc.LLMBaseURL = ""; return rc },
		"no source repo":    func() RunConfig { rc := complete(npm); rc.SourceRepo = ""; return rc },
		"no commits":        func() RunConfig { rc := complete(npm); rc.MaliciousCommit = ""; return rc },
		"cert without key":  func() RunConfig { rc := complete(npm); rc.TLSCertFile = "/c"; return rc },
		"tls ecosystem without a certificate": func() RunConfig {
			return complete(nuget)
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := RenderConfig(mk()); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// --- mock LLM ---------------------------------------------------------------

// verdictOf extracts and decodes the verdict JSON the mock embedded in a
// provider response.
func verdictOf(t *testing.T, text string) (malicious bool, risk int) {
	t.Helper()
	var v struct {
		RiskScore int  `json:"riskScore"`
		Malicious bool `json:"malicious"`
		Findings  []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		t.Fatalf("the mock's verdict is not valid JSON: %v (%q)", err, text)
	}
	if v.Malicious && len(v.Findings) == 0 {
		t.Error("a malicious verdict must carry a finding")
	}
	return v.Malicious, v.RiskScore
}

func postJSON(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestMockLLMAnthropic(t *testing.T) {
	m := &MockLLM{models: map[string]int{}}
	h := m.Handler()

	decode := func(rr *httptest.ResponseRecorder) (string, string) {
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
		}
		var resp struct {
			Type    string `json:"type"`
			Role    string `json:"role"`
			Model   string `json:"model"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			StopReason string `json:"stop_reason"`
			Usage      struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("not an Anthropic message: %v", err)
		}
		if resp.Type != "message" || resp.Role != "assistant" || resp.StopReason != "end_turn" ||
			len(resp.Content) != 1 || resp.Content[0].Type != "text" || resp.Usage.InputTokens == 0 {
			t.Fatalf("malformed Anthropic message: %+v", resp)
		}
		return resp.Content[0].Text, resp.Model
	}

	// Content as an array of blocks plus a system prompt (what the SDK sends).
	benign := `{"model":"claude-test","max_tokens":10,"system":[{"type":"text","text":"You are a reviewer."}],` +
		`"messages":[{"role":"user","content":[{"type":"text","text":"diff --git a/README.md"}]}]}`
	text, model := decode(postJSON(t, h, "/v1/messages", benign))
	if mal, risk := verdictOf(t, text); mal || risk >= 50 {
		t.Errorf("benign prompt -> malicious=%v risk=%d", mal, risk)
	}
	if model != "claude-test" {
		t.Errorf("model echoed as %q", model)
	}

	// Content as a plain string, carrying the marker.
	bad := `{"model":"claude-test","messages":[{"role":"user","content":"+// ` + MaliciousMarker + `"}]}`
	text, _ = decode(postJSON(t, h, "/v1/messages", bad))
	if mal, risk := verdictOf(t, text); !mal || risk < 80 {
		t.Errorf("prompt with the marker -> malicious=%v risk=%d", mal, risk)
	}

	// The marker in the system prompt counts too: the whole prompt is judged.
	sys := `{"model":"claude-deep","system":"` + MaliciousMarker + `","messages":[{"role":"user","content":"x"}]}`
	text, _ = decode(postJSON(t, h, "/v1/messages", sys))
	if mal, _ := verdictOf(t, text); !mal {
		t.Error("marker in the system prompt was ignored")
	}

	stats := m.Stats()
	if stats.Calls != 3 || stats.Malicious != 2 || stats.Models["claude-test"] != 2 || stats.Models["claude-deep"] != 1 {
		t.Errorf("stats = %+v", stats)
	}

	if rr := postJSON(t, h, "/v1/messages", "{not json"); rr.Code != http.StatusBadRequest {
		t.Errorf("malformed body: status %d, want 400", rr.Code)
	}
	get := httptest.NewRecorder()
	h.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/v1/messages", nil))
	if get.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status %d, want 405", get.Code)
	}
	if m.Stats().Calls != 3 {
		t.Error("rejected requests must not count as completions")
	}
}

func TestMockLLMOpenAI(t *testing.T) {
	m := &MockLLM{models: map[string]int{}}
	h := m.Handler()

	decode := func(rr *httptest.ResponseRecorder) string {
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
		}
		var resp struct {
			Object  string `json:"object"`
			Choices []struct {
				Message struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage struct {
				TotalTokens int `json:"total_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("not a chat completion: %v", err)
		}
		if resp.Object != "chat.completion" || len(resp.Choices) != 1 ||
			resp.Choices[0].Message.Role != "assistant" || resp.Choices[0].FinishReason != "stop" || resp.Usage.TotalTokens == 0 {
			t.Fatalf("malformed chat completion: %+v", resp)
		}
		return resp.Choices[0].Message.Content
	}

	// Both the bare and the /v1-prefixed path are served.
	for _, path := range []string{"/chat/completions", "/v1/chat/completions"} {
		benign := `{"model":"gpt-test","messages":[{"role":"system","content":"review"},{"role":"user","content":"a tidy diff"}]}`
		if mal, _ := verdictOf(t, decode(postJSON(t, h, path, benign))); mal {
			t.Errorf("%s: benign prompt judged malicious", path)
		}
		bad := `{"model":"gpt-test","messages":[{"role":"user","content":"` + MaliciousMarker + `"}]}`
		if mal, _ := verdictOf(t, decode(postJSON(t, h, path, bad))); !mal {
			t.Errorf("%s: prompt with the marker judged benign", path)
		}
	}
	if stats := m.Stats(); stats.Calls != 4 || stats.Malicious != 2 {
		t.Errorf("stats = %+v", stats)
	}
	if rr := postJSON(t, h, "/chat/completions", "nope"); rr.Code != http.StatusBadRequest {
		t.Errorf("malformed body: status %d, want 400", rr.Code)
	}
}

func TestMockLLMServesOverTCP(t *testing.T) {
	m, err := StartMockLLM()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if !strings.HasPrefix(m.URL(), "http://127.0.0.1:") || m.OpenAIURL() != m.URL()+"/v1" {
		t.Fatalf("URL = %q, OpenAIURL = %q", m.URL(), m.OpenAIURL())
	}

	resp, err := http.Post(m.URL()+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}

	statsResp, err := http.Get(m.URL() + "/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer statsResp.Body.Close()
	var stats MockLLMStats
	if err := json.NewDecoder(statsResp.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	if stats.Calls != 1 || stats.Malicious != 0 {
		t.Errorf("/stats = %+v, want one benign call", stats)
	}
}

func TestTextOf(t *testing.T) {
	cases := map[string]string{
		`"plain"`: "plain",
		`[{"type":"text","text":"a"},{"type":"text","text":"b"}]`: "a\nb\n",
		``:                       "",
		`42`:                     "",
		`{"unexpected":"shape"}`: "",
	}
	for in, want := range cases {
		if got := textOf(json.RawMessage(in)); got != want {
			t.Errorf("textOf(%s) = %q, want %q", in, got, want)
		}
	}
}

// The personal-link check (Task 177) runs for every ecosystem whose client can
// carry a link in the address it is configured with. An ecosystem that opts
// out must say why — the reason is published in the reference — and the check
// is then "not applicable", not silently absent.
func TestPersonalLinkAppliesUnlessTheCatalogSaysWhyNot(t *testing.T) {
	asserted := 0
	for _, e := range Catalog() {
		res := NewResult(e)
		switch got := res.Status(CheckPersonalLink); {
		case e.NoPersonalLink == "" && got != StatusSkipped:
			t.Errorf("%s: initial status of %s = %q, want skipped (it applies and has not run)", e.ID, CheckPersonalLink, got)
		case e.NoPersonalLink != "" && got != StatusNA:
			t.Errorf("%s: the catalog opts out of %s but its status is %q, want n/a", e.ID, CheckPersonalLink, got)
		case e.NoPersonalLink != "" && len(e.NoPersonalLink) < 40:
			t.Errorf("%s: NoPersonalLink %q does not explain much", e.ID, e.NoPersonalLink)
		}
		if e.NoPersonalLink == "" {
			asserted++
		}
	}
	if asserted < len(Catalog())-2 {
		t.Errorf("only %d of %d ecosystems assert personal links", asserted, len(Catalog()))
	}
	// The rendered configuration serves the personal prefix and lets the
	// operator issue links: both are what the check needs.
	npm, _ := Lookup("npm")
	out, _ := renderFor(t, npm, t.TempDir())
	for _, want := range []string{"userLinks:", "enabled: true", "adminToken: " + AdminToken} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the rendered configuration lacks %q:\n%s", want, out)
		}
	}
}

// --- report -----------------------------------------------------------------

func TestResultLifecycle(t *testing.T) {
	npm, _ := Lookup("npm")
	git, _ := Lookup("git")

	r := NewResult(npm)
	if r.GoodPackage != "is-number@7.0.0" || r.BadPackage == "" {
		t.Errorf("packages = %q / %q", r.GoodPackage, r.BadPackage)
	}
	for _, name := range checkOrder {
		want := StatusSkipped
		if name == CheckDownloadLog {
			want = StatusNA // npm does not opt into the download-log assertion
		}
		if got := r.Status(name); got != want {
			t.Errorf("npm: initial status of %s = %q, want %s", name, got, want)
		}
	}
	r.Finalize()
	if r.Passed {
		t.Error("a result with unreached checks must not pass")
	}
	for _, name := range checkOrder {
		r.Set(name, StatusPass, "ok")
	}
	r.Finalize()
	if !r.Passed {
		t.Error("all checks passed but the result did not")
	}
	r.Set(CheckBlock, StatusFail, "client installed the bad package")
	r.Finalize()
	if r.Passed {
		t.Error("a failed check must fail the result")
	}
	r.Set(CheckBlock, StatusPass, "ok")
	r.Error = "setup: boom"
	r.Finalize()
	if r.Passed {
		t.Error("a recorded error must fail the result")
	}

	// Git has no package coordinate and (pass-through) nothing cacheable.
	g := NewResult(git)
	for _, name := range []string{CheckCached, CheckScanAdmit, CheckCacheHit, CheckBlock, CheckDownloadLog} {
		if got := g.Status(name); got != StatusNA {
			t.Errorf("git: status of %s = %q, want n/a", name, got)
		}
	}

	// The ecosystems the download log is asserted with: every check applies.
	for _, id := range []string{"cargo", "go"} {
		e, ok := Lookup(id)
		if !ok || !e.DownloadLog {
			t.Fatalf("%s must assert the download log", id)
		}
		res := NewResult(e)
		if got := res.Status(CheckDownloadLog); got != StatusSkipped {
			t.Errorf("%s: initial status of %s = %q, want skipped (it applies and has not run)", id, CheckDownloadLog, got)
		}
		for _, name := range checkOrder {
			if name != CheckDownloadLog {
				res.Set(name, StatusPass, "ok")
			}
		}
		res.Finalize()
		if res.Passed {
			t.Errorf("%s: the result passed although the download-log check never ran", id)
		}
	}
	// What does apply to Git — the clone, and the clone through a personal
	// link — decides.
	g.Set(CheckInstall, StatusPass, "cloned")
	g.Finalize()
	if g.Passed {
		t.Error("git: the result passed although the personal-link check never ran")
	}
	g.Set(CheckPersonalLink, StatusPass, "cloned through a personal link")
	g.Finalize()
	if g.Passed {
		t.Error("git: the result passed although the interception legs never ran")
	}
	g.Set(CheckIntercept, StatusPass, "cloned through the forward proxy")
	g.Set(CheckNAT, StatusPass, "cloned through NAT")
	g.Finalize()
	if !g.Passed {
		t.Error("git: n/a checks must not prevent a pass")
	}
	if g.BadPackage != "" {
		t.Errorf("git: BadPackage = %q, want empty", g.BadPackage)
	}

	// Set on an unknown check appends rather than dropping the information.
	g.Set("extra", StatusPass, "x")
	if g.Status("extra") != StatusPass || g.Status("missing") != "" {
		t.Error("Set/Status on unknown checks misbehaves")
	}
}

func TestMatrixRoundTrip(t *testing.T) {
	dir := t.TempDir()
	npm, _ := Lookup("npm")
	pip, _ := Lookup("pip")

	ok := NewResult(npm)
	ok.ClientVersion = "10.9.9"
	for _, name := range checkOrder {
		ok.Set(name, StatusPass, "ok")
	}
	ok.Finalize()
	if _, err := ok.WriteFile(dir); err != nil {
		t.Fatal(err)
	}

	// The second result lives one directory down, the way CI lays out the
	// per-job artifacts it downloads.
	bad := NewResult(pip)
	bad.Set(CheckInstall, StatusPass, "ok")
	bad.Set(CheckCached, StatusFail, "no cache entry | with a pipe\nand a newline")
	bad.Finalize()
	if _, err := bad.WriteFile(filepath.Join(dir, "ecosystem-result-pip")); err != nil {
		t.Fatal(err)
	}
	// Unrelated JSON in the directory must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "unrelated.json"), []byte(`{"hello":"world"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := LoadResults(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Ecosystem != "npm" || results[1].Ecosystem != "pip" {
		t.Fatalf("LoadResults = %+v", results)
	}

	m := BuildMatrix(results, []string{"npm", "pip", "cargo"})
	if m.Passed {
		t.Error("a matrix with a failing and a missing ecosystem must not pass")
	}
	if len(m.Missing) != 1 || m.Missing[0] != "cargo" {
		t.Errorf("Missing = %v, want [cargo]", m.Missing)
	}

	md := m.Markdown()
	for _, want := range []string{
		"❌ failing", "1/3 ecosystems passed", "no result for: cargo",
		"| npm | npm 10.9.9 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |",
		// pip does not assert the download log: that column is "not applicable".
		// The personal-link check and the interception legs come last and were
		// not reached.
		"| pip | pip | ✅ | ❌ | ⏭ | ⏭ | ⏭ | ➖ | ⏭ | ⏭ | ⏭ | ❌ |",
		"| cargo | — |",
		"### Failures",
		`no cache entry \| with a pipe and a newline`,
	} {
		if !strings.Contains(md, want) {
			t.Errorf("matrix Markdown lacks %q:\n%s", want, md)
		}
	}

	path, err := WriteMatrix(m, dir)
	if err != nil {
		t.Fatal(err)
	}
	if written, _ := os.ReadFile(path); string(written) != md {
		t.Error("WriteMatrix wrote different Markdown than Markdown() returns")
	}
	// The rendered matrix JSON sits next to the result files; reloading must not
	// mistake it for a result.
	again, err := LoadResults(dir)
	if err != nil || len(again) != 2 {
		t.Fatalf("LoadResults after WriteMatrix = %d results, %v", len(again), err)
	}

	// All present and passing -> the matrix passes.
	bad.Set(CheckCached, StatusPass, "ok")
	for _, name := range checkOrder {
		bad.Set(name, StatusPass, "ok")
	}
	bad.Finalize()
	if all := BuildMatrix([]*Result{ok, bad}, []string{"npm", "pip"}); !all.Passed || !strings.Contains(all.Markdown(), "✅ all passed") {
		t.Errorf("an all-green matrix did not pass:\n%s", all.Markdown())
	}
	// No results at all is a failure, not a vacuous pass.
	if empty := BuildMatrix(nil, nil); empty.Passed {
		t.Error("an empty matrix must not pass")
	}
}

// --- generated reference ------------------------------------------------------

func TestGenerateReference(t *testing.T) {
	ref := GenerateReference()

	// Deterministic: the staleness check in CI compares bytes.
	for i := 0; i < 3; i++ {
		if again := GenerateReference(); again != ref {
			t.Fatal("GenerateReference is not deterministic")
		}
	}
	if !strings.HasPrefix(ref, "# Ecosystem test reference (generated)\n") {
		t.Errorf("unexpected header: %q", ref[:60])
	}
	if !strings.Contains(ref, "GENERATED FILE — DO NOT EDIT") || !strings.Contains(ref, "make ecosystem-reference-gen") {
		t.Error("the reference must say it is generated and how to regenerate it")
	}

	for _, e := range Catalog() {
		// One overview row and one section per ecosystem.
		if !strings.Contains(ref, "| ["+e.ID+"](#"+e.ID+") |") {
			t.Errorf("%s: missing overview row", e.ID)
		}
		if !strings.Contains(ref, "\n## "+e.ID+"\n") {
			t.Errorf("%s: missing section", e.ID)
		}
		// The section carries the client script verbatim — that is the point.
		script, err := e.Script()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(ref, strings.TrimRight(string(script), "\n")) {
			t.Errorf("%s: the client script is not reproduced verbatim", e.ID)
		}
		if !strings.Contains(ref, e.Image) || !strings.Contains(ref, e.Upstream.URL) {
			t.Errorf("%s: image or upstream URL missing", e.ID)
		}
		// The packages are pinned only where the run gates them: with no package
		// to refuse (git, generic) the proxy runs no admission chain.
		if e.Bad != nil {
			if !strings.Contains(ref, pinLabel(e.Upstream.Type, e.Good)) {
				t.Errorf("%s: the good package's pin is missing", e.ID)
			}
			if !strings.Contains(ref, pinLabel(e.Upstream.Type, *e.Bad)) {
				t.Errorf("%s: the bad package's pin is missing", e.ID)
			}
		} else if strings.Contains(ref, pinLabel(e.Upstream.Type, e.Good)) {
			t.Errorf("%s: the reference shows a pin, but the run configures none", e.ID)
		}
		// Configuration beyond type and URL is part of what makes the client
		// work: a generic upstream's routes are shown.
		if routes, ok := e.Upstream.Config["generic"].(map[string]any); ok {
			for _, r := range routes["routes"].([]any) {
				if match := r.(map[string]any)["match"].(string); !strings.Contains(ref, match) {
					t.Errorf("%s: the route %s is not shown", e.ID, match)
				}
			}
		}
	}

	if strings.Contains(ref, "{{") || strings.Contains(ref, "{%") {
		t.Error("the reference contains a Liquid tag opener; the Jekyll-built documentation site would mangle it")
	}

	// Ecosystem-specific facts a reader needs.
	for _, want := range []string{
		"HTTPS with a test CA",                           // nuget
		"server.registry.defaultUpstream: docker",        // docker
		"Docker-in-Docker daemon whose registry mirror",  // docker
		"no package coordinate for the admission policy", // git
		"setting `trustedPublicKeys:",                    // nix
		"for the client's own tooling",                   // conan / ansible / openvsx / puppet
	} {
		if !strings.Contains(ref, want) {
			t.Errorf("reference lacks %q", want)
		}
	}
}

func TestPinLabel(t *testing.T) {
	if got, want := pinLabel("npm", Package{Name: "is-number", CoordinateVersion: "7.0.0"}),
		"`{ecosystem: npm, name: is-number, version: 7.0.0}`"; got != want {
		t.Errorf("pinLabel = %s, want %s", got, want)
	}
	// The coordinate, not the client-facing name, is what gets pinned; without a
	// coordinate version the pin covers every version.
	if got, want := pinLabel("cpan", Package{Name: "Try::Tiny", Coordinate: "Try-Tiny"}),
		"`{ecosystem: cpan, name: Try-Tiny}`"; got != want {
		t.Errorf("pinLabel = %s, want %s", got, want)
	}
}
