package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// --- pure helpers -----------------------------------------------------------

func TestSplitCoordinate(t *testing.T) {
	cases := []struct {
		in, name, ver string
	}{
		{"lodash@4.17.21", "lodash", "4.17.21"},
		{"lodash", "lodash", ""},
		{"@scope/pkg", "@scope/pkg", ""},
		{"@scope/pkg@1.2.3", "@scope/pkg", "1.2.3"},
		{"group:artifact@1.0", "group:artifact", "1.0"},
	}
	for _, c := range cases {
		n, v := splitCoordinate(c.in)
		if n != c.name || v != c.ver {
			t.Errorf("splitCoordinate(%q) = (%q,%q), want (%q,%q)", c.in, n, v, c.name, c.ver)
		}
	}
}

func TestWithUserinfo(t *testing.T) {
	got := withUserinfo("https://proxy.example.com/v1/npm", "abc/123")
	want := "https://abc%2F123@proxy.example.com/v1/npm"
	if got != want {
		t.Errorf("withUserinfo = %q, want %q", got, want)
	}
	if withUserinfo("https://x/y", "") != "https://x/y" {
		t.Error("empty token should not alter the URL")
	}
}

func TestParseBackendSpecs(t *testing.T) {
	bs, err := parseBackendSpecs([]string{"npm=npm", "central=maven"})
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != 2 || bs[0].Name != "central" || bs[1].Type != "npm" {
		t.Errorf("unexpected specs: %+v", bs)
	}
	if _, err := parseBackendSpecs([]string{"bad"}); err == nil {
		t.Error("expected error for spec without =type")
	}
}

func TestFilterBackends(t *testing.T) {
	in := []backend{{Name: "npm", Type: "npm"}, {Name: "central", Type: "maven"}, {Name: "pypi", Type: "pip"}}
	if got := filterBackends(in, ""); len(got) != 3 {
		t.Errorf("empty selector should keep all, got %d", len(got))
	}
	if got := filterBackends(in, "maven,npm"); len(got) != 2 {
		t.Errorf("by type, got %d", len(got))
	}
	if got := filterBackends(in, "pypi"); len(got) != 1 || got[0].Type != "pip" {
		t.Errorf("by name, got %+v", got)
	}
}

func TestSanitizeFilename(t *testing.T) {
	if got := sanitizeFilename("npm — npm (.npmrc)"); strings.Contains(got, " ") || strings.Contains(got, "--") {
		t.Errorf("sanitizeFilename left spaces/double-dashes: %q", got)
	}
}

// --- snippet generation -----------------------------------------------------

func ctxFor(token string) snippetContext {
	return snippetContext{proxyBase: "https://proxy.example.com", host: "proxy.example.com", tenant: "acme", token: token}
}

func TestSnippetsMountAndToken(t *testing.T) {
	ctx := ctxFor("secret-tok")
	cases := []struct {
		typ        string
		mustHave   []string
		mustHaveTk bool
	}{
		{"npm", []string{"registry=https://proxy.example.com/v1/x/", "_authToken=secret-tok"}, true},
		{"pip", []string{"index-url = https://secret-tok@proxy.example.com/v1/x/simple/"}, true},
		// cargo cannot present a proxy token for crate downloads (docs/clients/cargo.md).
		{"cargo", []string{"sparse+https://proxy.example.com/v1/x/", "auth.anonymousRoles"}, false},
		{"go", []string{"go env -w GOPROXY=https://proxy.example.com/v1/x\n", "password secret-tok"}, true},
		// NuGet sends source credentials only in answer to a Basic challenge, which
		// the proxy does not send (docs/clients/nuget.md).
		{"nuget", []string{"/v1/x/v3/index.json", "<clear />", "auth.anonymousRoles"}, false},
		// Maven sends the token as a header configured on the mirror's <server>.
		{"maven", []string{"<url>https://proxy.example.com/v1/x</url>", "<value>Bearer secret-tok</value>"}, true},
		{"docker", []string{"docker login proxy.example.com", "secret-tok",
			// Explicit reference: the upstream is the repository's first component.
			"docker pull proxy.example.com/x/library/alpine:latest",
			// The Docker Engine rejects a mirror URL with a path: bare proxy URL only.
			`"registry-mirrors": ["https://proxy.example.com"]`}, true},
		{"helm", []string{"helm repo add pullthrough https://proxy.example.com/v1/x", "secret-tok"}, true},
		{"terraform", []string{
			// A host block serves the public registry from the proxy, so .tf
			// source addresses stay unchanged.
			`host "registry.terraform.io"`,
			`"providers.v1" = "https://proxy.example.com/v1/x/v1/providers/"`,
			`"modules.v1"   = "https://proxy.example.com/v1/x/v1/modules/"`,
			`credentials "registry.terraform.io"`, "secret-tok"}, true},
		// Conan cannot present a proxy token (see TestConanSnippetCarriesNoToken).
		{"conan", []string{"conan remote add x https://proxy.example.com/v1/x", "auth.anonymousRoles"}, false},
	}
	for _, c := range cases {
		t.Run(c.typ, func(t *testing.T) {
			snips := snippetsFor(ctx, backend{Name: "x", Type: c.typ})
			if len(snips) == 0 {
				t.Fatalf("no snippets for %s", c.typ)
			}
			blob := snips[0].Body + strings.Join(snips[0].Notes, "\n")
			for _, want := range c.mustHave {
				if !strings.Contains(blob, want) {
					t.Errorf("%s snippet missing %q\n--- body ---\n%s", c.typ, want, blob)
				}
			}
			// A client that cannot send a token must not be handed one in a file.
			if got := strings.Contains(blob, "secret-tok"); got != c.mustHaveTk {
				t.Errorf("%s snippet carries the token: %v, want %v\n--- body ---\n%s", c.typ, got, c.mustHaveTk, blob)
			}
		})
	}
}

// TestConanSnippetCarriesNoToken pins that the Conan snippet never suggests
// `conan remote login` and never embeds the caller's token. A Conan client gets
// the token it presents from the remote's login endpoint, which the proxy
// refuses (forwarding it would hand out a session for the proxy's upstream
// account), so a token in the snippet could not work and would only be exposed.
func TestConanSnippetCarriesNoToken(t *testing.T) {
	for _, token := range []string{"secret-tok", ""} {
		snips := snippetsFor(ctxFor(token), backend{Name: "x", Type: "conan"})
		if len(snips) != 1 {
			t.Fatalf("conan snippets = %d, want 1", len(snips))
		}
		blob := snips[0].Body + strings.Join(snips[0].Notes, "\n")
		if strings.Contains(snips[0].Body, "remote login") {
			t.Errorf("conan snippet suggests a login the proxy refuses:\n%s", snips[0].Body)
		}
		for _, leaked := range []string{"secret-tok", "${PULLTHROUGH_TOKEN}"} {
			if strings.Contains(blob, leaked) {
				t.Errorf("conan snippet (token=%q) contains %q:\n%s", token, leaked, blob)
			}
		}
	}
}

func TestSnippetsPlaceholderWithoutToken(t *testing.T) {
	snips := snippetsFor(ctxFor(""), backend{Name: "npm", Type: "npm"})
	if !strings.Contains(snips[0].Body, "${PULLTHROUGH_TOKEN}") {
		t.Errorf("expected token placeholder, got:\n%s", snips[0].Body)
	}
}

func TestSnippetsUnknownType(t *testing.T) {
	snips := snippetsFor(ctxFor(""), backend{Name: "weird", Type: "quux"})
	if len(snips) != 1 || len(snips[0].Notes) == 0 {
		t.Fatalf("unknown type should yield an advisory snippet, got %+v", snips)
	}
	if !strings.Contains(snips[0].Notes[0], "/v1/weird") {
		t.Errorf("advisory should mention the mount, got %q", snips[0].Notes[0])
	}
}

// --- client URL handling ----------------------------------------------------

func TestNewClientURLNormalization(t *testing.T) {
	c, err := newClient(globalFlags{url: "proxy.example.com", adminPrefix: "admin/"})
	if err != nil {
		t.Fatal(err)
	}
	if c.baseURL != "https://proxy.example.com" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
	if c.adminPrefix != "/admin" {
		t.Errorf("adminPrefix = %q", c.adminPrefix)
	}
	if got := c.adminURL("api/overview", map[string]string{"tenant": "", "package": "p"}); !strings.HasSuffix(got, "/admin/api/overview?package=p") {
		t.Errorf("adminURL = %q", got)
	}
	if _, err := newClient(globalFlags{url: ""}); err == nil {
		t.Error("expected error for empty URL")
	}
	if _, err := newClient(globalFlags{url: "ftp://x"}); err == nil {
		t.Error("expected error for non-http scheme")
	}
}

// --- end-to-end against a fake proxy ----------------------------------------

// fakeProxy serves the handful of endpoints ptctl uses.
func fakeProxy(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/admin/api/overview", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"info": map[string]any{
				"version": "test",
				"upstreams": []map[string]string{
					{"name": "npm", "type": "npm", "url": "https://registry.npmjs.org"},
					{"name": "central", "type": "maven", "url": "https://repo1.maven.org/maven2"},
				},
			},
			"backends": []string{"npm", "central"},
		})
	})
	mux.HandleFunc("/v1/npm/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/v1/central/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })

	in := policyengine.Input{
		Artifact: policyengine.ArtifactInput{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", Digest: "sha256:abc"},
		Tenant:   "acme",
		Vuln:     &policyengine.VulnInput{Scanned: true, Scanner: "osv", MaxSeverity: "high", Total: 2, HighCount: 1},
	}
	doc := findings.FromInput(in, findings.Options{})
	mux.HandleFunc("/admin/api/findings", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled": true, "total": 1, "items": []findings.Document{doc},
		})
	})

	// A real signed attestation bundle, so Statement() decoding is exercised.
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, err := attestbundle.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := attestbundle.NewService(attestbundle.Config{
		Signer:   signer,
		Attester: attestbundle.Attester{ID: "pullthrough-proxy", Name: "pullthrough", Version: "test"},
		Store:    attestbundle.NewStore(attestbundle.StoreOptions{MaxEntries: 8}),
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := svc.Attest(in, attestbundle.Options{})
	if err != nil {
		t.Fatal(err)
	}
	mux.HandleFunc("/admin/api/attest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled": true, "total": 1, "items": []*attestbundle.Bundle{bundle},
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDiscoverBackends(t *testing.T) {
	srv := fakeProxy(t)
	c, _ := newClient(globalFlags{url: srv.URL})
	bs, err := discoverBackends(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != 2 || bs[0].Name != "central" || bs[1].Name != "npm" {
		t.Errorf("backends = %+v", bs)
	}
}

func TestProbeClassification(t *testing.T) {
	srv := fakeProxy(t)
	c, _ := newClient(globalFlags{url: srv.URL})

	if r := c.probe("ok", c.gatewayURL("v1/npm/")); r.Verdict != "OK" || r.Status != 200 {
		t.Errorf("npm probe = %+v", r)
	}
	if r := c.probe("nf", c.gatewayURL("v1/central/")); r.Verdict != "OK" || r.Status != 404 {
		t.Errorf("404 probe should be OK-reachable, got %+v", r)
	}
	if r := c.probe("down", "http://127.0.0.1:0/nope"); r.Verdict != "UNREACHABLE" {
		t.Errorf("unreachable probe = %+v", r)
	}
}

func TestInspectMatchAndVerdict(t *testing.T) {
	srv := fakeProxy(t)
	var resp findingsListResp
	c, _ := newClient(globalFlags{url: srv.URL, tenant: "acme"})
	if err := c.getJSON(c.adminURL("api/findings", map[string]string{"q": "lodash"}), &resp); err != nil {
		t.Fatal(err)
	}
	doc, ok := matchDocument(resp.Items, "lodash", "4.17.21", "")
	if !ok {
		t.Fatal("expected to match lodash@4.17.21")
	}
	if doc.Artifact.Name != "lodash" {
		t.Errorf("matched wrong doc: %+v", doc.Artifact)
	}
	if _, ok := matchDocument(resp.Items, "ghost", "", ""); ok {
		t.Error("should not match an absent package")
	}
}

func TestAttestSummaryAndRaw(t *testing.T) {
	srv := fakeProxy(t)
	var resp attestListResp
	c, _ := newClient(globalFlags{url: srv.URL, tenant: "acme"})
	if err := c.getJSON(c.adminURL("api/attest", map[string]string{"package": "lodash@4.17.21"}), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Enabled || len(resp.Items) != 1 {
		t.Fatalf("unexpected attest resp: %+v", resp)
	}
	stmt, err := resp.Items[0].Statement()
	if err != nil {
		t.Fatalf("decoding statement: %v", err)
	}
	if stmt.Predicate.Artifact.Name != "lodash" {
		t.Errorf("statement artifact = %+v", stmt.Predicate.Artifact)
	}
	if stmt.Predicate.Admission.Verdict == "" {
		t.Error("expected an admission verdict in the predicate")
	}
}

func TestAPIErrorMessage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/api/overview", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing or invalid admin token"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, _ := newClient(globalFlags{url: srv.URL})
	err := c.getJSON(c.adminURL("api/overview", nil), &overviewResp{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "read-capable --token") {
		t.Errorf("401 error should guide on tokens, got %q", err.Error())
	}
}

// --- completion -------------------------------------------------------------

func TestCompletionScripts(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			// runCompletion writes to stdout; just assert it doesn't error and that
			// the generators include subcommand names.
			if err := runCompletion([]string{shell}); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := runCompletion([]string{"powershell"}); err == nil {
		t.Error("expected error for unsupported shell")
	}
	// Static content checks on the generators.
	if !strings.Contains(bashCompletion("config selftest", "--url"), "config selftest") {
		t.Error("bash completion missing commands")
	}
	if !strings.Contains(fishCompletion(), "inspect") {
		t.Error("fish completion missing inspect")
	}
	if !strings.Contains(zshCompletion("x"), "attest") {
		t.Error("zsh completion missing attest summary")
	}
}
