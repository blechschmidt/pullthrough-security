package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// helmIndexThrough builds a helm upstream the way the server does and returns
// the index.yaml it serves for a repository whose index lists one chart on
// another host.
func helmIndexThrough(t *testing.T, publicURL string, settings map[string]string) string {
	t.Helper()
	repo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/index.yaml" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "apiVersion: v1\nentries:\n  app:\n  - name: app\n    version: 1.2.3\n"+
			"    urls:\n    - https://releases.example.net/download/app-1.2.3.tgz\n")
	}))
	t.Cleanup(repo.Close)

	cfg := &config.Config{}
	cfg.Server.PublicURL = publicURL
	up := config.UpstreamConfig{Type: "helm", URL: repo.URL, Settings: settings}
	b, err := buildBackend(cfg, "charts", up, upstream.NewWithHTTPClient(repo.Client(), "test/1"), upstream.Credentials{})
	if err != nil {
		t.Fatalf("buildBackend: %v", err)
	}

	resolved, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/index.yaml"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	res, err := b.Fetch(context.Background(), resolved)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer res.Content.Close()
	body, err := io.ReadAll(res.Content)
	if err != nil {
		t.Fatalf("reading the index: %v", err)
	}
	return string(body)
}

// The helm upstream is wired with the proxy's public base, so the index it
// serves sends chart downloads back through the proxy — also for an archive the
// repository hosts elsewhere.
func TestHelmBackendRewritesIndexToThePublicURL(t *testing.T) {
	index := helmIndexThrough(t, "https://proxy.example.com/", nil)
	if want := `- "https://proxy.example.com/v1/charts/-/app/1.2.3/app-1.2.3.tgz"`; !strings.Contains(index, want) {
		t.Errorf("served index does not route the chart through the public URL; want %s in:\n%s", want, index)
	}
	if strings.Contains(index, "releases.example.net") {
		t.Errorf("served index still points at the upstream host:\n%s", index)
	}
}

// Without a public URL the index is still rewritten, to references a Helm
// client resolves against the repository URL it was given.
func TestHelmBackendRewritesIndexWithoutAPublicURL(t *testing.T) {
	index := helmIndexThrough(t, "", nil)
	if want := `- "-/app/1.2.3/app-1.2.3.tgz"`; !strings.Contains(index, want) {
		t.Errorf("served index does not use repository-relative links; want %s in:\n%s", want, index)
	}
	if strings.Contains(index, "releases.example.net") {
		t.Errorf("served index still points at the upstream host:\n%s", index)
	}
}

// OCI mode speaks the registry protocol and has no index to rewrite.
func TestHelmBackendOCIModeIsARegistry(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.PublicURL = "https://proxy.example.com"
	up := config.UpstreamConfig{Type: "helm", URL: "https://registry.example.net", Settings: map[string]string{"oci": "true"}}
	b, err := buildBackend(cfg, "charts", up, upstream.NewWithHTTPClient(http.DefaultClient, "test/1"), upstream.Credentials{})
	if err != nil {
		t.Fatalf("buildBackend: %v", err)
	}
	resolved, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/v2/library/app/manifests/1.2.3"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Coordinate != (backends.Coordinate{Name: "library/app", Version: "1.2.3"}) {
		t.Errorf("coordinate = %+v", resolved.Coordinate)
	}
	if _, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/index.yaml"}); err == nil {
		t.Error("OCI mode resolved a chart-repository path")
	}
}
