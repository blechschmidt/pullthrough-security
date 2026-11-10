package main

import (
	"io"
	"log/slog"
	"reflect"
	"sort"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/config"
)

func registryTestConfig() *config.Config {
	cfg := config.Default()
	cfg.Upstreams = map[string]config.UpstreamConfig{
		"dockerhub": {Type: "docker", URL: "https://registry-1.docker.io"},
		"ghcr":      {Type: "docker", URL: "https://ghcr.io"},
		"charts":    {Type: "helm", URL: "https://registry.example.com:5000", Settings: map[string]string{"oci": "true"}},
		"bitnami":   {Type: "helm", URL: "https://charts.bitnami.com/bitnami"}, // classic repo: not a registry
		"npm":       {Type: "npm", URL: "https://registry.npmjs.org"},
	}
	return &cfg
}

func TestBuildRegistryRoot(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := registryTestConfig()
	cfg.Server.Registry.DefaultUpstream = "dockerhub"
	root := buildRegistryRoot(cfg, logger)
	if root == nil {
		t.Fatal("expected the alias to be built when registry upstreams exist")
	}
	got := append([]string(nil), root.Upstreams...)
	sort.Strings(got)
	if want := []string{"charts", "dockerhub", "ghcr"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Upstreams = %v, want %v (docker + OCI-mode helm only)", got, want)
	}
	if root.DefaultUpstream != "dockerhub" {
		t.Errorf("DefaultUpstream = %q, want dockerhub", root.DefaultUpstream)
	}
	wantNS := map[string]string{
		"registry-1.docker.io":      "dockerhub",
		"docker.io":                 "dockerhub", // the name clients use for Docker Hub
		"ghcr.io":                   "ghcr",
		"registry.example.com:5000": "charts",
	}
	if !reflect.DeepEqual(root.Namespaces, wantNS) {
		t.Errorf("Namespaces = %v, want %v", root.Namespaces, wantNS)
	}
}

func TestBuildRegistryRootDisabledOrEmpty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := registryTestConfig()
	off := false
	cfg.Server.Registry.Enabled = &off
	if root := buildRegistryRoot(cfg, logger); root != nil {
		t.Errorf("alias built although server.registry.enabled is false: %+v", root)
	}

	cfg = registryTestConfig()
	cfg.Upstreams = map[string]config.UpstreamConfig{"npm": {Type: "npm", URL: "https://registry.npmjs.org"}}
	if root := buildRegistryRoot(cfg, logger); root != nil {
		t.Errorf("alias built without any registry upstream: %+v", root)
	}

	// A disabled registry upstream is not served, so it must not be routable.
	cfg = registryTestConfig()
	for _, name := range []string{"dockerhub", "ghcr", "charts"} {
		up := cfg.Upstreams[name]
		up.Enabled = &off
		cfg.Upstreams[name] = up
	}
	if root := buildRegistryRoot(cfg, logger); root != nil {
		t.Errorf("alias built from disabled upstreams only: %+v", root)
	}
}

// TestBuildRegistryRootNamespaceTieBreak pins the behaviour when two upstreams
// front the same registry host: the configured default owns that registry's
// namespace hint, so a mirror request is served by the same upstream whether or
// not the client sends the hint; without a default the first upstream by name
// wins, deterministically.
func TestBuildRegistryRootNamespaceTieBreak(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mk := func() *config.Config {
		cfg := config.Default()
		cfg.Upstreams = map[string]config.UpstreamConfig{
			"hub-a": {Type: "docker", URL: "https://registry-1.docker.io"},
			"hub-b": {Type: "docker", URL: "https://registry-1.docker.io"},
		}
		return &cfg
	}

	if got := buildRegistryRoot(mk(), logger).Namespaces["docker.io"]; got != "hub-a" {
		t.Errorf("without a default, docker.io -> %q, want hub-a (first by name)", got)
	}
	cfg := mk()
	cfg.Server.Registry.DefaultUpstream = "hub-b"
	if got := buildRegistryRoot(cfg, logger).Namespaces["docker.io"]; got != "hub-b" {
		t.Errorf("with defaultUpstream hub-b, docker.io -> %q, want hub-b", got)
	}
}

func TestRegistryNamespaces(t *testing.T) {
	cases := map[string][]string{
		"https://registry-1.docker.io":  {"registry-1.docker.io", "docker.io"},
		"https://index.docker.io/":      {"index.docker.io", "docker.io"},
		"https://GHCR.io":               {"ghcr.io"},
		"http://registry.internal:5000": {"registry.internal:5000"},
		"":                              nil,
		"not a url":                     nil,
	}
	for raw, want := range cases {
		if got := registryNamespaces(raw); !reflect.DeepEqual(got, want) {
			t.Errorf("registryNamespaces(%q) = %v, want %v", raw, got, want)
		}
	}
}
