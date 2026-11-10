package main

import (
	"log/slog"
	"net/url"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
)

// buildRegistryRoot assembles the host-root Docker/OCI Registry v2 alias
// ("/v2/...") from configuration. It returns nil — leaving the alias unmounted —
// when the alias is disabled or no registry upstream is configured, so a
// deployment without container registries exposes nothing at "/v2/".
//
// The alias exists because container clients cannot address a path-prefixed
// registry: the Docker Engine rejects a registry mirror URL that carries a path,
// and every client inserts "/v2/" directly after the registry host. See
// proxy.RegistryRoot for the two addressing conventions it serves.
func buildRegistryRoot(cfg *config.Config, logger *slog.Logger) *proxy.RegistryRoot {
	rc := cfg.Server.Registry
	if !rc.EnabledOrDefault() {
		return nil
	}

	root := &proxy.RegistryRoot{
		DefaultUpstream: strings.TrimSpace(rc.DefaultUpstream),
		Namespaces:      map[string]string{},
	}
	// Iterate in name order so that, when two upstreams front the same registry
	// host, the namespace hint resolves to the same one on every start.
	names := make([]string, 0, len(cfg.Upstreams))
	for name := range cfg.Upstreams {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		up := cfg.Upstreams[name]
		if !up.IsEnabled() || !up.IsRegistryUpstream() {
			continue
		}
		root.Upstreams = append(root.Upstreams, name)
		for _, host := range registryNamespaces(up.URL) {
			if _, taken := root.Namespaces[host]; !taken {
				root.Namespaces[host] = name
			}
		}
	}
	if len(root.Upstreams) == 0 {
		return nil
	}
	// The configured default always wins its registry's namespace hint, so a
	// mirror request is served by the same upstream with or without the hint.
	if root.DefaultUpstream != "" {
		for _, host := range registryNamespaces(cfg.Upstreams[root.DefaultUpstream].URL) {
			root.Namespaces[host] = root.DefaultUpstream
		}
	}

	logger.Info("registry v2 alias enabled at /v2/",
		"upstreams", root.Upstreams, "defaultUpstream", root.DefaultUpstream)
	return root
}

// registryNamespaces returns the registry hosts a client may name (in
// containerd's "ns" mirror hint) when it mirrors the registry at rawURL: the
// URL's own host and, for Docker Hub, the "docker.io" name clients use for it —
// the Hub's API lives at registry-1.docker.io but images are addressed as
// docker.io/<repository>.
func registryNamespaces(rawURL string) []string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return nil
	}
	host := strings.ToLower(u.Host)
	hosts := []string{host}
	switch u.Hostname() {
	case "registry-1.docker.io", "index.docker.io", "registry.hub.docker.com":
		hosts = append(hosts, "docker.io")
	}
	return hosts
}
