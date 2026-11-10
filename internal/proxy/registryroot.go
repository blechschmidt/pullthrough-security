package proxy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// RegistryRoot configures the host-root Docker/OCI Registry v2 alias.
//
// Every container client — the Docker Engine, containerd, podman, skopeo,
// crane, the Helm OCI client — builds its request URLs by inserting "/v2/"
// directly after the registry host. None of them can address a registry that
// lives under a path prefix, so the path-prefixed backend mount
// ("/v1/<upstream>/v2/...") is unreachable for them without an external
// rewriting reverse proxy. The alias closes that gap: the gateway also answers
// at "/v2/..." and maps each request onto the regular "/v1/<upstream>/v2/..."
// route space, where it runs through the identical access-control, rate-limit
// and admission-gate chain as any other pull.
//
// Two addressing conventions are supported, because clients use both:
//
//   - Upstream-prefixed repositories ("repository path" addressing): the first
//     path component of the repository names the upstream, so
//     `docker pull proxy.example.com/dockerhub/library/alpine:3.19` requests
//     "/v2/dockerhub/library/alpine/manifests/3.19" and is served by the
//     "dockerhub" upstream as repository "library/alpine". This works for any
//     number of registry upstreams and needs no daemon configuration.
//
//   - Registry-mirror mode: a daemon configured with the proxy as a mirror
//     (dockerd "registry-mirrors", containerd/CRI-O hosts.toml, podman
//     registries.conf) requests the upstream's own repository path, e.g.
//     "/v2/library/alpine/manifests/3.19". Such un-prefixed requests are served
//     by DefaultUpstream, or — when the client states which registry it is
//     mirroring via containerd's "ns" query parameter — by the upstream fronting
//     that registry host (Namespaces).
type RegistryRoot struct {
	// Upstreams names every configured upstream that speaks the Registry v2 API
	// (docker upstreams and OCI-mode helm upstreams).
	Upstreams []string
	// DefaultUpstream serves requests whose repository path carries no upstream
	// prefix. Empty disables registry-mirror mode (only prefixed repositories and
	// "ns"-hinted requests are served).
	DefaultUpstream string
	// Namespaces maps a registry host (as sent in containerd's "ns" mirror hint,
	// e.g. "docker.io", "ghcr.io") to the upstream fronting it.
	Namespaces map[string]string
}

// registryRootPrefix is the path every Registry v2 request starts with.
const registryRootPrefix = "/v2/"

// registryRoute is the outcome of mapping a host-root registry request onto the
// gateway's backend route space.
type registryRoute struct {
	// upstream is the backend the request is served by.
	upstream string
	// path is the rewritten "/v1/<upstream>/v2/..." gateway path.
	path string
	// stripNS reports that the request carried a containerd "ns" mirror hint
	// that must not be forwarded to the upstream registry.
	stripNS bool
}

// has reports whether name is a configured registry upstream.
func (rr *RegistryRoot) has(name string) bool {
	for _, u := range rr.Upstreams {
		if u == name {
			return true
		}
	}
	return false
}

// pingUpstream picks the upstream that answers the bare "/v2/" API version
// check: the default upstream when one is configured, otherwise the first
// registry upstream in name order (deterministic across restarts).
func (rr *RegistryRoot) pingUpstream() (string, bool) {
	if rr.DefaultUpstream != "" {
		return rr.DefaultUpstream, true
	}
	if len(rr.Upstreams) == 0 {
		return "", false
	}
	names := append([]string(nil), rr.Upstreams...)
	sort.Strings(names)
	return names[0], true
}

// route maps a host-root registry request path ("/v2/...") and its query onto a
// backend route. ok is false when no upstream can serve the request.
func (rr *RegistryRoot) route(p string, query url.Values) (registryRoute, bool) {
	if p == "/v2" {
		p = registryRootPrefix
	}
	if !strings.HasPrefix(p, registryRootPrefix) {
		return registryRoute{}, false
	}
	rest := strings.TrimPrefix(p, registryRootPrefix)

	// API version check ("GET /v2/"): no repository, so any registry upstream can
	// answer; it also runs the access-control challenge for that upstream.
	if rest == "" {
		up, ok := rr.pingUpstream()
		if !ok {
			return registryRoute{}, false
		}
		return registryRoute{upstream: up, path: "/v1/" + up + registryRootPrefix}, true
	}

	// A containerd-style mirror request names the registry it is mirroring. That
	// is unambiguous, so it wins over the path-prefix heuristic below.
	if ns := strings.ToLower(strings.TrimSpace(query.Get("ns"))); ns != "" {
		if up, ok := rr.Namespaces[ns]; ok {
			return registryRoute{upstream: up, path: "/v1/" + up + registryRootPrefix + rest, stripNS: true}, true
		}
	}

	// Upstream-prefixed repository: "<upstream>/<repository...>/<verb>/<ref>".
	// The remainder must still be a complete repository request (a repository
	// component plus the verb and reference, or a bare registry-level endpoint),
	// otherwise the first component is just an ordinary namespace on the default
	// upstream that happens to share an upstream's name.
	if first, remainder, found := strings.Cut(rest, "/"); found && rr.has(first) && isRegistryRequest(remainder) {
		return registryRoute{upstream: first, path: "/v1/" + first + registryRootPrefix + remainder}, true
	}

	if rr.DefaultUpstream != "" {
		return registryRoute{
			upstream: rr.DefaultUpstream,
			path:     "/v1/" + rr.DefaultUpstream + registryRootPrefix + rest,
			stripNS:  query.Has("ns"),
		}, true
	}
	return registryRoute{}, false
}

// isRegistryRequest reports whether p (the part of a registry path after the
// "/v2/" prefix and an optional upstream component) is a well-formed registry
// request: a registry-level endpoint such as "_catalog", or
// "<repository>/<verb>/<reference>" with a non-empty repository.
func isRegistryRequest(p string) bool {
	if p == "" {
		return false
	}
	if strings.HasPrefix(p, "_") { // registry-level endpoints (_catalog)
		return true
	}
	segs := strings.Split(p, "/")
	for i := 1; i < len(segs); i++ {
		switch segs[i] {
		case "manifests", "blobs", "referrers":
			// "<repo...>/<verb>/<reference>": a reference must follow the verb.
			if i+1 < len(segs) && segs[i+1] != "" {
				return true
			}
		case "tags":
			// "<repo...>/tags/list"
			if i+1 < len(segs) && segs[i+1] == "list" {
				return true
			}
		}
	}
	return false
}

// handleRegistryRoot serves the host-root "/v2/" alias: it rewrites the request
// onto "/v1/<upstream>/v2/..." and hands it to next — the same handler chain
// that serves "/v1/" — so authentication, RBAC, rate limiting, tracing and every
// admission gate apply exactly as they do for a path-prefixed pull.
func (g *Gateway) handleRegistryRoot(next http.Handler) http.Handler {
	rr := g.opts.RegistryRoot
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, ok := rr.route(r.URL.Path, r.URL.Query())
		if !ok {
			writeRegistryRootError(w, rr)
			return
		}

		// Rewrite on a shallow copy so the outer request-logging middleware still
		// reports the path the client actually sent.
		r2 := r.Clone(r.Context())
		r2.URL.Path = route.path
		r2.URL.RawPath = ""
		if route.stripNS {
			q := r2.URL.Query()
			q.Del("ns")
			r2.URL.RawQuery = q.Encode()
		}
		next.ServeHTTP(w, r2)
	})
}

// writeRegistryRootError answers a host-root registry request no upstream can
// serve, in the Registry v2 error envelope so container clients surface the
// explanation instead of a bare status line.
func writeRegistryRootError(w http.ResponseWriter, rr *RegistryRoot) {
	names := append([]string(nil), rr.Upstreams...)
	sort.Strings(names)
	msg := "no registry upstream serves this repository: prefix the repository with a configured " +
		"registry upstream name (" + strings.Join(names, ", ") + "), e.g. <proxy-host>/" + firstOr(names, "<upstream>") +
		"/<repository>, or set server.registry.defaultUpstream to serve un-prefixed repositories (registry-mirror mode)"
	body := map[string]any{"errors": []map[string]string{{"code": "NAME_UNKNOWN", "message": msg}}}

	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Docker-Distribution-Api-Version", "registry/2.0")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(body)
}

// firstOr returns the first element of s, or fallback when s is empty.
func firstOr(s []string, fallback string) string {
	if len(s) == 0 {
		return fallback
	}
	return s[0]
}
