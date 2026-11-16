package homebrew

import (
	"net/url"
	"strings"
)

// This file exports the backend's rewrite of a bottle URL for the full-mirror
// feed adapter (internal/fullmirror, Task 191), which follows a Homebrew JSON
// API through its formula index and lists each formula's bottles at the paths
// the backend rewrites them to in the formula documents it serves — without
// reading those documents, which a CDN or a mirror may serve older than the
// index.

// BottlePath is the path, relative to the backend's mount, that the backend
// rewrites a formula's bottle URL to in the formula JSON it serves: its
// synthetic bottle endpoint, "/bottle/{name}/{version}/v2/{repo}/blobs/
// sha256:{digest}". bottleRegistryURL is the upstream's bottleRegistryUrl
// setting ("" for the default, https://ghcr.io); name and version are the
// formula's name and stable version as its JSON states them. ok is false where
// the backend leaves the URL as it is — not an OCI blob on the bottle
// registry, a bottle registry URL New would refuse, a name or version that is
// empty or holds a "/" — and for a path the backend would not serve as that
// formula's bottle.
func BottlePath(bottleRegistryURL, rawURL, name, version string) (string, bool) {
	host, ok := bottleRegistryHost(bottleRegistryURL)
	if !ok {
		return "", false
	}
	// As bottleURLsIn takes a formula's coordinate.
	name, version = strings.TrimSpace(name), strings.TrimSpace(version)
	if name == "" || version == "" || strings.Contains(name, "/") || strings.Contains(version, "/") {
		return "", false
	}
	p, ok := proxyBottlePath("", host, rawURL, name, version)
	if !ok {
		return "", false
	}
	res, ok := classify(p)
	if !ok || res.kind != kindBottle || res.name != name || res.version != version {
		return "", false
	}
	return p, true
}

// bottleRegistryHost is the bottle registry's host as New takes it from the
// bottleRegistryUrl setting; ok is false for a setting New refuses.
func bottleRegistryHost(setting string) (string, bool) {
	registryURL := strings.TrimSpace(setting)
	if registryURL == "" {
		registryURL = defaultBottleRegistry
	}
	u, err := url.Parse(strings.TrimRight(registryURL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false
	}
	return u.Host, true
}
