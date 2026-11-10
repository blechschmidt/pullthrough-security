package main

import (
	"fmt"
	"sort"
	"strings"
)

// backend is a single enabled upstream as seen by the client: its mount name
// (the path segment after /v1/) and its protocol type.
type backend struct {
	Name string
	Type string
	URL  string
}

// overviewResp is the subset of the admin /api/overview payload the client
// needs to enumerate enabled backends. Defined locally so the client binary
// stays decoupled from the server's admin package.
type overviewResp struct {
	Info struct {
		Version   string `json:"version"`
		Upstreams []struct {
			Name string `json:"name"`
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"upstreams"`
	} `json:"info"`
	Backends []string `json:"backends"`
}

// discoverBackends asks the proxy which upstreams are enabled via the admin
// overview endpoint. The result is sorted by name for stable output.
func discoverBackends(c *client) ([]backend, error) {
	var resp overviewResp
	if err := c.getJSON(c.adminURL("api/overview", nil), &resp); err != nil {
		return nil, err
	}
	out := make([]backend, 0, len(resp.Info.Upstreams))
	for _, u := range resp.Info.Upstreams {
		if u.Name == "" {
			continue
		}
		out = append(out, backend{Name: u.Name, Type: strings.ToLower(u.Type), URL: u.URL})
	}
	// Older proxies (or ones that elide upstream detail) still report backend
	// names; fall back to those with an unknown type so config/selftest degrade
	// gracefully rather than emitting nothing.
	if len(out) == 0 {
		for _, n := range resp.Backends {
			if n != "" {
				out = append(out, backend{Name: n, Type: ""})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// parseBackendSpecs parses explicit "name=type" arguments, letting a developer
// generate config without admin access to the overview endpoint. A bare "name"
// (no "=type") is rejected, since the type drives snippet selection.
func parseBackendSpecs(specs []string) ([]backend, error) {
	out := make([]backend, 0, len(specs))
	for _, s := range specs {
		name, typ, ok := strings.Cut(s, "=")
		name, typ = strings.TrimSpace(name), strings.ToLower(strings.TrimSpace(typ))
		if !ok || name == "" || typ == "" {
			return nil, fmt.Errorf("invalid backend spec %q: want name=type, e.g. npm=npm", s)
		}
		out = append(out, backend{Name: name, Type: typ})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// resolveBackends returns the backend set to operate on: explicit specs when
// given, otherwise auto-discovered from the proxy. The discovery error is
// wrapped with onboarding guidance, since it is the most likely first failure.
func resolveBackends(c *client, specs []string) ([]backend, error) {
	if len(specs) > 0 {
		return parseBackendSpecs(specs)
	}
	bs, err := discoverBackends(c)
	if err != nil {
		return nil, fmt.Errorf("discovering backends from the proxy: %w\n"+
			"(either grant this token read access to %s/api/overview, or pass explicit backends as name=type arguments)",
			err, c.adminPrefix)
	}
	if len(bs) == 0 {
		return nil, fmt.Errorf("the proxy reports no enabled upstreams")
	}
	return bs, nil
}
