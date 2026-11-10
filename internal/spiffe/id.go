// Package spiffe implements SPIFFE/SVID mutual-TLS workload identity for client
// authentication (Task 58). It is an alternative — or complement — to the
// token/OIDC client auth (Task 10) aimed at enterprises running the proxy inside
// a service mesh (Istio, Linkerd, SPIRE) that want zero-trust workload identity
// rather than long-lived bearer tokens.
//
// The package provides four composable pieces:
//
//   - ID: parsing and inspection of SPIFFE IDs (spiffe://trust-domain/path).
//   - TrustBundle / BundleSource: a reloadable, offline/air-gapped-friendly set
//     of trusted X.509 roots per trust domain, loadable from a PEM file or the
//     SPIFFE Trust Bundle (federated JWKS-style) JSON format.
//   - Policy: an identity-mapping policy (SPIFFE-ID glob/regex -> tenant +
//     capabilities) with per-tenant overrides.
//   - Authenticator: an auth.Authenticator that terminates/validates mutual TLS
//     (chain validation against the trust bundle, SPIFFE-ID extraction from the
//     client certificate SAN URI) and maps the verified identity to a tenant +
//     roles for the existing access-control, rate-limit, and audit subsystems.
//
// Certificate-chain verification is performed in the application layer (rather
// than only at the TLS handshake) so the trust bundle can be hot-reloaded
// without restarting the listener and so the SPIFFE-specific rules — trust
// domain, SAN URI shape — are enforced explicitly.
package spiffe

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Scheme is the URI scheme of every SPIFFE ID.
const Scheme = "spiffe"

// ID is a parsed SPIFFE ID of the form spiffe://<trust-domain>/<path>. The
// trust domain is the authority (host) component and selects which set of
// trusted roots a presenting certificate is validated against; the path
// identifies the workload within that domain (by SPIFFE convention a sequence
// of /key/value segments such as /ns/<namespace>/sa/<service-account>).
type ID struct {
	// TrustDomain is the SPIFFE trust domain (lower-cased authority), e.g.
	// "example.org".
	TrustDomain string
	// Path is the workload path including the leading slash, e.g.
	// "/ns/prod/sa/web". Empty for a bare trust-domain ID.
	Path string
}

// ParseID parses and validates a SPIFFE ID string per the SPIFFE-ID format:
// scheme "spiffe", a non-empty lower-case trust domain authority, no userinfo,
// no port, no query, and no fragment. It returns an error describing the first
// violation so a malformed SAN URI cannot be silently accepted.
func ParseID(raw string) (ID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ID{}, errors.New("spiffe: empty id")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ID{}, fmt.Errorf("spiffe: invalid id %q: %w", raw, err)
	}
	if !strings.EqualFold(u.Scheme, Scheme) {
		return ID{}, fmt.Errorf("spiffe: id %q has scheme %q, want %q", raw, u.Scheme, Scheme)
	}
	if u.User != nil {
		return ID{}, fmt.Errorf("spiffe: id %q must not contain userinfo", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return ID{}, fmt.Errorf("spiffe: id %q must not contain a query or fragment", raw)
	}
	if u.Port() != "" {
		return ID{}, fmt.Errorf("spiffe: id %q must not contain a port", raw)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ID{}, fmt.Errorf("spiffe: id %q has an empty trust domain", raw)
	}
	// A trust domain is a DNS-like label set; reject characters that would let a
	// SAN URI smuggle path separators or wildcards into the authority.
	if strings.ContainsAny(host, "/\\*") {
		return ID{}, fmt.Errorf("spiffe: id %q has an invalid trust domain %q", raw, host)
	}
	path := u.Path
	if path == "/" {
		path = ""
	}
	if path != "" && !strings.HasPrefix(path, "/") {
		return ID{}, fmt.Errorf("spiffe: id %q has a relative path", raw)
	}
	return ID{TrustDomain: host, Path: path}, nil
}

// String renders the canonical SPIFFE ID string.
func (id ID) String() string {
	return Scheme + "://" + id.TrustDomain + id.Path
}

// IsZero reports whether the ID is the empty value.
func (id ID) IsZero() bool { return id.TrustDomain == "" && id.Path == "" }

// Selectors parses the path as a sequence of /key/value pairs and returns them
// as a map. A trailing key without a value (odd segment count) is returned with
// an empty value. It is a convenience for policies/audit that key on the
// conventional /ns/<namespace>/sa/<service-account> layout; callers that need
// the exact path should use Path directly.
func (id ID) Selectors() map[string]string {
	segs := splitPath(id.Path)
	if len(segs) == 0 {
		return nil
	}
	out := make(map[string]string, (len(segs)+1)/2)
	for i := 0; i < len(segs); i += 2 {
		key := segs[i]
		val := ""
		if i+1 < len(segs) {
			val = segs[i+1]
		}
		// First occurrence wins so a crafted duplicate cannot shadow an earlier
		// selector.
		if _, ok := out[key]; !ok {
			out[key] = val
		}
	}
	return out
}

// splitPath splits a SPIFFE path ("/a/b/c") into its non-empty segments.
func splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}
