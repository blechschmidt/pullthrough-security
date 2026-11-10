package k8swebhook

import "strings"

// ImageRef is a parsed container image reference. It follows the Docker/OCI
// reference grammar closely enough for coordinate resolution: an optional
// registry host, a repository path, and a tag and/or digest.
type ImageRef struct {
	// Original is the reference exactly as it appeared in the Pod spec.
	Original string
	// Registry is the registry host (e.g. "docker.io", "ghcr.io"), empty when
	// the reference omits one.
	Registry string
	// Repository is the repository path without the registry host
	// (e.g. "library/nginx", "org/app").
	Repository string
	// Tag is the tag component (empty for a digest-only reference).
	Tag string
	// Digest is the "sha256:..." component (empty for a tag-only reference).
	Digest string
}

// ParseImageRef parses a container image reference. It never fails: an
// unparseable or empty input yields a best-effort ImageRef with Original set, so
// the caller can still log and bypass/deny it deterministically.
//
// The grammar handled:
//
//	[registry[:port]/]repository[:tag][@sha256:digest]
//
// A leading host segment is treated as a registry only when it contains a '.'
// or ':' or is exactly "localhost" (the Docker heuristic), so "org/app" keeps
// "org" as part of the repository rather than mistaking it for a host.
func ParseImageRef(ref string) ImageRef {
	out := ImageRef{Original: ref}
	s := strings.TrimSpace(ref)
	if s == "" {
		return out
	}

	// Split off the digest first (@sha256:...). A digest always follows any tag.
	if at := strings.LastIndex(s, "@"); at >= 0 {
		out.Digest = strings.TrimSpace(s[at+1:])
		s = s[:at]
	}

	// Split off the registry host, if present.
	registry := ""
	rest := s
	if slash := strings.Index(s, "/"); slash >= 0 {
		head := s[:slash]
		if isRegistryHost(head) {
			registry = head
			rest = s[slash+1:]
		}
	}
	out.Registry = registry

	// The remainder is repository[:tag]. A ':' in the repository segment is a
	// tag separator only when it appears in the LAST path element (a port colon
	// would have been consumed with the registry host above).
	repo := rest
	if colon := strings.LastIndex(rest, ":"); colon >= 0 && !strings.Contains(rest[colon+1:], "/") {
		repo = rest[:colon]
		out.Tag = strings.TrimSpace(rest[colon+1:])
	}
	out.Repository = strings.TrimSpace(repo)
	return out
}

// isRegistryHost applies the Docker heuristic: the first path segment is a
// registry host only when it looks like one (contains a dot or a port colon, or
// is literally "localhost").
func isRegistryHost(seg string) bool {
	if seg == "localhost" {
		return true
	}
	return strings.ContainsAny(seg, ".:")
}

// Coordinate renders the dossier lookup coordinate for the image. When
// stripRegistry is true the registry host is dropped so the coordinate matches
// the repository path the proxy's Docker backend records (e.g. "org/app"); when
// false the full "registry/repository" is used. The returned version prefers the
// digest (the strongest identity) and falls back to the tag.
func (r ImageRef) Coordinate(stripRegistry bool) (name, version string) {
	name = r.Repository
	if !stripRegistry && r.Registry != "" {
		name = r.Registry + "/" + r.Repository
	}
	switch {
	case r.Digest != "":
		version = r.Digest
	case r.Tag != "":
		version = r.Tag
	}
	return name, version
}

// String renders a canonical reference for logging and rejection messages.
func (r ImageRef) String() string {
	if r.Original != "" {
		return r.Original
	}
	b := strings.Builder{}
	if r.Registry != "" {
		b.WriteString(r.Registry)
		b.WriteByte('/')
	}
	b.WriteString(r.Repository)
	if r.Tag != "" {
		b.WriteByte(':')
		b.WriteString(r.Tag)
	}
	if r.Digest != "" {
		b.WriteByte('@')
		b.WriteString(r.Digest)
	}
	return b.String()
}

// matchesPrefix reports whether the original reference starts with any of the
// given prefixes (used for the always-admit image allowlist).
func (r ImageRef) matchesPrefix(prefixes []string) bool {
	orig := strings.TrimSpace(r.Original)
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p != "" && strings.HasPrefix(orig, p) {
			return true
		}
	}
	return false
}
