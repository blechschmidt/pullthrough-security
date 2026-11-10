package provenance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// This file implements per-ecosystem Resolvers. Each tries the strongest signal
// available for its ecosystem and degrades gracefully:
//
//   - npm:  signed provenance attestations (Sigstore bundles from npm's
//           attestation API) first; the packument `repository` field as a
//           claimed fallback.
//   - pypi: the project's repository URL from PyPI metadata (claimed). PEP 740
//           attestation presence is surfaced when advertised.
//   - go:   the module path is authoritative VCS info; the commit is recovered
//           from a pseudo-version. Integrity is guaranteed by the checksum DB,
//           so the link is claimed.
//
// SECURITY: metadata fallbacks (repository URLs, module paths) are self-asserted
// by the package and are therefore ConfidenceClaimed at best — never attested.
// They tell scanning *which* repository to look at; they do not prove the
// artifact was built from it.

// httpDoer is the minimal upstream surface the resolvers need; *upstream.Client
// satisfies it and tests can inject a stub.
type httpDoer interface {
	Do(ctx context.Context, req upstream.Request) (*upstream.Response, error)
}

// maxMetadataBytes bounds how much of an ecosystem metadata / attestation
// response we buffer, so a hostile or oversized upstream cannot exhaust memory.
const maxMetadataBytes = 16 << 20 // 16 MiB

// getJSON fetches url and decodes the (size-limited) JSON body into v. A non-2xx
// status is returned as an error; 404 is normalized to ErrNoProvenance so callers
// can fall through to the next signal.
func getJSON(ctx context.Context, doer httpDoer, creds upstream.Credentials, rawURL string, header http.Header, v any) error {
	resp, err := doer.Do(ctx, upstream.Request{URL: rawURL, Method: http.MethodGet, Header: header, Creds: creds})
	if err != nil {
		return err
	}
	defer drain(resp.Body)
	if resp.Status == http.StatusNotFound {
		return ErrNoProvenance
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("provenance: %s returned status %d", rawURL, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes))
	if err != nil {
		return fmt.Errorf("provenance: reading %s: %w", rawURL, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("provenance: decoding %s: %w", rawURL, err)
	}
	return nil
}

func drain(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4096))
	_ = body.Close()
}

// --- npm --------------------------------------------------------------------

// NPMResolver resolves provenance for npm packages: signed attestations from the
// registry's attestation endpoint first, then the packument repository field.
type NPMResolver struct {
	doer     httpDoer
	verifier *Verifier
	base     string // registry base, e.g. "https://registry.npmjs.org"
	creds    upstream.Credentials
	now      func() time.Time
}

// NewNPMResolver constructs an npm resolver. registryBase defaults to the public
// npm registry when empty.
func NewNPMResolver(doer httpDoer, verifier *Verifier, registryBase string, creds upstream.Credentials) *NPMResolver {
	if registryBase == "" {
		registryBase = "https://registry.npmjs.org"
	}
	return &NPMResolver{
		doer:     doer,
		verifier: verifier,
		base:     strings.TrimRight(registryBase, "/"),
		creds:    creds,
		now:      time.Now,
	}
}

// Name implements Resolver.
func (r *NPMResolver) Name() string { return "npm-metadata" }

// npmAttestationsResponse is the shape of {base}/-/npm/v1/attestations/{spec}.
type npmAttestationsResponse struct {
	Attestations []struct {
		PredicateType string          `json:"predicateType"`
		Bundle        json.RawMessage `json:"bundle"`
	} `json:"attestations"`
}

// Resolve implements Resolver.
func (r *NPMResolver) Resolve(ctx context.Context, art Artifact) (*Link, error) {
	if art.Name == "" || art.Version == "" {
		return nil, ErrNoProvenance
	}
	spec := art.Name + "@" + art.Version
	// npm escapes "/" in scoped names as "%2f" in the attestation path.
	attURL := r.base + "/-/npm/v1/attestations/" + strings.ReplaceAll(url.PathEscape(spec), "%2F", "%2f")

	if link := r.resolveAttested(ctx, art, attURL); link != nil {
		return link, nil
	}
	return r.resolveFromPackument(ctx, art)
}

func (r *NPMResolver) resolveAttested(ctx context.Context, art Artifact, attURL string) *Link {
	var resp npmAttestationsResponse
	if err := getJSON(ctx, r.doer, r.creds, attURL, nil, &resp); err != nil {
		return nil
	}
	for _, a := range resp.Attestations {
		if len(a.Bundle) == 0 {
			continue
		}
		link := verifyAndExtract(r.verifier, a.Bundle, art, r.Name(), r.now)
		if link != nil {
			return link
		}
	}
	return nil
}

// npmPackument is the subset of an npm packument we read for the repository.
type npmPackument struct {
	Repository json.RawMessage `json:"repository"`
	Versions   map[string]struct {
		Repository json.RawMessage `json:"repository"`
	} `json:"versions"`
}

func (r *NPMResolver) resolveFromPackument(ctx context.Context, art Artifact) (*Link, error) {
	var pkg npmPackument
	pkgURL := r.base + "/" + strings.ReplaceAll(url.PathEscape(art.Name), "%2F", "%2f")
	if err := getJSON(ctx, r.doer, r.creds, pkgURL, nil, &pkg); err != nil {
		return nil, ErrNoProvenance
	}
	repo := parseNPMRepository(pkg.Repository)
	if repo == "" {
		if v, ok := pkg.Versions[art.Version]; ok {
			repo = parseNPMRepository(v.Repository)
		}
	}
	if repo == "" {
		return nil, ErrNoProvenance
	}
	l := &Link{
		Artifact:      art,
		RepositoryURL: repo,
		Confidence:    ConfidenceClaimed,
		ResolverName:  r.Name(),
	}
	stampNow(l, r.now)
	return l, nil
}

// parseNPMRepository handles the two npm `repository` encodings: a bare string,
// or an object {"type":"git","url":"..."}.
func parseNPMRepository(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && s != "" {
		return normalizeRepoURL(stripNPMShorthand(s))
	}
	var obj struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.URL != "" {
		return normalizeRepoURL(stripNPMShorthand(obj.URL))
	}
	return ""
}

// stripNPMShorthand expands npm's "github:owner/repo" / "owner/repo" shorthand.
func stripNPMShorthand(s string) string {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "github:"):
		return "https://github.com/" + strings.TrimPrefix(s, "github:")
	case strings.HasPrefix(s, "gitlab:"):
		return "https://gitlab.com/" + strings.TrimPrefix(s, "gitlab:")
	case strings.HasPrefix(s, "bitbucket:"):
		return "https://bitbucket.org/" + strings.TrimPrefix(s, "bitbucket:")
	}
	// "owner/repo" with no scheme and exactly one slash → GitHub shorthand.
	if !strings.Contains(s, "://") && !strings.HasPrefix(s, "git@") && strings.Count(s, "/") == 1 {
		return "https://github.com/" + s
	}
	return s
}

// --- pypi -------------------------------------------------------------------

// PyPIResolver resolves provenance for Python packages from PyPI JSON metadata.
type PyPIResolver struct {
	doer  httpDoer
	base  string // e.g. "https://pypi.org"
	creds upstream.Credentials
	now   func() time.Time
}

// NewPyPIResolver constructs a PyPI resolver. base defaults to https://pypi.org.
func NewPyPIResolver(doer httpDoer, base string, creds upstream.Credentials) *PyPIResolver {
	if base == "" {
		base = "https://pypi.org"
	}
	return &PyPIResolver{doer: doer, base: strings.TrimRight(base, "/"), creds: creds, now: time.Now}
}

// Name implements Resolver.
func (r *PyPIResolver) Name() string { return "pypi-metadata" }

// pypiProject is the subset of PyPI's JSON API we read.
type pypiProject struct {
	Info struct {
		HomePage    string            `json:"home_page"`
		ProjectURLs map[string]string `json:"project_urls"`
	} `json:"info"`
	URLs []struct {
		Provenance string `json:"provenance"`
	} `json:"urls"`
}

// Resolve implements Resolver.
func (r *PyPIResolver) Resolve(ctx context.Context, art Artifact) (*Link, error) {
	if art.Name == "" {
		return nil, ErrNoProvenance
	}
	name := url.PathEscape(art.Name)
	metaURL := r.base + "/pypi/" + name + "/json"
	if art.Version != "" {
		metaURL = r.base + "/pypi/" + name + "/" + url.PathEscape(art.Version) + "/json"
	}
	var proj pypiProject
	header := http.Header{"Accept": {"application/json"}}
	if err := getJSON(ctx, r.doer, r.creds, metaURL, header, &proj); err != nil {
		return nil, ErrNoProvenance
	}
	repo := pickRepoURL(proj.Info.ProjectURLs, proj.Info.HomePage)
	if repo == "" {
		return nil, ErrNoProvenance
	}
	// PEP 740 provenance presence raises confidence intent but we do not fetch and
	// verify the provenance file here; that path lives in the attestation layer.
	l := &Link{
		Artifact:      art,
		RepositoryURL: repo,
		Confidence:    ConfidenceClaimed,
		ResolverName:  r.Name(),
	}
	stampNow(l, r.now)
	return l, nil
}

// pickRepoURL chooses the most repository-like URL from PyPI project_urls,
// preferring keys that name a source/repository, then any forge URL, then the
// home page.
func pickRepoURL(projectURLs map[string]string, homePage string) string {
	preferredKeys := []string{"source", "source code", "repository", "code", "github", "git"}
	for _, want := range preferredKeys {
		for k, v := range projectURLs {
			if strings.Contains(strings.ToLower(k), want) && isForgeURL(v) {
				return normalizeRepoURL(v)
			}
		}
	}
	for _, v := range projectURLs {
		if isForgeURL(v) {
			return normalizeRepoURL(v)
		}
	}
	if isForgeURL(homePage) {
		return normalizeRepoURL(homePage)
	}
	return ""
}

// forgeHostRE matches the common source-forge hosts whose URLs are repositories.
var forgeHostRE = regexp.MustCompile(`(?i)://(www\.)?(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|sr\.ht|gitea\.[^/]+)/`)

func isForgeURL(u string) bool {
	return forgeHostRE.MatchString(u)
}

// --- go ---------------------------------------------------------------------

// GoResolver resolves provenance for Go modules from the module path and version.
// The module path is the authoritative VCS location (the proxy and checksum DB
// guarantee the bytes match); the commit is recovered from a pseudo-version.
type GoResolver struct {
	now func() time.Time
}

// NewGoResolver constructs a Go module resolver. It needs no network access:
// everything is derivable from the module coordinate.
func NewGoResolver() *GoResolver { return &GoResolver{now: time.Now} }

// Name implements Resolver.
func (r *GoResolver) Name() string { return "go-module" }

// pseudoVersionRE captures the 12-hex commit prefix embedded in a Go
// pseudo-version, e.g. "v0.0.0-20210101000000-abcdef123456".
var pseudoVersionRE = regexp.MustCompile(`-([0-9a-f]{12})$`)

// Resolve implements Resolver.
func (r *GoResolver) Resolve(_ context.Context, art Artifact) (*Link, error) {
	repo := repoFromModulePath(art.Name)
	if repo == "" {
		return nil, ErrNoProvenance
	}
	l := &Link{
		Artifact:      art,
		RepositoryURL: repo,
		Confidence:    ConfidenceClaimed,
		ResolverName:  r.Name(),
	}
	if m := pseudoVersionRE.FindStringSubmatch(art.Version); m != nil {
		l.CommitSHA = m[1]
	}
	stampNow(l, r.now)
	return l, nil
}

// repoFromModulePath maps a module path to its repository root URL. It handles
// the well-known forges (where the repo is host/owner/repo) and major-version
// suffixes (".../v2"). Vanity import paths that are not on a known forge are not
// resolved, since their VCS root is not derivable without a meta fetch.
func repoFromModulePath(mod string) string {
	mod = strings.TrimSpace(mod)
	if mod == "" {
		return ""
	}
	// Strip a trailing major-version element ("/v2", "/v3", ...).
	parts := strings.Split(mod, "/")
	if n := len(parts); n > 0 && len(parts[n-1]) >= 2 && parts[n-1][0] == 'v' && isAllDigits(parts[n-1][1:]) {
		parts = parts[:n-1]
	}
	if len(parts) < 3 {
		return ""
	}
	host := parts[0]
	switch host {
	case "github.com", "gitlab.com", "bitbucket.org", "codeberg.org":
		return "https://" + strings.Join(parts[:3], "/")
	}
	// gopkg.in/pkg.v3 → github mirror is not safely derivable; skip.
	return ""
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// verifyAndExtract verifies a Sigstore bundle, enforces the subject-digest
// binding when a digest is known, and builds a Link from the SLSA source. It
// returns nil when the bundle does not verify, does not bind, or carries no
// usable source — so the caller can try the next signal.
func verifyAndExtract(v *Verifier, bundle []byte, art Artifact, resolver string, now func() time.Time) *Link {
	if v == nil {
		return nil
	}
	att, err := v.VerifyBundle(bundle)
	if err != nil {
		return nil
	}
	// Binding: when we know the artifact's content digest, the attestation MUST
	// be about that exact content. Without this an attacker substitutes a valid
	// attestation for a different, benign artifact.
	if art.Digest != "" && !att.Statement.BindsDigest(art.Digest) {
		return nil
	}
	src, ok := att.Statement.sourceRef()
	if !ok {
		return nil
	}
	l := &Link{
		Artifact:          art,
		RepositoryURL:     src.RepositoryURL,
		CommitSHA:         src.CommitSHA,
		BuilderID:         src.BuilderID,
		Confidence:        att.confidence(),
		ResolverName:      resolver,
		PredicateType:     att.Statement.PredicateType,
		SignerIdentity:    att.SignerIdentity,
		SignatureVerified: att.SignatureValid,
		ChainTrusted:      att.ChainTrusted,
		Attestation:       att.Raw,
	}
	stampNow(l, now)
	return l
}
