package buildprov

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrNotApplicable signals that the gate does not apply to an artifact (no source
// handles its ecosystem, or the resource is not a verifiable subject). The caller
// treats it as "skip" rather than a verification failure.
var ErrNotApplicable = errors.New("buildprov: gate not applicable to artifact")

// HTTPDoer is the minimal HTTP surface the registry sources need. The standard
// *http.Client and the proxy's outbound client satisfy it.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Source discovers inbound build-provenance attestations for an artifact. It is
// the only registry/HTTP-aware part of the gate, kept behind an interface so the
// verification core stays exhaustively unit-testable with fixtures.
type Source interface {
	// Fetch returns the discovered provenance material for an artifact, nil when
	// the artifact simply has no published provenance, or ErrNotApplicable when the
	// source does not handle the artifact's ecosystem.
	Fetch(ctx context.Context, art Artifact) (*Material, error)
}

// fetchDocument GETs rawURL and returns its (bounded) body. A 404 yields
// (nil, nil): the artifact simply has no published provenance.
func fetchDocument(ctx context.Context, doer HTTPDoer, rawURL, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := doer.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("attestations request returned status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxAttestationBytes))
}

// NPMSource discovers npm provenance: the Sigstore bundle npm attaches to a
// package version published with provenance, served at
// "/-/npm/v1/attestations/<name>@<version>".
type NPMSource struct {
	doer HTTPDoer
	base string
}

// NewNPMSource constructs an NPMSource for a registry rooted at baseURL (e.g.
// "https://registry.npmjs.org").
func NewNPMSource(doer HTTPDoer, baseURL string) *NPMSource {
	return &NPMSource{doer: doer, base: strings.TrimRight(baseURL, "/")}
}

// Fetch implements Source for npm.
func (s *NPMSource) Fetch(ctx context.Context, art Artifact) (*Material, error) {
	if s == nil || s.doer == nil {
		return nil, ErrNotApplicable
	}
	if art.Name == "" || art.Version == "" {
		return nil, ErrNotApplicable
	}
	rawURL := s.base + "/-/npm/v1/attestations/" + art.Name + "@" + art.Version
	body, err := fetchDocument(ctx, s.doer, rawURL, "")
	if err != nil {
		return nil, fmt.Errorf("buildprov/npm: %w", err)
	}
	if body == nil {
		return nil, nil
	}
	atts, err := ParseAttestations(body)
	if err != nil {
		return nil, fmt.Errorf("buildprov/npm: %w", err)
	}
	if len(atts) == 0 {
		return nil, nil
	}
	return &Material{Source: "npm-provenance", Attestations: atts}, nil
}

// GitHubSource discovers GitHub artifact attestations: the in-toto SLSA
// provenance served at "/repos/{owner}/{repo}/attestations/{digest}". It needs
// both the artifact's content digest and a source-repository hint (the owner/repo
// to query); absent the hint it is not applicable.
type GitHubSource struct {
	doer    HTTPDoer
	apiBase string
	token   string
}

// NewGitHubSource constructs a GitHubSource. apiBase defaults to
// "https://api.github.com"; token, when set, authenticates the API request (for
// private repositories / higher rate limits).
func NewGitHubSource(doer HTTPDoer, apiBase, token string) *GitHubSource {
	base := strings.TrimRight(strings.TrimSpace(apiBase), "/")
	if base == "" {
		base = "https://api.github.com"
	}
	return &GitHubSource{doer: doer, apiBase: base, token: strings.TrimSpace(token)}
}

// Fetch implements Source for GitHub artifact attestations.
func (s *GitHubSource) Fetch(ctx context.Context, art Artifact) (*Material, error) {
	if s == nil || s.doer == nil {
		return nil, ErrNotApplicable
	}
	if art.Digest == "" {
		return nil, ErrNotApplicable
	}
	owner, repo, ok := githubOwnerRepo(art.RepositoryURL)
	if !ok {
		// Fall back to the claimed association's repository, if any.
		owner, repo, ok = githubOwnerRepo(art.Claim.RepositoryURL)
	}
	if !ok {
		return nil, ErrNotApplicable
	}
	rawURL := fmt.Sprintf("%s/repos/%s/%s/attestations/%s", s.apiBase, owner, repo, url.PathEscape(art.Digest))
	body, err := fetchDocument(ctx, s.doer, rawURL, s.token)
	if err != nil {
		return nil, fmt.Errorf("buildprov/github: %w", err)
	}
	if body == nil {
		return nil, nil
	}
	atts, err := ParseAttestations(body)
	if err != nil {
		return nil, fmt.Errorf("buildprov/github: %w", err)
	}
	if len(atts) == 0 {
		return nil, nil
	}
	return &Material{Source: "github-attestations", Forge: ForgeGitHub, Attestations: atts}, nil
}

// githubOwnerRepo extracts the owner and repository from a GitHub repository URL
// (https://github.com/owner/repo[.git], git@github.com:owner/repo, etc.).
func githubOwnerRepo(repoURL string) (owner, repo string, ok bool) {
	u := strings.TrimSpace(repoURL)
	if u == "" {
		return "", "", false
	}
	u = strings.TrimPrefix(u, "git+")
	u = strings.TrimPrefix(u, "ssh://")
	u = strings.TrimSuffix(u, ".git")
	// Normalize scp-like syntax git@github.com:owner/repo.
	if strings.HasPrefix(u, "git@github.com:") {
		u = "https://github.com/" + strings.TrimPrefix(u, "git@github.com:")
	}
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if !strings.HasPrefix(u, "github.com/") {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(u, "github.com/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// MultiSource tries each Source in order, returning the first that yields
// material (or a hard error). Sources that report ErrNotApplicable or no material
// are skipped. It lets the gate consult the npm source for npm artifacts and the
// GitHub source for any artifact carrying a GitHub repository hint.
type MultiSource struct {
	sources []Source
}

// NewMultiSource constructs a MultiSource from the given (non-nil) sources.
func NewMultiSource(sources ...Source) *MultiSource {
	out := make([]Source, 0, len(sources))
	for _, s := range sources {
		if s != nil {
			out = append(out, s)
		}
	}
	return &MultiSource{sources: out}
}

// Fetch implements Source.
func (m *MultiSource) Fetch(ctx context.Context, art Artifact) (*Material, error) {
	if m == nil || len(m.sources) == 0 {
		return nil, ErrNotApplicable
	}
	applicable := false
	for _, s := range m.sources {
		mat, err := s.Fetch(ctx, art)
		if err != nil {
			if errors.Is(err, ErrNotApplicable) {
				continue
			}
			return nil, err
		}
		applicable = true
		if !mat.IsEmpty() {
			return mat, nil
		}
	}
	if !applicable {
		return nil, ErrNotApplicable
	}
	return nil, nil
}
