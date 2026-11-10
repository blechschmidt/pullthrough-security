package buildprov

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// This file adds attestation-discovery Sources for GitLab and Bitbucket,
// broadening the gate beyond its original GitHub/npm centricity. Both implement
// the same Source interface the gate consumes, so the verification core, the
// package-to-commit cross-check, the findings, and the admission gating are
// reused unchanged. Each stamps Material.Forge so the Service verifies the
// discovered attestations against that forge's trust material (see forge.go).

// GitLabSource discovers GitLab CI/CD build-provenance attestations. A GitLab
// pipeline that publishes SLSA provenance exposes the attestation document for a
// built artifact's content digest; this source fetches it from the GitLab API
// using the project path derived from the artifact's source-repository hint.
//
// The discovery path is "{apiBase}/api/v4/projects/{url-encoded-path}/
// attestations/{digest}". The project path is the full namespace path
// (group/subgroup/project), URL-encoded per the GitLab API convention. apiBase
// defaults to "https://gitlab.com"; host defaults to "gitlab.com" and is the
// host a repository hint must match (set both for a self-hosted instance).
type GitLabSource struct {
	doer    HTTPDoer
	apiBase string
	token   string
	host    string
}

// NewGitLabSource constructs a GitLabSource. apiBase defaults to
// "https://gitlab.com" and host to "gitlab.com"; token, when set, authenticates
// the API request. For a self-hosted GitLab set apiBase/host to the instance.
func NewGitLabSource(doer HTTPDoer, apiBase, host, token string) *GitLabSource {
	base := strings.TrimRight(strings.TrimSpace(apiBase), "/")
	if base == "" {
		base = "https://gitlab.com"
	}
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		h = "gitlab.com"
	}
	return &GitLabSource{doer: doer, apiBase: base, host: h, token: strings.TrimSpace(token)}
}

// Fetch implements Source for GitLab attestations.
func (s *GitLabSource) Fetch(ctx context.Context, art Artifact) (*Material, error) {
	if s == nil || s.doer == nil {
		return nil, ErrNotApplicable
	}
	if art.Digest == "" {
		return nil, ErrNotApplicable
	}
	path, ok := forgeRepoPath(art.RepositoryURL, s.host)
	if !ok {
		path, ok = forgeRepoPath(art.Claim.RepositoryURL, s.host)
	}
	if !ok {
		return nil, ErrNotApplicable
	}
	rawURL := fmt.Sprintf("%s/api/v4/projects/%s/attestations/%s",
		s.apiBase, url.PathEscape(path), url.PathEscape(art.Digest))
	body, err := fetchDocument(ctx, s.doer, rawURL, s.token)
	if err != nil {
		return nil, fmt.Errorf("buildprov/gitlab: %w", err)
	}
	if body == nil {
		return nil, nil
	}
	atts, err := ParseAttestations(body)
	if err != nil {
		return nil, fmt.Errorf("buildprov/gitlab: %w", err)
	}
	if len(atts) == 0 {
		return nil, nil
	}
	return &Material{Source: "gitlab-attestations", Forge: ForgeGitLab, Attestations: atts}, nil
}

// BitbucketSource discovers Bitbucket Pipelines build-provenance attestations. A
// Bitbucket pipeline that emits SLSA provenance exposes the attestation document
// for a built artifact's content digest; this source fetches it from the
// Bitbucket Cloud API using the workspace/repository derived from the artifact's
// source-repository hint.
//
// The discovery path is "{apiBase}/2.0/repositories/{workspace}/{repo}/
// attestations/{digest}". apiBase defaults to "https://api.bitbucket.org"; host
// defaults to "bitbucket.org" and is the host a repository hint must match.
type BitbucketSource struct {
	doer    HTTPDoer
	apiBase string
	token   string
	host    string
}

// NewBitbucketSource constructs a BitbucketSource. apiBase defaults to
// "https://api.bitbucket.org" and host to "bitbucket.org"; token, when set,
// authenticates the API request.
func NewBitbucketSource(doer HTTPDoer, apiBase, host, token string) *BitbucketSource {
	base := strings.TrimRight(strings.TrimSpace(apiBase), "/")
	if base == "" {
		base = "https://api.bitbucket.org"
	}
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		h = "bitbucket.org"
	}
	return &BitbucketSource{doer: doer, apiBase: base, host: h, token: strings.TrimSpace(token)}
}

// Fetch implements Source for Bitbucket attestations.
func (s *BitbucketSource) Fetch(ctx context.Context, art Artifact) (*Material, error) {
	if s == nil || s.doer == nil {
		return nil, ErrNotApplicable
	}
	if art.Digest == "" {
		return nil, ErrNotApplicable
	}
	path, ok := forgeRepoPath(art.RepositoryURL, s.host)
	if !ok {
		path, ok = forgeRepoPath(art.Claim.RepositoryURL, s.host)
	}
	if !ok {
		return nil, ErrNotApplicable
	}
	// Bitbucket addresses a repository by workspace/repo; take the first two path
	// segments (forgeRepoPath guarantees at least two).
	segs := strings.SplitN(path, "/", 3)
	workspace, repo := segs[0], segs[1]
	rawURL := fmt.Sprintf("%s/2.0/repositories/%s/%s/attestations/%s",
		s.apiBase, url.PathEscape(workspace), url.PathEscape(repo), url.PathEscape(art.Digest))
	body, err := fetchDocument(ctx, s.doer, rawURL, s.token)
	if err != nil {
		return nil, fmt.Errorf("buildprov/bitbucket: %w", err)
	}
	if body == nil {
		return nil, nil
	}
	atts, err := ParseAttestations(body)
	if err != nil {
		return nil, fmt.Errorf("buildprov/bitbucket: %w", err)
	}
	if len(atts) == 0 {
		return nil, nil
	}
	return &Material{Source: "bitbucket-attestations", Forge: ForgeBitbucket, Attestations: atts}, nil
}

// forgeRepoPath extracts the repository path (everything after the host) from a
// source-repository URL for the given forge host. It tolerates git+ / ssh:// /
// scp-like (git@host:path) forms, embedded credentials, a ".git" suffix, and a
// trailing "@<ref>" pin, and requires at least two path segments (so a bare host
// or a single-segment path is rejected). The returned path preserves nested
// GitLab subgroups (group/subgroup/project).
func forgeRepoPath(repoURL, host string) (string, bool) {
	u := strings.TrimSpace(repoURL)
	if u == "" || host == "" {
		return "", false
	}
	u = strings.TrimPrefix(u, "git+")
	u = strings.TrimPrefix(u, "ssh://")
	// Normalize scp-like syntax git@host:owner/repo to host/owner/repo.
	if strings.HasPrefix(u, "git@"+host+":") {
		u = host + "/" + strings.TrimPrefix(u, "git@"+host+":")
	}
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimSuffix(u, ".git")

	// Drop embedded credentials "user[:pass]@" that precede the host.
	if slash := strings.Index(u, "/"); slash >= 0 {
		if at := strings.LastIndex(u[:slash], "@"); at >= 0 {
			u = u[at+1:]
		}
	}
	if !strings.HasPrefix(strings.ToLower(u), host+"/") {
		return "", false
	}
	rest := u[len(host)+1:]
	// Drop a trailing "@<ref>" pin in the path portion (git+https://.../repo@main).
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[:at]
	}
	rest = strings.Trim(rest, "/")
	if rest == "" {
		return "", false
	}
	segs := strings.Split(rest, "/")
	if len(segs) < 2 || segs[0] == "" || segs[1] == "" {
		return "", false
	}
	return rest, true
}
