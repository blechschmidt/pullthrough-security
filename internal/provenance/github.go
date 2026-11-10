package provenance

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// GitHubResolver resolves provenance via GitHub's build-provenance attestation
// API. Given an artifact's content digest and the source repository it claims to
// come from, it fetches the signed attestations GitHub stores for that digest:
//
//	GET {apiBase}/repos/{owner}/{repo}/attestations/{algo}:{digest}
//
// Each returned attestation is a Sigstore bundle; it is signature-verified and
// its subject digest is checked against the artifact's digest before its SLSA
// source claim is accepted.
//
// The repository to query is taken from Artifact.RepositoryURL (typically
// discovered by an ecosystem-metadata resolver). This resolver therefore enriches
// a claimed repository link into an attested commit link when GitHub has
// provenance for the exact bytes.
type GitHubResolver struct {
	doer     httpDoer
	verifier *Verifier
	apiBase  string
	token    string
	now      func() time.Time
}

// NewGitHubResolver constructs a GitHub attestation resolver. apiBase defaults to
// the public GitHub API; token (optional) raises rate limits and reaches private
// repositories.
func NewGitHubResolver(doer httpDoer, verifier *Verifier, apiBase, token string) *GitHubResolver {
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	return &GitHubResolver{
		doer:     doer,
		verifier: verifier,
		apiBase:  strings.TrimRight(apiBase, "/"),
		token:    token,
		now:      time.Now,
	}
}

// Name implements Resolver.
func (r *GitHubResolver) Name() string { return "github-attestation" }

type githubAttestationsResponse struct {
	Attestations []struct {
		Bundle json.RawMessage `json:"bundle"`
	} `json:"attestations"`
}

// Resolve implements Resolver. It requires a content digest (to query and bind)
// and a GitHub repository hint.
func (r *GitHubResolver) Resolve(ctx context.Context, art Artifact) (*Link, error) {
	if art.Digest == "" {
		return nil, ErrNoProvenance
	}
	owner, repo, ok := githubOwnerRepo(art.RepositoryURL)
	if !ok {
		return nil, ErrNoProvenance
	}

	apiURL := r.apiBase + "/repos/" + owner + "/" + repo + "/attestations/" + art.Digest
	header := http.Header{"Accept": {"application/vnd.github+json"}}
	header.Set("X-GitHub-Api-Version", "2022-11-28")
	var creds upstream.Credentials
	if r.token != "" {
		creds = upstream.Credentials{Token: r.token}
	}

	var resp githubAttestationsResponse
	if err := getJSON(ctx, r.doer, creds, apiURL, header, &resp); err != nil {
		return nil, ErrNoProvenance
	}
	for _, a := range resp.Attestations {
		if len(a.Bundle) == 0 {
			continue
		}
		if link := verifyAndExtract(r.verifier, a.Bundle, art, r.Name(), r.now); link != nil {
			// Preserve the queried repository when the predicate omitted it.
			if link.RepositoryURL == "" {
				link.RepositoryURL = "https://github.com/" + owner + "/" + repo
			}
			return link, nil
		}
	}
	return nil, ErrNoProvenance
}

// githubOwnerRepo extracts the owner and repository from a GitHub repository URL.
func githubOwnerRepo(repoURL string) (owner, repo string, ok bool) {
	u := normalizeRepoURL(repoURL)
	const host = "https://github.com/"
	if !strings.HasPrefix(u, host) {
		return "", "", false
	}
	path := strings.Trim(strings.TrimPrefix(u, host), "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
