package provenance

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// doerFunc adapts a function to httpDoer, returning JSON bodies keyed off the URL.
type doerFunc func(url string) (int, []byte)

func (f doerFunc) Do(_ context.Context, req upstream.Request) (*upstream.Response, error) {
	status, body := f(req.URL)
	return &upstream.Response{
		Status:      status,
		Body:        io.NopCloser(bytes.NewReader(body)),
		ContentType: "application/json",
	}, nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestNPMResolver_Attested(t *testing.T) {
	id := newSigningIdentity(t, "https://github.com/acme/widget/.github/workflows/ci.yml@refs/heads/main")
	artifact := []byte("tarball")
	subjectDigest := digestOf(artifact)
	commit := "abc1234567890abc1234567890abc1234567890a"
	bundle := id.signBundle(t, statementFor(subjectDigest, "https://github.com/acme/widget", commit))

	doer := doerFunc(func(url string) (int, []byte) {
		if strings.Contains(url, "/attestations/") {
			return 200, mustJSON(map[string]any{
				"attestations": []map[string]any{
					{"predicateType": predicateSLSAv1, "bundle": json.RawMessage(bundle)},
				},
			})
		}
		return 404, nil
	})

	r := NewNPMResolver(doer, NewVerifier(id.rootPool()), "https://registry.npmjs.org", upstream.Credentials{})
	link, err := r.Resolve(context.Background(), Artifact{
		Ecosystem: "npm", Name: "widget", Version: "1.0.0", Digest: subjectDigest,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if link.Confidence != ConfidenceAttested {
		t.Errorf("confidence = %q, want attested", link.Confidence)
	}
	if link.CommitSHA != commit {
		t.Errorf("commit = %q, want %q", link.CommitSHA, commit)
	}
	if link.RepositoryURL != "https://github.com/acme/widget" {
		t.Errorf("repo = %q", link.RepositoryURL)
	}
}

func TestNPMResolver_AttestationDigestMismatchRejected(t *testing.T) {
	id := newSigningIdentity(t, "")
	// Attestation is about a DIFFERENT artifact than the one being resolved.
	bundle := id.signBundle(t, statementFor(digestOf([]byte("other")), "https://github.com/evil/repo", "dead"))

	doer := doerFunc(func(url string) (int, []byte) {
		if strings.Contains(url, "/attestations/") {
			return 200, mustJSON(map[string]any{
				"attestations": []map[string]any{{"bundle": json.RawMessage(bundle)}},
			})
		}
		// Packument fallback also has no repository → no link at all.
		return 404, nil
	})

	r := NewNPMResolver(doer, NewVerifier(id.rootPool()), "", upstream.Credentials{})
	_, err := r.Resolve(context.Background(), Artifact{
		Ecosystem: "npm", Name: "widget", Version: "1.0.0", Digest: digestOf([]byte("the-real-artifact")),
	})
	if err == nil {
		t.Fatal("expected ErrNoProvenance: attestation binds a different digest and must be rejected")
	}
}

func TestNPMResolver_PackumentFallback(t *testing.T) {
	doer := doerFunc(func(url string) (int, []byte) {
		if strings.Contains(url, "/attestations/") {
			return 404, nil
		}
		return 200, mustJSON(map[string]any{
			"repository": map[string]any{"type": "git", "url": "git+https://github.com/acme/widget.git"},
		})
	})
	r := NewNPMResolver(doer, NewVerifier(nil), "", upstream.Credentials{})
	link, err := r.Resolve(context.Background(), Artifact{Ecosystem: "npm", Name: "widget", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if link.Confidence != ConfidenceClaimed {
		t.Errorf("confidence = %q, want claimed", link.Confidence)
	}
	if link.RepositoryURL != "https://github.com/acme/widget" {
		t.Errorf("repo = %q", link.RepositoryURL)
	}
}

func TestNPMRepositoryShorthand(t *testing.T) {
	cases := map[string]string{
		`"github:acme/widget"`:                     "https://github.com/acme/widget",
		`"acme/widget"`:                            "https://github.com/acme/widget",
		`{"url":"https://gitlab.com/acme/widget"}`: "https://gitlab.com/acme/widget",
	}
	for raw, want := range cases {
		if got := parseNPMRepository(json.RawMessage(raw)); got != want {
			t.Errorf("parseNPMRepository(%s) = %q, want %q", raw, got, want)
		}
	}
}

func TestPyPIResolver(t *testing.T) {
	doer := doerFunc(func(url string) (int, []byte) {
		return 200, mustJSON(map[string]any{
			"info": map[string]any{
				"home_page": "https://requests.readthedocs.io",
				"project_urls": map[string]string{
					"Documentation": "https://requests.readthedocs.io",
					"Source":        "https://github.com/psf/requests",
				},
			},
		})
	})
	r := NewPyPIResolver(doer, "https://pypi.org", upstream.Credentials{})
	link, err := r.Resolve(context.Background(), Artifact{Ecosystem: "pip", Name: "requests", Version: "2.31.0"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if link.RepositoryURL != "https://github.com/psf/requests" {
		t.Errorf("repo = %q, want the Source project URL", link.RepositoryURL)
	}
	if link.Confidence != ConfidenceClaimed {
		t.Errorf("confidence = %q, want claimed", link.Confidence)
	}
}

func TestGoResolver(t *testing.T) {
	r := NewGoResolver()

	// Pseudo-version → repo + short commit.
	link, err := r.Resolve(context.Background(), Artifact{
		Ecosystem: "go", Name: "github.com/acme/widget", Version: "v0.0.0-20210101000000-abcdef123456",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if link.RepositoryURL != "https://github.com/acme/widget" {
		t.Errorf("repo = %q", link.RepositoryURL)
	}
	if link.CommitSHA != "abcdef123456" {
		t.Errorf("commit = %q, want the pseudo-version hash", link.CommitSHA)
	}

	// Major-version suffix is stripped; tagged version has no commit.
	link2, err := r.Resolve(context.Background(), Artifact{
		Ecosystem: "go", Name: "github.com/acme/widget/v2", Version: "v2.1.0",
	})
	if err != nil {
		t.Fatalf("Resolve v2: %v", err)
	}
	if link2.RepositoryURL != "https://github.com/acme/widget" {
		t.Errorf("v2 repo = %q", link2.RepositoryURL)
	}
	if link2.CommitSHA != "" {
		t.Errorf("tagged version should have no commit, got %q", link2.CommitSHA)
	}

	// A vanity/non-forge module path is not resolvable.
	if _, err := r.Resolve(context.Background(), Artifact{Ecosystem: "go", Name: "example.com/x", Version: "v1.0.0"}); err == nil {
		t.Error("expected ErrNoProvenance for a non-forge module path")
	}
}

func TestGitHubResolver(t *testing.T) {
	id := newSigningIdentity(t, "https://github.com/acme/widget/.github/workflows/release.yml@refs/tags/v1")
	artifact := []byte("blob")
	subjectDigest := digestOf(artifact)
	commit := "0123456789012345678901234567890123456789"
	bundle := id.signBundle(t, statementFor(subjectDigest, "https://github.com/acme/widget", commit))

	doer := doerFunc(func(url string) (int, []byte) {
		if strings.Contains(url, "/repos/acme/widget/attestations/") {
			return 200, mustJSON(map[string]any{
				"attestations": []map[string]any{{"bundle": json.RawMessage(bundle)}},
			})
		}
		return 404, nil
	})
	r := NewGitHubResolver(doer, NewVerifier(id.rootPool()), "", "")
	link, err := r.Resolve(context.Background(), Artifact{
		Ecosystem: "oci", Name: "widget", Digest: subjectDigest, RepositoryURL: "https://github.com/acme/widget",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if link.Confidence != ConfidenceAttested || link.CommitSHA != commit {
		t.Errorf("link = %+v, want attested with commit %s", link, commit)
	}
}

func TestGitHubResolver_RequiresRepoHint(t *testing.T) {
	r := NewGitHubResolver(doerFunc(func(string) (int, []byte) { return 200, nil }), NewVerifier(nil), "", "")
	if _, err := r.Resolve(context.Background(), Artifact{Digest: "sha256:aa"}); err == nil {
		t.Error("expected ErrNoProvenance without a repository hint")
	}
}
