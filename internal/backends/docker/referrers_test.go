package docker

import (
	"context"
	"net/http"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

func TestParseReferenceReferrers(t *testing.T) {
	subject := sha256Digest([]byte("image-manifest"))
	ref, ok := parseReference("/v2/library/nginx/referrers/" + subject)
	if !ok {
		t.Fatal("parseReference returned ok=false for a referrers path")
	}
	if ref.kind != refReferrers {
		t.Errorf("kind = %d, want refReferrers (%d)", ref.kind, refReferrers)
	}
	if ref.name != "library/nginx" {
		t.Errorf("name = %q, want library/nginx", ref.name)
	}
	if ref.reference != subject {
		t.Errorf("reference = %q, want %q", ref.reference, subject)
	}
	if !ref.isDigest {
		t.Error("referrers reference should be recognized as a digest")
	}
	if got := ref.scope(); got != "repository:library/nginx:pull" {
		t.Errorf("scope = %q, want repository:library/nginx:pull", got)
	}
}

func TestResolveReferrersIsLiveScopedAndUnverified(t *testing.T) {
	reg := newFakeRegistry(t)
	b := testBackend(t, reg)

	subject := sha256Digest([]byte("image-manifest"))
	path := "/v2/library/nginx/referrers/" + subject
	resolved, err := b.Resolve(context.Background(), &backends.Request{
		Method: http.MethodGet,
		Path:   path,
		Header: http.Header{"Accept": {ociIndexAccept}},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// The referrers index is mutable: it must be served live, never cached.
	if resolved.Cacheable {
		t.Error("referrers response must not be cacheable")
	}
	// The path digest identifies the subject, not the body, so no digest
	// verification is applied to the response.
	if resolved.Digest != "" {
		t.Errorf("Digest = %q, want empty (subject digest is not the body digest)", resolved.Digest)
	}
	if got := resolved.Metadata[metaKind]; got != "referrers" {
		t.Errorf("metaKind = %q, want referrers", got)
	}
	if got := resolved.Metadata[metaScope]; got != "repository:library/nginx:pull" {
		t.Errorf("metaScope = %q, want repository:library/nginx:pull", got)
	}
	if got := resolved.Metadata[metaRepo]; got != "library/nginx" {
		t.Errorf("metaRepo = %q, want library/nginx", got)
	}
	if got := resolved.Metadata[metaSubject]; got != subject {
		t.Errorf("metaSubject = %q, want %q", got, subject)
	}
}

func TestReferrersFallbackTag(t *testing.T) {
	cases := []struct {
		digest string
		want   string
		ok     bool
	}{
		{"sha256:abc123", "sha256-abc123", true},
		{"sha512:deadbeef", "sha512-deadbeef", true},
		{"", "", false},
		{"notadigest", "", false},
		{"sha256:", "", false},
		{":abc", "", false},
	}
	for _, c := range cases {
		got, ok := referrersFallbackTag(c.digest)
		if ok != c.ok || got != c.want {
			t.Errorf("referrersFallbackTag(%q) = (%q, %v), want (%q, %v)", c.digest, got, ok, c.want, c.ok)
		}
	}
}

func TestClassifyReferrer(t *testing.T) {
	cases := []struct {
		artifactType string
		mediaType    string
		want         ReferrerKind
	}{
		{"application/vnd.dev.cosign.artifact.sig.v1+json", "application/vnd.oci.image.manifest.v1+json", ReferrerSignature},
		{"application/vnd.in-toto+json", "application/vnd.oci.image.manifest.v1+json", ReferrerAttestation},
		{"application/vnd.dev.sigstore.bundle+json", "", ReferrerAttestation},
		{"https://slsa.dev/provenance/v1", "", ReferrerAttestation},
		{"application/spdx+json", "", ReferrerSBOM},
		{"application/vnd.cyclonedx+json", "", ReferrerSBOM},
		{"application/vnd.dev.cosign.artifact.sbom.v1+json", "", ReferrerSBOM},
		{"application/vnd.example.unknown", "application/octet-stream", ReferrerOther},
	}
	for _, c := range cases {
		got := classifyReferrer(c.artifactType, c.mediaType)
		if got != c.want {
			t.Errorf("classifyReferrer(%q, %q) = %v, want %v", c.artifactType, c.mediaType, got, c.want)
		}
	}
}
