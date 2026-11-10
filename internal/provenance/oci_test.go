package provenance

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// fakeRegistry serves manifests and blobs by path for the OCI resolver tests.
type fakeRegistry struct {
	objects map[string][]byte // path -> body
}

func (f *fakeRegistry) Resolve(_ context.Context, req *backends.Request) (*backends.Resolved, error) {
	return &backends.Resolved{UpstreamURL: req.Path, Metadata: map[string]string{"path": req.Path}}, nil
}

func (f *fakeRegistry) Fetch(_ context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	body, ok := f.objects[resolved.Metadata["path"]]
	if !ok {
		return &backends.FetchResult{Status: http.StatusNotFound, Content: io.NopCloser(strings.NewReader(""))}, nil
	}
	return &backends.FetchResult{Status: http.StatusOK, Content: io.NopCloser(strings.NewReader(string(body)))}, nil
}

func TestOCIResolver_CosignTag(t *testing.T) {
	id := newSigningIdentity(t, "https://github.com/acme/image/.github/workflows/build.yml@refs/heads/main")
	imageDigest := "sha256:" + strings.Repeat("a", 64)
	commit := "abcabcabcabcabcabcabcabcabcabcabcabcabca"
	envelope := id.signEnvelope(t, statementFor(imageDigest, "https://github.com/acme/image", commit))
	blobDigest := "sha256:" + strings.Repeat("b", 64)

	// The cosign ".att" manifest references one DSSE layer; the layer annotation
	// carries the signing certificate (PEM).
	certPEM := certToPEM(id.der)
	manifest := mustJSON(map[string]any{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"layers": []map[string]any{
			{
				"mediaType":   "application/vnd.dsse.envelope.v1+json",
				"digest":      blobDigest,
				"annotations": map[string]string{annoCertificate: certPEM},
			},
		},
	})

	reg := &fakeRegistry{objects: map[string][]byte{
		"/v2/acme/image/referrers/" + imageDigest:                             mustJSON(map[string]any{"manifests": []any{}}),
		"/v2/acme/image/manifests/sha256-" + strings.Repeat("a", 64) + ".att": manifest,
		"/v2/acme/image/blobs/" + blobDigest:                                  envelope,
	}}

	r := NewOCIResolver(reg, NewVerifier(id.rootPool()))
	link, err := r.Resolve(context.Background(), Artifact{Ecosystem: "oci", Name: "acme/image", Digest: imageDigest})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if link.Confidence != ConfidenceAttested {
		t.Errorf("confidence = %q, want attested", link.Confidence)
	}
	if link.CommitSHA != commit || link.RepositoryURL != "https://github.com/acme/image" {
		t.Errorf("link = %+v", link)
	}
}

func TestOCIResolver_Referrers(t *testing.T) {
	id := newSigningIdentity(t, "")
	imageDigest := "sha256:" + strings.Repeat("c", 64)
	commit := "fedfedfedfedfedfedfedfedfedfedfedfedfedf"
	bundle := id.signBundle(t, statementFor(imageDigest, "https://github.com/acme/image", commit))
	bundleDigest := "sha256:" + strings.Repeat("d", 64)
	attManifestDigest := "sha256:" + strings.Repeat("e", 64)

	attManifest := mustJSON(map[string]any{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"layers": []map[string]any{
			{"mediaType": "application/vnd.in-toto+json", "digest": bundleDigest},
		},
	})
	referrers := mustJSON(map[string]any{
		"manifests": []map[string]any{
			{"artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json", "digest": attManifestDigest},
		},
	})

	reg := &fakeRegistry{objects: map[string][]byte{
		"/v2/acme/image/referrers/" + imageDigest:       referrers,
		"/v2/acme/image/manifests/" + attManifestDigest: attManifest,
		"/v2/acme/image/blobs/" + bundleDigest:          bundle,
	}}

	r := NewOCIResolver(reg, NewVerifier(id.rootPool()))
	link, err := r.Resolve(context.Background(), Artifact{Ecosystem: "oci", Name: "acme/image", Digest: imageDigest})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if link.CommitSHA != commit {
		t.Errorf("commit = %q, want %q", link.CommitSHA, commit)
	}
}

func TestOCIResolver_NoAttestation(t *testing.T) {
	reg := &fakeRegistry{objects: map[string][]byte{}}
	r := NewOCIResolver(reg, NewVerifier(nil))
	_, err := r.Resolve(context.Background(), Artifact{
		Ecosystem: "oci", Name: "acme/image", Digest: "sha256:" + strings.Repeat("f", 64),
	})
	if err == nil {
		t.Error("expected ErrNoProvenance when no attestation exists")
	}
}

func TestCosignAttTag(t *testing.T) {
	tag, ok := cosignAttTag("sha256:deadbeef")
	if !ok || tag != "sha256-deadbeef.att" {
		t.Errorf("cosignAttTag = %q, %v", tag, ok)
	}
	if _, ok := cosignAttTag("notadigest"); ok {
		t.Error("cosignAttTag accepted a malformed digest")
	}
}

func certToPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
