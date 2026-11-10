//go:build integration
// +build integration

// Integration test for OCI Distribution v1.1 Referrers API support in the Docker
// backend (Task 116). It stands up a hermetic mock registry that serves a
// referrers index for an image subject digest — a cosign signature, an in-toto
// DSSE attestation, and an attached SPDX SBOM — and verifies that the backend:
//
//   - lists and classifies the referrers (Referrers),
//   - fetches and digest-verifies the referenced manifests and blobs and caches
//     them in the shared content-addressable store (FetchReferrerBlob +
//     loadThroughCache),
//   - routes the discovered signature/attestation referrers to the sigstore/
//     cosign verification gate's OCI source (Task 23), and
//   - falls back to the referrers fallback-tag schema when a registry does not
//     implement the Referrers API endpoint.
//
// Gated behind the `integration` build tag (mirroring the other backends'
// convention) though it needs no network. Run with:
//
//	go test -tags integration ./internal/backends/docker/
package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// referrersRegistry is a mock Docker Registry v2 that serves a referrers index,
// the referrer manifests (by digest), and their blobs. It enforces the bearer
// handshake and can emulate a registry with or without the Referrers API.
type referrersRegistry struct {
	srv  *httptest.Server
	repo string

	subject string // the image manifest digest the referrers reference

	// referrer manifest digests, exposed so assertions can target them.
	sigManifestDigest  string
	attManifestDigest  string
	sbomManifestDigest string
	sbomBlobDigest     string
	sbomBlob           []byte

	manifests map[string]mockDoc // digest -> manifest doc
	blobs     map[string]mockDoc // digest -> blob doc

	referrersIndex []byte // the index body (served by API and/or fallback tag)

	referrersAPIEnabled bool // false -> /referrers/ 404s, forcing the fallback tag

	tokenFetches int64
}

type mockDoc struct {
	contentType string
	body        []byte
}

const refTestToken = "REF-TEST-TOKEN"

func newReferrersRegistry(t *testing.T, referrersAPIEnabled bool) *referrersRegistry {
	t.Helper()
	reg := &referrersRegistry{
		repo:                "library/app",
		subject:             sha256Digest([]byte("the-image-manifest-bytes")),
		manifests:           map[string]mockDoc{},
		blobs:               map[string]mockDoc{},
		referrersAPIEnabled: referrersAPIEnabled,
	}

	// --- Signature referrer (cosign): a manifest whose single layer carries the
	// cosign signature annotation; the layer blob is the signed payload. ---
	sigPayload := []byte(`{"critical":{"identity":{"docker-reference":"library/app"}}}`)
	sigBlobDigest := reg.addBlob("application/vnd.dev.cosign.simplesigning.v1+json", sigPayload)
	sigManifest := reg.ociManifest(ociDesc{
		MediaType:   "application/vnd.dev.cosign.simplesigning.v1+json",
		Digest:      sigBlobDigest,
		Size:        int64(len(sigPayload)),
		Annotations: map[string]string{annoSignatureTest: base64.StdEncoding.EncodeToString([]byte("fake-signature-bytes"))},
	})
	reg.sigManifestDigest = reg.addManifest("application/vnd.oci.image.manifest.v1+json", sigManifest)

	// --- Attestation referrer (in-toto DSSE): the layer blob is a DSSE envelope. ---
	stmt := []byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[{"name":"library/app"}]}`)
	envelope, _ := json.Marshal(map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(stmt),
		"signatures":  []map[string]string{{"sig": base64.StdEncoding.EncodeToString([]byte("fake-dsse-sig"))}},
	})
	attBlobDigest := reg.addBlob("application/vnd.dsse.envelope.v1+json", envelope)
	attManifest := reg.ociManifest(ociDesc{
		MediaType: "application/vnd.in-toto+json",
		Digest:    attBlobDigest,
		Size:      int64(len(envelope)),
	})
	reg.attManifestDigest = reg.addManifest("application/vnd.oci.image.manifest.v1+json", attManifest)

	// --- SBOM referrer (SPDX): the layer blob is an SPDX JSON document. ---
	reg.sbomBlob = []byte(`{"spdxVersion":"SPDX-2.3","name":"library/app","packages":[]}`)
	reg.sbomBlobDigest = reg.addBlob("application/spdx+json", reg.sbomBlob)
	sbomManifest := reg.ociManifest(ociDesc{
		MediaType: "application/spdx+json",
		Digest:    reg.sbomBlobDigest,
		Size:      int64(len(reg.sbomBlob)),
	})
	reg.sbomManifestDigest = reg.addManifest("application/spdx+json", sbomManifest)

	// --- The referrers index: descriptors for the three referrer manifests. ---
	index, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []ociDesc{
			{MediaType: "application/vnd.oci.image.manifest.v1+json", ArtifactType: "application/vnd.dev.cosign.artifact.sig.v1+json", Digest: reg.sigManifestDigest},
			{MediaType: "application/vnd.oci.image.manifest.v1+json", ArtifactType: "application/vnd.in-toto+json", Digest: reg.attManifestDigest},
			{MediaType: "application/spdx+json", ArtifactType: "application/spdx+json", Digest: reg.sbomManifestDigest},
		},
	})
	reg.referrersIndex = index

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&reg.tokenFetches, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"token":"`+refTestToken+`","expires_in":300}`)
	})
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+refTestToken {
			ref, _ := parseReference(r.URL.Path)
			ch := `Bearer realm="` + reg.srv.URL + `/token",service="ref-registry"`
			if sc := ref.scope(); sc != "" {
				ch += `,scope="` + sc + `"`
			}
			w.Header().Set("WWW-Authenticate", ch)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		reg.serve(w, r)
	})
	reg.srv = httptest.NewServer(mux)
	t.Cleanup(reg.srv.Close)
	return reg
}

// annoSignatureTest mirrors the cosign signature annotation key the sigverify
// gate recognizes (kept local to the test to avoid exporting it).
const annoSignatureTest = "dev.cosignproject.cosign/signature"

// ociDesc is the descriptor shape used to build mock index/manifest documents.
type ociDesc struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

func (reg *referrersRegistry) ociManifest(layer ociDesc) []byte {
	b, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest":    sha256Digest([]byte("config")),
			"size":      6,
		},
		"layers": []ociDesc{layer},
	})
	return b
}

func (reg *referrersRegistry) addBlob(contentType string, body []byte) string {
	d := sha256Digest(body)
	reg.blobs[d] = mockDoc{contentType: contentType, body: body}
	return d
}

func (reg *referrersRegistry) addManifest(contentType string, body []byte) string {
	d := sha256Digest(body)
	reg.manifests[d] = mockDoc{contentType: contentType, body: body}
	return d
}

func (reg *referrersRegistry) serve(w http.ResponseWriter, r *http.Request) {
	ref, ok := parseReference(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch {
	case ref.kind == refReferrers:
		if !reg.referrersAPIEnabled {
			http.Error(w, "referrers API not implemented", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		_, _ = w.Write(reg.referrersIndex)
	case ref.kind == refManifest && !ref.isDigest:
		// Fallback-tag request: serve the referrers index under the tag.
		fallback, _ := referrersFallbackTag(reg.subject)
		if !reg.referrersAPIEnabled && ref.reference == fallback {
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			_, _ = w.Write(reg.referrersIndex)
			return
		}
		http.NotFound(w, r)
	case ref.kind == refManifest:
		doc, found := reg.manifests[ref.reference]
		if !found {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", doc.contentType)
		_, _ = w.Write(doc.body)
	case ref.kind == refBlob:
		doc, found := reg.blobs[ref.reference]
		if !found {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", doc.contentType)
		_, _ = w.Write(doc.body)
	default:
		http.NotFound(w, r)
	}
}

func (reg *referrersRegistry) backend(t *testing.T) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:        "ociupstream",
		UpstreamURL: reg.srv.URL,
		Client:      upstream.NewWithHTTPClient(reg.srv.Client(), "test/1"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func TestReferrersAPIListsClassifiesAndRoutes(t *testing.T) {
	reg := newReferrersRegistry(t, true)
	b := reg.backend(t)
	ctx := context.Background()

	// --- 1. The backend lists and classifies the referrers. ---
	refs, err := b.Referrers(ctx, reg.repo, reg.subject, "")
	if err != nil {
		t.Fatalf("Referrers: %v", err)
	}
	if len(refs) != 3 {
		t.Fatalf("got %d referrers, want 3", len(refs))
	}
	byKind := map[ReferrerKind]Referrer{}
	for _, r := range refs {
		byKind[r.Kind] = r
	}
	if _, ok := byKind[ReferrerSignature]; !ok {
		t.Error("no signature referrer discovered")
	}
	if _, ok := byKind[ReferrerAttestation]; !ok {
		t.Error("no attestation referrer discovered")
	}
	sbomRef, ok := byKind[ReferrerSBOM]
	if !ok {
		t.Fatal("no SBOM referrer discovered")
	}
	if sbomRef.Digest != reg.sbomManifestDigest {
		t.Errorf("SBOM referrer digest = %q, want %q", sbomRef.Digest, reg.sbomManifestDigest)
	}

	// --- 1b. The artifactType filter narrows the result (client-side). ---
	onlySBOM, err := b.Referrers(ctx, reg.repo, reg.subject, "application/spdx+json")
	if err != nil {
		t.Fatalf("filtered Referrers: %v", err)
	}
	if len(onlySBOM) != 1 || onlySBOM[0].Kind != ReferrerSBOM {
		t.Fatalf("filtered referrers = %+v, want a single SBOM referrer", onlySBOM)
	}

	// --- 2. The attached SBOM blob is fetched, digest-verified, and cached. ---
	sbomBytes, err := b.FetchReferrerBlob(ctx, reg.repo, reg.sbomBlobDigest)
	if err != nil {
		t.Fatalf("FetchReferrerBlob(sbom): %v", err)
	}
	if string(sbomBytes) != string(reg.sbomBlob) {
		t.Errorf("SBOM blob = %q, want %q", sbomBytes, reg.sbomBlob)
	}

	c, err := cache.NewFilesystemCache(cache.FilesystemOptions{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewFilesystemCache: %v", err)
	}
	defer c.Close()
	blobPath := "/v2/" + reg.repo + "/blobs/" + reg.sbomBlobDigest
	if _, loaded, err := loadThroughCache(t, c, b, blobPath, nil); err != nil || !loaded {
		t.Fatalf("first SBOM blob load: loaded=%v err=%v (want a cache miss)", loaded, err)
	}
	if _, loaded, err := loadThroughCache(t, c, b, blobPath, nil); err != nil || loaded {
		t.Fatalf("second SBOM blob load: loaded=%v err=%v (want a cache hit)", loaded, err)
	}

	// --- 3. The discovered signature/attestation referrers reach the sigstore/
	// cosign verification gate's OCI source (Task 23). ---
	src := sigverify.NewOCISource(b)
	material, err := src.Fetch(ctx, sigverify.Artifact{
		Ecosystem: "docker",
		Backend:   "ociupstream",
		Name:      reg.repo,
		Digest:    reg.subject,
	})
	if err != nil {
		t.Fatalf("sigverify OCISource.Fetch: %v", err)
	}
	if material == nil || material.IsEmpty() {
		t.Fatal("sigverify gate discovered no material from the referrers index")
	}
	if material.Source != "oci-referrers" {
		t.Errorf("material source = %q, want oci-referrers", material.Source)
	}
	if len(material.Signatures) != 1 {
		t.Errorf("signatures = %d, want 1", len(material.Signatures))
	}
	if len(material.Attestations) != 1 {
		t.Errorf("attestations = %d, want 1", len(material.Attestations))
	}
}

func TestReferrersFallbackTagSchema(t *testing.T) {
	// A registry that does NOT implement the Referrers API: the backend must fall
	// back to the referrers fallback-tag schema and still surface the referrers.
	reg := newReferrersRegistry(t, false)
	b := reg.backend(t)
	ctx := context.Background()

	refs, err := b.Referrers(ctx, reg.repo, reg.subject, "")
	if err != nil {
		t.Fatalf("Referrers (via fallback tag): %v", err)
	}
	if len(refs) != 3 {
		t.Fatalf("got %d referrers via fallback tag, want 3", len(refs))
	}

	// The sigverify gate must also work transparently against the fallback tag.
	src := sigverify.NewOCISource(b)
	material, err := src.Fetch(ctx, sigverify.Artifact{
		Ecosystem: "docker",
		Backend:   "ociupstream",
		Name:      reg.repo,
		Digest:    reg.subject,
	})
	if err != nil {
		t.Fatalf("sigverify OCISource.Fetch (fallback): %v", err)
	}
	if material.IsEmpty() {
		t.Fatal("no material discovered via the fallback tag")
	}
	if len(material.Signatures) != 1 || len(material.Attestations) != 1 {
		t.Errorf("fallback material: sigs=%d atts=%d, want 1 and 1",
			len(material.Signatures), len(material.Attestations))
	}
}

func TestReferrersUnavailableSurfacesError(t *testing.T) {
	// A registry with neither the Referrers API nor the fallback tag: discovery
	// must surface an error (not an empty index), so callers fall through to their
	// own discovery schemes rather than concluding "no referrers".
	reg := newReferrersRegistry(t, false)
	b := reg.backend(t)

	// Query an unrelated subject: the Referrers API is disabled (404) and no
	// fallback tag is published for this digest, so neither path yields an index.
	orphan := sha256Digest([]byte("an-image-with-no-referrers"))
	if _, err := b.Referrers(context.Background(), reg.repo, orphan, ""); err == nil {
		t.Fatal("expected an error when neither the Referrers API nor the fallback tag is available")
	}
}

var _ sigverify.RegistryClient = (*Backend)(nil)
var _ backends.Backend = (*Backend)(nil)
