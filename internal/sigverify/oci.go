package sigverify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// RegistryClient is the minimal Docker Registry v2 surface the OCI source needs
// to discover and fetch cosign signature/attestation artifacts. The docker
// backend (internal/backends/docker) satisfies it, so the gate reuses the
// proxy's authenticated, pooled upstream client and its digest verification.
type RegistryClient interface {
	Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error)
	Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error)
}

// maxSigArtifactBytes bounds how much of a signature manifest/blob is read, so a
// hostile or misconfigured registry cannot exhaust memory through the gate.
const maxSigArtifactBytes = 4 << 20 // 4 MiB

// ociManifestAccept lists the manifest media types the registry may return for a
// cosign signature/attestation/referrers request.
var ociManifestAccept = strings.Join([]string{
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
}, ", ")

// OCISource discovers cosign signatures and SLSA attestations for an OCI image,
// via the cosign tag scheme (sha256-<hex>.sig / .att) and the OCI Referrers API.
// cosign signatures live in the same registry as the image, so the source routes
// each artifact to the registry client of the backend that served it.
type OCISource struct {
	// byBackend maps a backend name to its registry client. When the artifact's
	// backend is absent and a single client is registered, that client is used.
	byBackend map[string]RegistryClient
}

// NewOCISource constructs an OCISource over a single registry client, used for
// every artifact regardless of backend.
func NewOCISource(client RegistryClient) *OCISource {
	return &OCISource{byBackend: map[string]RegistryClient{"": client}}
}

// NewOCIRouter constructs an OCISource that routes each artifact to the registry
// client of the backend that served it (for deployments with several OCI
// upstreams).
func NewOCIRouter(clients map[string]RegistryClient) *OCISource {
	m := make(map[string]RegistryClient, len(clients))
	for name, c := range clients {
		if c != nil {
			m[name] = c
		}
	}
	return &OCISource{byBackend: m}
}

// clientFor selects the registry client for an artifact's backend, falling back
// to the sole registered client when the backend is unknown but unambiguous.
func (s *OCISource) clientFor(backend string) (RegistryClient, bool) {
	if c, ok := s.byBackend[backend]; ok {
		return c, true
	}
	if c, ok := s.byBackend[""]; ok {
		return c, true
	}
	if len(s.byBackend) == 1 {
		for _, c := range s.byBackend {
			return c, true
		}
	}
	return nil, false
}

// ociDescriptor is an OCI content descriptor (manifest list / image layers).
type ociDescriptor struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// ociManifest covers both an image manifest (Layers) and an index/referrers
// response (Manifests).
type ociManifest struct {
	MediaType    string          `json:"mediaType"`
	ArtifactType string          `json:"artifactType,omitempty"`
	Config       ociDescriptor   `json:"config"`
	Layers       []ociDescriptor `json:"layers"`
	Manifests    []ociDescriptor `json:"manifests"`
}

// Fetch implements Source. It requires the image manifest digest and walks the
// available cosign artifacts, returning all signatures and attestations found.
func (s *OCISource) Fetch(ctx context.Context, art Artifact) (*Material, error) {
	repo := strings.TrimSpace(art.Name)
	digest := strings.TrimSpace(art.Digest)
	if repo == "" || digest == "" {
		return nil, ErrNotApplicable
	}
	client, ok := s.clientFor(art.Backend)
	if !ok {
		return nil, ErrNotApplicable
	}

	material := &Material{Source: "oci-cosign"}

	// 1. OCI Referrers API: artifacts that reference the image by digest.
	if idx, err := s.fetchManifest(ctx, client, repo, digest, true); err == nil && idx != nil {
		for _, ref := range idx.Manifests {
			if ref.Digest == "" || !isCosignArtifactType(ref) {
				continue
			}
			if m, err := s.fetchManifest(ctx, client, repo, ref.Digest, false); err == nil && m != nil {
				s.extract(ctx, client, repo, m, material)
			}
		}
		if !material.IsEmpty() {
			material.Source = "oci-referrers"
		}
	}

	// 2. cosign tag scheme: sha256-<hex>.sig (signatures) and .att (attestations).
	if material.IsEmpty() {
		for _, tag := range cosignTags(digest) {
			m, err := s.fetchManifest(ctx, client, repo, tag, false)
			if err != nil || m == nil {
				continue
			}
			s.extract(ctx, client, repo, m, material)
		}
	}

	if material.IsEmpty() {
		return nil, nil
	}
	return material, nil
}

// extract walks a cosign manifest's layers and classifies each as a signature
// (carries the cosign signature annotation) or a DSSE attestation (the blob is a
// DSSE envelope), accumulating into material.
func (s *OCISource) extract(ctx context.Context, client RegistryClient, repo string, m *ociManifest, material *Material) {
	for _, layer := range m.Layers {
		if layer.Digest == "" {
			continue
		}
		blob, err := s.fetchBlob(ctx, client, repo, layer.Digest)
		if err != nil {
			continue
		}
		leaf, chain, bundle := certBundleFromAnnotations(layer.Annotations)

		if sigB64 := layer.Annotations[annoSignature]; sigB64 != "" {
			sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
			if err != nil {
				continue
			}
			material.Signatures = append(material.Signatures, SimpleSignature{
				Payload:     blob,
				Signature:   sig,
				Cert:        leaf,
				Chain:       chain,
				RekorBundle: bundle,
			})
			continue
		}

		// Otherwise attempt to parse the blob as a DSSE attestation envelope.
		var env Envelope
		if json.Unmarshal(blob, &env) == nil && env.Payload != "" && len(env.Signatures) > 0 {
			material.Attestations = append(material.Attestations, DSSEAttestation{
				Envelope:    &env,
				Cert:        leaf,
				Chain:       chain,
				RekorBundle: bundle,
			})
		}
	}
}

// fetchManifest fetches a manifest (or index, for referrers) by tag or digest and
// decodes it. referrers selects the /referrers/<digest> endpoint.
func (s *OCISource) fetchManifest(ctx context.Context, client RegistryClient, repo, ref string, referrers bool) (*ociManifest, error) {
	var path string
	if referrers {
		path = "/v2/" + repo + "/referrers/" + ref
	} else {
		path = "/v2/" + repo + "/manifests/" + ref
	}
	body, err := s.get(ctx, client, path, ociManifestAccept)
	if err != nil {
		return nil, err
	}
	var m ociManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("sigverify/oci: decoding manifest %s: %w", ref, err)
	}
	return &m, nil
}

// fetchBlob fetches a content blob by digest.
func (s *OCISource) fetchBlob(ctx context.Context, client RegistryClient, repo, digest string) ([]byte, error) {
	return s.get(ctx, client, "/v2/"+repo+"/blobs/"+digest, "")
}

// get performs a Resolve+Fetch through the registry client and reads the bounded
// body. A non-2xx upstream status is surfaced as an error.
func (s *OCISource) get(ctx context.Context, client RegistryClient, path, accept string) ([]byte, error) {
	req := &backends.Request{
		Method: http.MethodGet,
		Path:   path,
		Query:  url.Values{},
		Header: http.Header{},
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resolved, err := client.Resolve(ctx, req)
	if err != nil {
		return nil, err
	}
	result, err := client.Fetch(ctx, resolved)
	if err != nil {
		return nil, err
	}
	if result.Content == nil {
		return nil, fmt.Errorf("sigverify/oci: empty response for %s", path)
	}
	defer result.Content.Close()
	return io.ReadAll(io.LimitReader(result.Content, maxSigArtifactBytes))
}

// cosignTags returns the cosign signature and attestation tags for an image
// digest "sha256:<hex>": "sha256-<hex>.sig" and "sha256-<hex>.att".
func cosignTags(digest string) []string {
	algo, hex, ok := strings.Cut(digest, ":")
	if !ok || algo == "" || hex == "" {
		return nil
	}
	prefix := algo + "-" + hex
	return []string{prefix + ".sig", prefix + ".att"}
}

// isCosignArtifactType reports whether a referrers descriptor is a cosign
// signature or attestation artifact (by artifactType or media type).
func isCosignArtifactType(d ociDescriptor) bool {
	t := strings.ToLower(d.ArtifactType + " " + d.MediaType)
	return strings.Contains(t, "cosign") ||
		strings.Contains(t, "sigstore") ||
		strings.Contains(t, "in-toto") ||
		strings.Contains(t, "dsse")
}
