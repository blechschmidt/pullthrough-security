package provenance

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// OCIResolver resolves provenance for OCI images and other OCI artifacts by
// discovering and verifying their Sigstore/cosign attestations, then extracting
// the SLSA source repository and commit.
//
// Two discovery mechanisms are tried, covering both the modern and the legacy
// cosign storage conventions:
//
//   - OCI 1.1 Referrers API: GET /v2/<name>/referrers/<digest> lists manifests
//     that reference the image as their subject; attestation manifests carry the
//     in-toto/DSSE artifactType.
//   - cosign tag scheme: the image digest "sha256:<hex>" has a companion tag
//     "sha256-<hex>.att" whose manifest's layers are the DSSE attestations.
//
// Registry access (auth handshake, caching, digest verification) is delegated to
// the existing Docker/OCI pull-through Backend (Task 5) via the RegistryFetcher
// interface, so this resolver does not re-implement the registry client.
//
// SECURITY: every attestation is signature-verified and, critically, its in-toto
// subject digest is checked to equal the image digest being resolved. An
// attestation that verifies but describes a different image is rejected.
type OCIResolver struct {
	fetcher  RegistryFetcher
	verifier *Verifier
	now      func() time.Time
}

// RegistryFetcher is the subset of backends.Backend (the Docker/OCI backend) the
// OCI resolver needs: resolve a Registry v2 path and stream its bytes.
type RegistryFetcher interface {
	Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error)
	Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error)
}

// NewOCIResolver constructs an OCI attestation resolver backed by a registry
// fetcher (typically the Docker backend for the same upstream).
func NewOCIResolver(fetcher RegistryFetcher, verifier *Verifier) *OCIResolver {
	return &OCIResolver{fetcher: fetcher, verifier: verifier, now: time.Now}
}

// Name implements Resolver.
func (r *OCIResolver) Name() string { return "oci-cosign" }

// manifest media types we accept when fetching an image/index/attestation
// manifest.
const ociManifestAccept = "application/vnd.oci.image.index.v1+json," +
	"application/vnd.docker.distribution.manifest.list.v2+json," +
	"application/vnd.oci.image.manifest.v1+json," +
	"application/vnd.docker.distribution.manifest.v2+json"

// ociDescriptor is an OCI content descriptor.
type ociDescriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// ociIndex is an image index / referrers response.
type ociIndex struct {
	Manifests []ociDescriptor `json:"manifests"`
}

// ociManifest is an image/artifact manifest.
type ociManifest struct {
	MediaType string          `json:"mediaType"`
	Config    ociDescriptor   `json:"config"`
	Layers    []ociDescriptor `json:"layers"`
}

// cosign annotation keys carrying the signing certificate (PEM) on a DSSE layer.
const (
	annoCertificate = "dev.sigstore.cosign/certificate"
	annoChain       = "dev.sigstore.cosign/chain"
)

// Resolve implements Resolver.
func (r *OCIResolver) Resolve(ctx context.Context, art Artifact) (*Link, error) {
	repo := art.Name
	digest := art.Digest
	if repo == "" || digest == "" {
		return nil, ErrNoProvenance
	}

	// 1. Referrers API.
	if idx, err := r.fetchIndex(ctx, "/v2/"+repo+"/referrers/"+digest); err == nil {
		for _, m := range idx.Manifests {
			if !isAttestationArtifact(m.ArtifactType, m.MediaType) {
				continue
			}
			if link := r.fromManifestRef(ctx, repo, m.Digest, art); link != nil {
				return link, nil
			}
		}
	}

	// 2. cosign ".att" tag scheme.
	if tag, ok := cosignAttTag(digest); ok {
		if link := r.fromManifestRef(ctx, repo, tag, art); link != nil {
			return link, nil
		}
	}

	return nil, ErrNoProvenance
}

// fromManifestRef fetches an attestation manifest by reference (digest or tag)
// and tries to derive a link from each of its DSSE layers.
func (r *OCIResolver) fromManifestRef(ctx context.Context, repo, ref string, art Artifact) *Link {
	man, err := r.fetchManifest(ctx, "/v2/"+repo+"/manifests/"+ref)
	if err != nil {
		return nil
	}
	for _, layer := range man.Layers {
		if !isDSSELayer(layer.MediaType) {
			continue
		}
		blob, err := r.fetchBlob(ctx, repo, layer.Digest)
		if err != nil {
			continue
		}
		if link := r.verifyLayer(blob, layer.Annotations, art); link != nil {
			return link
		}
	}
	return nil
}

// verifyLayer verifies a single attestation layer. It first tries to treat the
// blob as a self-contained Sigstore bundle; failing that, it parses a bare DSSE
// envelope and pairs it with the certificate carried in the cosign annotation.
func (r *OCIResolver) verifyLayer(blob []byte, annotations map[string]string, art Artifact) *Link {
	// Path A: a full Sigstore bundle blob (referrers-stored attestations).
	if link := verifyAndExtract(r.verifier, blob, art, r.Name(), r.now); link != nil {
		return link
	}

	// Path B: a bare DSSE envelope with the certificate in the cosign annotation.
	var env dsseEnvelope
	if json.Unmarshal(blob, &env) != nil || env.Payload == "" {
		return nil
	}
	certs := parsePEMCerts(annotations[annoCertificate])
	certs = append(certs, parsePEMCerts(annotations[annoChain])...)
	if len(certs) == 0 {
		return nil
	}
	att, err := r.verifier.VerifyEnvelope(&env, certs, blob)
	if err != nil {
		return nil
	}
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
		ResolverName:      r.Name(),
		PredicateType:     att.Statement.PredicateType,
		SignerIdentity:    att.SignerIdentity,
		SignatureVerified: att.SignatureValid,
		ChainTrusted:      att.ChainTrusted,
		Attestation:       att.Raw,
	}
	stampNow(l, r.now)
	return l
}

// fetchIndex fetches and decodes an OCI index / referrers response.
func (r *OCIResolver) fetchIndex(ctx context.Context, path string) (*ociIndex, error) {
	data, err := r.fetchPath(ctx, path, ociManifestAccept)
	if err != nil {
		return nil, err
	}
	var idx ociIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("provenance: decoding OCI index: %w", err)
	}
	return &idx, nil
}

// fetchManifest fetches and decodes an OCI image/artifact manifest.
func (r *OCIResolver) fetchManifest(ctx context.Context, path string) (*ociManifest, error) {
	data, err := r.fetchPath(ctx, path, ociManifestAccept)
	if err != nil {
		return nil, err
	}
	var man ociManifest
	if err := json.Unmarshal(data, &man); err != nil {
		return nil, fmt.Errorf("provenance: decoding OCI manifest: %w", err)
	}
	return &man, nil
}

// fetchBlob fetches a blob by digest from a repository.
func (r *OCIResolver) fetchBlob(ctx context.Context, repo, digest string) ([]byte, error) {
	return r.fetchPath(ctx, "/v2/"+repo+"/blobs/"+digest, "")
}

// fetchPath performs a registry GET via the backend and returns the (size-bounded)
// body. The Docker backend handles the token handshake and, for digest-addressed
// resources, verifies the content digest as it streams.
func (r *OCIResolver) fetchPath(ctx context.Context, path, accept string) ([]byte, error) {
	header := http.Header{}
	if accept != "" {
		header.Set("Accept", accept)
	}
	req := &backends.Request{Method: http.MethodGet, Path: path, Header: header}
	resolved, err := r.fetcher.Resolve(ctx, req)
	if err != nil {
		return nil, err
	}
	res, err := r.fetcher.Fetch(ctx, resolved)
	if err != nil {
		return nil, err
	}
	if res.Content == nil {
		return nil, fmt.Errorf("provenance: empty registry response for %s", path)
	}
	defer res.Content.Close()
	if res.Status != 0 && (res.Status < 200 || res.Status >= 300) {
		return nil, fmt.Errorf("provenance: registry returned status %d for %s", res.Status, path)
	}
	return io.ReadAll(io.LimitReader(res.Content, maxMetadataBytes))
}

// cosignAttTag maps an image digest "sha256:<hex>" to its cosign attestation tag
// "sha256-<hex>.att".
func cosignAttTag(digest string) (string, bool) {
	algo, hex, ok := strings.Cut(digest, ":")
	if !ok || algo == "" || hex == "" {
		return "", false
	}
	return algo + "-" + hex + ".att", true
}

// isAttestationArtifact reports whether a referrer descriptor is an in-toto/DSSE
// attestation by its artifactType or config media type.
func isAttestationArtifact(artifactType, mediaType string) bool {
	t := strings.ToLower(artifactType)
	switch {
	case strings.Contains(t, "in-toto"):
		return true
	case strings.Contains(t, "dsse"):
		return true
	case strings.Contains(t, "sigstore.bundle"):
		return true
	default:
		// Some registries leave artifactType empty; accept image manifests too and
		// let layer inspection decide.
		return strings.Contains(strings.ToLower(mediaType), "manifest")
	}
}

// isDSSELayer reports whether a layer media type carries a DSSE envelope or an
// in-toto statement (the two cosign attestation layer encodings).
func isDSSELayer(mediaType string) bool {
	t := strings.ToLower(mediaType)
	return strings.Contains(t, "dsse") || strings.Contains(t, "in-toto")
}

// parsePEMCerts parses zero or more PEM CERTIFICATE blocks into certificates,
// skipping any that fail to parse.
func parsePEMCerts(pemData string) []*x509.Certificate {
	var out []*x509.Certificate
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, cert)
		}
	}
	return out
}
