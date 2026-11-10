package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// This file implements OCI Distribution v1.1 referrer discovery on top of the
// backend's Resolve/Fetch primitives (which add the token handshake, the
// referrers fallback-tag schema, and digest verification of fetched manifests
// and blobs).
//
// Referrer artifacts are how signatures, SBOMs, and in-toto/SLSA attestations
// are attached to an image: each is a separate manifest whose `subject` points
// at the image's manifest digest. The Referrers API returns an OCI image index
// of descriptors for those manifests. Discovering and classifying them here lets
// the signature/attestation verification gates (Task 23, Task 72) and the
// SBOM/vulnerability gates (Task 15) consume referrer-stored material through the
// same authenticated, cached registry client that served the image.

// maxReferrersIndexBytes bounds how much of a referrers index the backend buffers
// to decode it, so a hostile or misconfigured registry cannot exhaust memory.
const maxReferrersIndexBytes = 4 << 20 // 4 MiB

// Media and artifact types used to classify referrer artifacts. Registries and
// tools populate either the descriptor's artifactType (the OCI v1.1 convention)
// or, on older cosign conventions, only the referenced config/layer media type,
// so classification matches case-insensitive substrings of both.
const (
	artifactTypeInToto = "application/vnd.in-toto+json"
	// SPDX and CycloneDX SBOM media types as published by Syft/cosign/Trivy.
	artifactTypeSPDXJSON  = "application/spdx+json"
	artifactTypeCycloneDX = "application/vnd.cyclonedx+json"
)

// ReferrerKind classifies an OCI referrer artifact by the supply-chain purpose
// it serves, so a caller can route it to the correct admission gate.
type ReferrerKind int

const (
	// ReferrerOther is a referrer the backend does not recognize as signature,
	// attestation, or SBOM material.
	ReferrerOther ReferrerKind = iota
	// ReferrerSignature is a cosign/sigstore image signature artifact.
	ReferrerSignature
	// ReferrerAttestation is an in-toto / SLSA / DSSE attestation artifact.
	ReferrerAttestation
	// ReferrerSBOM is an attached SBOM (SPDX or CycloneDX) artifact.
	ReferrerSBOM
)

// String renders the kind for logs and findings.
func (k ReferrerKind) String() string {
	switch k {
	case ReferrerSignature:
		return "signature"
	case ReferrerAttestation:
		return "attestation"
	case ReferrerSBOM:
		return "sbom"
	default:
		return "other"
	}
}

// Referrer describes one artifact that references a subject image digest, as
// listed by the Referrers API. The Digest addresses the referrer's own manifest,
// which can be fetched (and is then cached and digest-verified) via FetchBlob or
// a manifest request.
type Referrer struct {
	Digest       string            `json:"digest"`
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Size         int64             `json:"size"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	// Kind is the backend's classification of the referrer's purpose.
	Kind ReferrerKind `json:"kind"`
}

// referrersIndex is the OCI image index returned by the Referrers API (and its
// fallback tag): a list of descriptors for the manifests referencing a subject.
type referrersIndex struct {
	MediaType string     `json:"mediaType"`
	Manifests []Referrer `json:"manifests"`
}

// Referrers lists the OCI referrers for subjectDigest in repository repo. It
// issues GET /v2/<repo>/referrers/<subjectDigest> through the backend (which
// transparently falls back to the referrers fallback-tag schema when the
// upstream does not implement the Referrers API), decodes the returned index,
// and classifies each referrer.
//
// filterArtifactType, when non-empty, restricts the result to referrers whose
// artifactType equals it (case-insensitive). The filter is always applied
// client-side here: a registry serving the fallback tag returns the full,
// unfiltered index, and even a native Referrers API response is re-checked so
// the caller's contract is independent of upstream filter support.
//
// A subject with no referrers yields (nil, nil). A registry that implements
// neither the Referrers API nor the fallback tag surfaces an error, so a caller
// can distinguish "no referrers" from "discovery unavailable".
func (b *Backend) Referrers(ctx context.Context, repo, subjectDigest, filterArtifactType string) ([]Referrer, error) {
	repo = strings.Trim(strings.TrimSpace(repo), "/")
	subjectDigest = strings.TrimSpace(subjectDigest)
	if repo == "" {
		return nil, fmt.Errorf("docker: referrers: repository is required")
	}
	if !IsDigest(subjectDigest) {
		return nil, fmt.Errorf("docker: referrers: %q is not a valid subject digest", subjectDigest)
	}

	idx, err := b.fetchReferrersIndex(ctx, repo, subjectDigest)
	if err != nil {
		return nil, err
	}

	filter := strings.ToLower(strings.TrimSpace(filterArtifactType))
	out := make([]Referrer, 0, len(idx.Manifests))
	for _, m := range idx.Manifests {
		if m.Digest == "" {
			continue
		}
		if filter != "" && !strings.EqualFold(strings.TrimSpace(m.ArtifactType), filter) {
			continue
		}
		m.Kind = classifyReferrer(m.ArtifactType, m.MediaType)
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// fetchReferrersIndex retrieves and decodes the referrers index for a subject.
func (b *Backend) fetchReferrersIndex(ctx context.Context, repo, subjectDigest string) (*referrersIndex, error) {
	req := &backends.Request{
		Method: http.MethodGet,
		Path:   "/v2/" + repo + "/referrers/" + subjectDigest,
		Query:  url.Values{},
		Header: http.Header{"Accept": {ociIndexAccept}},
	}
	resolved, err := b.Resolve(ctx, req)
	if err != nil {
		return nil, err
	}
	result, err := b.Fetch(ctx, resolved)
	if err != nil {
		return nil, err
	}
	if result.Content == nil {
		return nil, fmt.Errorf("docker: referrers: empty response for %s", req.Path)
	}
	defer result.Content.Close()
	body, err := io.ReadAll(io.LimitReader(result.Content, maxReferrersIndexBytes))
	if err != nil {
		return nil, fmt.Errorf("docker: referrers: reading index: %w", err)
	}
	var idx referrersIndex
	if err := json.Unmarshal(body, &idx); err != nil {
		return nil, fmt.Errorf("docker: referrers: decoding index: %w", err)
	}
	return &idx, nil
}

// FetchReferrerBlob fetches a referrer's content blob by digest through the
// backend, returning the (size-bounded) bytes. The backend verifies the blob
// against its digest as it streams and caches it in the content-addressable
// store, so an attached SBOM or attestation blob is fetched once and reused. The
// maximum is bounded by maxReferrersIndexBytes to protect the gate caller.
func (b *Backend) FetchReferrerBlob(ctx context.Context, repo, digest string) ([]byte, error) {
	repo = strings.Trim(strings.TrimSpace(repo), "/")
	if repo == "" {
		return nil, fmt.Errorf("docker: referrers: repository is required")
	}
	if !IsDigest(digest) {
		return nil, fmt.Errorf("docker: referrers: %q is not a valid blob digest", digest)
	}
	req := &backends.Request{
		Method: http.MethodGet,
		Path:   "/v2/" + repo + "/blobs/" + digest,
		Query:  url.Values{},
		Header: http.Header{},
	}
	resolved, err := b.Resolve(ctx, req)
	if err != nil {
		return nil, err
	}
	result, err := b.Fetch(ctx, resolved)
	if err != nil {
		return nil, err
	}
	if result.Content == nil {
		return nil, fmt.Errorf("docker: referrers: empty blob response for %s", digest)
	}
	defer result.Content.Close()
	return io.ReadAll(io.LimitReader(result.Content, maxReferrersIndexBytes))
}

// classifyReferrer classifies a referrer descriptor by its artifactType and
// media type. Classification is a best-effort substring match against both
// fields because the two cosign storage conventions (OCI v1.1 artifactType vs.
// the legacy config/layer media type) populate different ones.
func classifyReferrer(artifactType, mediaType string) ReferrerKind {
	t := strings.ToLower(artifactType + " " + mediaType)
	switch {
	case strings.Contains(t, "spdx") || strings.Contains(t, "cyclonedx") || strings.Contains(t, "sbom"):
		return ReferrerSBOM
	case strings.Contains(t, "in-toto") || strings.Contains(t, "dsse") ||
		strings.Contains(t, "slsa") || strings.Contains(t, "sigstore.bundle") ||
		strings.Contains(t, "attestation"):
		return ReferrerAttestation
	case strings.Contains(t, "cosign") || strings.Contains(t, "sigstore") ||
		strings.Contains(t, "signature"):
		return ReferrerSignature
	default:
		return ReferrerOther
	}
}
