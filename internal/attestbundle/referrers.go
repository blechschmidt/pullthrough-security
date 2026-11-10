package attestbundle

import "time"

// This file models the OCI referrers response shape so a downstream consumer can
// discover the proxy's attestation for an artifact the same way it would discover
// any OCI referrer: query by the subject's content digest and receive an OCI
// image index whose manifests list the attached attestations (filtered by
// artifactType). The proxy is not a registry, so it serves this index directly
// from its attestation store rather than from registry storage — but the shape is
// the conventional one (OCI image-spec v1.1 referrers), so existing tooling
// (`oras discover`, cosign) can consume it.

// Media types from the OCI image specification used by the referrers response.
const (
	MediaTypeImageIndex    = "application/vnd.oci.image.index.v1+json"
	MediaTypeImageManifest = "application/vnd.oci.image.manifest.v1+json"
)

// ReferrersIndex is an OCI image index listing the attestation manifests that
// refer to a given subject digest. It is the body of the referrers endpoint.
type ReferrersIndex struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []Descriptor `json:"manifests"`
}

// Descriptor is an OCI content descriptor pointing at one attestation manifest.
// The proxy fills ArtifactType with the in-toto predicate type so a consumer can
// select the "served by pullthrough" attestation, and Annotations with the
// human-readable bundle metadata.
type Descriptor struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// OCI predefined annotation keys used in the referrers descriptors.
const (
	annotationCreated   = "org.opencontainers.image.created"
	annotationTitle     = "org.opencontainers.image.title"
	annotationPredicate = "dev.pullthrough.attestation.predicateType"
	annotationKeyID     = "dev.pullthrough.attestation.keyId"
	annotationSubject   = "dev.pullthrough.attestation.subjectDigest"
)

// referrersIndex builds the OCI referrers index for a set of bundles that share a
// subject digest. Each bundle becomes one manifest descriptor whose digest is the
// bundle's envelope digest and whose size is the envelope's byte length.
func referrersIndex(bundles []*Bundle) ReferrersIndex {
	idx := ReferrersIndex{
		SchemaVersion: 2,
		MediaType:     MediaTypeImageIndex,
		Manifests:     make([]Descriptor, 0, len(bundles)),
	}
	for _, b := range bundles {
		raw, err := b.EnvelopeJSON()
		size := int64(len(raw))
		if err != nil {
			size = 0
		}
		idx.Manifests = append(idx.Manifests, Descriptor{
			MediaType:    MediaTypeImageManifest,
			ArtifactType: ArtifactType,
			Digest:       b.Digest,
			Size:         size,
			Annotations: map[string]string{
				annotationCreated:   b.CreatedAt.UTC().Format(time.RFC3339),
				annotationTitle:     b.Coordinate,
				annotationPredicate: b.PredicateType,
				annotationKeyID:     b.KeyID,
				annotationSubject:   b.SubjectDigest,
			},
		})
	}
	return idx
}
