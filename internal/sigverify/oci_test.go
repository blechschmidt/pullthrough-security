package sigverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// fakeRegistry serves a fixed map of path -> bytes, modeling a registry's
// manifest/blob endpoints. A missing path is an error (e.g. the referrers
// endpoint), so the source falls back to the cosign tag scheme.
type fakeRegistry struct {
	objects map[string][]byte
}

func (f *fakeRegistry) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	return &backends.Resolved{UpstreamURL: req.Path, Metadata: map[string]string{"path": req.Path}}, nil
}

func (f *fakeRegistry) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	data, ok := f.objects[resolved.Metadata["path"]]
	if !ok {
		return nil, &backends.StatusError{Status: 404, URL: resolved.UpstreamURL}
	}
	return &backends.FetchResult{
		Resolved: resolved,
		Content:  io.NopCloser(bytes.NewReader(data)),
		Size:     int64(len(data)),
	}, nil
}

func blobDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestOCISourceDiscoversAndVerifies(t *testing.T) {
	root, rootKey, pool := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testIdentity, testIssuer)
	certPEM := rootPoolPEM(t, leaf)

	repo := "acme/widgets"
	tags := cosignTags(testDigest)
	sigTag, attTag := tags[0], tags[1]

	// --- cosign signature artifact (.sig) ---
	sigPayload := simpleSigningPayloadJSON(t, testDigest)
	sigBytes := signECDSA(t, leafKey, sigPayload)
	sigBlobDigest := blobDigest(sigPayload)
	sigManifest := ociManifest{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Layers: []ociDescriptor{{
			MediaType: "application/vnd.dev.cosign.simplesigning.v1+json",
			Digest:    sigBlobDigest,
			Size:      int64(len(sigPayload)),
			Annotations: map[string]string{
				annoSignature:   base64.StdEncoding.EncodeToString(sigBytes),
				annoCertificate: certPEM,
			},
		}},
	}

	// --- cosign attestation artifact (.att) ---
	attEnvelope := dsseAttestation(t, leafKey, leaf, slsaPayload(t, testDigest, testRepo, testCommit))
	attBlob, err := json.Marshal(attEnvelope.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	attBlobDigest := blobDigest(attBlob)
	attManifest := ociManifest{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Layers: []ociDescriptor{{
			MediaType:   "application/vnd.dsse.envelope.v1+json",
			Digest:      attBlobDigest,
			Size:        int64(len(attBlob)),
			Annotations: map[string]string{annoCertificate: certPEM},
		}},
	}

	reg := &fakeRegistry{objects: map[string][]byte{
		"/v2/" + repo + "/manifests/" + sigTag:    mustJSON(t, sigManifest),
		"/v2/" + repo + "/blobs/" + sigBlobDigest: sigPayload,
		"/v2/" + repo + "/manifests/" + attTag:    mustJSON(t, attManifest),
		"/v2/" + repo + "/blobs/" + attBlobDigest: attBlob,
		// referrers endpoint intentionally absent -> falls back to tag scheme.
	}}

	src := NewOCISource(reg)
	svc, err := NewService(Config{
		RequireSignature:   true,
		RequireAttestation: true,
		Roots:              pool,
		Identities:         []Identity{{Issuer: testIssuer, SubjectPattern: `^https://github\.com/acme/.*`}},
	}, src, nil)
	if err != nil {
		t.Fatal(err)
	}

	report, err := svc.Verify(context.Background(), Artifact{Ecosystem: "docker", Name: repo, Digest: testDigest})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.VerifiedSignature {
		t.Fatalf("expected verified signature, findings=%+v", report.Findings)
	}
	if !report.VerifiedAttestation {
		t.Fatalf("expected verified attestation, findings=%+v", report.Findings)
	}
	if d := svc.Gate(report); d.Action != policy.ActionAllow {
		t.Fatalf("expected allow, got %s: %s", d.Action, d.Reason)
	}
}

func TestOCISourceNoSignaturesIsEmpty(t *testing.T) {
	reg := &fakeRegistry{objects: map[string][]byte{}} // nothing served
	src := NewOCISource(reg)
	m, err := src.Fetch(context.Background(), Artifact{Ecosystem: "docker", Name: "x/y", Digest: testDigest})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.IsEmpty() {
		t.Fatalf("expected empty material, got %+v", m)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}
