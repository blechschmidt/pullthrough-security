package proxy

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

func newTestAttestor(t *testing.T) *attestbundle.Service {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	signer, err := attestbundle.NewSigner(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	svc, err := attestbundle.NewService(attestbundle.Config{
		Signer:   signer,
		Attester: attestbundle.Attester{ID: "pullthrough-proxy", Version: "test"},
	})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	return svc
}

func newAttestGateway(t *testing.T, attestor *attestbundle.Service, auditLog *audit.Logger) *Gateway {
	t.Helper()
	g, err := New(Dependencies{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:    cache.NewMemoryCache(),
		Backends: backends.NewRegistry(),
		Attestor: attestor,
		Audit:    auditLog,
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func attestableInput() policyengine.Input {
	return policyengine.Input{
		Tenant: "acme",
		Artifact: policyengine.ArtifactInput{
			Ecosystem: "npm", Backend: "npm", Name: "left-pad", Version: "1.3.0",
			Digest: "sha256:abcdef00112233445566778899aabbccddeeff00112233445566778899aabbcc",
		},
		Provenance: &policyengine.ProvenanceInput{
			Found: true, Confidence: "attested",
			CommitSHA: "0123456789abcdef0123456789abcdef01234567", RepositoryURL: "https://github.com/acme/left-pad",
		},
	}
}

func TestRecordAttestationProducesSignedBundle(t *testing.T) {
	attestor := newTestAttestor(t)
	g := newAttestGateway(t, attestor, nil)

	r := reqWithSignals(attestableInput())
	g.recordAttestation(r, "npm", "npm")

	b, ok := attestor.Get("acme", "left-pad@1.3.0")
	if !ok {
		t.Fatal("expected an attestation bundle to be recorded")
	}
	if b.SubjectDigest != "sha256:abcdef00112233445566778899aabbccddeeff00112233445566778899aabbcc" {
		t.Fatalf("subject digest = %q", b.SubjectDigest)
	}
	stmt, err := b.Statement()
	if err != nil {
		t.Fatal(err)
	}
	if stmt.Predicate.Source == nil || stmt.Predicate.Source.CommitSHA == "" {
		t.Fatalf("attestation did not bind the source commit: %#v", stmt.Predicate.Source)
	}
	// Referrers endpoint must surface it by subject digest.
	idx, ok := attestor.Referrers(b.SubjectDigest)
	if !ok || len(idx.Manifests) != 1 {
		t.Fatalf("referrers lookup failed: ok=%v manifests=%d", ok, len(idx.Manifests))
	}
}

func TestRecordAttestationSkipsWithoutDigest(t *testing.T) {
	attestor := newTestAttestor(t)
	g := newAttestGateway(t, attestor, nil)

	in := attestableInput()
	in.Artifact.Digest = "" // no resolved digest → nothing bindable
	g.recordAttestation(reqWithSignals(in), "npm", "npm")

	if attestor.Store().Len() != 0 {
		t.Fatal("attestation should be skipped when no content digest is present")
	}
}

func TestRecordAttestationNilAttestorIsNoop(t *testing.T) {
	g := newAttestGateway(t, nil, nil)
	// Must not panic with a nil attestor or missing accumulator.
	g.recordAttestation(reqWithSignals(attestableInput()), "npm", "npm")
	r := httptest.NewRequest(http.MethodGet, "/v1/npm/x", nil).WithContext(context.Background())
	g.recordAttestation(r, "npm", "npm")
}

func TestRecordAttestationEmbedsBundleDigestInAudit(t *testing.T) {
	sink := audit.NewMemorySink()
	auditLog, err := audit.NewLogger(context.Background(), audit.Options{
		Key:  []byte("test-key"),
		Sink: sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	attestor := newTestAttestor(t)
	g := newAttestGateway(t, attestor, auditLog)

	r := reqWithSignals(attestableInput())
	g.recordAttestation(r, "npm", "npm")

	b, _ := attestor.Get("acme", "left-pad@1.3.0")
	rec, ok, err := sink.Last(context.Background())
	if err != nil || !ok {
		t.Fatalf("expected an audit record: ok=%v err=%v", ok, err)
	}
	if rec.Event.Type != audit.EventAttestation {
		t.Fatalf("audit event type = %q, want %q", rec.Event.Type, audit.EventAttestation)
	}
	if got := rec.Event.Detail["bundleDigest"]; got != b.Digest {
		t.Fatalf("audit bundleDigest = %v, want %q", got, b.Digest)
	}
}
