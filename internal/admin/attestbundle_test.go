package admin

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

func newAttestService(t *testing.T) *attestbundle.Service {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 3)
	}
	signer, err := attestbundle.NewSigner(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := attestbundle.NewService(attestbundle.Config{
		Signer:   signer,
		Attester: attestbundle.Attester{ID: "pullthrough-proxy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func seedAttestation(t *testing.T, svc *attestbundle.Service) *attestbundle.Bundle {
	t.Helper()
	in := policyengine.Input{
		Tenant: "acme",
		Artifact: policyengine.ArtifactInput{
			Ecosystem: "npm", Backend: "npm", Name: "lodash", Version: "4.17.21",
			Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		},
	}
	b, err := svc.Attest(in, attestbundle.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newAttestServer(t *testing.T, svc *attestbundle.Service) *Server {
	t.Helper()
	return newTestServer(t, Options{Cache: &fakeCache{}, Attest: attestAdapter{svc: svc}})
}

// attestAdapter satisfies AttestInspector from a real Service.
type attestAdapter struct{ svc *attestbundle.Service }

func (a attestAdapter) Snapshot() attestbundle.Snapshot { return a.svc.Snapshot() }
func (a attestAdapter) Get(t, p string) (*attestbundle.Bundle, bool) {
	return a.svc.Get(t, p)
}
func (a attestAdapter) Documents(t, q string) []*attestbundle.Bundle {
	return a.svc.Store().Documents(t, q)
}
func (a attestAdapter) Referrers(d string) (attestbundle.ReferrersIndex, bool) {
	return a.svc.Referrers(d)
}

func TestHandleAttestList(t *testing.T) {
	svc := newAttestService(t)
	seedAttestation(t, svc)
	srv := newAttestServer(t, svc)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/attest?tenant=acme", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp attestListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Enabled || resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("unexpected list response: %+v", resp)
	}
	if resp.Status.Produced != 1 {
		t.Errorf("status.produced = %d, want 1", resp.Status.Produced)
	}
}

func TestHandleAttestBundleRaw(t *testing.T) {
	svc := newAttestService(t)
	b := seedAttestation(t, svc)
	srv := newAttestServer(t, svc)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/attest/bundle?tenant=acme&package=lodash@4.17.21", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Attestation-Digest"); got != b.Digest {
		t.Errorf("X-Attestation-Digest = %q, want %q", got, b.Digest)
	}
	var env attestbundle.Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("body is not a DSSE envelope: %v", err)
	}
	if env.PayloadType != attestbundle.DSSEPayloadType || len(env.Signatures) == 0 {
		t.Fatalf("unexpected envelope: %+v", env)
	}
}

func TestHandleAttestReferrers(t *testing.T) {
	svc := newAttestService(t)
	b := seedAttestation(t, svc)
	srv := newAttestServer(t, svc)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/attest/referrers?digest="+b.SubjectDigest, nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != attestbundle.MediaTypeImageIndex {
		t.Errorf("content-type = %q", ct)
	}
	var idx attestbundle.ReferrersIndex
	if err := json.Unmarshal(rec.Body.Bytes(), &idx); err != nil {
		t.Fatal(err)
	}
	if len(idx.Manifests) != 1 || idx.Manifests[0].Digest != b.Digest {
		t.Fatalf("unexpected referrers index: %+v", idx)
	}
}

func TestHandleAttestDisabled(t *testing.T) {
	srv := newTestServer(t, Options{Cache: &fakeCache{}})
	req := httptest.NewRequest(http.MethodGet, "/admin/api/attest", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp attestListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Enabled {
		t.Error("attest surface should report disabled when no inspector is wired")
	}
}
