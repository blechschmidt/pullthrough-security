package spiffe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
)

// fixedNow returns a clock fixed at 2024-06-01.
func fixedNow() time.Time { return time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC) }

// buildAuth wires an authenticator over a single-CA PEM bundle for trustDomain.
func buildAuth(t *testing.T, ca *testCA, trustDomain string, rules []Rule, opts ...func(*Options)) *Authenticator {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	if err := os.WriteFile(path, ca.pemBundle(), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := NewBundleSource(path, FormatPEM, trustDomain)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(RuleSet{Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	o := Options{
		Source:  src,
		Policy:  policy,
		Metrics: NewMetrics(fixedNow),
		Now:     fixedNow,
	}
	for _, fn := range opts {
		fn(&o)
	}
	a, err := NewAuthenticator(o)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// requestWithCerts builds a request whose TLS state presents the given chain.
func requestWithCerts(certs ...*x509.Certificate) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "https://proxy/v1/npm/pkg.tgz", nil)
	if len(certs) > 0 {
		r.TLS = &tls.ConnectionState{PeerCertificates: certs}
	}
	return r
}

func TestAuthenticateSuccess(t *testing.T) {
	ca := newTestCA(t, "ca")
	a := buildAuth(t, ca, "example.org", []Rule{
		{Pattern: "spiffe://example.org/ns/prod/sa/*", Tenant: "prod", Roles: []string{"reader"}},
	})
	leaf := ca.issueLeaf(t, leafOptions{spiffeID: "spiffe://example.org/ns/prod/sa/web"})

	p, err := a.Authenticate(context.Background(), requestWithCerts(leaf))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Subject != "spiffe://example.org/ns/prod/sa/web" {
		t.Fatalf("Subject = %q", p.Subject)
	}
	if p.Team != "prod" || p.Method != "mtls" {
		t.Fatalf("principal = %+v", p)
	}
	if p.Attributes["spiffe_trust_domain"] != "example.org" {
		t.Fatalf("attributes = %v", p.Attributes)
	}
	if got := a.MetricsSnapshot().Success; got != 1 {
		t.Fatalf("success count = %d", got)
	}
}

func TestAuthenticateNoCertFallsThrough(t *testing.T) {
	ca := newTestCA(t, "ca")
	a := buildAuth(t, ca, "example.org", []Rule{{Pattern: "spiffe://example.org/**", Tenant: "prod", Roles: []string{"reader"}}})

	_, err := a.Authenticate(context.Background(), requestWithCerts())
	if !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrUnauthenticated (fall-through)", err)
	}
	// A clean fall-through is not a failure.
	if total := a.MetricsSnapshot().FailureTotal; total != 0 {
		t.Fatalf("failure total = %d, want 0", total)
	}
}

func TestAuthenticateUntrustedDomain(t *testing.T) {
	ca := newTestCA(t, "ca")
	a := buildAuth(t, ca, "example.org", []Rule{{Pattern: "spiffe://**", Tenant: "prod", Roles: []string{"reader"}}})
	// Leaf issued by the trusted CA but claiming a different trust domain.
	leaf := ca.issueLeaf(t, leafOptions{spiffeID: "spiffe://evil.example/ns/x/sa/y"})

	_, err := a.Authenticate(context.Background(), requestWithCerts(leaf))
	if err == nil || errors.Is(err, auth.ErrUnauthenticated) && err.Error() == auth.ErrUnauthenticated.Error() {
		t.Fatalf("err = %v, want present-but-invalid", err)
	}
	if a.MetricsSnapshot().FailuresByReason[ReasonUntrustedDomain] != 1 {
		t.Fatalf("expected untrusted_domain failure, got %v", a.MetricsSnapshot().FailuresByReason)
	}
}

func TestAuthenticateUntrustedIssuer(t *testing.T) {
	trusted := newTestCA(t, "trusted")
	rogue := newTestCA(t, "rogue")
	a := buildAuth(t, trusted, "example.org", []Rule{{Pattern: "spiffe://example.org/**", Tenant: "prod", Roles: []string{"reader"}}})
	// Correct trust domain, but signed by a CA not in the bundle.
	leaf := rogue.issueLeaf(t, leafOptions{spiffeID: "spiffe://example.org/ns/x/sa/y"})

	_, err := a.Authenticate(context.Background(), requestWithCerts(leaf))
	if err == nil {
		t.Fatal("expected chain validation failure")
	}
	if a.MetricsSnapshot().FailuresByReason[ReasonChainInvalid] != 1 {
		t.Fatalf("expected chain_invalid failure, got %v", a.MetricsSnapshot().FailuresByReason)
	}
}

func TestAuthenticateExpiredCert(t *testing.T) {
	ca := newTestCA(t, "ca")
	a := buildAuth(t, ca, "example.org", []Rule{{Pattern: "spiffe://example.org/**", Tenant: "prod", Roles: []string{"reader"}}})
	// Cert valid only in 2021 — expired relative to the fixed 2024 clock.
	leaf := ca.issueLeaf(t, leafOptions{
		spiffeID:  "spiffe://example.org/ns/x/sa/y",
		notBefore: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		notAfter:  time.Date(2021, 2, 1, 0, 0, 0, 0, time.UTC),
	})
	_, err := a.Authenticate(context.Background(), requestWithCerts(leaf))
	if err == nil {
		t.Fatal("expected expiry failure")
	}
	if a.MetricsSnapshot().FailuresByReason[ReasonExpired] != 1 {
		t.Fatalf("expected expired failure, got %v", a.MetricsSnapshot().FailuresByReason)
	}
}

func TestAuthenticateNoSPIFFEID(t *testing.T) {
	ca := newTestCA(t, "ca")
	a := buildAuth(t, ca, "example.org", []Rule{{Pattern: "spiffe://example.org/**", Tenant: "prod", Roles: []string{"reader"}}})
	leaf := ca.issueLeaf(t, leafOptions{}) // no SAN URI

	_, err := a.Authenticate(context.Background(), requestWithCerts(leaf))
	if !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrUnauthenticated", err)
	}
	if a.MetricsSnapshot().FailuresByReason[ReasonNoSPIFFEID] != 1 {
		t.Fatalf("expected no_spiffe_id failure, got %v", a.MetricsSnapshot().FailuresByReason)
	}
}

func TestAuthenticatePolicyDenied(t *testing.T) {
	ca := newTestCA(t, "ca")
	a := buildAuth(t, ca, "example.org", []Rule{
		{Pattern: "spiffe://example.org/ns/prod/sa/*", Tenant: "prod", Roles: []string{"reader"}},
	})
	// Authentic identity, but no rule maps it.
	leaf := ca.issueLeaf(t, leafOptions{spiffeID: "spiffe://example.org/ns/staging/sa/web"})

	_, err := a.Authenticate(context.Background(), requestWithCerts(leaf))
	if !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if a.MetricsSnapshot().FailuresByReason[ReasonPolicyDenied] != 1 {
		t.Fatalf("expected policy_denied failure, got %v", a.MetricsSnapshot().FailuresByReason)
	}
}

func TestAuthenticateAllowedDomainsRestriction(t *testing.T) {
	ca := newTestCA(t, "ca")
	a := buildAuth(t, ca, "example.org",
		[]Rule{{Pattern: "spiffe://example.org/**", Tenant: "prod", Roles: []string{"reader"}}},
		func(o *Options) { o.AllowedTrustDomains = []string{"other.org"} },
	)
	leaf := ca.issueLeaf(t, leafOptions{spiffeID: "spiffe://example.org/ns/x/sa/y"})

	_, err := a.Authenticate(context.Background(), requestWithCerts(leaf))
	if err == nil {
		t.Fatal("expected rejection: example.org not in AllowedTrustDomains")
	}
	if a.MetricsSnapshot().FailuresByReason[ReasonUntrustedDomain] != 1 {
		t.Fatalf("expected untrusted_domain failure, got %v", a.MetricsSnapshot().FailuresByReason)
	}
}

func TestAuthenticateComposesInChain(t *testing.T) {
	ca := newTestCA(t, "ca")
	a := buildAuth(t, ca, "example.org", []Rule{{Pattern: "spiffe://example.org/**", Tenant: "prod", Roles: []string{"reader"}}})

	// A chain of [mtls, stub-token]. With no cert, mtls falls through and the
	// stub authenticates; with a cert, mtls wins.
	stub := stubAuth{principal: &auth.Principal{Subject: "token-user", Team: "tok", Method: "token"}}
	chain := auth.Chain{a, stub}

	p, err := chain.Authenticate(context.Background(), requestWithCerts())
	if err != nil || p.Method != "token" {
		t.Fatalf("no-cert chain = %+v, %v (want token)", p, err)
	}

	leaf := ca.issueLeaf(t, leafOptions{spiffeID: "spiffe://example.org/ns/x/sa/y"})
	p, err = chain.Authenticate(context.Background(), requestWithCerts(leaf))
	if err != nil || p.Method != "mtls" {
		t.Fatalf("cert chain = %+v, %v (want mtls)", p, err)
	}
}

func TestCertExpirySoonGauge(t *testing.T) {
	ca := newTestCA(t, "ca")
	a := buildAuth(t, ca, "example.org",
		[]Rule{{Pattern: "spiffe://example.org/**", Tenant: "prod", Roles: []string{"reader"}}},
		func(o *Options) { o.ExpiryWarning = 90 * 24 * time.Hour },
	)
	// Cert expiring ~30 days after the fixed clock — within the 90-day window.
	leaf := ca.issueLeaf(t, leafOptions{
		spiffeID: "spiffe://example.org/ns/x/sa/y",
		notAfter: fixedNow().Add(30 * 24 * time.Hour),
	})
	if _, err := a.Authenticate(context.Background(), requestWithCerts(leaf)); err != nil {
		t.Fatal(err)
	}
	snap := a.MetricsSnapshot()
	if snap.CertsExpiringSoon != 1 {
		t.Fatalf("CertsExpiringSoon = %d, want 1", snap.CertsExpiringSoon)
	}
	if snap.SoonestCertExpirySeconds <= 0 {
		t.Fatalf("SoonestCertExpirySeconds = %v, want > 0", snap.SoonestCertExpirySeconds)
	}
}

// stubAuth is a trivial authenticator returning a fixed principal.
type stubAuth struct{ principal *auth.Principal }

func (s stubAuth) Authenticate(_ context.Context, _ *http.Request) (*auth.Principal, error) {
	cp := *s.principal
	return &cp, nil
}
