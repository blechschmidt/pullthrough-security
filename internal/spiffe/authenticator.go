package spiffe

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
)

// Authenticator authenticates inbound requests by their mutual-TLS client
// certificate, mapping the verified SPIFFE ID to a tenant + roles. It
// implements auth.Authenticator so it composes with the existing token/OIDC
// authenticators in an auth.Chain.
//
// Contract (matching the chain semantics in internal/auth): when no client
// certificate is presented at all, Authenticate returns auth.ErrUnauthenticated
// so the chain falls through to token/OIDC auth (either-or mode). When a
// certificate IS presented but fails validation — untrusted/expired chain,
// missing or malformed SPIFFE SAN, or no policy mapping — the credential is
// present-but-invalid and Authenticate returns a non-ErrUnauthenticated error so
// the chain stops and the request is rejected (an invalid client cert must not
// silently fall back to anonymous).
type Authenticator struct {
	source        *BundleSource
	policy        *Policy
	metrics       *Metrics
	now           func() time.Time
	expiryWarning time.Duration
	// allowedDomains, when non-empty, restricts which trust domains are accepted
	// even if present in the bundle (defense in depth for federated bundles).
	allowedDomains map[string]struct{}
}

// Options configures an Authenticator.
type Options struct {
	// Source is the reloadable trust bundle (required).
	Source *BundleSource
	// Policy maps verified SPIFFE IDs to tenants + roles (required).
	Policy *Policy
	// Metrics records auth outcomes and cert expiries. A nil value disables
	// recording.
	Metrics *Metrics
	// ExpiryWarning is the window used for the "certs expiring soon" gauge.
	// Defaults to 30 days.
	ExpiryWarning time.Duration
	// AllowedTrustDomains optionally restricts accepted trust domains to this
	// set (in addition to them being present in the bundle). Empty means accept
	// any domain the bundle knows.
	AllowedTrustDomains []string
	// Now overrides the clock (tests). Defaults to time.Now.
	Now func() time.Time
}

// NewAuthenticator validates the options and constructs an Authenticator.
func NewAuthenticator(opts Options) (*Authenticator, error) {
	if opts.Source == nil {
		return nil, errors.New("spiffe: authenticator requires a trust bundle source")
	}
	if opts.Policy == nil {
		return nil, errors.New("spiffe: authenticator requires an identity-mapping policy")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	warn := opts.ExpiryWarning
	if warn <= 0 {
		warn = 30 * 24 * time.Hour
	}
	a := &Authenticator{
		source:        opts.Source,
		policy:        opts.Policy,
		metrics:       opts.Metrics,
		now:           now,
		expiryWarning: warn,
	}
	if len(opts.AllowedTrustDomains) > 0 {
		a.allowedDomains = make(map[string]struct{}, len(opts.AllowedTrustDomains))
		for _, d := range opts.AllowedTrustDomains {
			a.allowedDomains[normalizeDomain(d)] = struct{}{}
		}
	}
	return a, nil
}

// Authenticate implements auth.Authenticator.
func (a *Authenticator) Authenticate(ctx context.Context, r *http.Request) (*auth.Principal, error) {
	_ = ctx
	// No mutual-TLS handshake / no client certificate: not our credential. Fall
	// through so token/OIDC auth (when configured) can handle the request.
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, auth.ErrUnauthenticated
	}
	leaf := r.TLS.PeerCertificates[0]

	id, ok, err := spiffeIDFromCert(leaf)
	if err != nil {
		// A SAN URI exists with the spiffe scheme but is malformed: a present,
		// broken credential — reject rather than fall through.
		a.metrics.recordFailure(ReasonMalformedID)
		return nil, fmt.Errorf("%w: %v", auth.ErrUnauthenticated, err)
	}
	if !ok {
		// A client cert without any SPIFFE SAN URI is not a workload-identity
		// credential; let other authenticators try.
		a.metrics.recordFailure(ReasonNoSPIFFEID)
		return nil, auth.ErrUnauthenticated
	}

	domain := id.TrustDomain
	if a.allowedDomains != nil {
		if _, allowed := a.allowedDomains[domain]; !allowed {
			a.metrics.recordFailure(ReasonUntrustedDomain)
			return nil, fmt.Errorf("%w: trust domain %q is not accepted", auth.ErrUnauthenticated, domain)
		}
	}

	bundle := a.source.Current()
	roots, known := bundle.Roots(domain)
	if !known {
		a.metrics.recordFailure(ReasonUntrustedDomain)
		return nil, fmt.Errorf("%w: unknown trust domain %q", auth.ErrUnauthenticated, domain)
	}

	// Validate the certificate chain against the trust-domain roots. Any
	// intermediates the peer sent are made available to the verifier.
	intermediates := x509.NewCertPool()
	for _, c := range r.TLS.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	now := a.now()
	_, verr := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		// SVIDs are client certificates; accept any EKU (SPIFFE leaf certs
		// commonly set clientAuth+serverAuth, and some omit EKU entirely).
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if verr != nil {
		reason := ReasonChainInvalid
		if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
			reason = ReasonExpired
		}
		a.metrics.recordFailure(reason)
		return nil, fmt.Errorf("%w: certificate chain validation failed: %v", auth.ErrUnauthenticated, verr)
	}

	mapping, mapped := a.policy.Resolve(id)
	if !mapped {
		// The identity is authentic but no rule grants it access: a definite
		// authorization failure (403), not a fall-through.
		a.metrics.recordFailure(ReasonPolicyDenied)
		return nil, fmt.Errorf("%w: SPIFFE id %q is not mapped to any tenant", auth.ErrForbidden, id.String())
	}

	a.metrics.recordSuccess(id.String(), leaf.NotAfter)

	principal := &auth.Principal{
		// Subject carries the full SPIFFE ID so the audit subsystem attributes
		// every pull/decision to the verified workload identity.
		Subject: id.String(),
		Team:    mapping.Tenant,
		Roles:   mapping.Roles,
		Method:  "mtls",
		Attributes: map[string]string{
			"spiffe_id":           id.String(),
			"spiffe_trust_domain": id.TrustDomain,
			"spiffe_path":         id.Path,
			"cert_serial":         serialString(leaf),
			"cert_not_after":      leaf.NotAfter.UTC().Format(time.RFC3339),
		},
	}
	return principal, nil
}

// MetricsSnapshot returns the current authenticator metrics computed against the
// configured expiry-warning window. Convenience for the Prometheus bridge.
func (a *Authenticator) MetricsSnapshot() MetricsSnapshot {
	return a.metrics.Snapshot(a.expiryWarning)
}

// Metrics returns the underlying metrics accumulator.
func (a *Authenticator) Metrics() *Metrics { return a.metrics }

// ExpiryWarning returns the configured cert-expiry warning window.
func (a *Authenticator) ExpiryWarning() time.Duration { return a.expiryWarning }

// Source returns the trust-bundle source backing the authenticator.
func (a *Authenticator) Source() *BundleSource { return a.source }

// spiffeIDFromCert extracts the SPIFFE ID from a certificate's SAN URIs. It
// returns ok=false when the certificate carries no spiffe:// URI (so the caller
// can fall through), and an error only when a spiffe:// URI is present but
// malformed or when more than one is found (an SVID must carry exactly one).
func spiffeIDFromCert(cert *x509.Certificate) (ID, bool, error) {
	var found *ID
	for _, u := range cert.URIs {
		if u == nil || !strings.EqualFold(u.Scheme, Scheme) {
			continue
		}
		id, err := ParseID(u.String())
		if err != nil {
			return ID{}, false, err
		}
		if found != nil {
			return ID{}, false, fmt.Errorf("certificate carries multiple SPIFFE SAN URIs")
		}
		c := id
		found = &c
	}
	if found == nil {
		return ID{}, false, nil
	}
	return *found, true, nil
}
