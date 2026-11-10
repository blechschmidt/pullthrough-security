package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// OIDCOptions configures an OIDCAuthenticator.
type OIDCOptions struct {
	// Issuer is the expected "iss" claim. Required.
	Issuer string
	// Audience is the expected "aud" claim. Empty disables audience checking
	// (not recommended).
	Audience string
	// JWKSURL is the endpoint serving the issuer's JWK Set. Mutually usable with
	// StaticJWKS (static keys take precedence when both are set).
	JWKSURL string
	// StaticJWKS is an inline JWK Set document (JSON). Useful for air-gapped
	// deployments or pinning keys.
	StaticJWKS []byte
	// HTTPClient fetches the JWKS (defaults to a 10s-timeout client).
	HTTPClient *http.Client
	// JWKSCacheTTL bounds how long fetched keys are cached (default 15m).
	JWKSCacheTTL time.Duration
	// Leeway tolerates clock skew when checking exp/nbf (default 60s).
	Leeway time.Duration

	// SubjectClaim names the claim used as the principal subject (default "sub").
	SubjectClaim string
	// TeamClaim names the claim carrying the caller's team (default "team").
	TeamClaim string
	// RolesClaim names the claim carrying the caller's roles; it may be a string
	// (space- or comma-separated) or an array of strings (default "roles").
	RolesClaim string
	// RoleMap optionally translates IdP group/role names into the proxy's role
	// names. Unmapped values pass through unchanged.
	RoleMap map[string]string

	// Now overrides the clock (for tests).
	Now func() time.Time
}

// OIDCAuthenticator validates OIDC/JWT bearer tokens and maps their claims onto
// a Principal. It verifies the token signature against the issuer's keys and
// the registered claims (exp/nbf/iss/aud) before trusting any claim.
type OIDCAuthenticator struct {
	opts     OIDCOptions
	keys     keyProvider
	now      func() time.Time
	subClaim string
	teamCl   string
	rolesCl  string
}

// NewOIDCAuthenticator constructs an OIDCAuthenticator. It requires an issuer
// and at least one key source (StaticJWKS or JWKSURL).
func NewOIDCAuthenticator(opts OIDCOptions) (*OIDCAuthenticator, error) {
	if strings.TrimSpace(opts.Issuer) == "" {
		return nil, fmt.Errorf("auth: oidc issuer is required")
	}
	if len(opts.StaticJWKS) == 0 && strings.TrimSpace(opts.JWKSURL) == "" {
		return nil, fmt.Errorf("auth: oidc requires jwksUrl or static jwks")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	var kp keyProvider
	if len(opts.StaticJWKS) > 0 {
		ks, err := parseJWKS(opts.StaticJWKS)
		if err != nil {
			return nil, fmt.Errorf("auth: oidc static jwks: %w", err)
		}
		kp = staticKeyProvider{ks: ks}
	} else {
		kp = newRemoteKeyProvider(opts.JWKSURL, opts.HTTPClient, opts.JWKSCacheTTL, now)
	}

	a := &OIDCAuthenticator{
		opts:     opts,
		keys:     kp,
		now:      now,
		subClaim: orDefault(opts.SubjectClaim, "sub"),
		teamCl:   orDefault(opts.TeamClaim, "team"),
		rolesCl:  orDefault(opts.RolesClaim, "roles"),
	}
	return a, nil
}

// Authenticate implements Authenticator. It only handles JWT-shaped bearer
// tokens; any other request shape declines with ErrUnauthenticated so a token
// authenticator earlier in the chain can handle static tokens.
func (a *OIDCAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*Principal, error) {
	tok := bearerToken(r)
	if tok == "" || !looksLikeJWT(tok) {
		return nil, ErrUnauthenticated
	}

	ks, err := a.keys.get(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot load verification keys: %v", ErrUnauthenticated, err)
	}

	leeway := a.opts.Leeway
	if leeway == 0 {
		leeway = 60 * time.Second
	}
	claims, err := parseAndVerifyJWT(tok, ks, verifyParams{
		issuer:   a.opts.Issuer,
		audience: a.opts.Audience,
		now:      a.now(),
		leeway:   leeway,
	})
	if err != nil {
		return nil, err
	}

	subject := claimString(claims.raw, a.subClaim)
	if subject == "" {
		subject = claims.Subject
	}
	if subject == "" {
		return nil, fmt.Errorf("%w: token has no subject", ErrUnauthenticated)
	}

	roles := a.mapRoles(claimStrings(claims.raw, a.rolesCl))

	return &Principal{
		Subject: subject,
		Team:    claimString(claims.raw, a.teamCl),
		Roles:   roles,
		Method:  "oidc",
		Attributes: map[string]string{
			"issuer": claims.Issuer,
		},
	}, nil
}

// mapRoles applies the configured role map and de-duplicates the result.
func (a *OIDCAuthenticator) mapRoles(in []string) []string {
	if len(a.opts.RoleMap) == 0 {
		return dedupeSorted(in)
	}
	out := make([]string, 0, len(in))
	for _, r := range in {
		if mapped, ok := a.opts.RoleMap[r]; ok {
			out = append(out, mapped)
		} else {
			out = append(out, r)
		}
	}
	return dedupeSorted(out)
}

// claimString extracts a string claim by name.
func claimString(claims map[string]any, name string) string {
	if claims == nil {
		return ""
	}
	v, ok := claims[name]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

// claimStrings extracts a claim that may be a string (space/comma separated) or
// an array of strings into a normalized slice.
func claimStrings(claims map[string]any, name string) []string {
	if claims == nil {
		return nil
	}
	v, ok := claims[name]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case string:
		fields := strings.FieldsFunc(t, func(r rune) bool { return r == ' ' || r == ',' })
		return fields
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
