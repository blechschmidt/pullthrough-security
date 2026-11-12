package auth

import (
	"context"
	"errors"
	"net/http"
)

// Stage identifies which access-control check produced a decision, for audit
// logging.
type Stage string

const (
	StageAuthn Stage = "authentication"
	StageAuthz Stage = "authorization"
	StageQuota Stage = "quota"
	StageAllow Stage = "allow"
)

// Result is the outcome of an access-control check. On denial, Status is the
// HTTP status the gateway should return and Reason explains why (safe to log;
// it never contains secrets).
type Result struct {
	Principal *Principal
	Allowed   bool
	Status    int
	Reason    string
	Stage     Stage
}

// Enforcer combines authentication, RBAC authorization, and quota admission
// into a single decision. It is the gateway's entry point for access control. A
// nil *Enforcer denies nothing and authenticates no one (access control
// disabled) — callers handle that case explicitly.
type Enforcer struct {
	authn Authenticator
	authz *Authorizer
	quota *QuotaManager

	// allowAnonymous permits requests without credentials, binding them to
	// anon. When false, a request without valid credentials is rejected 401.
	allowAnonymous bool
	anon           *Principal
}

// EnforcerOptions configures an Enforcer.
type EnforcerOptions struct {
	Authenticator  Authenticator
	Authorizer     *Authorizer
	Quota          *QuotaManager
	AllowAnonymous bool
	// Anonymous is the principal assigned to unauthenticated requests when
	// AllowAnonymous is true. Defaults to a principal with team "" and no roles
	// (which the authorizer denies unless granted via a wildcard role).
	Anonymous *Principal
}

// NewEnforcer constructs an Enforcer. An authorizer is required; the
// authenticator may be nil only when AllowAnonymous is true.
func NewEnforcer(opts EnforcerOptions) (*Enforcer, error) {
	if opts.Authorizer == nil {
		return nil, errors.New("auth: enforcer requires an authorizer")
	}
	if opts.Authenticator == nil && !opts.AllowAnonymous {
		return nil, errors.New("auth: enforcer requires an authenticator unless anonymous access is allowed")
	}
	anon := opts.Anonymous
	if anon == nil {
		anon = &Principal{Subject: "anonymous", Method: "anonymous"}
	}
	return &Enforcer{
		authn:          opts.Authenticator,
		authz:          opts.Authorizer,
		quota:          opts.Quota,
		allowAnonymous: opts.AllowAnonymous,
		anon:           anon,
	}, nil
}

// Authenticate resolves the principal for a request without performing
// authorization or quota checks. It is used for surfaces (such as the admin
// API) that need an identity but apply their own policy.
func (e *Enforcer) Authenticate(ctx context.Context, r *http.Request) (*Principal, error) {
	if e == nil {
		return nil, ErrUnauthenticated
	}
	if e.authn != nil {
		p, err := e.authn.Authenticate(ctx, r)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, ErrUnauthenticated) {
			return nil, err
		}
	}
	if e.allowAnonymous {
		cp := *e.anon
		return &cp, nil
	}
	return nil, ErrUnauthenticated
}

// Check performs the full admission decision for a pull of the given upstream
// (of the given ecosystem): authenticate, authorize, then reserve quota. It
// returns a Result whose Allowed/Status/Reason the caller uses to either
// proceed or reject, and whose Principal is attached for downstream auditing.
//
// The order matters: authentication first (401 before any resource is named),
// then authorization (403), then quota (429). Quota is only consumed once the
// caller is known to be allowed, so denied requests never burn a tenant's
// budget.
func (e *Enforcer) Check(ctx context.Context, r *http.Request, upstream, ecosystem string) Result {
	if e == nil {
		// Access control disabled: allow as anonymous.
		return Result{Principal: &Principal{Subject: "anonymous", Method: "disabled"}, Allowed: true, Stage: StageAllow}
	}

	p, err := e.Authenticate(ctx, r)
	if err != nil {
		reason := "missing or invalid credentials"
		if !errors.Is(err, ErrUnauthenticated) {
			reason = err.Error()
		}
		status := http.StatusUnauthorized
		if errors.Is(err, ErrForbidden) {
			status = http.StatusForbidden
		}
		return Result{Allowed: false, Status: status, Reason: reason, Stage: StageAuthn}
	}

	return e.Admit(p, upstream, ecosystem)
}

// Admit performs the admission decision for a caller that has already been
// authenticated by other means — a personal cache link (Task 177), whose token
// the gateway resolves itself: authorize, then reserve quota, exactly as Check
// does after it has authenticated a request. The principal is subject to the
// same RBAC roles and the same team quota as any other.
//
// With access control disabled (a nil Enforcer) there is nothing to decide and
// the principal is admitted as it is: the identity is then for the record, not
// for a decision.
func (e *Enforcer) Admit(p *Principal, upstream, ecosystem string) Result {
	if e == nil {
		return Result{Principal: p, Allowed: true, Status: http.StatusOK, Stage: StageAllow}
	}

	if allowed, reason := e.authz.Authorize(p, upstream, ecosystem); !allowed {
		return Result{Principal: p, Allowed: false, Status: http.StatusForbidden, Reason: reason, Stage: StageAuthz}
	}

	if allowed, reason := e.quota.Reserve(p.Team); !allowed {
		return Result{Principal: p, Allowed: false, Status: http.StatusTooManyRequests, Reason: reason, Stage: StageQuota}
	}

	return Result{Principal: p, Allowed: true, Status: http.StatusOK, Stage: StageAllow}
}

// RecordBytes attributes served bytes to the principal's team quota.
func (e *Enforcer) RecordBytes(p *Principal, n int64) {
	if e == nil || p == nil {
		return
	}
	e.quota.RecordBytes(p.Team, n)
}

// QuotaSnapshot returns the current quota usage for a team.
func (e *Enforcer) QuotaSnapshot(team string) Usage {
	if e == nil {
		return Usage{Team: team}
	}
	return e.quota.Snapshot(team)
}
