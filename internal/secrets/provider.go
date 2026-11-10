package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Provider resolves secret references for a single scheme. Implementations must
// never log, wrap into errors, or otherwise expose a resolved secret value;
// errors returned here propagate into operator-facing diagnostics and must
// describe only the reference (scheme/path), never the secret.
type Provider interface {
	// Scheme returns the reference scheme this provider handles (SchemeEnv, …).
	Scheme() string
	// Resolve returns the cleartext secret for a parsed reference. The returned
	// string is the secret and must be treated as such by the caller.
	Resolve(ctx context.Context, ref Ref) (string, error)
	// Close releases any background resources (e.g. a Vault lease-refresh
	// goroutine). It is safe to call on providers that hold none.
	Close() error
}

// Resolver dispatches secretRef resolution to the registered Provider for each
// reference's scheme, resolving plain literals to themselves. It is the single
// central entry point the config layer uses to turn reference-bearing
// credential fields into live secret values.
//
// A Resolver is safe for concurrent use. The zero value is not usable; call
// NewResolver.
type Resolver struct {
	mu        sync.RWMutex
	providers map[string]Provider
	metrics   *Metrics
	log       *slog.Logger
}

// NewResolver returns a Resolver pre-registered with the always-available
// providers: env (environment variables), file (read-at-start with permission
// checks), and literal (verbatim). These reproduce and formalize the historical
// behavior and require no external configuration. Register additional providers
// (e.g. Vault) with Register.
func NewResolver(log *slog.Logger) *Resolver {
	if log == nil {
		log = slog.Default()
	}
	r := &Resolver{
		providers: make(map[string]Provider),
		metrics:   NewMetrics(),
		log:       log,
	}
	r.Register(&envProvider{})
	r.Register(&fileProvider{})
	r.Register(&literalProvider{})
	return r
}

// Register adds or replaces the provider for a scheme.
func (r *Resolver) Register(p Provider) {
	if p == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.Scheme()] = p
}

// Metrics returns a point-in-time snapshot of resolution/refresh counters.
func (r *Resolver) Metrics() Snapshot { return r.metrics.Snapshot() }

// MetricsSink exposes the underlying counters so a provider constructed outside
// NewResolver (e.g. a Vault provider built then Registered) can share the same
// metrics. It never exposes secret values.
func (r *Resolver) MetricsSink() *Metrics { return r.metrics }

// Resolve turns a single configuration value into its cleartext secret. A value
// that is not a secretRef is returned unchanged (the literal/default behavior),
// without touching any provider and without recording a metric. A recognized
// reference is dispatched to its provider; success and failure are counted by
// scheme. On failure the returned error names the reference but never the
// secret value.
func (r *Resolver) Resolve(ctx context.Context, value string) (string, error) {
	ref, err := ParseRef(value)
	if err != nil {
		if err == ErrNotRef {
			return value, nil
		}
		// A malformed reference for a known scheme: count against that scheme
		// when we can recover it, otherwise leave it uncounted.
		if scheme, _, ok := splitScheme(value); ok {
			r.metrics.recordResolve(scheme, false)
		}
		return "", err
	}

	r.mu.RLock()
	p := r.providers[ref.Scheme]
	r.mu.RUnlock()
	if p == nil {
		r.metrics.recordResolve(ref.Scheme, false)
		return "", fmt.Errorf("secrets: no provider configured for %q references (reference %s)", ref.Scheme, ref)
	}

	out, rerr := p.Resolve(ctx, ref)
	if rerr != nil {
		r.metrics.recordResolve(ref.Scheme, false)
		// rerr is contractually free of secret material.
		return "", fmt.Errorf("secrets: resolving %s: %w", ref, rerr)
	}
	r.metrics.recordResolve(ref.Scheme, true)
	return out, nil
}

// Close shuts down every registered provider, aggregating any errors.
func (r *Resolver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var errs []string
	for scheme, p := range r.providers {
		if err := p.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", scheme, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("secrets: closing providers: %s", strings.Join(errs, "; "))
	}
	return nil
}

// --- env provider -----------------------------------------------------------

// envProvider resolves env://NAME to the value of the named environment
// variable. An unset or empty variable is an error: an explicit reference to a
// missing secret is a misconfiguration that should fail fast rather than
// silently yield an empty credential.
type envProvider struct{}

func (p *envProvider) Scheme() string { return SchemeEnv }

func (p *envProvider) Resolve(_ context.Context, ref Ref) (string, error) {
	v, ok := os.LookupEnv(ref.Path)
	if !ok {
		return "", fmt.Errorf("environment variable %q is not set", ref.Path)
	}
	if v == "" {
		return "", fmt.Errorf("environment variable %q is empty", ref.Path)
	}
	return v, nil
}

func (p *envProvider) Close() error { return nil }

// --- file provider ----------------------------------------------------------

// fileProvider resolves file://PATH by reading the file at start, enforcing
// restrictive permissions: the file must be a regular file readable only by its
// owner (no group or other permission bits). This mirrors the strictness SSH
// enforces on private keys and prevents a world- or group-readable secret from
// being silently accepted. Trailing newlines/whitespace are trimmed so a file
// authored with a text editor resolves to the intended value.
type fileProvider struct{}

func (p *fileProvider) Scheme() string { return SchemeFile }

func (p *fileProvider) Resolve(_ context.Context, ref Ref) (string, error) {
	info, err := os.Stat(ref.Path)
	if err != nil {
		return "", fmt.Errorf("stat secret file %q: %w", ref.Path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("secret file %q is not a regular file", ref.Path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("secret file %q has overly permissive mode %#o (must be owner-only, e.g. 0600)", ref.Path, perm)
	}
	data, err := os.ReadFile(ref.Path)
	if err != nil {
		return "", fmt.Errorf("read secret file %q: %w", ref.Path, err)
	}
	v := strings.TrimRight(string(data), "\r\n\t ")
	if v == "" {
		return "", fmt.Errorf("secret file %q is empty", ref.Path)
	}
	return v, nil
}

func (p *fileProvider) Close() error { return nil }

// --- literal provider -------------------------------------------------------

// literalProvider resolves literal://VALUE to VALUE verbatim. It is the escape
// hatch for a literal secret that would otherwise be parsed as a reference.
type literalProvider struct{}

func (p *literalProvider) Scheme() string { return SchemeLiteral }

func (p *literalProvider) Resolve(_ context.Context, ref Ref) (string, error) {
	return ref.Path, nil
}

func (p *literalProvider) Close() error { return nil }
