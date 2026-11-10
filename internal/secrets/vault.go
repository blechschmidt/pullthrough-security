package secrets

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// VaultOptions configures the HashiCorp Vault secrets provider. It is populated
// by the config layer from secrets.vault.* and carries no proxy-specific types
// so the secrets package stays free of a config dependency.
type VaultOptions struct {
	// Address is the Vault API base URL, e.g. "https://vault.internal:8200".
	Address string
	// Namespace is the optional Vault Enterprise namespace (X-Vault-Namespace).
	Namespace string
	// KVMount is the KV v2 secrets-engine mount path. Defaults to "secret".
	KVMount string
	// AuthMethod is "token" or "approle". Defaults to "token".
	AuthMethod string
	// Token is the Vault token for the "token" auth method. It may itself be an
	// env:// reference resolved by the config layer before this struct is built.
	Token string
	// RoleID and SecretID are the AppRole login credentials.
	RoleID   string
	SecretID string
	// ApproleMount is the AppRole auth mount path. Defaults to "approle".
	ApproleMount string
	// RefreshInterval is how often the background refresher renews the auth
	// lease and re-reads cached secrets. Defaults to 1m; clamped to >= 10s.
	RefreshInterval time.Duration
	// RequestTimeout bounds a single Vault API call. Defaults to 10s.
	RequestTimeout time.Duration
	// CACertFile, when set, is a PEM bundle trusted for the Vault TLS
	// connection in addition to (actually, in place of) the system roots.
	CACertFile string
	// TLSSkipVerify disables Vault TLS verification. Intended only for test or
	// bootstrap environments; never for production.
	TLSSkipVerify bool
}

func (o VaultOptions) withDefaults() VaultOptions {
	if o.KVMount == "" {
		o.KVMount = "secret"
	}
	if o.AuthMethod == "" {
		o.AuthMethod = "token"
	}
	if o.ApproleMount == "" {
		o.ApproleMount = "approle"
	}
	if o.RefreshInterval <= 0 {
		o.RefreshInterval = time.Minute
	}
	if o.RefreshInterval < 10*time.Second {
		o.RefreshInterval = 10 * time.Second
	}
	if o.RequestTimeout <= 0 {
		o.RequestTimeout = 10 * time.Second
	}
	return o
}

// VaultProvider resolves vault://<path>#<key> references against a Vault KV v2
// secrets engine. It authenticates with a static token or via AppRole, caches
// resolved secrets with their lease metadata, and runs a background refresher
// that renews the auth lease and re-reads cached secrets so a long-lived
// process survives token expiry and picks up rotated secret values.
//
// No method ever logs a resolved secret value, a token, or a SecretID.
type VaultProvider struct {
	opts    VaultOptions
	client  *http.Client
	metrics *Metrics
	log     *slog.Logger

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time // zero when the token is non-expiring/renewable-unknown
	renewable   bool
	cache       map[string]string // ref.String() -> last resolved value

	// onChange, when set, is invoked (with the redaction-safe reference string,
	// never the value) whenever a refresh observes a changed secret value.
	onChange func(ref string)

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// vaultClock is overridable in tests; production uses time.Now.
var vaultClock = time.Now

// NewVaultProvider constructs a VaultProvider, performs the initial
// authentication, and starts the background refresher. metrics may be nil
// (counters are then dropped). The caller must Close the provider to stop the
// refresher.
func NewVaultProvider(opts VaultOptions, metrics *Metrics, log *slog.Logger) (*VaultProvider, error) {
	opts = opts.withDefaults()
	if strings.TrimSpace(opts.Address) == "" {
		return nil, errors.New("secrets: vault address must not be empty")
	}
	if log == nil {
		log = slog.Default()
	}
	httpClient, err := vaultHTTPClient(opts)
	if err != nil {
		return nil, err
	}
	p := &VaultProvider{
		opts:    opts,
		client:  httpClient,
		metrics: metrics,
		log:     log,
		cache:   make(map[string]string),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	if err := p.authenticate(context.Background()); err != nil {
		return nil, err
	}
	go p.refreshLoop()
	return p, nil
}

// SetOnChange registers a callback invoked when the background refresher
// observes a rotated secret value. The callback receives the redaction-safe
// reference string only.
func (p *VaultProvider) SetOnChange(fn func(ref string)) {
	p.mu.Lock()
	p.onChange = fn
	p.mu.Unlock()
}

func (p *VaultProvider) Scheme() string { return SchemeVault }

// Resolve reads <key> out of the KV v2 secret at <path> and caches it for the
// background refresher.
func (p *VaultProvider) Resolve(ctx context.Context, ref Ref) (string, error) {
	val, err := p.readSecret(ctx, ref)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	p.cache[ref.String()] = val
	p.mu.Unlock()
	return val, nil
}

// Close stops the background refresher. It is idempotent.
func (p *VaultProvider) Close() error {
	p.stopOnce.Do(func() {
		close(p.stop)
		<-p.done
	})
	return nil
}

// --- authentication ---------------------------------------------------------

func (p *VaultProvider) authenticate(ctx context.Context) error {
	switch p.opts.AuthMethod {
	case "token":
		if strings.TrimSpace(p.opts.Token) == "" {
			return errors.New("secrets: vault token auth requires a token")
		}
		p.mu.Lock()
		p.token = p.opts.Token
		// A static token's lease is unknown to us; treat it as non-renewable and
		// rely on lookup-self during refresh to detect expiry.
		p.tokenExpiry = time.Time{}
		p.renewable = false
		p.mu.Unlock()
		return nil
	case "approle":
		return p.approleLogin(ctx)
	default:
		return fmt.Errorf("secrets: unknown vault auth method %q", p.opts.AuthMethod)
	}
}

func (p *VaultProvider) approleLogin(ctx context.Context) error {
	if strings.TrimSpace(p.opts.RoleID) == "" || strings.TrimSpace(p.opts.SecretID) == "" {
		return errors.New("secrets: vault approle auth requires roleId and secretId")
	}
	body := map[string]string{"role_id": p.opts.RoleID, "secret_id": p.opts.SecretID}
	path := fmt.Sprintf("/v1/auth/%s/login", p.opts.ApproleMount)
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
			Renewable     bool   `json:"renewable"`
		} `json:"auth"`
	}
	if err := p.do(ctx, http.MethodPost, path, "", body, &out); err != nil {
		return fmt.Errorf("approle login: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return errors.New("secrets: vault approle login returned no client token")
	}
	p.applyToken(out.Auth.ClientToken, out.Auth.LeaseDuration, out.Auth.Renewable)
	return nil
}

func (p *VaultProvider) applyToken(token string, leaseSeconds int, renewable bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.token = token
	p.renewable = renewable
	if leaseSeconds > 0 {
		p.tokenExpiry = vaultClock().Add(time.Duration(leaseSeconds) * time.Second)
	} else {
		p.tokenExpiry = time.Time{}
	}
}

func (p *VaultProvider) currentToken() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.token
}

// --- background refresh -----------------------------------------------------

func (p *VaultProvider) refreshLoop() {
	defer close(p.done)
	ticker := time.NewTicker(p.opts.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.refreshOnce()
		}
	}
}

// refreshOnce renews the auth lease when it is approaching expiry and re-reads
// every cached secret so rotations propagate into the cache. Each distinct
// operation is counted; a changed value additionally increments the rotation
// counter and fires the onChange callback.
func (p *VaultProvider) refreshOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), p.opts.RequestTimeout)
	defer cancel()

	p.maybeRenewToken(ctx)

	// Snapshot the set of references to re-read without holding the lock during
	// network I/O.
	p.mu.Lock()
	refs := make([]string, 0, len(p.cache))
	for k := range p.cache {
		refs = append(refs, k)
	}
	onChange := p.onChange
	p.mu.Unlock()

	for _, raw := range refs {
		ref, err := ParseRef(raw)
		if err != nil {
			continue
		}
		val, err := p.readSecret(ctx, ref)
		if err != nil {
			p.metrics.recordRefresh(false)
			p.log.Warn("vault secret refresh failed", "ref", ref.String(), "error", err.Error())
			continue
		}
		p.metrics.recordRefresh(true)
		p.mu.Lock()
		changed := p.cache[raw] != val
		p.cache[raw] = val
		p.mu.Unlock()
		if changed {
			p.metrics.recordRotation()
			p.log.Info("vault secret rotated", "ref", ref.String())
			if onChange != nil {
				onChange(ref.String())
			}
		}
	}
}

func (p *VaultProvider) maybeRenewToken(ctx context.Context) {
	p.mu.Lock()
	expiry := p.tokenExpiry
	renewable := p.renewable
	method := p.opts.AuthMethod
	p.mu.Unlock()

	// Renew when within one refresh interval of expiry (or when the lease is
	// unknown for a static token, verify it is still valid).
	needRenew := renewable && !expiry.IsZero() && vaultClock().Add(p.opts.RefreshInterval).After(expiry)
	if !needRenew {
		return
	}

	if err := p.renewSelf(ctx); err != nil {
		p.metrics.recordRefresh(false)
		p.log.Warn("vault token renewal failed; re-authenticating", "error", err.Error())
		if method == "approle" {
			if lerr := p.approleLogin(ctx); lerr != nil {
				p.log.Error("vault approle re-login failed", "error", lerr.Error())
				return
			}
			p.metrics.recordRefresh(true)
		}
		return
	}
	p.metrics.recordRefresh(true)
}

func (p *VaultProvider) renewSelf(ctx context.Context) error {
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
			Renewable     bool   `json:"renewable"`
		} `json:"auth"`
	}
	if err := p.do(ctx, http.MethodPost, "/v1/auth/token/renew-self", p.currentToken(), map[string]string{}, &out); err != nil {
		return err
	}
	if out.Auth.ClientToken != "" {
		p.applyToken(out.Auth.ClientToken, out.Auth.LeaseDuration, out.Auth.Renewable)
	} else if out.Auth.LeaseDuration > 0 {
		// renew-self commonly returns a lease extension without a new token.
		p.mu.Lock()
		p.tokenExpiry = vaultClock().Add(time.Duration(out.Auth.LeaseDuration) * time.Second)
		p.renewable = out.Auth.Renewable
		p.mu.Unlock()
	}
	return nil
}

// --- KV v2 read -------------------------------------------------------------

func (p *VaultProvider) readSecret(ctx context.Context, ref Ref) (string, error) {
	path := fmt.Sprintf("/v1/%s/data/%s", strings.Trim(p.opts.KVMount, "/"), strings.TrimLeft(ref.Path, "/"))
	var out struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := p.do(ctx, http.MethodGet, path, p.currentToken(), nil, &out); err != nil {
		return "", err
	}
	raw, ok := out.Data.Data[ref.Key]
	if !ok {
		// Name the missing key but never dump the secret's other fields.
		return "", fmt.Errorf("key %q not found in vault secret %q", ref.Key, ref.Path)
	}
	switch v := raw.(type) {
	case string:
		return v, nil
	case json.Number:
		return v.String(), nil
	default:
		return "", fmt.Errorf("key %q in vault secret %q is not a string value", ref.Key, ref.Path)
	}
}

// --- HTTP plumbing ----------------------------------------------------------

func (p *VaultProvider) do(ctx context.Context, method, path, token string, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reqBody = strings.NewReader(string(b))
	}
	url := strings.TrimRight(p.opts.Address, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if p.opts.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.opts.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("vault request to %s: %w", path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read vault response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Surface Vault's structured error list but not the response body
		// wholesale (which, on a read, could echo secret data).
		return fmt.Errorf("vault returned HTTP %d for %s: %s", resp.StatusCode, path, vaultErrors(data))
	}
	if out != nil {
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.UseNumber()
		if err := dec.Decode(out); err != nil {
			return fmt.Errorf("decode vault response: %w", err)
		}
	}
	return nil
}

// vaultErrors extracts the "errors" array from a Vault error response, if
// present, so diagnostics are informative without echoing a success body.
func vaultErrors(data []byte) string {
	var e struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(data, &e) == nil && len(e.Errors) > 0 {
		return strings.Join(e.Errors, "; ")
	}
	return "(no error detail)"
}

func vaultHTTPClient(opts VaultOptions) (*http.Client, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: opts.TLSSkipVerify, //nolint:gosec // opt-in for bootstrap/test only
	}
	if opts.CACertFile != "" {
		pem, err := os.ReadFile(opts.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("secrets: reading vault CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("secrets: vault CA cert %q contained no certificates", opts.CACertFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   opts.RequestTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}
