package config

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/secrets"
)

// This file wires the pluggable secrets provider (internal/secrets, Task 133)
// into configuration loading. Credential fields may carry a secretRef — an
// "env://NAME", "file://path", or "vault://path#key" locator — in place of an
// inline secret. ResolveRefs turns those locators into live secret values via a
// central resolver, and redactCredentials scrubs the same set of fields for the
// drift fingerprint so no resolved secret value ever influences the fingerprint
// (and a Vault rotation is never misreported as configuration drift).

// credentialField is a single secret-bearing configuration value, identified by
// its dotted YAML path (used only in diagnostics — the path is configuration,
// never a secret) and an in-place accessor/mutator.
type credentialField struct {
	name string
	get  func() string
	set  func(string)
}

// visitCredentialFields applies fn to every resolvable credential field and
// writes the result back in place. fn receives the field's dotted path and
// current value and must never log or otherwise expose that value. The set of
// fields is the authoritative list of credential-bearing values that accept a
// secretRef; it intentionally excludes the Vault bootstrap credentials
// (secrets.vault.*) and the at-rest passphrase, which are consumed before the
// resolver exists and therefore cannot themselves be secretRefs.
func visitCredentialFields(cfg *Config, fn func(name, value string) (string, error)) error {
	apply := func(name string, get func() string, set func(string)) error {
		out, err := fn(name, get())
		if err != nil {
			return err
		}
		set(out)
		return nil
	}

	fields := credentialFields(cfg)
	for _, f := range fields {
		if err := apply(f.name, f.get, f.set); err != nil {
			return err
		}
	}

	// Upstreams is a map of value types, so its entries are not addressable;
	// resolve into locals and reassign the map value.
	for name, up := range cfg.Upstreams {
		up := up
		for _, f := range upstreamCredentialFields(name, &up) {
			if err := apply(f.name, f.get, f.set); err != nil {
				return err
			}
		}
		cfg.Upstreams[name] = up
	}

	// Tracing headers may carry an ingest token.
	for k, v := range cfg.Tracing.Headers {
		out, err := fn(fmt.Sprintf("tracing.headers[%q]", k), v)
		if err != nil {
			return err
		}
		cfg.Tracing.Headers[k] = out
	}

	// OTLP-logs export headers may likewise carry an ingest token.
	for k, v := range cfg.Telemetry.OTLPLogs.Headers {
		out, err := fn(fmt.Sprintf("telemetry.otlpLogs.headers[%q]", k), v)
		if err != nil {
			return err
		}
		cfg.Telemetry.OTLPLogs.Headers[k] = out
	}
	return nil
}

// credentialFields returns every addressable credential field, including those
// nested in slices.
func credentialFields(cfg *Config) []credentialField {
	str := func(name string, p *string) credentialField {
		return credentialField{name: name, get: func() string { return *p }, set: func(v string) { *p = v }}
	}
	fields := []credentialField{
		str("scanning.apiKey", &cfg.Scanning.APIKey),
		str("llmPackageScan.apiKey", &cfg.LLMPackageScan.APIKey),
		str("scanning.watch.webhookSecret", &cfg.Scanning.Watch.WebhookSecret),
		str("provenance.githubToken", &cfg.Provenance.GitHubToken),
		str("observability.adminToken", &cfg.Observability.AdminToken),
		str("adminAuth.sessionKey", &cfg.AdminAuth.SessionKey),
		str("adminAuth.oidc.clientSecret", &cfg.AdminAuth.OIDC.ClientSecret),
		str("audit.hmacKey", &cfg.Audit.HMACKey),
		str("audit.transparency.signingKey", &cfg.Audit.Transparency.SigningKey),
		str("attest.signingKey", &cfg.Attest.SigningKey),
		str("backup.passphrase", &cfg.Backup.Passphrase),
		str("compliance.signingKey", &cfg.Compliance.SigningKey),
		str("cache.s3.accessKeyId", &cfg.Cache.S3.AccessKeyID),
		str("cache.s3.secretAccessKey", &cfg.Cache.S3.SecretAccessKey),
		str("cache.s3.sessionToken", &cfg.Cache.S3.SessionToken),
		str("cache.encryption.keyRef", &cfg.Cache.Encryption.KeyRef),
		str("coordination.s3.accessKeyId", &cfg.Coordination.S3.AccessKeyID),
		str("coordination.s3.secretAccessKey", &cfg.Coordination.S3.SecretAccessKey),
		str("coordination.s3.sessionToken", &cfg.Coordination.S3.SessionToken),
		str("userLinks.sessionKey", &cfg.UserLinks.SessionKey),
		str("userLinks.oidc.clientSecret", &cfg.UserLinks.OIDC.ClientSecret),
		str("userLinks.store.s3.accessKeyId", &cfg.UserLinks.Store.S3.AccessKeyID),
		str("userLinks.store.s3.secretAccessKey", &cfg.UserLinks.Store.S3.SecretAccessKey),
		str("userLinks.store.s3.sessionToken", &cfg.UserLinks.Store.S3.SessionToken),
		str("cacheFed.auth.secretRef", &cfg.CacheFed.Auth.SecretRef),
		str("sbomExport.dependencyTrack.apiKey", &cfg.SBOMExport.DependencyTrack.APIKey),
		str("sbomExport.guac.token", &cfg.SBOMExport.GUAC.Token),
	}
	for i := range cfg.Scanning.Commit.Consensus {
		fields = append(fields, str(fmt.Sprintf("scanning.commit.consensus[%d].apiKey", i), &cfg.Scanning.Commit.Consensus[i].APIKey))
	}
	for i := range cfg.Scanning.Watch.Repos {
		fields = append(fields,
			str(fmt.Sprintf("scanning.watch.repos[%d].username", i), &cfg.Scanning.Watch.Repos[i].Username),
			str(fmt.Sprintf("scanning.watch.repos[%d].token", i), &cfg.Scanning.Watch.Repos[i].Token),
		)
	}
	for i := range cfg.Auth.Tokens {
		fields = append(fields, str(fmt.Sprintf("auth.tokens[%d].token", i), &cfg.Auth.Tokens[i].Token))
	}
	for i := range cfg.Cache.Encryption.PreviousKeys {
		fields = append(fields, str(fmt.Sprintf("cache.encryption.previousKeys[%d].keyRef", i), &cfg.Cache.Encryption.PreviousKeys[i].KeyRef))
	}
	for i := range cfg.AdminAuth.StaticTokens {
		fields = append(fields, str(fmt.Sprintf("adminAuth.staticTokens[%d].token", i), &cfg.AdminAuth.StaticTokens[i].Token))
	}
	for i := range cfg.Notifications.Sinks {
		fields = append(fields, str(fmt.Sprintf("notifications.sinks[%d].url", i), &cfg.Notifications.Sinks[i].URL))
	}
	for i := range cfg.SIEM.Sinks {
		fields = append(fields,
			str(fmt.Sprintf("siem.sinks[%d].url", i), &cfg.SIEM.Sinks[i].URL),
			str(fmt.Sprintf("siem.sinks[%d].token", i), &cfg.SIEM.Sinks[i].Token),
		)
	}
	return fields
}

// upstreamCredentialFields returns the credential fields of a single upstream
// (and its mirrors), bound to the supplied addressable copy.
func upstreamCredentialFields(name string, up *UpstreamConfig) []credentialField {
	str := func(fieldName string, p *string) credentialField {
		return credentialField{name: fieldName, get: func() string { return *p }, set: func(v string) { *p = v }}
	}
	fields := []credentialField{
		str("upstreams."+name+".credentials.username", &up.Credentials.Username),
		str("upstreams."+name+".credentials.password", &up.Credentials.Password),
		str("upstreams."+name+".credentials.token", &up.Credentials.Token),
	}
	for i := range up.Mirrors {
		fields = append(fields,
			str(fmt.Sprintf("upstreams.%s.mirrors[%d].credentials.username", name, i), &up.Mirrors[i].Credentials.Username),
			str(fmt.Sprintf("upstreams.%s.mirrors[%d].credentials.password", name, i), &up.Mirrors[i].Credentials.Password),
			str(fmt.Sprintf("upstreams.%s.mirrors[%d].credentials.token", name, i), &up.Mirrors[i].Credentials.Token),
		)
	}
	return fields
}

// NewSecretsResolver builds a secrets.Resolver from the configuration. The
// env:// and file:// providers are always registered; the Vault provider is
// added only when secrets.vault.enabled is true, in which case this performs the
// initial Vault authentication and starts the background lease refresher. The
// caller owns the returned resolver and must Close it on shutdown.
func NewSecretsResolver(cfg *Config, log *slog.Logger) (*secrets.Resolver, error) {
	resolver := secrets.NewResolver(log)
	v := cfg.Secrets.Vault
	if v.Enabled {
		vp, err := secrets.NewVaultProvider(secrets.VaultOptions{
			Address:         v.Address,
			Namespace:       v.Namespace,
			KVMount:         v.KVMount,
			AuthMethod:      v.AuthMethod,
			Token:           v.Token,
			RoleID:          v.RoleID,
			SecretID:        v.SecretID,
			ApproleMount:    v.ApproleMount,
			RefreshInterval: v.RefreshInterval,
			RequestTimeout:  v.RequestTimeout,
			CACertFile:      v.CACertFile,
			TLSSkipVerify:   v.TLSSkipVerify,
		}, resolver.MetricsSink(), log)
		if err != nil {
			return nil, fmt.Errorf("config: vault provider: %w", err)
		}
		vp.SetOnChange(func(ref string) {
			// ref is the redaction-safe locator, never a secret value.
			log.Info("vault secret rotated; restart or reload to apply", "ref", ref)
		})
		resolver.Register(vp)
	}
	return resolver, nil
}

// ResolveRefs resolves every secretRef-bearing credential field in place using
// the supplied resolver. A field whose value is a plain literal is left
// unchanged, so configs that predate secretRef support are unaffected. Errors
// name the field's path but never its value. This is the single central
// resolution pass invoked once at startup after Load.
func ResolveRefs(ctx context.Context, cfg *Config, resolver *secrets.Resolver) error {
	if cfg == nil || resolver == nil {
		return nil
	}
	return visitCredentialFields(cfg, func(name, value string) (string, error) {
		out, err := resolver.Resolve(ctx, value)
		if err != nil {
			return "", fmt.Errorf("config: resolving %s: %w", name, err)
		}
		return out, nil
	})
}

// redactCredentials replaces every credential field's value with a fixed,
// non-secret marker ("***") while preserving the empty/non-empty distinction.
// It operates in place on the supplied config, which must therefore be a copy.
func redactCredentials(cfg *Config) {
	mark := func(_, value string) (string, error) {
		if value == "" {
			return "", nil
		}
		return redactionMarker, nil
	}
	// visitCredentialFields never errors for a non-erroring fn.
	_ = visitCredentialFields(cfg, mark)
	// Also redact the Vault bootstrap credentials and the at-rest passphrase,
	// which are excluded from the resolvable set but are still secrets.
	if cfg.Secrets.Vault.Token != "" {
		cfg.Secrets.Vault.Token = redactionMarker
	}
	if cfg.Secrets.Vault.RoleID != "" {
		cfg.Secrets.Vault.RoleID = redactionMarker
	}
	if cfg.Secrets.Vault.SecretID != "" {
		cfg.Secrets.Vault.SecretID = redactionMarker
	}
	if cfg.Secrets.Passphrase != "" {
		cfg.Secrets.Passphrase = redactionMarker
	}
}

const redactionMarker = "***"

// validateSecrets validates the secrets-provider configuration (Task 133).
func (c *Config) validateSecrets() error {
	v := c.Secrets.Vault
	if !v.Enabled {
		return nil
	}
	if strings.TrimSpace(v.Address) == "" {
		return fmt.Errorf("config: secrets.vault.enabled requires secrets.vault.address")
	}
	switch v.AuthMethod {
	case "", "token":
		if strings.TrimSpace(v.Token) == "" {
			return fmt.Errorf("config: secrets.vault token auth requires secrets.vault.token")
		}
	case "approle":
		if strings.TrimSpace(v.RoleID) == "" || strings.TrimSpace(v.SecretID) == "" {
			return fmt.Errorf("config: secrets.vault approle auth requires secrets.vault.roleId and secretId")
		}
	default:
		return fmt.Errorf("config: unknown secrets.vault.authMethod %q (want \"token\" or \"approle\")", v.AuthMethod)
	}
	if v.RefreshInterval < 0 || v.RequestTimeout < 0 {
		return fmt.Errorf("config: secrets.vault durations must not be negative")
	}
	return nil
}
