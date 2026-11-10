package secrets

import (
	"errors"
	"fmt"
	"strings"
)

// Secret-reference schemes. A configuration value that begins with one of these
// schemes followed by "://" is a secretRef: a pointer to secret material held
// outside the config document, resolved at runtime by the matching Provider.
//
// A value with no recognized scheme is a literal (the historical behavior), so
// adding secretRef support never changes the meaning of existing configs. The
// explicit "literal://" scheme is an escape hatch for a literal value that would
// otherwise be mistaken for a reference (e.g. a token that genuinely starts with
// "env://").
const (
	SchemeEnv     = "env"
	SchemeFile    = "file"
	SchemeVault   = "vault"
	SchemeLiteral = "literal"
)

// refSchemes is the set of schemes this package recognizes as secret
// references. Order is irrelevant; membership is what matters.
var refSchemes = map[string]bool{
	SchemeEnv:     true,
	SchemeFile:    true,
	SchemeVault:   true,
	SchemeLiteral: true,
}

var (
	// ErrNotRef indicates a value does not use the secretRef syntax.
	ErrNotRef = errors.New("secrets: value is not a secret reference")
	// ErrBadRef indicates a structurally invalid secret reference.
	ErrBadRef = errors.New("secrets: malformed secret reference")
)

// Ref is a parsed secret reference. It deliberately holds only the locator
// (scheme, path, key) and never a resolved secret value, so a Ref is safe to
// log, carry in errors, and use as a metrics-label source — the locator is
// configuration, not a secret.
type Ref struct {
	// Scheme is the reference scheme (SchemeEnv, SchemeFile, …).
	Scheme string
	// Path is the body of the reference after "scheme://" and before any "#key"
	// fragment: an environment variable name, a filesystem path, or a Vault
	// secret path.
	Path string
	// Key is the optional "#key" fragment, used by providers whose backing store
	// returns a set of keyed values (e.g. a Vault KV secret's field).
	Key string
	// Raw is the original reference string, retained for diagnostics. It never
	// contains a resolved secret value (it is the reference, not the secret).
	Raw string
}

// String renders the reference in its canonical, redaction-safe form. Because a
// Ref carries no secret value, this is safe to emit in logs and errors.
func (r Ref) String() string {
	if r.Key != "" {
		return fmt.Sprintf("%s://%s#%s", r.Scheme, r.Path, r.Key)
	}
	return fmt.Sprintf("%s://%s", r.Scheme, r.Path)
}

// IsRef reports whether a configuration value uses the secretRef syntax for a
// scheme this package recognizes. A plain literal (including a bare URL such as
// "https://hooks.slack.com/...") returns false and is left untouched.
func IsRef(value string) bool {
	scheme, _, ok := splitScheme(value)
	return ok && refSchemes[scheme]
}

// ParseRef parses a secretRef. It returns ErrNotRef (wrapped) when the value is
// a plain literal, so callers can distinguish "not a reference, pass through
// unchanged" from "a reference that failed to parse".
func ParseRef(value string) (Ref, error) {
	scheme, body, ok := splitScheme(value)
	if !ok || !refSchemes[scheme] {
		return Ref{}, ErrNotRef
	}
	ref := Ref{Scheme: scheme, Raw: value}
	switch scheme {
	case SchemeVault:
		// vault://<mount>/<path>#<key>. The key fragment selects a field within
		// the KV secret; it is required because a KV v2 secret is a map.
		path, key, found := strings.Cut(body, "#")
		if !found || strings.TrimSpace(key) == "" {
			return Ref{}, fmt.Errorf("%w: vault reference %q must include a #key fragment", ErrBadRef, value)
		}
		if strings.TrimSpace(path) == "" {
			return Ref{}, fmt.Errorf("%w: vault reference %q has an empty secret path", ErrBadRef, value)
		}
		ref.Path = strings.TrimSpace(path)
		ref.Key = strings.TrimSpace(key)
	case SchemeEnv:
		name := strings.TrimSpace(body)
		if name == "" {
			return Ref{}, fmt.Errorf("%w: env reference %q has an empty variable name", ErrBadRef, value)
		}
		ref.Path = name
	case SchemeFile:
		// Preserve the path verbatim (paths may legitimately contain spaces);
		// only reject an entirely empty path.
		if strings.TrimSpace(body) == "" {
			return Ref{}, fmt.Errorf("%w: file reference %q has an empty path", ErrBadRef, value)
		}
		ref.Path = body
	case SchemeLiteral:
		// literal://<value> yields <value> verbatim, including an empty string.
		ref.Path = body
	}
	return ref, nil
}

// splitScheme splits "scheme://body" into its scheme and body. ok is false when
// the value does not contain the "://" separator.
func splitScheme(value string) (scheme, body string, ok bool) {
	const sep = "://"
	i := strings.Index(value, sep)
	if i <= 0 {
		return "", "", false
	}
	return value[:i], value[i+len(sep):], true
}
