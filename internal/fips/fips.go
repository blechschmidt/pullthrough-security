// Package fips centralizes the proxy's FIPS 140-3 cryptographic operating mode
// (Task 120).
//
// It serves three roles:
//
//  1. Mode detection & fail-fast. [Detect] combines the operator's intent
//     (fips.enabled / fips.requireModule from config) with the live state of the
//     Go FIPS 140-3 cryptographic module (crypto/fips140) to produce a [Mode].
//     [Mode.Validate] is the startup gate that aborts the process when FIPS mode
//     is requested but the validated module is not actually active, so an
//     operator can never believe they are compliant when they are not.
//
//  2. Approved-algorithm policy. The package is the single source of truth for
//     the FIPS 140-3 approved TLS floor, cipher suites, and digest algorithms,
//     and exposes helpers ([HardenServerTLSConfig], [HashApproved],
//     [TLSMinVersionApproved]) that the TLS-termination, signature-verification,
//     audit, and cache subsystems consult to enforce an approved-only posture
//     regardless of whether the binary was compiled with the validated module.
//
//  3. Build-variant reporting. [BuildVariant] reflects the compile-time build
//     tag ("fips" vs "standard") so the active crypto build is surfaced in logs
//     and the admin API.
//
// The actual cryptographic enforcement of approved primitives is delegated to
// the Go FIPS 140-3 Cryptographic Module itself: when the binary is built with
// GOFIPS140 and run with GODEBUG=fips140=on (or =only), the standard library's
// crypto packages restrict themselves to approved algorithms and parameters.
// This package does not reimplement that gating; it wires the toggle, fails
// fast on a non-compliant configuration, applies defense-in-depth approved
// parameters where the application sets them explicitly (TLS), and reports the
// result.
//
// See go.dev/doc/security/fips140 and docs/fips-compliance.md.
package fips

import (
	"crypto/fips140"
	"crypto/tls"
	"fmt"
	"runtime/debug"
	"strings"
)

// ApprovedTLSMinVersion is the lowest TLS version permitted under FIPS 140-3.
// TLS 1.0 and 1.1 rely on non-approved constructions (notably the MD5/SHA-1 PRF)
// and are rejected; TLS 1.2 and 1.3 are permitted.
const ApprovedTLSMinVersion = uint16(tls.VersionTLS12)

// ModuleName is the human-readable name of the validated module, used in logs
// and the admin API alongside the module version.
const ModuleName = "Go Cryptographic Module"

// approvedTLS12CipherSuites is the FIPS 140-3 approved subset of configurable
// (TLS 1.2 and earlier) cipher suites: ephemeral-ECDH key agreement with
// AES-GCM AEAD and a SHA-2 PRF. Non-approved suites (CBC-mode, RC4,
// ChaCha20-Poly1305, static-RSA key exchange) are deliberately omitted. TLS 1.3
// cipher suites are not configurable via tls.Config.CipherSuites; the Go FIPS
// module restricts those automatically when the module is active.
var approvedTLS12CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

// approvedHashes is the set of FIPS 140-3 approved secure hash / content-address
// algorithm identifiers the proxy may use. Legacy MD5 and SHA-1 are absent and
// therefore rejected. Identifiers are matched case-insensitively after trimming.
var approvedHashes = map[string]bool{
	"sha224":     true,
	"sha256":     true,
	"sha384":     true,
	"sha512":     true,
	"sha512-224": true,
	"sha512-256": true,
	"sha3-224":   true,
	"sha3-256":   true,
	"sha3-384":   true,
	"sha3-512":   true,
}

// Mode describes the proxy's effective cryptographic operating mode. It is
// computed once at startup by [Detect] and then treated as immutable.
type Mode struct {
	// Enabled reports whether approved-crypto enforcement (fips.enabled) was
	// requested by the operator.
	Enabled bool
	// RequireModule reports whether startup must fail unless the validated Go
	// FIPS 140-3 module is active. It is only meaningful when Enabled is true.
	RequireModule bool
	// ModuleActive reports whether the Go FIPS 140-3 cryptographic module is
	// active in this process (crypto/fips140.Enabled, i.e. the binary was built
	// with GOFIPS140 and run with GODEBUG=fips140=on or =only).
	ModuleActive bool
	// ModuleEnforced reports whether the module is in enforcing ("only") mode,
	// where any attempt to use a non-approved algorithm fails rather than being
	// silently permitted (crypto/fips140.Enforced, GODEBUG=fips140=only).
	ModuleEnforced bool
	// ModuleVersion is the FIPS 140-3 module selector the binary was built
	// against, read from the GOFIPS140 build setting (e.g. "v1.0.0" or "latest").
	// It is empty when the binary was not built with GOFIPS140. It reflects the
	// build-time selection and is reported for provenance; it is not a reliable
	// indicator of whether the module is active at runtime — use ModuleActive.
	ModuleVersion string
	// BuildVariant is the compile-time crypto build variant: "fips" when built
	// with the fips build tag (see `make build-fips`), otherwise "standard".
	BuildVariant string
}

// Detect builds the effective [Mode] from the operator's configured intent and
// the live state of the Go FIPS 140-3 module in this process.
func Detect(enabled, requireModule bool) Mode {
	return Mode{
		Enabled:        enabled,
		RequireModule:  requireModule,
		ModuleActive:   fips140.Enabled(),
		ModuleEnforced: moduleEnforced(),
		ModuleVersion:  moduleVersion(),
		BuildVariant:   BuildVariant,
	}
}

// moduleVersion returns the GOFIPS140 module selector the binary was built with
// (e.g. "v1.0.0" or "latest"), or "" when it was not built with GOFIPS140. It is
// read from the recorded build settings, which is available on Go 1.24+ (unlike
// crypto/fips140.Version, which is Go 1.26+).
func moduleVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == "GOFIPS140" {
			if v := strings.TrimSpace(s.Value); v != "" && v != "off" {
				return v
			}
			return ""
		}
	}
	return ""
}

// Validate is the startup fail-fast gate. It returns an error when FIPS mode is
// requested (Enabled) and the validated module is required (RequireModule) but
// is not active in this process — the single condition under which an operator
// could falsely believe the deployment is FIPS compliant. It is a no-op when
// FIPS mode is disabled.
func (m Mode) Validate() error {
	if !m.Enabled {
		return nil
	}
	if m.RequireModule && !m.ModuleActive {
		return fmt.Errorf(
			"fips.enabled is set with fips.requireModule=true, but the Go FIPS 140-3 cryptographic module is not active in this process; " +
				"build the FIPS variant (`make build-fips`, which sets GOFIPS140) and run it with GODEBUG=fips140=on, " +
				"or set fips.requireModule=false to run approved-algorithm enforcement without the validated module")
	}
	return nil
}

// CryptoModeLabel returns a short label for the active crypto mode, suitable for
// logs and the admin API: "fips" when enforcement is enabled, else "standard".
func (m Mode) CryptoModeLabel() string {
	if m.Enabled {
		return "fips"
	}
	return "standard"
}

// LogAttrs returns the mode as a flat slice of structured-logging key/value
// pairs for a single startup log line.
func (m Mode) LogAttrs() []any {
	return []any{
		"mode", m.CryptoModeLabel(),
		"fips.enabled", m.Enabled,
		"fips.requireModule", m.RequireModule,
		"module.active", m.ModuleActive,
		"module.enforced", m.ModuleEnforced,
		"module.version", m.ModuleVersion,
		"build.variant", m.BuildVariant,
	}
}

// ApprovedCipherSuites returns a copy of the FIPS 140-3 approved configurable
// (TLS 1.2) cipher suites, in preference order.
func ApprovedCipherSuites() []uint16 {
	out := make([]uint16, len(approvedTLS12CipherSuites))
	copy(out, approvedTLS12CipherSuites)
	return out
}

// HardenServerTLSConfig applies the FIPS-approved floor to a server-side
// *tls.Config in place and returns it: it raises MinVersion to at least TLS 1.2
// and restricts the configurable cipher suites to the approved AES-GCM set. A
// nil input yields a fresh hardened config. It is safe to call on a config that
// already sets a higher MinVersion (the higher floor is preserved).
func HardenServerTLSConfig(c *tls.Config) *tls.Config {
	if c == nil {
		c = &tls.Config{}
	}
	if c.MinVersion < ApprovedTLSMinVersion {
		c.MinVersion = ApprovedTLSMinVersion
	}
	c.CipherSuites = ApprovedCipherSuites()
	return c
}

// HashApproved reports whether a hash / content-addressing algorithm identifier
// (e.g. "sha256", "SHA-512", "sha3-256") names a FIPS 140-3 approved algorithm.
// Matching is case-insensitive and tolerant of a "sha-" vs "sha" spelling and
// surrounding whitespace. An empty identifier is not approved.
func HashApproved(algo string) bool {
	return approvedHashes[normalizeHash(algo)]
}

func normalizeHash(algo string) string {
	s := strings.ToLower(strings.TrimSpace(algo))
	// Accept "sha-256" / "sha3-256" spellings by collapsing the first hyphen
	// that follows the "sha" family prefix.
	if strings.HasPrefix(s, "sha-") {
		s = "sha" + s[len("sha-"):]
	}
	return s
}

// TLSMinVersionApproved reports whether a configured TLS minVersion string
// ("", "1.0", "1.1", "1.2", "1.3") selects a FIPS-approved floor (>= TLS 1.2).
// An empty string (unset) is treated as approved: the proxy applies the TLS 1.2
// floor itself, and [HardenServerTLSConfig] raises it where a listener is built.
func TLSMinVersionApproved(v string) bool {
	switch strings.TrimSpace(v) {
	case "", "1.2", "1.3":
		return true
	default: // "1.0", "1.1", or anything else
		return false
	}
}
