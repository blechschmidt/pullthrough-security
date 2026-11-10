package fips

import (
	"crypto/tls"
	"testing"
)

func TestModeValidate(t *testing.T) {
	cases := []struct {
		name    string
		mode    Mode
		wantErr bool
	}{
		{"disabled is always ok", Mode{Enabled: false}, false},
		{"disabled ignores missing module", Mode{Enabled: false, RequireModule: true, ModuleActive: false}, false},
		{"enabled, module required and active", Mode{Enabled: true, RequireModule: true, ModuleActive: true}, false},
		{"enabled, module required but inactive", Mode{Enabled: true, RequireModule: true, ModuleActive: false}, true},
		{"enabled, module not required and inactive", Mode{Enabled: true, RequireModule: false, ModuleActive: false}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.mode.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestCryptoModeLabel(t *testing.T) {
	if got := (Mode{Enabled: true}).CryptoModeLabel(); got != "fips" {
		t.Fatalf("enabled label = %q, want fips", got)
	}
	if got := (Mode{Enabled: false}).CryptoModeLabel(); got != "standard" {
		t.Fatalf("disabled label = %q, want standard", got)
	}
}

func TestHashApproved(t *testing.T) {
	approved := []string{"sha256", "SHA-256", "  sha512 ", "SHA-384", "sha3-256", "sha512-256"}
	for _, a := range approved {
		if !HashApproved(a) {
			t.Errorf("HashApproved(%q) = false, want true", a)
		}
	}
	rejected := []string{"", "md5", "sha1", "sha-1", "crc32", "blake2b"}
	for _, a := range rejected {
		if HashApproved(a) {
			t.Errorf("HashApproved(%q) = true, want false", a)
		}
	}
}

func TestTLSMinVersionApproved(t *testing.T) {
	for _, v := range []string{"", "1.2", "1.3", " 1.2 "} {
		if !TLSMinVersionApproved(v) {
			t.Errorf("TLSMinVersionApproved(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"1.0", "1.1", "garbage"} {
		if TLSMinVersionApproved(v) {
			t.Errorf("TLSMinVersionApproved(%q) = true, want false", v)
		}
	}
}

func TestHardenServerTLSConfig(t *testing.T) {
	// nil input yields a hardened config.
	c := HardenServerTLSConfig(nil)
	if c.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want TLS 1.2 (%x)", c.MinVersion, tls.VersionTLS12)
	}
	if len(c.CipherSuites) != len(approvedTLS12CipherSuites) {
		t.Fatalf("CipherSuites length = %d, want %d", len(c.CipherSuites), len(approvedTLS12CipherSuites))
	}
	for _, cs := range c.CipherSuites {
		if cs == tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA || cs == tls.TLS_RSA_WITH_AES_128_GCM_SHA256 {
			t.Fatalf("approved suites unexpectedly contain a non-approved suite %x", cs)
		}
	}

	// A higher pre-set floor is preserved.
	c = HardenServerTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13})
	if c.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want preserved TLS 1.3 (%x)", c.MinVersion, tls.VersionTLS13)
	}
}

func TestApprovedCipherSuitesIsCopy(t *testing.T) {
	a := ApprovedCipherSuites()
	if len(a) == 0 {
		t.Fatal("ApprovedCipherSuites returned empty")
	}
	a[0] = 0xffff // mutate the returned slice
	if ApprovedCipherSuites()[0] == 0xffff {
		t.Fatal("ApprovedCipherSuites returns a shared backing array; callers can corrupt the policy")
	}
}

func TestDetectReflectsRuntime(t *testing.T) {
	// Detect must mirror the live module state. In the default (non-FIPS) test
	// build the module is inactive; under `make test-fips` it is active. Either
	// way Detect's module fields must agree with the package-level helpers.
	m := Detect(true, true)
	if !m.Enabled || !m.RequireModule {
		t.Fatalf("Detect did not carry intent: %+v", m)
	}
	if m.BuildVariant != BuildVariant {
		t.Fatalf("BuildVariant = %q, want %q", m.BuildVariant, BuildVariant)
	}
	// LogAttrs is an even-length key/value slice.
	if attrs := m.LogAttrs(); len(attrs)%2 != 0 {
		t.Fatalf("LogAttrs length = %d, want even", len(attrs))
	}
}
