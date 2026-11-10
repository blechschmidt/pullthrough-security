package config

import (
	"strings"
	"testing"
)

// hasIssue reports whether the report contains an issue of the given severity
// whose path equals path (when non-empty) and whose message contains substr.
func hasIssue(r *Report, sev Severity, path, substr string) bool {
	for _, is := range r.Issues {
		if is.Severity != sev {
			continue
		}
		if path != "" && is.Path != path {
			continue
		}
		if substr != "" && !strings.Contains(is.Message, substr) {
			continue
		}
		return true
	}
	return false
}

func TestCheckBytesMinimalConfigIsValid(t *testing.T) {
	r := CheckBytes([]byte("server:\n  httpAddr: \":8080\"\n"))
	if !r.OK || r.Errors != 0 {
		t.Fatalf("expected a valid minimal config, got errors=%d issues=%+v", r.Errors, r.Issues)
	}
	if r.Fingerprint == "" {
		t.Fatalf("expected a fingerprint on a valid report")
	}
	// No upstreams configured is a warning, not an error.
	if !hasIssue(r, SeverityWarning, "upstreams", "no upstreams") {
		t.Fatalf("expected the no-upstreams warning, got %+v", r.Issues)
	}
}

func TestCheckBytesUnknownKeyIsError(t *testing.T) {
	// A typo'd key under server must be caught by the strict decoder.
	r := CheckBytes([]byte("server:\n  htpAddr: \":9090\"\n"))
	if r.OK || r.Errors == 0 {
		t.Fatalf("expected an error for the unknown key, got %+v", r.Issues)
	}
	if !hasIssue(r, SeverityError, "", "htpAddr") {
		t.Fatalf("expected an unknown-field error mentioning htpAddr, got %+v", r.Issues)
	}
}

func TestCheckBytesTypeMismatchIsError(t *testing.T) {
	// A string where a bool is expected is a strict-decode type error.
	r := CheckBytes([]byte("observability:\n  metrics: \"yes please\"\n"))
	if r.Errors == 0 {
		t.Fatalf("expected a type-mismatch error, got %+v", r.Issues)
	}
}

func TestCheckBytesSurfacesMultipleUnknownKeysAtOnce(t *testing.T) {
	r := CheckBytes([]byte("server:\n  bogusOne: 1\n  bogusTwo: 2\n"))
	got := 0
	for _, is := range r.Issues {
		if is.Severity == SeverityError && (strings.Contains(is.Message, "bogusOne") || strings.Contains(is.Message, "bogusTwo")) {
			got++
		}
	}
	if got < 2 {
		t.Fatalf("expected both unknown keys reported in one pass, got %d: %+v", got, r.Issues)
	}
}

func TestCheckBytesSyntaxErrorIsTerminal(t *testing.T) {
	r := CheckBytes([]byte("server: : :\n  - broken\n"))
	if r.Errors == 0 {
		t.Fatalf("expected a syntax error, got %+v", r.Issues)
	}
}

func TestConsistencyLicenseRequiresVuln(t *testing.T) {
	cfg := Default()
	cfg.License.Enabled = true
	cfg.Vulnerabilities.Enabled = false
	var r Report
	cfg.checkConsistency(&r)
	if !hasIssue(&r, SeverityWarning, "license.enabled", "vulnerabilities") {
		t.Fatalf("expected license-requires-vuln warning, got %+v", r.Issues)
	}
}

func TestConsistencyEncryptedValueNeedsKey(t *testing.T) {
	t.Setenv("PTS_SECRETS_KEY", "")
	cfg := Default()
	cfg.Scanning.APIKey = "enc:v1:ZmFrZWNpcGhlcg=="
	cfg.Secrets.KeyFile = ""
	cfg.Secrets.Passphrase = ""
	var r Report
	cfg.checkConsistency(&r)
	if !hasIssue(&r, SeverityError, "secrets", "enc:v1") {
		t.Fatalf("expected encrypted-without-key error, got %+v", r.Issues)
	}

	// Providing a key source clears it.
	cfg.Secrets.KeyFile = "/etc/keys/master.key"
	var r2 Report
	cfg.checkConsistency(&r2)
	if hasIssue(&r2, SeverityError, "secrets", "enc:v1") {
		t.Fatalf("expected no error once a key is configured, got %+v", r2.Issues)
	}
}

func TestReportFinalizeSortsAndDedupes(t *testing.T) {
	r := &Report{}
	r.warnf("b.field", "a warning")
	r.errorf("a.field", "an error")
	r.warnf("b.field", "a warning") // duplicate
	r.finalize()
	if len(r.Issues) != 2 {
		t.Fatalf("expected dedupe to 2 issues, got %d: %+v", len(r.Issues), r.Issues)
	}
	if r.Issues[0].Severity != SeverityError {
		t.Fatalf("expected errors sorted first, got %+v", r.Issues)
	}
	if r.Errors != 1 || r.Warnings != 1 || r.OK {
		t.Fatalf("unexpected counts: errors=%d warnings=%d ok=%v", r.Errors, r.Warnings, r.OK)
	}
}
