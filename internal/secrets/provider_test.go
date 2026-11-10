package secrets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRef(t *testing.T) {
	cases := []struct {
		in      string
		wantRef bool
		wantErr bool
		scheme  string
		path    string
		key     string
	}{
		{in: "plain-token", wantRef: false},
		{in: "https://hooks.slack.com/x", wantRef: false}, // non-secret scheme stays literal
		{in: "env://MY_VAR", wantRef: true, scheme: SchemeEnv, path: "MY_VAR"},
		{in: "file:///etc/creds/token", wantRef: true, scheme: SchemeFile, path: "/etc/creds/token"},
		{in: "vault://kv/data/app#password", wantRef: true, scheme: SchemeVault, path: "kv/data/app", key: "password"},
		{in: "literal://env://not-a-ref", wantRef: true, scheme: SchemeLiteral, path: "env://not-a-ref"},
		{in: "vault://kv/app", wantRef: false, wantErr: true}, // missing #key
		{in: "env://", wantRef: false, wantErr: true},
		{in: "file://", wantRef: false, wantErr: true},
	}
	for _, c := range cases {
		ref, err := ParseRef(c.in)
		switch {
		case c.wantErr:
			if err == nil || err == ErrNotRef {
				t.Fatalf("%q: want parse error, got ref=%+v err=%v", c.in, ref, err)
			}
			continue
		case !c.wantRef:
			if err != ErrNotRef {
				t.Fatalf("%q: want ErrNotRef, got %v", c.in, err)
			}
			if IsRef(c.in) {
				t.Fatalf("%q: IsRef should be false", c.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: unexpected error %v", c.in, err)
		}
		if !IsRef(c.in) {
			t.Fatalf("%q: IsRef should be true", c.in)
		}
		if ref.Scheme != c.scheme || ref.Path != c.path || ref.Key != c.key {
			t.Fatalf("%q: got %+v", c.in, ref)
		}
	}
}

func TestResolverLiteralPassthrough(t *testing.T) {
	r := NewResolver(nil)
	defer r.Close()
	got, err := r.Resolve(context.Background(), "just-a-literal")
	if err != nil || got != "just-a-literal" {
		t.Fatalf("passthrough: got %q err %v", got, err)
	}
	// A literal resolution records no metric.
	snap := r.Metrics()
	if len(snap.ResolveSuccess) != 0 || len(snap.ResolveFailure) != 0 {
		t.Fatalf("literal passthrough should not be counted: %+v", snap)
	}
}

func TestResolverEnv(t *testing.T) {
	r := NewResolver(nil)
	defer r.Close()
	t.Setenv("PTS_TEST_SECRET", "s3cr3t")
	got, err := r.Resolve(context.Background(), "env://PTS_TEST_SECRET")
	if err != nil {
		t.Fatalf("resolve env: %v", err)
	}
	if got != "s3cr3t" {
		t.Fatalf("got %q", got)
	}
	// Missing env var is an error, counted as a failure.
	if _, err := r.Resolve(context.Background(), "env://PTS_TEST_MISSING"); err == nil {
		t.Fatalf("expected error for missing env var")
	}
	snap := r.Metrics()
	if snap.ResolveSuccess[SchemeEnv] != 1 || snap.ResolveFailure[SchemeEnv] != 1 {
		t.Fatalf("metrics: %+v", snap)
	}
}

func TestResolverEnvNeverLeaksValueInError(t *testing.T) {
	r := NewResolver(nil)
	defer r.Close()
	t.Setenv("PTS_TEST_EMPTY", "")
	_, err := r.Resolve(context.Background(), "env://PTS_TEST_EMPTY")
	if err == nil {
		t.Fatalf("empty env var must error")
	}
}

func TestFileProviderPermissionChecks(t *testing.T) {
	dir := t.TempDir()
	r := NewResolver(nil)
	defer r.Close()

	secure := filepath.Join(dir, "secure")
	if err := os.WriteFile(secure, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := r.Resolve(context.Background(), "file://"+secure)
	if err != nil {
		t.Fatalf("secure file: %v", err)
	}
	if got != "file-secret" { // trailing newline trimmed
		t.Fatalf("got %q", got)
	}

	// World/group-accessible file is rejected.
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(context.Background(), "file://"+loose); err == nil {
		t.Fatalf("expected rejection of overly-permissive file")
	} else if !strings.Contains(err.Error(), "permissive") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Missing file errors.
	if _, err := r.Resolve(context.Background(), "file://"+filepath.Join(dir, "nope")); err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestLiteralProvider(t *testing.T) {
	r := NewResolver(nil)
	defer r.Close()
	got, err := r.Resolve(context.Background(), "literal://env://looks-like-a-ref")
	if err != nil {
		t.Fatalf("literal: %v", err)
	}
	if got != "env://looks-like-a-ref" {
		t.Fatalf("got %q", got)
	}
}

func TestResolverUnconfiguredVaultIsError(t *testing.T) {
	r := NewResolver(nil)
	defer r.Close()
	if _, err := r.Resolve(context.Background(), "vault://kv/app#pw"); err == nil {
		t.Fatalf("expected error when vault provider not registered")
	}
	if r.Metrics().ResolveFailure[SchemeVault] != 1 {
		t.Fatalf("failure should be counted")
	}
}
