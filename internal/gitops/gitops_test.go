package gitops

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/config"
)

// writeConfigFile marshals the default config to a YAML file and returns its path
// together with the loaded *Config (the "running" config).
func writeConfigFile(t *testing.T) (string, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data, err := yaml.Marshal(config.Default())
	if err != nil {
		t.Fatalf("marshal default config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return path, cfg
}

// writeBundle writes a desired-state bundle (setting snapshot.maxSnapshots) and
// returns its path.
func writeBundle(t *testing.T, dir string, maxSnapshots int) string {
	t.Helper()
	b := Bundle{
		APIVersion:  BundleAPIVersion,
		Revision:    "v1",
		Description: "test bundle",
		Settings: []Setting{
			{Path: "snapshot.maxSnapshots", Value: maxSnapshots, Desc: "test"},
		},
	}
	data, err := yaml.Marshal(b)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	path := filepath.Join(dir, "bundle.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

func TestParseBundle(t *testing.T) {
	good := []byte("apiVersion: " + BundleAPIVersion + "\nsettings:\n  - path: policyEngine.mode\n    value: enforce\n")
	b, err := ParseBundle(good)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if len(b.Settings) != 1 || b.Settings[0].Path != "policyEngine.mode" {
		t.Fatalf("unexpected settings: %+v", b.Settings)
	}

	for _, tc := range []string{
		"",
		"apiVersion: wrong/v9\nsettings: []\n",
		"apiVersion: " + BundleAPIVersion + "\nsettings: []\n",
		"apiVersion: " + BundleAPIVersion + "\nsettings:\n  - path: \"\"\n    value: 1\n",
		"apiVersion: " + BundleAPIVersion + "\nsettings:\n  - path: a.b\n    value: 1\n  - path: a.b\n    value: 2\n",
	} {
		if _, err := ParseBundle([]byte(tc)); err == nil {
			t.Fatalf("expected error parsing %q", tc)
		}
	}
}

func TestApplyReconcileAndRollback(t *testing.T) {
	cfgPath, live := writeConfigFile(t)
	bundlePath := writeBundle(t, filepath.Dir(cfgPath), 123)

	svc, err := New(Config{
		Enabled:    true,
		Mode:       ModeApply,
		ConfigPath: cfgPath,
		Interval:   time.Hour,
	}, live, NewLocalSource(bundlePath), nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out, err := svc.Reconcile(context.Background(), "test", "tester")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if out.Result != "applied" || !out.Applied {
		t.Fatalf("expected applied, got %+v", out)
	}
	if out.Changed != 1 {
		t.Fatalf("expected 1 change, got %d", out.Changed)
	}

	// The on-disk config should now carry the bundle's setting.
	patched, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload patched config: %v", err)
	}
	if patched.Snapshot.MaxSnapshots != 123 {
		t.Fatalf("expected maxSnapshots=123 on disk, got %d", patched.Snapshot.MaxSnapshots)
	}

	// A second reconcile is idempotent: the in-memory live was updated, so we are
	// now in sync and nothing re-applies.
	out2, err := svc.Reconcile(context.Background(), "test", "tester")
	if err != nil {
		t.Fatalf("Reconcile #2: %v", err)
	}
	if out2.Result != "in_sync" || out2.Applied {
		t.Fatalf("expected in_sync on second pass, got %+v", out2)
	}

	st := svc.Status()
	if st.LastApplied == nil || st.LastApplied.Changed != 1 {
		t.Fatalf("expected apply history, got %+v", st.LastApplied)
	}
	if !st.InSync {
		t.Fatalf("expected InSync status")
	}

	// Roll back to the last-known-good config (pre-apply state).
	res, err := svc.Rollback(context.Background(), "tester", "revert test")
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if res.RolledBackFrom != "v1" {
		t.Fatalf("unexpected rollback from %q", res.RolledBackFrom)
	}
	restored, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload restored config: %v", err)
	}
	if restored.Snapshot.MaxSnapshots != 0 {
		t.Fatalf("expected maxSnapshots restored to 0, got %d", restored.Snapshot.MaxSnapshots)
	}
}

func TestVerifyDigestAndSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	bundle := []byte("apiVersion: " + BundleAPIVersion + "\nsettings:\n  - path: policyEngine.mode\n    value: enforce\n")
	sig, err := signDetached(priv, bundle)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigB64 := []byte(base64.StdEncoding.EncodeToString(sig))

	// Digest pin + valid signature → verified.
	v, err := NewVerifier(pemBytes, Digest(bundle))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	res := v.Verify(bundle, sigB64)
	if !res.Verified || !res.SignatureOK || !res.DigestOK {
		t.Fatalf("expected verified, got %+v", res)
	}

	// Tampered bundle → digest mismatch.
	if r := v.Verify([]byte("apiVersion: x\n"), sigB64); r.Verified {
		t.Fatalf("expected digest mismatch failure, got %+v", r)
	}

	// Missing signature when a key is configured → not verified.
	vKeyOnly, _ := NewVerifier(pemBytes, "")
	if r := vKeyOnly.Verify(bundle, nil); r.Verified {
		t.Fatalf("expected missing-signature failure, got %+v", r)
	}

	// No trust configured → unverified-but-allowed.
	vNone, _ := NewVerifier(nil, "")
	if r := vNone.Verify(bundle, nil); !r.Verified {
		t.Fatalf("expected pass-through verification, got %+v", r)
	}
}

func TestFailClosedRefusesUnverifiedBundle(t *testing.T) {
	cfgPath, live := writeConfigFile(t)
	bundlePath := writeBundle(t, filepath.Dir(cfgPath), 99)

	pub, _, _ := ed25519.GenerateKey(nil)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	verifier, _ := NewVerifier(pemBytes, "") // key configured but bundle is unsigned

	svc, err := New(Config{
		Enabled:    true,
		Mode:       ModeApply,
		ConfigPath: cfgPath,
		FailClosed: true,
	}, live, NewLocalSource(bundlePath), verifier, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, err := svc.Reconcile(context.Background(), "test", "tester")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if out.Result != "verify_failed" || out.Applied {
		t.Fatalf("expected verify_failed, got %+v", out)
	}
	// Config must be untouched.
	after, _ := config.Load(cfgPath)
	if after.Snapshot.MaxSnapshots != 0 {
		t.Fatalf("config should be untouched, got maxSnapshots=%d", after.Snapshot.MaxSnapshots)
	}
}

// stubApprover is a controllable ApprovalConsulter for suggest-mode tests.
type stubApprover struct {
	allow bool
}

func (s *stubApprover) Enabled() bool { return true }
func (s *stubApprover) Consult(_ context.Context, _ approvals.Scope) approvals.Disposition {
	return approvals.Disposition{Allow: s.allow, RequestID: "req-1"}
}

func TestSuggestModeRequiresApproval(t *testing.T) {
	cfgPath, live := writeConfigFile(t)
	bundlePath := writeBundle(t, filepath.Dir(cfgPath), 77)

	appr := &stubApprover{allow: false}
	svc, err := New(Config{
		Enabled:    true,
		Mode:       ModeSuggest,
		ConfigPath: cfgPath,
	}, live, NewLocalSource(bundlePath), nil, nil, WithApprovals(appr))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out, err := svc.Reconcile(context.Background(), "test", "tester")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if out.Result != "pending_approval" || !out.Pending {
		t.Fatalf("expected pending_approval, got %+v", out)
	}
	if after, _ := config.Load(cfgPath); after.Snapshot.MaxSnapshots != 0 {
		t.Fatalf("config should be untouched while pending, got %d", after.Snapshot.MaxSnapshots)
	}
	if st := svc.Status(); st.Pending == nil || st.Pending.RequestID != "req-1" {
		t.Fatalf("expected pending change in status, got %+v", st.Pending)
	}

	// Once approved, the next reconcile applies.
	appr.allow = true
	out2, err := svc.Reconcile(context.Background(), "test", "tester")
	if err != nil {
		t.Fatalf("Reconcile #2: %v", err)
	}
	if out2.Result != "applied" || !out2.Applied {
		t.Fatalf("expected applied after approval, got %+v", out2)
	}
	if after, _ := config.Load(cfgPath); after.Snapshot.MaxSnapshots != 77 {
		t.Fatalf("expected applied config, got %d", after.Snapshot.MaxSnapshots)
	}
}

func TestStatePersistence(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "gitops.json")
	st := &state{LastRevision: "abc", LastOutcome: "applied"}
	st.append(AppliedEntry{Revision: "abc", Changed: 2})
	if err := saveState(storePath, st); err != nil {
		t.Fatalf("saveState: %v", err)
	}
	loaded, err := loadState(storePath)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if loaded.LastRevision != "abc" || len(loaded.History) != 1 {
		t.Fatalf("unexpected loaded state: %+v", loaded)
	}
	if !strings.Contains(loaded.head().Revision, "abc") {
		t.Fatalf("unexpected head: %+v", loaded.head())
	}
}
