package selfrelease

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/rekor"
)

func writeRekorSidecar(t *testing.T, dir, binBase string, entry *rekor.LogEntry, key []byte) {
	t.Helper()
	b, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, binBase+".rekor.json"), b, 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
	if key != nil {
		if err := os.WriteFile(filepath.Join(dir, "rekor-pubkey.pem"), key, 0o644); err != nil {
			t.Fatalf("write key: %v", err)
		}
	}
}

func TestVerifyRekor_NoSidecar(t *testing.T) {
	c := verifyRekor(t.TempDir(), "pullthrough")
	if c.Status != StatusSkip {
		t.Errorf("expected SKIP without a sidecar, got %s: %s", c.Status, c.Detail)
	}
}

func TestVerifyRekor_PassWithKey(t *testing.T) {
	dir := t.TempDir()
	log := rekor.NewFakeLog(nil)
	log.Append([]byte("seed"))
	entry := log.Append([]byte("release-attestation"))
	writeRekorSidecar(t, dir, "pullthrough", entry, log.PublicKeyPEM())

	c := verifyRekor(dir, "pullthrough")
	if c.Status != StatusPass {
		t.Errorf("expected PASS, got %s: %s", c.Status, c.Detail)
	}
}

func TestVerifyRekor_WarnWithoutKey(t *testing.T) {
	dir := t.TempDir()
	log := rekor.NewFakeLog(nil)
	entry := log.Append([]byte("release-attestation"))
	writeRekorSidecar(t, dir, "pullthrough", entry, nil)

	c := verifyRekor(dir, "pullthrough")
	if c.Status != StatusWarn {
		t.Errorf("expected WARN without a log key, got %s: %s", c.Status, c.Detail)
	}
}

func TestVerifyRekor_FailOnTamper(t *testing.T) {
	dir := t.TempDir()
	log := rekor.NewFakeLog(nil)
	entry := log.Append([]byte("release-attestation"))
	entry.InclusionProof.RootHash = "00" + entry.InclusionProof.RootHash[2:]
	writeRekorSidecar(t, dir, "pullthrough", entry, log.PublicKeyPEM())

	c := verifyRekor(dir, "pullthrough")
	if c.Status != StatusFail {
		t.Errorf("expected FAIL on a tampered root, got %s: %s", c.Status, c.Detail)
	}
}
