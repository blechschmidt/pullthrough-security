package docker

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func sha256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%x", sum)
}

func TestParseDigest(t *testing.T) {
	valid := sha256Digest([]byte("hello"))
	if _, err := ParseDigest(valid); err != nil {
		t.Fatalf("ParseDigest(%q) unexpected error: %v", valid, err)
	}
	if !IsDigest(valid) {
		t.Errorf("IsDigest(%q) = false, want true", valid)
	}

	bad := []string{
		"",
		"latest",
		"sha256:tooshort",
		"sha256:" + strings.Repeat("Z", 64), // non-hex
		"sha256:" + strings.Repeat("a", 63), // wrong length
		"md5:" + strings.Repeat("a", 32),    // unsupported algorithm
		"sha256:" + strings.Repeat("A", 64), // uppercase hex rejected (non-canonical)
	}
	for _, s := range bad {
		if IsDigest(s) {
			t.Errorf("IsDigest(%q) = true, want false", s)
		}
	}
}

func TestVerifyingReaderPasses(t *testing.T) {
	content := []byte("the quick brown fox")
	d, err := ParseDigest(sha256Digest(content))
	if err != nil {
		t.Fatal(err)
	}
	vr := newVerifyingReader(io.NopCloser(strings.NewReader(string(content))), d)
	got, err := io.ReadAll(vr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content = %q, want %q", got, content)
	}
}

func TestVerifyingReaderDetectsMismatch(t *testing.T) {
	// Digest of different content than what the reader will serve.
	d, err := ParseDigest(sha256Digest([]byte("expected content")))
	if err != nil {
		t.Fatal(err)
	}
	vr := newVerifyingReader(io.NopCloser(strings.NewReader("tampered content")), d)
	_, err = io.ReadAll(vr)
	if err == nil {
		t.Fatal("expected a digest mismatch error, got nil")
	}
	var mism *DigestMismatchError
	if !errors.As(err, &mism) {
		t.Fatalf("error = %v, want *DigestMismatchError", err)
	}
	if mism.Expected != d.String() {
		t.Errorf("Expected = %q, want %q", mism.Expected, d.String())
	}
}
