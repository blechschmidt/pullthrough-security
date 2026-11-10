package maven

import (
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:])
}

func sha1Hex(b []byte) string {
	sum := sha1.Sum(b)
	return fmt.Sprintf("%x", sum[:])
}

func algByName(t *testing.T, name string) checksumAlg {
	t.Helper()
	for _, a := range verifyAlgorithms {
		if a.name == name {
			return a
		}
	}
	t.Fatalf("unknown algorithm %q", name)
	return checksumAlg{}
}

func TestParseChecksumValue(t *testing.T) {
	sha256 := algByName(t, "sha256")
	want := sha256Hex([]byte("hello"))

	cases := []struct {
		name string
		body string
		ok   bool
	}{
		{"bare hex", want, true},
		{"hex with filename", want + "  hello.jar", true},
		{"uppercase", strings.ToUpper(want), true},
		{"trailing newline", want + "\n", true},
		{"bsd style", "hello.jar: " + want, true},
		{"empty", "", false},
		{"too short", "abc123", false},
		{"non hex", strings.Repeat("z", 64), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseChecksumValue([]byte(tc.body), sha256)
			if tc.ok {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !strings.EqualFold(got, want) {
					t.Errorf("got %q, want %q", got, want)
				}
			} else if err == nil {
				t.Errorf("expected error for %q, got %q", tc.body, got)
			}
		})
	}
}

func TestVerifyingReaderPass(t *testing.T) {
	data := []byte("the genuine artifact bytes")
	exp := expectedChecksum{alg: algByName(t, "sha256"), hex: sha256Hex(data)}

	var called, result bool
	vr := newVerifyingReader(io.NopCloser(strings.NewReader(string(data))), exp, "http://x", func(ok bool) {
		called, result = true, ok
	})
	out, err := io.ReadAll(vr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(out) != string(data) {
		t.Errorf("content mangled: %q", out)
	}
	if !called || !result {
		t.Errorf("onResult called=%v result=%v, want true/true", called, result)
	}
}

func TestVerifyingReaderMismatch(t *testing.T) {
	served := []byte("POISONED PAYLOAD")
	exp := expectedChecksum{alg: algByName(t, "sha256"), hex: sha256Hex([]byte("the real bytes"))}

	var result = true
	vr := newVerifyingReader(io.NopCloser(strings.NewReader(string(served))), exp, "http://x/lib.jar", func(ok bool) {
		result = ok
	})
	_, err := io.ReadAll(vr)
	var mm *ChecksumMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected ChecksumMismatchError, got %v", err)
	}
	if result {
		t.Error("onResult should report failure")
	}
	if mm.Algorithm != "sha256" {
		t.Errorf("mismatch algorithm = %q", mm.Algorithm)
	}
}

func TestVerifyBytes(t *testing.T) {
	data := []byte("<project/>")
	exp := expectedChecksum{alg: algByName(t, "sha1"), hex: sha1Hex(data)}
	if err := verifyBytes(data, exp, "http://x"); err != nil {
		t.Fatalf("verifyBytes (good): %v", err)
	}

	bad := expectedChecksum{alg: algByName(t, "sha1"), hex: sha1Hex([]byte("other"))}
	if err := verifyBytes(data, bad, "http://x"); err == nil {
		t.Error("verifyBytes (bad): expected mismatch error")
	}
}
