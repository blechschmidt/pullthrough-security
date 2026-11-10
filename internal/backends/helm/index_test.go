package helm

import (
	"strings"
	"testing"
)

const sampleIndex = `apiVersion: v1
entries:
  nginx:
    - name: nginx
      version: 1.2.3
      digest: 1111111111111111111111111111111111111111111111111111111111111111
      urls:
        - nginx-1.2.3.tgz
    - name: nginx
      version: 1.2.2
      digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
      urls:
        - https://cdn.example.com/charts/nginx-1.2.2.tgz
  empty:
    - name: empty
      version: ""
      digest: 3333333333333333333333333333333333333333333333333333333333333333
generated: "2024-01-02T03:04:05Z"
`

func TestParseIndex(t *testing.T) {
	idx, err := ParseIndex([]byte(sampleIndex))
	if err != nil {
		t.Fatalf("ParseIndex: %v", err)
	}
	if idx.APIVersion != "v1" {
		t.Errorf("apiVersion = %q", idx.APIVersion)
	}
	if len(idx.Entries["nginx"]) != 2 {
		t.Fatalf("nginx versions = %d, want 2", len(idx.Entries["nginx"]))
	}
	// The version-less "empty" entry must be dropped, removing the chart entirely.
	if _, ok := idx.Entries["empty"]; ok {
		t.Error("version-less entry should have been dropped")
	}
	// The "sha256:" prefix must be normalized away to bare hex.
	v122, ok := idx.FindVersion("nginx", "1.2.2")
	if !ok {
		t.Fatal("FindVersion(nginx,1.2.2) not found")
	}
	if v122.Digest != "2222222222222222222222222222222222222222222222222222222222222222" {
		t.Errorf("digest not normalized: %q", v122.Digest)
	}
}

func TestFindByFilename(t *testing.T) {
	idx, err := ParseIndex([]byte(sampleIndex))
	if err != nil {
		t.Fatalf("ParseIndex: %v", err)
	}
	// Relative URL basename match.
	if cv, ok := idx.FindByFilename("nginx-1.2.3.tgz"); !ok || cv.Version != "1.2.3" {
		t.Errorf("FindByFilename(nginx-1.2.3.tgz) = %+v, %v", cv, ok)
	}
	// Absolute URL basename match.
	if cv, ok := idx.FindByFilename("nginx-1.2.2.tgz"); !ok || cv.Version != "1.2.2" {
		t.Errorf("FindByFilename(nginx-1.2.2.tgz) = %+v, %v", cv, ok)
	}
	// A path is reduced to its basename.
	if cv, ok := idx.FindByFilename("/charts/nginx-1.2.3.tgz"); !ok || cv.Version != "1.2.3" {
		t.Errorf("FindByFilename with dir = %+v, %v", cv, ok)
	}
	if _, ok := idx.FindByFilename("absent-0.0.0.tgz"); ok {
		t.Error("FindByFilename should miss for an absent file")
	}
}

func TestParseIndexErrors(t *testing.T) {
	cases := map[string]string{
		"not yaml":   "\x00\x01 not: [valid",
		"no entries": "apiVersion: v1\ngenerated: now\n",
		"scalar top": "just a string",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseIndex([]byte(in)); err == nil {
				t.Errorf("ParseIndex(%q) expected error", in)
			}
		})
	}
}

func TestParseIndexTooLarge(t *testing.T) {
	big := make([]byte, maxIndexBytes+1)
	if _, err := ParseIndex(big); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected size-limit error, got %v", err)
	}
}

func TestChecksumFromEntry(t *testing.T) {
	idx, _ := ParseIndex([]byte(sampleIndex))
	cv, _ := idx.FindVersion("nginx", "1.2.3")
	cs, ok := cv.Checksum()
	if !ok || len(cs.hex) != sha256HexLen {
		t.Errorf("Checksum() = %+v, %v", cs, ok)
	}
}

func TestNormalizeDigest(t *testing.T) {
	good := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{good, good, true},
		{"SHA256:" + strings.ToUpper(good), good, true},
		{"sha512:" + good, "", false},
		{"tooshort", "", false},
		{"", "", false},
		{"zz" + good[2:], "", false},
	}
	for _, c := range cases {
		got, ok := normalizeDigest(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("normalizeDigest(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}
