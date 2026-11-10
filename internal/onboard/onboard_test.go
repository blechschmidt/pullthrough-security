package onboard

import (
	"strings"
	"testing"
)

func ctx(token string) Context {
	return Context{ProxyBase: "https://proxy.example.com", Host: "proxy.example.com", Tenant: "acme", Token: token}
}

func TestForKnownTypesEmbedMountAndToken(t *testing.T) {
	c := ctx("secret-tok")
	cases := []struct {
		typ      string
		mustHave []string
	}{
		{"npm", []string{"registry=https://proxy.example.com/v1/x/", "_authToken=secret-tok"}},
		{"pip", []string{"index-url = https://secret-tok@proxy.example.com/v1/x/simple/"}},
		{"go", []string{"GOPROXY=https://proxy.example.com/v1/x,direct", "password secret-tok"}},
		{"docker", []string{"docker login proxy.example.com", "secret-tok"}},
	}
	for _, tc := range cases {
		t.Run(tc.typ, func(t *testing.T) {
			snips := For(c, Backend{Name: "x", Type: tc.typ})
			if len(snips) == 0 {
				t.Fatalf("no snippets for %s", tc.typ)
			}
			blob := snips[0].Body + strings.Join(snips[0].Notes, "\n")
			for _, want := range tc.mustHave {
				if !strings.Contains(blob, want) {
					t.Errorf("%s snippet missing %q\n%s", tc.typ, want, blob)
				}
			}
		})
	}
}

func TestForPlaceholderWithoutToken(t *testing.T) {
	snips := For(ctx(""), Backend{Name: "npm", Type: "npm"})
	if !strings.Contains(snips[0].Body, "${PULLTHROUGH_TOKEN}") {
		t.Errorf("expected token placeholder, got:\n%s", snips[0].Body)
	}
}

func TestForUnknownTypeIsAdvisory(t *testing.T) {
	snips := For(ctx(""), Backend{Name: "weird", Type: "quux"})
	if len(snips) != 1 || len(snips[0].Notes) == 0 {
		t.Fatalf("unknown type should yield an advisory snippet, got %+v", snips)
	}
	if !strings.Contains(snips[0].Notes[0], "/v1/weird") {
		t.Errorf("advisory should mention the mount, got %q", snips[0].Notes[0])
	}
}

func TestForAllCoversEveryBackend(t *testing.T) {
	snips := ForAll(ctx(""), []Backend{{Name: "npm", Type: "npm"}, {Name: "pypi", Type: "pip"}})
	if len(snips) != 2 {
		t.Fatalf("ForAll = %d snippets, want 2", len(snips))
	}
}

func TestWithUserinfoEncodesToken(t *testing.T) {
	got := WithUserinfo("https://proxy.example.com/v1/npm", "abc/123")
	want := "https://abc%2F123@proxy.example.com/v1/npm"
	if got != want {
		t.Errorf("WithUserinfo = %q, want %q", got, want)
	}
	if WithUserinfo("https://x/y", "") != "https://x/y" {
		t.Error("empty token should not alter the URL")
	}
}
