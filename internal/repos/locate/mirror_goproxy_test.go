package locate

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

func TestGoEscapePathMatchesTheGoLocator(t *testing.T) {
	for in, want := range map[string]string{
		"github.com/BurntSushi/toml": "github.com/!burnt!sushi/toml",
		"github.com/google/uuid":     "github.com/google/uuid",
		"github.com/DOCKER/DOCKER":   "github.com/!d!o!c!k!e!r/!d!o!c!k!e!r",
		"v1.0.0-RC1":                 "v1.0.0-!r!c1",
	} {
		got, err := GoEscapePath(in)
		if err != nil || got != want {
			t.Errorf("GoEscapePath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"github.com/a!b/c", "example.com/ü"} {
		if got, err := GoEscapePath(bad); err == nil {
			t.Errorf("GoEscapePath(%q) = %q, want an error", bad, got)
		}
	}
	// The escaped module is the prefix of every path the locator names for
	// one of its versions.
	env := Env{Upstreams: []Upstream{{Name: "gomod", Type: "go", URLs: []string{"https://proxy.golang.org"}}}}
	plan, err := Locate(context.Background(), env, lockfiles.Dependency{Type: "go", Name: "github.com/BurntSushi/toml", Version: "v1.3.2"})
	if err != nil {
		t.Fatal(err)
	}
	esc, _ := GoEscapePath("github.com/BurntSushi/toml")
	for _, a := range plan.Artifacts {
		if !strings.HasPrefix(a.Path, "/"+esc+"/@v/") {
			t.Errorf("located %s, not beneath /%s/@v/", a.Path, esc)
		}
	}
}
