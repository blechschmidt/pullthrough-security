//go:build fuzz
// +build fuzz

// Fuzz targets for the bazel feed's parsers (Task 190): a registry's
// metadata.json and source.json, the paths of its Git repository, and the
// commit headers the settle period is read from (feed_gitsettle.go, shared
// by the bazel, conan and homebrew feeds). Every input is the registry's;
// none of them may panic, and what they accept must stay bounded and name
// only paths the backend serves.
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzBazelMetadata$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/bazel"
)

func bazelFuzzSeeds(f *testing.F, prefix string) {
	entries, _ := os.ReadDir(filepath.Join("testdata", "feeds", "bazel"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			if data, err := os.ReadFile(filepath.Join("testdata", "feeds", "bazel", e.Name())); err == nil {
				f.Add(data)
			}
		}
	}
}

func FuzzBazelMetadata(f *testing.F) {
	bazelFuzzSeeds(f, "metadata-")
	for _, s := range []string{``, `null`, `[]`, `{"versions": null}`, `{"versions": "1.0"}`, `{"versions": [1, "1.0", "1.0", "a\u0000b"]}`,
		`{"versions": ["1.0"], "yanked_versions": {"1.0": null, "2.0": "x"}}`, `{"versions": [], "yanked_versions": []}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := bazelParseMetadata(data)
		if err != nil {
			return
		}
		if len(m.versions) > bazelMaxVersions {
			t.Fatalf("%d versions", len(m.versions))
		}
		seen := map[string]bool{}
		for _, v := range m.versions {
			if v == "" || len(v) > 256 || !cleanName(v) || seen[v] {
				t.Fatalf("version %q", v)
			}
			seen[v] = true
		}
		for v := range m.yanked {
			if !seen[v] {
				t.Fatalf("yanked %q is not listed", v)
			}
		}
	})
}

func FuzzBazelSource(f *testing.F) {
	bazelFuzzSeeds(f, "source-")
	for _, s := range []string{``, `null`, `{}`, `{"type": 1}`, `{"type": "git_repository", "patches": {"a.patch": 1}}`,
		`{"url": "", "mirror_urls": ["https://x"]}`, `{"urls": []}`, `{"overlay": {"../x": "", "a/b.c": "", "": ""}, "patches": []}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := bazelParseSource(data)
		if err != nil {
			return
		}
		for _, list := range [][]string{s.patches, s.overlay} {
			if len(list) > bazelMaxSourceFiles || !sort.StringsAreSorted(list) {
				t.Fatalf("%d entries, sorted %v", len(list), sort.StringsAreSorted(list))
			}
		}
		// Whatever the document names, a path the backend's builders accept
		// is one the engine may request.
		for _, p := range s.patches {
			if path, ok := bazel.PatchPath("zlib", "1.0", p); ok && !validArtifactPath(path) {
				t.Fatalf("patch %q: path %q", p, path)
			}
		}
		for _, o := range s.overlay {
			if path, ok := bazel.OverlayPath("zlib", "1.0", o); ok && !validArtifactPath(path) {
				t.Fatalf("overlay %q: path %q", o, path)
			}
		}
	})
}

func FuzzBazelCoordinate(f *testing.F) {
	for _, s := range []string{"modules/zlib/1.3.1/MODULE.bazel", "modules/zlib/metadata.json", "modules/zlib/1.3.1/overlay/a/b",
		"modules/../1/MODULE.bazel", "modules//1/source.json", "modules/a/b/c/d/e", "", "/", "modules"} {
		f.Add(s, uint8(gitAdded))
		f.Add(s, uint8(gitDeleted))
	}
	f.Fuzz(func(t *testing.T, p string, change uint8) {
		_ = bazelArea(p)
		c, ok := bazelCoordinate(p, gitChange(change%4))
		if !ok {
			return
		}
		if _, ok := bazel.ModuleFilePath(c.Name, c.Version); !ok || !cleanName(c.Name) {
			t.Fatalf("%q gave %+v", p, c)
		}
	})
}

func FuzzGitSettleCommit(f *testing.F) {
	tree := strings.Repeat("ab", 20)
	for _, s := range []string{
		"tree " + tree + "\nparent " + strings.Repeat("cd", 20) + "\nauthor A <a@example.org> 1 +0000\ncommitter C <c@example.org> 1763230585 +0000\n\nmsg\n",
		"tree " + tree + "\nparent " + strings.Repeat("cd", 20) + "\nparent " + strings.Repeat("ef", 20) + "\ncommitter C <c> 5 +0100\n\nmerge",
		"tree " + tree + "\nparent xyz\n\n",
		"tree " + tree + "\n\nparent " + strings.Repeat("cd", 20) + "\n",
		"", "\n", "parent " + strings.Repeat("cd", 20),
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		when, parents, err := gitSettleCommit(data)
		if err != nil {
			return
		}
		if len(parents) > bytes.Count(data, []byte("parent ")) {
			t.Fatalf("%d parents", len(parents))
		}
		if !when.IsZero() && when.After(time.Unix(1<<40, 0)) {
			t.Fatalf("time %v", when)
		}
	})
}
