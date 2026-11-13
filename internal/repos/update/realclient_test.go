package update

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestNpmReadsTheRewrite: real npm reads each rewritten lock file and finds
// the tree consistent with the manifests — `npm ls --package-lock-only`
// checks every entry against the ranges that require it, offline. The new
// versions are made up but within the ranges.
func TestNpmReadsTheRewrite(t *testing.T) {
	if testing.Short() {
		t.Skip("runs npm")
	}
	npm, err := exec.LookPath("npm")
	if err != nil {
		t.Skip("npm is not installed")
	}
	ms := npmUpdate("ms", "2.1.2", "2.1.99", fakeSHA512("ms-2.1.99"))
	sw := npmUpdate("string-width", "4.2.3", "4.2.99", fakeSHA512("sw-4.2.99"))
	lodash := npmUpdate("lodash", "4.17.20", "4.99.0", fakeSHA512("lodash-4.99.0"))
	for _, tc := range []struct {
		dir     string
		changes []Change
		want    map[string]string // top-level dependency → version npm reports
	}{
		{"npm-v1", []Change{ms, sw}, map[string]string{"ms": "2.1.99", "string-width-cjs": "4.2.99"}},
		{"npm-v2", []Change{ms, sw}, map[string]string{"ms": "2.1.99", "string-width-cjs": "4.2.99"}},
		{"npm-v3", []Change{ms, sw}, map[string]string{"ms": "2.1.99", "string-width-cjs": "4.2.99"}},
		{"npm-workspaces-v2", []Change{lodash, ms}, map[string]string{"left-pad": "1.3.0"}},
		{"npm-workspaces-v3", []Change{lodash, ms}, map[string]string{"left-pad": "1.3.0"}},
	} {
		t.Run(tc.dir, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string][]byte{"package-lock.json": fixture(t, tc.dir, "before", "package-lock.json")}
			after := apply(t, NativeUpdater("npm/package-lock.json"), "package-lock.json", files, tc.changes)
			copyTree(t, filepath.Join("testdata", tc.dir), dir, "before", "after", "GENERATED.md")
			if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), after["package-lock.json"], 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "npmrc"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(npm, "ls", "--package-lock-only", "--all", "--json")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "npm_config_cache="+filepath.Join(dir, "cache"), "npm_config_offline=true",
				"npm_config_update_notifier=false", "npm_config_userconfig="+filepath.Join(dir, "npmrc"), "HOME="+dir)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("npm ls: %v\n%s", err, out)
			}
			var tree struct {
				Problems     []string `json:"problems"`
				Dependencies map[string]struct {
					Version string `json:"version"`
				} `json:"dependencies"`
			}
			if err := json.Unmarshal(out, &tree); err != nil {
				t.Fatal(err)
			}
			if len(tree.Problems) > 0 {
				t.Fatalf("npm finds problems: %v", tree.Problems)
			}
			for name, v := range tc.want {
				if got := tree.Dependencies[name].Version; got != v {
					t.Errorf("npm reads %s %s, want %s", name, got, v)
				}
			}
		})
	}
}

// TestGoReadsTheRewrite: the go command parses the rewritten go.mod (`go mod
// edit -json`, offline) and finds the new requirements.
func TestGoReadsTheRewrite(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go is not installed")
	}
	dir := t.TempDir()
	files := map[string][]byte{"go.mod": fixture(t, "go-modules", "before", "go.mod"), "go.sum": fixture(t, "go-modules", "before", "go.sum")}
	indirect := goUpdate("github.com/inconshreveable/mousetrap", "v1.1.0", "v1.1.1", fakeH1("mz"), fakeH1("mm"))
	after := apply(t, NativeUpdater("go/go.mod"), "go.mod", files, append([]Change{indirect}, goUpdates...))
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), after["go.mod"], 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(gobin, "mod", "edit", "-json")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOFLAGS=")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go mod edit: %v\n%s", err, out)
	}
	var mod struct {
		Require []struct {
			Path, Version string
			Indirect      bool
		}
	}
	if err := json.Unmarshal(out, &mod); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range mod.Require {
		got[r.Path] = r.Version
		if r.Path == "github.com/inconshreveable/mousetrap" && !r.Indirect {
			t.Error("mousetrap lost its // indirect")
		}
	}
	for path, v := range map[string]string{"github.com/spf13/pflag": "v1.0.10", "github.com/google/uuid": "v1.6.0",
		"github.com/inconshreveable/mousetrap": "v1.1.1", "github.com/spf13/cobra": "v1.8.0"} {
		if got[path] != v {
			t.Errorf("go reads %s %s, want %s", path, got[path], v)
		}
	}
}

// copyTree copies the files under src to dst, but for the names skipped.
func copyTree(t *testing.T, src, dst string, skip ...string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		for _, s := range skip {
			if info.Name() == s {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}
