package lockfiles

import (
	"reflect"
	"strings"
	"testing"
)

// TestCargoLockWhoseChecksumsCargoDiscards: Cargo reads a format 2 or later
// lock file that still has [metadata] checksums as a bad merge and discards
// every checksum, so the scan must not report the crates as pinned.
func TestCargoLockWhoseChecksumsCargoDiscards(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	lock := "version = 3\n\n" +
		"[[package]]\nname = \"itoa\"\nversion = \"1.0.11\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"" + sum + "\"\n\n" +
		"[[package]]\nname = \"semver\"\nversion = \"1.0.23\"\nsource = \"git+https://github.com/dtolnay/semver?tag=1.0.23#69efd3cc770ead273a06ad1788477b3092996d29\"\n"
	f := ParseFile(nil, nil, "Cargo.lock", []byte(lock))
	if d := dependencyNamed(t, f, "itoa"); d.Unverified || len(d.Digests) != 1 {
		t.Fatalf("a well-formed lock file: %+v", d)
	}
	for _, bad := range []string{
		lock + "\n[metadata]\n\"checksum nothing-here 9.9.9 (registry+https://github.com/rust-lang/crates.io-index)\" = \"" + sum + "\"\n",
		// No version key: the inline checksum alone makes it format 2.
		strings.TrimPrefix(lock, "version = 3\n\n") + "\n[metadata]\n\"checksum itoa 1.0.11 (registry+https://github.com/rust-lang/crates.io-index)\" = \"" + sum + "\"\n",
	} {
		f := ParseFile(nil, nil, "Cargo.lock", []byte(bad))
		d := dependencyNamed(t, f, "itoa")
		if !d.Unverified || len(d.Digests) != 0 || !strings.Contains(d.UnverifiedReason, "Cargo discards every checksum") {
			t.Errorf("a crate whose checksum Cargo discards: %+v", d)
		}
		if g := dependencyNamed(t, f, "semver"); g.Unverified {
			t.Errorf("a Git crate pinned to a commit: %+v", g)
		}
		if len(f.Warnings) == 0 || !strings.Contains(strings.Join(f.Warnings, "\n"), "Cargo discards every checksum") {
			t.Errorf("no warning: %v", f.Warnings)
		}
	}
	// Format 1 keeps its checksums in [metadata], as Cargo reads them.
	v1 := "[[package]]\nname = \"itoa\"\nversion = \"1.0.11\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n" +
		"[metadata]\n\"checksum itoa 1.0.11 (registry+https://github.com/rust-lang/crates.io-index)\" = \"" + sum + "\"\n"
	if d := dependencyNamed(t, ParseFile(nil, nil, "Cargo.lock", []byte(v1)), "itoa"); d.Unverified || len(d.Digests) != 1 {
		t.Fatalf("a format 1 lock file: %+v", d)
	}
}

func dependencyNamed(t *testing.T, f *File, name string) Dependency {
	t.Helper()
	if f == nil {
		t.Fatal("not read")
	}
	for _, d := range f.Dependencies {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("%s is not among %+v (error %q)", name, f.Dependencies, f.Error)
	return Dependency{}
}

func TestGoWorkAndGoModReplacements(t *testing.T) {
	uses, replaced, err := GoWork([]byte("go 1.22\n\nuse (\n\t./svc // the service\n\t\"./lib\"\n)\nuse ./tools\n\n" +
		"replace example.com/a v1.1.0 => ./evil\nreplace (\n\texample.com/b => example.com/c v1.0.0\n)\n"))
	if err != nil || !reflect.DeepEqual(uses, []string{"./svc", "./lib", "./tools"}) || !reflect.DeepEqual(replaced, []string{"example.com/a", "example.com/b"}) {
		t.Fatalf("GoWork: %q %q %v", uses, replaced, err)
	}
	if _, _, err := GoWork([]byte("use (\n./a\n")); err == nil {
		t.Error("an unclosed block was read")
	}
	module, replaced, err := GoModReplaced([]byte("module example.com/m\n\nrequire example.com/a v1.0.0\nreplace example.com/a v1.0.1 => ../a\n"))
	if err != nil || module != "example.com/m" || !reflect.DeepEqual(replaced, []string{"example.com/a"}) {
		t.Fatalf("GoModReplaced: %q %q %v", module, replaced, err)
	}
}

func TestCargoPatchesAndConfigRedirects(t *testing.T) {
	patched, err := CargoPatched([]byte("[package]\nname = \"app\"\n\n[patch.crates-io]\nitoa = { path = \"evil-itoa\" }\nmy-serde = { git = \"https://x/y\", package = \"serde\" }\n\n" +
		"[patch.\"https://github.com/o/r\"]\nrand = { path = \"r\" }\n\n[replace]\n\"foo:0.1.0\" = { path = \"f\" }\n\"https://github.com/rust-lang/crates.io-index#bar@1.0.0\" = { path = \"b\" }\n"))
	if err != nil || !reflect.DeepEqual(patched, []string{"bar", "foo", "itoa", "my-serde", "rand", "serde"}) {
		t.Fatalf("CargoPatched: %q %v", patched, err)
	}
	unused, err := CargoPatchUnused([]byte("version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n[[patch.unused]]\nname = \"itoa\"\nversion = \"1.0.11\"\n"))
	if err != nil || !reflect.DeepEqual(unused, []string{"itoa"}) {
		t.Fatalf("CargoPatchUnused: %q %v", unused, err)
	}
	for config, want := range map[string]string{
		"[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory=\"vendor\"\n": "a source replacement",
		"paths = [\"../itoa\"]\n":                                   "path overrides",
		"[registry]\nindex = \"https://evil.example/index\"\n":      "another crates.io index",
		"[source.mirror]\nregistry = \"https://m.example/index\"\n": "",
		"[net]\noffline = true\n":                                   "",
	} {
		redirect, _, err := CargoConfigRedirects([]byte(config))
		if err != nil || (want == "") != (redirect == "") || !strings.Contains(redirect, want) {
			t.Errorf("%q: %q %v, want %q", config, redirect, err, want)
		}
	}
	_, patched, err = CargoConfigRedirects([]byte("[patch.crates-io]\nitoa = { path = \"../itoa\" }\n"))
	if err != nil || !reflect.DeepEqual(patched, []string{"itoa"}) {
		t.Fatalf("a [patch] in the configuration: %q %v", patched, err)
	}
	if _, _, err := CargoConfigRedirects([]byte("[source\n")); err == nil {
		t.Error("a malformed configuration was read")
	}
}

func TestNPMOverrides(t *testing.T) {
	names, err := NPMOverrides([]byte("\xef\xbb\xbf" + `{"name":"app","overrides":{"left-pad@1.0.1":"npm:evil@1.0.0","foo":{".":"1.0.0","@scope/bar@^2":"2.0.1","baz":{"qux":"1.0.0"}}}}`))
	if err != nil || !reflect.DeepEqual(names, []string{"@scope/bar", "baz", "foo", "left-pad", "qux"}) {
		t.Fatalf("NPMOverrides: %q %v", names, err)
	}
	if names, err := NPMOverrides([]byte(`{"name":"app"}`)); err != nil || len(names) != 0 {
		t.Fatalf("no overrides: %q %v", names, err)
	}
	if _, err := NPMOverrides([]byte(`{"overrides":`)); err == nil {
		t.Error("a malformed package.json was read")
	}
}

func TestPythonSources(t *testing.T) {
	got := PythonSources([]byte("# -i https://commented.example\n" +
		"-i https://a.example/simple\n" +
		"--index-url=https://b.example/simple\n" +
		"--extra-i https://c.example/simple --find-links ./wheels\n" +
		"-fhttps://d.example/links\n" +
		"--find \"./more wheels\"\n" +
		"requests==2.32.3 --hash=sha256:" + strings.Repeat("a", 64) + "\n" +
		"--no-index\n--editable ./local\n--extra-index-url \\\n    https://e.example/simple\n"))
	want := []PythonSource{
		{"--index-url", "https://a.example/simple"},
		{"--index-url", "https://b.example/simple"},
		{"--extra-index-url", "https://c.example/simple"},
		{"--find-links", "./wheels"},
		{"--find-links", "https://d.example/links"},
		{"--find-links", "./more"},
		{"--extra-index-url", "https://e.example/simple"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PythonSources:\n%q\nwant\n%q", got, want)
	}
}

func TestProxyServes(t *testing.T) {
	p := &Proxy{PublicURLs: []string{"https://proxy.example.com/base"}, Upstreams: map[string]ProxyUpstream{"pypi": {URL: "https://pypi.org/simple", Type: "pip"}}}
	for raw, want := range map[string]bool{
		"https://proxy.example.com/base/v1/pypi/simple/":  true,
		"https://proxy.example.com/base/v1/other/simple/": false, // no such upstream
		"https://proxy.example.com/v1/pypi/simple/":       false, // not under the base
		"https://evil.example/base/v1/pypi/simple/":       false,
		"./wheels": false,
	} {
		if got := p.Serves(raw); got != want {
			t.Errorf("Serves(%q) = %v, want %v", raw, got, want)
		}
	}
	if (*Proxy)(nil).Serves("https://proxy.example.com/base/v1/pypi/simple/") {
		t.Error("a nil Proxy serves something")
	}
}
