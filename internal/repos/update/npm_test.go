package update

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The integrities npm recorded for the versions the real updates moved to.
const (
	ms213Integrity      = "sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA=="
	lodash4181Integrity = "sha512-dMInicTPVE8d1e5otfwmmjlxkZoUpiVLwyeTdUsi/Caj/gfzzblBcCE5sRHV/AsjuCmxWrte2TNGSYuCeCq+0Q=="
)

// TestNpmWritesWhatNpmWrites: for an update that needs no re-resolution, the
// rewrite is byte for byte the file npm itself wrote — in every lockfile
// version, in a shrinkwrap, in workspaces (an entry nested under a workspace
// folder, and in version 2 under the workspace's link in the legacy tree).
func TestNpmWritesWhatNpmWrites(t *testing.T) {
	ms := npmUpdate("ms", "2.1.2", "2.1.3", sriHex(t, ms213Integrity))
	lodash := npmUpdate("lodash", "4.17.20", "4.18.1", sriHex(t, lodash4181Integrity))
	for _, tc := range []struct {
		dir, file string
		changes   []Change
	}{
		{"npm-v1", "package-lock.json", []Change{ms}},
		{"npm-v2", "package-lock.json", []Change{ms}},
		{"npm-v3", "package-lock.json", []Change{ms}},
		{"npm-v3", "npm-shrinkwrap.json", []Change{ms}},
		{"npm-workspaces-v2", "package-lock.json", []Change{lodash, ms}},
		{"npm-workspaces-v3", "package-lock.json", []Change{ms, lodash}},
	} {
		t.Run(tc.dir+"/"+tc.file, func(t *testing.T) {
			lock := "web/" + tc.file
			files := map[string][]byte{
				lock:               fixture(t, tc.dir, "before", "package-lock.json"),
				"web/package.json": fixture(t, tc.dir, "package.json"),
			}
			u := NativeUpdater("npm/" + tc.file)
			if u == nil || u.Key() != "npm/"+tc.file {
				t.Fatalf("no updater for npm/%s", tc.file)
			}
			after := apply(t, u, lock, files, tc.changes)
			sameBytes(t, lock, after[lock], fixture(t, tc.dir, "after", "package-lock.json"))
			if !bytes.Equal(after["web/package.json"], files["web/package.json"]) {
				t.Error("package.json was rewritten")
			}
		})
	}
}

// TestNpmNestedCopies: every copy of the old version moves, wherever it is
// in node_modules; a copy of another version stays.
func TestNpmNestedCopies(t *testing.T) {
	sum := fakeSHA512("ms-2.0.1")
	c := npmUpdate("ms", "2.0.0", "2.0.1", sum)
	want := []string{
		`"version": "2.0.1",`,
		`"resolved": "https://registry.npmjs.org/ms/-/ms-2.0.1.tgz",`,
		`"integrity": "sha512-` + b64(t, sum) + `"`,
	}
	for _, tc := range []struct {
		dir     string
		entries int
	}{{"npm-v1", 2}, {"npm-v2", 4}, {"npm-v3", 2}} {
		t.Run(tc.dir, func(t *testing.T) {
			before := fixture(t, tc.dir, "before", "package-lock.json")
			after := apply(t, NativeUpdater("npm/package-lock.json"), "package-lock.json",
				map[string][]byte{"package-lock.json": before}, []Change{c})["package-lock.json"]
			_, changed := diffLines(t, before, after)
			if len(changed) != 3*tc.entries {
				t.Fatalf("%d lines changed, want %d: %q", len(changed), 3*tc.entries, changed)
			}
			for i, l := range changed {
				if w := want[i%3]; strings.TrimSuffix(l, ",") != strings.TrimSuffix(w, ",") {
					t.Errorf("changed line %q, want %q", l, w)
				}
			}
			if !bytes.Contains(after, []byte(`"resolved": "https://registry.npmjs.org/ms/-/ms-2.1.2.tgz"`)) {
				t.Error("the hoisted ms 2.1.2 moved too")
			}
		})
	}
}

// TestNpmAliasAndScope: an alias keeps its key and names its real package
// (in the legacy tree in its version, "npm:<name>@<version>"); a scoped
// package's tarball is named without the scope.
func TestNpmAliasAndScope(t *testing.T) {
	sw := npmUpdate("string-width", "4.2.3", "4.2.4", fakeSHA512("string-width-4.2.4"))
	node := npmUpdate("@types/node", "20.14.10", "20.14.11", fakeSHA512("node-20.14.11"))
	for _, tc := range []struct {
		dir  string
		want []string
	}{
		{"npm-v1", []string{
			`"version": "20.14.11",`, `"resolved": "https://registry.npmjs.org/@types/node/-/node-20.14.11.tgz",`,
			`"version": "npm:string-width@4.2.4",`, `"resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.4.tgz",`,
		}},
		{"npm-v2", []string{
			`"version": "20.14.11",`, `"resolved": "https://registry.npmjs.org/@types/node/-/node-20.14.11.tgz",`,
			`"version": "4.2.4",`, `"resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.4.tgz",`,
			`"version": "20.14.11",`, `"resolved": "https://registry.npmjs.org/@types/node/-/node-20.14.11.tgz",`,
			`"version": "npm:string-width@4.2.4",`, `"resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.4.tgz",`,
		}},
		{"npm-v3", []string{
			`"version": "20.14.11",`, `"resolved": "https://registry.npmjs.org/@types/node/-/node-20.14.11.tgz",`,
			`"version": "4.2.4",`, `"resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.4.tgz",`,
		}},
	} {
		t.Run(tc.dir, func(t *testing.T) {
			before := fixture(t, tc.dir, "before", "package-lock.json")
			after := apply(t, NativeUpdater("npm/package-lock.json"), "package-lock.json",
				map[string][]byte{"package-lock.json": before}, []Change{sw, node})["package-lock.json"]
			_, changed := diffLines(t, before, after)
			var got []string
			for _, l := range changed {
				if !strings.HasPrefix(l, `"integrity"`) {
					got = append(got, l)
				}
			}
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("changed lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
			if tc.dir != "npm-v1" && !bytes.Contains(after, []byte("\"node_modules/string-width-cjs\": {\n      \"name\": \"string-width\",\n      \"version\": \"4.2.4\"")) {
				t.Error("the alias entry did not keep its key and name")
			}
		})
	}
}

// TestNpmScopeSpellings: a scoped package's tarball URL names it with its
// slash escaped, or escaped altogether, as some registries write it.
func TestNpmScopeSpellings(t *testing.T) {
	c := npmUpdate("@types/node", "20.14.10", "20.14.11", fakeSHA512("n"))
	sri, err := npmIntegrity(c)
	if err != nil {
		t.Fatal(err)
	}
	const old = "sha1-VgiurfwAvmwpAd9fmGF4jeDVl8g="
	for _, path := range []string{"@types/node", "@types%2fnode", "@types%2Fnode", "%40types%2fnode"} {
		lock := `{"lockfileVersion":3,"packages":{"node_modules/@types/node":{"version":"20.14.10","resolved":"https://r.example/npm/` + path + `/-/node-20.14.10.tgz","integrity":"` + old + `"}}}`
		after := apply(t, NativeUpdater("npm/package-lock.json"), "package-lock.json", map[string][]byte{"package-lock.json": []byte(lock)}, []Change{c})
		if want := strings.ReplaceAll(strings.ReplaceAll(lock, "20.14.10", "20.14.11"), old, sri); string(after["package-lock.json"]) != want {
			t.Errorf("%s: %s", path, after["package-lock.json"])
		}
	}
}

// TestNpmKeepsTheBytes: a byte order mark, CRLF line endings, tabs and keys
// in another order survive; only the three values change.
func TestNpmKeepsTheBytes(t *testing.T) {
	crlf := func(b []byte) []byte {
		b = bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))
		b = bytes.ReplaceAll(b, []byte("  "), []byte("\t"))
		return append([]byte("\xef\xbb\xbf"), b...)
	}
	before := crlf(fixture(t, "npm-v3", "before", "package-lock.json"))
	want := crlf(fixture(t, "npm-v3", "after", "package-lock.json"))
	c := npmUpdate("ms", "2.1.2", "2.1.3", sriHex(t, ms213Integrity))
	after := apply(t, NativeUpdater("npm/package-lock.json"), "package-lock.json", map[string][]byte{"package-lock.json": before}, []Change{c})
	sameBytes(t, "package-lock.json", after["package-lock.json"], want)

	// Escapes and members in any order; an entry without resolved keeps
	// none (npm fetches it from its configured registry, and checks it
	// against the integrity).
	const old = `"integrity":"sha1-VgiurfwAvmwpAd9fmGF4jeDVl8g="`
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"x"},` +
		`"node_modules/m` + "\\" + `u0073":{` + old + `,"resolved":"https:\/\/r.example\/ms\/-\/ms-2.1.2.tgz","version":"2.1.2","dev":true},` +
		`"node_modules/a/node_modules/ms":{"version":"2.1.2",` + old + `},` +
		`"node_modules/b/node_modules/ms":{"version":"2.1.2","resolved":"https://r.example/ms/-/ms-2.1.2.tgz",` + old + `}}}`
	moved := `"integrity":"` + ms213Integrity + `"`
	wantLock := `{"lockfileVersion":3,"packages":{"":{"name":"x"},` +
		`"node_modules/m` + "\\" + `u0073":{` + moved + `,"resolved":"https://r.example/ms/-/ms-2.1.3.tgz","version":"2.1.3","dev":true},` +
		`"node_modules/a/node_modules/ms":{"version":"2.1.3",` + moved + `},` +
		`"node_modules/b/node_modules/ms":{"version":"2.1.3","resolved":"https://r.example/ms/-/ms-2.1.3.tgz",` + moved + `}}}`
	after = apply(t, NativeUpdater("npm/package-lock.json"), "package-lock.json", map[string][]byte{"package-lock.json": []byte(lock)}, []Change{c})
	sameBytes(t, "package-lock.json", after["package-lock.json"], []byte(wantLock))

	// An entry without integrity pins nothing: it does not move.
	bare := strings.Replace(lock, `"version":"2.1.2",`+old, `"version":"2.1.2"`, 1)
	applyFails(t, NativeUpdater("npm/package-lock.json"), "package-lock.json", map[string][]byte{"package-lock.json": []byte(bare)}, []Change{c}, "records no integrity")
}

// TestNpmRefuses: what the npm updater does not rewrite.
func TestNpmRefuses(t *testing.T) {
	v3 := string(fixture(t, "npm-v3", "before", "package-lock.json"))
	v2 := string(fixture(t, "npm-v2", "before", "package-lock.json"))
	ws := string(fixture(t, "npm-workspaces-v3", "before", "package-lock.json"))
	ms := npmUpdate("ms", "2.1.2", "2.1.3", sriHex(t, ms213Integrity))
	entry := func(body string) string {
		return `{"lockfileVersion":3,"packages":{"node_modules/ms":` + body + `}}`
	}
	for _, tc := range []struct {
		name, lock string
		changes    []Change
		want       string
	}{
		{"absent", v3, []Change{npmUpdate("left-pad", "9.9.9", "9.9.10", fakeSHA512("x"))}, "is not in the lock file"},
		{"workspace folder", ws, []Change{npmUpdate("@fixture/a", "1.0.0", "1.0.1", fakeSHA512("x"))}, "is not in the lock file"},
		{"git", entry(`{"version":"2.1.2","resolved":"git+ssh://git@github.com/vercel/ms.git#` + strings.Repeat("a", 40) + `"}`), []Change{ms}, "not a registry tarball"},
		{"tarball elsewhere", entry(`{"version":"2.1.2","resolved":"https://example.com/ms.tgz"}`), []Change{ms}, "not a registry tarball"},
		{"query", entry(`{"version":"2.1.2","resolved":"https://r.example/ms/-/ms-2.1.2.tgz?x=1"}`), []Change{ms}, "not a registry tarball"},
		{"query ending like a tarball", entry(`{"version":"2.1.2","resolved":"https://r.example/ms/-/ms-2.1.2.tgz?/-/ms-2.1.2.tgz"}`), []Change{ms}, "not a registry tarball"},
		{"git ref ending like a tarball", entry(`{"version":"2.1.2","resolved":"git+https://github.com/evil/repo.git#x/-/ms-2.1.2.tgz"}`), []Change{ms}, "not a registry tarball"},
		{"github shorthand", entry(`{"version":"2.1.2","resolved":"github:evil/repo#x/-/ms-2.1.2.tgz"}`), []Change{ms}, "not a registry tarball"},
		{"local path", entry(`{"version":"2.1.2","resolved":"file:vendor/-/ms-2.1.2.tgz"}`), []Change{ms}, "not a registry tarball"},
		{"another package's path", entry(`{"version":"2.1.2","resolved":"https://evil.example/files/-/ms-2.1.2.tgz"}`), []Change{ms}, "not a registry tarball"},
		{"repeated key", entry(`{"version":"2.1.2","version":"2.1.2"}`), []Change{ms}, "repeats a key"},
		{"integrity not a string", entry(`{"version":"2.1.2","integrity":null}`), []Change{ms}, "integrity is not a string"},
		{"integrity unreadable", entry(`{"version":"2.1.2","integrity":"sha512-abc md5-x"}`), []Change{ms}, "integrity is not one the updater reads"},
		{"no artifact", entry(`{"version":"2.1.2","integrity":"sha1-VgiurfwAvmwpAd9fmGF4jeDVl8g="}`), []Change{{Type: "npm", Name: "ms", From: "2.1.2", To: "2.1.3"}}, "no \"package\" artifact"},
		{"no sha512", entry(`{"version":"2.1.2","integrity":"sha1-VgiurfwAvmwpAd9fmGF4jeDVl8g="}`),
			[]Change{{Type: "npm", Name: "ms", From: "2.1.2", To: "2.1.3", Artifacts: []Artifact{{Role: "package", SHA256: fakeSHA256("x")}}}}, "no SHA-512"},
		{"install path twice", `{"packages":{"node_modules/ms":{"version":"2.1.2","integrity":"sha1-VgiurfwAvmwpAd9fmGF4jeDVl8g="},"node_modules/ms":{"version":"2.1.2"}}}`, []Change{ms}, "twice"},
		{"no integrity", entry(`{"version":"2.1.2","resolved":"https://r.example/ms/-/ms-2.1.2.tgz"}`), []Change{ms}, "records no integrity"},
		// The proxy vetted the package of one registry; an entry from
		// another does not move under that vetting.
		{"two registries", `{"lockfileVersion":3,"packages":{` +
			`"node_modules/ms":{"version":"2.1.2","resolved":"https://registry.npmjs.org/ms/-/ms-2.1.2.tgz","integrity":"sha1-VgiurfwAvmwpAd9fmGF4jeDVl8g="},` +
			`"node_modules/a/node_modules/ms":{"version":"2.1.2","resolved":"https://evil.example/ms/-/ms-2.1.2.tgz","integrity":"sha1-VgiurfwAvmwpAd9fmGF4jeDVl8g="}}}`,
			[]Change{ms}, "comes from two registries"},
		{"two packages sections", `{"packages":{},"packages":{}}`, []Change{ms}, "two \"packages\" sections"},
		{"sections disagree", strings.Replace(v2, "\"ms\": {\n      \"version\": \"2.1.2\"", "\"ms\": {\n      \"version\": \"2.1.1\"", 1), []Change{ms},
			"packages section has 1 entries of it, its dependencies section 0"},
		{"not JSON", v3[:len(v3)/2], []Change{ms}, "JSON document"},
		{"trailing data", v3 + "{}", []Change{ms}, "data after the document"},
		{"not a lock file", `{"name":"x"}`, []Change{ms}, "not an npm lock file"},
		{"other type", v3, []Change{{Type: "pip", Name: "ms", From: "2.1.2", To: "2.1.3"}}, "a change of type"},
		{"same version", v3, []Change{npmUpdate("ms", "2.1.2", "2.1.2", fakeSHA512("x"))}, "keeps version"},
		{"bad version", v3, []Change{npmUpdate("ms", "2.1.2", "2.1.3\",\"x", fakeSHA512("x"))}, "is not a npm version"},
		{"twice", v3, []Change{ms, ms}, "two changes"},
		{"chained", v3, []Change{ms, npmUpdate("ms", "2.1.3", "2.1.4", fakeSHA512("x"))}, "is changed and is what another change moves"},
		{"none", v3, nil, "no changes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			applyFails(t, NativeUpdater("npm/package-lock.json"), "app/package-lock.json",
				map[string][]byte{"app/package-lock.json": []byte(tc.lock)}, tc.changes, tc.want)
		})
	}
	applyFails(t, NativeUpdater("npm/package-lock.json"), "npm-shrinkwrap.json",
		map[string][]byte{"npm-shrinkwrap.json": []byte(v3)}, []Change{ms}, "is not a package-lock.json")
	applyFails(t, NativeUpdater("npm/package-lock.json"), "package-lock.json", map[string][]byte{}, []Change{ms}, "not among the files")
}

// TestNpmLargeLockFile: a lock file of npm's largest real size is rewritten
// in one pass.
func TestNpmLargeLockFile(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 30 MB lock file")
	}
	var b bytes.Buffer
	b.WriteString("{\n  \"name\": \"big\",\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"\": {\"name\": \"big\"}")
	for i := 0; b.Len() < 30<<20; i++ {
		fmt.Fprintf(&b, ",\n    \"node_modules/pkg-%d\": {\n      \"version\": \"1.0.%d\",\n      \"resolved\": \"https://registry.npmjs.org/pkg-%d/-/pkg-%d-1.0.%d.tgz\",\n      \"integrity\": \"%s\",\n      \"dependencies\": {\"ms\": \"^2.1.0\"}\n    }",
			i, i%7, i, i, i%7, ms213Integrity)
		if i%100 == 0 {
			fmt.Fprintf(&b, ",\n    \"node_modules/pkg-%d/node_modules/ms\": {\n      \"version\": \"2.1.2\",\n      \"resolved\": \"https://registry.npmjs.org/ms/-/ms-2.1.2.tgz\",\n      \"integrity\": \"sha1-VgiurfwAvmwpAd9fmGF4jeDVl8g=\"\n    }", i)
		}
	}
	b.WriteString("\n  }\n}\n")
	data := b.Bytes()
	c := npmUpdate("ms", "2.1.2", "2.1.3", sriHex(t, ms213Integrity))
	start := time.Now()
	out, err := NativeUpdater("npm/package-lock.json").Apply("package-lock.json", map[string][]byte{"package-lock.json": data}, []Change{c})
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(out["package-lock.json"], []byte(`"version": "2.1.3"`)); n == 0 || n != bytes.Count(data, []byte(`"version": "2.1.2"`)) {
		t.Fatalf("%d entries moved", n)
	}
	t.Logf("%d MB rewritten in %v", len(data)>>20, took)
	if !raceEnabled && took > 2*time.Second {
		t.Errorf("rewriting %d MB took %v", len(data)>>20, took)
	}
	// Verify reads both versions of the file entry by entry, once each.
	files := map[string][]byte{"package-lock.json": data}
	start = time.Now()
	if err := Verify("package-lock.json", files, merged(files, out), []Change{c}); err != nil {
		t.Fatal(err)
	}
	took = time.Since(start)
	t.Logf("%d MB verified in %v", len(data)>>20, took)
	// A bound against a blow-up (it reads every entry twice), not a
	// benchmark: shared CI runners are slow.
	if !raceEnabled && took > 20*time.Second {
		t.Errorf("verifying %d MB took %v", len(data)>>20, took)
	}
}
