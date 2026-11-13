package update

import (
	"strings"
	"testing"
)

// tamper returns files with one file's text replaced once (the text must be
// there).
func tamper(t *testing.T, files map[string][]byte, path, old, new string) map[string][]byte {
	t.Helper()
	s := string(files[path])
	if !strings.Contains(s, old) {
		t.Fatalf("%s holds no %q", path, old)
	}
	out := cloneFiles(files)
	out[path] = []byte(strings.Replace(s, old, new, 1))
	return out
}

// verifyFails expects Verify to refuse, naming the discrepancy.
func verifyFails(t *testing.T, lockPath string, before, after map[string][]byte, changes []Change, want string) {
	t.Helper()
	err := Verify(lockPath, before, after, changes)
	if err == nil {
		t.Fatalf("Verify passed, want an error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("Verify: %v, want an error containing %q", err, want)
	}
}

// TestVerifyCatchesWrongRewrites: rewrites that went right, then wrong in
// one respect each — Verify names what.
func TestVerifyCatchesWrongRewrites(t *testing.T) {
	ms := npmUpdate("ms", "2.1.2", "2.1.3", sriHex(t, ms213Integrity))
	npmBefore := map[string][]byte{"package-lock.json": fixture(t, "npm-v3", "before", "package-lock.json")}
	npmAfter := map[string][]byte{"package-lock.json": fixture(t, "npm-v3", "after", "package-lock.json")}
	if err := Verify("package-lock.json", npmBefore, npmAfter, []Change{ms}); err != nil {
		t.Fatalf("npm's own update: %v", err)
	}
	v2Before := map[string][]byte{"package-lock.json": fixture(t, "npm-v2", "before", "package-lock.json")}
	v2After := map[string][]byte{"package-lock.json": fixture(t, "npm-v2", "after", "package-lock.json")}
	nested := npmUpdate("ms", "2.0.0", "2.0.1", fakeSHA512("ms-2.0.1"))
	nestedAfter := apply(t, NativeUpdater("npm/package-lock.json"), "package-lock.json", npmBefore, []Change{nested})

	reqBefore := map[string][]byte{"requirements.txt": fixture(t, "pip-hashes", "before", "requirements.txt")}
	reqAfter := map[string][]byte{"requirements.txt": fixture(t, "pip-hashes", "after", "requirements.txt")}
	reqChanges := []Change{idnaUpdate, coloramaUpdate}

	cargoBefore := map[string][]byte{"Cargo.lock": fixture(t, "cargo-v1", "before", "Cargo.lock")}
	cargoAfter := map[string][]byte{"Cargo.lock": fixture(t, "cargo-v1", "after", "Cargo.lock")}

	goBefore := map[string][]byte{"go.mod": fixture(t, "go-modules", "before", "go.mod"), "go.sum": fixture(t, "go-modules", "before", "go.sum")}
	goAfter := apply(t, NativeUpdater("go/go.mod"), "go.mod", goBefore, goUpdates)

	for _, tc := range []struct {
		name          string
		lock          string
		before, after map[string][]byte
		changes       []Change
		want          string
	}{
		{"wrong digest", "package-lock.json", npmBefore, tamper(t, npmAfter, "package-lock.json", ms213Integrity, "sha512-"+b64(t, fakeSHA512("evil"))),
			[]Change{ms}, "ms 2.1.3 is pinned with the digests sha512:"},
		{"digest dropped", "package-lock.json", npmBefore, tamper(t, npmAfter, "package-lock.json", "\"integrity\": \""+ms213Integrity+"\",\n", ""),
			[]Change{ms}, "is pinned with the digests none after the rewrite"},
		{"unrelated entry moved", "package-lock.json", npmBefore,
			tamper(t, npmAfter, "package-lock.json", `"version": "1.3.0",`, `"version": "1.3.1",`), []Change{ms}, "left-pad 1.3.1 (package-lock.json) is not read as before"},
		{"unrelated digest changed", "package-lock.json", npmBefore,
			tamper(t, npmAfter, "package-lock.json", "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==", "sha512-"+b64(t, fakeSHA512("lp"))),
			[]Change{ms}, "left-pad 1.3.0 (package-lock.json) is not read as before"},
		{"entry dropped", "package-lock.json", npmBefore,
			tamper(t, npmAfter, "package-lock.json", "\"node_modules/etag\": {", "\"node_modules/etag-gone\": {\"link\": true},\n    \"x\": {"),
			[]Change{ms}, "etag 1.8.1 is not read as before"},
		{"stray entry", "package-lock.json", npmBefore,
			tamper(t, npmAfter, "package-lock.json", "\"node_modules/etag\": {", "\"node_modules/etag/node_modules/ms\": {\"version\": \"2.1.3\", \"resolved\": \"https://evil.example/ms/-/ms-2.1.3.tgz\"},\n    \"node_modules/etag\": {"),
			[]Change{ms}, "ms 2.1.3 appears from https://evil.example after the rewrite"},
		{"old version left", "package-lock.json", npmBefore,
			tamper(t, nestedAfter, "package-lock.json", "\"version\": \"2.0.1\"", "\"version\": \"2.0.0\""), []Change{nested}, "ms 2.0.0 is still pinned after the rewrite"},
		{"dev flag", "package-lock.json", npmBefore,
			tamper(t, npmAfter, "package-lock.json", "\"integrity\": \""+ms213Integrity+"\",", "\"integrity\": \""+ms213Integrity+"\",\n      \"dev\": true,"),
			[]Change{ms}, "changed whether it is development-only"},
		{"other URL", "package-lock.json", npmBefore,
			tamper(t, npmAfter, "package-lock.json", "ms/-/ms-2.1.3.tgz", "ms/-/ms-2.1.3-x.tgz"), []Change{ms}, "is downloaded from another URL"},
		{"new warning", "package-lock.json", npmBefore,
			tamper(t, npmAfter, "package-lock.json", "\"resolved\": \"https://registry.npmjs.org/ms/-/ms-2.1.3.tgz\"", "\"resolved\": \"ftp://registry.npmjs.org/ms/-/ms-2.1.3.tgz\""),
			[]Change{ms}, "a new warning after the rewrite: ms 2.1.3: unrecognised resolved location"},
		{"format version", "package-lock.json", npmBefore,
			tamper(t, npmAfter, "package-lock.json", "\"lockfileVersion\": 3", "\"lockfileVersion\": 2"), []Change{ms}, "format version \"3\" before the rewrite, \"2\" after"},
		{"unreadable", "package-lock.json", npmBefore,
			map[string][]byte{"package-lock.json": npmAfter["package-lock.json"][:100]}, []Change{ms}, "cannot be read after the rewrite"},
		{"legacy tree left", "package-lock.json", v2Before,
			tamper(t, v2After, "package-lock.json", "\"ms\": {\n      \"version\": \"2.1.3\",\n      \"resolved\": \"https://registry.npmjs.org/ms/-/ms-2.1.3.tgz\",\n      \"integrity\": \""+ms213Integrity+"\"",
				"\"ms\": {\n      \"version\": \"2.1.2\",\n      \"resolved\": \"https://registry.npmjs.org/ms/-/ms-2.1.2.tgz\",\n      \"integrity\": \"sha512-sGkPx+VjMtmA6MX27oA4FBFELFCZZ4S4XqeGOXCv68tT+jb3vk/RyaKWP0PTKyWtmLSM0b+adUTEvbs1PEaH2w==\""),
			[]Change{ms}, "the dependencies section: ms 2.1.2 is still pinned after the rewrite"},
		{"not pinned before", "package-lock.json", npmBefore, npmAfter, []Change{ms, npmUpdate("lodash", "4.17.20", "4.18.1", sriHex(t, lodash4181Integrity))},
			"the lock file did not pin lodash 4.17.20"},
		{"other type", "package-lock.json", npmBefore, npmAfter, []Change{{Type: "pip", Name: "ms", From: "2.1.2", To: "2.1.3"}}, "a pip change for a npm/package-lock.json lock file"},
		{"no changes", "package-lock.json", npmBefore, npmAfter, nil, "no changes"},
		{"file gone", "package-lock.json", npmBefore, map[string][]byte{}, []Change{ms}, "is not among the files after the rewrite"},
		{"not a lock file", "README.md", map[string][]byte{"README.md": nil}, map[string][]byte{"README.md": nil}, []Change{ms}, "README.md is not a lock file"},

		{"a hash missing", "requirements.txt", reqBefore,
			tamper(t, reqAfter, "requirements.txt", " \\\n    --hash=sha256:d838c2c0ed6fced7693d5e8ab8e734d5f8fda53a039c0164afb0b82e771e3603", ""),
			reqChanges, "idna 3.8 is pinned with the digests sha256:050b4e5baadcd44d"},
		{"requirement dropped", "requirements.txt", reqBefore,
			tamper(t, reqAfter, "requirements.txt", "click==8.1.7", "# click==8.1.7"), reqChanges, "click 8.1.7 is not read as before"},
		{"requirement duplicated", "requirements.txt", reqBefore,
			tamper(t, reqAfter, "requirements.txt", "idna==3.8 \\\n", "idna==3.8 \\\n    --hash=sha256:"+fakeSHA256("x")+" \\\n"), reqChanges, "idna 3.8 is pinned with the digests"},

		{"wrong checksum", "Cargo.lock", cargoBefore,
			tamper(t, cargoAfter, "Cargo.lock", "49f1f14873335454500d59611f1cf4a4b0f786f9ac11f4312a78e4cf2566695b", fakeSHA256("evil")), cargoUpdates, "itoa 1.0.11 is pinned with the digests"},
		{"other crate touched", "Cargo.lock", cargoBefore,
			tamper(t, cargoAfter, "Cargo.lock", "523dc4f511e55ab87b694dc30d0f820d60906ef06413f93d4d7a1385599cc149", fakeSHA256("memchr")), cargoUpdates, "memchr 2.7.1 (Cargo.lock) is not read as before"},

		{"go.sum without the new go.mod hash", "go.mod", goBefore,
			tamper(t, goAfter, "go.sum", "github.com/spf13/pflag v1.0.10/go.mod h1:McXfInJRrz4CZXVZOBLb0bTZqETkiAhM9Iw0y3An2Bg=\n", ""), goUpdates,
			"github.com/spf13/pflag v1.0.10 is pinned with the digests"},
		{"go.mod left behind", "go.sum", goBefore,
			tamper(t, goAfter, "go.mod", "github.com/spf13/pflag v1.0.10", "github.com/spf13/pflag v1.0.9"), goUpdates, "github.com/spf13/pflag v1.0.9 is still pinned"},
		{"another zip hash", "go.mod", goBefore,
			tamper(t, goAfter, "go.sum", "4EBh2KAYBwaONj6b2Ye1GiHfwjqyROoF4RwYO+vPwFk=", fakeH1("evil")), goUpdates, "github.com/spf13/pflag v1.0.10 is pinned with the digests"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifyFails(t, tc.lock, tc.before, tc.after, tc.changes, tc.want)
		})
	}

	// The go.mod hash nothing reads as a dependency: a module whose zip go.sum
	// never hashed.
	mod := "module m\n\ngo 1.22\n\nrequire example.com/i v1.1.0\n"
	sum := "example.com/i v1.1.0/go.mod h1:" + fakeH1("i110m") + "\n"
	c := goUpdate("example.com/i", "v1.1.0", "v1.1.1", fakeH1("i111"), fakeH1("i111m"))
	before := map[string][]byte{"go.mod": []byte(mod), "go.sum": []byte(sum)}
	after := apply(t, NativeUpdater("go/go.mod"), "go.mod", before, []Change{c})
	verifyFails(t, "go.mod", before, tamper(t, after, "go.sum", "example.com/i v1.1.1/go.mod", "example.com/i v1.1.2/go.mod"), []Change{c},
		"go.sum does not hold the hash of the go.mod of example.com/i v1.1.1")
	verifyFails(t, "go.mod", before, tamper(t, after, "go.sum", fakeH1("i111m"), fakeH1("other")), []Change{c},
		"go.sum holds another hash of the go.mod of example.com/i v1.1.1")
}

// TestVerifyRefusesWhatNoRewriteMoves: an entry from a Git repository or a
// tarball URL is not moved, and a document of two dependencies objects does
// not trip the legacy view.
func TestVerifyRefusesWhatNoRewriteMoves(t *testing.T) {
	c := npmUpdate("foo", "1.0.0", "2.0.0", fakeSHA512("foo"))
	for _, resolved := range []string{"git+https://github.com/evil/repo.git#" + strings.Repeat("a", 40), "https://evil.example/files/foo.tgz"} {
		lock := `{"lockfileVersion":3,"packages":{"node_modules/foo":{"version":"%s","resolved":"` + resolved + `"}}}`
		before := map[string][]byte{"package-lock.json": []byte(strings.Replace(lock, "%s", "1.0.0", 1))}
		after := map[string][]byte{"package-lock.json": []byte(strings.Replace(lock, "%s", "2.0.0", 1))}
		verifyFails(t, "package-lock.json", before, after, []Change{c}, "which a native rewrite does not move")
	}
	twice := map[string][]byte{"package-lock.json": []byte(`{"dependencies":{},"dependencies":{"foo":{"version":"1.0.0"}}}`)}
	if err := Verify("package-lock.json", twice, twice, []Change{c}); err == nil {
		t.Fatal("Verify passed a rewrite that moved nothing")
	}
}

// TestVerifyAcceptsPinsTheFileHad: an entry of the new version the lock file
// already had stays, if its digests are the new version's.
func TestVerifyAcceptsPinsTheFileHad(t *testing.T) {
	sum := fakeSHA512("ms-2.0.1")
	lock := `{"lockfileVersion":3,"packages":{` +
		`"node_modules/a/node_modules/ms":{"version":"2.0.0","resolved":"https://registry.npmjs.org/ms/-/ms-2.0.0.tgz","integrity":"sha1-VgiurfwAvmwpAd9fmGF4jeDVl8g="},` +
		`"node_modules/ms":{"version":"2.0.1","resolved":"https://registry.npmjs.org/ms/-/ms-2.0.1.tgz","integrity":"sha512-` + b64(t, sum) + `"}}}`
	before := map[string][]byte{"package-lock.json": []byte(lock)}
	apply(t, NativeUpdater("npm/package-lock.json"), "package-lock.json", before, []Change{npmUpdate("ms", "2.0.0", "2.0.1", sum)})

	other := strings.Replace(lock, b64(t, sum), b64(t, fakeSHA512("other")), 1)
	before = map[string][]byte{"package-lock.json": []byte(other)}
	out, err := NativeUpdater("npm/package-lock.json").Apply("package-lock.json", before, []Change{npmUpdate("ms", "2.0.0", "2.0.1", sum)})
	if err != nil {
		t.Fatal(err)
	}
	verifyFails(t, "package-lock.json", before, merged(before, out), []Change{npmUpdate("ms", "2.0.0", "2.0.1", sum)},
		"ms 2.0.1 was already pinned with sha512:")
}
