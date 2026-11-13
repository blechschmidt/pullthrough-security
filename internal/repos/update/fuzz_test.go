//go:build fuzz

// Fuzz targets for the native lock-file updaters (Task 182). A lock file comes
// out of a repository, which is whatever its last committer made it: every
// updater is a parser and rewriter of untrusted input, and runs inside the
// proxy. The properties:
//
//   - no input panics an updater, the JSON scanner or Verify;
//   - an updater is deterministic, and returns no files with an error;
//   - a rewrite it returns of files internal/lockfiles reads without error
//     passes Verify: an updater that succeeds where Verify fails has read the
//     file otherwise than the parser everything downstream trusts (the
//     first such input found — a go.sum hash that is not h1 — is in
//     testdata/fuzz);
//   - the JSON scanner accepts exactly the documents encoding/json accepts.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run='^$' -fuzz=FuzzNpmLockUpdate ./internal/repos/update/
package update

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// fuzzMaxInput bounds an input: larger ones only make each run slower.
const fuzzMaxInput = 1 << 20

// fuzzSeeds returns this package's fixtures and internal/lockfiles' whose
// file name is name.
func fuzzSeeds(f *testing.F, name string) [][]byte {
	f.Helper()
	var seeds [][]byte
	for _, root := range []string{"testdata", "../../lockfiles/testdata/fixtures"} {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || d.Name() != name {
				return nil
			}
			if data, err := os.ReadFile(p); err == nil && len(data) <= fuzzMaxInput {
				seeds = append(seeds, data)
			}
			return nil
		})
	}
	if len(seeds) == 0 {
		f.Fatalf("no seeds named %s", name)
	}
	return seeds
}

// fuzzApply runs an updater over files and Verify over what it wrote.
func fuzzApply(t *testing.T, u Updater, lockPath string, files map[string][]byte, changes []Change) {
	t.Helper()
	out, err := u.Apply(lockPath, files, changes)
	if err != nil {
		if out != nil {
			t.Fatalf("files returned with the error %v", err)
		}
		return
	}
	again, err := u.Apply(lockPath, files, changes)
	if err != nil || len(again) != len(out) {
		t.Fatalf("not deterministic: %v", err)
	}
	for k, v := range out {
		if !bytes.Equal(again[k], v) {
			t.Fatalf("%s: not deterministic", k)
		}
	}
	err = Verify(lockPath, files, merged(files, out), changes)
	for _, f := range lockfiles.ParseFiles(nil, nil, files) {
		if f.Error != "" {
			return // Verify refuses a file it cannot read before the rewrite
		}
	}
	if err != nil {
		t.Fatalf("the rewrite of a file the parser reads fails Verify: %v", err)
	}
}

func FuzzNpmLockUpdate(f *testing.F) {
	for _, s := range fuzzSeeds(f, "package-lock.json") {
		f.Add(s)
	}
	f.Add([]byte(`{"lockfileVersion":3,"packages":{"node_modules/ms":{"version":"2.1.2","resolved":"https://r/ms/-/ms-2.1.2.tgz","integrity":"sha1-x"}}}`))
	changes := []Change{
		npmUpdate("ms", "2.1.2", "2.1.3", fakeSHA512("ms")),
		npmUpdate("string-width", "4.2.3", "4.2.4", fakeSHA512("sw")),
	}
	u := NativeUpdater("npm/package-lock.json")
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		fuzzApply(t, u, "package-lock.json", map[string][]byte{"package-lock.json": data}, changes)
	})
}

func FuzzRequirementsUpdate(f *testing.F) {
	for _, s := range fuzzSeeds(f, "requirements.txt") {
		f.Add(s)
	}
	f.Add([]byte("idna==3.7 --hash=sha256:" + fakeSHA256("a") + " \\\n    --hash=sha256:" + fakeSHA256("b") + "\n"))
	changes := []Change{
		pipUpdate("idna", "3.7", "3.8", fakeSHA256("i1"), fakeSHA256("i2")),
		pipUpdate("urllib3", "2.6.3", "2.6.4", fakeSHA256("u1")),
	}
	u := NativeUpdater("pip/requirements.txt")
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		fuzzApply(t, u, "requirements.txt", map[string][]byte{"requirements.txt": data}, changes)
	})
}

func FuzzCargoLockUpdate(f *testing.F) {
	for _, s := range fuzzSeeds(f, "Cargo.lock") {
		f.Add(s)
	}
	u := NativeUpdater("cargo/Cargo.lock")
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		fuzzApply(t, u, "Cargo.lock", map[string][]byte{"Cargo.lock": data}, cargoUpdates)
	})
}

func FuzzGoModUpdate(f *testing.F) {
	mods, sums := fuzzSeeds(f, "go.mod"), fuzzSeeds(f, "go.sum")
	for i := range mods {
		f.Add(mods[i], sums[i%len(sums)])
	}
	u := NativeUpdater("go/go.mod")
	f.Fuzz(func(t *testing.T, mod, sum []byte) {
		if len(mod)+len(sum) > fuzzMaxInput {
			return
		}
		fuzzApply(t, u, "go.sum", map[string][]byte{"go.mod": mod, "go.sum": sum}, goUpdates)
	})
}

func FuzzJSONScanner(f *testing.F) {
	for _, s := range fuzzSeeds(f, "package-lock.json") {
		f.Add(s)
	}
	for _, s := range jsonScannerCases {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		s := &jsonScanner{data: data}
		err := s.skip()
		if err == nil {
			err = s.end()
		}
		if ok := err == nil; ok != json.Valid(data) {
			t.Fatalf("the scanner says %v (%v), encoding/json %v", ok, err, !ok)
		}
	})
}
