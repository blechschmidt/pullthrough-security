package update

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture reads a file of testdata.
func fixture(t testing.TB, parts ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// fakeSHA512, fakeSHA256 and fakeH1 are digests of made-up artifacts, for
// versions the tests invent.
func fakeSHA512(seed string) string {
	sum := sha512.Sum512([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func fakeSHA256(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func fakeH1(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// sriHex turns npm's "sha512-<base64>" into the hex of the digest.
func sriHex(t testing.TB, sri string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sri, "sha512-"))
	if err != nil || len(raw) != 64 {
		t.Fatalf("not a sha512 integrity: %q", sri)
	}
	return hex.EncodeToString(raw)
}

// npmUpdate is a change of an npm package whose new tarball has the given
// SHA-512 (hex).
func npmUpdate(name, from, to, sha512Hex string) Change {
	return Change{Type: "npm", Name: name, From: from, To: to,
		Artifacts: []Artifact{{Role: "package", SHA256: fakeSHA256(name + to), SHA512: sha512Hex}}}
}

// merged returns files with the rewrite's files replaced.
func merged(files, out map[string][]byte) map[string][]byte {
	m := map[string][]byte{}
	for k, v := range files {
		m[k] = v
	}
	for k, v := range out {
		m[k] = v
	}
	return m
}

// cloneFiles copies files, contents included.
func cloneFiles(files map[string][]byte) map[string][]byte {
	m := map[string][]byte{}
	for k, v := range files {
		m[k] = append([]byte(nil), v...)
	}
	return m
}

// apply runs an updater, checks it left its input alone, runs Verify on
// the result and returns the files after the rewrite.
func apply(t testing.TB, u Updater, lockPath string, files map[string][]byte, changes []Change) map[string][]byte {
	t.Helper()
	orig := cloneFiles(files)
	out, err := u.Apply(lockPath, files, changes)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for k, v := range orig {
		if !bytes.Equal(files[k], v) {
			t.Fatalf("Apply changed its input %s", k)
		}
	}
	for k := range out {
		if _, ok := files[k]; !ok {
			t.Fatalf("Apply wrote %s, which it was not given", k)
		}
	}
	after := merged(files, out)
	if err := Verify(lockPath, files, after, changes); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return after
}

// applyFails expects Apply to refuse, with an error containing want.
func applyFails(t testing.TB, u Updater, lockPath string, files map[string][]byte, changes []Change, want string) {
	t.Helper()
	out, err := u.Apply(lockPath, files, changes)
	if err == nil {
		t.Fatalf("Apply succeeded, want an error containing %q; wrote %d files", want, len(out))
	}
	if out != nil {
		t.Errorf("Apply returned files with its error")
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("Apply: %v, want an error containing %q", err, want)
	}
}

// sameBytes fails with the first differing line.
func sameBytes(t testing.TB, what string, got, want []byte) {
	t.Helper()
	if bytes.Equal(got, want) {
		return
	}
	g, w := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			t.Fatalf("%s differs at line %d:\n got: %q\nwant: %q", what, i+1, gl, wl)
		}
	}
	t.Fatalf("%s differs (line endings or the end of the file)", what)
}

// diffLines returns the lines of a and b that differ, which must be as many
// in both (the rewrites of these tests keep the number of lines).
func diffLines(t testing.TB, a, b []byte) (before, after []string) {
	t.Helper()
	al, bl := strings.Split(string(a), "\n"), strings.Split(string(b), "\n")
	if len(al) != len(bl) {
		t.Fatalf("the rewrite changed the number of lines: %d → %d", len(al), len(bl))
	}
	for i := range al {
		if al[i] != bl[i] {
			before = append(before, strings.TrimSpace(al[i]))
			after = append(after, strings.TrimSpace(bl[i]))
		}
	}
	return before, after
}

// TestFixturesSayHowTheyWereMade: every fixture says, in GENERATED.md, how
// it was made.
func TestFixturesSayHowTheyWereMade(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "fuzz" { // go test's corpus of fuzz inputs
			continue
		}
		n++
		if _, err := os.Stat(filepath.Join("testdata", e.Name(), "GENERATED.md")); err != nil {
			t.Errorf("testdata/%s has no GENERATED.md", e.Name())
		}
	}
	if n < 10 {
		t.Fatalf("only %d fixtures", n)
	}
	_ = filepath.WalkDir("testdata", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".go") {
			t.Errorf("%s: no Go files in testdata", p)
		}
		return nil
	})
}

// b64 returns the base64 of a hex digest, as npm's integrity spells it.
func b64(t testing.TB, h string) string {
	t.Helper()
	raw, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}
