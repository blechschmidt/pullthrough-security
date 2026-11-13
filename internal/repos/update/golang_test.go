package update

import (
	"bytes"
	"strings"
	"testing"
)

// goUpdate is a change of a module whose new zip and go.mod have the hashes.
func goUpdate(name, from, to, zipH1, modH1 string) Change {
	c := Change{Type: "go", Name: name, From: from, To: to}
	if zipH1 != "" {
		c.Artifacts = append(c.Artifacts, Artifact{Role: "package", H1: zipH1, SHA256: fakeSHA256(name + to + "zip")})
	}
	if modH1 != "" {
		c.Artifacts = append(c.Artifacts, Artifact{Role: "go.mod", H1: modH1, SHA256: fakeSHA256(name + to + "mod")})
	}
	return c
}

// The real updates of go-modules, with the hashes go wrote.
var goUpdates = []Change{
	goUpdate("github.com/spf13/pflag", "v1.0.9", "v1.0.10",
		"4EBh2KAYBwaONj6b2Ye1GiHfwjqyROoF4RwYO+vPwFk=", "McXfInJRrz4CZXVZOBLb0bTZqETkiAhM9Iw0y3An2Bg="),
	goUpdate("github.com/google/uuid", "v1.5.0", "v1.6.0",
		"NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=", "TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo="),
}

// TestGoWritesWhatGoWrites: go.mod is byte for byte what `go get` and `go mod
// tidy` wrote; go.sum too, but for the old versions' go.mod hashes, which the
// rewrite keeps (tidy dropped them as they left the module graph) — and v1.0.10
// sorts after v1.0.5 and v1.0.9 as the go command sorts. The lock path may be
// either file, in any directory.
func TestGoWritesWhatGoWrites(t *testing.T) {
	wantSum := string(fixture(t, "go-modules", "after", "go.sum"))
	for _, kept := range []struct{ after, line string }{
		{"github.com/cpuguy83/go-md2man/v2 v2.0.3/go.mod h1:tgQtvFlXSQOSOSIRvRPT7W67SCa46tRHOmNcaadrF8o=\n", "github.com/google/uuid v1.5.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=\n"},
		{"github.com/spf13/pflag v1.0.5/go.mod h1:McXfInJRrz4CZXVZOBLb0bTZqETkiAhM9Iw0y3An2Bg=\n", "github.com/spf13/pflag v1.0.9/go.mod h1:McXfInJRrz4CZXVZOBLb0bTZqETkiAhM9Iw0y3An2Bg=\n"},
	} {
		if !strings.Contains(wantSum, kept.after) {
			t.Fatalf("the fixture has no %q", kept.after)
		}
		wantSum = strings.Replace(wantSum, kept.after, kept.after+kept.line, 1)
	}
	for _, lock := range []string{"go.mod", "go.sum", "tools/go.sum"} {
		t.Run(lock, func(t *testing.T) {
			dir := strings.TrimSuffix(strings.TrimSuffix(lock, "go.mod"), "go.sum")
			files := map[string][]byte{
				dir + "go.mod": fixture(t, "go-modules", "before", "go.mod"),
				dir + "go.sum": fixture(t, "go-modules", "before", "go.sum"),
			}
			u := NativeUpdater("go/" + strings.TrimPrefix(lock, dir))
			if u == nil || u.Key() != "go/go.mod" {
				t.Fatal("no go updater")
			}
			after := apply(t, u, lock, files, goUpdates)
			sameBytes(t, "go.mod", after[dir+"go.mod"], fixture(t, "go-modules", "after", "go.mod"))
			sameBytes(t, "go.sum", after[dir+"go.sum"], []byte(wantSum))
		})
	}
}

// TestGoIndirectAndOrder: a single-line requirement keeps its comment; go.sum
// lines go where the go command sorts them — by semantic version (v1.10.0
// after v1.9.0), pseudo-versions before releases — whether the file ends in
// a newline or not, with LF or CRLF.
func TestGoIndirectAndOrder(t *testing.T) {
	mod := "module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/a v1.9.0\n\texample.com/p v0.0.0-20230101000000-abcdefabcdef\n)\n\n" +
		"require example.com/i v1.1.0 // indirect\n\nexclude example.com/a v1.11.0\n"
	sum := "example.com/a v1.2.0/go.mod h1:" + fakeH1("a120m") + "\n" +
		"example.com/a v1.9.0 h1:" + fakeH1("a190") + "\n" +
		"example.com/a v1.9.0/go.mod h1:" + fakeH1("a190m") + "\n" +
		"example.com/b v1.0.0/go.mod h1:" + fakeH1("b100m") + "\n" +
		"example.com/i v1.1.0 h1:" + fakeH1("i110") + "\n" +
		"example.com/i v1.1.0/go.mod h1:" + fakeH1("i110m") + "\n" +
		"example.com/p v0.0.0-20230101000000-abcdefabcdef h1:" + fakeH1("p1") + "\n" +
		"example.com/p v0.0.0-20230101000000-abcdefabcdef/go.mod h1:" + fakeH1("p1m") + "\n" +
		"example.com/p v0.1.0/go.mod h1:" + fakeH1("p010m")
	changes := []Change{
		goUpdate("example.com/a", "v1.9.0", "v1.10.0", fakeH1("a1100"), fakeH1("a1100m")),
		goUpdate("example.com/i", "v1.1.0", "v1.1.1", fakeH1("i111"), fakeH1("i111m")),
		goUpdate("example.com/p", "v0.0.0-20230101000000-abcdefabcdef", "v0.0.0-20240101000000-123456123456", fakeH1("p2"), fakeH1("p2m")),
	}
	wantMod := strings.Replace(strings.Replace(strings.Replace(mod, "a v1.9.0", "a v1.10.0", 1), "i v1.1.0 //", "i v1.1.1 //", 1),
		"p v0.0.0-20230101000000-abcdefabcdef", "p v0.0.0-20240101000000-123456123456", 1)
	wantSum := "example.com/a v1.2.0/go.mod h1:" + fakeH1("a120m") + "\n" +
		"example.com/a v1.9.0/go.mod h1:" + fakeH1("a190m") + "\n" +
		"example.com/a v1.10.0 h1:" + fakeH1("a1100") + "\n" +
		"example.com/a v1.10.0/go.mod h1:" + fakeH1("a1100m") + "\n" +
		"example.com/b v1.0.0/go.mod h1:" + fakeH1("b100m") + "\n" +
		"example.com/i v1.1.0/go.mod h1:" + fakeH1("i110m") + "\n" +
		"example.com/i v1.1.1 h1:" + fakeH1("i111") + "\n" +
		"example.com/i v1.1.1/go.mod h1:" + fakeH1("i111m") + "\n" +
		"example.com/p v0.0.0-20230101000000-abcdefabcdef/go.mod h1:" + fakeH1("p1m") + "\n" +
		"example.com/p v0.0.0-20240101000000-123456123456 h1:" + fakeH1("p2") + "\n" +
		"example.com/p v0.0.0-20240101000000-123456123456/go.mod h1:" + fakeH1("p2m") + "\n" +
		"example.com/p v0.1.0/go.mod h1:" + fakeH1("p010m")
	crlf := func(s string) []byte { return []byte(strings.ReplaceAll(s, "\n", "\r\n")) }
	for name, conv := range map[string]func(string) []byte{"lf": func(s string) []byte { return []byte(s) }, "crlf": crlf} {
		for _, final := range []string{"", "\n"} {
			files := map[string][]byte{"go.mod": conv(mod), "go.sum": conv(sum + final)}
			after := apply(t, NativeUpdater("go/go.mod"), "go.mod", files, changes)
			sameBytes(t, name+" go.mod", after["go.mod"], conv(wantMod))
			sameBytes(t, name+" go.sum", after["go.sum"], conv(wantSum+final))
		}
	}

	// A module whose zip go.sum never hashed gets no zip hash.
	files := map[string][]byte{"go.mod": []byte(mod), "go.sum": []byte(strings.Replace(sum, "example.com/i v1.1.0 h1:"+fakeH1("i110")+"\n", "", 1))}
	after := apply(t, NativeUpdater("go/go.mod"), "go.mod", files, changes[1:2])
	if strings.Contains(string(after["go.sum"]), "example.com/i v1.1.1 h1:") || !strings.Contains(string(after["go.sum"]), "example.com/i v1.1.1/go.mod h1:") {
		t.Errorf("go.sum:\n%s", after["go.sum"])
	}
	// A line the file already has is not written twice.
	files = map[string][]byte{"go.mod": []byte(mod), "go.sum": []byte(sum + "\nexample.com/i v1.1.1/go.mod h1:" + fakeH1("i111m") + "\n")}
	after = apply(t, NativeUpdater("go/go.mod"), "go.mod", files, changes[1:2])
	if n := bytes.Count(after["go.sum"], []byte("example.com/i v1.1.1/go.mod")); n != 1 {
		t.Errorf("the new go.mod hash is in go.sum %d times", n)
	}
}

// TestGoRefuses: what the go updater does not rewrite.
func TestGoRefuses(t *testing.T) {
	mod := string(fixture(t, "go-modules", "before", "go.mod"))
	sum := string(fixture(t, "go-modules", "before", "go.sum"))
	pflag := goUpdates[0]
	h := fakeH1("x")
	for _, tc := range []struct {
		name, mod, sum string
		changes        []Change
		want           string
	}{
		{"not required", mod, sum, []Change{goUpdate("gopkg.in/yaml.v3", "v3.0.1", "v3.0.2", h, h)}, "does not require gopkg.in/yaml.v3"},
		{"other version", mod, sum, []Change{goUpdate("github.com/spf13/pflag", "v1.0.8", "v1.0.10", h, h)}, "requires github.com/spf13/pflag v1.0.9, not v1.0.8"},
		{"replaced", mod + "\nreplace github.com/spf13/pflag => ../pflag\n", sum, []Change{pflag}, "a replace directive names github.com/spf13/pflag"},
		{"replaced version", mod + "\nreplace (\n\tgithub.com/spf13/pflag v1.0.9 => github.com/spf13/pflag v1.0.8\n)\n", sum, []Change{pflag}, "a replace directive names"},
		{"replacement", mod + "\nreplace example.com/other => github.com/spf13/pflag v1.0.9\n", sum, []Change{pflag}, "a replace directive names"},
		{"excluded", mod + "\nexclude github.com/spf13/pflag v1.0.10\n", sum, []Change{pflag}, "excludes github.com/spf13/pflag v1.0.10"},
		{"required twice", mod + "\nrequire github.com/spf13/pflag v1.0.9\n", sum, []Change{pflag}, "more than once"},
		{"quoted", strings.Replace(mod, "github.com/spf13/pflag v1.0.9", "github.com/spf13/pflag \"v1.0.9\"", 1), sum, []Change{pflag}, "in a form the updater does not rewrite"},
		{"unclosed block", strings.TrimSuffix(mod, "require github.com/inconshreveable/mousetrap v1.1.0 // indirect\n") + "require (\n", sum, []Change{pflag}, "is not closed"},
		{"another hash", mod, sum + "github.com/spf13/pflag v1.0.10/go.mod h1:" + h + "\n", []Change{pflag}, "already holds another hash"},
		{"malformed go.sum", mod, sum + "github.com/x v1.0.0\n", []Change{pflag}, "expected three fields"},
		{"old hash not h1", mod, strings.Replace(sum, "github.com/spf13/pflag v1.0.9 h1:9exaQaMOCwffKiiiYk6/BndUBv+iRViNW+4lEMi0PvY=", "github.com/spf13/pflag v1.0.9 0", 1),
			[]Change{pflag}, "that is not an h1 hash"},
		{"no zip hash", mod, sum, []Change{goUpdate("github.com/spf13/pflag", "v1.0.9", "v1.0.10", "", h)}, "no \"package\" artifact"},
		{"no go.mod hash", mod, sum, []Change{goUpdate("github.com/spf13/pflag", "v1.0.9", "v1.0.10", h, "")}, "no \"go.mod\" artifact"},
		{"bad hash", mod, sum, []Change{goUpdate("github.com/spf13/pflag", "v1.0.9", "v1.0.10", "abc", h)}, "has no module hash"},
		{"major version", mod, sum, []Change{goUpdate("github.com/spf13/pflag", "v1.0.9", "v2.0.0", h, h)}, "is not a version of that module path"},
		{"not canonical", mod, sum, []Change{goUpdate("github.com/spf13/pflag", "v1.0.9", "v1.1", h, h)}, "is not a go version"},
		{"NUL", mod + "\x00", sum, []Change{pflag}, "NUL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			applyFails(t, NativeUpdater("go/go.mod"), "go.mod", map[string][]byte{"go.mod": []byte(tc.mod), "go.sum": []byte(tc.sum)}, tc.changes, tc.want)
		})
	}
	applyFails(t, NativeUpdater("go/go.mod"), "go.mod", map[string][]byte{"go.mod": []byte(mod)}, []Change{pflag}, "go.sum is not among the files")
	applyFails(t, NativeUpdater("go/go.sum"), "a/go.sum", map[string][]byte{"a/go.sum": []byte(sum)}, []Change{pflag}, "a/go.mod is not among the files")
	applyFails(t, NativeUpdater("go/go.mod"), "go.work", map[string][]byte{"go.work": []byte(mod)}, []Change{pflag}, "not a go.mod or go.sum")
}

// TestGoMajorVersions: the version must be one of the module path's.
func TestGoMajorVersions(t *testing.T) {
	for _, tc := range []struct {
		path, version string
		ok            bool
	}{
		{"example.com/a", "v0.1.0", true},
		{"example.com/a", "v1.2.3", true},
		{"example.com/a", "v2.0.0", false},
		{"example.com/a", "v2.0.0+incompatible", true},
		{"example.com/a/v2", "v2.1.0", true},
		{"example.com/a/v2", "v3.0.0", false},
		{"example.com/a/v2", "v2.0.0+incompatible", false},
		{"example.com/a/v1", "v1.0.0", true},
		{"gopkg.in/yaml.v3", "v3.0.1", true},
		{"gopkg.in/yaml.v3", "v2.4.0", false},
		{"gopkg.in/check.v1", "v0.0.0-20161208181325-20d25e280405", true},
		{"gopkg.in/foo.v2-unstable", "v2.0.0", true},
	} {
		if got := goMajorFits(tc.path, tc.version); got != tc.ok {
			t.Errorf("goMajorFits(%q, %q) = %v", tc.path, tc.version, got)
		}
	}
}

// TestSemverOrder: Go's order of module versions (golang.org/x/mod/semver)
// and Cargo's.
func TestSemverOrder(t *testing.T) {
	ordered := []string{"bad", "v0.0.0-20230101000000-abcdefabcdef", "v0.1.0", "v1", "v1.0.1-alpha", "v1.0.1-alpha.1", "v1.0.1-alpha.beta",
		"v1.0.1-beta", "v1.0.1-beta.2", "v1.0.1-beta.11", "v1.0.1-rc.1", "v1.0.1", "v1.2", "v1.9.0", "v1.10.0", "v2.0.0+incompatible", "v10.0.0"}
	for i := range ordered {
		for j := range ordered {
			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			if got := goSemverCompare(ordered[i], ordered[j]); got != want {
				t.Errorf("goSemverCompare(%q, %q) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	for _, tc := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.0.9", "1.0.10", -1, true},
		{"1.0.10", "0.4.8", 1, true},
		{"1.0.0-rc.1", "1.0.0", -1, true},
		{"1.0.0+a", "1.0.0+b", 0, false},
		{"1.0", "1.0.0", 0, false},
		{"01.0.0", "1.0.0", 0, false},
	} {
		if got, ok := semverCompare(tc.a, tc.b); got != tc.want || ok != tc.ok {
			t.Errorf("semverCompare(%q, %q) = %d, %v", tc.a, tc.b, got, ok)
		}
	}
}
