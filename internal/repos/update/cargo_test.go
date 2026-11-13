package update

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// cargoUpdate is a change of a crate whose new .crate has the SHA-256 sum.
func cargoUpdate(name, from, to, sum string) Change {
	return Change{Type: "cargo", Name: name, From: from, To: to,
		Artifacts: []Artifact{{Role: "package", File: name + "-" + to + ".crate", SHA256: sum}}}
}

// The real updates of cargo-v3 and cargo-v4.
var cargoUpdates = []Change{
	cargoUpdate("itoa", "1.0.10", "1.0.11", "49f1f14873335454500d59611f1cf4a4b0f786f9ac11f4312a78e4cf2566695b"),
	cargoUpdate("ryu", "1.0.17", "1.0.18", "f3cb5ba0dc43242ce17de99c180e96db90b235b8a9fdc9543c96d2209116bd9f"),
}

// TestCargoWritesWhatCargoWrites: the rewrite is byte for byte what cargo
// update wrote (formats 3 and 4), or what Cargo before 1.41 wrote and cargo
// fetch --locked accepts (format 1: dependencies with their source, checksums
// in [metadata]), with LF and with CRLF line endings.
func TestCargoWritesWhatCargoWrites(t *testing.T) {
	crlf := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")) }
	same := func(b []byte) []byte { return b }
	for _, dir := range []string{"cargo-v1", "cargo-v3", "cargo-v4"} {
		for name, conv := range map[string]func([]byte) []byte{"lf": same, "crlf": crlf} {
			t.Run(dir+"/"+name, func(t *testing.T) {
				files := map[string][]byte{"Cargo.lock": conv(fixture(t, dir, "before", "Cargo.lock"))}
				if dir != "cargo-v1" {
					files["Cargo.toml"] = fixture(t, dir, "Cargo.toml")
				}
				after := apply(t, NativeUpdater("cargo/Cargo.lock"), "Cargo.lock", files, cargoUpdates)
				sameBytes(t, "Cargo.lock", after["Cargo.lock"], conv(fixture(t, dir, "after", "Cargo.lock")))
			})
		}
	}
}

// TestCargoOnlyCrateOfItsName: a crate listed by name alone stays so.
func TestCargoOnlyCrateOfItsName(t *testing.T) {
	before := fixture(t, "cargo-v4", "before", "Cargo.lock")
	sum := fakeSHA256("memchr-2.7.2")
	after := apply(t, NativeUpdater("cargo/Cargo.lock"), "Cargo.lock", map[string][]byte{"Cargo.lock": before},
		[]Change{cargoUpdate("memchr", "2.7.1", "2.7.2", sum)})["Cargo.lock"]
	was, is := diffLines(t, before, after)
	if strings.Join(is, "\n") != "version = \"2.7.2\"\nchecksum = \""+sum+"\"" || len(was) != 2 {
		t.Fatalf("changed %q → %q", was, is)
	}
}

// TestCargoRefuses: what the Cargo.lock updater does not rewrite.
func TestCargoRefuses(t *testing.T) {
	v4 := string(fixture(t, "cargo-v4", "before", "Cargo.lock"))
	v1 := string(fixture(t, "cargo-v1", "before", "Cargo.lock"))
	sum := fakeSHA256("x")
	itoa := cargoUpdate("itoa", "1.0.10", "1.0.11", sum)
	git := "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"semver\",\n]\n\n" +
		"[[package]]\nname = \"semver\"\nversion = \"1.0.23\"\nsource = \"git+https://github.com/dtolnay/semver?tag=1.0.23#69efd3cc770ead273a06ad1788477b3092996d29\"\n"
	for _, tc := range []struct {
		name, lock string
		changes    []Change
		want       string
	}{
		{"absent", v4, []Change{cargoUpdate("serde", "1.0.0", "1.0.1", sum)}, "from a registry is not in the lock file"},
		{"git crate", git, []Change{cargoUpdate("semver", "1.0.23", "1.0.24", sum)}, "from another source"},
		{"new version already there", v4, []Change{cargoUpdate("itoa", "1.0.10", "0.4.8", sum)}, "is already in the lock file"},
		{"sorts elsewhere", v4, []Change{cargoUpdate("itoa", "0.4.8", "1.0.12", sum)}, "sorts elsewhere"},
		{"same name twice from a registry", v4 + "\n[[package]]\nname = \"itoa\"\nversion = \"1.0.10\"\nsource = \"sparse+https://example.com/index/\"\nchecksum = \"" + sum + "\"\n",
			[]Change{itoa}, "comes from two registries"},
		{"checksum none", strings.Replace(v1, "\"b1a46d1a171d865aa5f83f92695765caa047a9b4cbae2cbf37dbd613a793fd4c\"", "\"<none>\"", 1), []Change{itoa}, "not a SHA-256"},
		{"no artifact", v4, []Change{{Type: "cargo", Name: "itoa", From: "1.0.10", To: "1.0.11"}}, "no \"package\" artifact"},
		{"multi-line string", v4 + "\n[x]\ny = \"\"\"\n[[package]]\n\"\"\"\n", []Change{itoa}, "multi-line string"},
		{"escape", strings.Replace(v4, `name = "ryu"`, `name = "r`+"\\"+`u0079u"`, 1), []Change{itoa}, "an escape"},
		{"literal string", strings.Replace(v4, `name = "ryu"`, `name = 'ryu'`, 1), []Change{itoa}, "a value in a form"},
		{"dotted key", strings.Replace(v4, `name = "ryu"`, `package.name = "ryu"`, 1), []Change{itoa}, "a key in a form"},
		{"unknown key", strings.Replace(v4, `name = "ryu"`, "name = \"ryu\"\nfeatures = []", 1), []Change{itoa}, "does not know"},
		{"repeated key", strings.Replace(v4, `name = "ryu"`, "name = \"ryu\"\nname = \"ryu\"", 1), []Change{itoa}, "repeated key"},
		{"quoted table", strings.Replace(v4, "[[package]]\nname = \"ryu\"", "[[\"package\"]]\nname = \"ryu\"", 1), []Change{itoa}, "quoted table name"},
		{"unclosed list", "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"itoa\",\n", []Change{itoa}, "a list is not closed"},
		{"another source named", strings.Replace(v1, "\"itoa 1.0.10 (registry+https://github.com/rust-lang/crates.io-index)\",\n \"memchr",
			"\"itoa 1.0.10 (sparse+https://example.com/)\",\n \"memchr", 1), []Change{itoa}, "from another source"},
		{"replaced", strings.Replace(v4, "name = \"ryu\"", "name = \"ryu\"\nreplace = \"itoa 1.0.10 (registry+https://github.com/rust-lang/crates.io-index)\"", 1),
			[]Change{itoa}, "is the replacement of another crate"},
		{"list order", strings.Replace(v4, " \"itoa 0.4.8\",\n \"itoa 1.0.10\",", " \"itoa 1.0.10\",\n \"itoa 1.0.9\",", 1) +
			"\n[[package]]\nname = \"itoa\"\nversion = \"1.0.9\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
			[]Change{cargoUpdate("itoa", "1.0.10", "1.0.95", sum)}, "would need another order"},
		{"not UTF-8", v4 + "# \xff\n", []Change{itoa}, "not valid UTF-8"},
		{"bad name", v4, []Change{cargoUpdate("it oa", "1.0.10", "1.0.11", sum)}, "is not a cargo package name"},
		// A patch of the workspace that no locked version uses yet: at the
		// version it provides, Cargo would build it, not the vetted crate.
		{"patch unused", v4 + "\n[[patch.unused]]\nname = \"itoa\"\nversion = \"1.0.11\"\n", []Change{itoa}, "the workspace patches it"},
		// Cargo reads [metadata] checksums in a lock file of format 2 or
		// later as a bad merge, and discards every checksum.
		{"metadata checksums besides inline ones", v4 + "\n[metadata]\n\"checksum nothing-here 9.9.9 (registry+https://github.com/rust-lang/crates.io-index)\" = \"" + sum + "\"\n",
			[]Change{itoa}, "Cargo discards every checksum"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			applyFails(t, NativeUpdater("cargo/Cargo.lock"), "Cargo.lock", map[string][]byte{"Cargo.lock": []byte(tc.lock)}, tc.changes, tc.want)
		})
	}
}

// TestCargoManyCratesOfAName: the rewrite costs the size of the file, however
// many crates share the changed crate's name and however many lists name them.
func TestCargoManyCratesOfAName(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a large Cargo.lock")
	}
	const n = 40000
	var b strings.Builder
	b.WriteString("version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n")
	for i := 0; i < 4*n; i++ {
		b.WriteString(" \"itoa 2.0.0\",\n")
	}
	b.WriteString("]\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "\n[[package]]\nname = \"itoa\"\nversion = \"0.%d.0\"\n", i)
	}
	b.WriteString("\n[[package]]\nname = \"itoa\"\nversion = \"2.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"" + fakeSHA256("x") + "\"\n")
	data := []byte(b.String())
	start := time.Now()
	_, err := NativeUpdater("cargo/Cargo.lock").Apply("Cargo.lock", map[string][]byte{"Cargo.lock": data}, []Change{cargoUpdate("itoa", "2.0.0", "2.0.1", fakeSHA256("y"))})
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	// Looking up the changed crate for every reference among all the crates
	// of its name took 8 s here.
	t.Logf("%d crates of a name, %d references: %v", n, 4*n, took)
	if !raceEnabled && took > 2*time.Second {
		t.Errorf("rewriting a %d KB Cargo.lock took %v", len(data)>>10, took)
	}
}
