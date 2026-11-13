package update

import (
	"bytes"
	"sort"
	"strings"
	"testing"
)

// pipUpdate is a change of a Python project whose new release has files of
// the given SHA-256s.
func pipUpdate(name, from, to string, sha256s ...string) Change {
	c := Change{Type: "pip", Name: name, From: from, To: to}
	for i, h := range sha256s {
		c.Artifacts = append(c.Artifacts, Artifact{Role: "file", File: name + "-" + to + "-" + string(rune('a'+i)) + ".whl", SHA256: h})
	}
	return c
}

// The real updates of pip-hashes: the new releases' files, listed unsorted.
var (
	coloramaUpdate = pipUpdate("colorama", "0.4.5", "0.4.6",
		"4f1d9991f5acc0ca119f9d443620b77f9d6b33703e51011c16baf57afb285fc6",
		"08695f5cb7ed6e0531a20572697297273c47b8cae5a63ffc6d6ed5c201be6e44")
	idnaUpdate = pipUpdate("idna", "3.7", "3.8",
		"d838c2c0ed6fced7693d5e8ab8e734d5f8fda53a039c0164afb0b82e771e3603",
		"050b4e5baadcd44d760cedbd2b8e639f2ff89bbc7a5730fcc662954303377aac")
)

// TestRequirementsWritesWhatUvWrites: the rewrite is byte for byte what uv
// pip compile wrote for the new pins, with hashes and without, with LF and
// with CRLF line endings.
func TestRequirementsWritesWhatUvWrites(t *testing.T) {
	crlf := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")) }
	same := func(b []byte) []byte { return b }
	for _, dir := range []string{"pip-hashes", "pip-plain"} {
		for name, conv := range map[string]func([]byte) []byte{"lf": same, "crlf": crlf} {
			t.Run(dir+"/"+name, func(t *testing.T) {
				files := map[string][]byte{"requirements/prod.txt": conv(fixture(t, dir, "before", "requirements.txt"))}
				u := NativeUpdater("pip/requirements.txt")
				after := apply(t, u, "requirements/prod.txt", files, []Change{idnaUpdate, coloramaUpdate})
				sameBytes(t, "requirements/prod.txt", after["requirements/prod.txt"], conv(fixture(t, dir, "after", "requirements.txt")))
			})
		}
	}
}

// TestRequirementsMarkers: of two pins of a project for different
// environments, only the one at the old version moves.
func TestRequirementsMarkers(t *testing.T) {
	before := fixture(t, "pip-hashes", "before", "requirements.txt")
	c := pipUpdate("urllib3", "2.6.3", "2.6.4", fakeSHA256("u2"), fakeSHA256("u1"), fakeSHA256("u3"))
	after := apply(t, NativeUpdater("pip/requirements.txt"), "requirements.txt",
		map[string][]byte{"requirements.txt": before}, []Change{c})["requirements.txt"]
	i := bytes.Index(before, []byte("urllib3==2.6.3"))
	j := bytes.Index(before, []byte("urllib3==2.8.0"))
	got := string(after)
	if !strings.Contains(got, "urllib3==2.8.0 ; python_full_version >= '3.10' \\\n    --hash=sha256:0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3") {
		t.Error("the pin for Python 3.10 and later moved")
	}
	if !bytes.Equal(after[:i], before[:i]) || !strings.HasSuffix(got, string(before[j-len("    # via requests\n"):])) {
		t.Error("lines around the pin changed")
	}
	block := got[i:strings.Index(got, "    # via requests\nurllib3==2.8.0")]
	hashes := sortedHex(fakeSHA256("u1"), fakeSHA256("u2"), fakeSHA256("u3"))
	want := "urllib3==2.6.4 ; python_full_version < '3.10' \\\n" +
		"    --hash=sha256:" + hashes[0] + " \\\n" +
		"    --hash=sha256:" + hashes[1] + " \\\n" +
		"    --hash=sha256:" + hashes[2] + "\n"
	if block != want {
		t.Fatalf("the pin became\n%s\nwant\n%s", block, want)
	}
}

func sortedHex(hs ...string) []string {
	out := append([]string(nil), hs...)
	sort.Strings(out)
	return out
}

// TestRequirementsByHand: requirements as people write them — hashes in a
// row, extras, spaces around "==", names in their own spelling, comments, a
// project pinned twice for different environments.
func TestRequirementsByHand(t *testing.T) {
	h := func(s string) string { return fakeSHA256(s) }
	before := "# Hand-maintained.\n" +
		"--index-url https://pypi.org/simple\n" +
		"-r base.txt\n" +
		"requests[socks]==2.32.3  --hash=sha256:" + h("r1") + "  --hash=sha256:" + h("r2") + "  # reviewed\n" +
		"My_Weird.Name==0.1  # trailing comment\n" +
		"zope.interface == 7.0.3 \\\n" +
		"\t--hash=sha256:" + h("z1") + " \\\n" +
		"\t--hash=sha256:" + h("z2") + "\n" +
		"foo==1.0 ; python_version < \"3.8\"\n" +
		"foo==1.0 ; python_version >= \"3.8\" and sys_platform != \"win32\"\n" +
		"foo==2.0 ; python_version >= \"3.12\"\n" +
		"bar==1.0 --hash=sha256:" + h("b1")
	rs := sortedHex(h("R1"), h("R2"), h("R3"))
	zs := sortedHex(h("Z1"))
	want := "# Hand-maintained.\n" +
		"--index-url https://pypi.org/simple\n" +
		"-r base.txt\n" +
		"requests[socks]==2.32.4  --hash=sha256:" + rs[0] + "  --hash=sha256:" + rs[1] + "  --hash=sha256:" + rs[2] + "  # reviewed\n" +
		"My_Weird.Name==0.2  # trailing comment\n" +
		"zope.interface == 7.1.0 \\\n" +
		"\t--hash=sha256:" + zs[0] + "\n" +
		"foo==1.1 ; python_version < \"3.8\"\n" +
		"foo==1.1 ; python_version >= \"3.8\" and sys_platform != \"win32\"\n" +
		"foo==2.0 ; python_version >= \"3.12\"\n" +
		"bar==1.1 --hash=sha256:" + h("B1")
	changes := []Change{
		pipUpdate("requests", "2.32.3", "2.32.4", h("R3"), h("R1"), h("R2"), h("R1")),
		pipUpdate("my-weird-name", "0.1", "0.2", h("W1")),
		pipUpdate("zope-interface", "7.0.3", "7.1.0", h("Z1")),
		pipUpdate("foo", "1.0", "1.1", h("F1")),
		pipUpdate("bar", "1.0", "1.1", h("B1")),
	}
	after := apply(t, NativeUpdater("pip/requirements.txt"), "requirements.txt",
		map[string][]byte{"requirements.txt": []byte(before)}, changes)
	sameBytes(t, "requirements.txt", after["requirements.txt"], []byte(want))

	// One hash becomes several on continuation lines, in the file's style.
	before = "six==1.16.0 \\\r\n    --hash=sha256:" + h("s1") + "\r\n    # via x\r\n"
	ss := sortedHex(h("S1"), h("S2"))
	want = "six==1.17.0 \\\r\n    --hash=sha256:" + ss[0] + " \\\r\n    --hash=sha256:" + ss[1] + "\r\n    # via x\r\n"
	after = apply(t, NativeUpdater("pip/requirements.txt"), "requirements.txt",
		map[string][]byte{"requirements.txt": []byte(before)}, []Change{pipUpdate("six", "1.16.0", "1.17.0", h("S2"), h("S1"))})
	sameBytes(t, "requirements.txt", after["requirements.txt"], []byte(want))

	// A byte order mark is not part of the first requirement, and stays.
	before = "\xef\xbb\xbfidna==3.7 --hash=sha256:" + h("i1") + "\n"
	want = "\xef\xbb\xbfidna==3.8 --hash=sha256:" + h("I1") + "\n"
	after = apply(t, NativeUpdater("pip/requirements.txt"), "requirements.txt",
		map[string][]byte{"requirements.txt": []byte(before)}, []Change{pipUpdate("idna", "3.7", "3.8", h("I1"))})
	sameBytes(t, "requirements.txt", after["requirements.txt"], []byte(want))
}

// TestRequirementsRefuses: what the requirements updater does not rewrite.
func TestRequirementsRefuses(t *testing.T) {
	h := fakeSHA256("x")
	c := pipUpdate("idna", "3.7", "3.8", h)
	for _, tc := range []struct {
		name, file string
		changes    []Change
		want       string
	}{
		{"absent", "requests==2.32.3\n", []Change{c}, "is not in the requirements file"},
		{"arbitrary equality", "idna===3.7\n", []Change{c}, "arbitrary-equality"},
		{"range", "idna==3.7\nidna>=3.0\n", []Change{c}, "not pinned to an exact version"},
		{"wildcard", "idna==3.*\n", []Change{c}, "not pinned to an exact version"},
		{"direct reference", "idna @ https://files.example/idna-3.7-py3-none-any.whl\n", []Change{c}, "direct reference"},
		{"hashes without files", "idna==3.7 --hash=sha256:" + h + "\n", []Change{{Type: "pip", Name: "idna", From: "3.7", To: "3.8"}}, "no file artifacts"},
		{"hash value apart", "idna==3.7 --hash sha256:" + h + "\n", []Change{c}, "a --hash option in a form"},
		{"empty hash value", "idna==3.7 --hash= sha256:" + h + "\n", []Change{c}, "a --hash option in a form"},
		{"unreadable hash", "idna==3.7 \\\n    --hash=sha256:" + h[:10] + "\n", []Change{c}, "a --hash option in a form"},
		{"unknown algorithm", "idna==3.7 --hash=blake2:" + h + "\n", []Change{c}, "a --hash option in a form"},
		{"hashes on both lines", "idna==3.7 --hash=sha256:" + h + " \\\n    --hash=sha256:" + h + "\n", []Change{c}, "laid out"},
		{"two hashes on a line", "idna==3.7 \\\n    --hash=sha256:" + h + " --hash=sha256:" + h + "\n", []Change{c}, "laid out"},
		{"marker on a continuation line", "idna==3.7 \\\n    ; python_version < '3.8' \\\n    --hash=sha256:" + h + "\n", []Change{c}, "laid out"},
		{"interleaved", "idna==3.7 --hash=sha256:" + h + " --config-settings=a=b --hash=sha256:" + h + "\n", []Change{c}, "interleaved"},
		{"comment in a continued requirement", "idna==3.7 \\\n    --hash=sha256:" + h + "  # x\n", []Change{c}, "a comment inside"},
		{"NUL", "idna==3.7\n\x00\n", []Change{c}, "NUL"},
		{"bad version", "idna==3.7\n", []Change{pipUpdate("idna", "3.7", "3.8,<4", h)}, "is not a pip version"},
		{"epoch", "idna==3.7\n", []Change{pipUpdate("idna", "3.7", "1!3.8", h)}, "is not a pip version"},
		{"two spellings", "idna==3.7\n", []Change{c, pipUpdate("IDNA", "3.7", "3.9", h)}, "two changes"},
		{"lone carriage return", "idna==3.7\n# note\ridna==3.7\n", []Change{c}, "breaks lines where pip"},
		{"form feed", "idna==3.7\n# x\fevil==6.6.6\n", []Change{c}, "breaks lines where pip"},
		{"line separator", "idna==3.7\n# x" + "\u2028" + "evil==6.6.6\n", []Change{c}, "breaks lines where pip"},
		{"comment continued", "idna==3.7\n# pinned \\\nevil==6.6.6\n", []Change{c}, "a comment line"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			applyFails(t, NativeUpdater("pip/requirements.txt"), "requirements.txt",
				map[string][]byte{"requirements.txt": []byte(tc.file)}, tc.changes, tc.want)
		})
	}
}

// TestRequirementsLeavesOtherPins: another pin of a changed project — for
// other environments — stays as it is, whatever its form.
func TestRequirementsLeavesOtherPins(t *testing.T) {
	h := fakeSHA256
	before := "urllib3==2.6.3 ; python_full_version < '3.10' --hash=sha256:" + h("a") + "\n" +
		"urllib3==2.8.0 ; python_full_version >= '3.10' --hash sha256:" + h("b") + "\n"
	want := "urllib3==2.6.4 ; python_full_version < '3.10' --hash=sha256:" + h("c") + "\n" +
		"urllib3==2.8.0 ; python_full_version >= '3.10' --hash sha256:" + h("b") + "\n"
	after := apply(t, NativeUpdater("pip/requirements.txt"), "requirements.txt",
		map[string][]byte{"requirements.txt": []byte(before)}, []Change{pipUpdate("urllib3", "2.6.3", "2.6.4", h("c"))})
	sameBytes(t, "requirements.txt", after["requirements.txt"], []byte(want))
}
