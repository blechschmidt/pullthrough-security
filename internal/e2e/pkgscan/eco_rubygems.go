//go:build integration
// +build integration

package pkgscan

import (
	"crypto/md5"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// RubyGems: Bundler resolves through the compact index — "/versions" lists
// every gem with its versions and an MD5 of the gem's info document,
// "/info/<gem>" lists one gem's versions with their dependencies and the
// SHA-256 of each .gem — and downloads "/gems/<name>-<version>.gem". The
// backend reads /info/<gem> itself to verify the .gem it fetches. Nothing is
// rewritten.
//
// A .gem is an uncompressed tar of three members, in the order `gem build`
// writes them: metadata.gz (the gzipped YAML gemspec), data.tar.gz (the gem's
// files) and checksums.yaml.gz (the SHA-256 and SHA-512 of the other two). The
// scanner opens data.tar.gz in place, so a gem's files are listed by the paths
// they are installed at.

func init() {
	register(eco{
		ID: "rubygems", Type: "rubygems", Title: "RubyGems",
		Format:   "gem (.gem, tar of metadata.gz, data.tar.gz, checksums.yaml.gz)",
		Registry: gemRegistry,
	})
}

func gemRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	var versions []string // the lines of /versions, one per gem
	for _, s := range env.Specs {
		name := s.Name()
		gem := gemBuild(name, map[string]string{
			"lib/" + name + ".rb": "module Pte2e\n  def self.answer\n    42\n  end\nend\n",
			markerFile:            s.Text(""),
		})
		path := "/gems/" + name + "-" + fixtureVersion + ".gem"
		reg.mux.File(path, gem, "application/octet-stream")
		// A version without dependencies: an empty dependency list before the "|".
		info := "---\n" + fixtureVersion + " |checksum:" + hexOf(gem) + "\n"
		reg.mux.File("/info/"+name, []byte(info), "text/plain; charset=utf-8")
		infoMD5 := md5.Sum([]byte(info))
		versions = append(versions, name+" "+fixtureVersion+" "+hex.EncodeToString(infoMD5[:]))

		reg.add(s.Variant, &pkgPull{
			Name: name, Version: fixtureVersion,
			// What `bundle install` asks a compact-index source for, in order.
			Preamble: []step{
				{Path: "/versions", Contains: []string{"\n" + name + " " + fixtureVersion + " "}},
				{Path: "/info/" + name, Contains: []string{fixtureVersion + " |checksum:" + hexOf(gem)}},
			},
			Payload: step{Path: path},
			Body:    gem,
			Marker:  markerFile,
		})
	}
	sort.Strings(versions)
	reg.mux.File("/versions", []byte("created_at: 2024-01-02T03:04:05Z\n---\n"+strings.Join(versions, "\n")+"\n"), "text/plain; charset=utf-8")
	return reg, nil
}

// gemBuild builds a .gem the way `gem build` lays one out, for a gem named name
// whose files are files (path -> content).
func gemBuild(name string, files map[string]string) []byte {
	data := tarGz(files)
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	metadata := gzipOf([]byte(gemSpecYAML(name, paths)))
	sha512Of := func(b []byte) string {
		sum := sha512.Sum512(b)
		return hex.EncodeToString(sum[:])
	}
	checksums := fmt.Sprintf("---\nSHA256:\n  metadata.gz: %s\n  data.tar.gz: %s\nSHA512:\n  metadata.gz: %s\n  data.tar.gz: %s\n",
		hexOf(metadata), hexOf(data), sha512Of(metadata), sha512Of(data))
	return tarOf(
		member{Name: "metadata.gz", Data: string(metadata), Mode: 0o444},
		member{Name: "data.tar.gz", Data: string(data), Mode: 0o444},
		member{Name: "checksums.yaml.gz", Data: string(gzipOf([]byte(checksums))), Mode: 0o444},
	)
}

// gemSpecYAML renders a gem's specification as `gem build` serializes it into
// metadata.gz. It declares no native extension and no post-install message:
// those are what the install-hook gate (on by default) examines a gem for, and
// this fixture is about the package scan.
func gemSpecYAML(name string, files []string) string {
	var b strings.Builder
	b.WriteString("--- !ruby/object:Gem::Specification\n")
	b.WriteString("name: " + name + "\n")
	b.WriteString("version: !ruby/object:Gem::Version\n  version: " + fixtureVersion + "\n")
	b.WriteString("platform: ruby\nauthors:\n- pkgscan-e2e\nautorequire:\nbindir: bin\ncert_chain: []\n")
	b.WriteString("date: 2024-01-02 00:00:00.000000000 Z\ndependencies: []\n")
	b.WriteString("description: pullthrough llm-package-scan e2e fixture\nemail:\nexecutables: []\n")
	b.WriteString("extensions: []\nextra_rdoc_files: []\nfiles:\n")
	for _, f := range files {
		b.WriteString("- " + f + "\n")
	}
	b.WriteString("homepage:\nlicenses:\n- MIT\nmetadata: {}\npost_install_message:\nrdoc_options: []\n")
	b.WriteString("require_paths:\n- lib\n")
	for _, req := range []string{"required_ruby_version", "required_rubygems_version"} {
		b.WriteString(req + ": !ruby/object:Gem::Requirement\n  requirements:\n  - - \">=\"\n    - !ruby/object:Gem::Version\n      version: '0'\n")
	}
	b.WriteString("requirements: []\nrubygems_version: 3.5.3\nsigning_key:\nspecification_version: 4\n")
	b.WriteString("summary: pullthrough llm-package-scan e2e fixture\ntest_files: []\n")
	return b.String()
}
