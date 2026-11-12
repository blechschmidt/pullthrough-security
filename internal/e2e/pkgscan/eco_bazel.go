//go:build integration
// +build integration

package pkgscan

import (
	"crypto/sha256"
	"encoding/base64"
)

// Bazel (Bzlmod) registry: a static tree. Bazel reads the registry's
// bazel_registry.json (its mirrors), a module's metadata.json (versions, yanked
// versions) and MODULE.bazel, then the version's source.json, which names the
// module's source archive — at an external URL, usually a GitHub release — with
// its Subresource-Integrity digest and the prefix to strip. The proxy rewrites
// source.json's "url" onto its synthetic ".../<version>/archive/<file>"
// endpoint; on a miss that endpoint re-reads source.json from the registry,
// fetches the archive from the URL it names and verifies it against the
// "integrity" before serving it.
//
// The source archive is the payload pulled here. MODULE.bazel is a payload too
// (a single Starlark file, examined on its own), so it is served by the stub
// but kept out of the preamble, which holds documents only.

func init() {
	register(eco{
		ID: "bazel", Type: "bazel", Title: "Bazel (Bzlmod registry)",
		Format:   "source archive (.tar.gz) behind source.json",
		Registry: bazelRegistry,
	})
}

func bazelRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	reg.mux.File("/bazel_registry.json", jsonDoc(map[string]any{"mirrors": []string{}}), "application/json")
	for _, s := range env.Specs {
		module := s.Name() // module names: lower-case letters, digits, '.', '_', '-'
		// A release archive holds one top-level directory, which source.json's
		// strip_prefix names.
		prefix := module + "-" + fixtureVersion
		root := prefix + "/"
		moduleFile := "module(\n    name = \"" + module + "\",\n    version = \"" + fixtureVersion + "\",\n    compatibility_level = 1,\n)\n"
		archive := tarGz(map[string]string{
			root + "MODULE.bazel": moduleFile,
			root + "BUILD.bazel":  "exports_files([\"defs.bzl\"])\n",
			root + "defs.bzl":     "def answer():\n    return 42\n",
			root + markerFile:     s.Text(""),
		})
		// The archive lives on the release host the module's source.json names.
		file := prefix + ".tar.gz"
		release := "/releases/download/v" + fixtureVersion + "/" + file
		reg.mux.File(release, archive, "application/gzip")

		base := "/modules/" + module + "/"
		reg.mux.File(base+"metadata.json", jsonDoc(map[string]any{
			"homepage":        "https://example.invalid/pte2e/" + module,
			"maintainers":     []map[string]string{{"name": "pkgscan e2e"}},
			"repository":      []string{"github:pte2e/" + module},
			"versions":        []string{fixtureVersion},
			"yanked_versions": map[string]string{},
		}), "application/json")
		reg.mux.File(base+fixtureVersion+"/MODULE.bazel", []byte(moduleFile), "text/plain")
		integrity := bazelIntegrity(archive)
		reg.mux.File(base+fixtureVersion+"/source.json", jsonDoc(map[string]any{
			"url":          env.URL + release,
			"integrity":    integrity,
			"strip_prefix": prefix,
		}), "application/json")

		// The endpoint the rewritten source.json names carries the archive's own
		// file name: Bazel picks the decompressor from it.
		archivePath := base + fixtureVersion + "/archive/" + file
		reg.add(s.Variant, &pkgPull{
			Name: module, Version: fixtureVersion,
			Preamble: []step{
				{Path: "/bazel_registry.json", Contains: []string{"mirrors"}},
				{Path: base + "metadata.json", Contains: []string{fixtureVersion}},
				// Bazel downloads the archive from source.json's "url": it must be the
				// proxy's archive endpoint, and the integrity Bazel checks it against
				// must be the registry's (the proxy re-encodes the document compactly).
				{Path: base + fixtureVersion + "/source.json", Contains: []string{
					`"url":"` + mountPlaceholder + archivePath + `"`,
					`"integrity":"` + integrity + `"`,
				}},
			},
			Payload: step{Path: archivePath},
			Body:    archive,
			Marker:  root + markerFile,
		})
	}
	return reg, nil
}

// bazelIntegrity is the Subresource-Integrity digest source.json records for
// an archive: "sha256-" and the standard base64 of the raw SHA-256.
func bazelIntegrity(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}
