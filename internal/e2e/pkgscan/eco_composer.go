//go:build integration
// +build integration

package pkgscan

import (
	"crypto/sha1"
	"encoding/hex"
)

// Composer 2 (Packagist): packages.json, the repository root, names the URL
// template of the per-package metadata ("metadata-url"), which the proxy
// rewrites onto itself. "/p2/<vendor>/<package>.json" lists a package's
// versions, each with the URL its dist archive is downloaded from — on
// Packagist a GitHub zipball, on another host — and the proxy rewrites every
// one of those onto its own dist endpoint,
// "/dist/<vendor>/<package>/<version>/<reference>.<type>". A dist request makes
// the backend read the metadata again, find exactly that version, reference
// and type, fetch the URL listed there and check the archive against the
// listed SHA-1 shasum.
//
// The archive is a zipball as GitHub generates it: every file under
// "<vendor>-<package>-<short reference>/". Packagist publishes no shasum for
// such an archive; a repository that builds its own archives (Satis, Private
// Packagist) does, and the stub does too, so the backend's verification runs.

func init() {
	register(eco{
		ID: "composer", Type: "composer", Title: "Composer (Packagist)",
		Format:   "dist archive (zipball, zip)",
		Registry: composerRegistry,
	})
}

// composerVendor is the vendor every fixture package is published under.
const composerVendor = "pte2e"

func composerRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	// The root of a Composer 2 repository. Of what Packagist's root holds, only
	// the metadata template matters to a client that installs; the proxy drops
	// the statistics endpoint ("notify-batch") rather than send a client's
	// install reports around it.
	reg.mux.File("/packages.json", jsonDoc(map[string]any{
		"packages":     []any{},
		"metadata-url": "/p2/%package%.json",
		"notify-batch": env.URL + "/downloads/",
	}), "application/json")
	for _, s := range env.Specs {
		pkg := s.Slug()
		name := composerVendor + "/" + pkg
		// A dist reference is the commit the archive was made from.
		ref := composerReference(s)
		root := composerVendor + "-" + pkg + "-" + ref[:7] + "/"
		zip := zipOf(
			member{Name: root + "composer.json", Data: string(jsonDoc(map[string]any{
				"name": name, "description": "pullthrough llm-package-scan e2e fixture", "type": "library",
				"license": "MIT", "autoload": map[string]any{"classmap": []string{"src/"}},
			}))},
			member{Name: root + "src/Fixture.php", Data: "<?php\n\nnamespace Pte2e;\n\nfinal class Fixture\n{\n    public static function answer(): int\n    {\n        return 42;\n    }\n}\n"},
			member{Name: root + markerFile, Data: s.Text("")},
		)
		// Where the upstream metadata says the archive is: the stub plays the
		// archive host (GitHub's API) as well as the repository.
		archive := "/repos/" + composerVendor + "/" + pkg + "/zipball/" + ref
		reg.mux.File(archive, zip, "application/zip")
		shasum := sha1.Sum(zip)
		reg.mux.File("/p2/"+name+".json", jsonDoc(map[string]any{
			"minified": "composer/2.0",
			"packages": map[string]any{name: []any{map[string]any{
				"name": name, "description": "pullthrough llm-package-scan e2e fixture",
				"version": fixtureVersion, "version_normalized": fixtureVersion + ".0",
				"license": []string{"MIT"}, "type": "library", "time": "2024-01-02T03:04:05+00:00",
				"dist": map[string]string{
					"type": "zip", "url": env.URL + archive, "reference": ref, "shasum": hex.EncodeToString(shasum[:]),
				},
				"autoload": map[string]any{"classmap": []string{"src/"}},
			}}},
		}), "application/json")

		dist := "/dist/" + name + "/" + fixtureVersion + "/" + ref + ".zip"
		reg.add(s.Variant, &pkgPull{
			Name: name, Version: fixtureVersion,
			// What `composer require` reads before it downloads: the root, then the
			// package's metadata at the URL the root's template names. Both must
			// keep the client on the proxy.
			Preamble: []step{
				{Path: "/packages.json", Contains: []string{mountPlaceholder + "/p2/%package%.json"}},
				{Path: "/p2/" + name + ".json", Contains: []string{mountPlaceholder + dist}},
			},
			Payload: step{Path: dist},
			Body:    zip,
			Marker:  root + markerFile,
		})
	}
	return reg, nil
}

// composerReference derives the dist reference — a 40-hex git commit id — of a
// fixture package, from its content token so that every package has its own.
func composerReference(s pkgSpec) string {
	sum := sha1.Sum([]byte("pkgscan-e2e composer reference\x00" + s.Token))
	return hex.EncodeToString(sum[:])
}
