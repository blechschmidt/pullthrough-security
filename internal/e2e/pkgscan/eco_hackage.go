//go:build integration
// +build integration

package pkgscan

import (
	"crypto/md5"
	"encoding/hex"
)

// Hackage (secure repository, hackage-security): `cabal update` downloads the
// package index, "/01-index.tar.gz" — a tar holding every package version's
// .cabal description and its TUF target metadata (package.json, which pins the
// sdist's length and SHA-256) — and `cabal get <name>-<version>` then fetches
// the source distribution from "/package/<name>-<version>.tar.gz" and checks it
// against the index. The proxy serves the index as it is: an archive at a path
// where an archive is what belongs, which the package scan leaves alone. It
// verifies an sdist against the per-package target metadata,
// "/package/<name>-<version>/package.json", which it fetches itself. An sdist
// is a gzip-compressed tar whose members sit under "<name>-<version>/".

func init() {
	register(eco{
		ID: "hackage", Type: "hackage", Title: "Hackage (Haskell)",
		Format:   "source distribution (.tar.gz)",
		Registry: hackageRegistry,
	})
}

// hackageCabal is the package description of a fixture package.
func hackageCabal(name string) string {
	return "cabal-version:      2.4\nname:               " + name + "\nversion:            " + fixtureVersion + "\n" +
		"synopsis:           pullthrough llm-package-scan e2e fixture\nlicense:            MIT\n" +
		"build-type:         Simple\nextra-source-files: " + markerFile + "\n\n" +
		"library\n    exposed-modules:  PTE2E\n    hs-source-dirs:   src\n" +
		"    build-depends:    base >=4 && <5\n    default-language: Haskell2010\n"
}

// hackageMD5 returns the hex MD5 of b, which Hackage records next to the
// SHA-256 as mirroring metadata.
func hackageMD5(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

// hackageTargets is the TUF target metadata of an sdist, as Hackage keys it:
// by the sdist's repository path.
func hackageTargets(pkgid string, sdist []byte) []byte {
	return jsonDoc(map[string]any{
		"signed": map[string]any{
			"_type": "Targets", "version": 0, "expires": nil,
			"targets": map[string]any{
				"<repo>/package/" + pkgid + ".tar.gz": map[string]any{
					"length": len(sdist),
					"hashes": map[string]string{"md5": hackageMD5(sdist), "sha256": hexOf(sdist)},
				},
			},
		},
		"signatures": []any{},
	})
}

func hackageRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	var index []member
	for _, s := range env.Specs {
		name := s.Name() // Hackage names allow hyphens: "pte2e-<variant>"
		pkgid := name + "-" + fixtureVersion
		cabal := hackageCabal(name)
		sdist := tarGzOf(
			member{Name: pkgid + "/" + name + ".cabal", Data: cabal},
			member{Name: pkgid + "/src/PTE2E.hs", Data: "module PTE2E (answer) where\n\nanswer :: Int\nanswer = 42\n"},
			member{Name: pkgid + "/" + markerFile, Data: s.Text("")},
		)
		targets := hackageTargets(pkgid, sdist)
		sdistPath := "/package/" + pkgid + ".tar.gz" // hackage-security's layout
		reg.mux.File(sdistPath, sdist, "application/gzip")
		reg.mux.File("/package/"+pkgid+"/package.json", targets, "application/json")
		index = append(index,
			member{Name: name + "/" + fixtureVersion + "/" + name + ".cabal", Data: cabal},
			member{Name: name + "/" + fixtureVersion + "/package.json", Data: string(targets)},
		)

		reg.add(s.Variant, &pkgPull{
			Name: name, Version: fixtureVersion,
			// The index is metadata that is itself an archive; it must be served
			// whatever the package scan's fail mode. (It is gzip-compressed, so
			// there is no text to look for in the response.)
			Preamble: []step{{Path: "/01-index.tar.gz"}},
			Payload:  step{Path: sdistPath},
			Body:     sdist,
			Marker:   pkgid + "/" + markerFile,
		})
	}
	reg.mux.File("/01-index.tar.gz", tarGzOf(index...), "application/gzip")
	return reg, nil
}
