//go:build integration
// +build integration

package pkgscan

import (
	"crypto/md5"
	"encoding/hex"
	"sort"
	"strings"
)

// CRAN: a repository is a static tree. "src/contrib/PACKAGES" is a
// Debian-control file with one stanza per package — its version and the MD5 of
// its tarball among the fields — and "src/contrib/<pkg>_<version>.tar.gz" is
// the source package, a gzip-compressed tar whose members sit under "<pkg>/",
// as `R CMD build` writes it. The backend reads the sibling PACKAGES itself to
// verify a tarball's MD5. Nothing is rewritten.
//
// install.packages() asks for the index as PACKAGES.rds, then PACKAGES.gz, then
// PACKAGES, and reads the first one the repository has. The stub publishes the
// plain index only — the one the backend verifies against — so that is the
// document a client reads here.

func init() {
	register(eco{
		ID: "cran", Type: "cran", Title: "CRAN (R)",
		Format:   "source package (.tar.gz)",
		Registry: cranRegistry,
	})
}

func cranRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	var stanzas []string
	for _, s := range env.Specs {
		// An R package name is letters, digits and dots: no hyphen, no underscore
		// (the underscore separates name and version in the file name).
		name := "pte2e." + s.Slug()
		root := name + "/"
		description := "Package: " + name + "\nType: Package\nTitle: Pullthrough LLM Package-Scan E2E Fixture\n" +
			"Version: " + fixtureVersion + "\nAuthor: pkgscan e2e [aut, cre]\nMaintainer: pkgscan e2e <e2e@example.test>\n" +
			"Description: A fixture package served by the pullthrough package-scan e2e suite.\n" +
			"License: CC0\nEncoding: UTF-8\nNeedsCompilation: no\nPackaged: 2024-01-02 03:04:05 UTC; pkgscan\n"
		tarball := tarGzOf(
			member{Name: root + "DESCRIPTION", Data: description},
			member{Name: root + "NAMESPACE", Data: "export(answer)\n"},
			member{Name: root + "R/answer.R", Data: "answer <- function() 42\n"},
			// Files under inst/ are installed into the package's directory as they are.
			member{Name: root + "inst/" + markerFile, Data: s.Text("")},
		)
		file := name + "_" + fixtureVersion + ".tar.gz"
		reg.mux.File("/src/contrib/"+file, tarball, "application/x-gzip")
		md5sum := md5.Sum(tarball)
		stanza := "Package: " + name + "\nVersion: " + fixtureVersion + "\nLicense: CC0\n" +
			"MD5sum: " + hex.EncodeToString(md5sum[:]) + "\nNeedsCompilation: no\n"
		stanzas = append(stanzas, stanza)

		reg.add(s.Variant, &pkgPull{
			Name: name, Version: fixtureVersion,
			Preamble: []step{{Path: "/src/contrib/PACKAGES", Contains: []string{stanza}}},
			Payload:  step{Path: "/src/contrib/" + file},
			Body:     tarball,
			Marker:   root + "inst/" + markerFile,
		})
	}
	// write_PACKAGES orders the stanzas by package name and separates them by a
	// blank line.
	sort.Strings(stanzas)
	reg.mux.File("/src/contrib/PACKAGES", []byte(strings.Join(stanzas, "\n")), "text/plain; charset=utf-8")
	return reg, nil
}
