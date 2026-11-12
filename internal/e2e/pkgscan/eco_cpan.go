//go:build integration
// +build integration

package pkgscan

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// CPAN: a mirror is a static tree. "modules/02packages.details.txt.gz" maps
// every module to the distribution that provides it, by the distribution's path
// below "authors/id/"; a distribution is
// "authors/id/<A>/<AB>/<AUTHOR>/<Dist>-<Version>.tar.gz", a gzip-compressed tar
// whose members sit under "<Dist>-<Version>/"; and every author directory holds
// a CHECKSUMS file — Perl source assigning each file in the directory its
// digests and size — against which the backend verifies a distribution before
// it caches or serves it. Nothing is rewritten.
//
// The stub's CHECKSUMS is unsigned, as CPAN::Checksums writes it for a mirror
// without a signing key; PAUSE clear-signs its own. The backend reads the
// digests and does not check a signature either way.

func init() {
	register(eco{
		ID: "cpan", Type: "cpan", Title: "CPAN (Perl)",
		Format:   "distribution (.tar.gz)",
		Registry: cpanRegistry,
	})
}

// cpanAuthor is the PAUSE id every fixture distribution is uploaded by, and
// cpanAuthorDir its directory: the id's first letter, first two letters, and
// the id itself.
const (
	cpanAuthor    = "PTE2E"
	cpanAuthorDir = "/authors/id/P/PT/" + cpanAuthor + "/"
)

func cpanRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	// The lines of 02packages and the entries of CHECKSUMS, one per distribution.
	var index, checksums []string
	for _, s := range env.Specs {
		// CPAN names a distribution after its main module, "::" spelled "-".
		module := cpanAuthor + "::" + strings.ToUpper(s.Slug()[:1]) + s.Slug()[1:]
		dist := strings.ReplaceAll(module, "::", "-")
		root := dist + "-" + fixtureVersion + "/"
		pm := "lib/" + strings.ReplaceAll(module, "::", "/") + ".pm"
		file := dist + "-" + fixtureVersion + ".tar.gz"
		tarball := tarGzOf(
			member{Name: root + "MANIFEST", Data: "MANIFEST\nMakefile.PL\n" + markerFile + "\n" + pm + "\n"},
			member{Name: root + "Makefile.PL", Data: "use strict;\nuse warnings;\nuse ExtUtils::MakeMaker;\n\nWriteMakefile(\n" +
				"    NAME         => '" + module + "',\n    VERSION_FROM => '" + pm + "',\n    LICENSE      => 'perl_5',\n);\n"},
			member{Name: root + markerFile, Data: s.Text("")},
			member{Name: root + pm, Data: "package " + module + ";\n\nuse strict;\nuse warnings;\n\nour $VERSION = '" + fixtureVersion + "';\n\nsub answer { return 42 }\n\n1;\n"},
		)
		reg.mux.File(cpanAuthorDir+file, tarball, "application/x-gzip")

		// The record CPAN::Checksums writes per file of the directory.
		md5sum := md5.Sum(tarball)
		checksums = append(checksums, fmt.Sprintf("  '%s' => {\n    'md5' => '%s',\n    'mtime' => '2024-01-02',\n    'sha256' => '%s',\n    'size' => %d\n  },\n",
			file, hex.EncodeToString(md5sum[:]), hexOf(tarball), len(tarball)))
		// 02packages: the module, its version, and the distribution's path below
		// authors/id/.
		index = append(index, fmt.Sprintf("%-30s %-8s %s\n", module, fixtureVersion, strings.TrimPrefix(cpanAuthorDir, "/authors/id/")+file))

		reg.add(s.Variant, &pkgPull{
			Name: dist, Version: fixtureVersion,
			Preamble: []step{
				// `cpanm --mirror <proxy> --mirror-only` looks the module up in the
				// master index (served compressed; nothing in it is rewritten).
				{Path: "/modules/02packages.details.txt.gz"},
				// CPAN.pm and `cpanm --verify` read the author directory's CHECKSUMS
				// to check the download against it: a document, to be served under
				// every fail mode like the index.
				{Path: cpanAuthorDir + "CHECKSUMS", Contains: []string{"'" + file + "' => {", "'sha256' => '" + hexOf(tarball) + "'"}},
			},
			Payload: step{Path: cpanAuthorDir + file},
			Body:    tarball,
			Marker:  root + markerFile,
		})
	}
	// Both documents are sorted: CHECKSUMS by file name (Data::Dumper with
	// Sortkeys), 02packages by package name.
	sort.Strings(checksums)
	sort.Strings(index)
	reg.mux.File(cpanAuthorDir+"CHECKSUMS", []byte(
		"# CHECKSUMS file written on Tue Jan  2 03:04:05 2024 GMT by CPAN::Checksums (v2.14)\n"+
			"$cksum = {\n"+strings.Join(checksums, "")+"};\n"), "text/plain")
	reg.mux.File("/modules/02packages.details.txt.gz", gzipOf([]byte(
		"File:         02packages.details.txt\n"+
			"URL:          http://www.perl.com/CPAN/modules/02packages.details.txt\n"+
			"Description:  Package names found in directory $CPAN/authors/id/\n"+
			"Columns:      package name, version, path\n"+
			"Intended-For: Automated fetch routines, namespace documentation.\n"+
			"Written-By:   PAUSE version 1.005\n"+
			fmt.Sprintf("Line-Count:   %d\n", len(env.Specs))+
			"Last-Updated: Tue, 02 Jan 2024 03:04:05 GMT\n\n"+
			strings.Join(index, ""))), "application/x-gzip")
	return reg, nil
}
