//go:build integration
// +build integration

package pkgscan

import (
	"archive/tar"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// APT (Debian / Ubuntu): a repository is a tree rooted at a signed Release
// file. A client configured with
//
//	deb [signed-by=<key>] <proxy>/v1/<name> stable main
//
// fetches dists/stable/InRelease — the Release file, clearsigned —, takes from
// its SHA256 table the digest of the package index it needs
// (dists/stable/main/binary-amd64/Packages.gz), and from that index's stanza
// for a package the Filename — a pool path relative to the repository root, so
// it resolves against the proxy with no rewriting — and the SHA256 of the .deb,
// which it then downloads from the pool. The backend follows the same chain:
// it verifies InRelease against the pinned key, the index against InRelease,
// and the .deb against the index.
//
// A .deb is an ar archive of three members, in this order: debian-binary
// ("2.0\n"), control.tar.gz — the control file, and any maintainer scripts dpkg
// runs as root (this fixture has none) — and data.tar.gz, the files dpkg
// installs. The scanner lists the control members under DEBIAN/ and the data
// members under their install paths, without the leading "./".
//
// The proxy reports the name and version it reads from the pool file name,
// "<name>_<version>_<arch>.deb".

func init() {
	apt := eco{
		ID: "apt", Type: "apt", Title: "APT (Debian / Ubuntu)",
		Format:   ".deb (ar: debian-binary, control.tar.gz, data.tar.gz)",
		Settings: osRepoSettings,
		Registry: aptRegistry,
	}
	register(apt)
	register(alias(apt, "deb"))
}

// The repository layout the stub publishes.
const (
	aptSuite     = "stable"
	aptComponent = "main"
	aptArch      = "amd64"
	// aptIndex is the package index, relative to dists/<suite>/: what Release
	// lists and the backend verifies against it. Architecture: all packages are
	// listed in every binary-<arch> index, as in the Debian archive.
	aptIndex = aptComponent + "/binary-" + aptArch + "/Packages"
)

func aptRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	type pool struct {
		spec pkgSpec
		path string // relative to the repository root, as the index names it
		deb  []byte
	}
	var debs []pool
	var index strings.Builder
	for _, s := range env.Specs {
		name := s.Name()
		file := name + "_" + fixtureVersion + "_all.deb"
		p := pool{spec: s, path: "pool/" + aptComponent + "/" + name[:1] + "/" + name + "/" + file}
		control := aptControl(name)
		p.deb = debPackage(control, []member{
			{Name: "usr/share/doc/" + name + "/copyright", Data: "Files: *\nCopyright: pullthrough pkgscan e2e\nLicense: MIT\n"},
			{Name: "usr/share/" + name + "/" + markerFile, Data: s.Text("")},
		})
		reg.mux.File("/"+p.path, p.deb, "application/vnd.debian.binary-package")
		debs = append(debs, p)

		// The index stanza: the control file's fields, where the package is and
		// what it hashes to (as dpkg-scanpackages writes it), the description last.
		fields, description, _ := strings.Cut(control, "Description:")
		md5sum := md5.Sum(p.deb)
		fmt.Fprintf(&index, "%sFilename: %s\nSize: %d\nMD5sum: %s\nSHA256: %s\nDescription:%s\n",
			fields, p.path, len(p.deb), hex.EncodeToString(md5sum[:]), hexOf(p.deb), description)
	}

	packages := []byte(index.String())
	packagesGz := osRepoGzipStored(packages)
	dists := "/dists/" + aptSuite + "/"
	reg.mux.File(dists+aptIndex, packages, "text/plain")
	reg.mux.File(dists+aptIndex+".gz", packagesGz, "application/gzip")

	release := []byte(strings.Join([]string{
		"Origin: pullthrough-pkgscan-e2e",
		"Label: pullthrough-pkgscan-e2e",
		"Suite: " + aptSuite,
		"Codename: pte2e",
		"Date: " + stubModTime.Format("Mon, 02 Jan 2006 15:04:05 UTC"),
		"Architectures: " + aptArch,
		"Components: " + aptComponent,
		"Description: stub repository of the pullthrough llm-package-scan e2e suite",
		"SHA256:",
		aptReleaseEntry(aptIndex, packages),
		aptReleaseEntry(aptIndex+".gz", packagesGz),
	}, "\n") + "\n")
	inRelease, err := osRepoClearsign(release)
	if err != nil {
		return nil, fmt.Errorf("clearsigning Release: %w", err)
	}
	releaseSig, err := osRepoDetachSign(release)
	if err != nil {
		return nil, fmt.Errorf("signing Release: %w", err)
	}
	// InRelease is what apt asks for; Release and Release.gpg are its older,
	// two-file form, which an archive publishes alongside.
	reg.mux.File(dists+"InRelease", inRelease, "text/plain")
	reg.mux.File(dists+"Release", release, "text/plain")
	reg.mux.File(dists+"Release.gpg", releaseSig, "application/pgp-signature")

	for _, p := range debs {
		name := p.spec.Name()
		reg.add(p.spec.Variant, &pkgPull{
			Name: name, Version: fixtureVersion,
			// What `apt-get update && apt-get install <name>` asks the repository for.
			Preamble: []step{
				// The signed Release, which pins the index's digest.
				{Path: dists + "InRelease", Contains: []string{"-----BEGIN PGP SIGNED MESSAGE-----", aptReleaseEntry(aptIndex+".gz", packagesGz)}},
				// The index: where the package is, relative to the repository root
				// the client was pointed at (the proxy), and its digest.
				{Path: dists + aptIndex + ".gz", Contains: []string{"Filename: " + p.path + "\n", "SHA256: " + hexOf(p.deb) + "\n"}},
			},
			Payload: step{Path: "/" + p.path},
			Body:    p.deb,
			Marker:  "usr/share/" + name + "/" + markerFile,
		})
	}
	return reg, nil
}

// aptControl is a package's control file.
func aptControl(name string) string {
	return "Package: " + name + "\n" +
		"Version: " + fixtureVersion + "\n" +
		"Architecture: all\n" +
		"Maintainer: pullthrough pkgscan e2e <pkgscan-e2e@example.invalid>\n" +
		"Installed-Size: 1\n" +
		"Section: misc\n" +
		"Priority: optional\n" +
		"Description: pullthrough llm-package-scan e2e fixture\n" +
		" A package the end-to-end suite of the LLM package-content scan pulls\n" +
		" through the proxy.\n"
}

// aptReleaseEntry is the line of a Release file's SHA256 table for one index
// file: digest, size, path below dists/<suite>/.
func aptReleaseEntry(rel string, data []byte) string {
	return fmt.Sprintf(" %s %d %s", hexOf(data), len(data), rel)
}

// debPackage builds a binary package the way dpkg-deb lays one out: an ar
// archive of debian-binary, control.tar.gz (the control file and the md5sums
// of the installed files) and data.tar.gz, in that order. files are the
// installed files, by install path without the leading "/".
func debPackage(control string, files []member) []byte {
	var md5sums strings.Builder
	for _, f := range files {
		sum := md5.Sum([]byte(f.Data))
		fmt.Fprintf(&md5sums, "%s  %s\n", hex.EncodeToString(sum[:]), f.Name)
	}
	controlTar := debTar([]member{
		{Name: "control", Data: control},
		{Name: "md5sums", Data: md5sums.String()},
	})
	return debAr(
		member{Name: "debian-binary", Data: "2.0\n"},
		member{Name: "control.tar.gz", Data: string(gzipOf(controlTar))},
		member{Name: "data.tar.gz", Data: string(gzipOf(debTar(files)))},
	)
}

// debTar builds a tar the way dpkg-deb does: every path behind "./", each
// directory as an entry of its own ahead of what it holds, sorted, owned by
// root.
func debTar(files []member) []byte {
	byName := map[string]member{}
	dirs := map[string]bool{"./": true}
	for _, f := range files {
		byName["./"+f.Name] = f
		for d := path.Dir(f.Name); d != "."; d = path.Dir(d) {
			dirs["./"+d+"/"] = true
		}
	}
	names := make([]string, 0, len(byName)+len(dirs))
	for n := range byName {
		names = append(names, n)
	}
	for d := range dirs {
		names = append(names, d)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		hdr := &tar.Header{Name: n, Uname: "root", Gname: "root", ModTime: stubModTime}
		f, isFile := byName[n]
		if isFile {
			hdr.Typeflag, hdr.Mode, hdr.Size = tar.TypeReg, f.Mode, int64(len(f.Data))
			if hdr.Mode == 0 {
				hdr.Mode = 0o644
			}
		} else {
			hdr.Typeflag, hdr.Mode = tar.TypeDir, 0o755
		}
		_ = tw.WriteHeader(hdr)
		if isFile {
			_, _ = io.WriteString(tw, f.Data)
		}
	}
	_ = tw.Close()
	return buf.Bytes()
}

// debAr writes a Unix ar archive the way dpkg-deb does: the global magic, then
// each member behind a 60-byte header of space-padded ASCII fields — name (16),
// modification time (12), owner (6), group (6), octal mode (8), size (10) and
// the terminator "`\n" — its data padded to an even length with a newline.
func debAr(members ...member) []byte {
	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")
	for _, m := range members {
		fmt.Fprintf(&buf, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", m.Name, stubModTime.Unix(), 0, 0, 0o100644, len(m.Data))
		buf.WriteString(m.Data)
		if len(m.Data)%2 == 1 {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}
