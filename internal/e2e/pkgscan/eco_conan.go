//go:build integration
// +build integration

package pkgscan

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// Conan 2 ("revisions" REST API, as ConanCenter/Artifactory serve it). For
// `conan install --requires=<name>/<version>` a client probes "/v1/ping" (and
// refuses a remote whose X-Conan-Server-Capabilities lacks "revisions"), asks
// for the recipe's latest revision, lists and downloads that revision's files
// (conanmanifest.txt, conanfile.py), computes the package_id of the binary it
// needs, asks for that package's latest revision, lists its files and downloads
// them: conanmanifest.txt, conaninfo.txt and conan_package.tgz.
//
// conan_package.tgz — the binary package, unpacked into the client's cache — is
// the payload pulled here; its members sit at the package root. conanfile.py is
// a payload of its own (Python the client runs, examined on its own), so the
// stub serves it but the preamble, which holds documents only, does not ask for
// it.
//
// Integrity: a revision's conanmanifest.txt lists the MD5 of every file in its
// unpacked form — conanfile.py and conaninfo.txt by name, the members of the
// archives, never the archives themselves. The proxy verifies a named file
// against the manifest and an archive against the X-Checksum-Md5 header the
// remote sends with it, as Artifactory does with every file.

func init() {
	register(eco{
		ID: "conan", Type: "conan", Title: "Conan",
		Format:   "binary package (conan_package.tgz)",
		Registry: conanRegistry,
	})
}

// conanTime is the revision time every fixture is published at, as the
// revision API spells it.
var conanTime = stubModTime.Format("2006-01-02T15:04:05.000-0700")

func conanRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	reg.mux.Handle("/v1/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Conan-Server-Capabilities", "revisions")
		w.WriteHeader(http.StatusOK)
	})
	for _, s := range env.Specs {
		name := s.Name() // Conan names: lower-case letters, digits, '_', '+', '.', '-'
		ident := strings.ReplaceAll(name, "-", "_")

		// The recipe revision.
		conanfile := "from conan import ConanFile\n\n\n" +
			"class Pte2eRecipe(ConanFile):\n" +
			"    name = \"" + name + "\"\n" +
			"    version = \"" + fixtureVersion + "\"\n" +
			"    settings = \"os\", \"arch\", \"compiler\", \"build_type\"\n"
		recipeManifest := conanManifest(map[string]string{"conanfile.py": conanfile})
		rrev := conanMD5(recipeManifest)

		// The binary package of one configuration. Its package_id is a hash of the
		// settings it was built with, which conaninfo.txt records.
		conaninfo := "[settings]\narch=x86_64\nbuild_type=Release\ncompiler=gcc\ncompiler.version=13\nos=Linux\n"
		pkgID := conanSHA1(conaninfo)
		packaged := map[string]string{
			"include/" + ident + ".h": "#pragma once\nint " + ident + "_answer(void);\n",
			"licenses/LICENSE":        "MIT License (pkgscan e2e fixture)\n",
			markerFile:                s.Text(""),
		}
		archive := tarGz(packaged)
		listed := map[string]string{"conaninfo.txt": conaninfo}
		for path, data := range packaged {
			listed[path] = data
		}
		packageManifest := conanManifest(listed)
		prev := conanMD5(packageManifest)

		ref := "/v2/conans/" + name + "/" + fixtureVersion + "/_/_"
		recipe := ref + "/revisions/" + rrev
		pkg := recipe + "/packages/" + pkgID
		binary := pkg + "/revisions/" + prev
		reg.mux.File(ref+"/latest", jsonDoc(map[string]string{"revision": rrev, "time": conanTime}), "application/json")
		reg.mux.File(recipe+"/files", jsonDoc(map[string]any{"files": map[string]any{"conanfile.py": map[string]any{}, "conanmanifest.txt": map[string]any{}}}), "application/json")
		conanFile(reg.mux, recipe+"/files/conanfile.py", []byte(conanfile))
		conanFile(reg.mux, recipe+"/files/conanmanifest.txt", []byte(recipeManifest))
		reg.mux.File(pkg+"/latest", jsonDoc(map[string]string{"revision": prev, "time": conanTime}), "application/json")
		reg.mux.File(binary+"/files", jsonDoc(map[string]any{"files": map[string]any{
			"conan_package.tgz": map[string]any{}, "conaninfo.txt": map[string]any{}, "conanmanifest.txt": map[string]any{},
		}}), "application/json")
		conanFile(reg.mux, binary+"/files/conanmanifest.txt", []byte(packageManifest))
		conanFile(reg.mux, binary+"/files/conaninfo.txt", []byte(conaninfo))
		conanFile(reg.mux, binary+"/files/conan_package.tgz", archive)

		reg.add(s.Variant, &pkgPull{
			Name: name, Version: fixtureVersion,
			Preamble: []step{
				{Path: "/v1/ping"},
				{Path: ref + "/latest", Contains: []string{rrev}},
				{Path: recipe + "/files", Contains: []string{"conanfile.py"}},
				{Path: recipe + "/files/conanmanifest.txt", Contains: []string{"conanfile.py: " + conanMD5(conanfile)}},
				{Path: pkg + "/latest", Contains: []string{prev}},
				{Path: binary + "/files", Contains: []string{"conan_package.tgz"}},
				{Path: binary + "/files/conanmanifest.txt", Contains: []string{"conaninfo.txt: " + conanMD5(conaninfo)}},
				{Path: binary + "/files/conaninfo.txt", Contains: []string{"[settings]"}},
			},
			Payload: step{Path: binary + "/files/conan_package.tgz"},
			Body:    archive,
			Marker:  markerFile,
		})
	}
	return reg, nil
}

// conanManifest renders a conanmanifest.txt: the time of the revision as a Unix
// timestamp, then "<path>: <md5>" for every file, in path order.
func conanManifest(files map[string]string) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var b strings.Builder
	b.WriteString(strconv.FormatInt(stubModTime.Unix(), 10) + "\n")
	for _, p := range paths {
		b.WriteString(p + ": " + conanMD5(files[p]) + "\n")
	}
	return b.String()
}

// conanFile serves a file of a revision the way an Artifactory remote does: with
// its digests in X-Checksum-* headers.
func conanFile(m *stubMux, path string, body []byte) {
	md5sum, sha1sum, sha256sum := md5.Sum(body), sha1.Sum(body), sha256.Sum256(body)
	contentType := "application/octet-stream"
	if strings.HasSuffix(path, ".txt") || strings.HasSuffix(path, ".py") {
		contentType = "text/plain"
	}
	m.Handle(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Checksum-Md5", hex.EncodeToString(md5sum[:]))
		w.Header().Set("X-Checksum-Sha1", hex.EncodeToString(sha1sum[:]))
		w.Header().Set("X-Checksum-Sha256", hex.EncodeToString(sha256sum[:]))
		w.Header().Set("Content-Type", contentType)
		http.ServeContent(w, r, "", stubModTime, bytes.NewReader(body))
	})
}

// conanMD5 returns the hex MD5 of s, the digest conanmanifest.txt records (and
// the form a revision takes).
func conanMD5(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// conanSHA1 returns the hex SHA-1 of s, the form a package_id takes.
func conanSHA1(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
