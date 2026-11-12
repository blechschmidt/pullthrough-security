//go:build integration
// +build integration

package pkgscan

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Conda: a channel is a static tree of subdirectories, one per platform plus
// "noarch". Each holds a repodata.json index, mapping every package file name
// in the subdir to its record — dependencies, and the sha256 and md5 of the
// file. A client fetches the index of its platform's subdir and of noarch,
// solves, and downloads the chosen file from the same subdir: the index names
// it relative to its own location, so it resolves against the proxy with no
// rewriting. The backend verifies a downloaded package against the sha256 its
// subdir's index declares.
//
// The package is the current format, ".conda": a zip whose members are stored,
// not deflated (they are compressed already), holding metadata.json and two
// zstd-compressed tarballs — pkg-<stem>.tar.zst, the files installed into the
// environment, and info-<stem>.tar.zst, the package's own metadata under info/.
// The scanner opens both tarballs in place and lists their members under the
// paths they install to.
//
// The proxy reports the name and version it reads from the file name,
// "<name>-<version>-<build>.conda".

func init() {
	register(eco{
		ID: "conda", Type: "conda", Title: "Conda",
		Format:   ".conda (zip: metadata.json, pkg-*.tar.zst, info-*.tar.zst)",
		Registry: condaRegistry,
	})
}

// condaBuild is the build string every fixture package is published as.
const condaBuild = "0"

func condaRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, fmt.Errorf("zstd encoder: %w", err)
	}
	defer enc.Close()

	records := map[string]any{}
	type pkg struct {
		spec pkgSpec
		file string
		data []byte
	}
	var pkgs []pkg
	for _, s := range env.Specs {
		name := s.Name()
		files := []member{
			{Name: "share/" + name + "/README", Data: "pullthrough pkgscan e2e fixture package\n"},
			{Name: "share/" + name + "/" + markerFile, Data: s.Text("")},
		}
		index := map[string]any{
			"name": name, "version": fixtureVersion, "build": condaBuild, "build_number": 0,
			"depends": []string{}, "license": "MIT", "noarch": "generic", "subdir": "noarch",
			"arch": nil, "platform": nil, "timestamp": stubModTime.UnixMilli(),
		}
		p := pkg{spec: s, file: name + "-" + fixtureVersion + "-" + condaBuild + ".conda"}
		p.data = condaPackage(enc, strings.TrimSuffix(p.file, ".conda"), index, files)
		reg.mux.File("/noarch/"+p.file, p.data, "application/octet-stream")
		pkgs = append(pkgs, p)

		record := map[string]any{"sha256": hexOf(p.data), "md5": condaMD5(p.data), "size": len(p.data)}
		for k, v := range index {
			record[k] = v
		}
		records[p.file] = record
	}
	noarch := jsonDoc(map[string]any{
		"info": map[string]any{"subdir": "noarch"}, "packages": map[string]any{},
		"packages.conda": records, "removed": []string{}, "repodata_version": 1,
	})
	reg.mux.File("/noarch/repodata.json", noarch, "application/json")
	// The platform subdir a linux-64 client reads alongside noarch: the fixture
	// has nothing built for it.
	reg.mux.File("/linux-64/repodata.json", jsonDoc(map[string]any{
		"info": map[string]any{"subdir": "linux-64"}, "packages": map[string]any{},
		"packages.conda": map[string]any{}, "removed": []string{}, "repodata_version": 1,
	}), "application/json")

	for _, p := range pkgs {
		reg.add(p.spec.Variant, &pkgPull{
			Name: p.spec.Name(), Version: fixtureVersion,
			// What `conda install -c <proxy>/v1/conda <name>` reads before it
			// downloads: the index of its platform's subdir and of noarch, which
			// names the file (relative to the subdir) and its digest.
			Preamble: []step{
				{Path: "/linux-64/repodata.json", Contains: []string{`"subdir": "linux-64"`}},
				{Path: "/noarch/repodata.json", Contains: []string{`"` + p.file + `": {`, `"sha256": "` + hexOf(p.data) + `"`}},
			},
			Payload: step{Path: "/noarch/" + p.file},
			Body:    p.data,
			Marker:  "share/" + p.spec.Name() + "/" + markerFile,
		})
	}
	return reg, nil
}

// condaPackage builds a .conda package: a zip of stored members — metadata.json
// (the format version), the pkg- tarball of the installed files and the info-
// tarball of info/index.json, info/paths.json and info/files, each tarball
// zstd-compressed. stem is the file name without ".conda".
func condaPackage(enc *zstd.Encoder, stem string, index map[string]any, files []member) []byte {
	files = append([]member(nil), files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	type pathEntry struct {
		Path   string `json:"_path"`
		Type   string `json:"path_type"`
		SHA256 string `json:"sha256"`
		Size   int    `json:"size_in_bytes"`
	}
	var paths []pathEntry
	var list strings.Builder
	for _, f := range files {
		paths = append(paths, pathEntry{Path: f.Name, Type: "hardlink", SHA256: hexOf([]byte(f.Data)), Size: len(f.Data)})
		list.WriteString(f.Name + "\n")
	}
	info := tarOf(
		member{Name: "info/files", Data: list.String()},
		member{Name: "info/index.json", Data: string(jsonDoc(index))},
		member{Name: "info/paths.json", Data: string(jsonDoc(map[string]any{"paths": paths, "paths_version": 1}))},
	)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range []member{
		{Name: "metadata.json", Data: `{"conda_pkg_format_version": 2}`},
		{Name: "pkg-" + stem + ".tar.zst", Data: string(enc.EncodeAll(tarOf(files...), nil))},
		{Name: "info-" + stem + ".tar.zst", Data: string(enc.EncodeAll(info, nil))},
	} {
		w, _ := zw.CreateHeader(&zip.FileHeader{Name: m.Name, Method: zip.Store, Modified: stubModTime})
		_, _ = io.WriteString(w, m.Data)
	}
	_ = zw.Close()
	return buf.Bytes()
}

// condaMD5 is the md5 a repodata record carries next to the sha256.
func condaMD5(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}
