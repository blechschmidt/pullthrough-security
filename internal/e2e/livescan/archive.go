package livescan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Builders of the artifacts a sample is served as. Every builder is
// deterministic — fixed timestamps, sorted members — so a sample's digest is
// the same on every run, and a stored verdict from an earlier run of the same
// corpus and model can be recognized in reports.

// fixedTime is every member's modification time: npm's own fixed date.
var fixedTime = time.Date(1985, 10, 26, 8, 15, 0, 0, time.UTC)

// fileMode is a member's mode: executable when the file starts with "#!".
func fileMode(data []byte) int64 {
	if bytes.HasPrefix(data, []byte("#!")) {
		return 0o755
	}
	return 0o644
}

// tarOf writes a tar stream of files under prefix, sorted by path.
func tarOf(prefix string, files map[string][]byte) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, p := range Paths(files) {
		data := files[p]
		hdr := &tar.Header{
			Name: prefix + p, Mode: fileMode(data), Size: int64(len(data)),
			ModTime: fixedTime, Typeflag: tar.TypeReg, Format: tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			panic(err)
		}
		if _, err := tw.Write(data); err != nil {
			panic(err)
		}
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// gzipOf compresses data deterministically.
func gzipOf(data []byte) []byte {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.ModTime = fixedTime
	if _, err := zw.Write(data); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// zipOf writes a zip of files in the given order (or sorted when order is
// nil).
func zipOf(files map[string][]byte, order []string) []byte {
	if order == nil {
		order = Paths(files)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range order {
		hdr := &zip.FileHeader{Name: p, Method: zip.Deflate, Modified: fixedTime}
		hdr.SetMode(0o644)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			panic(err)
		}
		if _, err := w.Write(files[p]); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// NPMTarball builds an npm package tarball: the tree under "package/".
func NPMTarball(tree map[string][]byte) []byte {
	return gzipOf(tarOf("package/", tree))
}

// NPMTarballName is the tarball file name npm gives a package version:
// "<name without scope>-<version>.tgz".
func NPMTarballName(name, version string) string {
	base := name
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	return base + "-" + version + ".tgz"
}

// WheelDist is a project's distribution name in file names (PEP 427): runs
// of "-", "_" and "." become "_".
func WheelDist(project string) string {
	var b strings.Builder
	prevSep := false
	for _, r := range project {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('_')
			}
			prevSep = true
			continue
		}
		prevSep = false
		b.WriteRune(r)
	}
	return b.String()
}

// WheelFileName is the wheel's file name for a pure-Python release.
func WheelFileName(project, version string) string {
	return WheelDist(project) + "-" + version + "-py3-none-any.whl"
}

// Wheel builds a pure-Python wheel of tree, adding the .dist-info files the
// tree does not already have (METADATA, WHEEL, top_level.txt) and a RECORD
// listing every file with its digest, as a real wheel's does.
func Wheel(project, version string, tree map[string][]byte) []byte {
	info := WheelDist(project) + "-" + version + ".dist-info/"
	files := make(map[string][]byte, len(tree)+4)
	for p, b := range tree {
		files[p] = b
	}
	if _, ok := files[info+"METADATA"]; !ok {
		files[info+"METADATA"] = []byte("Metadata-Version: 2.1\nName: " + project + "\nVersion: " + version + "\n")
	}
	if _, ok := files[info+"WHEEL"]; !ok {
		files[info+"WHEEL"] = []byte("Wheel-Version: 1.0\nGenerator: bdist_wheel (0.45.1)\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
	}
	if _, ok := files[info+"top_level.txt"]; !ok {
		tops := map[string]bool{}
		for p := range tree {
			if top, _, ok := strings.Cut(p, "/"); ok && !strings.HasSuffix(top, ".dist-info") {
				tops[top] = true
			}
		}
		var names []string
		for t := range tops {
			names = append(names, t)
		}
		sort.Strings(names)
		files[info+"top_level.txt"] = []byte(strings.Join(names, "\n") + "\n")
	}
	record := info + "RECORD"
	var rec strings.Builder
	for _, p := range Paths(files) {
		if p == record {
			continue
		}
		sum := sha256.Sum256(files[p])
		fmt.Fprintf(&rec, "%s,sha256=%s,%d\n", p, base64.RawURLEncoding.EncodeToString(sum[:]), len(files[p]))
	}
	rec.WriteString(record + ",,\n")
	files[record] = []byte(rec.String())
	// Package files first, .dist-info last, RECORD at the very end: the order
	// bdist_wheel writes.
	var order, dist []string
	for _, p := range Paths(files) {
		switch {
		case p == record:
		case strings.HasPrefix(p, info):
			dist = append(dist, p)
		default:
			order = append(order, p)
		}
	}
	order = append(append(order, dist...), record)
	return zipOf(files, order)
}

// Sdist builds a source distribution: the tree under "<name>-<version>/",
// with a PKG-INFO when the tree has none.
func Sdist(project, version string, tree map[string][]byte) []byte {
	files := make(map[string][]byte, len(tree)+1)
	for p, b := range tree {
		files[p] = b
	}
	if _, ok := files["PKG-INFO"]; !ok {
		files["PKG-INFO"] = []byte("Metadata-Version: 2.1\nName: " + project + "\nVersion: " + version + "\n")
	}
	return gzipOf(tarOf(WheelDist(project)+"-"+version+"/", files))
}

// SdistFileName is a source distribution's file name.
func SdistFileName(project, version string) string {
	return WheelDist(project) + "-" + version + ".tar.gz"
}

// Tarball builds a release tarball: the tree under "<dir>/".
func Tarball(dir string, tree map[string][]byte) []byte {
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	return gzipOf(tarOf(prefix, tree))
}

// OCIImage is a container image: one layer, its config and its manifest.
type OCIImage struct {
	Layer, Config, Manifest []byte
}

// Media types of a Docker image.
const (
	MediaDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	MediaDockerConfig   = "application/vnd.docker.container.image.v1+json"
	MediaDockerLayer    = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

// Digest is "sha256:<hex>" of b.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BuildImage builds a single-layer image of tree (paths relative to the
// root filesystem) with the sample's image configuration.
func BuildImage(tree map[string][]byte, meta *ImageMeta) OCIImage {
	layerTar := tarOf("", tree)
	layer := gzipOf(layerTar)
	cfg := map[string]any{}
	if meta != nil {
		if len(meta.Entrypoint) > 0 {
			cfg["Entrypoint"] = meta.Entrypoint
		}
		if len(meta.Cmd) > 0 {
			cfg["Cmd"] = meta.Cmd
		}
		if len(meta.Env) > 0 {
			cfg["Env"] = meta.Env
		}
		if meta.WorkingDir != "" {
			cfg["WorkingDir"] = meta.WorkingDir
		}
		if meta.User != "" {
			cfg["User"] = meta.User
		}
	}
	var history []map[string]any
	if meta != nil {
		for _, h := range meta.History {
			history = append(history, map[string]any{"created": "2026-01-01T00:00:00Z", "created_by": h})
		}
	}
	config := mustJSON(map[string]any{
		"architecture": "amd64",
		"os":           "linux",
		"config":       cfg,
		"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{Digest(layerTar)}},
		"history":      history,
	})
	manifest := mustJSON(map[string]any{
		"schemaVersion": 2,
		"mediaType":     MediaDockerManifest,
		"config":        map[string]any{"mediaType": MediaDockerConfig, "size": len(config), "digest": Digest(config)},
		"layers":        []map[string]any{{"mediaType": MediaDockerLayer, "size": len(layer), "digest": Digest(layer)}},
	})
	return OCIImage{Layer: layer, Config: config, Manifest: manifest}
}

// VSIX builds a VS Code extension archive: the tree (paths below
// "extension/") plus the VSIX manifest and content-types part `vsce`
// writes.
func VSIX(publisher, name, version string, tree map[string][]byte) []byte {
	files := map[string][]byte{}
	for p, b := range tree {
		files["extension/"+p] = b
	}
	files["extension.vsixmanifest"] = []byte(`<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="` + name + `" Version="` + version + `" Publisher="` + publisher + `" />
    <DisplayName>` + name + `</DisplayName>
    <Categories>Other</Categories>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="^1.80.0" />
    </Properties>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code"/>
  </Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />
  </Assets>
</PackageManifest>
`)
	files["[Content_Types].xml"] = []byte(`<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension=".json" ContentType="application/json"/><Default Extension=".js" ContentType="application/javascript"/><Default Extension=".md" ContentType="text/markdown"/><Default Extension=".vsixmanifest" ContentType="text/xml"/></Types>
`)
	order := []string{"extension.vsixmanifest", "[Content_Types].xml"}
	for _, p := range Paths(files) {
		if p != "extension.vsixmanifest" && p != "[Content_Types].xml" {
			order = append(order, p)
		}
	}
	return zipOf(files, order)
}

// sha1Hex is the hex SHA-1 of b: an npm packument's dist.shasum.
func sha1Hex(b []byte) string {
	sum := sha1.Sum(b)
	return hex.EncodeToString(sum[:])
}

// npmIntegrity is the Subresource Integrity string of b: an npm packument's
// dist.integrity.
func npmIntegrity(b []byte) string {
	sum := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
