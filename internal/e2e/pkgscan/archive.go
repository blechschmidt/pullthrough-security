//go:build integration
// +build integration

package pkgscan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"sort"
)

// The stub registries build their packages member by member, in the format the
// ecosystem ships. These are the building blocks; a format only one ecosystem
// uses (a .deb, an .rpm, a NAR) is written in that ecosystem's file.

// member is one file of an archive.
type member struct {
	Name string
	Data string
	// Mode is the file mode (0644 when zero).
	Mode int64
}

// sortedMembers turns a path -> content map into members in path order, so an
// archive built from a map is deterministic.
func sortedMembers(files map[string]string) []member {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]member, 0, len(names))
	for _, n := range names {
		out = append(out, member{Name: n, Data: files[n]})
	}
	return out
}

// tarOf builds an uncompressed tar holding members in the given order.
func tarOf(members ...member) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range members {
		mode := m.Mode
		if mode == 0 {
			mode = 0o644
		}
		_ = tw.WriteHeader(&tar.Header{Name: m.Name, Mode: mode, Size: int64(len(m.Data)), Typeflag: tar.TypeReg, ModTime: stubModTime})
		_, _ = io.WriteString(tw, m.Data)
	}
	_ = tw.Close()
	return buf.Bytes()
}

// gzipOf compresses data with gzip. The header carries no name and a fixed
// time, so equal input gives equal output.
func gzipOf(data []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

// tarGzOf builds a gzip-compressed tar holding members in the given order.
func tarGzOf(members ...member) []byte { return gzipOf(tarOf(members...)) }

// tarGz builds a gzip-compressed tar from a path -> content map, in path order.
func tarGz(files map[string]string) []byte { return tarGzOf(sortedMembers(files)...) }

// zipOf builds a zip archive holding members in the given order.
func zipOf(members ...member) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range members {
		hdr := &zip.FileHeader{Name: m.Name, Method: zip.Deflate, Modified: stubModTime}
		w, _ := zw.CreateHeader(hdr)
		_, _ = io.WriteString(w, m.Data)
	}
	_ = zw.Close()
	return buf.Bytes()
}

// zipFiles builds a zip archive from a path -> content map, in path order.
func zipFiles(files map[string]string) []byte { return zipOf(sortedMembers(files)...) }

// jsonDoc renders v as an indented JSON document.
func jsonDoc(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic("pkgscan: rendering a fixture document: " + err.Error())
	}
	return append(b, '\n')
}
