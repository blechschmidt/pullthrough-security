package contentscan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"io/fs"
	"sort"
	"strings"
	"testing"
)

// The exported walker is the unpacker an LLM gate hands an attacker-supplied
// archive to, so each bound and each "is this a file?" decision is pinned here.

// tarEntry is one member of a hand-built tar.
type tarEntry struct {
	name     string
	typeflag byte
	data     []byte
	linkname string
}

func tarGzEntries(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: e.typeflag, Linkname: e.linkname, Size: int64(len(e.data))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %q: %v", e.name, err)
		}
		if len(e.data) > 0 {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatalf("tar write %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// walked collects a WalkArchive run.
type walked struct {
	files map[string]ArchiveEntry
	order []string
	links []ArchiveLink
	stats ArchiveStats
	err   error
}

func walk(ctx context.Context, archive []byte, lim ArchiveLimits) walked {
	w := walked{files: map[string]ArchiveEntry{}}
	w.stats, w.err = WalkArchive(ctx, bytes.NewReader(archive), lim,
		func(e ArchiveEntry) bool {
			w.files[e.Name] = e
			w.order = append(w.order, e.Name)
			return true
		},
		func(l ArchiveLink) { w.links = append(w.links, l) })
	return w
}

func generous() ArchiveLimits {
	return ArchiveLimits{
		MaxArchiveBytes:     64 << 20,
		MaxUnpackedBytes:    256 << 20,
		MaxFileBytes:        1 << 20,
		MaxFiles:            10000,
		MaxCompressionRatio: 200,
	}
}

func hasReason(s ArchiveStats, reason string) bool {
	for _, r := range s.Incomplete {
		if r == reason {
			return true
		}
	}
	return false
}

func TestWalkArchiveFormats(t *testing.T) {
	files := map[string][]byte{"pkg/a.txt": []byte("alpha"), "pkg/b/c.txt": []byte("charlie")}
	for format, archive := range map[string][]byte{
		"tar.gz": tarGz(t, files),
		"tar":    rawTar(t, files),
		"zip":    zipBytes(t, files),
	} {
		w := walk(context.Background(), archive, generous())
		if w.err != nil {
			t.Fatalf("%s: %v", format, w.err)
		}
		if w.stats.Format != format {
			t.Errorf("%s: detected format %q", format, w.stats.Format)
		}
		if !w.stats.Complete() || w.stats.Files != 2 {
			t.Errorf("%s: stats = %+v, want a complete walk of 2 files", format, w.stats)
		}
		if string(w.files["pkg/a.txt"].Data) != "alpha" || string(w.files["pkg/b/c.txt"].Data) != "charlie" {
			t.Errorf("%s: files = %v", format, w.order)
		}
		if w.files["pkg/a.txt"].Size != 5 || w.files["pkg/a.txt"].Truncated {
			t.Errorf("%s: entry = %+v", format, w.files["pkg/a.txt"])
		}
		if w.stats.CompressedBytes <= 0 {
			t.Errorf("%s: compressed bytes not counted", format)
		}
	}
}

func TestWalkArchiveUnrecognized(t *testing.T) {
	w := walk(context.Background(), []byte{0xff, 0xfe, 0x01, 0x02, 0x03, 0x04}, generous())
	if !errors.Is(w.err, ErrUnrecognizedArchive) {
		t.Fatalf("err = %v, want ErrUnrecognizedArchive", w.err)
	}
	// Printable text is a tar candidate that the tar reader then rejects.
	w = walk(context.Background(), []byte("definitely not an archive, just prose"), generous())
	if w.err == nil || len(w.files) != 0 {
		t.Fatalf("prose must not walk as an archive (err %v, files %v)", w.err, w.order)
	}
}

func TestWalkArchiveNamesArePassedThroughNotSanitized(t *testing.T) {
	// The walker extracts nothing to disk; a traversal name is evidence for the
	// consumer and must not be silently rewritten or dropped.
	archive := tarGzEntries(t, []tarEntry{
		{name: "../../etc/cron.d/evil", typeflag: tar.TypeReg, data: []byte("x")},
		{name: "/abs/path", typeflag: tar.TypeReg, data: []byte("y")},
		{name: "./pkg/./ok.txt", typeflag: tar.TypeReg, data: []byte("z")},
	})
	w := walk(context.Background(), archive, generous())
	if w.err != nil {
		t.Fatal(w.err)
	}
	for _, want := range []string{"../../etc/cron.d/evil", "/abs/path", "pkg/ok.txt"} {
		if _, ok := w.files[want]; !ok {
			t.Errorf("missing entry %q (got %v)", want, w.order)
		}
	}
}

func TestWalkArchiveVisitsEveryDataBearingTarType(t *testing.T) {
	// A contiguous file ('7') and an undefined type flag are written out as
	// regular files by real extractors, so the walker must read them too;
	// otherwise a payload could be installed that the scanner never saw.
	archive := tarGzEntries(t, []tarEntry{
		{name: "pkg/regular.py", typeflag: tar.TypeReg, data: []byte("print(1)")},
		{name: "pkg/contiguous.py", typeflag: tar.TypeCont, data: []byte("import os")},
		{name: "pkg/unknown.py", typeflag: 'Z', data: []byte("os.system('x')")},
		{name: "pkg/dir/", typeflag: tar.TypeDir},
		{name: "pkg/link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
		{name: "pkg/hard", typeflag: tar.TypeLink, linkname: "pkg/regular.py"},
		{name: "pkg/fifo", typeflag: tar.TypeFifo},
	})
	w := walk(context.Background(), archive, generous())
	if w.err != nil {
		t.Fatal(w.err)
	}
	sort.Strings(w.order)
	if got, want := strings.Join(w.order, ","), "pkg/contiguous.py,pkg/regular.py,pkg/unknown.py"; got != want {
		t.Errorf("visited %s, want %s", got, want)
	}
	if string(w.files["pkg/unknown.py"].Data) != "os.system('x')" {
		t.Errorf("unknown-type entry data = %q", w.files["pkg/unknown.py"].Data)
	}
	if len(w.links) != 2 {
		t.Fatalf("links = %+v, want the symlink and the hard link", w.links)
	}
	if w.links[0].Name != "pkg/link" || w.links[0].Target != "/etc/passwd" || w.links[0].Hard {
		t.Errorf("symlink = %+v", w.links[0])
	}
	if w.links[1].Name != "pkg/hard" || !w.links[1].Hard {
		t.Errorf("hard link = %+v", w.links[1])
	}
	if w.stats.Links != 2 || w.stats.Others != 1 || w.stats.Files != 3 {
		t.Errorf("stats = %+v", w.stats)
	}
}

// zipWithModes builds a zip whose members carry the given unix mode bits.
func zipWithModes(t *testing.T, members []struct {
	name string
	mode fs.FileMode
	data string
}) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range members {
		hdr := &zip.FileHeader{Name: m.name, Method: zip.Deflate}
		hdr.SetMode(m.mode)
		// SetMode appends a slash-less directory bit only; keep the name as given.
		hdr.Name = m.name
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("zip header %q: %v", m.name, err)
		}
		if _, err := io.WriteString(w, m.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestWalkArchiveZipModeBitsDoNotHideFiles(t *testing.T) {
	// The mode bits in a zip are attacker-controlled metadata. pip writes any
	// member without a trailing slash out as a regular file, so a payload
	// labelled "directory", "symlink" or "fifo" must still be read.
	archive := zipWithModes(t, []struct {
		name string
		mode fs.FileMode
		data string
	}{
		{"pkg/plain.py", 0o644, "print(1)"},
		{"pkg/claims_dir.py", fs.ModeDir | 0o755, "import os; os.system('a')"},
		{"pkg/claims_symlink.py", fs.ModeSymlink | 0o777, "import os; os.system('b')"},
		{"pkg/claims_fifo.py", fs.ModeNamedPipe | 0o644, "import os; os.system('c')"},
		{"pkg/realdir/", fs.ModeDir | 0o755, ""},
	})
	w := walk(context.Background(), archive, generous())
	if w.err != nil {
		t.Fatal(w.err)
	}
	for _, name := range []string{"pkg/plain.py", "pkg/claims_dir.py", "pkg/claims_symlink.py", "pkg/claims_fifo.py"} {
		e, ok := w.files[name]
		if !ok {
			t.Errorf("member %q was not visited (got %v)", name, w.order)
			continue
		}
		if len(e.Data) == 0 {
			t.Errorf("member %q was visited without its content", name)
		}
	}
	if _, ok := w.files["pkg/realdir"]; ok {
		t.Error("a trailing-slash member is a directory and must not be visited")
	}
	// The symlink-typed member is also reported as a link, target = its content.
	if len(w.links) != 1 || w.links[0].Name != "pkg/claims_symlink.py" || !strings.Contains(w.links[0].Target, "os.system('b')") {
		t.Errorf("links = %+v", w.links)
	}
}

func TestWalkArchivePerFileCap(t *testing.T) {
	big := bytes.Repeat([]byte("A"), 5000)
	lim := generous()
	lim.MaxFileBytes = 1000
	w := walk(context.Background(), tarGz(t, map[string][]byte{"pkg/big.txt": big, "pkg/small.txt": []byte("s")}), lim)
	if w.err != nil {
		t.Fatal(w.err)
	}
	e := w.files["pkg/big.txt"]
	if len(e.Data) != 1000 || !e.Truncated || e.Size != 5000 {
		t.Errorf("big entry = len %d truncated %v size %d", len(e.Data), e.Truncated, e.Size)
	}
	if w.files["pkg/small.txt"].Truncated {
		t.Error("small entry must not be flagged truncated")
	}
	if !hasReason(w.stats, IncompleteFileBytes) || w.stats.Complete() {
		t.Errorf("stats = %+v, want %s", w.stats, IncompleteFileBytes)
	}
}

func TestWalkArchiveEntryCountGuard(t *testing.T) {
	files := map[string][]byte{}
	for i := 0; i < 40; i++ {
		files["pkg/f"+itoa(i)] = []byte("x")
	}
	lim := generous()
	lim.MaxFiles = 10
	for format, archive := range map[string][]byte{"tar.gz": tarGz(t, files), "zip": zipBytes(t, files)} {
		w := walk(context.Background(), archive, lim)
		if w.err != nil {
			t.Fatalf("%s: %v", format, w.err)
		}
		if w.stats.Files != 10 || !hasReason(w.stats, IncompleteFiles) {
			t.Errorf("%s: stats = %+v, want 10 files and %s", format, w.stats, IncompleteFiles)
		}
	}

	// Directories count against the guard too: a flood of empty directories is
	// cut off just like a flood of files.
	var entries []tarEntry
	for i := 0; i < 50; i++ {
		entries = append(entries, tarEntry{name: "d" + itoa(i) + "/", typeflag: tar.TypeDir})
	}
	entries = append(entries, tarEntry{name: "after.txt", typeflag: tar.TypeReg, data: []byte("x")})
	w := walk(context.Background(), tarGzEntries(t, entries), lim)
	if _, ok := w.files["after.txt"]; ok || !hasReason(w.stats, IncompleteFiles) {
		t.Errorf("directory flood not cut off: files %v stats %+v", w.order, w.stats)
	}
}

func TestWalkArchiveEntryCountGuardSpansNestedArchives(t *testing.T) {
	inner := map[string][]byte{}
	for i := 0; i < 30; i++ {
		inner["lib/f"+itoa(i)+".rb"] = []byte("puts 1\n")
	}
	lim := generous()
	lim.MaxFiles = 12
	w := walk(context.Background(), gemBytes(t, inner), lim)
	if w.err != nil {
		t.Fatal(w.err)
	}
	if !hasReason(w.stats, IncompleteFiles) {
		t.Fatalf("stats = %+v, want the guard to trip across the nested payload", w.stats)
	}
	if w.stats.Files > 12 {
		t.Errorf("visited %d files, more than the cap of 12", w.stats.Files)
	}
}

func TestWalkArchiveNestedGemPayloadIsStreamedPastThePerFileCap(t *testing.T) {
	// A gem's real files live in an inner data.tar.gz that is routinely larger
	// than the per-file cap; it must be walked, not cut off as "one big file".
	payload := highEntropyBytes(200 << 10)
	inner := map[string][]byte{"lib/a.bin": payload, "lib/b.bin": payload, "lib/c.rb": []byte("puts 1\n")}
	lim := generous()
	lim.MaxFileBytes = 16 << 10
	w := walk(context.Background(), gemBytes(t, inner), lim)
	if w.err != nil {
		t.Fatal(w.err)
	}
	for _, name := range []string{"lib/a.bin", "lib/b.bin", "lib/c.rb"} {
		if _, ok := w.files[name]; !ok {
			t.Errorf("nested member %q was not visited (got %v)", name, w.order)
		}
	}
	if string(w.files["lib/c.rb"].Data) != "puts 1\n" {
		t.Errorf("nested small file = %q", w.files["lib/c.rb"].Data)
	}
}

func TestWalkArchiveUnpackedBytesCap(t *testing.T) {
	// One entry far larger than the cap: the walker reads its capped prefix, then
	// must stop while skipping the rest rather than decompress it to the end.
	big := highEntropyBytes(3 << 20)
	lim := generous()
	lim.MaxFileBytes = 4 << 10
	lim.MaxUnpackedBytes = 1 << 20
	archive := tarGzEntries(t, []tarEntry{
		{name: "pkg/huge.bin", typeflag: tar.TypeReg, data: big},
		{name: "pkg/after.txt", typeflag: tar.TypeReg, data: []byte("never reached")},
	})
	w := walk(context.Background(), archive, lim)
	if w.err != nil {
		t.Fatalf("a tripped limit is not an error: %v", w.err)
	}
	if !hasReason(w.stats, IncompleteUnpackedBytes) {
		t.Fatalf("stats = %+v, want %s", w.stats, IncompleteUnpackedBytes)
	}
	if _, ok := w.files["pkg/after.txt"]; ok {
		t.Error("an entry beyond the unpacked-bytes cap was visited")
	}
	if w.stats.UnpackedBytes > lim.MaxUnpackedBytes+(64<<10) {
		t.Errorf("unpacked %d bytes, far past the %d cap", w.stats.UnpackedBytes, lim.MaxUnpackedBytes)
	}
}

func TestWalkArchiveCompressionRatioGuard(t *testing.T) {
	// 24 MiB of zeros compresses about a thousand-fold: a decompression bomb.
	bomb := make([]byte, 24<<20)
	lim := generous()
	lim.MaxCompressionRatio = 100
	archive := tarGzEntries(t, []tarEntry{
		{name: "pkg/bomb.bin", typeflag: tar.TypeReg, data: bomb},
		{name: "pkg/after.txt", typeflag: tar.TypeReg, data: []byte("never reached")},
	})
	w := walk(context.Background(), archive, lim)
	if w.err != nil {
		t.Fatalf("a tripped limit is not an error: %v", w.err)
	}
	if !hasReason(w.stats, IncompleteRatio) {
		t.Fatalf("stats = %+v, want %s", w.stats, IncompleteRatio)
	}
	if _, ok := w.files["pkg/after.txt"]; ok {
		t.Error("an entry after the bomb was visited")
	}
	if w.stats.UnpackedBytes >= int64(len(bomb)) {
		t.Errorf("the bomb was decompressed in full (%d bytes)", w.stats.UnpackedBytes)
	}

	// A small, highly-compressible archive is not a bomb: the guard only applies
	// once a few megabytes have been produced.
	small := tarGz(t, map[string][]byte{"pkg/zeros.bin": make([]byte, 1<<20)})
	w = walk(context.Background(), small, lim)
	if w.err != nil || hasReason(w.stats, IncompleteRatio) {
		t.Errorf("small compressible archive tripped the ratio guard: %+v (err %v)", w.stats, w.err)
	}

	// The same holds for a zip member.
	w = walk(context.Background(), zipBytes(t, map[string][]byte{"bomb.bin": bomb, "z-after.txt": []byte("x")}), ArchiveLimits{
		MaxArchiveBytes: 64 << 20, MaxFileBytes: 32 << 20, MaxFiles: 100, MaxCompressionRatio: 100,
	})
	if !hasReason(w.stats, IncompleteRatio) {
		t.Errorf("zip bomb not detected: %+v", w.stats)
	}
}

func TestWalkArchiveInputCap(t *testing.T) {
	archive := tarGz(t, map[string][]byte{"pkg/a.bin": highEntropyBytes(300 << 10), "pkg/b.bin": highEntropyBytes(300 << 10)})
	lim := generous()
	lim.MaxArchiveBytes = 64 << 10
	w := walk(context.Background(), archive, lim)
	if !hasReason(w.stats, IncompleteArchiveBytes) {
		t.Fatalf("tar.gz: stats = %+v, want %s", w.stats, IncompleteArchiveBytes)
	}
	if w.stats.CompressedBytes > lim.MaxArchiveBytes+1 {
		t.Errorf("consumed %d bytes, past the input cap", w.stats.CompressedBytes)
	}

	// A zip larger than the cap cannot be parsed at all (its directory is at the
	// end); it is reported incomplete with nothing visited.
	z := zipBytes(t, map[string][]byte{"a.bin": highEntropyBytes(300 << 10)})
	w = walk(context.Background(), z, lim)
	if w.err != nil || !hasReason(w.stats, IncompleteArchiveBytes) || len(w.files) != 0 {
		t.Errorf("zip: err %v stats %+v files %v", w.err, w.stats, w.order)
	}
}

func TestWalkArchiveZipDirectoryGuard(t *testing.T) {
	// A zip that declares far more members than the file cap is refused before
	// the directory is parsed: opening it would allocate a record per member.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < 4200; i++ {
		if _, err := zw.Create("f" + itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	lim := generous()
	lim.MaxFiles = 10 // threshold: 4*10 + 4096 = 4136 records
	w := walk(context.Background(), buf.Bytes(), lim)
	if w.err != nil {
		t.Fatal(w.err)
	}
	if !hasReason(w.stats, IncompleteZipDirectory) || len(w.files) != 0 {
		t.Errorf("stats = %+v files = %d, want the directory guard to refuse the archive", w.stats, len(w.files))
	}

	// Below the threshold the ordinary entry-count guard applies instead.
	lim.MaxFiles = 1000
	w = walk(context.Background(), buf.Bytes(), lim)
	if hasReason(w.stats, IncompleteZipDirectory) || w.stats.Files != 1000 || !hasReason(w.stats, IncompleteFiles) {
		t.Errorf("stats = %+v, want 1000 files then %s", w.stats, IncompleteFiles)
	}
}

func TestWalkArchiveStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	archive := tarGz(t, map[string][]byte{"a": highEntropyBytes(1 << 20), "b": highEntropyBytes(1 << 20), "c": highEntropyBytes(1 << 20)})
	seen := 0
	_, err := WalkArchive(ctx, bytes.NewReader(archive), generous(), func(e ArchiveEntry) bool {
		seen++
		cancel() // cancel while the walk is in progress
		return true
	}, nil)
	if err != nil {
		t.Fatalf("cancellation must end the walk quietly, got %v", err)
	}
	if seen != 1 {
		t.Errorf("visited %d entries after cancellation, want 1", seen)
	}

	// Already-canceled before the first read: nothing is visited and the archive
	// is not misreported as "not an archive".
	seen = 0
	_, err = WalkArchive(ctx, bytes.NewReader(archive), generous(), func(e ArchiveEntry) bool { seen++; return true }, nil)
	if err != nil || seen != 0 {
		t.Errorf("pre-canceled walk: err %v, visited %d", err, seen)
	}
}

func TestWalkArchiveVisitorCanStop(t *testing.T) {
	files := map[string][]byte{}
	for i := 0; i < 20; i++ {
		files["f"+itoa(i)] = []byte("x")
	}
	for format, archive := range map[string][]byte{"tar.gz": tarGz(t, files), "zip": zipBytes(t, files), "gem": gemBytes(t, files)} {
		seen := 0
		stats, err := WalkArchive(context.Background(), bytes.NewReader(archive), generous(), func(e ArchiveEntry) bool {
			seen++
			return seen < 3
		}, nil)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if seen != 3 {
			t.Errorf("%s: visitor called %d times after asking to stop at 3", format, seen)
		}
		if !stats.Complete() {
			t.Errorf("%s: a visitor stop is not a limit: %+v", format, stats)
		}
	}
}

// The wrapper the content-analysis gate itself uses reports truncation exactly
// when a limit cut the walk — not for an archive that was read in full.
func TestWalkArchiveWrapperReportsTruncationOnlyWhenCut(t *testing.T) {
	archive := tarGz(t, map[string][]byte{"pkg/a.js": []byte("a"), "pkg/b.js": []byte("b"), "pkg/c.js": []byte("c")})
	run := func(b budget) (visited int, truncated bool) {
		t.Helper()
		truncated, err := walkArchive(context.Background(), bytes.NewReader(archive), b, func(walkedFile) bool {
			visited++
			return true
		})
		if err != nil {
			t.Fatalf("walkArchive: %v", err)
		}
		return visited, truncated
	}
	if n, truncated := run(budget{maxArchiveBytes: 1 << 20, maxFileBytes: 1 << 20, maxFiles: 100}); n != 3 || truncated {
		t.Errorf("complete walk: visited %d, truncated %v; want 3, false", n, truncated)
	}
	if n, truncated := run(budget{maxArchiveBytes: 1 << 20, maxFileBytes: 1 << 20, maxFiles: 2}); n != 2 || !truncated {
		t.Errorf("walk cut by maxFiles: visited %d, truncated %v; want 2, true", n, truncated)
	}
}

// The ratio guard measures decompressed bytes against the compressed bytes
// actually consumed. A large archive that does not compress well is not a bomb
// and must be read to the end.
func TestWalkArchiveRatioGuardLeavesLargeIncompressibleArchivesAlone(t *testing.T) {
	payload := highEntropyBytes(6 << 20) // well past the few-megabyte floor
	lim := generous()
	lim.MaxFileBytes = 8 << 20
	lim.MaxCompressionRatio = 50
	archive := tarGzEntries(t, []tarEntry{
		{name: "pkg/blob.bin", typeflag: tar.TypeReg, data: payload},
		{name: "pkg/after.txt", typeflag: tar.TypeReg, data: []byte("reached")},
	})
	if ratio := float64(len(payload)) / float64(len(archive)); ratio > 2 {
		t.Fatalf("test payload compresses %.1f-fold; it is meant to be incompressible", ratio)
	}
	w := walk(context.Background(), archive, lim)
	if w.err != nil || hasReason(w.stats, IncompleteRatio) || !w.stats.Complete() {
		t.Fatalf("an incompressible 6 MiB archive tripped a limit: %+v (err %v)", w.stats, w.err)
	}
	if string(w.files["pkg/after.txt"].Data) != "reached" || w.files["pkg/blob.bin"].Size != int64(len(payload)) {
		t.Errorf("the archive was not read to the end: %v", w.order)
	}
}

// A member that is merely named like a gem's inner payload, but is not gzip, is
// an ordinary file and must be delivered byte for byte — including when it
// starts with half of the gzip magic.
func TestWalkArchiveNestedNameWithoutGzipMagicIsAnOrdinaryFile(t *testing.T) {
	for name, content := range map[string][]byte{
		"first magic byte only":  append([]byte{0x1f, 0x00}, []byte("not gzip at all, just bytes that must survive intact")...),
		"second magic byte only": append([]byte{0x00, 0x8b}, []byte("not gzip at all, just bytes that must survive intact")...),
		"plain text":             []byte("data.tar.gz is only this file's name"),
	} {
		archive := tarGzEntries(t, []tarEntry{
			{name: "data.tar.gz", typeflag: tar.TypeReg, data: content},
			{name: "metadata.gz", typeflag: tar.TypeReg, data: []byte("m")},
		})
		w := walk(context.Background(), archive, generous())
		if w.err != nil {
			t.Fatalf("%s: %v", name, w.err)
		}
		got, ok := w.files["data.tar.gz"]
		if !ok || !bytes.Equal(got.Data, content) {
			t.Errorf("%s: member data = %q (present %v), want it unchanged", name, got.Data, ok)
		}
		if _, ok := w.files["metadata.gz"]; !ok {
			t.Errorf("%s: the member after it was lost", name)
		}
	}
}

// The zip buffer limit is inclusive: an archive of exactly the limit is parsed,
// one byte more is not.
func TestWalkArchiveZipSizeBoundary(t *testing.T) {
	z := zipBytes(t, map[string][]byte{"pkg/a.txt": []byte("alpha"), "pkg/b.txt": []byte("beta")})
	lim := generous()

	lim.MaxArchiveBytes = int64(len(z))
	w := walk(context.Background(), z, lim)
	if w.err != nil || !w.stats.Complete() || len(w.files) != 2 {
		t.Errorf("zip of exactly the limit: err %v, stats %+v, files %v; want it walked in full", w.err, w.stats, w.order)
	}

	lim.MaxArchiveBytes = int64(len(z)) - 1
	w = walk(context.Background(), z, lim)
	if w.err != nil || !hasReason(w.stats, IncompleteArchiveBytes) || len(w.files) != 0 {
		t.Errorf("zip one byte over the limit: err %v, stats %+v, files %v; want nothing visited", w.err, w.stats, w.order)
	}
}
