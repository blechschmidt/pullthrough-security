package yum

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// fedoraEntries are two <package> entries recorded from Fedora 44's updates
// repository (x86_64, 2026-11-16): kicad-doc has an epoch, stb-doc a caret in
// its version and in its file name.
const fedoraEntries = `<package type="rpm">
  <name>kicad-doc</name>
  <arch>noarch</arch>
  <version epoch="1" ver="10.0.8" rel="1.fc44"/>
  <checksum type="sha256" pkgid="YES">4c7bd88324b81988389064d54e0aca5e3bb24c1159ab0f4201790cfc701b2f63</checksum>
  <summary>Documentation for KiCad</summary>
  <description>Documentation for KiCad.</description>
  <packager>Fedora Project</packager>
  <url>https://www.kicad.org</url>
  <time file="1793323640" build="1793310924"/>
  <size package="95650510" installed="128034897" archive="130109308"/>
  <location href="Packages/k/kicad-doc-10.0.8-1.fc44.noarch.rpm"/>
  <format>
    <rpm:license>GPL-3.0-or-later or CC-BY-3.0</rpm:license>
    <rpm:vendor>Fedora Project</rpm:vendor>
    <rpm:group>Unspecified</rpm:group>
    <rpm:buildhost>buildhw-x86-13.rdu3.fedoraproject.org</rpm:buildhost>
    <rpm:sourcerpm>kicad-10.0.8-1.fc44.src.rpm</rpm:sourcerpm>
    <rpm:header-range start="1910376" end="3578285"/>
    <rpm:provides>
      <rpm:entry name="kicad-doc" flags="EQ" epoch="1" ver="10.0.8" rel="1.fc44"/>
    </rpm:provides>
  </format>
</package>
<package type="rpm">
  <name>stb-doc</name>
  <arch>noarch</arch>
  <version epoch="0" ver="0^20261009.a7d4c21" rel="7.fc44"/>
  <checksum type="sha256" pkgid="YES">c565d2f05af42cad796248d5e74b27c7a3882cafd9973fdc2dbccbc1593f867d</checksum>
  <summary>Documentation for stb</summary>
  <description>Documentation for stb.</description>
  <packager>Fedora Project</packager>
  <url>https://github.com/nothings/stb</url>
  <time file="1792686056" build="1792685657"/>
  <size package="24907" installed="37462" archive="39120"/>
  <location href="Packages/s/stb-doc-0^20261009.a7d4c21-7.fc44.noarch.rpm"/>
  <format>
    <rpm:license>MIT OR Unlicense</rpm:license>
    <rpm:vendor>Fedora Project</rpm:vendor>
    <rpm:group>Unspecified</rpm:group>
    <rpm:buildhost>buildvm-x86-25.rdu3.fedoraproject.org</rpm:buildhost>
    <rpm:sourcerpm>stb-0^20261009.a7d4c21-7.fc44.src.rpm</rpm:sourcerpm>
    <rpm:header-range start="4504" end="11541"/>
    <rpm:provides>
      <rpm:entry name="stb-doc" flags="EQ" epoch="0" ver="0^20261009.a7d4c21" rel="7.fc44"/>
    </rpm:provides>
  </format>
</package>
`

// primaryDoc wraps entries in a primary.xml's root element, as createrepo_c
// writes it.
func primaryDoc(entries ...string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="` +
		fmt.Sprint(len(entries)) + `">
` + strings.Join(entries, "") + "</metadata>\n"
}

func streamAll(t *testing.T, doc string) []PrimaryEntry {
	t.Helper()
	var out []PrimaryEntry
	if err := StreamPrimary(strings.NewReader(doc), func(e PrimaryEntry) error {
		out = append(out, e)
		return nil
	}); err != nil {
		t.Fatalf("StreamPrimary: %v", err)
	}
	return out
}

func TestStreamPrimaryReadsEveryField(t *testing.T) {
	got := streamAll(t, primaryDoc(fedoraEntries, `<package type="rpm">
  <name> elsewhere </name><arch>x86_64</arch><version ver="1.0" rel="2"/>
  <checksum type="sha512">`+strings.Repeat("ab", 64)+`</checksum>
  <location xml:base="https://mirror.example/repo/" href="Packages/e/elsewhere-1.0-2.x86_64.rpm"/>
  <time build="5"/><size package="x"/>
</package>`))
	want := []PrimaryEntry{
		{Name: "kicad-doc", Arch: "noarch", Epoch: "1", Version: "10.0.8", Release: "1.fc44", ChecksumType: "sha256",
			Checksum: "4c7bd88324b81988389064d54e0aca5e3bb24c1159ab0f4201790cfc701b2f63",
			Location: "Packages/k/kicad-doc-10.0.8-1.fc44.noarch.rpm", Size: 95650510, Time: 1793323640},
		{Name: "stb-doc", Arch: "noarch", Epoch: "0", Version: "0^20261009.a7d4c21", Release: "7.fc44", ChecksumType: "sha256",
			Checksum: "c565d2f05af42cad796248d5e74b27c7a3882cafd9973fdc2dbccbc1593f867d",
			Location: "Packages/s/stb-doc-0^20261009.a7d4c21-7.fc44.noarch.rpm", Size: 24907, Time: 1792686056},
		{Name: "elsewhere", Arch: "x86_64", Version: "1.0", Release: "2", ChecksumType: "sha512", Checksum: strings.Repeat("ab", 64),
			Location: "Packages/e/elsewhere-1.0-2.x86_64.rpm", LocationBase: "https://mirror.example/repo/"},
	}
	if len(got) != len(want) {
		t.Fatalf("read %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
	// An empty repository's primary has no entry and is no error.
	if got := streamAll(t, `<metadata xmlns="http://linux.duke.edu/metadata/common" packages="0"/>`); len(got) != 0 {
		t.Errorf("empty repository: %+v", got)
	}
}

// One bad entry does not fail the document: it is left out.
func TestStreamPrimaryLeavesOutMalformedEntries(t *testing.T) {
	long := strings.Repeat("x", maxPrimaryField+1)
	got := streamAll(t, primaryDoc(
		`<package><name>two-names</name><name>other</name><location href="a.rpm"/></package>`,
		`<package><name>two-locations</name><location href="a.rpm"/><location href="b.rpm"/></package>`,
		`<package><name>no-location</name></package>`,
		`<package><location href="no-name.rpm"/></package>`,
		`<package><name>`+long+`</name><location href="c.rpm"/></package>`,
		`<package><name>long-href</name><location href="`+long+`"/></package>`,
		`<package><name>nested <b>text</b> kept</name><location href="d.rpm"/></package>`,
		`<package><name>kept</name><location href="e.rpm"/><format><x><y/></x></format></package>`,
		`<other><package><name>not a child of the root</name><location href="f.rpm"/></package></other>`,
	))
	var names []string
	for _, e := range got {
		names = append(names, e.Name)
	}
	if fmt.Sprint(names) != "[nested  kept kept]" {
		t.Errorf("entries kept: %q", names)
	}
}

func TestStreamPrimaryRefusesMalformedDocuments(t *testing.T) {
	deep := strings.Repeat("<x>", maxPrimaryDepth+1) + strings.Repeat("</x>", maxPrimaryDepth+1)
	attrs := ""
	for i := 0; i <= maxPrimaryAttrs; i++ {
		attrs += fmt.Sprintf(` a%d=""`, i)
	}
	for name, doc := range map[string]string{
		"empty":             "",
		"not xml":           "this is not xml",
		"html":              "<html><body>Service Unavailable</body></html>",
		"truncated":         primaryDoc(fedoraEntries)[:400],
		"no root end":       `<metadata><package><name>a</name><location href="a.rpm"/></package>`,
		"after the root":    `<metadata/><metadata/>`,
		"unknown entity":    `<metadata><package><name>&evil;</name></package></metadata>`,
		"mismatched tags":   `<metadata><package></metadata></package>`,
		"too deep":          `<metadata><package><name>a</name><format>` + deep + `</format></package></metadata>`,
		"too deep in text":  `<metadata><package><name>` + deep + `</name></package></metadata>`,
		"long token":        `<metadata><package><description>` + strings.Repeat("a", maxPrimaryToken+primaryReadAhead+1) + `</description></package></metadata>`,
		"long tag":          `<metadata><package x="` + strings.Repeat("a", maxPrimaryToken+primaryReadAhead+1) + `"/></metadata>`,
		"long start tag":    `<metadata><package><name>a</name><location href="a.rpm"/><format x="` + strings.Repeat("a", maxPrimaryTag) + `"/></package></metadata>`,
		"many attributes":   `<metadata><package><name>a</name><location href="a.rpm"/><format` + attrs + `/></package></metadata>`,
		"binary (zchunk)":   "\x00ZCK1\x00\x01\x02\x03",
		"charset not utf-8": `<?xml version="1.0" encoding="ISO-8859-1"?><metadata/>`,
	} {
		err := StreamPrimary(strings.NewReader(doc), func(PrimaryEntry) error { return nil })
		if !errors.Is(err, ErrMalformedPrimary) {
			t.Errorf("%s: %v, want an ErrMalformedPrimary", name, err)
		}
	}
}

// failingReader yields its data, then fails.
type failingReader struct {
	data []byte
	err  error
}

func (f *failingReader) Read(p []byte) (int, error) {
	if len(f.data) == 0 {
		return 0, f.err
	}
	n := copy(p, f.data)
	f.data = f.data[n:]
	return n, nil
}

// A failed read is the reader's error, not the document's; fn's error stops
// the walk.
func TestStreamPrimaryReturnsReaderAndCallbackErrors(t *testing.T) {
	boom := errors.New("connection reset")
	err := StreamPrimary(&failingReader{data: []byte(primaryDoc(fedoraEntries))[:700], err: boom}, func(PrimaryEntry) error { return nil })
	if !errors.Is(err, boom) || errors.Is(err, ErrMalformedPrimary) {
		t.Errorf("a failed read: %v", err)
	}
	stop := errors.New("enough")
	n := 0
	err = StreamPrimary(strings.NewReader(primaryDoc(fedoraEntries)), func(PrimaryEntry) error { n++; return stop })
	if !errors.Is(err, stop) || n != 1 {
		t.Errorf("fn's error: %v after %d entries", err, n)
	}
}

func zstdBytes(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf, zstd.WithWindowSize(4<<20))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

func xzBytes(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	xw, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = xw.Write(b)
	_ = xw.Close()
	return buf.Bytes()
}

// bz2Empty is `<metadata packages="0"></metadata>\n` compressed by bzip2 (the
// standard library has no bzip2 writer).
const bz2Empty = "\x42\x5a\x68\x39\x31\x41\x59\x26\x53\x59\x01\x92\xeb\xc9\x00\x00\x03\xd9\x80\x00\x10\x50\x00\xc0\x07\x2e\x8a\x4c\x00\x20\x00\x31\x4d\x32\x31\x31\x31\x06\xa0\x69\x90\x0f\x28\xf1\x0f\x0e\xd7\x2f\x64\x14\xc1\xe8\x69\x14\x28\x76\x4a\x61\x31\xf1\x77\x24\x53\x85\x09\x00\x19\x2e\xbc\x90"

func TestOpenPrimaryDecompressesByNameAndContent(t *testing.T) {
	doc := []byte(primaryDoc(fedoraEntries))
	for name, body := range map[string][]byte{
		"repodata/x-primary.xml.gz":  gzipBytes(doc),
		"repodata/x-primary.xml.xz":  xzBytes(t, doc),
		"repodata/x-primary.xml.zst": zstdBytes(t, doc),
		"repodata/x-primary.xml":     doc,
		// A plain name over compressed bytes: the content says what it is.
		"primary.xml": gzipBytes(doc),
	} {
		r, release, err := OpenPrimary(bytes.NewReader(body), name, int64(len(doc)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := io.ReadAll(r)
		release()
		if err != nil || !bytes.Equal(got, doc) {
			t.Errorf("%s: read %d bytes, %v", name, len(got), err)
		}
		// One byte less than the document is refused, not cut short.
		r, release, _ = OpenPrimary(bytes.NewReader(body), name, int64(len(doc))-1)
		if _, err := io.ReadAll(r); !errors.Is(err, errPrimaryTooLarge) {
			t.Errorf("%s past the limit: %v", name, err)
		}
		release()
	}
	r, release, err := OpenPrimary(strings.NewReader(bz2Empty), "x-primary.xml.bz2", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(r); err != nil || string(got) != "<metadata packages=\"0\"></metadata>\n" {
		t.Errorf("bzip2: %q %v", got, err)
	}
	release()

	// zchunk is not decoded; a name that disagrees with the content is
	// refused; a broken stream does not decompress.
	if _, _, err := OpenPrimary(strings.NewReader("\x00ZCK1"), "repodata/x-primary.xml.zck", 1<<20); !errors.Is(err, errUnsupportedCompression) {
		t.Errorf("zchunk: %v", err)
	}
	for name, body := range map[string][]byte{
		"x-primary.xml.zst": gzipBytes(doc),
		"x-primary.xml.gz":  doc,
		"x-primary.xml.xz":  zstdBytes(t, doc),
	} {
		if _, _, err := OpenPrimary(bytes.NewReader(body), name, 1<<20); err == nil {
			t.Errorf("%s over other content: accepted", name)
		}
	}
	if _, _, err := OpenPrimary(bytes.NewReader([]byte("\xfd7zXZ\x00garbage")), "x.xz", 1<<20); err == nil {
		t.Errorf("a broken xz stream: accepted")
	}
}

// zstdRepo is a repository in current Fedora's form: repomd.xml lists the
// primary as zstd (and as zchunk, which the backend does not decode), in
// Fedora's format.
func zstdRepo(t *testing.T, compress func([]byte) []byte, suffix string) *fakeRepo {
	t.Helper()
	fr := newFakeRepo(t)
	entry := func(name, file string, payload []byte) string {
		return fmt.Sprintf(`<package type="rpm">
  <name>%s</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="1.0" rel="1.fc44"/>
  <checksum type="sha256" pkgid="YES">%s</checksum>
  <summary>s</summary>
  <description>d &lt;with markup&gt;</description>
  <time file="1793323640" build="1793310924"/>
  <size package="%d" installed="1" archive="1"/>
  <location href="%s"/>
  <format>
    <rpm:license>MIT</rpm:license>
    <rpm:provides><rpm:entry name="%s" flags="EQ" epoch="0" ver="1.0" rel="1.fc44"/></rpm:provides>
    <rpm:requires><rpm:entry name="glibc"/><rpm:entry name="/bin/sh" pre="1"/></rpm:requires>
    <file>/usr/bin/%s</file>
  </format>
</package>
`, name, sha256Hex(payload), len(payload), file, name, name)
	}
	primary := []byte(primaryDoc(fedoraEntries,
		entry("hello", goodRPM, fr.files["/"+goodRPM]),
		entry("evil", poisonRPM, []byte("the ORIGINAL evil payload"))))
	body := compress(primary)
	loc := "repodata/" + sha256Hex(body) + "-primary.xml" + suffix
	fr.files["/"+loc] = body
	fr.files["/repodata/repomd.xml"] = []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo" xmlns:rpm="http://linux.duke.edu/metadata/rpm">
  <revision>1794788928</revision>
  <data type="primary">
    <checksum type="sha256">%s</checksum>
    <open-checksum type="sha256">%s</open-checksum>
    <location href="%s"/>
    <timestamp>1794788920</timestamp>
    <size>%d</size>
    <open-size>%d</open-size>
  </data>
  <data type="primary_zck">
    <checksum type="sha256">%s</checksum>
    <location href="repodata/%s-primary.xml.zck"/>
  </data>
</repomd>
`, sha256Hex(body), sha256Hex(primary), loc, len(body), len(primary), strings.Repeat("0", 64), strings.Repeat("0", 64)))
	return fr
}

// The finding this fixes: current Fedora publishes its primary as zstd only,
// and the backend, which decoded gzip alone, recorded no digest and served
// every RPM unverified. A zstd (or xz) primary now records the digests: the
// RPM verifies, a tampered one is refused — whether the primary was fetched
// first or the RPM found the store cold.
func TestZstdAndXZPrimariesVerifyRPMs(t *testing.T) {
	for suffix, compress := range map[string]func([]byte) []byte{
		".zst": func(b []byte) []byte { return zstdBytes(t, b) },
		".xz":  func(b []byte) []byte { return xzBytes(t, b) },
	} {
		fr := zstdRepo(t, compress, suffix)
		var loc string
		for p := range fr.files {
			if strings.HasSuffix(p, "-primary.xml"+suffix) {
				loc = p
			}
		}
		m := &Metrics{}
		b := testBackend(t, fr, Options{Metrics: m})
		if _, _, err := fetchAll(t, b, resolve(t, b, loc)); err != nil {
			t.Fatalf("%s: fetching the primary: %v", suffix, err)
		}
		if b.digests.len() != 4 || m.Stats().PrimaryParsed != 1 || m.Stats().RepodataVerified != 1 {
			t.Fatalf("%s: %d digests recorded, stats %+v", suffix, b.digests.len(), m.Stats())
		}
		fres, body, err := fetchAll(t, b, resolve(t, b, "/"+goodRPM))
		if err != nil || string(body) != "the genuine hello rpm payload" {
			t.Fatalf("%s: the good RPM: %q %v", suffix, body, err)
		}
		if got := fres.Resolved.Metadata[MetaChecksumVerified]; got != "sha256" || fres.Header.Get("X-Checksum-Verified") != "sha256" {
			t.Errorf("%s: the RPM was not verified (%q)", suffix, got)
		}
		_, _, err = fetchAll(t, b, resolve(t, b, "/"+poisonRPM))
		var mismatch *ChecksumMismatchError
		if !errors.As(err, &mismatch) {
			t.Errorf("%s: a tampered RPM: %v", suffix, err)
		}

		// A cold store: the RPM's fetch reads repomd.xml and the zstd primary.
		cold := testBackend(t, fr, Options{Metrics: &Metrics{}})
		fres, _, err = fetchAll(t, cold, resolve(t, cold, "/"+goodRPM))
		if err != nil || fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
			t.Errorf("%s: a cold store: %v %q", suffix, err, fres.Resolved.Metadata[MetaChecksumVerified])
		}
	}
	// zchunk alone is still not decoded: no digest, no error counted.
	m := &Metrics{}
	b := testBackend(t, newFakeRepo(t), Options{Metrics: m})
	b.populateFromPrimaryBytes("repodata/x-primary.xml.zck", []byte("\x00ZCK1"))
	if b.digests.len() != 0 || m.Stats().PrimaryErrors != 0 {
		t.Errorf("zchunk: %d digests, %v errors", b.digests.len(), m.Stats().PrimaryErrors)
	}
	// A document that breaks off is not the repository's declaration: none
	// of its digests is recorded, not even those read before the break.
	doc := primaryDoc(fedoraEntries)
	b.populateFromPrimaryBytes("repodata/x-primary.xml.zst", zstdBytes(t, []byte(doc[:strings.Index(doc, "stb-doc")])))
	if b.digests.len() != 0 || m.Stats().PrimaryErrors != 1 {
		t.Errorf("a broken-off primary: %d digests, %v errors", b.digests.len(), m.Stats().PrimaryErrors)
	}
}

// syntheticPrimary is a primary.xml of n packages shaped like Fedora's: about
// 3.3 KB a package (Fedora 44's updates average 3,257 bytes), most of it the
// <format> subtree — provides, requires with pre-requisites, files.
func syntheticPrimary(n int) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata xmlns=\"http://linux.duke.edu/metadata/common\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"%d\">\n", n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("synthetic-package-%06d", i)
		fmt.Fprintf(&b, `<package type="rpm">
  <name>%[1]s</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="%[2]d.%[3]d.%[4]d" rel="%[3]d.fc44"/>
  <checksum type="sha256" pkgid="YES">%064[5]x</checksum>
  <summary>Synthetic package %[2]d for the memory bound</summary>
  <description>A package whose entry is shaped like a real one: a description of a few lines,
the format subtree with what it provides and requires, and the files it installs.
It exists so that the parser's memory can be measured against a document of a realistic size.</description>
  <packager>Fedora Project</packager>
  <url>https://example.org/%[1]s</url>
  <time file="%[6]d" build="%[6]d"/>
  <size package="%[7]d" installed="%[8]d" archive="%[8]d"/>
  <location href="Packages/s/%[1]s-%[2]d.%[3]d.%[4]d-%[3]d.fc44.x86_64.rpm"/>
  <format>
    <rpm:license>MIT AND Apache-2.0 AND BSD-3-Clause</rpm:license>
    <rpm:vendor>Fedora Project</rpm:vendor>
    <rpm:group>Unspecified</rpm:group>
    <rpm:buildhost>buildvm-x86-24.rdu3.fedoraproject.org</rpm:buildhost>
    <rpm:sourcerpm>%[1]s-%[2]d.%[3]d.%[4]d-%[3]d.fc44.src.rpm</rpm:sourcerpm>
    <rpm:header-range start="4504" end="%[7]d"/>
    <rpm:provides>
`, name, i%97, i%13, i%7, i+1, 1700000000+i, 10000+i, 40000+i)
		for j := 0; j < 8; j++ {
			fmt.Fprintf(&b, "      <rpm:entry name=\"lib%s-%d.so()(64bit)\"/>\n", name, j)
		}
		b.WriteString("    </rpm:provides>\n    <rpm:requires>\n")
		for j := 0; j < 12; j++ {
			fmt.Fprintf(&b, "      <rpm:entry name=\"libdep%d.so.%d()(64bit)\" flags=\"GE\" epoch=\"0\" ver=\"%d.0\" pre=\"1\"/>\n", j, i%5, j)
		}
		b.WriteString("    </rpm:requires>\n")
		for j := 0; j < 6; j++ {
			fmt.Fprintf(&b, "    <file>/usr/lib64/%s/plugin-%d.so</file>\n", name, j)
		}
		b.WriteString("  </format>\n</package>\n")
	}
	b.WriteString("</metadata>\n")
	return b.Bytes()
}

// streamSampleHeap runs fn and returns the highest heap in use observed while
// it ran, above what was in use before (sampled every millisecond, after a
// collection).
func streamSampleHeap(fn func()) uint64 {
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				runtime.ReadMemStats(&m)
				if m.HeapInuse > base.HeapInuse && m.HeapInuse-base.HeapInuse > peak.Load() {
					peak.Store(m.HeapInuse - base.HeapInuse)
				}
			}
		}
	}()
	fn()
	close(stop)
	<-done
	return peak.Load()
}

// The backend's population reads a primary as a stream: its memory is the
// decoder's window, a token, and the digests it records — not the document.
// The bound, 48 MiB, is the 4 MiB zstd window Fedora's primaries use, the
// digest store's 10,000 entries (about 3 MiB), and the garbage a collection
// cycle lets accumulate on top (the collector lets the heap double), with
// headroom; the whole-document path it replaced holds the 33 MB document,
// and more while it grows it.
func TestStreamingPopulationMemoryIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 33 MB primary.xml")
	}
	n := 10_000
	if streamRaceEnabled {
		n = 500
	}
	doc := syntheticPrimary(n)
	size := len(doc)
	if !streamRaceEnabled && size < 30<<20 {
		t.Fatalf("the synthetic primary is %d bytes; the test wants at least 30 MB", size)
	}
	body := zstdBytes(t, doc)
	doc = nil
	fr := newFakeRepo(t)
	b := testBackend(t, fr, Options{DigestStoreMax: 1 << 20})
	peak := streamSampleHeap(func() { b.populateFromPrimaryBytes("repodata/x-primary.xml.zst", body) })
	if b.digests.len() != n {
		t.Fatalf("%d digests recorded, want %d", b.digests.len(), n)
	}
	old := testBackend(t, fr, Options{DigestStoreMax: 1 << 20})
	oldPeak := streamSampleHeap(func() {
		plain, err := decompressPrimary("x-primary.xml.zst", body)
		if err != nil {
			t.Error(err)
			return
		}
		entries, err := ParsePrimary(plain)
		if err != nil {
			t.Error(err)
			return
		}
		for _, e := range entries {
			old.digests.put(e.Location, e.Checksum)
		}
	})
	if old.digests.len() != n {
		t.Fatalf("the whole-document path recorded %d digests", old.digests.len())
	}
	t.Logf("a %d-byte primary.xml (%d packages, %d bytes as zstd): streaming peak heap %d MiB; the whole-document path (decompress, then ParsePrimary) %d MiB",
		size, n, len(body), peak>>20, oldPeak>>20)
	const ceiling = 48 << 20
	if !streamRaceEnabled && peak > ceiling {
		t.Errorf("populating from the primary held %d MiB of heap; the bound is %d MiB", peak>>20, ceiling>>20)
	}
}

// bombReader yields prefix, n bytes of fill repeated, then suffix, without
// holding the document in memory.
type bombReader struct {
	prefix, suffix string
	fill           []byte
	n              int64
	stage, off     int
}

func (g *bombReader) Read(p []byte) (int, error) {
	switch g.stage {
	case 0:
		k := copy(p, g.prefix[g.off:])
		if g.off += k; g.off == len(g.prefix) {
			g.stage, g.off = 1, 0
		}
		return k, nil
	case 1:
		k := 0
		for k < len(p) && g.n > 0 {
			c := copy(p[k:], g.fill[g.off:])
			if int64(c) > g.n {
				c = int(g.n)
			}
			k += c
			g.n -= int64(c)
			g.off = (g.off + c) % len(g.fill)
		}
		if g.n == 0 {
			g.stage, g.off = 2, 0
		}
		return k, nil
	case 2:
		k := copy(p, g.suffix[g.off:])
		if g.off += k; g.off == len(g.suffix) {
			g.stage = 3
		}
		return k, nil
	}
	return 0, io.EOF
}

// The token bound holds for every kind of token, whatever characters it
// holds: '>' is legal in text and in attribute values, a comment may hold '<'
// (a bound counting the bytes between two '<' or '>' was defeated by both).
// A 64 MiB token of each kind is refused, holding no more than the bound; a
// description of 3 MiB, within it, is read.
func TestStreamPrimaryBoundsEveryKindOfToken(t *testing.T) {
	size := int64(64 << 20)
	if streamRaceEnabled {
		size = 8 << 20
	}
	entry := `<package><name>a</name><location href="a.rpm"/>`
	for name, tc := range map[string]struct {
		prefix, fill, suffix string
	}{
		"text with '>'":        {`<metadata>` + entry + `<description>`, strings.Repeat("x", 1023) + ">", `</description></package></metadata>`},
		"comment with '<'":     {`<metadata><!--`, strings.Repeat("x", 1022) + "<>", `-->` + entry + `</package></metadata>`},
		"attribute with '>'":   {`<metadata>` + entry + `<summary lang="`, strings.Repeat("x", 1023) + ">", `"/></package></metadata>`},
		"CDATA":                {`<metadata>` + entry + `<description><![CDATA[`, strings.Repeat("x", 1022) + "<>", `]]></description></package></metadata>`},
		"processing statement": {`<metadata><?pi `, strings.Repeat("x", 1022) + "<>", `?>` + entry + `</package></metadata>`},
	} {
		doc := &bombReader{prefix: tc.prefix, fill: []byte(tc.fill), n: size, suffix: tc.suffix}
		var err error
		peak := streamSampleHeap(func() { err = StreamPrimary(doc, func(PrimaryEntry) error { return nil }) })
		if !errors.Is(err, ErrMalformedPrimary) {
			t.Errorf("%s: a %d MiB token: %v, want an ErrMalformedPrimary", name, size>>20, err)
		}
		if !streamRaceEnabled && peak > 32<<20 {
			t.Errorf("%s: a %d MiB token held %d MiB of heap; the token bound is %d MiB", name, size>>20, peak>>20, maxPrimaryToken>>20)
		}
	}
	var got []PrimaryEntry
	doc := &bombReader{prefix: `<metadata><package><name>big</name><location href="big.rpm"/><description>`,
		fill: []byte(strings.Repeat("x", 1023) + ">"), n: 3 << 20, suffix: `</description></package></metadata>`}
	if err := StreamPrimary(doc, func(e PrimaryEntry) error { got = append(got, e); return nil }); err != nil || len(got) != 1 {
		t.Errorf("a 3 MiB description: %d entries, %v", len(got), err)
	}
}

// segmentReader yields its segments in turn, each its fill repeated to n
// bytes, without holding the document in memory.
type segmentReader struct {
	segs []segment
	off  int
}

type segment struct {
	fill string
	n    int
}

func (r *segmentReader) Read(p []byte) (int, error) {
	k := 0
	for k < len(p) && len(r.segs) > 0 {
		s := &r.segs[0]
		if s.n == 0 {
			r.segs, r.off = r.segs[1:], 0
			continue
		}
		c := copy(p[k:], s.fill[r.off:])
		if c > s.n {
			c = s.n
		}
		k += c
		s.n -= c
		r.off = (r.off + c) % len(s.fill)
	}
	if k == 0 && len(r.segs) == 0 {
		return 0, io.EOF
	}
	return k, nil
}

// nestedDoc is a primary whose one package holds depth nested elements, each
// start tag an element name of nameLen bytes followed by reps copies of attr.
func nestedDoc(depth, nameLen int, attr string, reps int) *segmentReader {
	once := func(s string) segment { return segment{s, len(s)} }
	r := &segmentReader{segs: []segment{once(`<metadata><package><name>a</name><location href="a.rpm"/><format>`)}}
	for i := 0; i < depth; i++ {
		r.segs = append(r.segs, once("<"), segment{"e", nameLen}, segment{attr, len(attr) * reps}, once(">"))
	}
	for i := 0; i < depth; i++ {
		r.segs = append(r.segs, once("</"), segment{"e", nameLen}, once(">"))
	}
	r.segs = append(r.segs, once(`</format></package></metadata>`))
	return r
}

// The decoder keeps what the start tag of every open element declares (its
// name, its namespace declarations — several times their size) until the
// element ends: start tags far within the token bound, nested, held
// gigabytes (60 tags of 4 MiB of namespace declarations: 2.9 GB). A start
// tag is bounded more tightly than a token, and so is what it carries: a
// document doing this is refused at its first such tag. Tags within the
// bounds — real ones are under 1 KB, with 6 attributes — are read.
func TestStreamPrimaryBoundsWhatOpenElementsHold(t *testing.T) {
	depth, tag := 16, 1<<20
	if streamRaceEnabled {
		depth = 4
	}
	for name, tc := range map[string]struct {
		nameLen int
		attr    string
		reps    int
	}{
		"namespace declarations": {1, ` xmlns:a=""`, tag / 11},
		"attributes":             {1, ` a=""`, tag / 5},
		"a long element name":    {tag, "", 0},
		"a long namespace":       {1, ` xmlns:a="` + strings.Repeat("v", tag) + `"`, 1},
	} {
		var err error
		peak := streamSampleHeap(func() {
			err = StreamPrimary(nestedDoc(depth, tc.nameLen, tc.attr, tc.reps), func(PrimaryEntry) error { return nil })
		})
		t.Logf("%s: %d nested tags of %d KiB: %v; peak heap %d MiB", name, depth, tag>>10, err, peak>>20)
		if !errors.Is(err, ErrMalformedPrimary) || !strings.Contains(err.Error(), "start tag") {
			t.Errorf("%s: %d nested tags of %d KiB: %v, want a start tag refused", name, depth, tag>>10, err)
		}
		if !streamRaceEnabled && peak > 48<<20 {
			t.Errorf("%s: %d nested tags of %d KiB held %d MiB of heap", name, depth, tag>>10, peak>>20)
		}
	}
	// At the bounds: start tags of as many attributes as a tag may carry,
	// as long as a tag may be, nested as deep as a package may nest.
	var attrs strings.Builder
	for i := 0; i < maxPrimaryAttrs; i++ {
		fmt.Fprintf(&attrs, ` xmlns:a%02d="%s"`, i, strings.Repeat("v", maxPrimaryTag/maxPrimaryAttrs-16))
	}
	if n := len(attrs.String()) + 3; n > maxPrimaryTag || n < maxPrimaryTag-1024 {
		t.Fatalf("the tags at the bounds are %d bytes", n)
	}
	var got []PrimaryEntry
	err := StreamPrimary(nestedDoc(maxPrimaryDepth, 1, attrs.String(), 1), func(e PrimaryEntry) error { got = append(got, e); return nil })
	if err != nil || len(got) != 1 {
		t.Errorf("tags within the bounds: %d entries, %v", len(got), err)
	}
}
