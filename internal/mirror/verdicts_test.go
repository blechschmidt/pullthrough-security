package mirror

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

func contentDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// fakeVerdicts is a verdict source and sink: a gate's store, reduced to what a
// bundle needs of it.
type fakeVerdicts struct {
	have      []ScanVerdict // what the source holds
	asked     map[string]bool
	imported  []ScanVerdict
	present   map[string]bool // digests the sink already has a verdict for
	importErr error
	// blobsAtImport records how many blobs were in the target store when the
	// first verdict arrived.
	target        cache.Store
	blobsAtImport int
}

func (f *fakeVerdicts) ExportVerdicts(_ context.Context, digests map[string]bool) ([]ScanVerdict, error) {
	f.asked = digests
	return f.have, nil
}

func (f *fakeVerdicts) ImportVerdict(ctx context.Context, v ScanVerdict) (bool, error) {
	if f.target != nil && len(f.imported) == 0 {
		recs, _ := f.target.List(ctx)
		f.blobsAtImport = len(recs)
	}
	if f.importErr != nil {
		return false, f.importErr
	}
	if f.present[v.Digest] {
		return false, nil
	}
	f.imported = append(f.imported, v)
	return true, nil
}

func verdictRecord(verdict string) json.RawMessage {
	return json.RawMessage(`{"verdict":"` + verdict + `"}`)
}

func exportWithVerdicts(t *testing.T, store cache.Store, src VerdictSource) (*bytes.Buffer, *ExportResult) {
	t.Helper()
	exp, err := NewExporter(store)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	var buf bytes.Buffer
	res, err := exp.Export(context.Background(), &buf, ExportOptions{CreatedAt: time.Unix(1700000000, 0).UTC(), Verdicts: src})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	return &buf, res
}

// The verdicts a gate reached on the artifacts in a bundle travel with it, and
// only those: a verdict is carried with the bytes it is about.
func TestBundleCarriesVerdictsForItsBlobsOnly(t *testing.T) {
	src := newStore(t)
	put(t, src, "npm:evil/-/evil-1.0.0.tgz", "evil-content", "https://upstream/evil")
	put(t, src, "npm:good/-/good-1.0.0.tgz", "good-content", "https://upstream/good")
	evil, good, absent := contentDigest("evil-content"), contentDigest("good-content"), contentDigest("not in the cache")

	source := &fakeVerdicts{have: []ScanVerdict{
		{Gate: "llmpkgscan", Digest: good, Record: verdictRecord("benign")},
		{Gate: "llmpkgscan", Digest: evil, Record: verdictRecord("malicious")},
		{Gate: "llmpkgscan", Digest: absent, Record: verdictRecord("malicious")}, // not asked for; must not travel
		{Gate: "", Digest: evil, Record: verdictRecord("malicious")},             // no gate: dropped
		{Gate: "llmpkgscan", Digest: evil},                                       // no record: dropped
	}}
	bundle, res := exportWithVerdicts(t, src, source)
	if !source.asked[evil] || !source.asked[good] || len(source.asked) != 2 {
		t.Errorf("the source was asked for %v, want exactly the digests of the bundle's blobs", source.asked)
	}
	if res.ScanVerdicts != 2 {
		t.Fatalf("exported %d verdicts, want 2", res.ScanVerdicts)
	}

	// The same content and verdicts produce the same bytes: verdicts are ordered.
	shuffled := &fakeVerdicts{have: []ScanVerdict{source.have[1], source.have[0]}}
	again, res2 := exportWithVerdicts(t, src, shuffled)
	if !bytes.Equal(bundle.Bytes(), again.Bytes()) || res.ManifestDigest != res2.ManifestDigest {
		t.Error("the bundle is not reproducible: verdict order leaked into it")
	}

	// A bundle without verdicts is what it always was.
	plain, plainRes := exportToBuffer(t, src, nil)
	if bytes.Contains(plain.Bytes(), []byte("scanVerdicts")) {
		t.Error("a bundle without verdicts mentions them: the manifest of an existing bundle would no longer hash the same")
	}
	if plainRes.ManifestDigest == res.ManifestDigest {
		t.Error("the manifest digest does not cover the verdicts")
	}
}

// A verdict is something the importing instance acts on. It is taken only from
// a bundle whose manifest was verified against a digest obtained out of band.
func TestVerdictsAreImportedOnlyFromAVerifiedBundle(t *testing.T) {
	src := newStore(t)
	put(t, src, "npm:evil/-/evil-1.0.0.tgz", "evil-content", "https://upstream/evil")
	put(t, src, "npm:good/-/good-1.0.0.tgz", "good-content", "https://upstream/good")
	evil, good := contentDigest("evil-content"), contentDigest("good-content")
	bundle, res := exportWithVerdicts(t, src, &fakeVerdicts{have: []ScanVerdict{
		{Gate: "llmpkgscan", Digest: evil, Record: verdictRecord("malicious")},
		{Gate: "llmpkgscan", Digest: good, Record: verdictRecord("benign")},
	}})

	t.Run("no manifest digest given", func(t *testing.T) {
		dst := newStore(t)
		im, _ := NewImporter(dst)
		sink := &fakeVerdicts{}
		out, err := im.Import(context.Background(), bytes.NewReader(bundle.Bytes()), ImportOptions{Verdicts: sink})
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if len(sink.imported) != 0 || out.ScanVerdicts != 0 {
			t.Fatalf("%d verdicts were imported from a bundle nobody verified", len(sink.imported))
		}
		if out.ScanVerdictsUntrusted != 2 {
			t.Errorf("untrusted verdicts = %d, want 2 reported", out.ScanVerdictsUntrusted)
		}
		// The blobs are imported all the same: they are gated when served.
		if out.Imported != 2 {
			t.Errorf("imported blobs = %d, want 2", out.Imported)
		}
	})

	t.Run("manifest digest verified", func(t *testing.T) {
		dst := newStore(t)
		im, _ := NewImporter(dst)
		sink := &fakeVerdicts{target: dst, present: map[string]bool{good: true}}
		out, err := im.Import(context.Background(), bytes.NewReader(bundle.Bytes()), ImportOptions{Verdicts: sink, ExpectedManifestDigest: res.ManifestDigest})
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if len(sink.imported) != 1 || sink.imported[0].Digest != evil || string(sink.imported[0].Record) != `{"verdict":"malicious"}` {
			t.Fatalf("imported = %+v, want the malicious verdict (the benign one is already present)", sink.imported)
		}
		if out.ScanVerdicts != 1 || out.ScanVerdictsSkipped != 1 || out.ScanVerdictsUntrusted != 0 {
			t.Errorf("counts = %d imported / %d skipped / %d untrusted, want 1/1/0", out.ScanVerdicts, out.ScanVerdictsSkipped, out.ScanVerdictsUntrusted)
		}
		// Verdicts arrive after the content they are about.
		if sink.blobsAtImport != 2 {
			t.Errorf("the first verdict was imported when %d of 2 blobs were in the store", sink.blobsAtImport)
		}
	})

	t.Run("verified, but no sink", func(t *testing.T) {
		im, _ := NewImporter(newStore(t))
		out, err := im.Import(context.Background(), bytes.NewReader(bundle.Bytes()), ImportOptions{ExpectedManifestDigest: res.ManifestDigest})
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if out.ScanVerdictsUntrusted != 2 || out.ScanVerdicts != 0 {
			t.Errorf("counts = %d imported / %d not imported, want 0/2", out.ScanVerdicts, out.ScanVerdictsUntrusted)
		}
	})

	t.Run("a sink that rejects a verdict fails the import", func(t *testing.T) {
		im, _ := NewImporter(newStore(t))
		sink := &fakeVerdicts{importErr: errors.New("the record is not what it claims")}
		_, err := im.Import(context.Background(), bytes.NewReader(bundle.Bytes()), ImportOptions{Verdicts: sink, ExpectedManifestDigest: res.ManifestDigest})
		if err == nil || !strings.Contains(err.Error(), "not what it claims") {
			t.Fatalf("err = %v, want the sink's rejection", err)
		}
	})
}

// rewriteManifest returns the bundle with its manifest member replaced by f's
// edit of it. The blobs are untouched.
func rewriteManifest(t *testing.T, bundle []byte, f func(m *BundleManifest)) []byte {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(bundle))
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == manifestMember {
			var m BundleManifest
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatal(err)
			}
			f(&m)
			if data, err = json.Marshal(&m); err != nil {
				t.Fatal(err)
			}
			hdr.Size = int64(len(data))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	return out.Bytes()
}

// The manifest digest covers the verdicts: a bundle whose "malicious" was
// edited to "benign" in transit no longer matches the digest that was
// transferred out of band, and nothing of it is imported.
func TestTamperedVerdictFailsTheManifestDigest(t *testing.T) {
	src := newStore(t)
	put(t, src, "npm:evil/-/evil-1.0.0.tgz", "evil-content", "https://upstream/evil")
	evil := contentDigest("evil-content")
	bundle, res := exportWithVerdicts(t, src, &fakeVerdicts{have: []ScanVerdict{{Gate: "llmpkgscan", Digest: evil, Record: verdictRecord("malicious")}}})

	tampered := rewriteManifest(t, bundle.Bytes(), func(m *BundleManifest) {
		m.ScanVerdicts[0].Record = verdictRecord("benign")
	})
	dst := newStore(t)
	im, _ := NewImporter(dst)
	sink := &fakeVerdicts{}
	_, err := im.Import(context.Background(), bytes.NewReader(tampered), ImportOptions{Verdicts: sink, ExpectedManifestDigest: res.ManifestDigest})
	if err == nil || !strings.Contains(err.Error(), "manifest digest mismatch") {
		t.Fatalf("err = %v, want a manifest digest mismatch", err)
	}
	if len(sink.imported) != 0 {
		t.Error("a verdict from a tampered bundle reached the sink")
	}
	if recs, _ := dst.List(context.Background()); len(recs) != 0 {
		t.Errorf("%d blobs of a tampered bundle were imported", len(recs))
	}

	// Without the out-of-band digest the tampering cannot be seen — which is
	// exactly why the verdicts are then not imported at all.
	out, err := im.Import(context.Background(), bytes.NewReader(tampered), ImportOptions{Verdicts: sink})
	if err != nil {
		t.Fatalf("Import without a digest: %v", err)
	}
	if len(sink.imported) != 0 || out.ScanVerdictsUntrusted != 1 {
		t.Errorf("imported %d, untrusted %d; want the edited verdict left out", len(sink.imported), out.ScanVerdictsUntrusted)
	}
}

// A verdict about bytes the bundle does not carry is refused: a bundle cannot
// be used to file verdicts for artifacts that arrive some other way.
func TestVerdictForContentNotInTheBundleIsRefused(t *testing.T) {
	src := newStore(t)
	put(t, src, "npm:good/-/good-1.0.0.tgz", "good-content", "https://upstream/good")
	good, elsewhere := contentDigest("good-content"), contentDigest("an artifact from somewhere else")
	bundle, _ := exportWithVerdicts(t, src, &fakeVerdicts{have: []ScanVerdict{{Gate: "llmpkgscan", Digest: good, Record: verdictRecord("benign")}}})

	crafted := rewriteManifest(t, bundle.Bytes(), func(m *BundleManifest) {
		m.ScanVerdicts = append(m.ScanVerdicts, ScanVerdict{Gate: "llmpkgscan", Digest: elsewhere, Record: verdictRecord("benign")})
	})
	// The crafted bundle is internally consistent; whoever vouches for it does so
	// by its (new) digest.
	var m BundleManifest
	tr := tar.NewReader(bytes.NewReader(crafted))
	if _, err := tr.Next(); err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(tr).Decode(&m); err != nil {
		t.Fatal(err)
	}
	digest, err := m.Digest()
	if err != nil {
		t.Fatal(err)
	}

	im, _ := NewImporter(newStore(t))
	sink := &fakeVerdicts{}
	_, err = im.Import(context.Background(), bytes.NewReader(crafted), ImportOptions{Verdicts: sink, ExpectedManifestDigest: digest})
	if err == nil || !strings.Contains(err.Error(), "not the digest of any blob") {
		t.Fatalf("err = %v, want the stray verdict refused", err)
	}
	for _, v := range sink.imported {
		if v.Digest == elsewhere {
			t.Error("a verdict about content the bundle does not carry was imported")
		}
	}
}

// A bundle written before verdicts existed imports exactly as before.
func TestBundleWithoutVerdictsImportsUnchanged(t *testing.T) {
	src := newStore(t)
	put(t, src, "npm:good/-/good-1.0.0.tgz", "good-content", "https://upstream/good")
	bundle, res := exportToBuffer(t, src, nil)
	im, _ := NewImporter(newStore(t))
	sink := &fakeVerdicts{}
	out, err := im.Import(context.Background(), bytes.NewReader(bundle.Bytes()), ImportOptions{Verdicts: sink, ExpectedManifestDigest: res.ManifestDigest})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if out.Imported != 1 || out.ScanVerdicts != 0 || out.ScanVerdictsSkipped != 0 || out.ScanVerdictsUntrusted != 0 || len(sink.imported) != 0 {
		t.Errorf("result = %+v", out)
	}
}
