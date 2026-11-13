package mirror

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
)

// fakeReleases is the repository registry, reduced to what a bundle needs.
type fakeReleases struct {
	have     []ReleaseRecord
	pins     []string
	imported []ReleaseRecord
	present  map[string]bool
}

func (f *fakeReleases) ExportReleases(context.Context) ([]ReleaseRecord, []string, error) {
	return f.have, f.pins, nil
}

func (f *fakeReleases) ImportRelease(_ context.Context, r ReleaseRecord) (bool, error) {
	if f.present[r.Repo+"@"+r.Commit] {
		return false, nil
	}
	f.imported = append(f.imported, r)
	return true, nil
}

// Release manifests (Task 180) travel with a bundle together with the pinned
// keys it holds, are imported only from a verified bundle, and an import never
// overwrites an object the importing instance has pinned.
func TestBundleCarriesReleasesAndPins(t *testing.T) {
	src := newStore(t)
	put(t, src, "team-a/npm/left-pad/-/left-pad-1.0.0.tgz", "left-pad", "https://upstream/left-pad")
	put(t, src, "scratch", "unpinned", "https://upstream/scratch")
	manifest := json.RawMessage(`{"repo":"widgets","commit":"aaaa"}`)
	source := &fakeReleases{
		have: []ReleaseRecord{{Repo: "widgets", Commit: "aaaa", Manifest: manifest}},
		// A pinned key the cache no longer holds is not claimed by the bundle.
		pins: []string{"team-a/npm/left-pad/-/left-pad-1.0.0.tgz", "team-a/gone"},
	}
	exp, err := NewExporter(src)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := exp.Export(context.Background(), &buf, ExportOptions{CreatedAt: time.Unix(1700000000, 0).UTC(), Releases: source})
	if err != nil {
		t.Fatal(err)
	}
	if res.Releases != 1 || res.PinnedKeys != 1 {
		t.Fatalf("export: %+v", res)
	}

	// Not verified: the blobs come in, the manifests do not.
	dst := newStore(t)
	sink := &fakeReleases{}
	imp, _ := NewImporter(dst)
	got, err := imp.Import(context.Background(), bytes.NewReader(buf.Bytes()), ImportOptions{Releases: sink})
	if err != nil {
		t.Fatal(err)
	}
	if got.ReleasesUntrusted != 1 || len(sink.imported) != 0 {
		t.Fatalf("unverified: %+v %v", got, sink.imported)
	}

	// Verified: the manifests come in. The destination has its own copy of
	// the pinned key: it is kept, whatever the bundle holds.
	dst2 := newStore(t)
	put(t, dst2, "team-a/npm/left-pad/-/left-pad-1.0.0.tgz", "the pinned original", "https://upstream/left-pad")
	sink2 := &fakeReleases{}
	imp2, _ := NewImporter(dst2)
	got, err = imp2.Import(context.Background(), bytes.NewReader(buf.Bytes()), ImportOptions{
		ExpectedManifestDigest: res.ManifestDigest, Releases: sink2, Overwrite: true,
		Protected: func(key string) bool { return key == "team-a/npm/left-pad/-/left-pad-1.0.0.tgz" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Releases != 1 || len(sink2.imported) != 1 || string(sink2.imported[0].Manifest) != string(manifest) {
		t.Fatalf("verified: %+v %v", got, sink2.imported)
	}
	if got.Protected != 1 {
		t.Fatalf("protected: %+v", got)
	}
	if content, _ := mustGet(t, dst2, "team-a/npm/left-pad/-/left-pad-1.0.0.tgz"); content != "the pinned original" {
		t.Fatalf("a pinned object was overwritten by the bundle: %q", content)
	}
	if content, _ := mustGet(t, dst2, "scratch"); content != "unpinned" {
		t.Fatalf("an unpinned blob was not imported: %q", content)
	}
}
