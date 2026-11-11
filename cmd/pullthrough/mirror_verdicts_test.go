package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// The air-gap transfer, end to end through the commands an operator runs:
// `export` on the connected instance carries the LLM package-scan verdicts for
// the artifacts in the bundle, and `import` on the disconnected one files them
// — when, and only when, it was given the manifest digest out of band. After
// that the disconnected instance refuses the malicious artifact and admits the
// benign one without a provider it can reach.
func TestExportImportCarriesLLMVerdictsAcrossTheAirGap(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	writeConfig := func(side string) (configPath, cacheDir, verdictDir string) {
		cacheDir = filepath.Join(root, side, "cache")
		verdictDir = filepath.Join(root, side, "verdicts")
		configPath = filepath.Join(root, side+".yaml")
		doc := fmt.Sprintf("server:\n  httpAddr: \":8080\"\ncache:\n  backend: filesystem\n  dir: %q\nllmPackageScan:\n  storeDir: %q\n", cacheDir, verdictDir)
		if err := os.WriteFile(configPath, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return configPath, cacheDir, verdictDir
	}
	srcConfig, srcCache, srcVerdicts := writeConfig("connected")
	dstConfig, dstCache, dstVerdicts := writeConfig("airgapped")

	evil := pkgscantest.NpmTarball("evil-pad", "1.0.0", map[string]string{"postinstall": "node setup.js"},
		map[string]string{"setup.js": "require('child_process').exec('id'); // " + pkgscantest.MaliciousMarker + "\n"})
	good := pkgscantest.NpmTarball("left-pad", "1.3.0", nil, map[string]string{"index.js": "module.exports = 1;\n"})

	// The connected instance has pulled, cached and scanned both.
	store, err := cache.NewFilesystemStore(srcCache)
	if err != nil {
		t.Fatal(err)
	}
	for key, body := range map[string][]byte{"npm:evil-pad/-/evil-pad-1.0.0.tgz": evil, "npm:left-pad/-/left-pad-1.3.0.tgz": good} {
		if _, err := store.Put(ctx, cache.Record{Key: key, ContentType: "application/gzip"}, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	}
	_ = store.Close()
	scan := func(dir string, provider *pkgscantest.Provider, artifact []byte, name string) *llmpkgscan.Report {
		t.Helper()
		vs, err := llmpkgscan.NewFileStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer vs.Close()
		svc, err := llmpkgscan.NewService(llmpkgscan.Config{Enabled: true, Provider: provider, Model: "the-model", Store: vs, FailMode: llmpkgscan.FailClosed, Logger: llmTestLogger()})
		if err != nil {
			t.Fatal(err)
		}
		defer svc.Close()
		rep, err := svc.Assess(ctx, llmpkgscan.Request{
			Artifact: llmpkgscan.Artifact{Ecosystem: "npm", Name: name, Version: "1.0.0", Filename: name + ".tgz",
				Digest: pkgscantest.Digest(artifact), Size: int64(len(artifact)), Class: llmpkgscan.ClassPayload},
			Open: pkgscantest.Opener(artifact, nil),
		})
		if err != nil || rep == nil {
			t.Fatalf("Assess(%s): %v, %v", name, rep, err)
		}
		return rep
	}
	if rep := scan(srcVerdicts, &pkgscantest.Provider{}, evil, "evil-pad"); rep.Disposition != llmpkgscan.DispositionMalicious {
		t.Fatalf("connected side judged the malicious package %s", rep.Disposition)
	}
	if rep := scan(srcVerdicts, &pkgscantest.Provider{}, good, "left-pad"); rep.Disposition != llmpkgscan.DispositionBenign {
		t.Fatalf("connected side judged the benign package %s", rep.Disposition)
	}

	bundle := filepath.Join(root, "bundle.tar")
	if err := runExport([]string{"-config", srcConfig, "-out", bundle}); err != nil {
		t.Fatalf("export: %v", err)
	}

	countVerdicts := func(dir string) int {
		t.Helper()
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			return 0
		}
		vs, err := llmpkgscan.NewFileStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer vs.Close()
		all, err := vs.List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return len(all)
	}

	// Imported without the out-of-band digest: the artifacts arrive, the verdicts
	// are not taken on the bundle's word.
	if err := runImport([]string{"-config", dstConfig, "-in", bundle}); err != nil {
		t.Fatalf("import without a manifest digest: %v", err)
	}
	if n := countVerdicts(dstVerdicts); n != 0 {
		t.Fatalf("%d verdicts were imported from a bundle whose manifest was not verified", n)
	}
	imported, err := cache.NewFilesystemStore(dstCache)
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := imported.List(ctx)
	_ = imported.Close()
	if len(recs) != 2 {
		t.Fatalf("%d cache entries imported, want 2", len(recs))
	}
	// Behind the air gap, with no verdicts, the provider is unreachable and the
	// fail mode decides — for the benign package too.
	unreachable := &pkgscantest.Provider{Err: errors.New("no route to host")}
	if rep := scan(dstVerdicts, unreachable, good, "left-pad"); rep.Scanned() {
		t.Fatal("the air-gapped side has a verdict it was never given")
	}

	// Imported again, this time with the digest sidecar the export wrote.
	if err := runImport([]string{"-config", dstConfig, "-in", bundle, "-manifest-digest", bundle + ".sha256"}); err != nil {
		t.Fatalf("import with the manifest digest: %v", err)
	}
	if n := countVerdicts(dstVerdicts); n != 2 {
		t.Fatalf("%d verdicts imported from the verified bundle, want 2", n)
	}
	if rep := scan(dstVerdicts, unreachable, evil, "evil-pad"); !rep.Cached || rep.Disposition != llmpkgscan.DispositionMalicious {
		t.Errorf("air-gapped side, malicious package: cached=%v disposition=%s (unscanned %+v); want it refused from the imported verdict", rep.Cached, rep.Disposition, rep.Unscanned)
	}
	if rep := scan(dstVerdicts, unreachable, good, "left-pad"); !rep.Cached || rep.Disposition != llmpkgscan.DispositionBenign {
		t.Errorf("air-gapped side, benign package: cached=%v disposition=%s (unscanned %+v); want it admitted from the imported verdict", rep.Cached, rep.Disposition, rep.Unscanned)
	}
	if unreachable.Calls() > 1 {
		t.Errorf("the unreachable provider was called %d times; imported verdicts need no provider", unreachable.Calls())
	}

	// A wrong digest refuses the bundle outright.
	if err := runImport([]string{"-config", dstConfig, "-in", bundle, "-manifest-digest", "sha256:" + fmt.Sprintf("%064d", 0), "-overwrite"}); err == nil {
		t.Error("an import with a manifest digest that does not match succeeded")
	}

	// -no-verdicts leaves them out of the bundle.
	bare := filepath.Join(root, "bare.tar")
	if err := runExport([]string{"-config", srcConfig, "-out", bare, "-no-verdicts"}); err != nil {
		t.Fatalf("export -no-verdicts: %v", err)
	}
	data, err := os.ReadFile(bare)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("scanVerdicts")) {
		t.Error("export -no-verdicts still carried verdicts")
	}
}
